//! Parseurs de sortie structurés — de la sortie brute d'un outil aux artefacts
//!
//! Exécuter un outil tiers (`installer::run_tool`) ne suffit pas : sa sortie est
//! un flux texte que le LLM doit relire à chaque tour, et que rien n'injecte
//! dans l'état de campagne. Ce module comble la dernière marche :
//!
//! ```text
//!   sortie brute (nmap/ffuf/sqlmap/hydra/john/…) ──► parse() ──► [Finding]
//!                                                                  │
//!                                          ingest() ───────────────┘
//!                                             │
//!                                             ├─► ports/services  → HostMemory.services
//!                                             ├─► chemins web     → WebSurface.endpoints
//!                                             ├─► identifiants    → CampaignMemory.credentials
//!                                             ├─► SQLi confirmée  → hypotheses (VulnClass)
//!                                             ├─► CVE/avis        → confirmed_cves / notes
//!                                             └─► OID/LDAP/techs  → notes / tech_hints
//! ```
//!
//! Résultat : une exécution d'outil enrichit réellement la mémoire de campagne,
//! alimente l'état RL et le rapport final — au lieu de rester une simple ligne
//! de journal.

#![allow(dead_code)]
// Tous les `Regex::new(...).unwrap()` de ce module portent sur des motifs
// **littéraux** (constantes de compilation) : la compilation ne peut échouer que
// par faute de frappe, ce que les tests couvrent. L'unique `expect()` documente
// l'invariant local de `touch_host`. On autorise ces lints au niveau du module
// plutôt que de parsemer ~30 `#[allow]` individuels.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use regex::Regex;
use std::sync::OnceLock;

use chrono::Utc;

use super::campaign_memory::{
    normalize_host_key, CampaignMemory, Credential, CredentialType, HostMemory, WebSurface,
};
use super::hypothesis::VulnClass;

/// Nombre maximum d'entrées conservées dans `HostMemory.notes`.
const MAX_NOTES: usize = 300;

// ── Artefacts typés ──────────────────────────────────────────────────────────

/// Un fait extrait d'une sortie d'outil, prêt à être injecté en mémoire.
#[derive(Debug, Clone, PartialEq)]
pub enum Finding {
    /// Port ouvert avec service (et version si l'outil l'a donnée).
    Port {
        port: u16,
        proto: String,
        service: String,
        version: String,
    },
    /// Ressource web découverte (chemin + code HTTP).
    WebPath { path: String, status: u16 },
    /// Identifiant **vérifié** par l'outil sur la cible (hydra, nxc…).
    Secret {
        username: String,
        secret: String,
        service: String,
    },
    /// Injection SQL confirmée sur un paramètre.
    SqlInjection { param: String, technique: String },
    /// Secret en clair obtenu par cassage d'un hash (john, hashcat).
    CrackedSecret { identity: String, plaintext: String },
    /// OID SNMP et sa valeur.
    SnmpOid { oid: String, value: String },
    /// Entrée d'annuaire LDAP.
    LdapEntry { dn: String },
    /// Avis/vulnérabilité signalée (nikto, nuclei, wpscan, searchsploit…).
    Vuln { id: String, title: String },
    /// Indice technologique (whatweb…).
    TechHint { tech: String },
    /// Enregistrement DNS / découverte de nom.
    DnsRecord {
        name: String,
        kind: String,
        value: String,
    },
    /// Hash Kerberos exploitable (AS-REP roastable, TGS kerberoastable).
    KerberosHash {
        username: String,
        hash: String,
        kind: String,
    },
    /// Hash NTLM extrait (secretsdump, --sam/--lsa).
    NtlmHash {
        username: String,
        domain: String,
        ntlm: String,
    },
    /// Compte valide découvert (kerbrute, smtp-user-enum…).
    Account { username: String, service: String },
}

// ── Résumé d'injection ───────────────────────────────────────────────────────

/// Compte-rendu de ce qui a été injecté dans la mémoire de campagne.
#[derive(Debug, Default, Clone)]
pub struct IngestSummary {
    pub ports: usize,
    pub web_paths: usize,
    pub secrets: usize,
    pub vulns: usize,
    pub tech: usize,
    pub other: usize,
    pub highlights: Vec<String>,
}

impl IngestSummary {
    pub fn is_empty(&self) -> bool {
        self.ports + self.web_paths + self.secrets + self.vulns + self.tech + self.other == 0
    }

    /// Rendu compact destiné au prompt / à la console.
    pub fn render(&self) -> String {
        let mut parts = Vec::new();
        if self.ports > 0 {
            parts.push(format!("{} port(s)", self.ports));
        }
        if self.web_paths > 0 {
            parts.push(format!("{} chemin(s)", self.web_paths));
        }
        if self.secrets > 0 {
            parts.push(format!("{} identifiant(s)", self.secrets));
        }
        if self.vulns > 0 {
            parts.push(format!("{} avis", self.vulns));
        }
        if self.tech > 0 {
            parts.push(format!("{} techno", self.tech));
        }
        if self.other > 0 {
            parts.push(format!("{} entrée(s)", self.other));
        }

        let mut s = parts.join(", ");
        if !self.highlights.is_empty() {
            s.push_str(" → ");
            s.push_str(&self.highlights.join(" ; "));
        }
        s
    }
}

// ── Point d'entrée ───────────────────────────────────────────────────────────

/// Analyse la sortie d'un outil et retourne les artefacts reconnus.
///
/// Le dispatch se fait sur le **nom de base** du binaire (ex. `/usr/bin/nmap`
/// → `nmap`), ce qui le rend insensible au chemin d'installation. Un outil
/// inconnu ne produit aucun artefact (pas d'erreur : la sortie reste visible).
pub fn parse(tool: &str, output: &str, _host: &str) -> Vec<Finding> {
    let name = tool_basename(tool);

    if name.contains("nmap") {
        return parse_nmap(output);
    }
    if name.contains("ffuf") {
        return parse_ffuf(output);
    }
    if name.contains("gobuster")
        || name.contains("feroxbuster")
        || name.contains("dirb")
        || name.contains("wfuzz")
    {
        return parse_dir_brute(output);
    }
    if name.contains("sqlmap") {
        return parse_sqlmap(output);
    }
    if name.contains("hydra") || name.contains("medusa") || name.contains("ncrack") {
        return parse_hydra(output);
    }
    if name.contains("john") {
        return parse_john(output);
    }
    if name.contains("hashcat") {
        return parse_hashcat(output);
    }
    if name.contains("snmp") {
        return parse_snmp(output);
    }
    if name.contains("ldap") {
        return parse_ldap(output);
    }
    if name.contains("nikto") {
        return parse_nikto(output);
    }
    if name.contains("whatweb") {
        return parse_whatweb(output);
    }
    if name.contains("nuclei") {
        return parse_nuclei(output);
    }
    if name.contains("wpscan") {
        return parse_wpscan(output);
    }
    if name.contains("dnsrecon") || name.contains("dnsenum") || name.contains("fierce") {
        return parse_dns(output);
    }
    if name.contains("kerbrute") {
        return parse_kerbrute(output);
    }
    if name.contains("getuserspns") {
        return parse_kerberos_tgs(output);
    }
    if name.contains("getnpusers") {
        return parse_kerberos_asrep(output);
    }
    if name.contains("secretsdump") {
        return parse_secretsdump(output);
    }
    if name.contains("smtp-user-enum") || name.contains("smtp_enum") {
        return parse_smtp_enum(output);
    }
    if name.contains("searchsploit") {
        return parse_searchsploit(output);
    }
    if name.contains("gowitness") {
        return parse_gowitness(output);
    }
    if matches!(name.as_str(), "nxc" | "crackmapexec" | "cme" | "netexec") {
        return parse_smb_cme(output);
    }

    Vec::new()
}

/// Injecte les artefacts dans la mémoire de campagne et résume l'opération.
pub fn ingest(memory: &mut CampaignMemory, host: &str, findings: &[Finding]) -> IngestSummary {
    let mut summary = IngestSummary::default();
    if findings.is_empty() {
        return summary;
    }

    let key = normalize_host_key(host);

    // 1) Ports / services — fusionnés dans l'hôte (jamais écrasés).
    let services: Vec<String> = findings
        .iter()
        .filter_map(|f| match f {
            Finding::Port { port, service, .. } => {
                let svc = if service.is_empty() {
                    "unknown".to_string()
                } else {
                    service.clone()
                };
                Some(format!("{svc}/{port}"))
            }
            _ => None,
        })
        .collect();
    if !services.is_empty() {
        let h = touch_host(memory, &key);
        for s in &services {
            if !h.services.contains(s) {
                h.services.push(s.clone());
                summary.ports += 1;
            }
        }
        h.last_updated = Utc::now().to_rfc3339();
        let sample: Vec<String> = h.services.iter().rev().take(6).cloned().collect();
        summary.highlights.push(format!(
            "ports: {}",
            sample.into_iter().rev().collect::<Vec<_>>().join(", ")
        ));
    }

    // 2) Chemins web → surface d'attaque.
    let mut paths: Vec<(String, u16)> = Vec::new();
    for f in findings {
        if let Finding::WebPath { path, status } = f {
            paths.push((path.clone(), *status));
        }
    }
    if !paths.is_empty() {
        let h = touch_host(memory, &key);
        let surf = h.web_surface.get_or_insert_with(WebSurface::default);
        for (p, _st) in &paths {
            let entry = format!("GET {p}");
            if !surf.endpoints.contains(&entry) {
                surf.endpoints.push(entry);
                summary.web_paths += 1;
            }
        }
        surf.crawled_at = Some(Utc::now().to_rfc3339());
        let sample: Vec<&str> = paths.iter().take(5).map(|(p, _)| p.as_str()).collect();
        summary
            .highlights
            .push(format!("chemins: {}", sample.join(", ")));
    }

    // 3) Indices technologiques.
    let techs: Vec<String> = findings
        .iter()
        .filter_map(|f| {
            if let Finding::TechHint { tech } = f {
                Some(tech.clone())
            } else {
                None
            }
        })
        .collect();
    if !techs.is_empty() {
        let h = touch_host(memory, &key);
        let surf = h.web_surface.get_or_insert_with(WebSurface::default);
        for t in &techs {
            if !surf.tech_hints.contains(t) {
                surf.tech_hints.push(t.clone());
                summary.tech += 1;
            }
        }
        let sample: Vec<&str> = techs.iter().take(6).map(|s| s.as_str()).collect();
        summary
            .highlights
            .push(format!("techno: {}", sample.join(", ")));
    }

    // 4) Identifiants vérifiés → credentials de campagne.
    for f in findings {
        if let Finding::Secret {
            username,
            secret,
            service,
        } = f
        {
            let service = if service.is_empty() {
                "unknown".to_string()
            } else {
                service.clone()
            };
            memory.add_credential(Credential {
                id: uuid::Uuid::new_v4().to_string(),
                cred_type: CredentialType::Plaintext,
                username: Some(username.clone()),
                secret: secret.clone(),
                domain: None,
                source_host: key.clone(),
                service: service.clone(),
                valid_on: vec![key.clone()],
                harvested_at: Utc::now().to_rfc3339(),
            });
            summary.secrets += 1;
            summary
                .highlights
                .push(format!("{username}:<secret> ({service})"));
        }
    }

    // 5) Cassage de hash → identifiant (non rattaché à un hôte).
    for f in findings {
        if let Finding::CrackedSecret {
            identity,
            plaintext,
        } = f
        {
            memory.add_credential(Credential {
                id: uuid::Uuid::new_v4().to_string(),
                cred_type: CredentialType::Plaintext,
                username: Some(identity.clone()),
                secret: plaintext.clone(),
                domain: None,
                source_host: key.clone(),
                service: "hash".to_string(),
                valid_on: Vec::new(),
                harvested_at: Utc::now().to_rfc3339(),
            });
            summary.secrets += 1;
            summary.highlights.push(format!("hash cassé: {identity}"));
        }
    }

    // 6) SQLi confirmée → hypothèse validée (rouvre la voie à l'exploitation).
    for f in findings {
        if let Finding::SqlInjection { param, technique } = f {
            memory.record_hypothesis(&key, VulnClass::SqlInjection, true);
            let note = format!("SQLi confirmée param={param} ({technique})");
            if let Some(h) = memory.hosts.get_mut(&key) {
                push_note(h, &note);
            }
            summary.vulns += 1;
            summary.highlights.push(note);
        }
    }

    // 7) Avis / CVE + entrées brutes → notes de l'hôte.
    for f in findings {
        match f {
            Finding::Vuln { id, title } => {
                let h = touch_host(memory, &key);
                if id.to_uppercase().starts_with("CVE-") {
                    if !h.confirmed_cves.contains(id) {
                        h.confirmed_cves.push(id.clone());
                    }
                }
                push_note(
                    h,
                    &format!("{} : {}", if id.is_empty() { "avis" } else { id }, title),
                );
                summary.vulns += 1;
                if summary.highlights.len() < 12 {
                    summary.highlights.push(format!("{} {}", id, title));
                }
            }
            Finding::SnmpOid { oid, value } => {
                let h = touch_host(memory, &key);
                push_note(h, &format!("snmp {oid} = {value}"));
                summary.other += 1;
            }
            Finding::LdapEntry { dn } => {
                let h = touch_host(memory, &key);
                push_note(h, &format!("ldap {dn}"));
                summary.other += 1;
            }
            Finding::DnsRecord { name, kind, value } => {
                let h = touch_host(memory, &key);
                push_note(h, &format!("dns {kind} {name} → {value}"));
                summary.other += 1;
                if summary.highlights.len() < 12 {
                    summary.highlights.push(format!("dns {name}"));
                }
            }
            Finding::Account { username, service } => {
                let h = touch_host(memory, &key);
                push_note(h, &format!("compte valide {username} ({service})"));
                summary.other += 1;
                if summary.highlights.len() < 12 {
                    summary.highlights.push(format!("compte {username}"));
                }
            }
            _ => {}
        }
    }

    // 7bis) Hashs Kerberos / NTLM → using réutilisables (pass-the-hash, crack).
    for f in findings {
        match f {
            Finding::KerberosHash {
                username,
                hash,
                kind,
            } => {
                let (cred_type, service) = if kind == "asrep" {
                    (CredentialType::AsRepHash, "kerberos/asrep")
                } else {
                    (CredentialType::KerberosTgsHash, "kerberos/tgs")
                };
                memory.add_credential(Credential {
                    id: uuid::Uuid::new_v4().to_string(),
                    cred_type,
                    username: Some(username.clone()),
                    secret: hash.clone(),
                    domain: None,
                    source_host: key.clone(),
                    service: service.to_string(),
                    valid_on: Vec::new(),
                    harvested_at: Utc::now().to_rfc3339(),
                });
                summary.secrets += 1;
                summary
                    .highlights
                    .push(format!("hash kerberos {username} ({kind})"));
            }
            Finding::NtlmHash {
                username,
                domain,
                ntlm,
            } => {
                memory.add_credential(Credential {
                    id: uuid::Uuid::new_v4().to_string(),
                    cred_type: CredentialType::NtlmHash,
                    username: Some(username.clone()),
                    secret: ntlm.clone(),
                    domain: if domain.is_empty() {
                        None
                    } else {
                        Some(domain.clone())
                    },
                    source_host: key.clone(),
                    service: "ntlm".to_string(),
                    valid_on: Vec::new(),
                    harvested_at: Utc::now().to_rfc3339(),
                });
                summary.secrets += 1;
                summary
                    .highlights
                    .push(format!("hash NTLM {domain}\\{username}"));
            }
            _ => {}
        }
    }

    // 8) Trace d'audit dans la timeline.
    memory.log(
        "external_tool",
        "parse",
        Some(&key),
        if summary.is_empty() {
            "empty"
        } else {
            "success"
        },
        &summary.render(),
        "tool_parsers",
    );

    summary
}

// ── Parseurs individuels ─────────────────────────────────────────────────────

fn parse_nmap(out: &str) -> Vec<Finding> {
    // `80/tcp   open  http    Apache httpd 2.4.41`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re =
        RE.get_or_init(|| Regex::new(r"(?m)^(\d{1,5})/(tcp|udp)\s+open\s+(\S+)\s*(.*)$").unwrap());

    re.captures_iter(out)
        .filter_map(|c| {
            let port = c[1].parse::<u16>().ok()?;
            Some(Finding::Port {
                port,
                proto: c[2].to_string(),
                service: c[3].to_string(),
                version: c[4].trim().to_string(),
            })
        })
        .collect()
}

fn parse_ffuf(out: &str) -> Vec<Finding> {
    // `admin                   [Status: 200, Size: 1234, Words: 50, Lines: 10]`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?m)^\s*(\S+?)\s+\[Status:\s*(\d+),").unwrap());

    re.captures_iter(out)
        .filter_map(|c| {
            let path = c[1].trim();
            if path.is_empty() || path.contains("FUZZ") || path.starts_with("::") {
                return None;
            }
            Some(Finding::WebPath {
                path: path.to_string(),
                status: c[2].parse().unwrap_or(0),
            })
        })
        .collect()
}

fn parse_dir_brute(out: &str) -> Vec<Finding> {
    static GOBUSTER: OnceLock<Regex> = OnceLock::new();
    static FEROX: OnceLock<Regex> = OnceLock::new();
    static DIRB: OnceLock<Regex> = OnceLock::new();

    let gobuster =
        GOBUSTER.get_or_init(|| Regex::new(r"(?m)^\s*(\S+)\s+\(Status:\s*(\d+)\)").unwrap());
    let ferox = FEROX.get_or_init(|| {
        Regex::new(r"(?m)^\s*(\d{3})\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+(\S+)\s*$").unwrap()
    });
    let dirb = DIRB.get_or_init(|| Regex::new(r"(?m)^\+\s+(\S+)\s+\(CODE:(\d+)\|").unwrap());

    let mut out_findings = Vec::new();

    for c in gobuster.captures_iter(out) {
        let path = c[1].trim();
        if path.is_empty() || path.contains("FUZZ") {
            continue;
        }
        out_findings.push(Finding::WebPath {
            path: path.to_string(),
            status: c[2].parse().unwrap_or(0),
        });
    }
    for c in ferox.captures_iter(out) {
        out_findings.push(Finding::WebPath {
            path: c[2].to_string(),
            status: c[1].parse().unwrap_or(0),
        });
    }
    for c in dirb.captures_iter(out) {
        out_findings.push(Finding::WebPath {
            path: c[1].to_string(),
            status: c[2].parse().unwrap_or(0),
        });
    }

    out_findings
}

fn parse_sqlmap(out: &str) -> Vec<Finding> {
    // `[INFO] GET parameter 'id' is vulnerable. Do you want to keep testing...`
    static VULN: OnceLock<Regex> = OnceLock::new();
    static TYPE: OnceLock<Regex> = OnceLock::new();

    let vuln = VULN.get_or_init(|| Regex::new(r"(?i)parameter '([^']+)' is vulnerable").unwrap());
    let typ = TYPE.get_or_init(|| Regex::new(r"(?m)^\s+Type:\s*(.+?)\s*$").unwrap());

    let technique: String = typ
        .captures_iter(out)
        .map(|c| c[1].to_string())
        .take(2)
        .collect::<Vec<_>>()
        .join(" / ");

    vuln.captures_iter(out)
        .map(|c| Finding::SqlInjection {
            param: c[1].to_string(),
            technique: technique.clone(),
        })
        .collect()
}

fn parse_hydra(out: &str) -> Vec<Finding> {
    // `[22][ssh] host: 10.0.0.1   login: root   password: toor`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?m)^\[(\d+)\]\[([\w-]+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(.+?)\s*$",
        )
        .unwrap()
    });

    re.captures_iter(out)
        .map(|c| Finding::Secret {
            username: c[4].to_string(),
            secret: c[5].to_string(),
            service: c[2].to_string(),
        })
        .collect()
}

fn parse_john(out: &str) -> Vec<Finding> {
    // `password123      (username)`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?m)^(\S+)\s+\(([^)]+)\)\s*$").unwrap());

    re.captures_iter(out)
        .map(|c| Finding::CrackedSecret {
            identity: c[2].trim().to_string(),
            plaintext: c[1].to_string(),
        })
        .collect()
}

fn parse_hashcat(out: &str) -> Vec<Finding> {
    // `5f4dcc3b5aa765d61d8327deb882cf99:password`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?m)^([0-9a-fA-F]{16,}):(.+?)\s*$").unwrap());

    re.captures_iter(out)
        .map(|c| Finding::CrackedSecret {
            identity: c[1].to_string(),
            plaintext: c[2].to_string(),
        })
        .collect()
}

fn parse_snmp(out: &str) -> Vec<Finding> {
    static NUM: OnceLock<Regex> = OnceLock::new();
    static MIB: OnceLock<Regex> = OnceLock::new();

    let num = NUM.get_or_init(|| {
        Regex::new(r"(?m)^(?:iso\.|\.)?([0-9][0-9.]*)\s*=\s*(?:(\w+):)?\s*(.*)$").unwrap()
    });
    let mib = MIB
        .get_or_init(|| Regex::new(r"(?m)^([A-Za-z0-9-]+::[\w.]+)\s*=\s*(\w+):\s*(.*)$").unwrap());

    let mut findings = Vec::new();
    for c in num.captures_iter(out) {
        findings.push(Finding::SnmpOid {
            oid: c[1].to_string(),
            value: c[3].trim().to_string(),
        });
    }
    for c in mib.captures_iter(out) {
        findings.push(Finding::SnmpOid {
            oid: c[1].to_string(),
            value: c[3].trim().to_string(),
        });
    }
    findings
}

fn parse_ldap(out: &str) -> Vec<Finding> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?m)^dn:\s*(.+?)\s*$").unwrap());

    re.captures_iter(out)
        .map(|c| Finding::LdapEntry {
            dn: c[1].to_string(),
        })
        .collect()
}

fn parse_nikto(out: &str) -> Vec<Finding> {
    // `+ OSVDB-3092: /admin/: This might be interesting...`
    static OSVDB: OnceLock<Regex> = OnceLock::new();
    static PATH: OnceLock<Regex> = OnceLock::new();

    let osvdb = OSVDB.get_or_init(|| Regex::new(r"(?m)^\+\s+(OSVDB-\d+):\s*(.+?)\s*$").unwrap());
    let path = PATH.get_or_init(|| Regex::new(r"(?m)^\+\s+(/[^\s:]+):?\s*(.*)$").unwrap());

    let noise = [
        "Target IP",
        "Target Hostname",
        "Target Port",
        "Start Time",
        "End Time",
        "Server",
    ];

    let mut findings: Vec<Finding> = osvdb
        .captures_iter(out)
        .map(|c| Finding::Vuln {
            id: c[1].to_string(),
            title: c[2].to_string(),
        })
        .collect();

    for c in path.captures_iter(out) {
        let p = c[1].to_string();
        if noise.iter().any(|n| p.starts_with(n)) {
            continue;
        }
        findings.push(Finding::Vuln {
            id: p,
            title: c[2].trim().to_string(),
        });
    }
    findings
}

fn parse_whatweb(out: &str) -> Vec<Finding> {
    // `http://x [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx], IP[10.0.0.1]`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?m)^\S+\s+\[\d+\s+\w+\]\s+(.+)$").unwrap());

    let mut findings = Vec::new();
    for c in re.captures_iter(out) {
        for token in c[1].split(',') {
            let name = token.trim().split('[').next().unwrap_or("").trim();
            // On ignore les méta-champs peu utiles au raisonnement.
            if name.is_empty() || matches!(name, "Country" | "IP" | "Title" | "UncommonHeaders") {
                continue;
            }
            findings.push(Finding::TechHint {
                tech: name.to_string(),
            });
        }
    }
    findings
}

fn parse_smb_cme(out: &str) -> Vec<Finding> {
    // `SMB  10.0.0.1  445  DC01  [+] DOMAIN\admin:Password123 (Pwn3d!)`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE
        .get_or_init(|| Regex::new(r"(?m)^\S+\s+\S+\s+\d+\s+\S+\s+\[\+\]\s+(\S+):(\S+)").unwrap());

    let mut findings = Vec::new();
    for c in re.captures_iter(out) {
        let user_full = c[1].to_string();
        let username = user_full
            .rsplit('\\')
            .next()
            .unwrap_or(&user_full)
            .to_string();
        let secret = c[2].split_whitespace().next().unwrap_or(&c[2]).to_string();
        findings.push(Finding::Secret {
            username,
            secret,
            service: "smb".to_string(),
        });

        if out.contains("Pwn3d!") {
            findings.push(Finding::Vuln {
                id: "smb-admin".to_string(),
                title: format!("accès administrateur SMB ({user_full})"),
            });
        }
    }
    findings
}

fn parse_nuclei(out: &str) -> Vec<Finding> {
    // `[cve-2021-44228] [http] [critical] https://cible/chemin`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?m)^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)\s*$").unwrap()
    });

    re.captures_iter(out)
        .map(|c| {
            let id = c.get(1).map(|m| m.as_str()).unwrap_or("");
            let proto = c.get(2).map(|m| m.as_str()).unwrap_or("");
            let sev = c.get(3).map(|m| m.as_str()).unwrap_or("");
            let url = c.get(4).map(|m| m.as_str()).unwrap_or("");
            Finding::Vuln {
                id: id.to_string(),
                title: format!("[{sev}] {proto} — {url}"),
            }
        })
        .collect()
}

fn parse_wpscan(out: &str) -> Vec<Finding> {
    // `[+] WordPress version 5.8 identified`, `[!] No WAF detected`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?m)^\[([!+])\]\s+(.+?)\s*$").unwrap());

    re.captures_iter(out)
        .map(|c| Finding::Vuln {
            id: if &c[1] == "!" {
                "wpscan-alerte".to_string()
            } else {
                String::new()
            },
            title: c[2].to_string(),
        })
        .collect()
}

fn parse_dns(out: &str) -> Vec<Finding> {
    // dnsrecon : `[*] \t A example.com 93.184.216.34`
    static STAR: OnceLock<Regex> = OnceLock::new();
    // zone file : `example.com. 300 IN MX mail.example.com`
    static RR: OnceLock<Regex> = OnceLock::new();

    let star = STAR.get_or_init(|| {
        Regex::new(r"(?m)^\[\*\]\s+(A|AAAA|CNAME|MX|NS|TXT|SOA|PTR|SRV)\s+(\S+)\s+(\S+)").unwrap()
    });
    let rr = RR.get_or_init(|| {
        Regex::new(r"(?m)^(\S+?)\.?\s+\d+\s+IN\s+(A|AAAA|CNAME|MX|NS|TXT|SOA|PTR|SRV)\s+(\S+)")
            .unwrap()
    });

    let mut findings = Vec::new();
    for c in star.captures_iter(out) {
        findings.push(Finding::DnsRecord {
            name: c[2].to_string(),
            kind: c[1].to_string(),
            value: c[3].to_string(),
        });
    }
    for c in rr.captures_iter(out) {
        findings.push(Finding::DnsRecord {
            name: c[1].to_string(),
            kind: c[2].to_string(),
            value: c[3].to_string(),
        });
    }
    findings
}

fn parse_kerbrute(out: &str) -> Vec<Finding> {
    // `[+] VALID USERNAME:	admin@corp.local`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?m)^\[\+\]\s+VALID USERNAME:\s+([^@\s]+)").unwrap());

    re.captures_iter(out)
        .map(|c| Finding::Account {
            username: c[1].to_string(),
            service: "kerberos".to_string(),
        })
        .collect()
}

fn parse_kerberos_tgs(out: &str) -> Vec<Finding> {
    // `$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/dc:1433*$A1B2…`
    static LINE: OnceLock<Regex> = OnceLock::new();
    static USER: OnceLock<Regex> = OnceLock::new();

    let line = LINE.get_or_init(|| Regex::new(r"(?m)^(\$krb5tgs\$[^\r\n]+)").unwrap());
    let user = USER.get_or_init(|| Regex::new(r"^\$krb5tgs\$\d+\$\*([^$]+)\$").unwrap());

    line.captures_iter(out)
        .map(|c| {
            let hash = c[1].trim().to_string();
            let username = user
                .captures(&hash)
                .map(|u| u[1].to_string())
                .unwrap_or_default();
            Finding::KerberosHash {
                username,
                hash,
                kind: "tgs".to_string(),
            }
        })
        .collect()
}

fn parse_kerberos_asrep(out: &str) -> Vec<Finding> {
    // `$krb5asrep$23$svc@CORP.LOCAL:1a2b3c…`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re =
        RE.get_or_init(|| Regex::new(r"(?m)^(\$krb5asrep\$\d+\$([^@\s$]+)@[^\r\n]+)").unwrap());

    re.captures_iter(out)
        .map(|c| Finding::KerberosHash {
            username: c[2].to_string(),
            hash: c[1].trim().to_string(),
            kind: "asrep".to_string(),
        })
        .collect()
}

fn parse_secretsdump(out: &str) -> Vec<Finding> {
    // Passes uniques, dans l'ordre du flux :
    //   `CORP\Administrator:500:aad3b435…:31d6cfe0…:::`
    //   `Administrator:500:aad3b435…:31d6cfe0…:::`
    // Le préfixe `DOMAINE\` est optionnel et capturé séparément.
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?m)^(?:([^\s:\\]+)\\)?([^:]+):\d+:[0-9a-fA-F]{32}:([0-9a-fA-F]{32}):::")
            .unwrap()
    });

    re.captures_iter(out)
        .map(|c| Finding::NtlmHash {
            username: c[2].to_string(),
            domain: c.get(1).map(|m| m.as_str()).unwrap_or("").to_string(),
            ntlm: c[3].to_string(),
        })
        .collect()
}

fn parse_smtp_enum(out: &str) -> Vec<Finding> {
    // `root@example.com	exists`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?m)^([A-Za-z0-9._-]+)@\S+\s+exists\s*$").unwrap());

    re.captures_iter(out)
        .map(|c| Finding::Account {
            username: c[1].to_string(),
            service: "smtp".to_string(),
        })
        .collect()
}

fn parse_searchsploit(out: &str) -> Vec<Finding> {
    // `Apache 2.4.49 - Path Traversal               | multiple/remote/50383.py`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?m)^(.+?)\s+\|\s+(\S+\.\w+)\s*$").unwrap());

    re.captures_iter(out)
        .filter_map(|c| {
            let title = c[1].trim();
            if title.is_empty()
                || title.chars().all(|ch| ch == '-')
                || title.eq_ignore_ascii_case("Title")
            {
                return None;
            }
            Some(Finding::Vuln {
                id: c[2].to_string(),
                title: title.to_string(),
            })
        })
        .collect()
}

fn parse_gowitness(out: &str) -> Vec<Finding> {
    // `[+] https://cible/ (200 OK) - 123ms`
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?m)^\[\+\]\s+(https?://\S+)\s*\((\d{3})").unwrap());

    re.captures_iter(out)
        .map(|c| Finding::WebPath {
            path: c[1].to_string(),
            status: c[2].parse().unwrap_or(0),
        })
        .collect()
}

// ── Aides internes ───────────────────────────────────────────────────────────

/// Nom de base du binaire (sans chemin ni extension Windows).
fn tool_basename(tool: &str) -> String {
    tool.rsplit(['/', '\\'])
        .next()
        .unwrap_or(tool)
        .to_lowercase()
        .trim_end_matches(".exe")
        .to_string()
}

/// Récupère (ou crée) l'entrée d'hôte et renvoie une référence mutable.
fn touch_host<'a>(memory: &'a mut CampaignMemory, key: &str) -> &'a mut HostMemory {
    if !memory.hosts.contains_key(key) {
        memory.add_host(key, Vec::new());
    }
    memory
        .hosts
        .get_mut(key)
        .expect("l'hôte vient d'être inséré")
}

/// Ajoute une note en gardant la liste bornée (`MAX_NOTES`).
fn push_note(h: &mut HostMemory, note: &str) {
    if h.notes.iter().any(|n| n == note) {
        return;
    }
    if h.notes.len() >= MAX_NOTES {
        h.notes.remove(0);
    }
    h.notes.push(note.to_string());
    h.last_updated = Utc::now().to_rfc3339();
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_extrait_les_ports_ouverts() {
        let out = "\
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1
80/tcp   open  http     Apache httpd 2.4.41
443/tcp  closed https
";
        let f = parse("nmap", out, "10.0.0.1");
        assert_eq!(f.len(), 2);
        match &f[0] {
            Finding::Port { port, service, .. } => {
                assert_eq!(*port, 22);
                assert_eq!(service, "ssh");
            }
            other => panic!("attendu Port, obtenu {other:?}"),
        }
    }

    #[test]
    fn hydra_extrait_identifiants() {
        let out = "[22][ssh] host: 10.0.0.1   login: root   password: toor\n";
        let f = parse("hydra", out, "10.0.0.1");
        assert_eq!(
            f,
            vec![Finding::Secret {
                username: "root".into(),
                secret: "toor".into(),
                service: "ssh".into(),
            }]
        );
    }

    #[test]
    fn ffuf_ignore_la_ligne_progress() {
        let out = "\
:: Progress: [100/100] :: Job [1/1] :: 0 req/sec :: Elapsed: 00:00:01 ::
admin                   [Status: 200, Size: 1234, Words: 50, Lines: 10]
login                   [Status: 302, Size: 0, Words: 1, Lines: 1]
";
        let f = parse("ffuf", out, "10.0.0.1");
        assert_eq!(f.len(), 2);
        assert_eq!(
            f[0],
            Finding::WebPath {
                path: "admin".into(),
                status: 200
            }
        );
    }

    #[test]
    fn gobuster_extrait_les_chemins() {
        let out = "/admin                (Status: 200) [Size: 123]\n/index.html           (Status: 200) [Size: 42]\n";
        let f = parse("gobuster", out, "10.0.0.1");
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn sqlmap_detecte_parametre_vulnerable() {
        let out = "\
[INFO] testing connection to the target URL
[INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others?
    Type: boolean-based blind
";
        let f = parse("sqlmap", out, "10.0.0.1");
        assert_eq!(f.len(), 1);
        match &f[0] {
            Finding::SqlInjection { param, .. } => assert_eq!(param, "id"),
            other => panic!("attendu SqlInjection, obtenu {other:?}"),
        }
    }

    #[test]
    fn john_extrait_les_secrets_casses() {
        let out = "password123      (admin)\nletmein          (bob)\n";
        let f = parse("john", out, "10.0.0.1");
        assert_eq!(f.len(), 2);
        assert_eq!(
            f[0],
            Finding::CrackedSecret {
                identity: "admin".into(),
                plaintext: "password123".into()
            }
        );
    }

    #[test]
    fn snmpwalk_extrait_les_oid() {
        let out =
            ".1.3.6.1.2.1.1.5.0 = STRING: router.local\niso.3.6.1.2.1.1.1.0 = STRING: Linux\n";
        let f = parse("snmpwalk", out, "10.0.0.1");
        assert_eq!(f.len(), 2);
        match &f[0] {
            Finding::SnmpOid { oid, value } => {
                assert_eq!(oid, "1.3.6.1.2.1.1.5.0");
                assert_eq!(value, "router.local");
            }
            other => panic!("attendu SnmpOid, obtenu {other:?}"),
        }
    }

    #[test]
    fn nxc_extrait_identifiants_et_pwn3d() {
        let out = "SMB  10.0.0.1  445  DC01  [+] CORP\\admin:Password123 (Pwn3d!)\n";
        let f = parse("nxc", out, "10.0.0.1");
        assert!(f
            .iter()
            .any(|x| matches!(x, Finding::Secret { username, .. } if username == "admin")));
        assert!(f.iter().any(|x| matches!(x, Finding::Vuln { .. })));
    }

    #[test]
    fn nuclei_extrait_les_templates() {
        let out = "[cve-2021-44228] [http] [critical] https://cible/api\n[tech-detect:nginx] [http] [info] https://cible/\n";
        let f = parse("nuclei", out, "10.0.0.1");
        assert_eq!(f.len(), 2);
        match &f[0] {
            Finding::Vuln { id, .. } => assert_eq!(id, "cve-2021-44228"),
            other => panic!("attendu Vuln, obtenu {other:?}"),
        }
    }

    #[test]
    fn secretsdump_extrait_les_hash_ntlm() {
        let out = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\nCORP\\svc$:1001:aad3b435b51404eeaad3b435b51404ee:1a2b3c4d5e6f708192a3b4c5d6e7f809:::\n";
        let f = parse("impacket-secretsdump", out, "10.0.0.1");
        assert_eq!(f.len(), 2);
        match &f[0] {
            Finding::NtlmHash {
                username,
                domain,
                ntlm,
            } => {
                assert_eq!(username, "Administrator");
                assert!(domain.is_empty());
                assert_eq!(ntlm, "31d6cfe0d16ae931b73c59d7e0c089c0");
            }
            other => panic!("attendu NtlmHash, obtenu {other:?}"),
        }
        match &f[1] {
            Finding::NtlmHash {
                username, domain, ..
            } => {
                assert_eq!(username, "svc$");
                assert_eq!(domain, "CORP");
            }
            other => panic!("attendu NtlmHash, obtenu {other:?}"),
        }
    }

    #[test]
    fn kerberos_tgs_et_asrep() {
        let tgs = "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/dc.corp.local:1433*$A1B2C3D4E5F6\n";
        let f = parse("impacket-GetUserSPNs", tgs, "10.0.0.1");
        assert_eq!(
            f,
            vec![Finding::KerberosHash {
                username: "svc_sql".into(),
                hash: tgs.trim().into(),
                kind: "tgs".into(),
            }]
        );

        let asrep = "$krb5asrep$23$jdoe@CORP.LOCAL:1a2b3c4d5e6f\n";
        let f = parse("impacket-GetNPUsers", asrep, "10.0.0.1");
        assert_eq!(
            f,
            vec![Finding::KerberosHash {
                username: "jdoe".into(),
                hash: asrep.trim().into(),
                kind: "asrep".into(),
            }]
        );
    }

    #[test]
    fn dnsrecon_et_zone_produisent_des_enregistrements() {
        let out = "\
[*] \t A example.com 93.184.216.34
[*] \t MX example.com mail.example.com
example.com.\t300\tIN\tNS\tns1.example.com.
";
        let f = parse("dnsrecon", out, "example.com");
        assert_eq!(f.len(), 3);
        assert_eq!(
            f[0],
            Finding::DnsRecord {
                name: "example.com".into(),
                kind: "A".into(),
                value: "93.184.216.34".into(),
            }
        );
    }

    #[test]
    fn dnsrecon_ignore_les_lignes_de_progression() {
        let out = "[*] Performing General Enumeration of Domain: example.com\n";
        assert!(parse("dnsrecon", out, "example.com").is_empty());
    }

    #[test]
    fn searchsploit_extrait_titre_et_chemin() {
        let out = "\
------------------------------------------- ---------------------------------
 Title                                     | Path
------------------------------------------- ---------------------------------
 Apache 2.4.49 - Path Traversal            | multiple/remote/50383.py
";
        let f = parse("searchsploit", out, "apache");
        assert_eq!(f.len(), 1);
        match &f[0] {
            Finding::Vuln { id, title } => {
                assert_eq!(id, "multiple/remote/50383.py");
                assert_eq!(title, "Apache 2.4.49 - Path Traversal");
            }
            other => panic!("attendu Vuln, obtenu {other:?}"),
        }
    }

    #[test]
    fn smtp_enum_et_kerbrute_donnent_des_comptes() {
        let f = parse(
            "smtp-user-enum",
            "root@example.com\texists\nnobody@example.com\tdoes not exist\n",
            "10.0.0.1",
        );
        assert_eq!(
            f,
            vec![Finding::Account {
                username: "root".into(),
                service: "smtp".into()
            }]
        );

        let f = parse(
            "kerbrute",
            "[+] VALID USERNAME:\tadmin@corp.local\n",
            "10.0.0.1",
        );
        assert_eq!(
            f,
            vec![Finding::Account {
                username: "admin".into(),
                service: "kerberos".into()
            }]
        );
    }

    #[test]
    fn outil_inconnu_ne_produit_rien() {
        assert!(parse("totally-unknown-tool", "du bruit\n", "10.0.0.1").is_empty());
    }
}
