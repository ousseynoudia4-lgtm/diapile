//! DIAPILE — OSINT Module
//!
//! Reconnaissance passive : sous-domaines, GitHub leaks, Shodan, crt.sh, HIBP.
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::time::Duration;

#[doc(hidden)]
pub use crate::live_dashboard::{
    DashboardEmitter, OsintEdgeKind, OsintGraphDelta, OsintGraphEdge, OsintGraphNode,
    OsintGraphSnapshot, OsintGraphStats, OsintNodeKind,
};

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintReport {
    pub target: String,
    pub subdomains: Vec<SubdomainEntry>,
    pub emails: Vec<String>,
    pub breaches: Vec<BreachEntry>,
    pub technologies: Vec<String>,
    pub open_ports: Vec<ShodanResult>,
    pub cert_domains: Vec<String>,
    pub github_leaks: Vec<GithubLeak>,
    pub dns_records: Vec<DnsRecord>,
    pub intelligence: Option<OsintIntelligence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintIntelligence {
    pub summary: String,
    pub high_value_targets: Vec<String>,
    pub attack_scenarios: Vec<String>,
    pub correlation_notes: Vec<String>,
    pub recommended_next_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainEntry {
    pub subdomain: String,
    pub ip: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachEntry {
    pub email: String,
    pub breach_name: String,
    pub breach_date: String,
    pub data_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanResult {
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubLeak {
    pub repo: String,
    pub file_path: String,
    pub leak_type: String,
    pub snippet: String,
    pub commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Normalisation du domaine cible
// ─────────────────────────────────────────────────────────────────────────────

/// Normalise un nom de domaine pour OSINT.
///
/// Règles appliquées systématiquement :
///   - trim espaces + to_lowercase
///   - retire protocole (http:// https:// ftp:// ...)
///   - retire paths/ports finaux
///   - retire préfixes sous-domaine parasites : `www.`, `wwww.`, `www2.`, `*.`
///   - retire une seconde fois si besoin (ex: www.admin.example.com → admin.example.com)
///
/// Exemples :
///   "https://www.example.org/path?x=1"     → "example.org"
///   "www.example.org"                       → "example.org"
///   "http://*.admin.www.example.org:8443/"  → "admin.example.org"
///   "example.org"                           → "example.org"
pub fn normalize_domain(raw: &str) -> String {
    let mut s = raw.trim().to_lowercase();
    // Protocole
    if let Some(i) = s.find("://") {
        s = s.split_off(i + 3);
    }
    // Slash / path final
    if let Some(i) = s.find('/') {
        s.truncate(i);
    }
    // Port (après path car https://host:port/path — port est avant slash)
    // Donc refaire un find port sur ce qui reste
    if let Some(i) = s.find(':') {
        s.truncate(i);
    }
    // Trim trailing . (FQDN absolu)
    while s.ends_with('.') {
        s.pop();
    }

    // Retrait des labels parasites OÙ QU'ILS SOIENT (pas seulement en préfixe),
    // conformément à la doc : "*.admin.www.example.org" → "admin.example.org".
    const PARASITES: [&str; 8] = ["www", "www2", "www3", "wwww", "web", "m", "mobile", "*"];
    let cleaned: Vec<&str> = s
        .split('.')
        .filter(|lbl| !lbl.is_empty() && !PARASITES.contains(lbl))
        .collect();
    if cleaned.is_empty() {
        return s;
    }
    cleaned.join(".")
}
#[cfg(test)]
mod tests_normalize {
    use super::*;
    #[test]
    fn test_normalize_domain_cases() {
        assert_eq!(normalize_domain("www.example.org"), "example.org");
        assert_eq!(
            normalize_domain("https://www.example.org/path?q=1"),
            "example.org"
        );
        assert_eq!(
            normalize_domain("HTTP://WWW2.ADMIN.WWW.EXAMPLE.ORG:443/"),
            "admin.example.org"
        );
        assert_eq!(normalize_domain("*.www.example.org."), "example.org");
        assert_eq!(normalize_domain("http://example.org"), "example.org");
        assert_eq!(normalize_domain("  m.example.org  "), "example.org");
    }

    // Validation de la logique d'acceptation crt.sh — reproduit le comportement runtime
    // sans appel réseau. Domaines réservés IANA : example.org / example.net (neutres).
    #[test]
    fn test_crt_subdomain_acceptance_logic() {
        let domain = normalize_domain("example.org");
        assert_eq!(domain, "example.org");

        // Cas OK (doivent être acceptés)
        let valides = [
            "www.example.org",
            "portal.example.org",
            "moodle.example.org",
            "vpn.example.org",
            "mail.example.org",
            "ns1.example.org",
            "*.admin.example.org",
            "EXAMPLE.ORG",
            "  Intranet.example.org  ",
            ".backup.example.org.",
            "dev.apps.example.org",
            "example.org",
        ];
        for raw in valides.iter() {
            let clean = raw
                .trim()
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_lowercase();
            let ok = clean.ends_with(&format!(".{}", domain)) || clean == domain;
            assert!(ok, "aurait dû être accepté: {} → {}", raw, clean);
        }

        // Cas invalides (ne doivent PAS être acceptés — falsification/FP)
        let invalides = [
            "notexample.org",
            "hacked-example.shop",
            "example.org.attacker.com",
            "x.com",
            "lexample.org",
            "fexample.org",
        ];
        for raw in invalides.iter() {
            let clean = raw
                .trim()
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_lowercase();
            let ok = clean.ends_with(&format!(".{}", domain)) || clean == domain;
            assert!(!ok, "aurait dû être REJETÉ: {} → {}", raw, clean);
        }
    }

    // Même logique sur un deuxième domaine neutre (example.net)
    #[test]
    fn test_crt_subdomain_acceptance_secondary() {
        let domain = normalize_domain("example.net");
        assert_eq!(domain, "example.net");
        let cas = [
            "admin.example.net",
            "www.example.net",
            "monitor.example.net",
            "research.example.net",
            "internal.example.net",
            "example.net",
        ];
        for raw in cas.iter() {
            let clean = raw
                .trim()
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_lowercase();
            let ok = clean.ends_with(&format!(".{}", domain)) || clean == domain;
            assert!(ok, "échec pour {}", raw);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Résolveur DNS-over-HTTPS JSON (zero dep — via Cloudflare 1.1.1.1)
// Fallback : `std::net::ToSocketAddrs` pour A/AAAA.
// ─────────────────────────────────────────────────────────────────────────────

/// Requête Cloudflare DoH JSON, retourne le champ "Answer" → (type, data)
async fn doh_answer(domain: &str, record_type: &str) -> Vec<(u16, String)> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .user_agent("NRTG-RedTeam/2.0")
        .build()
        .unwrap_or_default();
    let url = format!(
        "https://1.1.1.1/dns-query?name={}&type={}",
        urlencoding::encode(domain),
        record_type
    );
    let resp = match client
        .get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Some(arr) = json.get("Answer").and_then(|a| a.as_array()) {
        for e in arr {
            let t = e.get("type").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
            let d = e
                .get("data")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if !d.is_empty() {
                out.push((t, d));
            }
        }
    }
    out
}

// Code DNS RR (https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
const RR_A: u16 = 1;
const RR_NS: u16 = 2;
const RR_CNAME: u16 = 5;
const RR_SOA: u16 = 6;
const RR_MX: u16 = 15;
const RR_TXT: u16 = 16;
const RR_AAAA: u16 = 28;
const RR_CAA: u16 = 257;

fn rr_name(code: u16) -> &'static str {
    match code {
        RR_A => "A",
        RR_NS => "NS",
        RR_CNAME => "CNAME",
        RR_SOA => "SOA",
        RR_MX => "MX",
        RR_TXT => "TXT",
        RR_AAAA => "AAAA",
        RR_CAA => "CAA",
        _ => "RR",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// crt.sh — Certificate Transparency subdomain enumeration
// ─────────────────────────────────────────────────────────────────────────────

/// Récupère les sous-domaines via crt.sh (Certificate Transparency)
/// Stratégie robuste :
///   1. Requête JSON principale `%.domain`
///   2. Fallback 1 : requête exacte `domain`
///   3. Fallback 2 : URL alternative `identity=` au cas où `q=` est filtré
pub async fn crtsh_subdomains(domain: &str) -> Vec<SubdomainEntry> {
    let domain = normalize_domain(domain);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
        .build()
        .unwrap_or_default();

    let endpoints = [
        format!("https://crt.sh/?q=%.{}&output=json", domain),
        format!("https://crt.sh/?q={}&output=json", domain),
        format!("https://crt.sh/?identity=%25.{}&output=json", domain),
    ];

    let mut entries_raw: Vec<serde_json::Value> = Vec::new();
    let mut last_error: Option<String> = None;

    for url in &endpoints {
        let resp = match client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                last_error = Some(format!("{}", e));
                continue;
            }
        };
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
            entries_raw.extend(arr);
            if !entries_raw.is_empty() {
                break;
            }
        }
    }

    if entries_raw.is_empty() {
        if let Some(e) = last_error {
            println!(
                "  \x1b[33m[crt.sh] ⚠ Aucun résultat — dernière erreur: {}\x1b[0m",
                e
            );
        } else {
            println!(
                "  \x1b[33m[crt.sh] ⚠ Aucune entrée CT retournée (0 certs pour {})\x1b[0m",
                domain
            );
        }
        return Vec::new();
    }

    let mut seen: HashSet<String> = HashSet::new();
    let mut results = Vec::new();

    for entry in &entries_raw {
        let names = entry["name_value"].as_str().unwrap_or("");
        for name in names.split(['\n', ',', ';']) {
            let clean = name
                .trim()
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_lowercase();
            if clean.is_empty() {
                continue;
            }
            // Validation stricte : doit finir par ".domain" OU être égal à "domain"
            let is_sub = clean.ends_with(&format!(".{}", domain)) || clean == domain;
            if is_sub && seen.insert(clean.clone()) {
                results.push(SubdomainEntry {
                    subdomain: clean,
                    ip: None,
                    source: "crt.sh".into(),
                });
            }
        }
    }

    results.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS Resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Résout des sous-domaines via **DoH Cloudflare concurrent (A+AAAA)** puis
/// fallback `ToSocketAddrs` stdlib si DoH échoue. Stratégie furtive, indépendante
/// du résolveur local/FAI. Garde les entrées sans IP (valeur passive CT).
pub async fn resolve_subdomains(entries: &mut Vec<SubdomainEntry>) {
    use futures::StreamExt;
    use std::net::ToSocketAddrs;

    println!(
        "  {}· résolution DoH Cloudflare concurrente ({} entrées){}",
        "\x1b[90m",
        entries.len(),
        "\x1b[0m"
    );

    let results: Vec<(usize, Option<String>)> = futures::stream::iter(entries.iter().enumerate())
        .map(|(idx, entry)| {
            let sub = entry.subdomain.clone();
            let source = entry.source.clone();
            async move {
                // 1) DoH A record (timeout 3s — rapide)
                let ans_a = tokio::time::timeout(Duration::from_secs(3), doh_answer(&sub, "A"))
                    .await
                    .unwrap_or_default();
                let a_ip: Option<String> = ans_a
                    .iter()
                    .filter(|(t, _)| *t == RR_A)
                    .map(|(_, d)| d.clone())
                    .next();

                if let Some(ip) = a_ip {
                    if source != "dns-brute" {
                        println!(
                            "  {}[DoH]{} {} → {}  {}[{}]{}",
                            "\x1b[32m", "\x1b[0m", sub, ip, "\x1b[90m", source, "\x1b[0m"
                        );
                    }
                    return (idx, Some(ip));
                }

                // 2) DoH AAAA fallback
                let ans_aaaa =
                    tokio::time::timeout(Duration::from_secs(2), doh_answer(&sub, "AAAA"))
                        .await
                        .unwrap_or_default();
                let aaaa_ip: Option<String> = ans_aaaa
                    .iter()
                    .filter(|(t, _)| *t == RR_AAAA)
                    .map(|(_, d)| d.clone())
                    .next();

                if let Some(ip) = aaaa_ip {
                    if source != "dns-brute" {
                        println!(
                            "  {}[DoH]{} {} → {}  {}[{}]{}",
                            "\x1b[32m", "\x1b[0m", sub, ip, "\x1b[90m", source, "\x1b[0m"
                        );
                    }
                    return (idx, Some(ip));
                }

                // 3) Fallback stdlib (si DoH Cloudflare est temporairement bloqué)
                let addr = format!("{}:443", sub);
                if let Ok(mut addrs) = addr.to_socket_addrs() {
                    if let Some(a) = addrs.next() {
                        return (idx, Some(a.ip().to_string()));
                    }
                }
                (idx, None)
            }
        })
        .buffer_unordered(32)
        .collect()
        .await;

    // Appliquer les IPs résolues aux entrées
    let n_ok = results.iter().filter(|(_, ip)| ip.is_some()).count();
    for (idx, ip_opt) in results {
        if ip_opt.is_none() {
            continue;
        }
        if let Some(entry) = entries.get_mut(idx) {
            entry.ip = ip_opt;
        }
    }
    println!(
        "  {}· {} sous-domaines résolus sur {} testés{}",
        "\x1b[90m",
        n_ok,
        entries.len(),
        "\x1b[0m"
    );
}

/// Récupère les enregistrements DNS de base pour un domaine
pub fn get_dns_commands(domain: &str) -> Vec<String> {
    vec![
        format!("dig A {}", domain),
        format!("dig AAAA {}", domain),
        format!("dig MX {}", domain),
        format!("dig NS {}", domain),
        format!("dig TXT {}", domain),
        format!("dig SOA {}", domain),
        format!("dig AXFR {}", domain), // Zone transfer attempt
        format!("host -t any {}", domain),
        format!("nslookup -type=any {}", domain),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// HaveIBeenPwned — Breach check
// ─────────────────────────────────────────────────────────────────────────────

/// Vérifie si un email est dans des données de breach via HIBP API v3
pub async fn check_hibp(email: &str, api_key: Option<&str>) -> Vec<BreachEntry> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("NRTG-RedTeam/2.0")
        .build()
        .unwrap_or_default();

    let url = format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false",
        email
    );
    let req = client
        .get(&url)
        .header("hibp-api-key", api_key.unwrap_or(""))
        .header("User-Agent", "NRTG-RedTeam/2.0");

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  [HIBP] Error: {}", e);
            return Vec::new();
        }
    };

    if resp.status() == 404 {
        return Vec::new();
    } // No breach

    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let mut breaches = Vec::new();
    if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
        for e in &entries {
            let data_classes = e["DataClasses"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            breaches.push(BreachEntry {
                email: email.to_string(),
                breach_name: e["Name"].as_str().unwrap_or("?").to_string(),
                breach_date: e["BreachDate"].as_str().unwrap_or("?").to_string(),
                data_types: data_classes,
            });
        }
    }

    breaches
}

// ─────────────────────────────────────────────────────────────────────────────
// GitHub leak detection
// ─────────────────────────────────────────────────────────────────────────────

/// Recherche des leaks GitHub pour un domaine/organisation
pub async fn github_search(query: &str, api_key: Option<&str>) -> Vec<GithubLeak> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("NRTG-RedTeam/2.0")
        .build()
        .unwrap_or_default();

    // Recherche avec guillemets pour match exact du domaine, + filtre sur extension
    let search_queries = [
        format!("\"{}\" password", query),
        format!("\"{}\" api_key", query),
        format!("\"{}\" secret", query),
        format!("\"{}\" token", query),
        format!("\"{}\" private_key", query),
    ];

    // Extensions de fichiers à exclure (listes de domaines, blocklists, etc.)
    let excluded_extensions = [".txt", ".list", ".blk", ".filter"];
    let excluded_path_keywords = [
        "porn",
        "domain",
        "blocklist",
        "allowlist",
        "adblock",
        "hosts",
    ];
    // Mots-clés de snippet qui indiquent un faux positif (liste de domaines)
    let fp_snippet_keywords = ["#", "0.0.0.0", "127.0.0.1", "::1", "||", "@@"];

    let mut leaks = Vec::new();
    let mut seen = std::collections::HashSet::new(); // déduplication repo+file

    for search_q in &search_queries {
        let url = format!(
            "https://api.github.com/search/code?q={}&per_page=10",
            urlencoding::encode(search_q)
        );

        let mut req = client
            .get(&url)
            // text-match+json pour récupérer le fragment de code contenant le match
            .header("Accept", "application/vnd.github.v3.text-match+json");

        if let Some(key) = api_key {
            req = req.header("Authorization", format!("token {}", key));
        }

        if let Ok(resp) = req.send().await {
            let status = resp.status();
            if let Ok(body) = resp.text().await {
                if !status.is_success() {
                    let err = serde_json::from_str::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|v| v["message"].as_str().map(|s| s.to_string()))
                        .unwrap_or_else(|| body.clone());
                    if status.as_u16() == 403 {
                        eprintln!("  \x1b[33m[GitHub]\x1b[0m rate limit (403): {}", err);
                    } else if status.as_u16() == 422 {
                        // GitHub search syntax error — on continue avec les autres requêtes
                    }
                    continue;
                }
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(items) = data["items"].as_array() {
                        for item in items {
                            let repo = item["repository"]["full_name"]
                                .as_str()
                                .unwrap_or("?")
                                .to_string();
                            let file_path = item["path"].as_str().unwrap_or("?").to_string();
                            let sha = item["sha"]
                                .as_str()
                                .map(|s| s[..8.min(s.len())].to_string());

                            // Extraire le vrai fragment de code depuis text_matches
                            let snippet = item["text_matches"]
                                .as_array()
                                .and_then(|arr| arr.first())
                                .and_then(|tm| tm["fragment"].as_str())
                                .map(|s| {
                                    s.lines()
                                        .filter(|l| !l.trim().is_empty())
                                        .take(3)
                                        .collect::<Vec<_>>()
                                        .join(" | ")
                                })
                                .unwrap_or_else(|| {
                                    item["name"].as_str().unwrap_or("?").to_string()
                                });

                            // ── Filtrage anti-faux-positifs ─────────────────────────
                            // 1) Exclure les extensions de listes de domaines
                            if excluded_extensions
                                .iter()
                                .any(|ext| file_path.to_lowercase().ends_with(ext))
                            {
                                continue;
                            }
                            // 2) Exclure les chemins contenant des mots-clés de listes
                            let path_lower = file_path.to_lowercase();
                            if excluded_path_keywords
                                .iter()
                                .any(|k| path_lower.contains(k))
                            {
                                continue;
                            }
                            // 3) Exclure les repos évidents de listes de domaines
                            let repo_lower = repo.to_lowercase();
                            if excluded_path_keywords
                                .iter()
                                .any(|k| repo_lower.contains(k))
                            {
                                continue;
                            }
                            // 4) Vérifier que le snippet contient réellement le domaine
                            if !snippet.to_lowercase().contains(&query.to_lowercase())
                                && !file_path.to_lowercase().contains(&query.to_lowercase())
                                && !repo_lower.contains(&query.to_lowercase())
                            {
                                continue;
                            }
                            // 5) Exclure les snippets qui ressemblent à des entrées de hosts/blocklist
                            if fp_snippet_keywords.iter().any(|k| snippet.contains(k)) {
                                continue;
                            }

                            // Déduplication
                            let dedup_key = format!("{}::{}", repo, file_path);
                            if !seen.insert(dedup_key) {
                                continue;
                            }

                            let leak_type = if search_q.contains("password") {
                                "password"
                            } else if search_q.contains("api_key") {
                                "api_key"
                            } else if search_q.contains("secret") {
                                "secret"
                            } else if search_q.contains("token") {
                                "token"
                            } else {
                                "private_key"
                            };

                            leaks.push(GithubLeak {
                                repo: repo.into(),
                                file_path: file_path.into(),
                                leak_type: leak_type.into(),
                                snippet: snippet.into(),
                                commit: sha,
                            });
                        }
                    }
                }
            }
        }
        // Rate limit GitHub : 30 req/min pour les search code
        tokio::time::sleep(Duration::from_millis(2100)).await;
    }

    leaks
}

// ─────────────────────────────────────────────────────────────────────────────
// Shodan-like queries (sans API — patterns de recherche)
// ─────────────────────────────────────────────────────────────────────────────

/// Génère des requêtes Shodan pour un domaine/IP
pub fn shodan_queries(domain: &str) -> Vec<String> {
    vec![
        format!("hostname:{}", domain),
        format!("ssl.cert.subject.cn:{}", domain),
        format!("http.title:\"{}\"", domain),
        format!("http.html:\"{}\"", domain),
        format!("org:\"{}\"", domain),
        format!("net:{}/24  # Si IP connue", domain),
    ]
}

/// Génère des requêtes Google Dork pour un domaine
pub fn google_dorks(domain: &str) -> Vec<String> {
    vec![
        format!(
            "site:{} filetype:env OR filetype:config OR filetype:xml",
            domain
        ),
        format!(
            "site:{} inurl:admin OR inurl:login OR inurl:dashboard",
            domain
        ),
        format!(
            "site:{} intext:password OR intext:apikey OR intext:secret",
            domain
        ),
        format!(
            "site:{} filetype:sql OR filetype:bak OR filetype:old",
            domain
        ),
        format!("site:{} inurl:phpmyadmin OR inurl:wp-admin", domain),
        format!("intext:\"@{}\" filetype:txt OR filetype:csv", domain),
        format!("site:pastebin.com \"{}\"", domain),
        format!("site:github.com \"{}\" password OR secret OR key", domain),
        format!("site:trello.com \"{}\"", domain),
        format!("site:jira.* \"{}\"", domain),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestrateur OSINT complet
// ─────────────────────────────────────────────────────────────────────────────

/// Lance une reconnaissance OSINT complète sur un domaine
pub async fn full_osint_recon(
    domain: &str,
    hibp_key: Option<&str>,
    github_key: Option<&str>,
) -> OsintReport {
    println!(
        "\n  \x1b[38;5;196m[OSINT]\x1b[0m Reconnaissance passive sur \x1b[33m{}\x1b[0m",
        domain
    );

    // 1. Sous-domaines via crt.sh
    print!("  → Sous-domaines crt.sh... ");
    let mut subdomains = crtsh_subdomains(domain).await;
    println!("\x1b[32m{} trouvés\x1b[0m", subdomains.len());

    // 2. Résolution DNS des sous-domaines
    print!("  → Résolution DNS... ");
    resolve_subdomains(&mut subdomains).await;
    let active = subdomains.iter().filter(|s| s.ip.is_some()).count();
    println!("\x1b[32m{} actifs\x1b[0m", active);

    // 3. Enregistrements DNS principaux (MX, NS, TXT, SOA)
    print!("  → Enregistrements DNS... ");
    let dns_records = collect_dns_records(domain).await;
    println!("\x1b[32m{} records\x1b[0m", dns_records.len());

    // 4. Extraction d'emails depuis les enregistrements DNS
    let emails = extract_emails_from_dns(&dns_records, domain);

    // 5. GitHub leaks
    print!("  → GitHub leaks... ");
    let github_leaks = github_search(domain, github_key).await;
    println!(
        "\x1b[{}m{} résultats\x1b[0m",
        if github_leaks.is_empty() { "90" } else { "196" },
        github_leaks.len()
    );

    // 6. HIBP breach check sur les emails découverts
    let mut breaches = Vec::new();
    if !emails.is_empty() {
        print!("  → HIBP breaches ({} emails)... ", emails.len());
        for email in emails.iter().take(5) {
            let email_breaches = check_hibp(email, hibp_key).await;
            breaches.extend(email_breaches);
        }
        println!(
            "\x1b[{}m{} breaches\x1b[0m",
            if breaches.is_empty() { "90" } else { "196" },
            breaches.len()
        );
    }

    // 7. Détection de technologies depuis les sous-domaines actifs
    let technologies = detect_technologies_from_subdomains(&subdomains).await;

    let cert_domains: Vec<String> = subdomains.iter().map(|s| s.subdomain.clone()).collect();

    OsintReport {
        target: domain.to_string(),
        subdomains,
        emails,
        breaches,
        technologies,
        open_ports: Vec::new(),
        cert_domains,
        github_leaks,
        dns_records,
        intelligence: None,
    }
}

/// Analyse un rapport OSINT via LLM pour corréler les fuites et les sous-domaines.
pub async fn analyze_osint_with_llm(
    report: &OsintReport,
    llm_client: &dyn crate::llm::LlmClient,
) -> Result<OsintIntelligence, Box<dyn std::error::Error + Send + Sync>> {
    let system_prompt = r#"Tu es un analyste OSINT senior spécialisé en corrélation de données pour le Red Teaming.
Ton but est d'analyser un rapport OSINT (sous-domaines, emails, fuites GitHub, techs) et d'identifier les vecteurs d'attaque les plus probables.
Identifie les infrastructures "fantômes", les développeurs exposés et les chemins d'accès initiaux.

Réponds UNIQUEMENT en JSON valide avec la structure suivante :
{
  "summary": "résumé global en 3 phrases",
  "high_value_targets": ["liste d'IPs ou sous-domaines critiques"],
  "attack_scenarios": ["scénarios d'attaque basés sur les leaks/techs"],
  "correlation_notes": ["observations sur les liens entre leaks et domaines"],
  "recommended_next_steps": ["actions concrètes pour la phase de scan/exploit"]
}"#;

    let user_prompt = format!(
        "Analyse ce rapport OSINT :\nCible: {}\nSous-domaines: {}\nEmails: {}\nGitHub Leaks: {}\nTechs: {:?}",
        report.target,
        report.subdomains.len(),
        report.emails.len(),
        report.github_leaks.len(),
        report.technologies
    );

    let messages = vec![
        crate::llm::ChatMessage {
            role: "system".into(),
            content: system_prompt.into(),
        },
        crate::llm::ChatMessage {
            role: "user".into(),
            content: user_prompt,
        },
    ];

    let response = llm_client.chat(messages, true).await?;
    let intel: OsintIntelligence = serde_json::from_str(&response)?;
    Ok(intel)
}

/// Collecte les enregistrements DNS via Cloudflare DoH JSON + fallbacks stdlib
async fn collect_dns_records(domain: &str) -> Vec<DnsRecord> {
    use std::net::ToSocketAddrs;
    let mut records: Vec<DnsRecord> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut push = |rtype: &str, value: &str| {
        let v = value.trim().trim_end_matches('.').to_string();
        if v.is_empty() {
            return;
        }
        if seen.insert((rtype.to_string(), v.clone())) {
            records.push(DnsRecord {
                record_type: rtype.to_string(),
                value: v,
                ttl: None,
            });
        }
    };

    // A record via stdlib (rapide, offline)
    if let Ok(addrs) = format!("{}:443", domain).to_socket_addrs() {
        for a in addrs {
            if a.is_ipv4() {
                push("A", &a.ip().to_string());
            }
        }
    }
    if let Ok(addrs) = format!("{}:443", domain).to_socket_addrs() {
        for a in addrs {
            if a.is_ipv6() {
                push("AAAA", &a.ip().to_string());
            }
        }
    }

    // Record via DoH JSON — A, AAAA, MX, NS, TXT, SOA, CAA, CNAME
    use futures::stream::{self, StreamExt};
    let doh_types = &["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME"];
    let futs = doh_types
        .iter()
        .map(|t| async move { (t.to_string(), doh_answer(domain, t).await) });
    let results: Vec<(String, Vec<(u16, String)>)> =
        stream::iter(futs).buffer_unordered(4).collect().await;

    for (req_type, ans) in results {
        for (code, data) in ans {
            match (req_type.as_str(), code) {
                ("A", RR_A) => push("A", &data),
                ("AAAA", RR_AAAA) => push("AAAA", &data),
                ("CNAME", RR_CNAME) => push("CNAME", &data),
                ("NS", RR_NS) => push("NS", &data),
                ("MX", RR_MX) => {
                    // MX format: "10 mail.example.com." — on affiche préférence + hôte
                    let mut it = data.splitn(2, ' ');
                    let _pref = it.next().unwrap_or("");
                    let host = it.next().unwrap_or(&data);
                    push("MX", host);
                }
                ("TXT", RR_TXT) => {
                    // TXT souvent entre guillemets, on concatène les parties
                    let cleaned = data.trim_matches('"').replace("\" \"", "");
                    if !cleaned.is_empty() {
                        push("TXT", &cleaned);
                    }
                }
                ("SOA", RR_SOA) => {
                    // SOA: ns1 hostmaster serial refresh retry expire min_ttl
                    let parts: Vec<&str> = data.split_whitespace().collect();
                    if parts.len() >= 2 {
                        push("SOA", &format!("ns={} mbox={}", parts[0], parts[1]));
                    } else {
                        push("SOA", &data);
                    }
                }
                ("CAA", RR_CAA) => push("CAA", &data),
                _ => continue,
            }
        }
    }

    // Enregistrements courants synthétiques si non vus (fallbacks)
    for extra in &["_dmarc"] {
        let fqdn = format!("{}.{}", extra, domain);
        for (code, data) in doh_answer(&fqdn, "TXT").await {
            if code == RR_TXT {
                let cleaned = data.trim_matches('"').replace("\" \"", "");
                if !cleaned.is_empty() {
                    if seen.insert(("DMARC".to_string(), cleaned.clone())) {
                        records.push(DnsRecord {
                            record_type: "DMARC".into(),
                            value: cleaned,
                            ttl: None,
                        });
                    }
                }
            }
        }
    }

    records
}

/// Extrait des emails depuis les enregistrements DNS et le domaine
fn extract_emails_from_dns(records: &[DnsRecord], domain: &str) -> Vec<String> {
    let mut emails = Vec::new();
    // Emails courants à vérifier avec HIBP
    for prefix in &[
        "admin",
        "security",
        "contact",
        "info",
        "webmaster",
        "noc",
        "abuse",
        "hostmaster",
        "postmaster",
    ] {
        emails.push(format!("{}@{}", prefix, domain));
    }
    for r in records {
        if r.record_type == "MX" {
            // MX value: "mail.example.com" ou parfois préfixé — on nettoie et ajoute postmaster@MX_host
            let host = r.value.trim().trim_end_matches('.');
            if !host.is_empty() {
                emails.push(format!("postmaster@{}", host));
            }
        } else if r.record_type == "SOA" {
            // Format stocké: "ns=ns1.example.com mbox=hostmaster.example.com"
            // SOA mbox convention : 1er point = @, dernier point = racine
            if let Some(mbox) = r.value.split("mbox=").nth(1) {
                let mbox_clean = mbox.trim().trim_end_matches('.');
                // Convertir hostmaster.example.com → hostmaster@example.com
                if let Some(dot_pos) = mbox_clean.find('.') {
                    let (local, dmn) = mbox_clean.split_at(dot_pos);
                    if !local.is_empty() && dmn.len() > 1 {
                        emails.push(format!("{}@{}", local, &dmn[1..]));
                    }
                }
            }
        } else if r.record_type == "TXT" {
            // SPF record peut contenir include:domain — pas d'email direct mais on skip
            // Les TXT génériques contenant un @ (ex: contact info)
            for token in r.value.split_whitespace() {
                if token.contains('@')
                    && !token.starts_with("v=spf")
                    && !token.starts_with("google-site-verification")
                {
                    let clean = token.trim_matches(|c: char| c == '"' || c == ',' || c == ';');
                    if clean.contains('@') && clean.contains('.') {
                        emails.push(clean.to_string());
                    }
                }
            }
        }
    }
    emails.sort();
    emails.dedup();
    emails
}

/// Détecte les technologies des sous-domaines actifs via HTTP headers
async fn detect_technologies_from_subdomains(subdomains: &[SubdomainEntry]) -> Vec<String> {
    let mut techs = std::collections::HashSet::new();
    let client = reqwest::Client::builder()
        .timeout(tokio::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (compatible; NRTG/2.0)")
        .build()
        .unwrap_or_default();

    for sub in subdomains.iter().filter(|s| s.ip.is_some()).take(5) {
        let url = format!("http://{}", sub.subdomain);
        if let Ok(resp) = client.get(&url).send().await {
            for (k, v) in resp.headers() {
                let key = k.as_str().to_lowercase();
                let val = v.to_str().unwrap_or("").to_lowercase();
                if key == "server" {
                    techs.insert(val.split('/').next().unwrap_or(&val).to_string());
                }
                if key == "x-powered-by" {
                    techs.insert(val.split('/').next().unwrap_or(&val).to_string());
                }
                if key == "x-generator" {
                    techs.insert(val.clone());
                }
            }
        }
    }
    techs.into_iter().filter(|t| !t.is_empty()).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Affichage
// ─────────────────────────────────────────────────────────────────────────────

pub fn print_osint_report(report: &OsintReport) {
    let fire = "\x1b[38;5;196m";
    let cyan = "\x1b[36m";
    let amber = "\x1b[33m";
    let green = "\x1b[32m";
    let dim = "\x1b[90m";
    let mag = "\x1b[35m";
    let blue = "\x1b[34m";
    let reset = "\x1b[0m";

    println!("\n{}╔══ OSINT — {} ══╗{}", fire, report.target, reset);

    // ── Enregistrements DNS ────────────────────────────────────────────────
    if !report.dns_records.is_empty() {
        let groups: std::collections::HashMap<&str, Vec<&DnsRecord>> = {
            let mut m = std::collections::HashMap::new();
            for r in &report.dns_records {
                m.entry(r.record_type.as_str())
                    .or_insert_with(Vec::new)
                    .push(r);
            }
            m
        };
        let order = [
            "A", "AAAA", "MX", "NS", "TXT", "SOA", "DMARC", "CAA", "CNAME",
        ];
        println!(
            "\n{}▍ ENREGISTREMENTS DNS ({} entrées){}",
            mag,
            report.dns_records.len(),
            reset
        );
        for t in &order {
            if let Some(recs) = groups.get(t) {
                for r in recs {
                    let display = if r.value.len() > 80 {
                        format!("{}…", &r.value[..77])
                    } else {
                        r.value.clone()
                    };
                    println!("  {}{:<6}{} {}", mag, t, reset, display);
                }
            }
        }
    }

    // ── Sous-domaines ──────────────────────────────────────────────────────
    let active: Vec<_> = report
        .subdomains
        .iter()
        .filter(|s| s.ip.is_some())
        .collect();
    let inactive: Vec<_> = report
        .subdomains
        .iter()
        .filter(|s| s.ip.is_none())
        .collect();
    let crt_total = report
        .subdomains
        .iter()
        .filter(|s| s.source == "crt.sh")
        .count();
    let brute_total = report
        .subdomains
        .iter()
        .filter(|s| s.source == "dns-brute")
        .count();

    println!(
        "\n{}▍ SOUS-DOMAINES ({} total){} — actifs={}, passifs(CT)={}, brute={}",
        cyan,
        report.subdomains.len(),
        reset,
        active.len(),
        inactive.len(),
        brute_total
    );

    // Actifs — triés par source puis nom
    let mut active_sorted = active.clone();
    active_sorted.sort_by(|a, b| a.source.cmp(&b.source).then(a.subdomain.cmp(&b.subdomain)));
    for s in &active_sorted {
        let src_tag = match s.source.as_str() {
            "crt.sh" => format!("{}[crt.sh]{}", dim, reset),
            "dns-brute" => format!("{}[brute]{}", "\x1b[36m", reset),
            other => format!("{}[{}]{}", dim, other, reset),
        };
        println!(
            "  {}✓{} {} → {}  {}",
            green,
            reset,
            s.subdomain,
            s.ip.as_deref().unwrap_or("?"),
            src_tag
        );
    }

    // Inactifs (issus de Certificate Transparency crt.sh — valeur !)
    if !inactive.is_empty() {
        let from_crt: Vec<_> = inactive.iter().filter(|s| s.source == "crt.sh").collect();
        let other: Vec<_> = inactive.iter().filter(|s| s.source != "crt.sh").collect();
        println!("\n{}▍ SOUS-DOMAINES PASSIFS — Certificats CT (crt.sh — {} entrées, non résolus actuellement){}",
            mag, from_crt.len(), reset);

        // Grouper par sous-domaine racine pour lisibilité (20 affichés max + compteur reste)
        for (i, s) in from_crt.iter().take(40).enumerate() {
            println!(
                "  {}{:>2}.{} {}{}{}",
                dim,
                i + 1,
                reset,
                "\x1b[35m",
                s.subdomain,
                reset
            );
        }
        if from_crt.len() > 40 {
            println!(
                "  {} … et {} autres sous-domaines issus de CT (voir graph.osint.json){}",
                dim,
                from_crt.len() - 40,
                reset
            );
        }
        if !other.is_empty() {
            println!(
                "  {}· {} sous-domaines non résolus autres sources{}",
                dim,
                other.len(),
                reset
            );
        }
    }
    // Fallback: si totalement vide (0 inactifs) mais crt.sh n'a rien donné, message explicite
    if inactive.is_empty() && crt_total == 0 {
        println!("  {}· Aucun certificat CT détecté — crt.sh indisponible ou domaine sans certs publics{}", dim, reset);
    }

    // ── Emails ─────────────────────────────────────────────────────────────
    if !report.emails.is_empty() {
        println!(
            "\n{}▍ EMAILS ({} candidats){}",
            amber,
            report.emails.len(),
            reset
        );
        for e in &report.emails {
            println!("  {}✉{} {}", amber, reset, e);
        }
    }

    // ── Technologies détectées ────────────────────────────────────────────
    if !report.technologies.is_empty() {
        println!(
            "\n{}▍ TECHNOLOGIES WEB ({} détectées){}",
            blue,
            report.technologies.len(),
            reset
        );
        for t in &report.technologies {
            println!("  {}{}{}", blue, t, reset);
        }
    }

    // ── Ports ouverts (Shodan) ────────────────────────────────────────────
    if !report.open_ports.is_empty() {
        println!(
            "\n{}▍ PORTS DÉCOUVERTS — Shodan ({} ports){}",
            fire,
            report.open_ports.len(),
            reset
        );
        let mut by_ip: std::collections::HashMap<String, Vec<&ShodanResult>> =
            std::collections::HashMap::new();
        for p in &report.open_ports {
            by_ip.entry(p.ip.clone()).or_default().push(p);
        }
        for (ip, ports) in by_ip.iter() {
            println!(
                "  {}IP {}  {}ports : {}{}{}",
                fire,
                ip,
                reset,
                green,
                ports
                    .iter()
                    .map(|p| format!("{}/{}", p.port, p.service))
                    .collect::<Vec<_>>()
                    .join(", "),
                reset
            );
        }
    }

    // ── GitHub leaks ──────────────────────────────────────────────────────
    if !report.github_leaks.is_empty() {
        println!(
            "\n{}▍ GITHUB LEAKS ({} résultats){}",
            fire,
            report.github_leaks.len(),
            reset
        );
        for l in &report.github_leaks {
            println!(
                "  {}🔴{} [{}] {}/{}",
                fire, reset, l.leak_type, l.repo, l.file_path
            );
            if !l.snippet.is_empty() && l.snippet != "?" {
                let snippet_short: String = l.snippet.chars().take(140).collect();
                println!("       {}↳ {}{}", dim, snippet_short, reset);
            }
        }
    }

    // ── Breaches HIBP ─────────────────────────────────────────────────────
    if !report.breaches.is_empty() {
        println!(
            "\n{}▍ DATA BREACHES ({} breaches){}",
            amber,
            report.breaches.len(),
            reset
        );
        for b in &report.breaches {
            println!(
                "  {} — {} ({}) → {}",
                b.email,
                b.breach_name,
                b.breach_date,
                b.data_types.join(", ")
            );
        }
    }

    // ── Google Dorks ──────────────────────────────────────────────────────
    println!("\n{}▍ GOOGLE DORKS{}", dim, reset);
    for dork in google_dorks(&report.target).iter().take(5) {
        println!("  {}🔍 {}{}", dim, dork, reset);
    }

    println!();
}

// ─────────────────────────────────────────────────────────────────────────────
// Shodan API
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanHost {
    pub ip: String,
    pub ports: Vec<u16>,
    pub hostnames: Vec<String>,
    pub org: Option<String>,
    pub country: Option<String>,
    pub vulns: Vec<String>,
    pub banners: Vec<String>,
}

/// Recherche via Shodan API (nécessite SHODAN_API_KEY dans .env)
pub async fn shodan_search(query: &str, api_key: &str) -> Vec<ShodanHost> {
    if api_key.is_empty() {
        return Vec::new();
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("NRTG-RedTeam/2.0")
        .build()
        .unwrap_or_default();

    let url = format!(
        "https://api.shodan.io/shodan/host/search?key={}&query={}&minify=false",
        api_key,
        urlencoding::encode(query)
    );

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  \x1b[33m[Shodan]\x1b[0m API error: {}", e);
            return Vec::new();
        }
    };

    let status = resp.status();
    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    if !status.is_success() {
        let err = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| body.clone());
        match status.as_u16() {
            401 => eprintln!("  \x1b[31m[Shodan]\x1b[0m clé API invalide (401)"),
            403 => eprintln!("  \x1b[31m[Shodan]\x1b[0m accès refusé (403): forfait insuffisant"),
            429 => eprintln!("  \x1b[33m[Shodan]\x1b[0m rate limit (429)"),
            _ => eprintln!("  \x1b[33m[Shodan]\x1b[0m HTTP {}: {}", status, err),
        }
        return Vec::new();
    }

    let mut hosts = Vec::new();
    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(matches) = data["matches"].as_array() {
            for m in matches {
                let ip = m["ip_str"].as_str().unwrap_or("").to_string();
                let port = m["port"].as_u64().unwrap_or(0) as u16;
                let org = m["org"].as_str().map(|s| s.to_string());
                let country = m["location"]["country_name"]
                    .as_str()
                    .map(|s| s.to_string());
                let banner = m["data"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(200)
                    .collect::<String>();
                let hostnames = m["hostnames"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let vulns = m["vulns"]
                    .as_object()
                    .map(|o| o.keys().cloned().collect())
                    .unwrap_or_default();

                // Trouver ou créer l'entrée pour cet IP
                if let Some(existing) = hosts.iter_mut().find(|h: &&mut ShodanHost| h.ip == ip) {
                    if port > 0 {
                        existing.ports.push(port);
                    }
                    if !banner.is_empty() {
                        existing.banners.push(banner);
                    }
                    existing.vulns.extend(vulns);
                } else {
                    hosts.push(ShodanHost {
                        ip,
                        org,
                        country,
                        hostnames,
                        vulns,
                        ports: if port > 0 { vec![port] } else { Vec::new() },
                        banners: if !banner.is_empty() {
                            vec![banner]
                        } else {
                            Vec::new()
                        },
                    });
                }
            }
        }
    }

    println!(
        "  \x1b[32m[Shodan]\x1b[0m {} résultats pour '{}'",
        hosts.len(),
        query
    );
    hosts
}

/// Recherche Shodan pour une IP spécifique
pub async fn shodan_host(ip: &str, api_key: &str) -> Option<ShodanHost> {
    if api_key.is_empty() {
        return None;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, api_key);
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  \x1b[33m[Shodan]\x1b[0m {} — requête échouée: {}", ip, e);
            return None;
        }
    };

    let status = resp.status();
    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "  \x1b[33m[Shodan]\x1b[0m {} — lecture réponse échouée: {}",
                ip, e
            );
            return None;
        }
    };

    // Gestion explicite des codes d'erreur Shodan
    if !status.is_success() {
        let err_msg = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| body.clone());
        match status.as_u16() {
            401 => eprintln!("  \x1b[31m[Shodan]\x1b[0m {} — clé API invalide (401)", ip),
            403 => eprintln!("  \x1b[31m[Shodan]\x1b[0m {} — accès refusé (403): forfait Shodan insuffisant pour /shodan/host/", ip),
            404 => { /* IP non indexée par Shodan — silencieux */ }
            429 => eprintln!("  \x1b[33m[Shodan]\x1b[0m {} — rate limit (429), ralentissement...", ip),
            _   => eprintln!("  \x1b[33m[Shodan]\x1b[0m {} — HTTP {}: {}", ip, status, err_msg),
        }
        return None;
    }

    let data: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("  \x1b[33m[Shodan]\x1b[0m {} — JSON invalide: {}", ip, e);
            return None;
        }
    };

    // Shodan renvoie parfois {"error": "..."} même avec 200
    if let Some(err) = data["error"].as_str() {
        eprintln!("  \x1b[33m[Shodan]\x1b[0m {} — API error: {}", ip, err);
        return None;
    }

    let ports: Vec<u16> = data["ports"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_u64().map(|p| p as u16))
                .collect()
        })
        .unwrap_or_default();
    let vulns: Vec<String> = data["vulns"]
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    let hostnames: Vec<String> = data["hostnames"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Récupérer les bannières des services
    let banners: Vec<String> = data["data"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| {
                    s["data"]
                        .as_str()
                        .map(|b| b.lines().next().unwrap_or("").to_string())
                })
                .filter(|b| !b.is_empty())
                .take(5)
                .collect()
        })
        .unwrap_or_default();

    if !vulns.is_empty() {
        println!(
            "  \x1b[38;5;196m[Shodan]\x1b[0m {} — {} CVEs: {}",
            ip,
            vulns.len(),
            vulns[..vulns.len().min(5)].join(", ")
        );
    }
    if !ports.is_empty() {
        println!("  \x1b[32m[Shodan]\x1b[0m {} — ports: {:?}", ip, ports);
    }

    Some(ShodanHost {
        ip: ip.to_string(),
        ports,
        hostnames,
        org: data["org"].as_str().map(|s| s.to_string()),
        country: data["country_name"].as_str().map(|s| s.to_string()),
        vulns,
        banners,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Censys API
// ─────────────────────────────────────────────────────────────────────────────

/// Recherche via Censys Search API v2
pub async fn censys_search(query: &str, api_id: &str, api_secret: &str) -> Vec<ShodanHost> {
    if api_id.is_empty() {
        return Vec::new();
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    let body = serde_json::json!({
        "q": query,
        "per_page": 50,
        "fields": ["ip", "services.port", "services.service_name", "autonomous_system.organization", "location.country"]
    });

    let resp = match client
        .post("https://search.censys.io/api/v2/hosts/search")
        .basic_auth(api_id, Some(api_secret))
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  [Censys] API error: {}", e);
            return Vec::new();
        }
    };

    let body_str = match resp.text().await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let data: serde_json::Value = match serde_json::from_str(&body_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut hosts = Vec::new();
    if let Some(results) = data["result"]["hits"].as_array() {
        for hit in results {
            let ip = hit["ip"].as_str().unwrap_or("").to_string();
            let org = hit["autonomous_system"]["organization"]
                .as_str()
                .map(|s| s.to_string());
            let country = hit["location"]["country"].as_str().map(|s| s.to_string());
            let ports: Vec<u16> = hit["services"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s["port"].as_u64().map(|p| p as u16))
                        .collect()
                })
                .unwrap_or_default();

            if !ip.is_empty() {
                hosts.push(ShodanHost {
                    ip,
                    ports,
                    hostnames: Vec::new(),
                    org,
                    country,
                    vulns: Vec::new(),
                    banners: Vec::new(),
                });
            }
        }
    }

    println!(
        "  \x1b[32m[Censys]\x1b[0m {} résultats pour '{}'",
        hosts.len(),
        query
    );
    hosts
}

// ─────────────────────────────────────────────────────────────────────────────
// Wayback Machine — URLs cachées
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaybackEntry {
    pub url: String,
    pub timestamp: String,
    pub mime_type: String,
    pub status: String,
}

/// Récupère les URLs historiques depuis Wayback Machine CDX API
pub async fn wayback_urls(domain: &str) -> Vec<WaybackEntry> {
    let domain = normalize_domain(domain);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("NRTG-RedTeam/2.0")
        .build()
        .unwrap_or_default();

    // CDX API — retourne toutes les URLs crawlées
    let url = format!(
        "https://web.archive.org/cdx/search/cdx?url=*.{}&output=json&fl=original,timestamp,mimetype,statuscode&filter=statuscode:200&collapse=urlkey&limit=200",
        domain
    );

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  [Wayback] Error: {}", e);
            return Vec::new();
        }
    };

    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let mut entries = Vec::new();
    if let Ok(rows) = serde_json::from_str::<Vec<Vec<String>>>(&body) {
        for row in rows.iter().skip(1) {
            // Skip header
            if row.len() >= 4 {
                let mime = &row[2];
                // Filtrer: garder seulement HTML, JS, JSON, XML, PHP, ASP
                if mime.contains("html")
                    || mime.contains("javascript")
                    || mime.contains("json")
                    || mime.contains("xml")
                    || row[0].ends_with(".php")
                    || row[0].ends_with(".asp")
                    || row[0].ends_with(".aspx")
                {
                    entries.push(WaybackEntry {
                        url: row[0].clone(),
                        timestamp: row[1].clone(),
                        mime_type: mime.clone(),
                        status: row[3].clone(),
                    });
                }
            }
        }
    }

    // Chercher des URLs intéressantes (backup, config, admin, api)
    let sensitive_keywords = [
        "backup", "config", "admin", "api", "debug", "test", ".env", ".sql", "swagger",
    ];
    let interesting: Vec<_> = entries
        .iter()
        .filter(|e| {
            sensitive_keywords
                .iter()
                .any(|k| e.url.to_lowercase().contains(k))
        })
        .collect();

    if !interesting.is_empty() {
        println!(
            "  \x1b[38;5;196m[Wayback]\x1b[0m {} URLs sensibles sur {} totales:",
            interesting.len(),
            entries.len()
        );
        for e in interesting.iter().take(10) {
            println!("    {} [{}]", e.url, e.timestamp);
        }
    } else {
        println!(
            "  \x1b[32m[Wayback]\x1b[0m {} URLs historiques pour {}",
            entries.len(),
            domain
        );
    }

    entries
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS Bruteforce
// ─────────────────────────────────────────────────────────────────────────────

/// Brute-force DNS avec une wordlist étendue (200+) via DoH Cloudflare.
/// Rapide, indépendant de la config DNS locale, concurrent.
pub async fn dns_brute_force(domain: &str) -> Vec<SubdomainEntry> {
    let domain = normalize_domain(domain);
    let wordlist = [
        // Web
        "www",
        "ww2",
        "ww3",
        "web",
        "webmail",
        "webdisk",
        "websso",
        "webadmin",
        "m",
        "mobile",
        "shop",
        "store",
        "blog",
        "news",
        "press",
        "info",
        "help",
        "support",
        "community",
        "forum",
        "forums",
        "wiki",
        "kb",
        "docs",
        "documentation",
        "status",
        "uptime",
        "monitor",
        "monitoring",
        "metrics",
        "stats",
        // Admin / Backoffice
        "admin",
        "adm",
        "administrator",
        "administration",
        "backend",
        "backoffice",
        "panel",
        "cpanel",
        "directadmin",
        "plesk",
        "ispconfig",
        "ajenti",
        "vestacp",
        "login",
        "signin",
        "auth",
        "sso",
        "oauth",
        "cas",
        "ldap",
        "radius",
        "portal",
        "intranet",
        "extranet",
        "staff",
        "employee",
        "hr",
        "payroll",
        // Dev / CI / QA
        "dev",
        "devel",
        "development",
        "staging",
        "stage",
        "preprod",
        "pre-prod",
        "prod",
        "production",
        "test",
        "testing",
        "qa",
        "uat",
        "sandbox",
        "demo",
        "lab",
        "laboratory",
        "experimental",
        "poc",
        "prototype",
        "new",
        "old",
        "legacy",
        "jenkins",
        "ci",
        "cd",
        "gitlab",
        "gitlab-ci",
        "github",
        "gitea",
        "bitbucket",
        "sonar",
        "sonarqube",
        "nexus",
        "artifactory",
        "jfrog",
        "registry",
        "harbor",
        "jira",
        "confluence",
        "atlassian",
        "trello",
        "asana",
        "slack",
        "mattermost",
        "kibana",
        "elastic",
        "elasticsearch",
        "logstash",
        "grafana",
        "prometheus",
        "zabbix",
        "nagios",
        "icinga",
        "sentry",
        "newrelic",
        "datadog",
        // Infrastructure
        "server",
        "host",
        "node",
        "ns1",
        "ns2",
        "ns3",
        "dns",
        "dns1",
        "dns2",
        "gateway",
        "gw",
        "router",
        "fw",
        "firewall",
        "proxy",
        "squid",
        "nginx",
        "loadbalancer",
        "lb",
        "haproxy",
        "traefik",
        "reverse",
        "edge",
        "cache",
        "vpn",
        "ovpn",
        "wireguard",
        "pptp",
        "ipsec",
        "remote",
        "ssh",
        "bastion",
        "jump",
        "jumpbox",
        "shell",
        "terminal",
        "console",
        "rdp",
        "vnc",
        "k8s",
        "k8s-api",
        "kubernetes",
        "kube",
        "master",
        "worker",
        "node01",
        "node02",
        "node03",
        "k8s-master",
        "k8s-worker",
        "control-plane",
        "cp",
        "etcd1",
        "etcd2",
        "docker",
        "swarm",
        "rancher",
        "openshift",
        "nomad",
        "consul",
        "etcd",
        "salt",
        "ansible",
        "chef",
        "puppet",
        "terraform",
        "packer",
        "awx",
        "foreman",
        "proxmox",
        "esxi",
        "vcenter",
        "vcsa",
        "xen",
        "libvirt",
        // Mail / Messaging
        "mail",
        "smtp",
        "mx",
        "mx1",
        "mx2",
        "mail1",
        "mail2",
        "mail3",
        "pop",
        "pop3",
        "imap",
        "imap4",
        "exchange",
        "outlook",
        "webmail2",
        "owa",
        "ews",
        "autodiscover",
        "spf",
        "dkim",
        "_dmarc",
        "dmarc",
        "smarthost",
        "relay",
        "postfix",
        "sendmail",
        "mta",
        "lists",
        "mailman",
        "sympa",
        "roundcube",
        "sogo",
        "zimbra",
        "groupware",
        "calendar",
        // Bases de données
        "db",
        "database",
        "db1",
        "db2",
        "primary",
        "replica",
        "slave",
        "master-db",
        "mysql",
        "mariadb",
        "postgres",
        "pgsql",
        "mongo",
        "mongodb",
        "redis",
        "memcache",
        "memcached",
        "elasticsearch",
        "cassandra",
        "couchbase",
        "neo4j",
        "oracle",
        "mssql",
        "sql",
        "dynamodb",
        "cosmos",
        // Stockage / Fichiers
        "ftp",
        "sftp",
        "ftps",
        "tftp",
        "nfs",
        "smb",
        "cifs",
        "nas",
        "san",
        "files",
        "filer",
        "storage",
        "backup",
        "backups",
        "archive",
        "s3",
        "minio",
        "cloudstorage",
        "drive",
        "nextcloud",
        "owncloud",
        "seafile",
        "upload",
        "download",
        "dl",
        "cdn",
        "static",
        "assets",
        "media",
        "img",
        "images",
        "pictures",
        "pics",
        "video",
        "videos",
        "stream",
        // API / Services
        "api",
        "api2",
        "api3",
        "graphql",
        "grpc",
        "rest",
        "soap",
        "ws",
        "wss",
        "websocket",
        "webhook",
        "hooks",
        "callback",
        "events",
        "realtime",
        "payment",
        "pay",
        "billing",
        "invoice",
        "subscription",
        "stripe",
        "paypal",
        "search",
        "es",
        "solr",
        "algolia",
        "geocode",
        "maps",
        "tiles",
        "auth",
        "idp",
        "identity",
        "accounts",
        "users",
        "profile",
        // CMS / Apps courantes
        "wp",
        "wordpress",
        "wp-admin",
        "wp-login",
        "phpmyadmin",
        "pma",
        "myadmin",
        "adminer",
        "phppgadmin",
        "cacti",
        "moodle",
        "drupal",
        "joomla",
        "magento",
        "prestashop",
        "shopware",
        "typo3",
        "liferay",
        "sharepoint",
        // Sécurité
        "waf",
        "ids",
        "ips",
        "siem",
        "splunk",
        "arcsight",
        "qradar",
        "honeypot",
        "canary",
        "audit",
        "compliance",
        "soc",
        "soc-portal",
        "sso-admin",
        "keycloak",
        "authentik",
        "authelia",
        "gluu",
        "okta",
    ];

    println!(
        "  \x1b[36m[DNS-BRUTE]\x1b[0m {} sous-domaines à tester pour {}",
        wordlist.len(),
        domain
    );

    use futures::StreamExt;
    let results: Vec<Option<SubdomainEntry>> = futures::stream::iter(wordlist.iter())
        .map(|&prefix| {
            let subdomain = format!("{}.{}", prefix, domain);
            async move {
                // DoH A record lookup — rapide, 4s timeout max
                let answers =
                    tokio::time::timeout(Duration::from_secs(4), doh_answer(&subdomain, "A"))
                        .await
                        .unwrap_or_default();

                let ipv4: Vec<String> = answers
                    .iter()
                    .filter(|(t, _)| *t == RR_A)
                    .map(|(_, d)| d.clone())
                    .collect();

                if let Some(ip) = ipv4.first() {
                    println!("  \x1b[32m[DNS]\x1b[0m {} → {}", subdomain, ip);
                    return Some(SubdomainEntry {
                        subdomain: subdomain.clone(),
                        ip: Some(ip.clone()),
                        source: "dns-brute".into(),
                    });
                }

                // Fallback AAAA si pas de A
                let answers_v6 =
                    tokio::time::timeout(Duration::from_secs(3), doh_answer(&subdomain, "AAAA"))
                        .await
                        .unwrap_or_default();
                let ipv6: Vec<String> = answers_v6
                    .iter()
                    .filter(|(t, _)| *t == RR_AAAA)
                    .map(|(_, d)| d.clone())
                    .collect();

                if let Some(ip) = ipv6.first() {
                    println!("  \x1b[32m[DNS]\x1b[0m {} → {}", subdomain, ip);
                    return Some(SubdomainEntry {
                        subdomain: subdomain.clone(),
                        ip: Some(ip.clone()),
                        source: "dns-brute".into(),
                    });
                }

                None
            }
        })
        .buffer_unordered(24)
        .collect()
        .await;

    let discovered: Vec<SubdomainEntry> = results.into_iter().flatten().collect();
    println!(
        "  \x1b[36m[DNS-BRUTE]\x1b[0m {} sous-domaines actifs découverts",
        discovered.len()
    );
    discovered
}

// ─────────────────────────────────────────────────────────────────────────────
// OSINT Full amélioré
// ─────────────────────────────────────────────────────────────────────────────

pub struct OsintApiKeys {
    pub shodan: Option<String>,
    pub censys_id: Option<String>,
    pub censys_secret: Option<String>,
    pub hibp: Option<String>,
    pub github: Option<String>,
}

impl OsintApiKeys {
    pub fn from_env() -> Self {
        Self {
            shodan: std::env::var("SHODAN_API_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
            censys_id: std::env::var("CENSYS_API_ID")
                .ok()
                .filter(|s| !s.is_empty()),
            censys_secret: std::env::var("CENSYS_API_SECRET")
                .ok()
                .filter(|s| !s.is_empty()),
            hibp: std::env::var("HIBP_API_KEY").ok().filter(|s| !s.is_empty()),
            github: std::env::var("GITHUB_TOKEN").ok().filter(|s| !s.is_empty()),
        }
    }
}

// ---------------------------------------------------------------------------
// Construction du graphe OSINT (nodes + edges) pour le WebSocket Live
// ---------------------------------------------------------------------------
use std::collections::HashMap as HMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Horodatage UNIX millisecondes (consistant pour `t` dans les nœuds)
pub(crate) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Helper pour construire un nœud graphe
fn node(
    id: impl Into<String>,
    label: impl Into<String>,
    kind: OsintNodeKind,
    weight: f32,
    detail: Option<String>,
) -> OsintGraphNode {
    OsintGraphNode {
        id: id.into(),
        label: label.into(),
        kind,
        weight,
        detail,
        t: unix_ms(),
    }
}

/// Helper pour construire un edge graphe
fn edge(
    id: impl Into<String>,
    source: impl Into<String>,
    target: impl Into<String>,
    kind: OsintEdgeKind,
    label: Option<String>,
) -> OsintGraphEdge {
    OsintGraphEdge {
        id: id.into(),
        source: source.into(),
        target: target.into(),
        kind,
        label,
    }
}

/// Convertit un rapport OSINT complet en graphe (nodes + edges + stats).
/// Tous les IDs sont stable (préfixés par type) pour éviter les doublons côté client.
pub fn build_osint_graph(report: &OsintReport) -> OsintGraphSnapshot {
    let target = &report.target;
    let root_id = format!("root:{}", target);

    let mut seen_nodes: HMap<String, OsintGraphNode> = HMap::new();
    let mut seen_edges: HMap<String, OsintGraphEdge> = HMap::new();

    // Helper d'insertion unique — renvoie true si nouvel élément
    let mut ins_node = |n: OsintGraphNode| -> bool {
        if !seen_nodes.contains_key(&n.id) {
            seen_nodes.insert(n.id.clone(), n);
            true
        } else {
            false
        }
    };
    let mut ins_edge = |e: OsintGraphEdge| {
        if !seen_edges.contains_key(&e.id) {
            seen_edges.insert(e.id.clone(), e);
        }
    };

    // ── Nœud racine ───────────────────────────────────────────────────────
    ins_node(node(
        root_id.clone(),
        target.clone(),
        OsintNodeKind::RootDomain,
        18.0,
        Some("cible principale".into()),
    ));

    // Compteurs statistiques
    let mut stats = OsintGraphStats::default();
    stats.total_subdomains = report.subdomains.len();
    stats.active_subdomains = report.subdomains.iter().filter(|s| s.ip.is_some()).count();
    stats.total_emails = report.emails.len();
    stats.total_techs = report.technologies.len();
    stats.total_ports = report.open_ports.len();
    stats.total_leaks = report.github_leaks.len();
    stats.total_breaches = report.breaches.len();
    stats.total_records = report.dns_records.len();

    // ── Sous-domaines + IPs (résolution) ──────────────────────────────────
    for s in &report.subdomains {
        let sub_id = format!("sub:{}", s.subdomain);
        let detail = Some(format!(
            "src:{} · ip:{}",
            s.source,
            s.ip.as_deref().unwrap_or("∅")
        ));
        let weight = if s.ip.is_some() { 7.0 } else { 3.5 };
        ins_node(node(
            sub_id.clone(),
            s.subdomain.clone(),
            OsintNodeKind::Subdomain,
            weight,
            detail,
        ));
        ins_edge(edge(
            format!("e:has:{}", sub_id),
            root_id.clone(),
            sub_id.clone(),
            OsintEdgeKind::HasSubdomain,
            None,
        ));

        if let Some(ip) = &s.ip {
            let ip_id = format!("ip:{}", ip);
            if ins_node(node(
                ip_id.clone(),
                ip.clone(),
                OsintNodeKind::IpAddr,
                5.0,
                Some(format!("résolu par {}", s.subdomain)),
            )) {
                stats.total_ips += 1;
            }
            ins_edge(edge(
                format!("e:resolve:{}", sub_id),
                sub_id.clone(),
                ip_id.clone(),
                OsintEdgeKind::ResolvesTo,
                Some("A/AAAA".into()),
            ));
        }
    }

    // ── Records DNS (attachés au root + sous-domaines quand correspond) ───
    for (i, r) in report.dns_records.iter().enumerate() {
        let rec_id = format!("dns:{:x}-{}", unix_ms(), i);
        let lab = format!(
            "{} {}",
            r.record_type,
            r.value.chars().take(60).collect::<String>()
        );
        ins_node(node(
            rec_id.clone(),
            lab,
            OsintNodeKind::DnsRecord,
            4.5,
            r.ttl.map(|t| format!("TTL={}s", t)),
        ));
        // Attacher au root par défaut (attacher au sub si le record contient un sous-domaine)
        let mut attach_to = root_id.clone();
        for s in &report.subdomains {
            if r.value.contains(&s.subdomain) {
                attach_to = format!("sub:{}", s.subdomain);
                break;
            }
        }
        ins_edge(edge(
            format!("e:recroot:{i}"),
            attach_to,
            rec_id.clone(),
            OsintEdgeKind::HasDnsRecord,
            Some(r.record_type.clone()),
        ));

        // Si MX : extraire le serveur mail et résoudre en IP si possible
        if r.record_type.eq_ignore_ascii_case("MX") {
            // "10 mail.example.org" → domaine serveur
            let mail_srv = r
                .value
                .split_whitespace()
                .last()
                .unwrap_or("")
                .trim_end_matches('.');
            if !mail_srv.is_empty() {
                for s in &report.subdomains {
                    if s.subdomain.eq_ignore_ascii_case(mail_srv) {
                        if let Some(ip) = &s.ip {
                            let sub_id = format!("sub:{}", s.subdomain);
                            let ip_id = format!("ip:{}", ip);
                            ins_edge(edge(
                                format!("e:mxip:{}", sub_id),
                                rec_id.clone(),
                                ip_id,
                                OsintEdgeKind::MailServerIp,
                                Some(format!("MX → {}", s.subdomain)),
                            ));
                        }
                        break;
                    }
                }
            }
        }

        // Contient-il un email ? extraire + créer lien (TXT/SOA souvent)
        for email in &report.emails {
            if r.value.contains(email) || email.contains(&r.value) {
                let em_id = format!("mail:{}", email);
                ins_edge(edge(
                    format!("e:emailin:{i}:{}", email.replace('@', "-at-")),
                    rec_id.clone(),
                    em_id,
                    OsintEdgeKind::ContainsEmail,
                    Some("extrait".into()),
                ));
            }
        }
    }

    // ── Emails (node) + Breaches associées ────────────────────────────────
    for email in &report.emails {
        let em_id = format!("mail:{}", email);
        ins_node(node(
            em_id.clone(),
            email.clone(),
            OsintNodeKind::Email,
            6.0,
            None,
        ));
        ins_edge(edge(
            format!("e:rootmail:{}", email.replace('@', "-at-")),
            root_id.clone(),
            em_id.clone(),
            OsintEdgeKind::ContainsEmail,
            Some("scope".into()),
        ));
    }
    for (i, b) in report.breaches.iter().enumerate() {
        let bre_id = format!(
            "breach:{}:{}",
            b.breach_name.replace(|c: char| !c.is_alphanumeric(), "_"),
            i
        );
        ins_node(node(
            bre_id.clone(),
            format!("{b} ({bdate})", b = b.breach_name, bdate = b.breach_date),
            OsintNodeKind::Breach,
            5.5,
            Some(format!("{}", b.data_types.join(", "))),
        ));
        let em_id = format!("mail:{}", b.email);
        ins_edge(edge(
            format!("e:hibp:{}", bre_id),
            em_id,
            bre_id,
            OsintEdgeKind::SeenInBreach,
            Some("HIBP".into()),
        ));
    }

    // ── Technologies (attachées à leur sous-domaine résolu, sinon root) ──
    for (i, tech) in report.technologies.iter().enumerate() {
        let tech_id = format!("tech:{}", tech.replace(|c: char| !c.is_alphanumeric(), "_"));
        ins_node(node(
            tech_id.clone(),
            tech.clone(),
            OsintNodeKind::Technology,
            5.0,
            None,
        ));
        // Attribuer la tech au 1er sous-domaine actif
        let host = report
            .subdomains
            .iter()
            .find(|s| s.ip.is_some())
            .map(|s| format!("sub:{}", s.subdomain))
            .unwrap_or_else(|| root_id.clone());
        ins_edge(edge(
            format!("e:tech{}:{i}", tech_id),
            host,
            tech_id.clone(),
            OsintEdgeKind::RunsTechnology,
            None,
        ));
    }

    // ── Ports ouverts Shodan (sur IP) ─────────────────────────────────────
    for (i, p) in report.open_ports.iter().enumerate() {
        let port_id = format!("port:{}:{}", p.ip, p.port);
        ins_node(node(
            port_id.clone(),
            format!("{}:{}", p.ip, p.port),
            OsintNodeKind::OpenPort,
            4.8,
            Some(format!(
                "svc:{} · {}",
                p.service,
                p.country.as_deref().unwrap_or("?")
            )),
        ));
        let ip_id = format!("ip:{}", p.ip);
        if ins_node(node(
            ip_id.clone(),
            p.ip.clone(),
            OsintNodeKind::IpAddr,
            5.0,
            None,
        )) {
            stats.total_ips += 1;
        }
        ins_edge(edge(
            format!("e:port:i{i}"),
            ip_id,
            port_id,
            OsintEdgeKind::HasOpenPort,
            Some(p.port.to_string()),
        ));
    }

    // ── GitHub Leaks (référence → domaines) ───────────────────────────────
    for (i, lk) in report.github_leaks.iter().enumerate() {
        let leak_id = format!(
            "leak:gh-{}-{i}",
            lk.repo.replace(|c: char| !c.is_alphanumeric(), "_")
        );
        // Le `detail` embarque type, commit ET le snippet (contenu fuité)
        // pour affichage dans le tooltip et le panneau de détail au clic.
        let snippet_preview = if lk.snippet.len() > 300 {
            format!("{}…", &lk.snippet[..300])
        } else {
            lk.snippet.clone()
        };
        let detail = format!(
            "type:{} · commit {}\n--- snippet ---\n{}",
            lk.leak_type,
            lk.commit.as_deref().unwrap_or("?"),
            snippet_preview
        );
        ins_node(node(
            leak_id.clone(),
            format!("{}/{}", lk.repo, lk.file_path),
            OsintNodeKind::Leak,
            6.5,
            Some(detail),
        ));
        ins_edge(edge(
            format!("e:leakroot:{i}"),
            root_id.clone(),
            leak_id.clone(),
            OsintEdgeKind::ReferencedInLeak,
            Some("GitHub".into()),
        ));
    }

    OsintGraphSnapshot {
        target: target.clone(),
        generated_at: unix_ms(),
        nodes: seen_nodes.into_values().collect(),
        edges: seen_edges.into_values().collect(),
        stats,
    }
}

// ---------------------------------------------------------------------------
// Helpers d'émission incrémentielle graphe OSINT
// ---------------------------------------------------------------------------
/// Envoie un snapshot initial vide pour déclencher le rendu côté frontend.
pub async fn emit_osint_bootstrap(emit: Option<&DashboardEmitter>, target: &str) {
    let Some(em) = emit else { return };
    let root_id = format!("root:{}", target);
    em.send_osint_snapshot(OsintGraphSnapshot {
        target: target.into(),
        generated_at: unix_ms(),
        nodes: vec![node(
            root_id,
            target,
            OsintNodeKind::RootDomain,
            18.0,
            Some("reconnaissance en cours…".into()),
        )],
        edges: vec![],
        stats: OsintGraphStats::default(),
    })
    .await;
}

/// Envoie un batch (sous-domaines trouvés par crt.sh + brute) en delta.
pub async fn emit_osint_subdomains(
    emit: Option<&DashboardEmitter>,
    target: &str,
    subs: &[SubdomainEntry],
    stats_snapshot: &OsintGraphStats,
) {
    let Some(em) = emit else { return };
    let root_id = format!("root:{}", target);
    let mut add_nodes: Vec<OsintGraphNode> = Vec::new();
    let mut add_edges: Vec<OsintGraphEdge> = Vec::new();
    for s in subs {
        let sub_id = format!("sub:{}", s.subdomain);
        let detail = Some(format!("src:{}", s.source));
        add_nodes.push(node(
            sub_id.clone(),
            s.subdomain.clone(),
            OsintNodeKind::Subdomain,
            if s.ip.is_some() { 7.0 } else { 3.5 },
            detail,
        ));
        add_edges.push(edge(
            format!("e:sub:{}", sub_id),
            root_id.clone(),
            sub_id.clone(),
            OsintEdgeKind::HasSubdomain,
            None,
        ));
        if let Some(ip) = &s.ip {
            let ip_id = format!("ip:{}", ip);
            add_nodes.push(node(
                ip_id.clone(),
                ip.clone(),
                OsintNodeKind::IpAddr,
                5.0,
                Some(format!("par {}", s.subdomain)),
            ));
            add_edges.push(edge(
                format!("e:res:{}", sub_id),
                sub_id,
                ip_id,
                OsintEdgeKind::ResolvesTo,
                Some("DoH".into()),
            ));
        }
    }
    em.send_osint_delta(OsintGraphDelta {
        target: target.into(),
        at: unix_ms(),
        add_nodes,
        add_edges,
        stats_update: Some(stats_snapshot.clone()),
    })
    .await;
}

/// Reconnaissance OSINT complète avec toutes les sources.
///
/// Paramètre `emit` optionnel : si `Some(emitter)` est fourni, les nœuds du
/// graphe sont transmis en **temps réel** sur le WebSocket Live Dashboard
/// via `emit_osint_bootstrap → emit_osint_subdomains → OsintGraphSnapshot final`.
pub async fn full_osint_recon_v2(
    raw_domain: &str,
    keys: &OsintApiKeys,
    emit: Option<&DashboardEmitter>,
    llm_client: Option<&dyn crate::llm::LlmClient>,
) -> OsintReport {
    let domain = normalize_domain(raw_domain);
    const OSINT_BUILD_TAG: &str = "OSINT-v3.2-build-20261010-WORDLIST~320";
    println!(
        "\n  \x1b[38;5;196m[{}]\x1b[0m Reconnaissance complète → \x1b[33m{}\x1b[0m",
        OSINT_BUILD_TAG, domain
    );
    println!("  \x1b[90m fingerprint: wordlist≈320 · crt.sh robuste · DoH Cloudflare · {} · live_graph={}\x1b[0m",
        if keys.shodan.is_some() { "Shodan ON" } else { "keys partielles" },
        if emit.is_some() { "WS" } else { "OFF" });

    // ── WS GRAPH: bootstrap (nœud racine) ───────────────────────────────────
    emit_osint_bootstrap(emit, &domain).await;

    // Sources parallèles
    print!("  → Sous-domaines (crt.sh + brute)... ");
    let (subdomains_crt, dns_brute, wayback, github_leaks) = tokio::join!(
        crtsh_subdomains(&domain),
        dns_brute_force(&domain),
        wayback_urls(&domain),
        github_search(&domain, keys.github.as_deref()),
    );
    println!(
        "\x1b[32mcrt.sh={}, brute={}\x1b[0m",
        subdomains_crt.len(),
        dns_brute.len()
    );

    // Fusionner les sous-domaines
    let mut all_subdomains = subdomains_crt;
    for s in dns_brute {
        if !all_subdomains
            .iter()
            .any(|x: &SubdomainEntry| x.subdomain == s.subdomain)
        {
            all_subdomains.push(s);
        }
    }

    // ── WS GRAPH: émission pré-résolution (passifs CT + brute) ───────────────
    {
        let snap_stats = OsintGraphStats {
            total_subdomains: all_subdomains.len(),
            active_subdomains: 0,
            total_leaks: github_leaks.len(),
            total_historical: wayback.len(),
            ..Default::default()
        };
        emit_osint_subdomains(emit, &domain, &all_subdomains, &snap_stats).await;
    }

    // Résolution DNS
    print!(
        "  → Résolution DNS ({} sous-domaines)... ",
        all_subdomains.len()
    );
    let mut resolved = all_subdomains.clone();
    resolve_subdomains(&mut resolved).await;
    let n_actifs = resolved.iter().filter(|s| s.ip.is_some()).count();
    println!("\x1b[32m{} actifs\x1b[0m", n_actifs);

    // ── WS GRAPH: mise à jour après résolution (IPs liées aux sub actifs) ────
    {
        let snap_stats = OsintGraphStats {
            total_subdomains: resolved.len(),
            active_subdomains: n_actifs,
            total_ips: resolved
                .iter()
                .filter_map(|s| s.ip.as_ref())
                .collect::<HashSet<_>>()
                .len(),
            total_leaks: github_leaks.len(),
            total_historical: wayback.len(),
            ..Default::default()
        };
        emit_osint_subdomains(emit, &domain, &resolved, &snap_stats).await;
    }

    // Shodan sur les IPs découvertes
    let mut open_ports = Vec::new();
    if let Some(ref sk) = keys.shodan {
        // 1) Recherche large par hostname (découvre des IPs non résolues par DNS)
        let search_query = format!("hostname:{}", domain);
        let shodan_hosts = shodan_search(&search_query, sk).await;
        for host in &shodan_hosts {
            for (j, port) in host.ports.iter().enumerate() {
                open_ports.push(ShodanResult {
                    ip: host.ip.clone(),
                    port: *port,
                    service: "unknown".into(),
                    banner: host.banners.get(j).cloned(),
                    country: host.country.clone(),
                });
            }
        }

        // 2) Lookup détaillé par IP (1 req/sec pour éviter le rate limit)
        let ips: Vec<String> = resolved
            .iter()
            .filter_map(|s| s.ip.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let ip_count = ips.len();
        if ip_count > 0 {
            println!("  → Shodan IP lookup ({} IPs)...", ip_count);
            for (i, ip) in ips.iter().enumerate() {
                if i > 0 || !shodan_hosts.is_empty() {
                    tokio::time::sleep(Duration::from_millis(1100)).await;
                }
                if let Some(host) = shodan_host(ip, sk).await {
                    for port in &host.ports {
                        // Éviter les doublons (déjà trouvés via search)
                        if !open_ports
                            .iter()
                            .any(|p| p.ip == host.ip && p.port == *port)
                        {
                            open_ports.push(ShodanResult {
                                ip: host.ip.clone(),
                                port: *port,
                                service: "unknown".into(),
                                banner: host.banners.first().cloned(),
                                country: host.country.clone(),
                            });
                        }
                    }
                }
            }
        }
        println!("  ✓ Shodan : {} ports trouvés", open_ports.len());
    }

    // DNS records + emails
    print!("  → Enregistrements DNS (DoH Cloudflare)... ");
    let dns_records = collect_dns_records(&domain).await;
    println!("\x1b[32m{} records\x1b[0m", dns_records.len());
    let emails = extract_emails_from_dns(&dns_records, &domain);
    if !emails.is_empty() {
        println!("  \x1b[33m→ Emails extraits : {}\x1b[0m", emails.len());
    }

    // HIBP
    let mut breaches = Vec::new();
    if let Some(ref hk) = keys.hibp {
        print!("  → HIBP breaches ({} emails)... ", emails.len().min(5));
        for email in emails.iter().take(5) {
            let b = check_hibp(email, Some(hk)).await;
            breaches.extend(b);
        }
        println!("{} breaches", breaches.len());
    }

    // Wayback sensitive URLs
    let cert_domains: Vec<String> = resolved.iter().map(|s| s.subdomain.clone()).collect();
    let wayback_sensitive: Vec<String> = wayback
        .iter()
        .filter(|e| {
            ["backup", "config", ".sql", ".env", "admin"]
                .iter()
                .any(|k| e.url.contains(k))
        })
        .map(|e| e.url.clone())
        .collect();
    if !wayback_sensitive.is_empty() {
        println!(
            "  \x1b[38;5;196m[Wayback ⚠️]\x1b[0m {} URLs sensibles historiques",
            wayback_sensitive.len()
        );
    }

    // Technologies
    print!("  → Détection technologies web... ");
    let technologies = detect_technologies_from_subdomains(&resolved).await;
    println!("\x1b[34m{} détectées\x1b[0m", technologies.len());

    println!("  \x1b[32m[OSINT v2]\x1b[0m Terminé. Sous-domaines={}, Ports={}, Leaks={}, Emails={}, Techs={}, DNSrecs={}",
        resolved.len(), open_ports.len(), github_leaks.len(),
        emails.len(), technologies.len(), dns_records.len());

    let mut report = OsintReport {
        target: domain.clone(),
        subdomains: resolved,
        emails,
        breaches,
        technologies,
        open_ports,
        cert_domains,
        github_leaks,
        dns_records,
        intelligence: None,
    };

    // Analyse Intelligence LLM si client dispo
    if let Some(client) = llm_client {
        print!("  → Analyse Intelligence LLM... ");
        if let Ok(intel) = analyze_osint_with_llm(&report, client).await {
            println!("\x1b[32mOK\x1b[0m");
            report.intelligence = Some(intel);
        } else {
            println!("\x1b[31mÉchec\x1b[0m");
        }
    }

    // ── WS GRAPH: snapshot FINAL complet (DNS records + emails + breaches
    // + technologies + ports) — envoyé après build du graphe total.
    if let Some(em) = emit {
        let snap = build_osint_graph(&report);
        println!(
            "  \x1b[35m[OSINT → WS]\x1b[0m graphe envoyé: {} nœuds · {} liens (cible {})",
            snap.nodes.len(),
            snap.edges.len(),
            snap.target
        );
        em.send_osint_snapshot(snap).await;
    }

    report
}
