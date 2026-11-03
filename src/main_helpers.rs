//! Fonctions utilitaires exposées pour l'agent IA autonome
#![allow(dead_code)]

use std::collections::HashMap;

use crate::cve::{find_cves_for_version, CveDatabase};
use crate::exploits::{ExploitManifest, PentestConfig};
use crate::flows::ScanTargetSummary;
use crate::reports::GraphNode;
use crate::risk::{evaluate_risk_enriched, EnrichmentContext, RiskRules};
use crate::scanner::enhanced::{analyze_security_headers, enhance_banner};
use crate::scanner::{
    extract_version, grab_http_banner, grab_tcp_banner, port_to_service, BannerResult,
};

// ─────────────────────────────────────────────────────────────────────────────
// Drapeaux d'environnement (CI / mode test)
// ─────────────────────────────────────────────────────────────────────────────

/// Lit un drapeau booléen d'environnement. Valeurs activantes : 1, true, yes, on
/// (insensible à la casse). Absent ou toute autre valeur → false.
fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// `NRTG_TEST_MODE` — les agents ne doivent PAS émettre de requêtes LLM réelles
/// (cf. job CI `test`). Active le client LLM factice dans `llm::build_client`.
pub fn test_mode_enabled() -> bool {
    env_flag("NRTG_TEST_MODE")
}

/// `NRTG_DRY_RUN` — aucune action réseau offensive réelle (exploits désactivés).
pub fn dry_run_enabled() -> bool {
    env_flag("NRTG_DRY_RUN")
}

// ─────────────────────────────────────────────────────────────────────────────
// OPSEC — masquage des secrets
// ─────────────────────────────────────────────────────────────────────────────

/// Masque un secret pour tout affichage console ou export (OPSEC : jamais de
/// secret en clair sur disque). Conserve un préfixe lisible (4 car.) pour
/// l'identification opérateur. Tronque sur les caractères Unicode, jamais sur
/// les octets (pas de panic UTF-8).
pub fn mask_secret(secret: &str) -> String {
    let visible: String = secret.chars().take(4).collect();
    format!("{}***({} car.)", visible, secret.chars().count())
}

/// Tronque une chaîne sur un nombre **maximal de caractères** (et non
/// d'octets) pour tout affichage borné. Évite toute panique sur frontière
/// UTF-8 lorsque le texte contient des caractères multi-octets (accents, etc.).
pub fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// Masque les données sensibles d'un contenu de fichier exfiltré (LFI/RFI)
/// avant tout affichage console ou persistance sur disque (OPSEC : jamais de
/// secret en clair). Conserve la structure du fichier — noms de variables,
/// utilisateurs — mais remplace les valeurs associées à des mots-clés
/// sensibles, ainsi que les hachages de type `/etc/shadow`.
pub fn redact_file_secrets(content: &str) -> String {
    const SENSITIVE: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "authorization",
        "credential",
        "auth_token",
        "aws_secret",
        "db_pass",
        "mysql_pwd",
        "session_key",
    ];

    content
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();

            // `KEY=value` ou `KEY: value` — la valeur est masquée dès que la
            // clé évoque un secret.
            let sep = line.find('=').or_else(|| line.find(": ").map(|i| i + 1));
            if let Some(idx) = sep {
                if SENSITIVE.iter().any(|k| lower.contains(k)) {
                    let key = line[..=idx.min(line.len() - 1)].trim_end();
                    return format!("{} <REDACTED>", key);
                }
            }

            // `/etc/shadow` : `user:$id$salt$hash:…` — le premier champ vient
            // avant le premier ':', le hachage juste après.
            let mut parts = line.splitn(3, ':');
            if let (Some(user), Some(hash)) = (parts.next(), parts.next()) {
                let looks_like_hash = hash.len() > 20
                    && (hash.starts_with('$')
                        || hash
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '/'));
                if !user.is_empty() && !hash.is_empty() && looks_like_hash {
                    return format!("{}:<REDACTED>", user);
                }
            }

            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers utilisés par l'agent IA autonome
// ─────────────────────────────────────────────────────────────────────────────

/// Version publique de scan_single_target — utilisée par l'agent IA
pub async fn scan_single_target_pub(
    raw: &str,
    cve_db: &CveDatabase,
    risk_rules: &RiskRules,
    http_t: u64,
    tcp_t: u64,
    verify_tls: bool,
) -> Option<(GraphNode, ScanTargetSummary)> {
    scan_single_target_enriched(raw, cve_db, risk_rules, http_t, tcp_t, verify_tls, None, 1).await
}

/// Version enrichie: accepte exploit_manifest (pour le boost exploit match) et open_port_count
pub async fn scan_single_target_enriched(
    raw: &str,
    cve_db: &CveDatabase,
    risk_rules: &RiskRules,
    http_t: u64,
    tcp_t: u64,
    verify_tls: bool,
    exploit_manifest: Option<&ExploitManifest>,
    host_open_port_count: usize,
) -> Option<(GraphNode, ScanTargetSummary)> {
    let (id, protocol, host, port, is_http) = parse_target_simple(raw)?;
    let label = format!("Host {}:{} ({})", host, port, protocol);

    let fallback_http = BannerResult {
        banner: None,
        content_type: None,
        service_name: if port == 443 { "https" } else { "http" }.into(),
        headers: HashMap::new(),
        http_status: None,
        page_title: None,
        dns_validated: false,
        silent_port: false,
        tls_info: None,
    };
    let fallback_tcp = BannerResult {
        banner: None,
        content_type: None,
        service_name: port_to_service(port).into(),
        headers: HashMap::new(),
        http_status: None,
        page_title: None,
        dns_validated: false,
        silent_port: false,
        tls_info: None,
    };

    let result: BannerResult = if is_http {
        let url = if raw.starts_with("http") {
            raw.to_string()
        } else {
            format!("http://{}:{}", host, port)
        };
        match grab_http_banner(&url, http_t, verify_tls).await {
            Ok(b) => b,
            Err(_) => fallback_http,
        }
    } else {
        match grab_tcp_banner(&host, port, tcp_t).await {
            Ok(b) => b,
            Err(_) => fallback_tcp,
        }
    };

    let reachable = !result.silent_port
        && result.dns_validated
        && (result.banner.is_some()
            || result.http_status.is_some()
            || result.service_name == "http"
            || result.service_name == "https");

    let version_info = result
        .banner
        .as_deref()
        .and_then(|b| extract_version(b, &protocol));

    let (product, version) = match &version_info {
        Some(vi) => (vi.product.clone(), vi.version.clone()),
        None => {
            let p = match result.service_name.as_str() {
                "ssh" => "openssh",
                "ftp" => "vsftpd",
                "smtp" => "postfix",
                "redis" => "redis",
                "mysql" => "mysql",
                "postgresql" => "postgresql",
                "mongodb" => "mongodb",
                "mssql" => "mssql",
                "elasticsearch" => "elasticsearch",
                "memcached" => "memcached",
                "smb" => "smb",
                "rdp" => "rdp",
                "ldap" => "ldap",
                "docker-api" => "docker",
                _ => "unknown",
            }
            .to_string();
            (p, "unknown".to_string())
        }
    };

    let cves = find_cves_for_version(cve_db, &product, &version);
    let cve_max = cves.iter().map(|c| c.1).fold(0.0f32, f32::max);

    // ── Enrichissement: enhanced.banner (OS + WAF + tech stack) + security hints ─
    let banner_str = result.banner.clone().unwrap_or_default();
    let enhanced = enhance_banner(
        &banner_str,
        &result.headers,
        "",
        None,
        None,
        None,
        &result.service_name,
    );
    let sec_hints =
        analyze_security_headers(&result.headers, result.page_title.as_deref(), &product);

    // ── Exploit match heuristic ────────────────────────────────────────────
    let has_matching_exploit = exploit_manifest
        .map(|em| {
            em.signatures.iter().any(|e| {
                e.service_match.iter().any(|s| {
                    s.eq_ignore_ascii_case(&result.service_name) || s.eq_ignore_ascii_case(&product)
                })
            })
        })
        .unwrap_or(false);

    // ── TLS info aggregation ───────────────────────────────────────────────
    let (tls_self_signed, tls_expired, tls_fingerprint) = result
        .tls_info
        .as_ref()
        .map(|t| {
            (
                t.self_signed,
                t.expired_or_future,
                Some(t.fingerprint_sha256.clone()),
            )
        })
        .unwrap_or((false, false, None));
    let weak_tls = tls_self_signed || tls_expired;

    // ── Version disclosure heuristic ───────────────────────────────────────
    let version_disclosed = result
        .banner
        .as_deref()
        .map(|b| b.chars().any(|c| c.is_ascii_digit()))
        .unwrap_or(false)
        || result
            .headers
            .get("server")
            .map(|s| s.chars().any(|c| c.is_ascii_digit()))
            .unwrap_or(false);

    // ── Internet-exposed heuristic (privés RFC1918 = non exposés) ─────────
    let internet_exposed = !host
        .parse::<std::net::IpAddr>()
        .map(|ip| match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                o[0] == 10
                    || (o[0] == 172 && (16..=31).contains(&o[1]))
                    || (o[0] == 192 && o[1] == 168)
                    || o[0] == 127
                    || v4.is_link_local()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
            }
        })
        .unwrap_or(false);

    // ── Enriched risk scoring (FIX #17) ────────────────────────────────────
    let ctx = EnrichmentContext {
        has_matching_exploit,
        default_creds_likely: sec_hints.default_creds_likely,
        weak_tls,
        version_disclosed,
        host_open_port_count,
        missing_security_headers: &sec_hints.missing_security_headers,
        internet_exposed,
    };
    let (risk, risk_reasons) = evaluate_risk_enriched(
        risk_rules,
        &protocol,
        Some(&result.service_name),
        result.banner.as_deref(),
        Some(&product),
        cves.len(),
        cve_max,
        ctx,
    );

    let summary = ScanTargetSummary {
        id: id.clone(),
        host: host.clone(),
        port,
        service: result.service_name.clone(),
        risk,
    };

    let (waf_name, waf_confidence, waf_indicators) = enhanced
        .waf
        .map(|w| (w.waf_name, w.confidence, w.indicators))
        .unwrap_or((None, 0.0, Vec::new()));
    let (os_type, os_confidence, os_evidence) = enhanced
        .os
        .map(|o| (o.os_type, o.confidence, o.evidence))
        .unwrap_or((None, 0.0, Vec::new()));
    let ts = enhanced.tech_stack.unwrap_or_default();

    Some((
        GraphNode {
            id,
            label,
            risk,
            services: vec![format!("{}/{}", result.service_name, port)],
            banner: result.banner.unwrap_or_else(|| "unknown".into()),
            version,
            protocol,
            product,
            cves,
            risk_reasons,
            host,
            port,
            reachable,
            waf_name,
            waf_confidence,
            waf_indicators,
            os_type,
            os_confidence,
            os_evidence,
            tech_stack_web_server: ts.web_server,
            tech_stack_framework: ts.framework,
            tech_stack_language: ts.language,
            tech_stack_cms: ts.cms,
            tech_stack_js_frameworks: ts.javascript_frameworks,
            missing_security_headers: sec_hints.missing_security_headers,
            weak_headers: sec_hints.weak_headers,
            insecure_cookies: sec_hints.insecure_cookies,
            default_creds_likely: sec_hints.default_creds_likely,
            tls_self_signed,
            tls_expired,
            tls_fingerprint,
            page_title: result.page_title,
            dns_validated: result.dns_validated,
            silent_port: result.silent_port,
        },
        summary,
    ))
}

/// Version publique de expand_target pour l'agent IA
pub fn expand_target_pub(target: &str) -> Vec<String> {
    let raw = target.trim();
    if raw.is_empty() {
        return vec![];
    }

    // CIDR : 192.168.1.0/24:22
    if let Some((cidr_part, rest)) = raw.split_once('/') {
        let (prefix, port_raw) = if rest.contains(':') {
            rest.split_once(':').unwrap_or((rest, ""))
        } else {
            (rest, "")
        };
        let port_opt = if port_raw.is_empty() {
            None
        } else {
            Some(port_raw)
        };
        if prefix.chars().all(|c| c.is_ascii_digit()) {
            let cidr = format!("{}/{}", cidr_part, prefix);
            if let Ok(net) = cidr.parse::<ipnetwork::IpNetwork>() {
                let count: u64 = match net {
                    ipnetwork::IpNetwork::V4(ref v4) => 2u64.pow(32 - v4.prefix() as u32),
                    ipnetwork::IpNetwork::V6(_) => u64::MAX,
                };
                if count <= 256 {
                    let port = port_opt.and_then(|p| p.parse::<u16>().ok()).unwrap_or(80);
                    return net
                        .iter()
                        .filter(|ip| {
                            if let std::net::IpAddr::V4(v4) = ip {
                                let o = v4.octets()[3];
                                o != 0 && o != 255
                            } else {
                                true
                            }
                        })
                        .map(|ip| format!("{}:{}", ip, port))
                        .collect();
                }
            }
        }
    }

    vec![raw.to_string()]
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_target_simple(raw: &str) -> Option<(String, String, String, u16, bool)> {
    if raw.starts_with("http://") || raw.starts_with("https://") {
        let url = url::Url::parse(raw).ok()?;
        let scheme = url.scheme().to_string();
        let host = url.host_str()?.to_string();
        let port = url.port_or_known_default()?;
        Some((format!("{}:{}", host, port), scheme, host, port, true))
    } else {
        let parts: Vec<&str> = raw.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return None;
        }
        let host: String = parts[1].to_string();
        let port: u16 = parts[0].parse().ok()?;
        if port == 0 {
            return None;
        }
        let svc = port_to_service(port).to_string();
        Some((format!("{}:{}", host, port), svc, host, port, false))
    }
}
