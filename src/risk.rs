use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct VersionRiskBump {
    pub service: String,
    pub product: String,
    pub pattern: String,
    pub risk: i32,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RiskRules {
    pub base_risk_by_service: HashMap<String, i32>,
    pub version_bumps: Vec<VersionRiskBump>,
    pub cap_risk: i32,
}

pub fn load_risk_rules(path: &str) -> anyhow::Result<RiskRules> {
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read risk rules at {}: {}", path, e))?;
    let data: Value = serde_json::from_str(&content)?;

    let mut base_risk_by_service: HashMap<String, i32> = HashMap::new();
    if let Some(obj) = data.get("base_risk_by_service").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            if let Some(n) = v.as_i64() {
                base_risk_by_service.insert(k.to_lowercase(), n as i32);
            }
        }
    }

    let mut version_bumps = Vec::new();
    if let Some(arr) = data.get("version_risk_bump").and_then(|v| v.as_array()) {
        for entry in arr {
            let bump: VersionRiskBump = match serde_json::from_value(entry.clone()) {
                Ok(b) => b,
                Err(_) => continue,
            };
            version_bumps.push(bump);
        }
    }

    let cap_risk = data.get("cap_risk").and_then(|v| v.as_i64()).unwrap_or(5) as i32;

    Ok(RiskRules {
        base_risk_by_service,
        version_bumps,
        cap_risk,
    })
}

pub fn default_risk_rules() -> RiskRules {
    let mut base = HashMap::new();
    base.insert("http".into(), 3);
    base.insert("https".into(), 3);
    base.insert("ftp".into(), 3);
    base.insert("ssh".into(), 4);
    base.insert("smtp".into(), 3);
    base.insert("redis".into(), 4);
    base.insert("mysql".into(), 4);
    base.insert("postgresql".into(), 4);
    base.insert("mongodb".into(), 4);
    base.insert("mssql".into(), 4);
    base.insert("telnet".into(), 5);
    base.insert("dns".into(), 2);
    base.insert("tcp".into(), 2);

    RiskRules {
        base_risk_by_service: base,
        version_bumps: vec![],
        cap_risk: 5,
    }
}

pub fn compute_weighted_cve_score(
    cves: &[(String, f32, String, String)],
    cve_count: usize,
    cve_max: f32,
) -> f32 {
    let mut weighted_sum = 0.0f32;
    for (_, severity, _, _) in cves {
        let weight = if *severity >= 9.0 {
            10.0
        } else if *severity >= 7.0 {
            5.0
        } else if *severity >= 4.0 {
            2.0
        } else {
            1.0
        };
        weighted_sum += weight;
    }

    if cves.is_empty() {
        let weight = if cve_max >= 9.0 {
            10.0
        } else if cve_max >= 7.0 {
            5.0
        } else if cve_max >= 4.0 {
            2.0
        } else if cve_max > 0.0 {
            1.0
        } else {
            0.0
        };
        weighted_sum = weight * cve_count as f32;
    }

    let density_bonus = (cve_count as f32).sqrt() * 0.5;
    let raw = weighted_sum + density_bonus;

    let normalized = (raw / 1000.0f32.sqrt()) * 100.0;
    normalized.min(100.0).max(0.0)
}

pub fn evaluate_risk(
    rules: &RiskRules,
    protocol: &str,
    service_name: Option<&str>,
    banner: Option<&str>,
    product: Option<&str>,
    cve_count: usize,
    cve_max_severity: f32,
) -> (i32, Vec<String>) {
    let mut reasons = Vec::new();
    let protocol_key = protocol.to_lowercase();
    let svc_key = service_name
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| protocol_key.clone());

    let mut risk = rules
        .base_risk_by_service
        .get(&svc_key)
        .or_else(|| rules.base_risk_by_service.get(&protocol_key))
        .copied()
        .unwrap_or(2);

    reasons.push(format!(
        "Base risk for service={} (protocol={}): {}",
        svc_key, protocol_key, risk
    ));

    let banner_lc = banner.map(|b| b.to_lowercase()).unwrap_or_default();
    let product_lc = product.map(|p| p.to_lowercase()).unwrap_or_default();

    for rule in &rules.version_bumps {
        let svc_match = rule.service == "*"
            || rule.service.to_lowercase() == svc_key
            || rule.service.to_lowercase() == protocol_key;
        let product_match = rule.product == "*"
            || (rule.pattern.is_empty() && product_lc.contains(&rule.product.to_lowercase()))
            || product_lc.contains(&rule.product.to_lowercase());

        if !svc_match {
            continue;
        }
        if rule.product != "*" && !product_match {
            continue;
        }

        let pattern_match = rule.pattern.is_empty()
            || banner_lc.contains(&rule.pattern.to_lowercase())
            || product_lc.contains(&rule.pattern.to_lowercase());

        if pattern_match && rule.risk > risk {
            risk = rule.risk;
            if !rule.reason.is_empty() {
                reasons.push(format!("Risk bumped to {}: {}", risk, rule.reason));
            } else {
                reasons.push(format!(
                    "Risk bumped to {} by pattern '{}'",
                    risk, rule.pattern
                ));
            }
        }
    }

    if cve_max_severity >= 9.0 {
        risk = risk.max(5);
        reasons.push(format!(
            "Risk maxed to {}: critical CVEs present (max severity {:.1})",
            rules.cap_risk, cve_max_severity
        ));
    } else if cve_max_severity >= 7.0 && risk < 4 {
        risk = 4;
        reasons.push(format!(
            "Risk bumped to {}: high-severity CVEs (max {:.1})",
            risk, cve_max_severity
        ));
    } else if cve_count > 0 && risk < 3 {
        risk = 3;
        reasons.push(format!(
            "Risk bumped to {}: {} CVE(s) matched",
            risk, cve_count
        ));
    }

    if cve_count > 0 && cve_max_severity > 0.0 {
        let weight = cve_max_severity * (1.0 + (cve_count as f32).sqrt() * 0.3);
        let score = (weight / 100.0f32.sqrt()) * 100.0;
        let score = score.min(100.0).max(0.0);

        let new_risk = if score < 5.0 {
            1
        } else if score < 20.0 {
            2
        } else if score < 50.0 {
            3
        } else if score < 80.0 {
            4
        } else {
            5
        };

        reasons.push(format!(
            "Weighted CVE score: {:.1} → risk level {}",
            score, new_risk
        ));
        risk = risk.max(new_risk);
    }

    risk = risk.min(rules.cap_risk);
    (risk, reasons)
}

/// Extended risk context used by evaluate_risk_enriched (FIX #17: correlated scoring).
#[derive(Debug, Clone, Default)]
pub struct EnrichmentContext<'a> {
    /// True if at least one exploit signature matched the banner (higher real exploitability)
    pub has_matching_exploit: bool,
    /// True if the banner or service suggests default creds are possible
    pub default_creds_likely: bool,
    /// Set if TLS is "expired_or_future" or "self-signed" (weak security posture)
    pub weak_tls: bool,
    /// Set if the service exposes version banner / verbose headers (info leak)
    pub version_disclosed: bool,
    /// Open port count for this host — more exposed services = higher aggregate risk
    pub host_open_port_count: usize,
    /// List of missing security headers (HTTP only)
    pub missing_security_headers: &'a [String],
    /// Service is directly reachable from internet (no NAT hint)
    pub internet_exposed: bool,
}

/// Enriched risk evaluation (FIX #17): correlates CVEs with exploitability, default creds,
/// weak TLS, information disclosure, host exposure density, missing headers.
/// Returns (risk_level_1..=5, detailed_reasons).
pub fn evaluate_risk_enriched(
    rules: &RiskRules,
    protocol: &str,
    service_name: Option<&str>,
    banner: Option<&str>,
    product: Option<&str>,
    cve_count: usize,
    cve_max_severity: f32,
    ctx: EnrichmentContext<'_>,
) -> (i32, Vec<String>) {
    let (base_risk, mut reasons) = evaluate_risk(
        rules,
        protocol,
        service_name,
        banner,
        product,
        cve_count,
        cve_max_severity,
    );
    let mut risk = base_risk;
    let max = rules.cap_risk.max(5);

    // ── Boost 1: Exploit signature match = real weaponization (FIX #17) ───
    if ctx.has_matching_exploit {
        risk = risk.min(max).max(risk.min(max) + 1).min(max);
        reasons.push("BOOST +1: matching exploit signature (exploitability confirmed)".to_string());
    }

    // ── Boost 2: Default creds + exposed = instant high risk ──────────────
    if ctx.default_creds_likely {
        if cve_count == 0 {
            risk = risk.min(max).max(4);
            reasons.push("BOOST → 4+: default credentials likely on product".to_string());
        } else {
            risk = risk.min(max).max(risk + 1).min(max);
            reasons.push("BOOST +1: default credentials likely on vulnerable product".to_string());
        }
    }

    // ── Boost 3: Weak TLS posture (self-signed + expired) ─────────────────
    if ctx.weak_tls {
        risk = risk.min(max).max(3);
        reasons.push("BOOST ≥3: weak TLS posture (expired / self-signed / untrusted)".to_string());
    }

    // ── Boost 4: Version disclosure on high-risk protocol ─────────────────
    if ctx.version_disclosed {
        let proto_lc = protocol.to_lowercase();
        let high_risk_proto = proto_lc.contains("http")
            || proto_lc.contains("ssh")
            || proto_lc.contains("ftp")
            || proto_lc.contains("smb")
            || proto_lc.contains("rdp");
        if high_risk_proto {
            reasons
                .push("INFO: version banner disclosed (facilitates targeted exploits)".to_string());
        }
    }

    // ── Boost 5: Density of open ports on host (exposure correlation) ──────
    if ctx.host_open_port_count >= 10 {
        risk = risk.min(max).max(risk + 1).min(max);
        reasons.push(format!(
            "BOOST +1: {}+ open ports on host (broad exposure)",
            ctx.host_open_port_count
        ));
    } else if ctx.host_open_port_count >= 4 {
        reasons.push(format!(
            "INFO: {} open ports on host",
            ctx.host_open_port_count
        ));
    }

    // ── Boost 6: Missing critical security headers (HTTP) ─────────────────
    let critical_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
    ];
    let missing_critical: Vec<_> = critical_headers
        .iter()
        .filter(|h| {
            ctx.missing_security_headers
                .iter()
                .any(|m| m.to_lowercase() == ***h)
        })
        .collect();
    if missing_critical.len() >= 2 {
        risk = risk.min(max).max(3);
        reasons.push(format!(
            "BOOST ≥3: {} critical security headers missing ({})",
            missing_critical.len(),
            missing_critical
                .iter()
                .map(|s| **s)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    // ── Boost 7: Internet exposed + CRITICAL CVE → MAX risk ───────────────
    if ctx.internet_exposed && cve_max_severity >= 9.0 {
        risk = max;
        reasons.push(format!(
            "BOOST → MAX ({}): internet-exposed host + CRITICAL CVE (CVSS {:.1})",
            max, cve_max_severity
        ));
    } else if ctx.internet_exposed && cve_max_severity >= 7.0 {
        risk = risk.min(max).max(risk + 1).min(max);
        reasons.push("BOOST +1: internet-exposed host + HIGH severity CVE".to_string());
    }

    (risk, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_risk_http() {
        let rules = default_risk_rules();
        let (r, _) = evaluate_risk(&rules, "http", None, None, None, 0, 0.0);
        assert_eq!(r, 3);
    }

    #[test]
    fn test_base_risk_telnet() {
        let rules = default_risk_rules();
        let (r, _) = evaluate_risk(&rules, "tcp", Some("telnet"), None, None, 0, 0.0);
        assert_eq!(r, 5);
    }

    #[test]
    fn test_cve_bumps_risk() {
        let rules = default_risk_rules();
        let (r, _) = evaluate_risk(&rules, "tcp", Some("ftp"), None, None, 2, 9.8);
        assert_eq!(r, 5);
    }

    #[test]
    fn test_risk_cap() {
        let rules = default_risk_rules();
        let (r, _) = evaluate_risk(
            &rules,
            "tcp",
            Some("redis"),
            Some("redis 5.0.3"),
            Some("redis"),
            5,
            10.0,
        );
        assert!(r <= rules.cap_risk);
    }

    #[test]
    fn test_enriched_default_creds_boost_to_4() {
        let rules = default_risk_rules();
        let ctx = EnrichmentContext {
            default_creds_likely: true,
            ..Default::default()
        };
        let (r, reasons) = evaluate_risk_enriched(
            &rules,
            "tcp",
            Some("mysql"),
            None,
            Some("mysql"),
            0,
            0.0,
            ctx,
        );
        assert!(r >= 4, "default creds should boost to 4+, got {}", r);
        assert!(reasons.iter().any(|x| x.contains("BOOST")));
    }

    #[test]
    fn test_enriched_weak_tls_boost_to_3() {
        let rules = default_risk_rules();
        let ctx = EnrichmentContext {
            weak_tls: true,
            ..Default::default()
        };
        let (r, _) =
            evaluate_risk_enriched(&rules, "tcp", Some("unknown"), None, None, 0, 0.0, ctx);
        assert!(r >= 3);
    }

    #[test]
    fn test_enriched_exploit_signature_boost_1() {
        let rules = default_risk_rules();
        let ctx = EnrichmentContext {
            has_matching_exploit: true,
            ..Default::default()
        };
        let (base_r, _) = evaluate_risk(&rules, "http", None, None, None, 0, 0.0);
        let (enr_r, reasons) =
            evaluate_risk_enriched(&rules, "http", None, None, None, 0, 0.0, ctx);
        assert!(enr_r >= base_r);
        assert!(reasons.iter().any(|x| x.contains("exploit signature")));
    }

    #[test]
    fn test_enriched_internet_exposed_critical_cve_max() {
        let rules = default_risk_rules();
        let ctx = EnrichmentContext {
            internet_exposed: true,
            ..Default::default()
        };
        let (r, reasons) = evaluate_risk_enriched(&rules, "https", None, None, None, 1, 9.5, ctx);
        assert_eq!(r, rules.cap_risk);
        assert!(reasons.iter().any(|x| x.contains("MAX")));
    }

    #[test]
    fn test_enriched_missing_critical_headers_boost() {
        let rules = default_risk_rules();
        let missing = vec![
            "strict-transport-security".into(),
            "content-security-policy".into(),
        ];
        let ctx = EnrichmentContext {
            missing_security_headers: &missing,
            ..Default::default()
        };
        let (r, reasons) = evaluate_risk_enriched(&rules, "http", None, None, None, 0, 0.0, ctx);
        assert!(r >= 3, "2+ critical headers missing → 3+, got {}", r);
        assert!(reasons
            .iter()
            .any(|x| x.contains("critical security headers")));
    }

    #[test]
    fn test_enriched_port_density_10plus_boost() {
        let rules = default_risk_rules();
        let ctx = EnrichmentContext {
            host_open_port_count: 15,
            ..Default::default()
        };
        let (r, reasons) = evaluate_risk_enriched(&rules, "tcp", None, None, None, 0, 0.0, ctx);
        assert!(reasons.iter().any(|x| x.contains("+ open ports")));
        let (base_r, _) = evaluate_risk(&rules, "tcp", None, None, None, 0, 0.0);
        assert!(r >= base_r);
    }
}
