use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;

#[derive(Debug, Clone, Default)]
pub struct CveEntry {
    pub cve: String,
    pub severity: f32,
    pub desc: String,
    pub affected_versions: Vec<String>,
    pub vector: String,
    /// CISA KEV : CVE exploitée « in the wild » (priorité maximale pour l'agent).
    pub kev: bool,
    /// Un exploit public est disponible (Exploit-DB / Metasploit).
    pub exploit_public: bool,
    /// Identifiants Exploit-DB référencés par la CVE (ex: `50383`), extraits des
    /// références NVD. Liste vide si aucun exploit public n'est référencé.
    pub edb_ids: Vec<u32>,
}

pub type CveDatabase = HashMap<String, Vec<CveEntry>>;

pub fn expand_product_aliases(product: &str) -> Vec<String> {
    let p = product.to_lowercase();
    let mut result: Vec<String> = vec![p.clone()];

    let mut add = |v: &str| {
        let s = v.to_lowercase();
        if !result.contains(&s) {
            result.push(s);
        }
    };

    match p.as_str() {
        "openssh" | "ssh" | "openbsd_openssh" => {
            add("openssh");
            add("ssh");
            add("openbsd_openssh");
        }
        "apache" | "http_server" | "apache_http_server" | "apache-http-server" => {
            add("apache");
            add("http_server");
            add("apache_http_server");
            add("apache-http-server");
        }
        "nginx" | "nginx_web_server" => {
            add("nginx");
            add("nginx_web_server");
        }
        "mysql" | "mariadb" | "mysql_server" => {
            add("mysql");
            add("mariadb");
            add("mysql_server");
        }
        "redis" | "redis_server" => {
            add("redis");
            add("redis_server");
        }
        "postgresql" | "postgres" | "postgresql_database" => {
            add("postgresql");
            add("postgres");
            add("postgresql_database");
        }
        "mongodb" | "mongo" | "mongodb_server" => {
            add("mongodb");
            add("mongo");
            add("mongodb_server");
        }
        "iis" | "internet_information_services" | "microsoft_iis" => {
            add("iis");
            add("internet_information_services");
            add("microsoft_iis");
        }
        "tomcat" | "apache_tomcat" | "tomcat_servlet" => {
            add("tomcat");
            add("apache_tomcat");
            add("tomcat_servlet");
        }
        "lighttpd" | "lighttpd_server" => {
            add("lighttpd");
            add("lighttpd_server");
        }
        "vsftpd" | "very_secure_ftp_daemon" => {
            add("vsftpd");
            add("very_secure_ftp_daemon");
        }
        "proftpd" | "proftp_server" => {
            add("proftpd");
            add("proftp_server");
        }
        "elasticsearch" | "elastic_search" | "elastic_search_engine" => {
            add("elasticsearch");
            add("elastic_search");
            add("elastic_search_engine");
        }
        "rabbitmq" | "rabbit_mq" | "rabbitmq_server" => {
            add("rabbitmq");
            add("rabbit_mq");
            add("rabbitmq_server");
        }
        "memcached" | "memcache" | "memcache_server" => {
            add("memcached");
            add("memcache");
            add("memcache_server");
        }
        "php" | "php_hypertext_preprocessor" => {
            add("php");
            add("php_hypertext_preprocessor");
        }
        "wordpress" | "wp" | "wordpress_cms" => {
            add("wordpress");
            add("wp");
            add("wordpress_cms");
        }
        "drupal" | "drupal_cms" => {
            add("drupal");
            add("drupal_cms");
        }
        "jenkins" | "jenkins_ci" | "jenkins_server" => {
            add("jenkins");
            add("jenkins_ci");
            add("jenkins_server");
        }
        "kubernetes" | "k8s" | "kubernetes_cluster" => {
            add("kubernetes");
            add("k8s");
            add("kubernetes_cluster");
        }
        _ => {}
    }

    result
}

pub fn cpe_product_match(banner_product: &str, db_product: &str) -> bool {
    let banner = banner_product.to_lowercase();

    if !db_product.starts_with("cpe:") {
        let dbp = db_product.to_lowercase();
        return banner == dbp || banner.contains(&dbp) || dbp.contains(&banner);
    }

    let parts: Vec<&str> = db_product.split(':').collect();
    if parts.len() < 5 {
        let dbp = db_product.to_lowercase();
        return banner == dbp || banner.contains(&dbp);
    }

    // CPE 2.3 : cpe:2.3:part:vendor:product:... → vendor = idx 3, product = idx 4
    // CPE 2.2 : cpe:/part:vendor:product:...    → vendor = idx 2, product = idx 3
    let (vendor_idx, product_idx) = if parts.get(1).copied() == Some("2.3") {
        (3, 4)
    } else {
        (2, 3)
    };
    let cpe_vendor = parts
        .get(vendor_idx)
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let cpe_product = parts
        .get(product_idx)
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    if cpe_vendor.is_empty() && cpe_product.is_empty() {
        return false;
    }

    let banner_aliases = expand_product_aliases(&banner);

    for alias in &banner_aliases {
        if alias == &cpe_product {
            return true;
        }
        if !cpe_vendor.is_empty() && alias.contains(&cpe_vendor) && alias.contains(&cpe_product) {
            return true;
        }
        let combined = format!("{}_{}", cpe_vendor, cpe_product);
        if alias == &combined {
            return true;
        }
        let combined_dash = format!("{}-{}", cpe_vendor, cpe_product);
        if alias == &combined_dash {
            return true;
        }
    }

    // Fallback substring heuristics (FIX #12: reduce false negatives like "Apache/2.4.49" vs "apache_http_server")
    if !cpe_product.is_empty() {
        let dash_cpe = cpe_product.replace('_', "-");
        let us_cpe = cpe_product.replace('-', "_");
        let flat_cpe = cpe_product.replace('_', "").replace('-', "");
        for alias in &banner_aliases {
            let flat_alias = alias.replace('_', "").replace('-', "");
            if alias.contains(&cpe_product)
                || alias.contains(&dash_cpe)
                || alias.contains(&us_cpe)
                || flat_alias.contains(&flat_cpe)
            {
                if !cpe_vendor.is_empty() {
                    let flat_vendor = cpe_vendor.replace('_', "").replace('-', "");
                    let combo = format!("{}{}", flat_vendor, flat_cpe);
                    if flat_alias.contains(&flat_vendor) || combo.contains(&flat_alias) {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }
    }

    false
}

/// Extrait le segment « produit » d'un CPE 2.2/2.3.
/// `cpe:/a:apache:http_server:2.4.46` → `Some("http_server")`.
pub fn cpe_product_segment(cpe: &str) -> Option<String> {
    if !cpe.starts_with("cpe:") {
        return None;
    }
    let parts: Vec<&str> = cpe.split(':').collect();
    // CPE 2.3 : cpe:2.3:part:vendor:product:... → product = idx 4
    // CPE 2.2 : cpe:/part:vendor:product:...    → product = idx 3
    let idx = if parts.get(1).copied() == Some("2.3") {
        4
    } else {
        3
    };
    parts
        .get(idx)
        .map(|s| s.trim_matches('*').to_lowercase())
        .filter(|s| !s.is_empty())
}

pub fn load_cve_db(path: &str) -> anyhow::Result<CveDatabase> {
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read CVE DB at {}: {}", path, e))?;
    let data: Value = serde_json::from_str(&content)?;

    let mut db: CveDatabase = HashMap::new();
    if let Some(obj) = data.as_object() {
        for (product, entries) in obj {
            if product.starts_with('_') {
                continue;
            }
            let mut list = Vec::new();
            if let Some(entries_array) = entries.as_array() {
                for entry in entries_array {
                    let cve = entry["cve"].as_str().unwrap_or("").to_string();
                    let severity = entry["severity"].as_f64().unwrap_or(0.0) as f32;
                    let desc = entry["desc"].as_str().unwrap_or("").to_string();
                    let vector = entry["vector"].as_str().unwrap_or("UNKNOWN").to_string();

                    let affected_versions: Vec<String> =
                        if let Some(s) = entry["affected_versions"].as_str() {
                            s.split(',').map(|x| x.trim().to_string()).collect()
                        } else {
                            entry["affected_versions"]
                                .as_array()
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                        .collect()
                                })
                                .unwrap_or_default()
                        };

                    // Identifiants Exploit-DB : tableau de nombres, tableau de
                    // chaînes ou liste « 50383,47890 » selon la source.
                    let edb_ids: Vec<u32> = if let Some(arr) = entry["edb_ids"].as_array() {
                        arr.iter()
                            .filter_map(|v| {
                                v.as_u64()
                                    .map(|n| n as u32)
                                    .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
                            })
                            .collect()
                    } else if let Some(s) = entry["edb_ids"].as_str() {
                        s.split(',').filter_map(|x| x.trim().parse().ok()).collect()
                    } else {
                        Vec::new()
                    };

                    list.push(CveEntry {
                        cve,
                        severity,
                        desc,
                        affected_versions,
                        vector,
                        kev: entry["kev"].as_bool().unwrap_or(false),
                        exploit_public: entry["exploit_public"].as_bool().unwrap_or(false),
                        edb_ids,
                    });
                }
            }
            db.insert(product.to_lowercase(), list);
        }
    }
    Ok(db)
}

fn normalize_version(v: &str) -> String {
    v.trim()
        .to_lowercase()
        .replace([' ', '_', '-'], "")
        .trim_matches(|c: char| !c.is_ascii_digit())
        .to_string()
}

/// Extrait le préfixe de version amont d'une chaîne de type distribution
/// (`2.4.41-4ubuntu3.13` → `2.4.41`, `7.2p2-4ubuntu2` → `7.2p2`).
/// Si la chaîne ne commence pas par un chiffre (« Apache httpd 2.4.29 »),
/// on la renvoie telle quelle : `normalize_version` fera le nettoyage.
fn upstream_version(v: &str) -> String {
    let s = v.trim().to_lowercase();
    let mut out = String::new();
    let mut seen_digit = false;
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            out.push(c);
            seen_digit = true;
            chars.next();
        } else if c == '.' && seen_digit {
            out.push(c);
            chars.next();
        } else if c == 'p' && seen_digit {
            // Niveau « portable » OpenSSH (ex. 7.2p2) : p suivi de chiffres
            let mut look = chars.clone();
            look.next();
            if look.peek().map(|x| x.is_ascii_digit()).unwrap_or(false) {
                out.push(c);
                chars.next();
            } else {
                break;
            }
        } else {
            break;
        }
    }
    if out.is_empty() {
        s
    } else {
        out
    }
}

/// Version canonique utilisée pour les comparaisons : on retire d'abord le
/// suffixe de packaging (distro), puis on normalise.
fn canonical_version(v: &str) -> String {
    normalize_version(&upstream_version(v))
}

/// Découpe une version en composants numériques (« 7.2p2 » → [7, 2, 2]).
fn numeric_components(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Vrai si l'un des deux vecteurs de composants est un préfixe de l'autre
/// (comparaison composant par composant, et non plus préfixe de chaîne :
/// évite que « 2.4.5 » ne matche « 2.4.50 »).
fn component_prefix(a: &[u64], b: &[u64]) -> bool {
    let n = a.len().min(b.len());
    n > 0 && a[..n] == b[..n]
}

fn try_parse_semver(v: &str) -> Option<semver::Version> {
    let norm = normalize_version(v);
    let parts: Vec<&str> = norm.split('.').collect();
    let padded: Vec<String> = (0..3)
        .map(|i| {
            parts
                .get(i)
                .and_then(|p| {
                    p.chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect::<String>()
                        .into()
                })
                .unwrap_or_else(|| "0".to_string())
        })
        .collect();
    let candidate = padded.join(".");
    semver::Version::parse(&candidate).ok()
}

fn version_in_range(detected: &str, range: &str) -> bool {
    let range_trim = range.trim();
    if range_trim == "*" || range_trim.is_empty() {
        return true;
    }
    // On compare sur la version canonique (suffixe de packaging retiré).
    let detected = canonical_version(detected);
    // Format interval "A - B" (espace autour du tiret)
    if range_trim.contains(" - ") {
        let mut it = range_trim.splitn(2, " - ");
        let lo = canonical_version(it.next().unwrap_or("").trim());
        let hi = canonical_version(it.next().unwrap_or("").trim());
        if let (Some(dv), Some(lv), Some(hv)) = (
            try_parse_semver(&detected),
            try_parse_semver(&lo),
            try_parse_semver(&hi),
        ) {
            return dv >= lv && dv <= hv;
        }
    }
    // Format csv de comparateurs: ">=2.4,<2.4.50"
    let conditions: Vec<&str> = range_trim.split(',').map(|s| s.trim()).collect();
    let dv = match try_parse_semver(&detected) {
        Some(v) => v,
        None => return versions_match(&detected, range_trim),
    };
    for cond in conditions {
        let (op, ver) = if let Some(rest) = cond.strip_prefix(">=") {
            (">=", rest.trim())
        } else if let Some(rest) = cond.strip_prefix("<=") {
            ("<=", rest.trim())
        } else if let Some(rest) = cond.strip_prefix('>') {
            (">", rest.trim())
        } else if let Some(rest) = cond.strip_prefix('<') {
            ("<", rest.trim())
        } else if let Some(rest) = cond.strip_prefix("==") {
            ("==", rest.trim())
        } else if let Some(rest) = cond.strip_prefix('=') {
            ("==", rest.trim())
        } else {
            ("==", cond.trim())
        };
        let ver = canonical_version(ver);
        let rv = match try_parse_semver(&ver) {
            Some(v) => v,
            None => return versions_match(&detected, range_trim),
        };
        let ok = match op {
            ">=" => dv >= rv,
            "<=" => dv <= rv,
            ">" => dv > rv,
            "<" => dv < rv,
            "==" => dv.major == rv.major && dv.minor == rv.minor && dv.patch == rv.patch,
            _ => versions_match(&detected, &ver),
        };
        if !ok {
            return false;
        }
    }
    true
}

fn versions_match(detected: &str, affected: &str) -> bool {
    if affected == "*" || detected == "*" {
        return true;
    }
    let has_cmp = affected.contains('>') || affected.contains('<') || affected.contains(" - ");
    if has_cmp {
        return version_in_range(detected, affected);
    }
    let d = canonical_version(detected);
    let a = canonical_version(affected);
    if d.is_empty() || a.is_empty() {
        return false;
    }
    if d == a {
        return true;
    }
    // Comparaison composant par composant (et non préfixe de chaîne brut).
    let (dc, ac) = (numeric_components(&d), numeric_components(&a));
    if component_prefix(&dc, &ac) {
        return true;
    }
    if let (Some(dv), Some(av)) = (try_parse_semver(detected), try_parse_semver(affected)) {
        if dv.major == av.major && dv.minor == av.minor {
            return dv.patch <= av.patch;
        }
    }
    false
}

pub fn find_cves_for_version(
    db: &CveDatabase,
    product: &str,
    version: &str,
) -> Vec<(String, f32, String, String)> {
    if version == "unknown" || product == "unknown" {
        return vec![];
    }

    let product_keys = expand_product_aliases(product);
    let mut seen_cves: HashSet<String> = HashSet::new();
    let mut result: Vec<(String, f32, String, String)> = Vec::new();

    for key in &product_keys {
        if let Some(list) = db.get(key) {
            for entry in list {
                if entry
                    .affected_versions
                    .iter()
                    .any(|av| versions_match(version, av))
                {
                    if !seen_cves.contains(&entry.cve) {
                        seen_cves.insert(entry.cve.clone());
                        result.push((
                            entry.cve.clone(),
                            entry.severity,
                            entry.desc.clone(),
                            entry.vector.clone(),
                        ));
                    }
                }
            }
        }
    }

    for (db_key, list) in db.iter() {
        if cpe_product_match(product, db_key) {
            for entry in list {
                if entry
                    .affected_versions
                    .iter()
                    .any(|av| versions_match(version, av))
                {
                    if !seen_cves.contains(&entry.cve) {
                        seen_cves.insert(entry.cve.clone());
                        result.push((
                            entry.cve.clone(),
                            entry.severity,
                            entry.desc.clone(),
                            entry.vector.clone(),
                        ));
                    }
                }
            }
        }
    }

    // Priorisation : KEV / exploit public d'abord, puis sévérité décroissante.
    // La valeur de tri provient de la base (les métadonnées kev/exploit_public
    // ne sont pas portées par le tuple de retour).
    let priorities: HashMap<String, f32> = result
        .iter()
        .map(|(cve, sev, _, _)| {
            let p = lookup_cve(db, cve).map(exploit_priority).unwrap_or(*sev);
            (cve.clone(), p)
        })
        .collect();
    result.sort_by(|a, b| {
        let pa = priorities.get(&a.0).copied().unwrap_or(a.1);
        let pb = priorities.get(&b.0).copied().unwrap_or(b.1);
        pb.partial_cmp(&pa).unwrap_or(std::cmp::Ordering::Equal)
    });

    result
}

// ── Interrogation de la base (garde-fous de l'agent IA) ──────────────────────

/// Extrait le premier identifiant CVE d'une chaîne libre.
/// « CVE-2021-41773 (Apache Path Traversal RCE) » → `Some("CVE-2021-41773")`.
pub fn extract_cve_id(s: &str) -> Option<String> {
    let re = regex::Regex::new(r"(?i)cve-\d{4}-\d{4,7}").ok()?;
    re.find(s).map(|m| m.as_str().to_uppercase())
}

/// Extrait l'identifiant Exploit-DB d'une URL de référence NVD.
/// `https://www.exploit-db.com/exploits/50383` → `Some(50383)`.
pub fn extract_edb_id(url: &str) -> Option<u32> {
    const NEEDLE: &str = "exploit-db.com/exploits/";
    let lower = url.to_ascii_lowercase();
    let start = lower.find(NEEDLE)? + NEEDLE.len();
    let digits: String = lower[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// L'identifiant CVE est-il présent dans la base locale ?
pub fn cve_exists(db: &CveDatabase, cve_id: &str) -> bool {
    let want = cve_id.to_uppercase();
    db.values()
        .any(|list| list.iter().any(|e| e.cve.to_uppercase() == want))
}

/// Première entrée de la base correspondant à un CVE.
pub fn lookup_cve<'a>(db: &'a CveDatabase, cve_id: &str) -> Option<&'a CveEntry> {
    let want = cve_id.to_uppercase();
    db.values().flatten().find(|e| e.cve.to_uppercase() == want)
}

/// Score de priorité d'exploitabilité d'une CVE.
/// Hiérarchie : CISA KEV (exploitée in-the-wild) > exploit public disponible
/// (Exploit-DB / Metasploit) > sévérité CVSS. Sert à trier les candidats
/// d'exploitation pour que l'agent tente d'abord ce qui a le plus de chances
/// d'aboutir.
pub fn exploit_priority(entry: &CveEntry) -> f32 {
    let mut score = entry.severity;
    if entry.exploit_public {
        score += 3.0;
    }
    if entry.kev {
        score += 5.0;
    }
    score
}

/// Le CVE s'applique-t-il au couple (produit, version) observé sur la cible ?
/// Une entrée sans plage de versions connue n'invalide pas l'exploitation
/// (applicabilité indéterminée → on ne bloque pas).
pub fn cve_applies_to(db: &CveDatabase, cve_id: &str, product: &str, version: &str) -> bool {
    if product == "unknown" || product.is_empty() {
        return false;
    }
    let want = cve_id.to_uppercase();

    let entry_matches = |e: &CveEntry| -> bool {
        if e.cve.to_uppercase() != want {
            return false;
        }
        e.affected_versions.is_empty()
            || version == "unknown"
            || e.affected_versions
                .iter()
                .any(|av| versions_match(version, av))
    };

    let product_keys = expand_product_aliases(product);

    if product_keys.iter().any(|key| {
        db.get(key)
            .map(|list| list.iter().any(&entry_matches))
            .unwrap_or(false)
    }) {
        return true;
    }

    db.iter()
        .any(|(db_key, list)| cpe_product_match(product, db_key) && list.iter().any(&entry_matches))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_matching_exact() {
        assert!(versions_match("1.14.0", "1.14.0"));
        assert!(versions_match("7.2", "7.2"));
    }

    #[test]
    fn test_extract_edb_id() {
        assert_eq!(
            extract_edb_id("https://www.exploit-db.com/exploits/50383"),
            Some(50383)
        );
        assert_eq!(
            extract_edb_id("http://exploit-db.com/exploits/47890/"),
            Some(47890)
        );
        assert_eq!(
            extract_edb_id("https://nvd.nist.gov/vuln/detail/CVE-2021-41773"),
            None
        );
        assert_eq!(extract_edb_id("https://www.exploit-db.com/exploits/"), None);
    }

    #[test]
    fn test_cpe_product_segment() {
        assert_eq!(
            cpe_product_segment("cpe:/a:apache:http_server:2.4.46").as_deref(),
            Some("http_server")
        );
        assert_eq!(
            cpe_product_segment("cpe:/a:openbsd:openssh:8.2p1").as_deref(),
            Some("openssh")
        );
        assert_eq!(
            cpe_product_segment("cpe:2.3:a:igor_sysoev:nginx:1.24.0:*:*:*:*:*:*:*").as_deref(),
            Some("nginx")
        );
        assert_eq!(cpe_product_segment("not-a-cpe"), None);
    }

    #[test]
    fn test_load_cve_db_parses_edb_ids() {
        let json = r#"{
            "apache": [
                {"cve":"CVE-2021-41773","severity":9.8,"desc":"d","affected_versions":["2.4.49"],
                 "kev":true,"exploit_public":true,"edb_ids":[50383,50406]}
            ],
            "openssh": [
                {"cve":"CVE-2099-0001","severity":5.0,"desc":"d","affected_versions":["8.2"],
                 "exploit_public":false,"edb_ids":"1234, 5678"}
            ]
        }"#;
        let tmp = std::env::temp_dir().join("nrtg_cve_edb_test.json");
        std::fs::write(&tmp, json).unwrap();
        let db = load_cve_db(tmp.to_str().unwrap()).unwrap();

        let apache = &db["apache"][0];
        assert_eq!(apache.edb_ids, vec![50383, 50406]);
        assert!(apache.exploit_public && apache.kev);

        let ssh = &db["openssh"][0];
        assert_eq!(ssh.edb_ids, vec![1234, 5678]);
        assert!(!ssh.exploit_public);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_version_matching_prefix() {
        assert!(versions_match("1.14.2", "1.14."));
        assert!(versions_match("5.0.3", "5.0."));
        assert!(versions_match("2.4.29", "2.4.29"));
    }

    #[test]
    fn test_version_matching_wildcard() {
        assert!(versions_match("anything", "*"));
    }

    #[test]
    fn test_version_matching_noise() {
        assert!(versions_match("nginx/1.14.0", "1.14.0"));
        assert!(versions_match("OpenSSH_7.2p2", "7.2"));
    }

    #[test]
    fn test_version_mismatch() {
        assert!(!versions_match("1.15.0", "1.14."));
        assert!(!versions_match("6.0.0", "5.0."));
    }

    #[test]
    fn test_expand_product_aliases_openssh() {
        let aliases = expand_product_aliases("openssh");
        assert!(aliases.contains(&"openssh".to_string()));
        assert!(aliases.contains(&"ssh".to_string()));
        assert!(aliases.contains(&"openbsd_openssh".to_string()));
    }

    #[test]
    fn test_expand_product_aliases_apache() {
        let aliases = expand_product_aliases("apache");
        assert!(aliases.contains(&"apache".to_string()));
        assert!(aliases.contains(&"http_server".to_string()));
        assert!(aliases.contains(&"apache_http_server".to_string()));
        assert!(aliases.contains(&"apache-http-server".to_string()));

        let aliases2 = expand_product_aliases("http_server");
        assert!(aliases2.contains(&"apache".to_string()));
        assert!(aliases2.contains(&"http_server".to_string()));
    }

    #[test]
    fn test_expand_product_aliases_mysql_mariadb() {
        let aliases = expand_product_aliases("mysql");
        assert!(aliases.contains(&"mysql".to_string()));
        assert!(aliases.contains(&"mariadb".to_string()));
        assert!(aliases.contains(&"mysql_server".to_string()));

        let aliases2 = expand_product_aliases("mariadb");
        assert!(aliases2.contains(&"mysql".to_string()));
        assert!(aliases2.contains(&"mariadb".to_string()));
    }

    #[test]
    fn test_expand_product_aliases_postgresql() {
        let aliases = expand_product_aliases("postgres");
        assert!(aliases.contains(&"postgresql".to_string()));
        assert!(aliases.contains(&"postgres".to_string()));
        assert!(aliases.contains(&"postgresql_database".to_string()));
    }

    #[test]
    fn test_cpe_product_match_simple() {
        assert!(cpe_product_match("apache", "apache"));
        assert!(cpe_product_match("Apache", "apache"));
        assert!(!cpe_product_match("nginx", "apache"));
    }

    #[test]
    fn test_cpe_product_match_cpe_string() {
        assert!(cpe_product_match(
            "apache",
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        ));
        assert!(cpe_product_match(
            "http_server",
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        ));
        assert!(cpe_product_match(
            "openssh",
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
        ));
        assert!(cpe_product_match(
            "ssh",
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
        ));
        assert!(cpe_product_match(
            "nginx",
            "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
        ));
        assert!(!cpe_product_match(
            "apache",
            "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
        ));
    }

    #[test]
    fn test_find_cves_for_version_with_aliases() {
        let mut db: CveDatabase = HashMap::new();

        let cve1 = CveEntry {
            cve: "CVE-2021-1234".to_string(),
            severity: 7.5,
            desc: "Test CVE 1".to_string(),
            affected_versions: vec!["2.4.49".to_string()],
            vector: "NETWORK".to_string(),
            ..Default::default()
        };

        let cve2 = CveEntry {
            cve: "CVE-2021-5678".to_string(),
            severity: 9.8,
            desc: "Test CVE 2".to_string(),
            affected_versions: vec!["2.4.*".to_string()],
            vector: "NETWORK".to_string(),
            ..Default::default()
        };

        db.insert("http_server".to_string(), vec![cve1.clone()]);
        db.insert("apache_http_server".to_string(), vec![cve2.clone()]);

        let results = find_cves_for_version(&db, "apache", "2.4.49");
        assert_eq!(results.len(), 2);

        let results2 = find_cves_for_version(&db, "http_server", "2.4.49");
        assert_eq!(results2.len(), 2);
    }

    #[test]
    fn test_find_cves_prioritizes_kev_and_public_exploit() {
        let mut db: CveDatabase = HashMap::new();

        // Sévérité élevée mais NI KEV ni exploit public.
        let high = CveEntry {
            cve: "CVE-2020-0001".to_string(),
            severity: 7.0,
            affected_versions: vec!["1.0".to_string()],
            ..Default::default()
        };
        // Exploit public, sévérité moyenne.
        let exploitable = CveEntry {
            cve: "CVE-2020-0002".to_string(),
            severity: 5.0,
            affected_versions: vec!["1.0".to_string()],
            exploit_public: true,
            ..Default::default()
        };
        // KEV (in-the-wild) malgré une sévérité faible → doit passer en tête.
        let kev = CveEntry {
            cve: "CVE-2020-0003".to_string(),
            severity: 3.0,
            affected_versions: vec!["1.0".to_string()],
            exploit_public: true,
            kev: true,
            ..Default::default()
        };

        db.insert("myapp".to_string(), vec![high, exploitable, kev]);

        let results = find_cves_for_version(&db, "myapp", "1.0");
        let order: Vec<&str> = results.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(
            order,
            vec!["CVE-2020-0003", "CVE-2020-0002", "CVE-2020-0001"]
        );
    }

    #[test]
    fn test_version_in_range_interval_dash() {
        assert!(version_in_range("2.4.40", "2.4.30 - 2.4.50"));
        assert!(version_in_range("2.4.30", "2.4.30 - 2.4.50"));
        assert!(version_in_range("2.4.50", "2.4.30 - 2.4.50"));
        assert!(!version_in_range("2.4.51", "2.4.30 - 2.4.50"));
        assert!(!version_in_range("2.4.29", "2.4.30 - 2.4.50"));
    }

    #[test]
    fn test_version_in_range_csv_comparators() {
        assert!(version_in_range("2.4.35", ">=2.4,<2.4.50"));
        assert!(!version_in_range("2.4.50", ">=2.4,<2.4.50"));
        assert!(version_in_range("1.14.0", ">=1.14,<=1.14.3"));
        assert!(!version_in_range("1.15.0", ">=1.14,<=1.14.3"));
    }

    #[test]
    fn test_version_in_range_single_comparator() {
        assert!(version_in_range("7.7", ">=7.0"));
        assert!(version_in_range("2.2", "<2.3"));
        assert!(!version_in_range("2.3", "<2.3"));
        assert!(version_in_range("1.0", "==1.0"));
    }

    #[test]
    fn test_version_in_range_star_or_empty() {
        assert!(version_in_range("anything", "*"));
        assert!(version_in_range("8.0.0", ""));
    }

    #[test]
    fn test_normalize_version_strips_noise() {
        assert_eq!(normalize_version("nginx/1.14.0 (Ubuntu)"), "1.14.0");
        assert_eq!(normalize_version("  7.2p2  "), "7.2p2");
        assert_eq!(normalize_version("Apache httpd 2.4.29"), "2.4.29");
    }

    #[test]
    fn test_try_parse_semver_padding() {
        let v = try_parse_semver("1.14").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (1, 14, 0));
        let v2 = try_parse_semver("8").unwrap();
        assert_eq!((v2.major, v2.minor, v2.patch), (8, 0, 0));
    }

    #[test]
    fn test_find_cves_unknown_returns_empty() {
        let db: CveDatabase = HashMap::new();
        let r = find_cves_for_version(&db, "unknown", "1.0");
        assert!(r.is_empty());
        let r2 = find_cves_for_version(&db, "mysql", "unknown");
        assert!(r2.is_empty());
    }

    #[test]
    fn test_find_cves_dedup_across_aliases() {
        let mut db: CveDatabase = HashMap::new();
        let cve = CveEntry {
            cve: "CVE-DEDUP-001".into(),
            severity: 7.0,
            desc: "dedup test".into(),
            affected_versions: vec!["1.0".into()],
            vector: "NETWORK".into(),
            ..Default::default()
        };
        db.insert("mysql".into(), vec![cve.clone()]);
        db.insert("mariadb".into(), vec![cve.clone()]);

        let results = find_cves_for_version(&db, "mysql", "1.0");
        assert_eq!(
            results.len(),
            1,
            "same CVE across aliases must be deduplicated"
        );
    }

    // ── P3b : matching de versions réaliste ──────────────────────────────

    #[test]
    fn test_upstream_version_strips_distro_suffix() {
        assert_eq!(canonical_version("2.4.41-4ubuntu3.13"), "2.4.41");
        assert_eq!(canonical_version("7.2p2-4ubuntu2.10"), "7.2p2");
        assert_eq!(canonical_version("1.18.0-6ubuntu14.4"), "1.18.0");
        assert_eq!(canonical_version("1.2.3+dfsg-1"), "1.2.3");
    }

    #[test]
    fn test_upstream_version_keeps_banner_forms() {
        // Les bannières non préfixées par un chiffre restent nettoyées par normalize_version
        assert_eq!(canonical_version("Apache httpd 2.4.29"), "2.4.29");
        assert_eq!(canonical_version("nginx/1.14.0 (Ubuntu)"), "1.14.0");
    }

    #[test]
    fn test_versions_match_distro_backport() {
        // Bannière distro vs plage amont
        assert!(versions_match("2.4.41-4ubuntu3.13", "2.4.41"));
        assert!(versions_match("7.2p2-4ubuntu2", "7.2p2"));
        assert!(versions_match("2.4.41-4ubuntu3.13", ">=2.4,<2.4.50"));
    }

    #[test]
    fn test_component_prefix_avoids_false_positive() {
        // « 2.4.5 » ne doit PAS matcher « 2.4.50 » par simple préfixe de chaîne
        assert!(!component_prefix(
            &numeric_components("2.4.5"),
            &numeric_components("2.4.50")
        ));
        assert!(component_prefix(
            &numeric_components("1.14.2"),
            &numeric_components("1.14")
        ));
    }

    // ── P1c : garde-fous sur les identifiants CVE ────────────────────────

    #[test]
    fn test_extract_cve_id_from_free_text() {
        assert_eq!(
            extract_cve_id("CVE-2021-41773 (Apache Path Traversal RCE)").as_deref(),
            Some("CVE-2021-41773")
        );
        assert_eq!(extract_cve_id("exploit/shellshock").as_deref(), None);
        assert_eq!(
            extract_cve_id("cve-2014-6271").as_deref(),
            Some("CVE-2014-6271")
        );
    }

    #[test]
    fn test_cve_exists_and_applies_to() {
        let mut db: CveDatabase = HashMap::new();
        db.insert(
            "apache".into(),
            vec![CveEntry {
                cve: "CVE-2021-41773".into(),
                severity: 9.8,
                desc: "path traversal".into(),
                affected_versions: vec!["2.4.49".into(), "2.4.50".into()],
                vector: "NETWORK".into(),
                ..Default::default()
            }],
        );

        assert!(cve_exists(&db, "cve-2021-41773"));
        assert!(!cve_exists(&db, "CVE-2021-99999"));
        assert!(cve_applies_to(&db, "CVE-2021-41773", "apache", "2.4.49"));
        assert!(!cve_applies_to(&db, "CVE-2021-41773", "apache", "2.4.55"));
        assert!(!cve_applies_to(&db, "CVE-2021-41773", "unknown", "2.4.49"));
    }
}
