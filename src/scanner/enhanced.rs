//! Enhanced scanning — WAF detection, OS fingerprinting, tech stack analysis
//! Used by the DIAPILE enrichment pass after banner scanning.
#![allow(dead_code)]
// Toutes les `Regex` de ce module sont compilées depuis des motifs **littéraux**
// (constantes de compilation) dans un `lazy_static!` : la compilation est
// infaillible dès lors que le motif est bien écrit, ce que les tests couvrent.
// Un `#[allow]` sur l'invocation de macro ne se propage pas à son expansion :
// on autorise donc `unwrap_used` au niveau du module.
#![allow(clippy::unwrap_used)]

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetection {
    pub detected: bool,
    pub waf_name: Option<String>,
    pub confidence: f32,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprint {
    pub os_type: Option<String>,
    pub os_version: Option<String>,
    pub confidence: f32,
    pub ttl: Option<u32>,
    pub window_size: Option<u32>,
    pub df_bit: Option<bool>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TechStack {
    pub web_server: Option<String>,
    pub framework: Option<String>,
    pub language: Option<String>,
    pub cms: Option<String>,
    pub javascript_frameworks: Vec<String>,
    pub databases: Vec<String>,
    pub cdn: Option<String>,
    pub auth_provider: Option<String>,
    pub api_gateway: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedBanner {
    pub raw_banner: String,
    pub service: String,
    pub version: Option<String>,
    pub os: Option<OsFingerprint>,
    pub waf: Option<WafDetection>,
    pub tech_stack: Option<TechStack>,
}

/// Contextual security notes attached to a node (no active probing)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityHints {
    /// Headers that are missing but should be present
    pub missing_security_headers: Vec<String>,
    /// Headers present but configured poorly
    pub weak_headers: Vec<(String, String)>,
    /// Page title (may reveal product/version)
    pub page_title: Option<String>,
    /// Detected cookies without Secure / HttpOnly flags
    pub insecure_cookies: Vec<String>,
    /// True if default creds are likely (Tomcat manager, Jenkins, etc.)
    pub default_creds_likely: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Static signature tables
// ─────────────────────────────────────────────────────────────────────────────

lazy_static! {
    // ── WAF signatures (header key patterns, lowercase) ─────────────────────
    static ref WAF_SIGS: Vec<(&'static str, Vec<&'static str>)> = vec![
        ("Cloudflare",   vec!["cf-ray", "cf-cache-status", "cf-request-id", "cf-connecting-ip"]),
        ("Akamai",       vec!["x-akamai-transformed", "akamai-grn", "x-check-cacheable"]),
        ("AWS WAF",      vec!["x-amzn-requestid", "x-amz-cf-id", "x-amz-id-2"]),
        ("ModSecurity",  vec!["x-modsecurity-txid", "x-modsecurity"]),
        ("F5 BIG-IP",    vec!["x-cnection", "x-waas-id", "bigipserver", "f5-bigip"]),
        ("Imperva",      vec!["x-iinfo", "incap_ses", "visid_incap", "x-cdn"]),
        ("Sucuri",       vec!["x-sucuri-id", "x-sucuri-cache"]),
        ("Barracuda",    vec!["barra_counter", "bnayuvpwsid"]),
        ("FortiWeb",     vec!["fortiwafsid", "x-fortiwaf"]),
        ("Radware",      vec!["x-ratelimit-limit", "rdwr"]),
        ("Fastly",       vec!["x-fastly-request-id", "fastly-io-info"]),
        ("Varnish",      vec!["x-varnish", "via"]),
        ("Nginx WAF",    vec!["x-nginx-cache", "x-cache-status"]),
        ("Reblaze",      vec!["x-reblaze-protection"]),
        ("Wallarm",      vec!["x-wallarm-node"]),
        ("StackPath",    vec!["x-sp-url", "x-storefront-url"]),
    ];

    // ── OS TTL → OS name (initial TTL values, we accept ±15 drift) ──────────
    static ref TTL_OS_MAP: Vec<(u32, &'static str, &'static str)> = vec![
        (30,  "Solaris",          "Solaris 2.x (old)"),
        (32,  "Windows",          "Windows 95/98"),
        (60,  "AIX",              "IBM AIX"),
        (64,  "Linux",            "Linux / FreeBSD / macOS"),
        (128, "Windows",          "Windows NT/2000/XP/Vista/7/10/11/Server"),
        (200, "OpenBSD",          "OpenBSD"),
        (255, "Cisco/Network",    "Cisco IOS / Network Device"),
    ];

    // ── TCP window size → OS type (typical values, ±200 tolerance) ──────────
    static ref WINDOW_OS_MAP: Vec<(u32, &'static str, f32)> = vec![
        (8192,  "Windows",       0.75),
        (65535, "Windows",       0.70),
        (64240, "Windows",       0.80),
        (5840,  "Linux",         0.75),
        (5792,  "Linux",         0.75),
        (29200, "Linux",         0.70),
        (65535, "Cisco/Network", 0.85),
    ];

    // ── Security header requirements ─────────────────────────────────────────
    static ref REQUIRED_SECURITY_HEADERS: Vec<&'static str> = vec![
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "content-security-policy",
        "referrer-policy",
        "permissions-policy",
    ];

    // ── CMS body-pattern detection ───────────────────────────────────────────
    static ref CMS_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("WordPress",   Regex::new(r"(?i)wp-content|wp-includes|wp-json").unwrap()),
        ("Drupal",      Regex::new(r"(?i)sites/default|drupal\.js|drupal-settings").unwrap()),
        ("Joomla",      Regex::new(r"(?i)media/jui|components/com_|joomla").unwrap()),
        ("Magento",     Regex::new(r"(?i)mage/cookies\.js|skin/frontend").unwrap()),
        ("Shopify",     Regex::new(r"(?i)cdn\.shopify\.com|shopify\.com/s/files").unwrap()),
        ("Typo3",       Regex::new(r"(?i)typo3|t3lib").unwrap()),
        ("Ghost",       Regex::new(r"(?i)ghost\.io|ghost/scripts").unwrap()),
        ("Strapi",      Regex::new(r"(?i)strapi|/admin/").unwrap()),
    ];

    // ── Framework body-pattern detection ─────────────────────────────────────
    static ref FRAMEWORK_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("Laravel",     Regex::new(r"(?i)laravel_session|laravel").unwrap()),
        ("Django",      Regex::new(r"(?i)django|csrfmiddlewaretoken").unwrap()),
        ("Rails",       Regex::new(r"(?i)ruby on rails|_rails").unwrap()),
        ("Spring",      Regex::new(r"(?i)spring-web|springboot|jsessionid").unwrap()),
        ("ASP.NET",     Regex::new(r"(?i)__viewstate|asp\.net").unwrap()),
        ("Flask",       Regex::new(r"(?i)werkzeug|flask").unwrap()),
        ("FastAPI",     Regex::new(r"(?i)fastapi|uvicorn").unwrap()),
        ("Next.js",     Regex::new(r"(?i)__next|_next/static").unwrap()),
        ("Nuxt",        Regex::new(r"(?i)__nuxt|_nuxt/").unwrap()),
    ];

    // ── JS Framework detection ───────────────────────────────────────────────
    static ref JS_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("React",       Regex::new(r"(?i)react(?:-dom)?\.(?:min\.)?js|react\.production").unwrap()),
        ("Vue.js",      Regex::new(r"(?i)vue(?:\.min)?\.js|vue-router").unwrap()),
        ("Angular",     Regex::new(r"(?i)angular(?:\.min)?\.js|ng-version").unwrap()),
        ("jQuery",      Regex::new(r"(?i)jquery(?:-[0-9.]+)?(?:\.min)?\.js").unwrap()),
        ("Svelte",      Regex::new(r"(?i)__svelte|svelte").unwrap()),
        ("Alpine.js",   Regex::new(r"(?i)alpinejs|x-data=").unwrap()),
        ("HTMX",        Regex::new(r"(?i)htmx|hx-get=").unwrap()),
    ];

    // ── CDN detection (via headers) ───────────────────────────────────────────
    static ref CDN_HEADERS: Vec<(&'static str, &'static str)> = vec![
        ("Cloudflare",  "cf-ray"),
        ("Fastly",      "x-fastly-request-id"),
        ("Akamai",      "x-akamai-transformed"),
        ("CloudFront",  "x-amz-cf-id"),
        ("Varnish",     "x-varnish"),
        ("KeyCDN",      "x-pull"),
        ("BunnyCDN",    "cdn-requestid"),
        ("StackPath",   "x-sp-url"),
    ];

    // ── Default-credentials likely (product name → note) ─────────────────────
    static ref DEFAULT_CREDS_PRODUCTS: Vec<&'static str> = vec![
        "jenkins", "tomcat", "phpmyadmin", "grafana", "kibana",
        "rabbitmq", "activemq", "hadoop", "zookeeper", "consul",
        "portainer", "gitea", "gitlab", "nexus", "sonarqube",
        "elasticsearch", "influxdb", "drone", "keycloak",
    ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Detect WAF from HTTP response headers (pass lowercased key map)
pub fn detect_waf(headers: &HashMap<String, String>) -> WafDetection {
    let mut best: Option<(String, f32)> = None;
    let mut all_indicators: Vec<String> = Vec::new();

    for (waf_name, sigs) in WAF_SIGS.iter() {
        let mut hits = 0usize;
        for sig in sigs.iter() {
            let matched = headers.keys().any(|k| k.contains(sig))
                || headers.values().any(|v| v.to_lowercase().contains(sig));
            if matched {
                hits += 1;
                all_indicators.push(format!("{}: {}", waf_name, sig));
            }
        }
        if hits > 0 {
            let conf = (hits as f32 / sigs.len() as f32).min(1.0);
            if best.as_ref().map(|(_, c)| conf > *c).unwrap_or(true) {
                best = Some((waf_name.to_string(), conf));
            }
        }
    }

    let (detected, waf_name, confidence) = match best {
        Some((name, conf)) if conf >= 0.25 => (true, Some(name), conf),
        Some((name, conf)) => (false, Some(name), conf),
        None => (false, None, 0.0),
    };

    WafDetection {
        detected,
        waf_name,
        confidence,
        indicators: all_indicators,
    }
}

/// Detect WAF with enhanced body + status evasion signatures (FIX #14)
pub fn detect_waf_with_evasion_signatures(
    base_headers: &HashMap<String, String>,
    body: &str,
    status: Option<u16>,
) -> WafDetection {
    let base = detect_waf(base_headers);
    let body_lower = body.to_lowercase();
    let mut extra_indicators: Vec<String> = Vec::new();
    let mut extra_confidence: f32 = 0.0;
    let mut candidate_waf: Option<String> = None;

    // ── Cloudflare Challenge Page (body) ─────────────────────────────────────
    if body_lower.contains("attention required")
        || body_lower.contains("cloudflare")
        || body_lower.contains("cf-chl")
        || body_lower.contains("just a moment")
    {
        candidate_waf = Some("Cloudflare".to_string());
        extra_confidence += 0.4;
        extra_indicators.push("body: Cloudflare challenge page detected".to_string());
    }

    // ── Akamai (body) ────────────────────────────────────────────────────────
    if body_lower.contains("akamai") || body_lower.contains("reference #") {
        if candidate_waf.is_none() {
            candidate_waf = Some("Akamai".to_string());
        }
        extra_confidence += 0.4;
        extra_indicators.push("body: Akamai pattern detected".to_string());
    }

    // ── Imperva/Incapsula (body) ─────────────────────────────────────────────
    if body_lower.contains("incapsula") || body_lower.contains("visid_incap") {
        if candidate_waf.is_none() {
            candidate_waf = Some("Imperva".to_string());
        }
        extra_confidence += 0.4;
        extra_indicators.push("body: Imperva/Incapsula pattern detected".to_string());
    }

    // ── F5 BIG-IP (body) ─────────────────────────────────────────────────────
    if body_lower.contains("the requested url was rejected") || body_lower.contains("support id") {
        if candidate_waf.is_none() {
            candidate_waf = Some("F5 BIG-IP".to_string());
        }
        extra_confidence += 0.4;
        extra_indicators.push("body: F5 rejection page detected".to_string());
    }

    // ── Status code heuristics ───────────────────────────────────────────────
    if let Some(s) = status {
        if s == 403 && body_lower.contains("forbidden") && body.len() < 2000 {
            if candidate_waf.is_none() {
                candidate_waf = Some("Generic WAF".to_string());
            }
            extra_confidence += 0.2;
            extra_indicators
                .push("status: 403 Forbidden + short body → possible WAF intercept".to_string());
        }

        let server_cf = base_headers
            .get("server")
            .map(|v| v.to_lowercase().contains("cloudflare"))
            .unwrap_or(false);

        if (s == 406 || s == 429) && server_cf {
            candidate_waf = Some("Cloudflare".to_string());
            extra_confidence += 0.2;
            extra_indicators.push(format!("status: {} + Server: cloudflare → rate limit", s));
        }
    }

    // ── Merge base detection with evasion results ────────────────────────────
    let merged_confidence = base.confidence.max(extra_confidence).min(1.0);
    let merged_name = match (base.waf_name.clone(), candidate_waf) {
        (Some(b), Some(c)) if b == c => Some(b),
        (Some(b), Some(c)) => {
            if merged_confidence == base.confidence {
                Some(b)
            } else {
                Some(c)
            }
        }
        (Some(b), None) => Some(b),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    };
    let merged_detected = merged_name.is_some() && merged_confidence >= 0.25;
    let mut merged_indicators = base.indicators.clone();
    merged_indicators.extend(extra_indicators);

    WafDetection {
        detected: merged_detected,
        waf_name: merged_name,
        confidence: merged_confidence,
        indicators: merged_indicators,
    }
}

/// Generate lightweight WAF evasion probe URLs (safe patterns only — not sent automatically)
pub fn waf_evasion_probe_urls(base_url: &str) -> Vec<String> {
    let trimmed = base_url.trim_end_matches('/');
    vec![
        format!("{}/?<script>alert(1)</script>", trimmed),
        format!("{}/../../etc/passwd", trimmed),
        format!("{}/%25%34%31/etc/passwd", trimmed),
        format!("{}/admin' OR '1'='1", trimmed),
        format!("{}/index.php?q=' UNION SELECT 1,2,3--", trimmed),
    ]
}

/// Fingerprint OS from TTL (accepts TTL already read from raw IP header or estimated)
pub fn fingerprint_os_from_ttl(ttl: u32) -> OsFingerprint {
    let best = TTL_OS_MAP
        .iter()
        .map(|(base, short, full)| (*base, *short, *full, ttl.abs_diff(*base)))
        .min_by_key(|(.., diff)| *diff);

    match best {
        Some((_, _, full, diff)) => {
            let conf = match diff {
                0..=5 => 0.95,
                6..=15 => 0.80,
                16..=30 => 0.55,
                _ => 0.30,
            };
            OsFingerprint {
                os_type: Some(full.to_string()),
                os_version: None,
                confidence: conf,
                ttl: Some(ttl),
                window_size: None,
                df_bit: None,
                evidence: vec![format!("TTL={} → {} (conf={:.2})", ttl, full, conf)],
            }
        }
        None => OsFingerprint {
            os_type: None,
            os_version: None,
            confidence: 0.0,
            ttl: Some(ttl),
            window_size: None,
            df_bit: None,
            evidence: vec![],
        },
    }
}

/// Advanced OS fingerprint: fuses TTL + TCP window size + DF bit for higher precision.
/// Mimics p0f/Nmap-style heuristic combining. Each signal votes; confidence is weighted sum.
pub fn fingerprint_os_advanced(
    ttl: Option<u32>,
    window_size: Option<u32>,
    df_bit: Option<bool>,
) -> OsFingerprint {
    use std::collections::HashMap;

    let mut votes: HashMap<String, (f32, Vec<String>)> = HashMap::new();

    let mut add_vote = |os: &str, weight: f32, ev: &str| {
        let entry = votes.entry(os.to_string()).or_insert((0.0, Vec::new()));
        entry.0 += weight;
        entry.1.push(ev.to_string());
    };

    // ── Signal 1: TTL (weight 0.55) ─────────────────────────────────────────
    if let Some(t) = ttl {
        let best = TTL_OS_MAP
            .iter()
            .map(|(base, short, _full)| (*base, *short, t.abs_diff(*base)))
            .min_by_key(|(.., diff)| *diff);
        if let Some((_base, short, diff)) = best {
            let conf = match diff {
                0..=5 => 0.95,
                6..=15 => 0.75,
                16..=30 => 0.45,
                _ => 0.20,
            };
            add_vote(short, 0.55 * conf, &format!("TTL={}→{}", t, short));
        }
    }

    // ── Signal 2: TCP window size (weight 0.35) ─────────────────────────────
    if let Some(ws) = window_size {
        let best = WINDOW_OS_MAP
            .iter()
            .map(|(base, os, wconf)| (*base, *os, *wconf, ws.abs_diff(*base)))
            .min_by_key(|(.., diff)| *diff);
        if let Some((base, os, wconf, diff)) = best {
            let tolerance = 200u32;
            if diff <= tolerance {
                let scaled = wconf * (1.0 - (diff as f32 / tolerance as f32) * 0.3);
                add_vote(
                    os,
                    0.35 * scaled,
                    &format!("WIN={}≈{} (ws_base={})", ws, os, base),
                );
            }
        }
    }

    // ── Signal 3: DF bit (weight 0.10) ──────────────────────────────────────
    if let Some(df) = df_bit {
        if df {
            add_vote("Windows", 0.10 * 0.70, "DF=1 → Windows/Linux default");
            add_vote("Linux", 0.10 * 0.65, "DF=1 → Linux modern kernel");
        } else {
            add_vote(
                "Cisco/Network",
                0.10 * 0.60,
                "DF=0 → typical of network gear",
            );
            add_vote("OpenBSD", 0.10 * 0.55, "DF=0 → some BSD variants");
        }
    }

    // ── Merge votes → best candidate ────────────────────────────────────────
    // `votes` peut être vide (aucune signature n'a voté) : on renvoie alors une
    // empreinte neutre — jamais de `unwrap()` sur un `max_by` potentiellement vide.
    let Some((best_os, (total_weight, all_ev))) = votes.into_iter().max_by(|a, b| {
        a.1 .0
            .partial_cmp(&b.1 .0)
            .unwrap_or(std::cmp::Ordering::Equal)
    }) else {
        return OsFingerprint {
            os_type: None,
            os_version: None,
            confidence: 0.0,
            ttl,
            window_size,
            df_bit,
            evidence: vec![],
        };
    };

    let confidence = total_weight.min(1.0);
    let os_label = TTL_OS_MAP
        .iter()
        .find(|(_, short, _)| *short == best_os.as_str())
        .map(|(_, _, full)| (*full).to_string())
        .unwrap_or_else(|| best_os.clone());

    OsFingerprint {
        os_type: Some(os_label),
        os_version: None,
        confidence,
        ttl,
        window_size,
        df_bit,
        evidence: all_ev,
    }
}

/// Heuristic TTL estimation from banner/service context when raw IP header isn't available.
/// Falls back to TTL=64 (Linux) for unknown — used when we didn't capture raw packets.
pub fn estimate_ttl_from_service(service: &str, banner: Option<&str>) -> u32 {
    let banner_lc = banner.map(|b| b.to_lowercase()).unwrap_or_default();
    let svc_lc = service.to_lowercase();
    if svc_lc.contains("smb")
        || svc_lc.contains("rdp")
        || svc_lc.contains("mssql")
        || banner_lc.contains("iis")
        || banner_lc.contains("windows")
        || banner_lc.contains("microsoft")
    {
        128
    } else if svc_lc.contains("cisco") || banner_lc.contains("cisco ios") {
        255
    } else if banner_lc.contains("solaris") || banner_lc.contains("sunos") {
        60
    } else if banner_lc.contains("openbsd") {
        200
    } else if banner_lc.contains("aix") {
        60
    } else {
        64
    }
}

/// Detect full technology stack from HTTP headers + body snippet
pub fn detect_tech_stack(headers: &HashMap<String, String>, body: &str) -> TechStack {
    let mut tech = TechStack::default();

    // ── Web server (Server header) ───────────────────────────────────────────
    if let Some(server) = headers.get("server") {
        let sl = server.to_lowercase();
        tech.web_server = Some(if sl.contains("nginx") {
            "nginx".into()
        } else if sl.contains("apache") {
            "apache".into()
        } else if sl.contains("iis") {
            format!("iis ({})", server)
        } else if sl.contains("caddy") {
            "caddy".into()
        } else if sl.contains("lighttpd") {
            "lighttpd".into()
        } else if sl.contains("tomcat") {
            "tomcat".into()
        } else if sl.contains("gunicorn") {
            "gunicorn".into()
        } else if sl.contains("uvicorn") {
            "uvicorn".into()
        } else if sl.contains("kestrel") {
            "kestrel (.NET)".into()
        } else {
            server.clone()
        });
    }

    // ── Language / runtime (X-Powered-By) ────────────────────────────────────
    if let Some(pb) = headers.get("x-powered-by") {
        let pl = pb.to_lowercase();
        tech.language = Some(if pl.contains("php") {
            format!("PHP ({})", pb)
        } else if pl.contains("asp.net") {
            "ASP.NET".into()
        } else if pl.contains("express") {
            "Node.js".into()
        } else if pl.contains("next.js") {
            "Node.js".into()
        } else if pl.contains("ruby") {
            "Ruby".into()
        } else {
            pb.clone()
        });
        if pl.contains("express") {
            tech.framework = Some("Express.js".into());
        }
        if pl.contains("asp.net") {
            tech.framework = Some("ASP.NET".into());
        }
    }

    // ── ASP.NET version ───────────────────────────────────────────────────────
    if let Some(aspver) = headers.get("x-aspnet-version") {
        tech.language = Some(format!("ASP.NET {}", aspver));
    }

    // ── CDN detection ─────────────────────────────────────────────────────────
    for (cdn_name, header_key) in CDN_HEADERS.iter() {
        if headers.contains_key(*header_key) {
            tech.cdn = Some(cdn_name.to_string());
            break;
        }
    }

    // ── CMS (body) ────────────────────────────────────────────────────────────
    for (name, re) in CMS_PATTERNS.iter() {
        if re.is_match(body) {
            tech.cms = Some((*name).to_string());
            break;
        }
    }

    // ── Framework (body + headers) ────────────────────────────────────────────
    if tech.framework.is_none() {
        for (name, re) in FRAMEWORK_PATTERNS.iter() {
            if re.is_match(body) {
                tech.framework = Some((*name).to_string());
                // Infer language from framework
                if tech.language.is_none() {
                    tech.language = Some(
                        match *name {
                            "Laravel" | "Symfony" => "PHP",
                            "Django" | "Flask" | "FastAPI" => "Python",
                            "Rails" => "Ruby",
                            "Spring" => "Java",
                            "Next.js" | "Nuxt" | "Express" => "Node.js",
                            "ASP.NET" => "C#",
                            _ => "",
                        }
                        .to_string(),
                    );
                }
                break;
            }
        }
    }

    // ── JavaScript frameworks (body) ──────────────────────────────────────────
    for (name, re) in JS_PATTERNS.iter() {
        if re.is_match(body) {
            tech.javascript_frameworks.push((*name).to_string());
        }
    }

    // ── Database hints (from Set-Cookie or body) ──────────────────────────────
    let combined = format!(
        "{} {}",
        body,
        headers.get("set-cookie").cloned().unwrap_or_default()
    );
    if combined.to_lowercase().contains("phpsessid") && !tech.databases.contains(&"MySQL".into()) {
        tech.databases.push("MySQL (likely)".into());
    }
    if combined.to_lowercase().contains("jsessionid") && !tech.databases.contains(&"Java".into()) {
        // Not a DB, but indicates Java app server
    }
    if combined.contains("PGPASSWORD") || combined.contains("postgresql") {
        tech.databases.push("PostgreSQL".into());
    }

    tech
}

/// Analyse security headers and return hints (passive, no extra requests)
pub fn analyze_security_headers(
    headers: &HashMap<String, String>,
    page_title: Option<&str>,
    product: &str,
) -> SecurityHints {
    let mut hints = SecurityHints::default();
    hints.page_title = page_title.map(|t| t.to_string());

    // Missing security headers
    for hdr in REQUIRED_SECURITY_HEADERS.iter() {
        if !headers.contains_key(*hdr) {
            hints.missing_security_headers.push((*hdr).to_string());
        }
    }

    // Weak HSTS
    if let Some(sts) = headers.get("strict-transport-security") {
        if !sts.contains("max-age=") || sts.contains("max-age=0") {
            hints.weak_headers.push((
                "strict-transport-security".into(),
                "max-age missing or 0".into(),
            ));
        } else if !sts.contains("includeSubDomains") {
            hints.weak_headers.push((
                "strict-transport-security".into(),
                "missing includeSubDomains".into(),
            ));
        }
    }

    // Overly permissive CORS
    if let Some(cors) = headers.get("access-control-allow-origin") {
        if cors == "*" {
            hints.weak_headers.push((
                "access-control-allow-origin".into(),
                "wildcard (*) — allows any origin".into(),
            ));
        }
    }

    // Server header reveals version — info leak
    if let Some(srv) = headers.get("server") {
        if srv.contains('/') || srv.chars().any(|c| c.is_ascii_digit()) {
            hints
                .weak_headers
                .push(("server".into(), format!("version disclosed: {}", srv)));
        }
    }

    // X-Powered-By leaks runtime
    if let Some(pb) = headers.get("x-powered-by") {
        hints
            .weak_headers
            .push(("x-powered-by".into(), format!("runtime disclosed: {}", pb)));
    }

    // Insecure cookies (scan Set-Cookie values)
    if let Some(sc) = headers.get("set-cookie") {
        for part in sc.split(';') {
            let p = part.trim().to_lowercase();
            if !p.contains("secure") || !p.contains("httponly") {
                if let Some(name) = sc.split('=').next() {
                    hints.insecure_cookies.push(name.trim().to_string());
                }
                break;
            }
        }
    }

    // Default credentials likely?
    let product_lower = product.to_lowercase();
    hints.default_creds_likely = DEFAULT_CREDS_PRODUCTS
        .iter()
        .any(|p| product_lower.contains(p));

    hints
}

/// Full enhancement pass — called once per node after banner scan
pub fn enhance_banner(
    banner: &str,
    headers: &HashMap<String, String>,
    body: &str,
    ttl: Option<u32>,
    window_size: Option<u32>,
    df_bit: Option<bool>,
    service_name: &str,
) -> EnhancedBanner {
    let waf_with_body = detect_waf_with_evasion_signatures(headers, body, None);
    let ttl_effective = ttl.or_else(|| Some(estimate_ttl_from_service(service_name, Some(banner))));
    let os = Some(fingerprint_os_advanced(ttl_effective, window_size, df_bit));
    let tech_stack = detect_tech_stack(headers, body);
    let (service, version) = extract_service_info(banner);

    EnhancedBanner {
        raw_banner: banner.to_string(),
        service,
        version,
        os,
        waf: if waf_with_body.detected {
            Some(waf_with_body)
        } else {
            None
        },
        tech_stack: Some(tech_stack),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn extract_service_info(banner: &str) -> (String, Option<String>) {
    let b = banner.to_lowercase();
    // Fast match on known patterns
    for (svc, re_str) in &[
        ("nginx", r"nginx/([0-9]+\.[0-9]+)"),
        ("apache", r"apache/([0-9]+\.[0-9]+)"),
        ("iis", r"iis/([0-9]+\.[0-9]+)"),
        ("php", r"php/([0-9]+\.[0-9]+)"),
    ] {
        if let Ok(re) = Regex::new(re_str) {
            if let Some(caps) = re.captures(&b) {
                let ver = caps.get(1).map(|m| m.as_str().to_string());
                return (svc.to_string(), ver);
            }
        }
    }
    let parts: Vec<&str> = banner.split_whitespace().collect();
    (parts.first().unwrap_or(&"unknown").to_lowercase(), None)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_waf() {
        let mut h = HashMap::new();
        h.insert("cf-ray".into(), "abc123".into());
        h.insert("cf-cache-status".into(), "MISS".into());
        let r = detect_waf(&h);
        assert!(r.detected);
        assert_eq!(r.waf_name, Some("Cloudflare".into()));
    }

    #[test]
    fn test_no_waf() {
        let mut h = HashMap::new();
        h.insert("server".into(), "nginx".into());
        let r = detect_waf(&h);
        assert!(!r.detected);
    }

    #[test]
    fn test_os_linux_ttl64() {
        let r = fingerprint_os_from_ttl(64);
        assert!(r.os_type.as_deref().unwrap_or("").contains("Linux"));
        assert!(r.confidence >= 0.80);
    }

    #[test]
    fn test_os_windows_ttl128() {
        let r = fingerprint_os_from_ttl(128);
        assert!(r.os_type.as_deref().unwrap_or("").contains("Windows"));
    }

    #[test]
    fn test_os_cisco_ttl255() {
        let r = fingerprint_os_from_ttl(255);
        assert!(r.os_type.as_deref().unwrap_or("").contains("Cisco"));
    }

    #[test]
    fn test_tech_wordpress_body() {
        let mut h = HashMap::new();
        h.insert("server".into(), "nginx/1.18.0".into());
        let body = "<html><link href='wp-content/themes/twenty'></html>";
        let t = detect_tech_stack(&h, body);
        assert_eq!(t.web_server, Some("nginx".into()));
        assert_eq!(t.cms, Some("WordPress".into()));
    }

    #[test]
    fn test_tech_laravel_body() {
        let mut h = HashMap::new();
        h.insert("set-cookie".into(), "laravel_session=abc; path=/".into());
        let body = "laravel_session";
        let t = detect_tech_stack(&h, body);
        assert_eq!(t.framework, Some("Laravel".into()));
    }

    #[test]
    fn test_security_missing_headers() {
        let headers = HashMap::new();
        let hints = analyze_security_headers(&headers, None, "nginx");
        assert!(!hints.missing_security_headers.is_empty());
        assert!(hints
            .missing_security_headers
            .contains(&"strict-transport-security".into()));
    }

    #[test]
    fn test_default_creds_jenkins() {
        let headers = HashMap::new();
        let hints = analyze_security_headers(&headers, None, "jenkins");
        assert!(hints.default_creds_likely);
    }

    #[test]
    fn test_wildcard_cors() {
        let mut h = HashMap::new();
        h.insert("access-control-allow-origin".into(), "*".into());
        let hints = analyze_security_headers(&h, None, "nginx");
        assert!(hints
            .weak_headers
            .iter()
            .any(|(k, _)| k == "access-control-allow-origin"));
    }
}
