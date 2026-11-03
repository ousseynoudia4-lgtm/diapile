// Toutes les `Regex` de ce module sont compilées depuis des motifs **littéraux**
// (constantes de compilation) dans un `lazy_static!` : la compilation est
// infaillible dès lors que le motif est bien écrit, ce que les tests couvrent.
// Un `#[allow]` sur l'invocation de macro ne se propage pas à son expansion :
// on autorise donc `unwrap_used` au niveau du module.
#![allow(clippy::unwrap_used)]

pub mod enhanced;

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

// ─────────────────────────────────────────────────────────────────────────────
// Version-extraction regexes
// ─────────────────────────────────────────────────────────────────────────────
lazy_static! {
    static ref RE_NGINX: Regex = Regex::new(r"(?i)nginx/([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_APACHE: Regex = Regex::new(r"(?i)Apache/([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_IIS: Regex = Regex::new(r"(?i)Microsoft-IIS/([0-9]+\.[0-9]+)").unwrap();
    static ref RE_LIGHTTPD: Regex =
        Regex::new(r"(?i)lighttpd/([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_CADDY: Regex = Regex::new(r"(?i)Caddy(/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?").unwrap();
    static ref RE_TOMCAT: Regex = Regex::new(r"(?i)Apache-Coyote/([0-9]+\.[0-9]+)").unwrap();
    static ref RE_SSH: Regex =
        Regex::new(r"(?i)(?:openssh|dropbear)[_-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_REDIS: Regex =
        Regex::new(r"(?i)redis(?:_server)?\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_REDIS_SHORT: Regex =
        Regex::new(r"(?i)redis(?:_version)?[_/\s:]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_POSTFIX: Regex =
        Regex::new(r"(?i)postfix/([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_EXIM: Regex = Regex::new(r"(?i)exim\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_SENDMAIL: Regex =
        Regex::new(r"(?i)sendmail/([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_VSFTPD: Regex =
        Regex::new(r"(?i)vsftpd\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_PROFTPD: Regex =
        Regex::new(r"(?i)ProFTPD\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_MYSQL: Regex =
        Regex::new(r"(?i)(?:mysql|mariadb)[/\s_-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_PGSQL: Regex =
        Regex::new(r"(?i)(?:postgresql|postgres)[/\s_-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_MONGO: Regex =
        Regex::new(r"(?i)mongodb?[/\s_-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_MSSQL: Regex =
        Regex::new(r"(?i)(?:mssql|sql\s*server)[/\s_-]?([0-9]{4}(?:\.[0-9]+)?)").unwrap();
    static ref RE_ELASTICSEARCH: Regex =
        Regex::new(r#"(?i)"number"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"#).unwrap();
    static ref RE_BIND: Regex =
        Regex::new(r"(?i)bind[/\s_-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_MEMCACHED: Regex =
        Regex::new(r"(?i)memcached\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_RABBITMQ: Regex =
        Regex::new(r"(?i)amqp\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
    static ref RE_TELNET: Regex = Regex::new(r"(?i)telnet").unwrap();
    static ref RE_GENERIC_VER: Regex = Regex::new(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Service mapping
// ─────────────────────────────────────────────────────────────────────────────

pub fn port_to_service(port: u16) -> &'static str {
    match port {
        21 | 2121 | 990 => "ftp",
        22 | 2222 | 222 => "ssh",
        23 | 2323 => "telnet",
        25 | 587 | 465 | 1025 => "smtp",
        53 => "dns",
        80 | 8080 | 8000 | 3000 | 8008 | 8888 | 8081 | 8082 | 9090 => "http",
        110 => "pop3",
        143 => "imap",
        389 | 636 => "ldap",
        443 | 8443 | 9443 => "https",
        139 | 445 => "smb",
        1080 => "socks5",
        1433 => "mssql",
        1521 => "oracle",
        2181 => "zookeeper",
        2375 | 2376 => "docker-api",
        2379 | 2380 => "etcd",
        3306 => "mysql",
        3389 => "rdp",
        4369 => "rabbitmq-epmd",
        5432 => "postgresql",
        5601 => "kibana",
        5672 | 5671 | 15672 => "rabbitmq",
        6379 | 6380 | 6381 => "redis",
        7001 | 7002 => "weblogic",
        8025 => "http",
        8086 => "influxdb",
        8161 => "activemq",
        9200 | 9300 => "elasticsearch",
        9092 => "kafka",
        11211 => "memcached",
        27017 | 27018 | 27019 => "mongodb",
        50000 => "db2",
        50070 | 50090 => "hadoop",
        // ── Nouveaux protocoles ──────────────────────────────────────────────
        161 | 162 => "snmp",
        88 | 749 => "kerberos",
        5985 | 5986 => "winrm",
        5900..=5910 => "vnc",
        1883 | 8883 => "mqtt",
        6443 | 8001 => "kubernetes",
        // ── Diffusion TV / Média ─────────────────────────────────────────────
        554 | 8554 | 8555 => "rtsp",
        1935 => "rtmp",
        1900 => "ssdp",
        8009 => "chromecast",
        8060 => "roku-ecp",
        8200 => "minidlna",
        _ => "tcp",
    }
}

pub fn service_port_map() -> HashMap<&'static str, Vec<u16>> {
    let mut m: HashMap<&'static str, Vec<u16>> = HashMap::new();
    m.insert("ftp", vec![21, 2121, 990]);
    m.insert("ssh", vec![22, 2222, 222]);
    m.insert("telnet", vec![23, 2323]);
    m.insert("smtp", vec![25, 1025, 587, 465]);
    m.insert("dns", vec![53]);
    m.insert("http", vec![80, 8080, 8000, 3000, 8008, 8888, 8081, 9090]);
    m.insert("ldap", vec![389, 636]);
    m.insert("https", vec![443, 8443, 9443]);
    m.insert("smb", vec![445]);
    m.insert("mssql", vec![1433]);
    m.insert("oracle", vec![1521]);
    m.insert("mysql", vec![3306]);
    m.insert("rdp", vec![3389]);
    m.insert("postgresql", vec![5432]);
    m.insert("rabbitmq", vec![5672, 15672]);
    m.insert("redis", vec![6379, 6380]);
    m.insert("elasticsearch", vec![9200, 9300]);
    m.insert("memcached", vec![11211]);
    m.insert("mongodb", vec![27017, 27018, 27019]);
    m.insert("docker-api", vec![2375, 2376]);
    m.insert("etcd", vec![2379, 2380]);
    m.insert("zookeeper", vec![2181]);
    m.insert("kafka", vec![9092]);
    m.insert("influxdb", vec![8086]);
    m.insert("kibana", vec![5601]);
    // ── Nouveaux protocoles ──────────────────────────────────────────────────
    m.insert("snmp", vec![161, 162]);
    m.insert("kerberos", vec![88, 749]);
    m.insert("winrm", vec![5985, 5986]);
    m.insert("vnc", vec![5900, 5901, 5902]);
    m.insert("mqtt", vec![1883, 8883]);
    m.insert("kubernetes", vec![6443, 8001]);
    m
}

/// Common ports for quick sweeps (sorted by likelihood of finding open service)
pub fn common_scan_ports() -> Vec<u16> {
    vec![
        80, 443, 22, 21, 25, 3306, 5432, 6379, 27017, 445, 8080, 8443, 3389, 1433, 23, 587, 465,
        110, 143, 389, 2375, 2376, 9200, 11211, 5672, 8086, 2181, 9092, 5601, 8000, 8008, 8081,
        8082, 8888, 9090, 9443, 1521, 2379, 4369, 7001, 7002, 8025, 8161, 50000, 50070,
        // Nouveaux protocoles
        161, 88, 5985, 5900, 1883, 6443,
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner grabbing
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BannerResult {
    pub banner: Option<String>,
    pub content_type: Option<String>,
    pub service_name: String,
    /// All HTTP response headers (lowercase keys), populated for HTTP/HTTPS targets
    pub headers: HashMap<String, String>,
    /// HTTP status code if applicable
    pub http_status: Option<u16>,
    /// Title extracted from HTML body (first 2KB only)
    pub page_title: Option<String>,
    /// true if DNS resolution succeeded (avoids wildcard-SNI false positives on HTTP)
    pub dns_validated: bool,
    /// true if the TCP 3-way handshake succeeded but the server sent zero application bytes
    /// (possible tarpit / filtered port / non-speaking service)
    pub silent_port: bool,
    /// TLS certificate information (if HTTPS and available)
    pub tls_info: Option<TlsCertInfo>,
}

/// Informations extraites du certificat TLS X.509 (côté client HTTPS)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertInfo {
    pub fingerprint_sha256: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    /// true si issuer == subject (self-signed)
    pub self_signed: bool,
    /// true si certificat expiré OU pas encore valide
    pub expired_or_future: bool,
    pub sans: Vec<String>,
}

impl Default for BannerResult {
    fn default() -> Self {
        Self {
            banner: None,
            content_type: None,
            service_name: "tcp".into(),
            headers: HashMap::new(),
            http_status: None,
            page_title: None,
            dns_validated: false,
            silent_port: false,
            tls_info: None,
        }
    }
}

/// Résout un hostname vers une adresse IP. Retourne true si le hostname est une IP valide
/// OU si la résolution DNS renvoie au moins un enregistrement A/AAAA non-boucle.
/// Si wildcard-detected (NXDOMAIN ne renvoie jamais, toutes requêtes résolues vers une unique IP),
/// on positionne un warning dans le résultat.
pub async fn validate_dns(host: &str) -> bool {
    // Cas 1 : IP littérale, toujours valide
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // Cas 2 : résolution DNS via tokio (utilise la pile OS)
    match tokio::net::lookup_host((host, 0)).await {
        Ok(mut addrs) => {
            // Vérifier qu'il y a au moins une adresse réelle (pas vide)
            let has_real = addrs.next().is_some();
            if !has_real {
                return false;
            }
            // Anti-wildcard-SNI : résoudre un sous-domaine aléatoire impossible
            // S'il résout aussi = wildcard DNS (catch-all). On refuse.
            let random_label = format!(
                "_nrtg_probe_{}_{}",
                uuid::Uuid::new_v4()
                    .simple()
                    .to_string()
                    .get(0..8)
                    .unwrap_or("zzzzzzzz"),
                host
            );
            if let Ok(mut wildcard_check) =
                tokio::net::lookup_host((random_label.as_str(), 0)).await
            {
                if wildcard_check.next().is_some() {
                    // Wildcard DNS détecté (tous sous-domaines résolvent) → refuser cette cible
                    // pour éviter faux positifs SNI wildcard
                    return false;
                }
            }
            true
        }
        Err(_) => false,
    }
}

/// Probe TLS handshake to extract certificate info (sha256 fingerprint,
/// subject/issuer, validity, self-signed, SANs). Used for HTTPS targets.
/// Implémentation TCP BRUT (ClientHello TLS 1.2 synthétique) — ZÉRO
/// dépendance crypto externe (ni rustls/ring, ni native-tls/dlltool, ni link.exe).
/// Parse le ServerCertificate record TLS pour extraire l'end-entity DER brut.
pub async fn probe_tls_cert(host: &str, port: u16) -> Option<TlsCertInfo> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ── 1. Ouvre une socket TCP ────────────────────────────────────────────
    let addr = format!("{}:{}", host, port);
    let mut tcp = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .ok()
        .and_then(|r| r.ok())?;

    // ── 2. Forge un ClientHello TLS 1.2 anti-JA3 / anti-fingerprint ────────
    //   Signature ClientHello randomisée par host + cipher_suites shuffled,
    //   extensions shuffled, cipher suites étendues Chrome-like.

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::Hasher;
    hasher.write(host.as_bytes());
    hasher.write_u16(port);
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 3600)
            .unwrap_or(0),
    ); // stable par heure
    let seed = hasher.finish();

    let mut rng = seedable_rand(seed);
    let random_bytes: Vec<u8> = (0..32).map(|_| rng.next()).collect();

    // Cipher suites étendues style Chrome (29 suites, shuffled par host seed)
    let mut cipher_suites: Vec<u16> = vec![
        0x1301, 0x1302, 0x1303, // TLS_AES_128/256_GCM, CHACHA20
        0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDHE ECDSA AES GCM
        0xcca9, 0xcca8, // ECDHE CHACHA20 POLY
        0xc013, 0xc014, 0x009c, 0x009d, // ECDHE RSA CBC / AES-GCM
        0x002f, 0x0035, 0x000a, // RSA CBC
    ];
    shuffle_with_seed(&mut cipher_suites, seed);
    let cipher_bytes: Vec<u8> = cipher_suites
        .iter()
        .flat_map(|s| s.to_be_bytes().to_vec())
        .collect();

    let sni_bytes = build_sni_extension(host);
    let sigalg_bytes = build_signature_algos_ext();
    let groups_bytes = build_supported_groups_ext();
    let points_bytes = build_ec_point_formats_ext();
    let alpn_bytes = build_alpn_ext();

    let mut all_exts: Vec<(&'static str, Vec<u8>)> = vec![
        ("sni", sni_bytes),
        ("sigalg", sigalg_bytes),
        ("groups", groups_bytes),
        ("points", points_bytes),
        ("alpn", alpn_bytes),
    ];
    shuffle_with_seed(&mut all_exts, seed ^ 0xA5A5A5A5);

    let mut exts: Vec<u8> = Vec::new();
    for (_, b) in &all_exts {
        exts.extend_from_slice(b);
    }

    let mut client_hello_body: Vec<u8> = Vec::new();
    client_hello_body.extend_from_slice(&[0x03, 0x03]);
    client_hello_body.extend_from_slice(&random_bytes);
    client_hello_body.push(0x00);
    client_hello_body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    client_hello_body.extend_from_slice(&cipher_bytes);
    client_hello_body.push(0x01);
    client_hello_body.push(0x00);
    client_hello_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    client_hello_body.extend_from_slice(&exts);

    let ch_len = client_hello_body.len() as u32;
    let mut handshake: Vec<u8> = Vec::with_capacity(4 + client_hello_body.len());
    handshake.push(0x01); // HandshakeType: client_hello
    handshake.extend_from_slice(&[(ch_len >> 16) as u8, (ch_len >> 8) as u8, ch_len as u8]);
    handshake.extend_from_slice(&client_hello_body);

    let mut tls_record: Vec<u8> = Vec::with_capacity(5 + handshake.len());
    tls_record.push(0x16); // ContentType: handshake
    tls_record.extend_from_slice(&[0x03, 0x01]); // record_layer version = TLS 1.0 (compat)
    tls_record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    tls_record.extend_from_slice(&handshake);

    // ── 3. Écrit ClientHello ───────────────────────────────────────────────
    timeout(Duration::from_secs(5), tcp.write_all(&tls_record))
        .await
        .ok()?
        .ok()?;

    // ── 4. Lit la réponse : on s'attend à plusieurs records TLS
    //    jusqu'au ServerCertificate (handshake type 0x0b).
    //    Les messages peuvent être fragmentés ou concaténés dans un record.
    //    On lit par chunk de 16Ko, on parse l'en-tête record.
    // ──────────────────────────────────────────────────────────────────────
    let mut buffer: Vec<u8> = Vec::with_capacity(65536);
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    let mut cert_der: Option<Vec<u8>> = None;

    while std::time::Instant::now() < deadline {
        // On lit petit à petit : soit il y a déjà assez de bytes, soit on bloque
        if buffer.len() < 5 {
            let mut tmp = [0u8; 4096];
            let remaining = deadline - std::time::Instant::now();
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, tcp.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buffer.extend_from_slice(&tmp[..n]),
                _ => break,
            }
            continue;
        }

        // Parse TLSPlaintext header (5B)
        let content_type = buffer[0];
        let _record_ver = u16::from_be_bytes([buffer[1], buffer[2]]);
        let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
        if buffer.len() < 5 + record_len {
            // Il faut lire la suite du record
            let need = 5 + record_len - buffer.len();
            let mut tmp = vec![0u8; need.max(2048)];
            let remaining = deadline - std::time::Instant::now();
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, tcp.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buffer.extend_from_slice(&tmp[..n]),
                _ => break,
            }
            continue;
        }

        // Consomme le record
        let record_payload = buffer[5..5 + record_len].to_vec();
        buffer.drain(0..5 + record_len);

        // On ne s'intéresse qu'aux records handshake (0x16)
        if content_type != 0x16 {
            continue;
        }

        // Parse tous les messages handshake du record (il peut y en avoir plusieurs
        // concaténés — TLS 1.2 permet ça)
        let mut p = &record_payload[..];
        while p.len() >= 4 {
            let hs_type = p[0];
            let hs_len = ((p[1] as usize) << 16) | ((p[2] as usize) << 8) | (p[3] as usize);
            if p.len() < 4 + hs_len {
                break;
            }
            let hs_body = &p[4..4 + hs_len];
            p = &p[4 + hs_len..];

            // ServerCertificate = HandshakeType 0x0B
            if hs_type == 0x0b {
                // Structure :
                //   3 bytes certificates_length
                //   repeat N:
                //     3 bytes cert_length
                //     <cert_length bytes ASN.1 DER>
                if hs_body.len() < 3 {
                    break;
                }
                let certs_total = ((hs_body[0] as usize) << 16)
                    | ((hs_body[1] as usize) << 8)
                    | (hs_body[2] as usize);
                let certs_bytes = &hs_body[3..];
                if certs_bytes.len() < certs_total {
                    break;
                }
                let mut cp = certs_bytes;
                if cp.len() < 3 {
                    break;
                }
                let first_len =
                    ((cp[0] as usize) << 16) | ((cp[1] as usize) << 8) | (cp[2] as usize);
                cp = &cp[3..];
                if cp.len() < first_len {
                    break;
                }
                cert_der = Some(cp[..first_len].to_vec());
                break;
            }

            // ServerHelloDone (0x0E) ou ServerKeyExchange (0x0C) après Certificate => on peut arrêter
            if hs_type == 0x0e {
                break;
            }
        }
        if cert_der.is_some() {
            break;
        }
    }

    // Clean fermeture TCP (best effort)
    let _ = tcp.shutdown().await;
    let cert_der = cert_der?;

    // ── 5. Calculs fingerprint + X.509 parse (code existant inchangé) ──────
    let mut ctx = sha256_ctx();
    ctx.update(&cert_der);
    let fp = ctx.finish();
    let fingerprint_sha256 = fp
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");

    let (subject, issuer, nb, na, sans) = extract_x509_fields_light(&cert_der);

    let self_signed = subject == issuer && !subject.is_empty();
    let now = chrono::Utc::now().timestamp();
    let expired_or_future = nb > now || na < now;

    Some(TlsCertInfo {
        fingerprint_sha256,
        subject,
        issuer,
        not_before: chrono::DateTime::from_timestamp(nb, 0)
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| "unknown".into()),
        not_after: chrono::DateTime::from_timestamp(na, 0)
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| "unknown".into()),
        self_signed,
        expired_or_future,
        sans,
    })
}

// ── Helpers TLS ClientHello (TCP brut) ──────────────────────────────────────

fn build_sni_extension(host: &str) -> Vec<u8> {
    // Extension 0x0000 server_name
    let host_bytes = host.as_bytes();
    // ServerNameList: list length 2B, then entries: type 1B + name_length 2B + name
    let mut server_name_list: Vec<u8> = Vec::new();
    server_name_list.push(0x00); // name_type = host_name (0)
    server_name_list.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    server_name_list.extend_from_slice(host_bytes);

    let mut ext: Vec<u8> = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00]); // ExtensionType: server_name
                                          // extension_data_length (2B) = server_name_list_length (2B) + server_name_list
    ext.extend_from_slice(&((2 + server_name_list.len()) as u16).to_be_bytes());
    ext.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());
    ext.extend_from_slice(&server_name_list);
    ext
}

fn build_signature_algos_ext() -> Vec<u8> {
    // Extension 0x000D signature_algorithms — requis par la plupart des serveurs modernes
    // SigAlgos: rsa_pkcs1_sha256(0x0401), rsa_pkcs1_sha384(0x0501), rsa_pss_rsae_sha256(0x0804)
    //            ecdsa_secp256r1_sha256(0x0403), ed25519(0x0807), rsa_pkcs1_sha1(0x0201 — compat)
    let algos: [u8; 12] = [
        0x08, 0x04, 0x04, 0x01, 0x05, 0x01, 0x04, 0x03, 0x08, 0x07, 0x02, 0x01,
    ];
    let mut ext: Vec<u8> = Vec::new();
    ext.extend_from_slice(&[0x00, 0x0d]);
    ext.extend_from_slice(&((2 + algos.len()) as u16).to_be_bytes());
    ext.extend_from_slice(&(algos.len() as u16).to_be_bytes());
    ext.extend_from_slice(&algos);
    ext
}

fn build_supported_groups_ext() -> Vec<u8> {
    // Extension 0x000A supported_groups: x25519(29), secp256r1(23), secp384r1(24)
    let groups: [u8; 6] = [0x00, 0x1d, 0x00, 0x17, 0x00, 0x18];
    let mut ext: Vec<u8> = Vec::new();
    ext.extend_from_slice(&[0x00, 0x0a]);
    ext.extend_from_slice(&((2 + groups.len()) as u16).to_be_bytes());
    ext.extend_from_slice(&(groups.len() as u16).to_be_bytes());
    ext.extend_from_slice(&groups);
    ext
}

fn build_ec_point_formats_ext() -> Vec<u8> {
    // Extension 0x000B ec_point_formats: uncompressed(0)
    let fmts: [u8; 1] = [0x00];
    let mut ext: Vec<u8> = Vec::new();
    ext.extend_from_slice(&[0x00, 0x0b]);
    ext.extend_from_slice(&((1 + fmts.len()) as u16).to_be_bytes());
    ext.push(fmts.len() as u8);
    ext.extend_from_slice(&fmts);
    ext
}

fn build_alpn_ext() -> Vec<u8> {
    // Extension 0x0010 application_layer_protocol_negotiation: h2, http/1.1
    let mut protos: Vec<u8> = Vec::new();
    for proto in &["h2", "http/1.1"] {
        protos.push(proto.len() as u8);
        protos.extend_from_slice(proto.as_bytes());
    }
    let mut ext: Vec<u8> = Vec::new();
    ext.extend_from_slice(&[0x00, 0x10]);
    ext.extend_from_slice(&((2 + protos.len()) as u16).to_be_bytes());
    ext.extend_from_slice(&(protos.len() as u16).to_be_bytes());
    ext.extend_from_slice(&protos);
    ext
}

// ── Deterministic PRNG + shuffle helpers (sans external crate) ───────────────

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn next(&mut self) -> u8 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = if x == 0 { 0x9E37_79B9_7F4A_7C15 } else { x };
        (self.state >> 32) as u8
    }
}

fn seedable_rand(seed: u64) -> XorShift64 {
    XorShift64 {
        state: if seed == 0 {
            0x1234_5678_9ABC_DEF0
        } else {
            seed
        },
    }
}

fn shuffle_with_seed<T>(items: &mut [T], seed: u64) {
    let n = items.len();
    if n < 2 {
        return;
    }
    let mut rng = seedable_rand(seed);
    for i in (1..n).rev() {
        let j = {
            let mut buf = [0u8; 8];
            for b in &mut buf {
                *b = rng.next();
            }
            let j = u64::from_be_bytes(buf) as usize;
            j % (i + 1)
        };
        items.swap(i, j);
    }
}

// ── Mini SHA-256 (sans ajouter de dépendance sha2) ───────────────────────────
fn sha256_ctx() -> Sha256 {
    Sha256::new()
}

struct Sha256 {
    state: [u32; 8],
    count: u64,
    buf: [u8; 64],
    buflen: usize,
}

impl Sha256 {
    fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            count: 0,
            buf: [0u8; 64],
            buflen: 0,
        }
    }
    fn update(&mut self, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            let need = 64 - self.buflen;
            let take = need.min(data.len() - i);
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[i..i + take]);
            self.buflen += take;
            i += take;
            if self.buflen == 64 {
                transform(&mut self.state, &self.buf);
                self.count += 512;
                self.buflen = 0;
            }
        }
    }
    fn finish(mut self) -> [u8; 32] {
        let bits = self.count + (self.buflen as u64) * 8;
        self.buf[self.buflen] = 0x80;
        self.buflen += 1;
        if self.buflen > 56 {
            while self.buflen < 64 {
                self.buf[self.buflen] = 0;
                self.buflen += 1;
            }
            transform(&mut self.state, &self.buf);
            self.buflen = 0;
        }
        while self.buflen < 56 {
            self.buf[self.buflen] = 0;
            self.buflen += 1;
        }
        self.buf[56..64].copy_from_slice(&bits.to_be_bytes());
        transform(&mut self.state, &self.buf);
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }
}

fn transform(s: &mut [u32; 8], block: &[u8]) {
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] =
        [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]];
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let mj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(mj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    s[0] = s[0].wrapping_add(a);
    s[1] = s[1].wrapping_add(b);
    s[2] = s[2].wrapping_add(c);
    s[3] = s[3].wrapping_add(d);
    s[4] = s[4].wrapping_add(e);
    s[5] = s[5].wrapping_add(f);
    s[6] = s[6].wrapping_add(g);
    s[7] = s[7].wrapping_add(h);
}

// ── Light X.509 DER parser (subject/issuer CN + validity + SAN DNS) ────────
fn extract_x509_fields_light(der: &[u8]) -> (String, String, i64, i64, Vec<String>) {
    fn read_len(bytes: &[u8], pos: usize) -> Option<(usize, usize)> {
        if pos >= bytes.len() {
            return None;
        }
        let l = bytes[pos] as usize;
        if l < 0x80 {
            Some((pos + 1, l))
        } else {
            let nb = l & 0x7f;
            if nb == 0 || pos + 1 + nb > bytes.len() {
                return None;
            }
            let mut total: usize = 0;
            for i in 0..nb {
                total = (total << 8) | bytes[pos + 1 + i] as usize;
            }
            Some((pos + 1 + nb, total))
        }
    }
    // Find TBSCertificate: der[0] = 0x30 SEQUENCE (outer cert), skip tag+len → inner 0x30 = TBS
    let mut p = 0;
    if der.get(p) != Some(&0x30) {
        return ("".into(), "".into(), 0, i64::MAX, vec![]);
    }
    p += 1;
    let (np, tbs_total) = match read_len(der, p) {
        Some(v) => v,
        None => return ("".into(), "".into(), 0, i64::MAX, vec![]),
    };
    p = np;
    let tbs_start = p;
    let _tbs_end = tbs_start + tbs_total;
    if der.get(p) != Some(&0x30) {
        return ("".into(), "".into(), 0, i64::MAX, vec![]);
    }
    p += 1;
    let (np, tbs_len) = match read_len(der, p) {
        Some(v) => v,
        None => return ("".into(), "".into(), 0, i64::MAX, vec![]),
    };
    p = np;
    let tbs_slice = match der.get(p..p + tbs_len) {
        Some(s) => s,
        None => return ("".into(), "".into(), 0, i64::MAX, vec![]),
    };

    // Walk TBS fields sequentially:
    //  [0] version EXPLICIT opt | serial | sigAlg | issuer | validity | subject | SPKI | [1] issuerUID opt | [2] subjectUID opt | extensions opt
    fn next_tlv(slc: &[u8], pos: usize) -> Option<(u8, usize, usize, usize)> {
        // returns (tag, header_len, val_len, val_start)
        if pos >= slc.len() {
            return None;
        }
        let tag = slc[pos];
        let (np, len) = read_len(slc, pos + 1)?;
        let hdr = np - pos;
        Some((tag, hdr, len, np))
    }

    fn read_rdn_sequence(slc: &[u8]) -> String {
        // slc = SEQUENCE OF SET OF SEQUENCE { OID, ANY value }
        // Extract printable UTF8/PrintableString/T61String tokens and join with ","
        let mut parts: Vec<String> = Vec::new();
        let mut p = 0;
        if slc.get(p) != Some(&0x30) {
            return String::new();
        }
        p += 1;
        let (np, len) = match read_len(slc, p) {
            Some(v) => v,
            None => return String::new(),
        };
        let end = np + len;
        p = np;
        while p < end {
            if slc.get(p) != Some(&0x31) {
                break;
            }
            p += 1;
            let (np2, setlen) = match read_len(slc, p) {
                Some(v) => v,
                None => break,
            };
            let set_end = np2 + setlen;
            let mut p2 = np2;
            while p2 < set_end {
                if slc.get(p2) != Some(&0x30) {
                    break;
                }
                p2 += 1;
                let (np3, seqlen) = match read_len(slc, p2) {
                    Some(v) => v,
                    None => break,
                };
                let seq_end = np3 + seqlen;
                let mut p3 = np3;
                // skip OID
                if p3 >= seq_end {
                    break;
                }
                let _oid_tag = slc[p3];
                p3 += 1;
                let (np4, oidlen) = match read_len(slc, p3) {
                    Some(v) => v,
                    None => break,
                };
                p3 = np4 + oidlen;
                // value
                if p3 < seq_end {
                    let vtag = slc[p3];
                    p3 += 1;
                    let (np5, vlen) = match read_len(slc, p3) {
                        Some(v) => v,
                        None => break,
                    };
                    let val_start = np5;
                    let val_end = val_start + vlen;
                    if (val_end) <= seq_end {
                        let raw = &slc[val_start..val_end];
                        let s = String::from_utf8_lossy(raw)
                            .trim_matches(|c: char| c.is_control())
                            .to_string();
                        if !s.is_empty() {
                            // Heuristic : only keep printable short strings
                            if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                                parts.push(s);
                            }
                        }
                    }
                    p3 = val_end;
                }
                p2 = seq_end;
            }
            p = set_end;
        }
        parts.join(", ")
    }

    fn read_validity(slc: &[u8]) -> (i64, i64) {
        // Validity ::= SEQUENCE { notBefore Time, notAfter Time }
        // Time : UTCTime (0x17) or GeneralizedTime (0x18)
        fn parse_utctime(s: &str) -> i64 {
            // YYMMDDhhmmssZ or YYMMDDhhmmss+hh'mm'
            if s.len() < 12 {
                return 0;
            }
            let yy: i32 = s[0..2].parse().unwrap_or(0);
            let mm: u32 = s[2..4].parse().unwrap_or(1);
            let dd: u32 = s[4..6].parse().unwrap_or(1);
            let hh: u32 = s[6..8].parse().unwrap_or(0);
            let mi: u32 = s[8..10].parse().unwrap_or(0);
            let ss: u32 = s[10..12].parse().unwrap_or(0);
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            chrono::NaiveDate::from_ymd_opt(year, mm, dd)
                .and_then(|d| d.and_hms_opt(hh, mi, ss))
                .map(|ndt| ndt.and_utc().timestamp())
                .unwrap_or(0)
        }
        fn parse_generalized(s: &str) -> i64 {
            // YYYYMMDDhhmmssZ
            if s.len() < 14 {
                return 0;
            }
            let y: i32 = s[0..4].parse().unwrap_or(1970);
            let mo: u32 = s[4..6].parse().unwrap_or(1);
            let d: u32 = s[6..8].parse().unwrap_or(1);
            let h: u32 = s[8..10].parse().unwrap_or(0);
            let mi: u32 = s[10..12].parse().unwrap_or(0);
            let ss: u32 = s[12..14].parse().unwrap_or(0);
            chrono::NaiveDate::from_ymd_opt(y, mo, d)
                .and_then(|dt| dt.and_hms_opt(h, mi, ss))
                .map(|ndt| ndt.and_utc().timestamp())
                .unwrap_or(0)
        }
        fn read_time(slc: &[u8], p: &mut usize) -> i64 {
            if *p >= slc.len() {
                return 0;
            }
            let tag = slc[*p];
            *p += 1;
            let (np, len) = match read_len(slc, *p) {
                Some(v) => v,
                None => {
                    *p += 1;
                    return 0;
                }
            };
            let bytes = &slc[np..np + len.min(slc.len().saturating_sub(np))];
            let s = String::from_utf8_lossy(bytes).to_string();
            *p = np + len;
            match tag {
                0x17 => parse_utctime(&s),
                0x18 => parse_generalized(&s),
                _ => 0,
            }
        }
        let mut p = 0;
        if slc.get(p) != Some(&0x30) {
            return (0, i64::MAX);
        }
        p += 1;
        let (np, _len) = match read_len(slc, p) {
            Some(v) => v,
            None => return (0, i64::MAX),
        };
        p = np;
        let nb = read_time(slc, &mut p);
        let na = read_time(slc, &mut p);
        (nb, na)
    }

    // skip [0] version EXPLICIT optional (tag 0xa0)
    let mut pos = 0;
    if tbs_slice.get(pos) == Some(&0xa0) {
        if let Some((_, hdr, len, _)) = next_tlv(tbs_slice, pos) {
            pos += hdr + len;
        }
    }
    // skip serial + sigAlg
    for _ in 0..2 {
        if let Some((_, hdr, len, _)) = next_tlv(tbs_slice, pos) {
            pos += hdr + len;
        } else {
            return ("".into(), "".into(), 0, i64::MAX, vec![]);
        }
    }
    // issuer (SEQUENCE 0x30)
    let mut issuer = String::new();
    if let Some((_, hdr, len, vs)) = next_tlv(tbs_slice, pos) {
        if tbs_slice.get(pos) == Some(&0x30) {
            issuer = read_rdn_sequence(&tbs_slice[pos..]);
        }
        pos += hdr + len;
        let _ = vs;
    }
    // validity
    let mut nb = 0i64;
    let mut na = i64::MAX;
    if let Some((_, hdr, len, vs)) = next_tlv(tbs_slice, pos) {
        let slice = &tbs_slice[pos..];
        if hdr + len <= slice.len() {
            let (a, b) = read_validity(slice);
            nb = a;
            na = b;
        }
        pos += hdr + len;
        let _ = vs;
    }
    // subject
    let mut subject = String::new();
    if let Some((_, hdr, len, _)) = next_tlv(tbs_slice, pos) {
        if tbs_slice.get(pos) == Some(&0x30) {
            subject = read_rdn_sequence(&tbs_slice[pos..]);
        }
        pos += hdr + len;
    }
    // skip SPKI (SEQUENCE) + optional [1] issuerUID + [2] subjectUID (context tags 0xa1, 0xa2)
    for _ in 0..1 {
        if let Some((_, hdr, len, _)) = next_tlv(tbs_slice, pos) {
            pos += hdr + len;
        }
    }
    for tg in [0xa1u8, 0xa2] {
        if tbs_slice.get(pos) == Some(&tg) {
            if let Some((_, hdr, len, _)) = next_tlv(tbs_slice, pos) {
                pos += hdr + len;
            }
        }
    }
    // extensions [3] EXPLICIT (0xa3)
    let mut sans: Vec<String> = Vec::new();
    if tbs_slice.get(pos) == Some(&0xa3) {
        if let Some((_, hdr, len, vs)) = next_tlv(tbs_slice, pos) {
            let inner = &tbs_slice[pos + hdr..pos.saturating_add(hdr).saturating_add(len)];
            // extensions SEQUENCE 0x30
            let mut p2 = 0;
            if inner.get(p2) == Some(&0x30) {
                p2 += 1;
                let (np, l) = match read_len(inner, p2) {
                    Some(v) => v,
                    None => (p2 + 1, 0),
                };
                let end = np + l;
                p2 = np;
                while p2 + 2 <= inner.len() && p2 < end {
                    // Extension SEQUENCE
                    if inner.get(p2) != Some(&0x30) {
                        break;
                    }
                    p2 += 1;
                    let (np_ex, ex_len) = match read_len(inner, p2) {
                        Some(v) => v,
                        None => break,
                    };
                    let ex_end = np_ex + ex_len;
                    let mut p_ex = np_ex;
                    // OID
                    if p_ex >= ex_end {
                        break;
                    }
                    if inner[p_ex] != 0x06 {
                        break;
                    }
                    p_ex += 1;
                    let (np_oid, oid_len) = match read_len(inner, p_ex) {
                        Some(v) => v,
                        None => break,
                    };
                    let oid_bytes = &inner[np_oid..np_oid + oid_len];
                    let is_san = oid_bytes.len() >= 9 &&
                        oid_bytes.starts_with(&[0x55, 0x1d, 0x11]) &&  // id-ce-subjectAltName = 2.5.29.17
                        oid_bytes.len() == 3; // 2.5.29.17 = three subidentifiers 85,29,17 → bytes: 0x55 0x1d 0x11 (since 85=0x55, 29=0x1d, 17=0x11)
                    let _ = is_san;
                    let oid_str = oid_bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(":");
                    p_ex = np_oid + oid_len;
                    // critical bool (opt tag 0x01)
                    if p_ex < ex_end && inner[p_ex] == 0x01 {
                        p_ex += 1;
                        if let Some((np_c, c_len)) = read_len(inner, p_ex) {
                            p_ex = np_c + c_len;
                        }
                    }
                    // value OCTET STRING (0x04)
                    if p_ex >= ex_end {
                        break;
                    }
                    if inner[p_ex] == 0x04 {
                        p_ex += 1;
                        if let Some((np_oc, oc_len)) = read_len(inner, p_ex) {
                            let oc_bytes = &inner
                                [np_oc..np_oc + oc_len.min(inner.len().saturating_sub(np_oc))];
                            // SAN OID "2.5.29.17" → DER: 0x55 0x1d 0x11
                            if oid_bytes == [0x55, 0x1d, 0x11] {
                                // GeneralNames SEQUENCE
                                let mut pp = 0;
                                if oc_bytes.get(pp) == Some(&0x30) {
                                    pp += 1;
                                    if let Some((np_gn, gn_len)) = read_len(oc_bytes, pp) {
                                        let gn_end = np_gn + gn_len;
                                        pp = np_gn;
                                        while pp < gn_end && pp < oc_bytes.len() {
                                            // tag: [2] = dNSName (context constructed 2 = 0x82)
                                            let tag = oc_bytes[pp];
                                            pp += 1;
                                            if let Some((np_n, n_len)) = read_len(oc_bytes, pp) {
                                                let n_start = np_n;
                                                let n_end = n_start
                                                    + n_len.min(
                                                        oc_bytes.len().saturating_sub(n_start),
                                                    );
                                                if tag == 0x82 {
                                                    let s = String::from_utf8_lossy(
                                                        &oc_bytes[n_start..n_end],
                                                    )
                                                    .to_string();
                                                    if !s.is_empty() {
                                                        sans.push(s);
                                                    }
                                                }
                                                pp = n_end;
                                            } else {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            let _ = oid_str;
                            p_ex = np_oc + oc_len;
                        }
                    }
                    p2 = ex_end;
                }
            }
            pos += hdr + len;
            let _ = vs;
        }
    }

    (subject, issuer, nb, na, sans)
}

pub async fn grab_http_banner(
    url: &str,
    timeout_sec: u64,
    verify_tls: bool,
) -> Result<BannerResult, Box<dyn std::error::Error + Send + Sync>> {
    // ── Pré-validation DNS : évite faux positifs wildcard SNI ──────────────
    let host_for_dns = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_default();
    let port_from_url = url::Url::parse(url).ok().and_then(|u| u.port());
    let dns_ok = if host_for_dns.is_empty() {
        true
    } else {
        validate_dns(&host_for_dns).await
    };
    if !dns_ok {
        return Err(format!(
            "DNS pre-validation failed for {} (wildcard/NXDOMAIN — avoiding SNI false positive)",
            host_for_dns
        )
        .into());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_sec))
        .danger_accept_invalid_certs(!verify_tls)
        .danger_accept_invalid_hostnames(!verify_tls)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("Mozilla/5.0 (compatible; NRTG/2.0; RedTeam-Scanner)")
        .build()?;

    // Try GET (more headers + body for tech detection) with size limit
    let resp = timeout(Duration::from_secs(timeout_sec), client.get(url).send())
        .await
        .map_err(|_| format!("HTTP timeout connecting to {}", url))?
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let status = resp.status().as_u16();
    let is_https = url.starts_with("https://");
    let service_name = if is_https { "https" } else { "http" }.to_string();

    // Probe certificat TLS (si HTTPS) avant la fin, pour récupérer fingerprint, dates, etc.
    let tls_info = if is_https {
        let host_clone = host_for_dns.clone();
        let port = port_from_url.unwrap_or(443);
        tokio::spawn(async move { probe_tls_cert(&host_clone, port).await })
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    // Collect all headers (lowercase)
    let mut headers_map: HashMap<String, String> = HashMap::new();
    for (k, v) in resp.headers().iter() {
        if let Ok(val) = v.to_str() {
            headers_map.insert(k.as_str().to_lowercase(), val.to_string());
        }
    }

    // Build banner from Server + X-Powered-By + interesting headers
    let server = headers_map.get("server").cloned();
    let powered_by = headers_map.get("x-powered-by").cloned();
    let content_type = headers_map.get("content-type").cloned();

    // Construct a rich banner string for version extraction
    let banner = {
        let mut parts: Vec<String> = Vec::new();
        if let Some(s) = &server {
            parts.push(format!("Server: {}", s));
        }
        if let Some(p) = &powered_by {
            parts.push(format!("X-Powered-By: {}", p));
        }
        // Add a few more useful headers for fingerprinting
        for hdr in &[
            "via",
            "x-generator",
            "x-aspnet-version",
            "x-drupal-cache",
            "x-wp-nonce",
            "x-jenkins",
            "x-content-type-options",
        ] {
            if let Some(v) = headers_map.get(*hdr) {
                parts.push(format!("{}: {}", hdr, v));
            }
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" | "))
        }
    };

    // Try to read first 4KB of body for tech stack detection
    let body_bytes = timeout(Duration::from_secs(timeout_sec.min(4)), resp.bytes())
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();

    let body_snippet =
        String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(4096)]).to_string();

    // Extract <title> tag
    let page_title = extract_page_title(&body_snippet);

    // Check for Elasticsearch JSON (may have no server header)
    let final_banner = if banner.is_none() && body_snippet.contains("\"cluster_name\"") {
        let ver = RE_ELASTICSEARCH
            .captures(&body_snippet)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "unknown".into());
        Some(format!("Elasticsearch/{}", ver))
    } else {
        banner
    };

    Ok(BannerResult {
        banner: final_banner,
        content_type,
        service_name,
        headers: headers_map,
        http_status: Some(status),
        page_title,
        dns_validated: dns_ok,
        silent_port: false,
        tls_info,
    })
}

pub async fn grab_tcp_banner(
    host: &str,
    port: u16,
    timeout_sec: u64,
) -> Result<BannerResult, Box<dyn std::error::Error + Send + Sync>> {
    // ── Pré-validation DNS ───────────────────────────────────────────────────
    let dns_ok = validate_dns(host).await;
    if !dns_ok {
        return Err(format!("DNS pre-validation failed for {} (wildcard/NXDOMAIN)", host).into());
    }

    let addr = format!("{}:{}", host, port);
    let service_name = port_to_service(port).to_string();

    let mut stream = timeout(Duration::from_secs(timeout_sec), TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("TCP timeout connecting to {}", addr))?
        .map_err(|e| format!("TCP connect to {} failed: {}", addr, e))?;

    let _ = stream.set_nodelay(true);

    // ── Service-specific probe payloads ─────────────────────────────────────
    match service_name.as_str() {
        "redis" => {
            let _ = timeout(
                Duration::from_millis(1000),
                stream.write_all(b"*1\r\n$4\r\nINFO\r\n"),
            )
            .await;
        }

        "mongodb" => {
            // isMaster wire-protocol query (OP_QUERY)
            let ping: &[u8] = &[
                0x41, 0x00, 0x00, 0x00, // messageLength = 65
                0x01, 0x00, 0x00, 0x00, // requestID
                0x00, 0x00, 0x00, 0x00, // responseTo
                0xd4, 0x07, 0x00, 0x00, // opCode OP_QUERY
                0x00, 0x00, 0x00, 0x00, // flags
                0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64,
                0x00, // "admin.$cmd\0"
                0x00, 0x00, 0x00, 0x00, // skip=0
                0xff, 0xff, 0xff, 0xff, // return=-1
                // { isMaster: 1 }
                0x13, 0x00, 0x00, 0x00, 0x10, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00,
            ];
            let _ = timeout(Duration::from_millis(1000), stream.write_all(ping)).await;
        }

        "mysql" => {
            // MySQL server greeting — just read (server sends first)
        }

        "smtp" => {
            // Server sends banner first; then we say EHLO for extra info
            let mut buf = [0u8; 512];
            let _ = timeout(Duration::from_millis(1500), stream.read(&mut buf)).await;
            let greeting = String::from_utf8_lossy(&buf);
            if greeting.starts_with("220") {
                let _ = timeout(
                    Duration::from_millis(1000),
                    stream.write_all(b"EHLO scanner.nrtg.local\r\n"),
                )
                .await;
            }
        }

        "ftp" => {
            // Server sends banner; then we send FEAT for extended info
            let mut buf = [0u8; 256];
            let _ = timeout(Duration::from_millis(1200), stream.read(&mut buf)).await;
            let _ = timeout(Duration::from_millis(800), stream.write_all(b"FEAT\r\n")).await;
        }

        "memcached" => {
            let _ = timeout(Duration::from_millis(800), stream.write_all(b"version\r\n")).await;
        }

        "elasticsearch" => {
            // HTTP GET on port 9200
            let req = format!(
                "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: NRTG/2.0\r\n\r\n",
                host
            );
            let _ = timeout(
                Duration::from_millis(1200),
                stream.write_all(req.as_bytes()),
            )
            .await;
        }

        "rabbitmq" => {
            // AMQP 0-9-1 protocol header
            let _ = timeout(
                Duration::from_millis(800),
                stream.write_all(b"AMQP\x00\x00\x09\x01"),
            )
            .await;
        }

        "docker-api" => {
            let req = format!(
                "GET /version HTTP/1.0\r\nHost: {}\r\nUser-Agent: NRTG/2.0\r\n\r\n",
                host
            );
            let _ = timeout(
                Duration::from_millis(1200),
                stream.write_all(req.as_bytes()),
            )
            .await;
        }

        "winrm" => {
            // WS-Management SOAP probe — check if WinRM is open and responding
            let soap = format!(
                concat!(
                    "POST /wsman HTTP/1.1\r\n",
                    "Host: {}\r\n",
                    "Content-Type: application/soap+xml;charset=UTF-8\r\n",
                    "Content-Length: 0\r\n",
                    "User-Agent: NRTG/2.0\r\n",
                    "\r\n"
                ),
                host
            );
            let _ = timeout(
                Duration::from_millis(1200),
                stream.write_all(soap.as_bytes()),
            )
            .await;
        }

        "vnc" => {
            // VNC server sends its banner first (RFB protocol)
            // Just read — no probe needed
        }

        "mqtt" => {
            // MQTT CONNECT packet — fixed header 0x10, variable header with protocol name
            // Protocol: MQTT, Version: 4 (3.1.1), Clean session, keepalive=60
            let connect: &[u8] = &[
                0x10, // CONNECT
                0x11, // remaining length = 17
                0x00, 0x04, // protocol name length
                0x4d, 0x51, 0x54, 0x54, // "MQTT"
                0x04, // protocol level 4 (3.1.1)
                0x02, // connect flags: clean session
                0x00, 0x3c, // keepalive = 60s
                0x00, 0x07, // client id length
                0x4e, 0x52, 0x54, 0x47, 0x2f, 0x32, 0x30, // "NRTG/20"
            ];
            let _ = timeout(Duration::from_millis(1000), stream.write_all(connect)).await;
        }

        "kubernetes" => {
            // Kubernetes API server — HTTP GET /version
            let req = format!(
                "GET /version HTTP/1.0\r\nHost: {}\r\nUser-Agent: NRTG/2.0\r\nAccept: application/json\r\n\r\n",
                host
            );
            let _ = timeout(
                Duration::from_millis(1500),
                stream.write_all(req.as_bytes()),
            )
            .await;
        }

        "kerberos" => {
            // Kerberos AS-REQ probe (minimal krb5 packet to check if port is open)
            // Send a basic KRB_AS_REQ to get an error response (confirms Kerberos)
            let krb_probe: &[u8] = &[
                0x00, 0x00, 0x00, 0x28, // length = 40
                0x6a, 0x26, 0x30, 0x24, // AS-REQ wrapper
                0xa1, 0x03, 0x02, 0x01, 0x05, // pvno = 5
                0xa2, 0x03, 0x02, 0x01, 0x0a, // msg-type = 10 (AS-REQ)
                0xa4, 0x18, 0x30, 0x16, // req-body
                0xa0, 0x07, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10, // kdc-options
                0xa2, 0x0b, 0x1b, 0x09, // realm
                0x4c, 0x4f, 0x43, 0x41, 0x4c, 0x48, 0x4f, 0x53, 0x54, // "LOCALHOST"
            ];
            let _ = timeout(Duration::from_millis(1000), stream.write_all(krb_probe)).await;
        }

        "snmp" => {
            // SNMP v1 GetRequest for sysDescr (OID 1.3.6.1.2.1.1.1.0)
            // community string "public"
            let snmp_get: &[u8] = &[
                0x30, 0x26, // SEQUENCE
                0x02, 0x01, 0x00, // version: 0 (SNMPv1)
                0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // community: "public"
                0xa0, 0x19, // GetRequest PDU
                0x02, 0x01, 0x01, // request-id: 1
                0x02, 0x01, 0x00, // error-status: 0
                0x02, 0x01, 0x00, // error-index: 0
                0x30, 0x0e, 0x30, 0x0c, // variable-bindings
                0x06, 0x08, // OID: sysDescr (1.3.6.1.2.1.1.1.0)
                0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00, // value: null
            ];
            // SNMP uses UDP, but we attempt TCP (some implementations support it)
            let _ = timeout(Duration::from_millis(800), stream.write_all(snmp_get)).await;
        }

        "etcd" => {
            let req = format!(
                "GET /version HTTP/1.0\r\nHost: {}\r\nUser-Agent: NRTG/2.0\r\n\r\n",
                host
            );
            let _ = timeout(
                Duration::from_millis(1200),
                stream.write_all(req.as_bytes()),
            )
            .await;
        }

        "kibana" => {
            let req = format!(
                "GET /api/status HTTP/1.0\r\nHost: {}\r\nUser-Agent: NRTG/2.0\r\n\r\n",
                host
            );
            let _ = timeout(
                Duration::from_millis(1200),
                stream.write_all(req.as_bytes()),
            )
            .await;
        }

        "influxdb" => {
            let req = format!(
                "GET /ping HTTP/1.0\r\nHost: {}\r\nUser-Agent: NRTG/2.0\r\n\r\n",
                host
            );
            let _ = timeout(
                Duration::from_millis(1200),
                stream.write_all(req.as_bytes()),
            )
            .await;
        }

        // SSH, telnet, pop3, imap, ldap, smb, rdp, mssql, postgresql, oracle,
        // zookeeper, kafka, dns — server speaks first or we just read
        _ => {}
    }

    // ── Read response ────────────────────────────────────────────────────────
    let mut buf = [0u8; 4096];
    let n = timeout(
        Duration::from_secs(timeout_sec.min(3)),
        stream.read(&mut buf),
    )
    .await
    .map_err(|_| "Banner read timeout".to_string())?
    .map_err(|e| format!("Read from {} failed: {}", addr, e))?;

    if n == 0 {
        // ⚠ Port TCP is open (3-way handshake OK) but server sent ZERO bytes.
        // This indicates: tarpit / filtered egress / non-speaking service / or firewall SYN-ACK spoof.
        // We no longer mark these as reachable (false positives on routed ports).
        return Ok(BannerResult {
            service_name,
            silent_port: true,
            dns_validated: dns_ok,
            ..Default::default()
        });
    }

    let raw = &buf[..n];
    let banner_str = lossy_truncate(raw, 1024);

    // ── Post-process specific protocols ─────────────────────────────────────
    let final_banner = match service_name.as_str() {
        "redis" => parse_redis_banner(&banner_str),
        "smb" => {
            // SMB negotiation response — any reply means port is open
            if n >= 4 {
                Some(format!(
                    "SMB [{} bytes — {}]",
                    n,
                    if raw[0] == 0xff && raw[1] == b'S' {
                        "SMBv1"
                    } else if raw[0] == 0xfe {
                        "SMBv2/3"
                    } else {
                        "SMB-like"
                    }
                ))
            } else {
                Some("SMB (open)".into())
            }
        }
        "rdp" => {
            if n > 0 {
                Some(format!("RDP [{} bytes — connection response]", n))
            } else {
                None
            }
        }
        "ldap" => {
            if n > 0 {
                Some(format!("LDAP [{} bytes]", n))
            } else {
                None
            }
        }
        "vnc" => {
            // RFB protocol: "RFB 003.008\n"
            if banner_str.starts_with("RFB") {
                let ver = banner_str.trim().replace("RFB ", "VNC/RFB-");
                Some(format!("{} (port open)", ver))
            } else if n > 0 {
                Some(format!("VNC-like [{} bytes]", n))
            } else {
                None
            }
        }
        "winrm" => {
            if banner_str.contains("HTTP")
                || banner_str.contains("WSMAN")
                || banner_str.contains("WSMan")
            {
                let status = banner_str.lines().next().unwrap_or("WinRM").to_string();
                Some(format!(
                    "WinRM — {}",
                    &status.chars().take(80).collect::<String>()
                ))
            } else if n > 0 {
                Some(format!("WinRM [{} bytes]", n))
            } else {
                None
            }
        }
        "mqtt" => {
            // CONNACK: 0x20 0x02 <session> <return_code>
            if n >= 4 && raw[0] == 0x20 && raw[1] == 0x02 {
                let rc = raw[3];
                let status = match rc {
                    0x00 => "Connection Accepted — NO AUTH REQUIRED",
                    0x04 => "Bad credentials",
                    0x05 => "Not authorized",
                    _ => "CONNACK received",
                };
                Some(format!("MQTT CONNACK — {} [rc=0x{:02x}]", status, rc))
            } else if n > 0 {
                Some(format!("MQTT-like [{} bytes]", n))
            } else {
                None
            }
        }
        "kubernetes" => {
            if banner_str.contains("gitVersion") || banner_str.contains("major") {
                let ver = banner_str
                    .find("\"gitVersion\"")
                    .map(|p| banner_str[p + 15..].split('"').next().unwrap_or("?"))
                    .unwrap_or("unknown");
                Some(format!("Kubernetes API gitVersion={}", ver))
            } else if banner_str.contains("Unauthorized") || banner_str.contains("401") {
                Some("Kubernetes API — 401 (auth required, port confirmed)".into())
            } else if banner_str.contains("Forbidden") || banner_str.contains("403") {
                Some("Kubernetes API — 403 (port confirmed, auth needed)".into())
            } else if n > 0 {
                Some(format!("Kubernetes-like [{} bytes]", n))
            } else {
                None
            }
        }
        "kerberos" => {
            if n >= 4 {
                // Any reply from port 88 = Kerberos KDC running
                Some(format!("Kerberos KDC — {} bytes (port confirmed)", n))
            } else {
                None
            }
        }
        "snmp" => {
            if n >= 2 && raw[0] == 0x30 {
                // SNMP response is a SEQUENCE — extract printable chars
                let readable: String = banner_str
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .take(120)
                    .collect();
                Some(format!("SNMP response [{} bytes] — {}", n, readable.trim()))
            } else if n > 0 {
                Some(format!("SNMP-like [{} bytes]", n))
            } else {
                None
            }
        }
        _ => {
            if banner_str.is_empty() {
                None
            } else {
                Some(banner_str)
            }
        }
    };

    Ok(BannerResult {
        banner: final_banner,
        content_type: None,
        service_name,
        headers: HashMap::new(),
        http_status: None,
        page_title: None,
        dns_validated: dns_ok,
        silent_port: false,
        tls_info: None,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Version extraction
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct VersionInfo {
    pub product: String,
    pub version: String,
}

pub fn extract_version(banner: &str, protocol: &str) -> Option<VersionInfo> {
    let b = banner; // keep original case for some patterns
    let b_lower = b.to_lowercase();

    macro_rules! try_re {
        ($re:expr, $product:expr) => {
            if let Some(m) = $re.captures(b) {
                let ver = m
                    .get(1)
                    .or_else(|| m.get(2))
                    .map(|g| g.as_str().to_string())
                    .unwrap_or_else(|| "unknown".into());
                return Some(VersionInfo {
                    product: $product.into(),
                    version: ver,
                });
            }
        };
    }

    // HTTP / HTTPS — server header parsing + x-generator / x-powered-by
    if protocol == "http" || protocol == "https" {
        try_re!(RE_NGINX, "nginx");
        try_re!(RE_APACHE, "apache");
        try_re!(RE_IIS, "iis");
        try_re!(RE_LIGHTTPD, "lighttpd");
        try_re!(RE_TOMCAT, "tomcat");

        if b_lower.contains("server:") && b_lower.contains("apache") {
            let ver = RE_APACHE
                .captures(b)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "unknown".into());
            if b_lower.contains("x-generator:")
                && (b_lower.contains("drupal") || b_lower.contains("wordpress"))
            {
                // CMS banner wins over the generic Apache server header.
                // Fall through to the x-generator branch below.
            } else {
                return Some(VersionInfo {
                    product: "apache".into(),
                    version: ver,
                });
            }
        }

        // Caddy (may have no version)
        if RE_CADDY.is_match(b) {
            let ver = RE_CADDY
                .captures(b)
                .and_then(|c| c.get(2))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "unknown".into());
            return Some(VersionInfo {
                product: "caddy".into(),
                version: ver,
            });
        }

        // Drupal / WordPress / Joomla via x-generator
        if let Some(m) = Regex::new(r"(?i)x-generator:\s*Drupal\s+(\d+(?:\.\d+)*)")
            .ok()?
            .captures(b)
        {
            let ver = m
                .get(1)
                .map(|g| g.as_str().into())
                .unwrap_or_else(|| "unknown".into());
            return Some(VersionInfo {
                product: "drupal".into(),
                version: ver,
            });
        }
        if let Some(m) = Regex::new(r"(?i)x-generator:\s*WordPress\s+(\d+(?:\.\d+)*)")
            .ok()?
            .captures(b)
        {
            let ver = m
                .get(1)
                .map(|g| g.as_str().into())
                .unwrap_or_else(|| "unknown".into());
            return Some(VersionInfo {
                product: "wordpress".into(),
                version: ver,
            });
        }
        if b_lower.contains("x-generator:") && b_lower.contains("drupal") {
            return Some(VersionInfo {
                product: "drupal".into(),
                version: "unknown".into(),
            });
        }
        if b_lower.contains("x-generator:") && b_lower.contains("wordpress") {
            return Some(VersionInfo {
                product: "wordpress".into(),
                version: "unknown".into(),
            });
        }
        if let Some(m) = Regex::new(r"(?i)x-aspnet-version:\s*([0-9.]+)")
            .ok()?
            .captures(b)
        {
            return Some(VersionInfo {
                product: "aspnet".into(),
                version: m
                    .get(1)
                    .map(|g| g.as_str().into())
                    .unwrap_or_else(|| "unknown".into()),
            });
        }

        // Elasticsearch JSON body
        if let Some(m) = RE_ELASTICSEARCH.captures(b) {
            return Some(VersionInfo {
                product: "elasticsearch".into(),
                version: m
                    .get(1)
                    .map(|g| g.as_str().into())
                    .unwrap_or_else(|| "unknown".into()),
            });
        }

        // X-Powered-By PHP
        if let Some(m) = Regex::new(r"(?i)PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
            .ok()?
            .captures(b)
        {
            return Some(VersionInfo {
                product: "php".into(),
                version: m
                    .get(1)
                    .map(|g| g.as_str().into())
                    .unwrap_or_else(|| "unknown".into()),
            });
        }
        if let Some(m) = Regex::new(r"(?i)x-powered-by:\s*Express(?:/([0-9.]+))?")
            .ok()?
            .captures(b)
        {
            let ver = m
                .get(1)
                .map(|g| g.as_str().into())
                .unwrap_or_else(|| "unknown".into());
            return Some(VersionInfo {
                product: "express".into(),
                version: ver,
            });
        }

        // Jenkins
        if b_lower.contains("x-jenkins") {
            if let Some(m) = Regex::new(r"(?i)x-jenkins:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
                .ok()?
                .captures(b)
            {
                return Some(VersionInfo {
                    product: "jenkins".into(),
                    version: m
                        .get(1)
                        .map(|g| g.as_str().into())
                        .unwrap_or_else(|| "unknown".into()),
                });
            }
            return Some(VersionInfo {
                product: "jenkins".into(),
                version: "unknown".into(),
            });
        }

        return None;
    }

    // TCP services
    try_re!(
        RE_SSH,
        if b.to_lowercase().contains("dropbear") {
            "dropbear"
        } else {
            "openssh"
        }
    );
    try_re!(RE_REDIS, "redis");
    try_re!(RE_REDIS_SHORT, "redis");
    try_re!(RE_VSFTPD, "vsftpd");
    try_re!(RE_PROFTPD, "proftpd");
    try_re!(RE_POSTFIX, "postfix");
    try_re!(RE_EXIM, "exim");
    try_re!(RE_SENDMAIL, "sendmail");
    try_re!(RE_MYSQL, "mysql");
    try_re!(RE_PGSQL, "postgresql");
    try_re!(RE_MONGO, "mongodb");
    try_re!(RE_MSSQL, "mssql");
    try_re!(RE_BIND, "bind");
    try_re!(RE_MEMCACHED, "memcached");
    try_re!(RE_ELASTICSEARCH, "elasticsearch");
    try_re!(RE_RABBITMQ, "rabbitmq");

    if RE_TELNET.is_match(&b.to_lowercase()) {
        return Some(VersionInfo {
            product: "telnet".into(),
            version: "*".into(),
        });
    }

    // SMB open port
    if b.starts_with("SMB") {
        return Some(VersionInfo {
            product: "smb".into(),
            version: "unknown".into(),
        });
    }

    // RDP open port
    if b.starts_with("RDP") {
        return Some(VersionInfo {
            product: "rdp".into(),
            version: "unknown".into(),
        });
    }

    // LDAP
    if b.starts_with("LDAP") {
        return Some(VersionInfo {
            product: "ldap".into(),
            version: "unknown".into(),
        });
    }

    // VNC — extract RFB version
    if b.starts_with("VNC/RFB") || b.starts_with("RFB") {
        let ver = b.split('-').last().unwrap_or("unknown").trim().to_string();
        return Some(VersionInfo {
            product: "vnc".into(),
            version: ver,
        });
    }

    // WinRM
    if b.starts_with("WinRM") {
        return Some(VersionInfo {
            product: "winrm".into(),
            version: "unknown".into(),
        });
    }

    // MQTT
    if b.starts_with("MQTT") {
        return Some(VersionInfo {
            product: "mqtt".into(),
            version: "3.1.1".into(),
        });
    }

    // Kubernetes
    if b.contains("Kubernetes API") {
        let ver = if let Some(p) = b.find("gitVersion=") {
            b[p + 11..]
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string()
        } else {
            "unknown".into()
        };
        return Some(VersionInfo {
            product: "kubernetes".into(),
            version: ver,
        });
    }

    // Kerberos
    if b.starts_with("Kerberos") {
        return Some(VersionInfo {
            product: "kerberos".into(),
            version: "5".into(),
        });
    }

    // SNMP
    if b.starts_with("SNMP") {
        return Some(VersionInfo {
            product: "snmp".into(),
            version: "v1/v2c".into(),
        });
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Port reachability check (fast TCP connect, no banner)
// ─────────────────────────────────────────────────────────────────────────────

/// Fast check: is a port open? Returns true if TCP connect succeeds.
pub async fn is_port_open(host: &str, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{}:{}", host, port);
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Scan a list of ports on a host — returns only open ones (fast connect sweep)
pub async fn sweep_ports(host: &str, ports: &[u16], timeout_ms: u64) -> Vec<u16> {
    use futures::StreamExt;
    futures::stream::iter(ports.iter().copied())
        .map(|p| {
            let h = host.to_string();
            async move {
                if is_port_open(&h, p, timeout_ms).await {
                    Some(p)
                } else {
                    None
                }
            }
        })
        .buffer_unordered(50)
        .filter_map(|x| async move { x })
        .collect()
        .await
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_redis_banner(raw: &str) -> Option<String> {
    // Pick out the version and key info lines from the INFO response
    let mut parts: Vec<String> = Vec::new();
    for line in raw.lines().take(30) {
        let l = line.trim();
        if l.starts_with("redis_version:")
            || l.starts_with("redis_mode:")
            || l.starts_with("os:")
            || l.starts_with("arch_bits:")
            || l.starts_with("role:")
        {
            parts.push(l.to_string());
        }
    }
    if parts.is_empty() {
        if raw.is_empty() {
            None
        } else {
            Some(raw.chars().take(512).collect())
        }
    } else {
        Some(parts.join(" | "))
    }
}

fn lossy_truncate(bytes: &[u8], max: usize) -> String {
    let s = String::from_utf8_lossy(bytes);
    let trimmed = s.trim();
    if trimmed.len() <= max {
        trimmed.to_string()
    } else {
        format!("{}…", &trimmed[..max])
    }
}

fn extract_page_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start = lower.find("<title>")?;
    let end = lower[start + 7..].find("</title>").map(|i| start + 7 + i)?;
    let raw = html[start + 7..end].trim().to_string();
    if raw.is_empty() {
        None
    } else {
        Some(raw.chars().take(120).collect())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_nginx_http() {
        let vi = extract_version("Server: nginx/1.14.0 (Ubuntu)", "http").unwrap();
        assert_eq!(vi.product, "nginx");
        assert_eq!(vi.version, "1.14.0");
    }

    #[test]
    fn test_extract_apache_http() {
        let vi = extract_version("Server: Apache/2.4.29 (Ubuntu)", "http").unwrap();
        assert_eq!(vi.product, "apache");
        assert_eq!(vi.version, "2.4.29");
    }

    #[test]
    fn test_extract_iis() {
        let vi = extract_version("Server: Microsoft-IIS/10.0", "http").unwrap();
        assert_eq!(vi.product, "iis");
        assert_eq!(vi.version, "10.0");
    }

    #[test]
    fn test_extract_openssh_tcp() {
        let vi = extract_version("SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10", "tcp").unwrap();
        assert_eq!(vi.product, "openssh");
        assert_eq!(vi.version, "7.2");
    }

    #[test]
    fn test_extract_dropbear() {
        let vi = extract_version("SSH-2.0-dropbear_2016.74", "tcp").unwrap();
        assert_eq!(vi.product, "dropbear");
    }

    #[test]
    fn test_extract_redis_info() {
        let banner = "redis_version:6.2.7 | redis_mode:standalone | role:master";
        let vi = extract_version(banner, "tcp").unwrap();
        assert_eq!(vi.product, "redis");
        assert_eq!(vi.version, "6.2.7");
    }

    #[test]
    fn test_extract_elasticsearch() {
        let body = r#"{"name":"node1","cluster_name":"es","version":{"number":"7.17.0"}}"#;
        let vi = extract_version(body, "http").unwrap();
        assert_eq!(vi.product, "elasticsearch");
        assert_eq!(vi.version, "7.17.0");
    }

    #[test]
    fn test_port_service_map() {
        assert_eq!(port_to_service(6379), "redis");
        assert_eq!(port_to_service(3306), "mysql");
        assert_eq!(port_to_service(5432), "postgresql");
        assert_eq!(port_to_service(27017), "mongodb");
        assert_eq!(port_to_service(23), "telnet");
        assert_eq!(port_to_service(445), "smb");
        assert_eq!(port_to_service(9200), "elasticsearch");
        assert_eq!(port_to_service(2375), "docker-api");
        assert_eq!(port_to_service(11211), "memcached");
    }

    #[test]
    fn test_page_title_extraction() {
        let html = "<html><head><title>Jenkins Dashboard</title></head></html>";
        assert_eq!(extract_page_title(html), Some("Jenkins Dashboard".into()));
    }

    #[test]
    fn test_unknown_banner_returns_none() {
        assert!(extract_version("some random banner no version", "tcp").is_none());
    }
}
