//! DIAPILE — IPTV / Streaming Media Recon Module
//!
//! Couvre les protocoles de diffusion TV/média (souvent absents des scanners
//! réseau classiques) :
//! - **SSDP/UPnP** (UDP 239.255.255.250:1900) — découverte DLNA MediaServer,
//!   Smart TV, MediaRenderer, SAT>IP, Chromecast (DIAL).
//! - **RTSP** (ports 554/8554/8555) — serveurs de flux live (OPTIONS + DESCRIBE).
//! - **HLS** (HTTP(S) `*.m3u8`) — playlists de streaming non protégées.
//! - **Fingerprint** des serveurs média à partir des en-têtes `Server`/`USN`.
//!
//! La sortie est sérialisable (JSON) pour l'intégration reporting / dashboard.
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
//! ⚠️ Ne scanner que des infrastructures dont vous détenez le mandat écrit.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Un serveur média / appareil de diffusion TV découvert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaServer {
    pub host: String,
    pub port: u16,
    /// DLNA/UPnP, RTSP, HLS, SAT>IP, Chromecast, RTMP…
    pub protocol: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub friendly_name: Option<String>,
    /// URL de description UPnP ou racine du flux (si connue).
    pub location: Option<String>,
    /// Types de services UPnP annoncés (urn:schemas-upnp-org:service:...).
    pub services: Vec<String>,
    /// URLs de flux découvertes (RTSP/HTTP/HLS).
    pub streams: Vec<String>,
    pub findings: Vec<MediaFinding>,
}

/// Constat de sécurité rattaché à un serveur média.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaFinding {
    pub finding_type: String,
    pub description: String,
    pub severity: String,
    pub evidence: String,
}

/// Rapport de reconnaissance IPTV/média.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IptvScanReport {
    pub servers: Vec<MediaServer>,
    pub open_ports: Vec<(String, u16, String)>, // (host, port, protocole)
}

// ─────────────────────────────────────────────────────────────────────────────
// Ports TV / média
// ─────────────────────────────────────────────────────────────────────────────

pub fn iptv_ports() -> Vec<(u16, &'static str)> {
    vec![
        (554, "rtsp"),
        (8554, "rtsp-alt"),
        (8555, "rtsp-tls"),
        (1935, "rtmp"),
        (1900, "ssdp/upnp"),
        (8009, "chromecast-castv2"),
        (8060, "roku-ecp"),
        (5000, "dlna-upnp"),
        (8200, "minidlna"),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. SSDP / UPnP — découverte des serveurs média
// ─────────────────────────────────────────────────────────────────────────────

/// Envoie un `M-SEARCH` SSDP (ssdp:all) en unicast vers `target:1900` et
/// collecte les réponses jusqu'à expiration du timeout.
pub async fn ssdp_discover(target: &str, timeout_secs: u64) -> Vec<MediaServer> {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let _ = socket.set_broadcast(true);

    let msearch = "M-SEARCH * HTTP/1.1\r\n\
                   HOST: 239.255.255.250:1900\r\n\
                   MAN: \"ssdp:discover\"\r\n\
                   MX: 2\r\n\
                   ST: ssdp:all\r\n\
                   USER-AGENT: DIAPILE/2.0 UPnP/1.1\r\n\r\n";
    let dest = format!("{}:1900", target);
    if socket
        .send_to(msearch.as_bytes(), dest.as_str())
        .await
        .is_err()
    {
        return Vec::new();
    }

    let mut servers: Vec<MediaServer> = Vec::new();
    let mut buf = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _peer))) => {
                let resp = String::from_utf8_lossy(&buf[..n]).to_string();
                if let Some(srv) = parse_ssdp_response(&resp, target).await {
                    let dup = servers
                        .iter()
                        .any(|s| s.location.is_some() && s.location == srv.location);
                    if !dup {
                        servers.push(srv);
                    }
                }
            }
            // Timeout ou erreur de socket → fin de collecte.
            _ => break,
        }
    }
    servers
}

/// Parse une réponse SSDP et, si possible, enrichit via la description UPnP.
async fn parse_ssdp_response(resp: &str, fallback_host: &str) -> Option<MediaServer> {
    let location = header_value(resp, "LOCATION");
    let server = header_value(resp, "SERVER");
    let st = header_value(resp, "ST");
    let usn = header_value(resp, "USN");

    // Filtrer : on ne retient que les réponses média/DLNA/SAT>IP/DIAL.
    let st_l = st.clone().unwrap_or_default().to_lowercase();
    let is_media = st_l.contains("mediaserver")
        || st_l.contains("mediarenderer")
        || st_l.contains("dial-multiscreen")
        || st_l.contains("sat>ip")
        || st_l.contains("schemas-upnp-org")
        || st_l.contains("ssdp:all")
        || location.is_some();

    if !is_media {
        return None;
    }

    let (host, port) = if let Some(ref loc) = location {
        parse_location(loc).unwrap_or((fallback_host.to_string(), 80))
    } else {
        (fallback_host.to_string(), 1900)
    };

    let mut srv = MediaServer {
        host,
        port,
        protocol: "DLNA/UPnP".into(),
        vendor: None,
        model: None,
        friendly_name: None,
        location: location.clone(),
        services: Vec::new(),
        streams: Vec::new(),
        findings: Vec::new(),
    };

    if let Some(s) = &server {
        srv.findings.push(MediaFinding {
            finding_type: "SSDP Server Header".into(),
            description: "Bannière SSDP exposée (empreinte du serveur média).".into(),
            severity: "info".into(),
            evidence: s.clone(),
        });
    }
    if let Some(u) = usn {
        srv.services.push(format!("USN: {}", u));
    }
    if let Some(s) = st {
        srv.services.push(format!("ST: {}", s));
        let sl = s.to_lowercase();
        if sl.contains("sat>ip") {
            srv.protocol = "SAT>IP".into();
        } else if sl.contains("dial-multiscreen") {
            srv.protocol = "Chromecast (DIAL)".into();
        } else if sl.contains("mediarenderer") {
            srv.protocol = "DLNA MediaRenderer".into();
        }
    }

    // Enrichissement via la description de l'appareil UPnP.
    if let Some(loc) = &location {
        if let Some(desc) = fetch_device_description(loc).await {
            srv.friendly_name = xml_tag(&desc, "friendlyName");
            srv.vendor = xml_tag(&desc, "manufacturer");
            srv.model = xml_tag(&desc, "modelName");
            // Types de services déclarés.
            let re = regex::Regex::new(r"(?i)<serviceType>\s*([^<]+?)\s*</serviceType>").ok();
            if let Some(re) = re {
                for cap in re.captures_iter(&desc) {
                    let st = cap[1].trim().to_string();
                    if !st.is_empty() && !srv.services.iter().any(|s| s.contains(&st)) {
                        srv.services.push(st);
                    }
                }
            }
            srv.findings.push(MediaFinding {
                finding_type: "UPnP Device Description Exposed".into(),
                description: format!(
                    "Description UPnP accessible sans authentification ({}) : {}{}{}",
                    loc,
                    srv.friendly_name.clone().unwrap_or_default(),
                    srv.vendor
                        .as_ref()
                        .map(|v| format!(" — {}", v))
                        .unwrap_or_default(),
                    srv.model
                        .as_ref()
                        .map(|m| format!(" / {}", m))
                        .unwrap_or_default(),
                ),
                severity: "medium".into(),
                evidence: loc.clone(),
            });
        }
    }

    Some(srv)
}

/// Récupère le XML de description d'un appareil UPnP (LOCATION).
async fn fetch_device_description(location: &str) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;
    let resp = client.get(location).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text().await.ok()
}

/// Extrait un en-tête HTTP insensible à la casse.
fn header_value(resp: &str, name: &str) -> Option<String> {
    let wanted = name.to_lowercase();
    for line in resp.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().to_lowercase() == wanted {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Extrait (host, port) d'une URL `http://host:port/path`.
fn parse_location(url: &str) -> Option<(String, u16)> {
    let rest = url.splitn(2, "://").nth(1).unwrap_or(url);
    let authority = rest.split('/').next()?;
    match authority.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((authority.to_string(), 80)),
    }
}

/// Extrait le contenu texte d'une balise XML (première occurrence).
fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let re = regex::Regex::new(&format!(
        r"(?is)<{}\b[^>]*>(.*?)</{}>",
        regex::escape(tag),
        regex::escape(tag)
    ))
    .ok()?;
    let cap = re.captures(xml)?;
    let val = cap[1].trim();
    if val.is_empty() {
        None
    } else {
        Some(strip_entities(val))
    }
}

/// Décodage minimal des entités XML usuelles.
fn strip_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. RTSP — serveurs de flux live
// ─────────────────────────────────────────────────────────────────────────────

/// Sonde un serveur RTSP : `OPTIONS` puis `DESCRIBE` pour énumérer les flux.
pub async fn probe_rtsp(host: &str, port: u16, timeout_secs: u64) -> Option<MediaServer> {
    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    let options = format!(
        "OPTIONS rtsp://{}:{} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: DIAPILE/2.0\r\n\r\n",
        host, port
    );
    timeout(
        Duration::from_secs(timeout_secs),
        stream.write_all(options.as_bytes()),
    )
    .await
    .ok()?
    .ok()?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(timeout_secs), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();
    if !resp.starts_with("RTSP/") {
        return None;
    }

    let server_hdr = header_value(&resp, "Server");
    let public = header_value(&resp, "Public");

    let mut srv = MediaServer {
        host: host.to_string(),
        port,
        protocol: "RTSP".into(),
        vendor: None,
        model: None,
        friendly_name: None,
        location: Some(format!("rtsp://{}:{}", host, port)),
        services: Vec::new(),
        streams: Vec::new(),
        findings: Vec::new(),
    };

    if let Some(p) = public {
        srv.services.push(format!("Public: {}", p));
        srv.findings.push(MediaFinding {
            finding_type: "RTSP Methods Exposed".into(),
            description: format!(
                "Serveur RTSP accessible et méthodes annoncées : {}. \
                 Vérifier l'absence d'authentification sur DESCRIBE/SETUP/PLAY.",
                p
            ),
            severity: "medium".into(),
            evidence: format!("{}:{}", host, port),
        });
    }
    if let Some(s) = server_hdr {
        srv.model = Some(s.clone());
        srv.findings.push(MediaFinding {
            finding_type: "RTSP Server Banner".into(),
            description: "Bannière du serveur RTSP exposée (empreinte logicielle).".into(),
            severity: "info".into(),
            evidence: s,
        });
    }

    // DESCRIBE → SDP : liste des pistes/contrôles exposés.
    let describe = format!(
        "DESCRIBE rtsp://{}:{} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\
         User-Agent: DIAPILE/2.0\r\n\r\n",
        host, port
    );
    if timeout(
        Duration::from_secs(timeout_secs),
        stream.write_all(describe.as_bytes()),
    )
    .await
    .is_ok()
    {
        if let Ok(Ok(n2)) = timeout(Duration::from_secs(timeout_secs), stream.read(&mut buf)).await
        {
            if n2 > 0 {
                let sdp = String::from_utf8_lossy(&buf[..n2]).to_string();
                for line in sdp.lines() {
                    let t = line.trim();
                    if let Some(ctrl) = t.strip_prefix("a=control:") {
                        let url = if ctrl.starts_with("rtsp://") {
                            ctrl.to_string()
                        } else {
                            format!("rtsp://{}:{}/{}", host, port, ctrl.trim_start_matches('*'))
                        };
                        srv.streams.push(url);
                    }
                }
                if !srv.streams.is_empty() {
                    srv.findings.push(MediaFinding {
                        finding_type: "RTSP Stream Enumeration".into(),
                        description: format!(
                            "{} flux/piste(s) énuméré(s) sans authentification via DESCRIBE.",
                            srv.streams.len()
                        ),
                        severity: "high".into(),
                        evidence: srv.streams.join(", "),
                    });
                }
            }
        }
    }

    Some(srv)
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. HLS — playlists de streaming HTTP(S)
// ─────────────────────────────────────────────────────────────────────────────

/// Chemins de playlists HLS les plus courants.
const HLS_PATHS: [&str; 10] = [
    "/playlist.m3u8",
    "/index.m3u8",
    "/master.m3u8",
    "/stream.m3u8",
    "/hls/playlist.m3u8",
    "/hls/index.m3u8",
    "/live/playlist.m3u8",
    "/tv/playlist.m3u8",
    "/live/index.m3u8",
    "/m3u8/playlist.m3u8",
];

/// Sonde des playlists HLS sur un hôte:port HTTP(S).
pub async fn probe_hls(host: &str, port: u16, tls: bool, timeout_secs: u64) -> Option<MediaServer> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;
    let scheme = if tls { "https" } else { "http" };

    let mut srv: Option<MediaServer> = None;

    for path in HLS_PATHS {
        let url = format!("{}://{}:{}{}", scheme, host, port, path);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !resp.status().is_success() {
            continue;
        }
        let body = resp.text().await.unwrap_or_default();
        if !body.contains("#EXTM3U") {
            continue;
        }

        let playlist = !body.contains("#EXT-X-STREAM-INF");
        let entry = srv.get_or_insert_with(|| MediaServer {
            host: host.to_string(),
            port,
            protocol: "HLS".into(),
            vendor: None,
            model: None,
            friendly_name: None,
            location: Some(format!("{}://{}:{}", scheme, host, port)),
            services: Vec::new(),
            streams: Vec::new(),
            findings: Vec::new(),
        });

        entry.streams.push(url.clone());
        let kind = if playlist {
            "media"
        } else {
            "master (multi-débit)"
        };
        entry.findings.push(MediaFinding {
            finding_type: "HLS Playlist Exposed".into(),
            description: format!(
                "Playlist HLS « {} » accessible sans authentification ({}, {} ligne(s)).",
                path,
                kind,
                body.lines().count()
            ),
            severity: "medium".into(),
            evidence: url,
        });
    }

    srv
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Orchestration — scan IPTV/média complet
// ─────────────────────────────────────────────────────────────────────────────

/// Scan IPTV/média complet sur une liste d'hôtes :
/// SSDP/UPnP + RTSP + HLS, avec dédoublonnage.
pub async fn full_iptv_scan(hosts: &[&str]) -> IptvScanReport {
    let mut report = IptvScanReport::default();

    println!(
        "\n  \x1b[38;5;213m[IPTV/MEDIA]\x1b[0m Reconnaissance sur {} hôte(s)",
        hosts.len()
    );

    for &host in hosts {
        print!("  → {} ... ", host);

        let mut found = 0usize;

        // ── SSDP / UPnP (DLNA, Smart TV, SAT>IP, Chromecast) ────────────────
        for srv in ssdp_discover(host, 3).await {
            report
                .open_ports
                .push((host.to_string(), srv.port, srv.protocol.clone()));
            report.servers.push(srv);
            found += 1;
        }

        // ── RTSP ────────────────────────────────────────────────────────────
        for port in [554u16, 8554, 8555] {
            if let Some(srv) = probe_rtsp(host, port, 4).await {
                report
                    .open_ports
                    .push((host.to_string(), port, "RTSP".into()));
                report.servers.push(srv);
                found += 1;
            }
        }

        // ── HLS (HTTP + HTTPS) ──────────────────────────────────────────────
        for (port, tls) in [(80u16, false), (8080, false), (443, true), (8443, true)] {
            if let Some(srv) = probe_hls(host, port, tls, 4).await {
                report
                    .open_ports
                    .push((host.to_string(), port, "HLS".into()));
                report.servers.push(srv);
                found += 1;
            }
        }

        if found == 0 {
            println!("\x1b[38;5;244maucun service média détecté\x1b[0m");
        } else {
            println!("\x1b[38;5;82m{} service(s) média\x1b[0m", found);
        }
    }

    // Synthèse
    println!(
        "  \x1b[38;5;213m[IPTV/MEDIA]\x1b[0m {} serveur(s) média, {} port(s) ouvert(s)\n",
        report.servers.len(),
        report.open_ports.len()
    );
    for srv in &report.servers {
        let name = srv.friendly_name.as_deref().unwrap_or("(sans nom)");
        println!(
            "    • \x1b[36m{}\x1b[0m {}:{} — {} {}{}",
            srv.protocol,
            srv.host,
            srv.port,
            name,
            srv.vendor
                .as_ref()
                .map(|v| format!("[{}] ", v))
                .unwrap_or_default(),
            if srv.streams.is_empty() {
                String::new()
            } else {
                format!("— {} flux", srv.streams.len())
            }
        );
    }

    report
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_value_case_insensitive() {
        let resp = "HTTP/1.1 200 OK\r\nServer: SAT>IP/1.0\r\nlocation: http://192.0.2.10:8200/desc.xml\r\n\r\n";
        assert_eq!(header_value(resp, "SERVER").as_deref(), Some("SAT>IP/1.0"));
        assert_eq!(
            header_value(resp, "LOCATION").as_deref(),
            Some("http://192.0.2.10:8200/desc.xml")
        );
        assert_eq!(header_value(resp, "ST"), None);
    }

    #[test]
    fn test_parse_location() {
        assert_eq!(
            parse_location("http://198.51.100.5:49152/desc.xml"),
            Some(("198.51.100.5".into(), 49152))
        );
        assert_eq!(
            parse_location("http://host.local/rootDesc.xml"),
            Some(("host.local".into(), 80))
        );
    }

    #[test]
    fn test_xml_tag_extraction() {
        let xml = r#"<?xml version="1.0"?>
        <root><device>
          <friendlyName>Salon TV &amp; Box</friendlyName>
          <manufacturer>Acme</manufacturer>
          <modelName>MediaBox 1000</modelName>
        </device></root>"#;
        assert_eq!(
            xml_tag(xml, "friendlyName").as_deref(),
            Some("Salon TV & Box")
        );
        assert_eq!(xml_tag(xml, "manufacturer").as_deref(), Some("Acme"));
        assert_eq!(xml_tag(xml, "modelName").as_deref(), Some("MediaBox 1000"));
        assert_eq!(xml_tag(xml, "absent"), None);
    }

    #[test]
    fn test_iptv_ports_contains_rtsp() {
        let ports = iptv_ports();
        assert!(ports.iter().any(|(p, n)| *p == 554 && *n == "rtsp"));
        assert!(ports.iter().any(|(p, _)| *p == 1900));
        assert!(ports.iter().any(|(p, _)| *p == 8009));
    }
}
