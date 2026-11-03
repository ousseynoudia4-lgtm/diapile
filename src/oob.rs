//! Écouteur OOB (Out-Of-Band) intégré.
//!
//! Deux canaux d'exfiltration sont disponibles :
//!   * **HTTP** — écoute sur une adresse locale (127.0.0.1 par défaut, OPSEC) ;
//!   * **DNS** — répondeur UDP : la simple *résolution* du nom `<token>.<domaine>`
//!     confirme la vulnérabilité (utile quand la cible bloque les sorties TCP).
//!
//! Les deux canaux alimentent le **même** registre de tokens, ce qui permet de
//! confirmer les vulnérabilités aveugles (SSRF, XXE, command injection) par un
//! callback reçu au lieu de les inférer depuis la réponse HTTP.
//!
//! Séparation bind / host public : `bind` est l'adresse d'écoute locale, tandis
//! que `public_host` (host:port joignable par la cible) est injecté dans les
//! payloads. En lab mono-hôte, `public_host` vaut l'adresse locale effective ;
//! en opération réelle, l'opérateur renseigne l'adresse d'un tunnel/relais.
//!
//! ⚠️ Pour le canal DNS, n'utiliser que des domaines contrôlés par l'opérateur
//! (ou réservés IANA, ex. `example.org`, en test). Aucun domaine réel tiers.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Registre des tokens OOB reçus (partagé HTTP + DNS).
static HITS: OnceLock<Arc<Mutex<HashSet<String>>>> = OnceLock::new();
/// `host:port` public injecté dans les payloads HTTP.
static PUBLIC_HOST: OnceLock<String> = OnceLock::new();
/// Domaine suffixe des payloads DNS (vide ⇒ canal DNS inactif).
static DNS_DOMAIN: OnceLock<String> = OnceLock::new();

fn hits() -> &'static Arc<Mutex<HashSet<String>>> {
    HITS.get_or_init(|| Arc::new(Mutex::new(HashSet::new())))
}

/// Façade statique de l'écouteur OOB (état global au processus).
pub struct OobListener;

impl OobListener {
    /// Démarre l'écouteur HTTP. `bind` = adresse locale (ex: `127.0.0.1:0`),
    /// `public_host` = `host:port` injecté dans les payloads (vide ⇒ adresse
    /// locale effective). Ne bloque pas : l'accept-loop tourne en tâche de fond.
    pub async fn start(bind: &str, public_host: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(bind).await?;
        let local = listener.local_addr()?;
        let public = if public_host.trim().is_empty() {
            local.to_string()
        } else {
            public_host.trim().to_string()
        };
        let _ = PUBLIC_HOST.set(public.clone());

        println!(
            "  \x1b[35m[OOB]\x1b[0m HTTP sur {} — callbacks attendus sur http://{}",
            local, public
        );

        let hits = hits().clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let hits = hits.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
                        .await
                    {
                        Ok(Ok(n)) => n,
                        _ => 0,
                    };
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    if let Some(token) = extract_token(&req) {
                        register(&hits, &token, &format!("HTTP {}", peer));
                    }
                    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        Ok(())
    }

    /// Démarre le répondeur DNS. `bind` = adresse d'écoute UDP,
    /// `answer_ip` = adresse IPv4 renvoyée en réponse A, `domain` = suffixe des
    /// payloads (`<token>.<domain>`). Un `domain` vide désactive les payloads DNS
    /// mais l'écoute reste active (utile si les payloads sont fournis ailleurs).
    pub async fn start_dns(bind: &str, answer_ip: &str, domain: &str) -> std::io::Result<()> {
        let sock = UdpSocket::bind(bind).await?;
        let local = sock.local_addr()?;
        let answer = Ipv4Addr::from_str(answer_ip.trim()).unwrap_or(Ipv4Addr::LOCALHOST);
        let domain = domain.trim().trim_end_matches('.').to_string();
        if !domain.is_empty() {
            let _ = DNS_DOMAIN.set(domain.clone());
        }

        println!(
            "  \x1b[35m[OOB]\x1b[0m DNS sur {} — payloads {}.{} (réponse A → {})",
            local,
            "<token>",
            if domain.is_empty() {
                "<domaine>"
            } else {
                &domain
            },
            answer
        );

        let hits = hits().clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let pkt = &buf[..n];
                let (qname, qend) = match parse_qname(pkt) {
                    Some(v) => v,
                    None => continue,
                };
                // Le token est le premier label : `<token>.domaine`.
                if let Some(label) = qname.split('.').next() {
                    if !label.is_empty() && label.len() <= 64 {
                        register(&hits, label, &format!("DNS {}", peer));
                    }
                }
                if let Some(resp) = build_dns_response(pkt, qend, answer) {
                    let _ = sock.send_to(&resp, peer).await;
                }
            }
        });

        Ok(())
    }

    /// `true` si un callback portant ce token a déjà été reçu (HTTP ou DNS).
    pub fn hit(token: &str) -> bool {
        hits().lock().map(|s| s.contains(token)).unwrap_or(false)
    }

    /// Nombre de tokens distincts reçus.
    pub fn hit_count() -> usize {
        hits().lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Base `host:port` HTTP à injecter dans les payloads (`None` si inactif).
    pub fn base() -> Option<String> {
        PUBLIC_HOST.get().cloned()
    }

    /// Domaine suffixe des payloads DNS (`None` si le canal DNS est inactif).
    pub fn dns_domain() -> Option<String> {
        DNS_DOMAIN.get().filter(|d| !d.is_empty()).cloned()
    }

    /// Construit `<token>.<domaine>` pour un payload DNS (`None` si inactif).
    pub fn dns_name(token: &str) -> Option<String> {
        if token.is_empty() {
            return None;
        }
        Self::dns_domain().map(|d| format!("{}.{}", token, d))
    }
}

/// Enregistre un token reçu et l'annonce sur la sortie standard.
fn register(hits: &Arc<Mutex<HashSet<String>>>, token: &str, source: &str) {
    println!(
        "  \x1b[35;1m[OOB HIT]\x1b[0m token={} depuis {}",
        token, source
    );
    if let Ok(mut s) = hits.lock() {
        s.insert(token.to_string());
    }
}

/// Extrait le token depuis la requête HTTP : premier segment de chemin, sinon
/// premier label du `Host` (utile si la cible résout via DNS vers l'écouteur).
fn extract_token(req: &str) -> Option<String> {
    if let Some(line) = req.lines().next() {
        if let Some(path) = line.split_whitespace().nth(1) {
            let seg = path
                .trim_start_matches('/')
                .split(|c| c == '?' || c == '/' || c == '#')
                .next()
                .unwrap_or("");
            if !seg.is_empty() && seg.len() <= 64 {
                return Some(seg.to_string());
            }
        }
    }
    for line in req.lines() {
        if let Some(v) = line.strip_prefix("Host:") {
            if let Some(sub) = v.trim().split('.').next() {
                if !sub.is_empty() && sub.len() <= 64 {
                    return Some(sub.to_string());
                }
            }
        }
    }
    None
}

/// Analyse le QNAME d'une requête DNS et retourne `(nom, offset_fin)` où
/// `offset_fin` pointe juste après l'octet de terminaison (donc sur le QTYPE).
fn parse_qname(pkt: &[u8]) -> Option<(String, usize)> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if pos >= pkt.len() {
            return None;
        }
        let len = pkt[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // La compression de pointeur n'apparaît pas dans une question DNS.
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if pos + len > pkt.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&pkt[pos..pos + len]).to_string());
        pos += len;
    }
    Some((labels.join("."), pos))
}

/// Construit une réponse A minimale : reprend l'en-tête et la question, puis
/// ajoute un RR A (`qname_end` = fin du QNAME dans le paquet d'origine).
fn build_dns_response(pkt: &[u8], qname_end: usize, ip: Ipv4Addr) -> Option<Vec<u8>> {
    // Question complète = QNAME + QTYPE(2) + QCLASS(2).
    if pkt.len() < 12 || qname_end + 4 > pkt.len() {
        return None;
    }
    let mut resp = Vec::with_capacity(qname_end + 4 + 16);
    resp.extend_from_slice(&pkt[0..2]); // ID (transaction)
    resp.push(0x81); // QR=1, RD=1
    resp.push(0x80); // RA=1, RCODE=0
    resp.extend_from_slice(&pkt[4..6]); // QDCOUNT (copie)
    resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
    resp.extend_from_slice(&pkt[12..qname_end + 4]); // question
    resp.extend_from_slice(&[0xC0, 0x0C]); // NAME = pointeur → offset 12
    resp.extend_from_slice(&[0x00, 0x01]); // TYPE A
    resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60 s
    resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
    resp.extend_from_slice(&ip.octets());
    Some(resp)
}

/// Utilitaire : parse un `host:port` et retourne l'IPv4 d'écoute, ou
/// `127.0.0.1` si l'adresse est indéterminée (bind `0.0.0.0`/`::`).
pub fn answer_ip_for_bind(bind: &str) -> String {
    let host = match SocketAddr::from_str(bind) {
        Ok(a) => a.ip().to_string(),
        Err(_) => bind
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_default(),
    };
    let host = host.trim();
    if host.is_empty() || host == "0.0.0.0" || host == "::" || host == "[::]" {
        Ipv4Addr::LOCALHOST.to_string()
    } else {
        host.to_string()
    }
}
