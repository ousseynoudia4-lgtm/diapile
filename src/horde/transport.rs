//! HORDE — Transport WebSocket
//!
//! Réutilise l'implémentation WebSocket RFC 6455 maison de `c2::ws_c2`
//! (read_ws_frame / write_ws_frame / sha1 accept).
//!
//! **Protocole HORDE**:
//!   1. HTTP Upgrade client → Sec-WebSocket-Protocol: `diapile-horde-v1`
//!   2. Server répons 101 + envoie immédiatement `Challenge{nonce_hex}` (en CLAIR
//!      — c'est un nonce, pas une donnée sensible).
//!   3. Worker dérive K_w = HKDF2(master, salt=worker_id, info=horde/worker/v1)
//!      calcule HMAC-SHA256(K_w, nonce_bytes), envoie `Handshake{worker_id,hmac,caps}`
//!      — CLAIR (hmac lui-même authentifie).
//!   4. Si auth OK: server envoie `HordeCoordMsg::AssignmentMsg(...)` WRAPPED
//!      (base64(nonce||AES-GCM||tag)). À partir d'ici TOUS messages sont WRAPPED.
//!   5. Keepalive : client envoie Ping toutes les 15s, server Ack.
//!   6. Timeout 45s côté server sur silence → kill connexion.
//!
//! **Wire format message post-auth**: 1 seule frame TEXT contenant 1 string =
//!   `base64::STANDARD(nonce_12B || AES-256-GCM(plaintext_json) || tag_16B)`

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use base64::Engine;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::horde::coordinator::HordeCoordinator;
use crate::horde::crypto::{horde_derive_worker_key, horde_unwrap_msg, horde_wrap_msg};
use crate::horde::worker::{launch_scoped_bots_via_public, HordeWorker};
use crate::horde::{HordeCommandKind, HordeCoordMsg, HordeWorkerMsg};

type WsWriter = OwnedWriteHalf;
type WsReader = BufReader<OwnedReadHalf>;

// ─────────────────────────────────────────────────────────────────────────────
// Implémentation interne WS (copiée depuis c2::ws_c2 car non exportée)
// ─────────────────────────────────────────────────────────────────────────────
fn sha1_bytes(input: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

async fn ws_handshake_server(
    stream: TcpStream,
    protocol: &str,
) -> Result<(WsWriter, WsReader), Box<dyn std::error::Error + Send + Sync>> {
    let (reader_half, writer_half) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut writer = writer_half;
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
    let ws_key = headers
        .iter()
        .find(|h| h.to_lowercase().starts_with("sec-websocket-key:"))
        .and_then(|h| h.splitn(2, ':').nth(1))
        .map(|v| v.trim().to_string())
        .ok_or("Missing Sec-WebSocket-Key")?;
    const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let accept_input = format!("{}{}", ws_key, WS_GUID);
    let accept_hash = sha1_bytes(accept_input.as_bytes());
    let accept_token = base64::engine::general_purpose::STANDARD.encode(&accept_hash);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {}\r\n\r\n",
        accept_token, protocol
    );
    writer.write_all(response.as_bytes()).await?;
    Ok((writer, reader))
}

async fn ws_handshake_client(
    stream: TcpStream,
    host: &str,
    path: &str,
    protocol: &str,
) -> Result<(WsWriter, WsReader, String), Box<dyn std::error::Error + Send + Sync>> {
    use rand::RngCore;
    let mut raw_key = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw_key);
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(&raw_key);
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {}\r\n\r\n",
        path, host, key_b64, protocol
    );
    let (reader_half, mut writer_half) = stream.into_split();
    writer_half.write_all(req.as_bytes()).await?;
    let mut reader = BufReader::new(reader_half);
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" {
            break;
        }
        headers.push(line.trim().to_string());
    }
    // Expect 101 Switching Protocols
    let first_line = headers.first().ok_or("missing status line")?;
    if !first_line.contains("101") {
        return Err(format!("bad ws upgrade: {}", first_line).into());
    }
    let accept_expected = {
        const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let s = format!("{}{}", key_b64, WS_GUID);
        base64::engine::general_purpose::STANDARD.encode(&sha1_bytes(s.as_bytes()))
    };
    let got_accept = headers
        .iter()
        .find(|h| h.to_lowercase().starts_with("sec-websocket-accept:"))
        .and_then(|h| h.splitn(2, ':').nth(1))
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    if got_accept != accept_expected {
        return Err(format!("bad accept: {} vs {}", got_accept, accept_expected).into());
    }
    Ok((writer_half, reader, key_b64))
}

async fn read_ws_frame(
    reader: &mut WsReader,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut header = [0u8; 2];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let _fin = (header[0] & 0x80) != 0;
    let opcode = header[0] & 0x0f;
    let masked = (header[1] & 0x80) != 0;
    let mut len = (header[1] & 0x7f) as u64;
    if opcode == 0x08 {
        return Ok(None);
    }
    if opcode != 0x01 && opcode != 0x00 {
        return Ok(None);
    }
    if len == 126 {
        let mut ext = [0u8; 2];
        reader.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as u64;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        reader.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext);
    }
    let mask_key = if masked {
        let mut mk = [0u8; 4];
        reader.read_exact(&mut mk).await?;
        Some(mk)
    } else {
        None
    };
    if len > 2 * 1024 * 1024 {
        return Err("Frame too large".into());
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    if let Some(mk) = mask_key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mk[i % 4];
        }
    }
    Ok(Some(String::from_utf8_lossy(&payload).to_string()))
}

async fn write_ws_frame(
    writer: &mut WsWriter,
    text: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let payload = text.as_bytes();
    let len = payload.len();
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
// HORDE Coordinator listener
// ─────────────────────────────────────────────────────────────────────────────
pub async fn horde_listen_ws(
    coord: Arc<HordeCoordinator>,
    bind_addr: &str,
    bind_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", bind_addr, bind_port);
    let listener = TcpListener::bind(&addr).await?;
    println!(
        "  \x1b[38;5;196m[HORDE-WS]\x1b[0m Coordinator listener \x1b[33mws://{}\x1b[0m  subproto=diapile-horde-v1",
        addr
    );

    // Spawn le rebalance sweep loop (Task 9)
    {
        let me = Arc::clone(&coord);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if me.stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                let dead = me.sweep_dead_workers(10).await;
                if !dead.is_empty() {
                    eprintln!("  \x1b[33m[HORDE-REBALANCE]\x1b[0m {} worker(s) marqué(s) mort → re-calcul ranges", dead.len());
                    // TODO Task 9 complète — ici simple notification
                }
            }
        });
    }

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("  [HORDE-WS] accept err: {}", e);
                continue;
            }
        };
        let me = Arc::clone(&coord);
        tokio::spawn(async move {
            if let Err(e) = handle_horde_conn(me, stream, peer).await {
                eprintln!("  [HORDE-WS] {} err: {}", peer, e);
            }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler de connexion côté Coordinator
// ─────────────────────────────────────────────────────────────────────────────
async fn handle_horde_conn(
    coord: Arc<HordeCoordinator>,
    stream: TcpStream,
    peer: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut writer, mut reader) = ws_handshake_server(stream, "diapile-horde-v1").await?;
    println!("  \x1b[32m[HORDE-WS]\x1b[0m Nouvelle WS depuis {}", peer);

    // Étape 2: Challenge en CLAIR (1 message JSON non wrappé)
    let (nonce_hex, challenge_msg) = {
        // On demande un challenge depuis le coordinator state
        // (celui-ci n'est pas encore bindé à un worker_id — on génère un temp nonce
        //  et on le stocke avec un faux worker_id temporaire).
        // Workaround: on stocke une map temporaire par peer.
        let tmp_worker = format!("pending-{}", peer.port());
        let n = coord.register_challenge(&tmp_worker).await;
        let c = serde_json::to_string(&HordeCoordMsg::Challenge {
            nonce_hex: n.clone(),
        })?;
        (n, c)
    };
    write_ws_frame(&mut writer, &challenge_msg).await?;

    // Étape 3: Attente Handshake en CLAIR
    let hs_msg: HordeWorkerMsg = loop {
        let frame = timeout(Duration::from_secs(15), read_ws_frame(&mut reader))
            .await
            .map_err(|_| "timeout handshake")??;
        let text = match frame {
            Some(t) => t,
            None => return Ok(()),
        };
        let parsed = match serde_json::from_str::<HordeWorkerMsg>(&text) {
            Ok(p) => p,
            Err(_) => {
                eprintln!("  [HORDE-WS] {} hs parse err", peer);
                continue;
            }
        };
        if let HordeWorkerMsg::Handshake { .. } = &parsed {
            break parsed;
        }
    };
    let (worker_id, hmac_hex, caps) = match hs_msg {
        HordeWorkerMsg::Handshake {
            worker_id,
            hmac,
            caps,
        } => (worker_id, hmac, caps),
        _ => unreachable!(),
    };
    // Transférer le challenge depuis pending-peer → worker_id réel
    {
        let mut pending = coord.pending_challenges.write().await;
        let peer_key = format!("pending-{}", peer.port());
        if let Some(original_nonce) = pending.remove(&peer_key) {
            pending.insert(worker_id.clone(), original_nonce);
        }
    }

    let peer_ip = peer.ip().to_string();
    let auth_ok = coord
        .verify_handshake(&worker_id, peer_ip.clone(), caps.clone(), &hmac_hex)
        .await;
    if !auth_ok {
        eprintln!(
            "  \x1b[31m[HORDE-AUTH FAIL]\x1b[0m worker={} peer={}",
            worker_id, peer
        );
        return Ok(());
    }
    println!(
        "  \x1b[32m[HORDE-AUTH OK]\x1b[0m worker={:.8} cpu={} cap={} peer={}",
        worker_id, caps.cpu_cores, caps.estimated_bot_capacity, peer
    );

    // Post-auth: wrapper clés partagées + anti-replay
    let worker_key = horde_derive_worker_key(&coord.master_key, &worker_id)?;
    let mut last_nonce_co2w: u128 = 0;
    let mut last_nonce_w2c: u128 = 0;

    // S'abonner au canal broadcast coordinator
    let mut coord_events = coord.events_subscriber();

    // Générer un assignment initial (si aucune campagne démarrée → AssignmentMsg vide + Idle)
    // — on laissera la CLI interactive déclencher Start.
    {
        let ack = HordeCoordMsg::ReportAck;
        let wrapped = horde_wrap_msg(&worker_key, &serde_json::to_string(&ack)?)?;
        write_ws_frame(&mut writer, &wrapped).await?;
    }

    // Loop principale
    let heartbeat_every = Duration::from_secs(15);
    let read_timeout = Duration::from_secs(45);
    let mut last_recv = Instant::now();
    loop {
        tokio::select! {
            incoming = timeout(read_timeout, read_ws_frame(&mut reader)) => {
                let frame = match incoming {
                    Err(_) => { // timeout → 45s sans activity
                        let mut wmap = coord.workers.write().await;
                        if let Some(w) = wmap.get_mut(&worker_id) { w.connected = false; }
                        return Ok(());
                    }
                    Ok(Ok(Some(t))) => t,
                    Ok(Ok(None)) | Ok(Err(_)) => {
                        let mut wmap = coord.workers.write().await;
                        if let Some(w) = wmap.get_mut(&worker_id) { w.connected = false; }
                        return Ok(());
                    }
                };
                last_recv = Instant::now();
                // Déchiffrer
                let pt = match horde_unwrap_msg(&worker_key, &frame, &mut last_nonce_w2c) {
                    Some(p) => p,
                    None => {
                        eprintln!("  \x1b[31m[HORDE-CRYPTO FAIL]\x1b[0m worker={:.8} (anti-replay ou bad key)", worker_id);
                        continue;
                    }
                };
                let parsed: HordeWorkerMsg = match serde_json::from_str(&pt) {
                    Ok(p) => p, Err(e) => { eprintln!("  w{} json err: {}", worker_id, e); continue; }
                };
                match parsed {
                    HordeWorkerMsg::StatsDeltaBox { delta } => {
                        coord.ingest_delta(&worker_id, &delta).await;
                    }
                    HordeWorkerMsg::Ping { .. } => {
                        // Envoyer Ack wrap back
                        let ack = serde_json::to_string(&HordeCoordMsg::Idle)?;
                        let wr = horde_wrap_msg(&worker_key, &ack)?;
                        let _ = write_ws_frame(&mut writer, &wr).await;
                    }
                    HordeWorkerMsg::Ack { assignment_id } => {
                        let mut wmap = coord.workers.write().await;
                        if let Some(w) = wmap.get_mut(&worker_id) {
                            w.last_assignment_ack = Some(assignment_id);
                        }
                    }
                    _ => {}
                }
            }
            cmd = coord_events.recv() => {
                let msg = match cmd {
                    Ok(m) => m, Err(_) => continue,
                };
                // Si command Start → d'abord compute assignments, puis envoie AssignmentMsg
                let final_msg = if let HordeCoordMsg::Command { kind: HordeCommandKind::Start, .. } = &msg {
                    // On a besoin d'un GoldenEyeConfig valide pour les assignments
                    // Le CLI interactive fournira via Task 7. Fallback template:
                    use crate::stress::goldeneye::GoldenEyeConfig;
                    let tmpl = GoldenEyeConfig::default();
                    let assign_by_id = coord.compute_assignments(&tmpl).await;
                    if let Some(mine) = assign_by_id.get(&worker_id) {
                        HordeCoordMsg::AssignmentMsg { assignment: mine.clone() }
                    } else { msg.clone() }
                } else {
                    msg.clone()
                };
                let pt = serde_json::to_string(&final_msg)?;
                let wrapped = horde_wrap_msg(&worker_key, &pt)?;
                // Mettre à jour le nonce tracker (pas utilisé en sens coord→worker mais gardé
                // pour symétrie future)
                let _ = &mut last_nonce_co2w;
                if write_ws_frame(&mut writer, &wrapped).await.is_err() {
                    return Ok(());
                }
            }
            _ = tokio::time::sleep(heartbeat_every) => {
                if last_recv.elapsed() > read_timeout {
                    let mut wmap = coord.workers.write().await;
                    if let Some(w) = wmap.get_mut(&worker_id) { w.connected = false; }
                    return Ok(());
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HORDE Worker connecteur
// ─────────────────────────────────────────────────────────────────────────────
pub async fn horde_connect_ws(
    worker: Arc<HordeWorker>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use url::Url;
    let parsed = Url::parse(&worker.coord_url).map_err(|e| anyhow!("URL coord invalid: {}", e))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("missing host in {}", worker.coord_url))?
        .to_string();
    let port = parsed.port().unwrap_or(match parsed.scheme() {
        "wss" => 443,
        _ => 80,
    });
    let path = if parsed.path().trim().is_empty() {
        "/"
    } else {
        parsed.path()
    }
    .to_string();

    // Loop de retry backoff
    let mut backoff_ms: u64 = 500;
    loop {
        let tcp_addr = format!("{}:{}", host, port);
        let mut stream = match TcpStream::connect(&tcp_addr).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  [HORDE-CONN] {} — retry dans {}ms", e, backoff_ms);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(10_000);
                continue;
            }
        };
        backoff_ms = 500;
        // WS Upgrade
        let (mut writer, mut reader, _key_b64) =
            match ws_handshake_client(stream, &host, &path, "diapile-horde-v1").await {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("  [HORDE-WS] upgrade err: {} — retry", e);
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(10_000);
                    continue;
                }
            };
        println!(
            "  \x1b[32m[HORDE-WORKER]\x1b[0m WS connecté ok à {}:{}",
            host, port
        );

        // Attendre Challenge (clair)
        let challenge_nonce_hex: String =
            match timeout(Duration::from_secs(30), read_ws_frame(&mut reader)).await {
                Ok(Ok(Some(t))) => match serde_json::from_str::<HordeCoordMsg>(&t) {
                    Ok(HordeCoordMsg::Challenge { nonce_hex }) => nonce_hex,
                    Ok(other) => {
                        eprintln!("  [HORDE] attend Challenge, reçu {:?}", other);
                        continue;
                    }
                    Err(e) => {
                        eprintln!("  [HORDE] challenge parse err: {}", e);
                        continue;
                    }
                },
                _ => {
                    eprintln!("  [HORDE] pas de challenge — retry");
                    continue;
                }
            };

        // Envoyer Handshake (clair)
        let hs = worker.handshake_payload(&challenge_nonce_hex)?;
        write_ws_frame(&mut writer, &serde_json::to_string(&hs)?).await?;

        // Attendre ReportAck wrappé → on passe en mode wrap
        let wrapped = match timeout(Duration::from_secs(15), read_ws_frame(&mut reader)).await {
            Ok(Ok(Some(t))) => t,
            _ => continue,
        };
        let mut last_nonce_w2c: u128 = 0;
        let mut last_nonce_c2w: u128 = 0;
        // On unwrap avec worker_key pour vérifier connexion
        let _ack_pt = match horde_unwrap_msg(&worker.worker_key, &wrapped, &mut last_nonce_c2w) {
            Some(p) => p,
            None => {
                eprintln!("  \x1b[31m[HORDE] Handshake ACK unwrap FAIL — mauvaise clé ?\x1b[0m");
                return Err("auth fail".into());
            }
        };
        println!("  \x1b[32m[HORDE-WORKER]\x1b[0m Authentifié OK.");

        // Démarrer le stats pusher (Task 5)
        worker.spawn_stats_pusher(500);

        // Loop lecture depuis coordinator
        let mut reader_sender_events = worker.event_tx.subscribe();
        loop {
            tokio::select! {
                incoming = timeout(Duration::from_secs(60), read_ws_frame(&mut reader)) => {
                    let frame = match incoming {
                        Ok(Ok(Some(t))) => t,
                        Ok(Ok(None)) | Ok(Err(_)) => { break; }
                        Err(_) => {
                            // timeout 60s — envoyer Ping
                            let pt = serde_json::to_string(&HordeWorkerMsg::Ping {
                                ts: chrono::Utc::now().to_rfc3339()
                            })?;
                            let wr = horde_wrap_msg(&worker.worker_key, &pt)?;
                            if write_ws_frame(&mut writer, &wr).await.is_err() { break; }
                            continue;
                        }
                    };
                    let pt = match horde_unwrap_msg(&worker.worker_key, &frame, &mut last_nonce_c2w) {
                        Some(p) => p, None => continue,
                    };
                    let parsed: HordeCoordMsg = match serde_json::from_str(&pt) {
                        Ok(p) => p, Err(_) => continue,
                    };
                    match parsed {
                        HordeCoordMsg::AssignmentMsg { assignment } => {
                            println!("  \x1b[33m[HORDE-ASSIGN]\x1b[0m {:.8} bots [{}-{}] jitter={}ms",
                                worker.worker_id, assignment.bot_id_range_start,
                                assignment.bot_id_range_end_excl, assignment.startup_jitter_ms);
                            *worker.current_assignment.write().await = Some(assignment.clone());
                            // Envoyer ack au coordinator (wrap)
                            let ack_pt = serde_json::to_string(&HordeWorkerMsg::Ack {
                                assignment_id: assignment.assignment_id,
                            })?;
                            let wr = horde_wrap_msg(&worker.worker_key, &ack_pt)?;
                            let _ = write_ws_frame(&mut writer, &wr).await;
                        }
                        HordeCoordMsg::Command { kind, factor } => {
                            println!("  \x1b[35m[HORDE-CMD]\x1b[0m {:?} factor={:?}", kind, factor);
                            match kind {
                                HordeCommandKind::Start | HordeCommandKind::Resume => {
                                    let _ = launch_scoped_bots_via_public(&worker).await;
                                }
                                other => {
                                    worker.handle_coord_command(other, factor).await;
                                }
                            }
                        }
                        HordeCoordMsg::Idle | HordeCoordMsg::ReportAck => {}
                        HordeCoordMsg::Challenge {..} => {}
                    }
                }
                evt = reader_sender_events.recv() => {
                    let msg = match evt {
                        Ok(m) => m, Err(_) => continue,
                    };
                    // Skip Handshake — déjà envoyé. Skip Ping here (heartbeat)
                    if let HordeWorkerMsg::Handshake {..} = msg { continue; }
                    let pt = serde_json::to_string(&msg)?;
                    let wrapped = horde_wrap_msg(&worker.worker_key, &pt)?;
                    if write_ws_frame(&mut writer, &wrapped).await.is_err() { break; }
                }
            }
        }
        println!(
            "  \x1b[33m[HORDE-WORKER]\x1b[0m Déconnecté — retry dans {}s",
            backoff_ms / 1000
        );
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        backoff_ms = (backoff_ms * 2).min(15_000);
    }
}
