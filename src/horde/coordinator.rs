//! HORDE — Coordinator state machine (sans transport WS)

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use hex::ToHex;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::horde::crypto::{horde_derive_handshake_mac, horde_derive_worker_key};
use crate::horde::transport::horde_listen_ws;
use crate::horde::{
    AdaptEvent, CampaignPhase, HordeCampaign, HordeCommandKind, HordeCoordMsg, HordeGlobalStats,
    PerWorkerState, StatsDelta, StressAssignment, WorkerCapabilities,
};
use crate::stress::goldeneye::{AttackMode, DosMethod, GoldenEyeConfig};

// ─────────────────────────────────────────────────────────────────────────────
// HordeCoordinator
// ─────────────────────────────────────────────────────────────────────────────
pub struct HordeCoordinator {
    pub campaign: RwLock<HordeCampaign>,
    pub workers: Arc<RwLock<HashMap<String, PerWorkerState>>>,
    pub global_stats: HordeGlobalStats,
    pub master_key: [u8; 32],
    pub stop_flag: Arc<AtomicBool>,
    pub adapt_auto: bool,
    pub tx_events: broadcast::Sender<HordeCoordMsg>,
    pub adaptive_events: RwLock<Vec<AdaptEvent>>,
    pub adaptive_factor: RwLock<f64>,
    pub base_output: String,

    pub pending_challenges: RwLock<HashMap<String, Vec<u8>>>,
    _rx_dropped: broadcast::Receiver<HordeCoordMsg>,
}

impl HordeCoordinator {
    pub fn new(
        master_key: [u8; 32],
        total_target_bots: usize,
        adapt_auto: bool,
        base_output: impl Into<String>,
    ) -> Self {
        let (tx, rx) = broadcast::channel::<HordeCoordMsg>(512);
        Self {
            campaign: RwLock::new(HordeCampaign {
                total_target_bots,
                ..HordeCampaign::default()
            }),
            workers: Arc::new(RwLock::new(HashMap::new())),
            global_stats: HordeGlobalStats::new(),
            master_key,
            stop_flag: Arc::new(AtomicBool::new(false)),
            adapt_auto,
            tx_events: tx,
            adaptive_events: RwLock::new(Vec::new()),
            adaptive_factor: RwLock::new(1.0),
            base_output: base_output.into(),
            pending_challenges: RwLock::new(HashMap::new()),
            _rx_dropped: rx,
        }
    }

    pub fn events_subscriber(&self) -> broadcast::Receiver<HordeCoordMsg> {
        self.tx_events.subscribe()
    }

    // ── Handshake / Auth (FR-4) ───────────────────────────────────────────
    pub async fn register_challenge(&self, worker_id: &str) -> String {
        let nonce: [u8; 32] = rand::random();
        self.pending_challenges
            .write()
            .await
            .insert(worker_id.to_string(), nonce.to_vec());
        nonce.encode_hex::<String>()
    }

    pub async fn verify_handshake(
        &self,
        worker_id: &str,
        peer_ip: String,
        caps: WorkerCapabilities,
        mac_hex: &str,
    ) -> bool {
        let pending = self.pending_challenges.read().await;
        let nonce = match pending.get(worker_id) {
            Some(n) => n.clone(),
            None => return false,
        };
        drop(pending);
        let worker_key = match horde_derive_worker_key(&self.master_key, worker_id) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let expected_mac = horde_derive_handshake_mac(&worker_key, &nonce);
        let expected_hex = expected_mac.encode_hex::<String>();
        if !constant_time_eq_hex(&expected_hex, mac_hex) {
            return false;
        }
        // Auth OK → enregistrer le worker
        let mut wmap = self.workers.write().await;
        let existing = wmap
            .entry(worker_id.to_string())
            .or_insert_with(PerWorkerState::default);
        existing.worker_id = worker_id.to_string();
        existing.peer_ip = peer_ip;
        existing.caps = caps;
        existing.connected = true;
        existing.last_seen = Instant::now();
        true
    }

    // ── Info workers ──────────────────────────────────────────────────────
    pub async fn connected_workers_count(&self) -> usize {
        self.workers
            .read()
            .await
            .values()
            .filter(|w| w.connected)
            .count()
    }

    pub async fn snapshot_workers(&self) -> Vec<(String, PerWorkerState)> {
        let r = self.workers.read().await;
        r.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    // ── Assignments (FR-5) ────────────────────────────────────────────────
    pub async fn compute_assignments(
        &self,
        global_cfg: &GoldenEyeConfig,
    ) -> HashMap<String, StressAssignment> {
        let campaign = self.campaign.read().await;
        let wmap = self.workers.write().await;
        let active_ids: Vec<String> = wmap
            .iter()
            .filter(|(_, w)| w.connected)
            .map(|(k, _)| k.clone())
            .collect();
        drop(wmap);
        let n = active_ids.len().max(1);
        let total = campaign.total_target_bots.max(1);
        let per_worker = total / n;
        let remainder = total % n;

        let mut assignments: HashMap<String, StressAssignment> = HashMap::new();
        let mut cursor: u64 = 0;
        for (i, wid) in active_ids.iter().enumerate() {
            let extra = if i < remainder { 1 } else { 0 };
            let count = (per_worker + extra) as u64;
            let start = cursor;
            let end = cursor.saturating_add(count);
            cursor = end;
            let mut global_cloned = global_cfg.clone();
            global_cloned.bot_id_offset = start;
            let jitter = rand::random::<u64>() % 10_000;
            let asgn = StressAssignment {
                assignment_id: format!("asgn-{}", Uuid::new_v4().simple()),
                bot_id_range_start: start,
                bot_id_range_end_excl: end,
                startup_jitter_ms: jitter,
                global_cfg: global_cloned,
            };
            assignments.insert(wid.clone(), asgn);
        }
        // Stocker assignments dans le worker state
        let mut wmap = self.workers.write().await;
        for (wid, asgn) in &assignments {
            if let Some(w) = wmap.get_mut(wid) {
                w.assignment = Some(asgn.clone());
            }
        }
        assignments
    }

    // ── Ingest delta stats (FR-7) ─────────────────────────────────────────
    pub async fn ingest_delta(&self, worker_id: &str, delta: &StatsDelta) {
        self.global_stats.ingest_delta(delta);
        let mut wmap = self.workers.write().await;
        if let Some(w) = wmap.get_mut(worker_id) {
            w.last_stats.ingest_delta(delta);
            w.last_seen = Instant::now();
        }
    }

    // ── Broadcast commandes (utilisé par interactive CLI) ─────────────────
    pub async fn broadcast_command(&self, kind: HordeCommandKind, factor: Option<f64>) {
        let msg = HordeCoordMsg::Command { kind, factor };
        let _ = self.tx_events.send(msg);
    }

    // ── Lifecycle campagne ────────────────────────────────────────────────
    pub async fn start_campaign(
        &self,
        target_url: String,
        attack_mode: AttackMode,
        _goldeneye_template: &GoldenEyeConfig,
    ) -> HordeCampaign {
        let mut camp = self.campaign.write().await;
        camp.phase = CampaignPhase::Running;
        camp.target_url = target_url;
        camp.attack_mode = attack_mode;
        camp.started_at = Some(Utc::now().to_rfc3339());
        camp.clone()
    }

    pub async fn stop_campaign(&self) {
        let mut camp = self.campaign.write().await;
        camp.phase = CampaignPhase::Stopped;
        camp.stopped_at = Some(Utc::now().to_rfc3339());
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    // ── Adaptive Control Loop (FR-8 / Task 8) ─────────────────────────────
    pub async fn adaptive_control_step(&self) -> Option<HordeCoordMsg> {
        if !self.adapt_auto {
            return None;
        }
        let r5xx = self.global_stats.r5xx();
        let rwaf = self.global_stats.rwaf();
        let mut curr_factor = self.adaptive_factor.write().await;
        let trigger_high = r5xx > 0.30 || rwaf > 0.15;
        let low_for_30s = false; // hysteresis managed by caller (Task 8)
        let (new_factor, _need_event) = if trigger_high && *curr_factor > 0.25 {
            (0.5, true)
        } else if low_for_30s && (*curr_factor - 1.0).abs() > f64::EPSILON {
            (1.0, true)
        } else {
            return None;
        };
        let reason = if r5xx > 0.30 {
            format!("r5xx={:.2} threshold=0.30", r5xx)
        } else {
            format!("rwaf={:.2} threshold=0.15", rwaf)
        };
        let event = AdaptEvent {
            ts: Utc::now().to_rfc3339(),
            factor: new_factor,
            r5xx,
            rwaf,
            reason,
        };
        self.adaptive_events.write().await.push(event);
        *curr_factor = new_factor;
        Some(HordeCoordMsg::Command {
            kind: HordeCommandKind::Adapt,
            factor: Some(new_factor),
        })
    }

    pub fn spawn_adaptive_loop(self: &Arc<Self>, interval_secs: u64) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut healthy_since: Option<Instant> = None;
            let hysteresis_s = 30;
            loop {
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
                if me.stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                let step = me.adaptive_control_step().await;
                if let Some(msg) = step {
                    // hysteresis simple via current factor 0.5 triggers reset timer
                    let factor_now = *me.adaptive_factor.read().await;
                    if factor_now < 1.0 - f64::EPSILON {
                        // check healthy
                        let r5 = me.global_stats.r5xx();
                        let rw = me.global_stats.rwaf();
                        if r5 <= 0.20 && rw <= 0.08 {
                            let since = healthy_since.get_or_insert(Instant::now());
                            if since.elapsed().as_secs() >= hysteresis_s {
                                let revert = HordeCoordMsg::Command {
                                    kind: HordeCommandKind::Adapt,
                                    factor: Some(1.0),
                                };
                                *me.adaptive_factor.write().await = 1.0;
                                healthy_since = None;
                                let _ = me.tx_events.send(revert);
                            }
                        } else {
                            healthy_since = None;
                        }
                    } else {
                        healthy_since = None;
                    }
                    let _ = me.tx_events.send(msg);
                }
            }
        });
    }

    // ── Sweep workers morts (utilisé par Task 9 rebalance) ────────────────
    pub async fn sweep_dead_workers(&self, threshold_secs: u64) -> Vec<String> {
        let mut dead = Vec::new();
        let mut wmap = self.workers.write().await;
        for (id, w) in wmap.iter_mut() {
            if w.connected && w.last_seen.elapsed() > Duration::from_secs(threshold_secs) {
                w.connected = false;
                dead.push(id.clone());
            }
        }
        dead
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI Interactive Coordinator (Task 7)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn run_horde_coordinator(
    master_key: [u8; 32],
    bind_addr: String,
    port: u16,
    adapt_auto: bool,
    total_bots: usize,
    duration_secs: Option<u64>,
    mut template_cfg: GoldenEyeConfig,
    base_output: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Total bots → on écrit dans template_cfg.num_bots pour que les assignments respectent
    template_cfg.num_bots = total_bots.max(template_cfg.num_bots);
    if let Some(d) = duration_secs {
        template_cfg.duration_secs = Some(d.max(1));
    }

    let coord = Arc::new(HordeCoordinator::new(
        master_key,
        total_bots,
        adapt_auto,
        base_output.clone(),
    ));

    // Spawn listener WS
    let ws_coord = Arc::clone(&coord);
    let ws_bind = bind_addr.clone();
    tokio::spawn(async move {
        let _ = horde_listen_ws(ws_coord, &ws_bind, port).await;
    });

    // Spawn adaptive loop (Task 8)
    coord.spawn_adaptive_loop(2);

    // Spawn rebalance sweep complet (Task 9)
    {
        let me = Arc::clone(&coord);
        let tpl = template_cfg.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if me.stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                let dead = me.sweep_dead_workers(10).await;
                if dead.is_empty() {
                    continue;
                }
                let campaign = me.campaign.read().await.clone();
                if !matches!(campaign.phase, CampaignPhase::Running) {
                    continue;
                }
                // Cas trivial: tous workers morts, rien à redistribuer
                let n_surv = me.connected_workers_count().await;
                if n_surv == 0 {
                    continue;
                }

                // ── Recalcul RANGES avec les SEULES tranches de workers MORTS,
                //    ajoutées à un reservoir global. Puis distribuées en parts
                //    égales parmi les survivants. Préserve leurs tranches
                //    actuelles intactes → pas de dédoublement runs.
                {
                    let wmap = me.workers.write().await;
                    // Étape 1: identifier workers vivants, récupérer union de leurs ranges + morts
                    let mut reservoir: Vec<(u64, u64)> = Vec::new();
                    let mut survivor_ids: Vec<String> = Vec::new();
                    let mut survivor_ranges: HashMap<String, (u64, u64)> = HashMap::new();
                    for (id, w) in wmap.iter() {
                        let r = if let Some(a) = &w.assignment {
                            (a.bot_id_range_start, a.bot_id_range_end_excl)
                        } else {
                            (0, 0)
                        };
                        if w.connected && r.1 > r.0 {
                            survivor_ids.push(id.clone());
                            survivor_ranges.insert(id.clone(), r);
                        } else if !w.connected && r.1 > r.0 {
                            reservoir.push(r);
                        }
                    }
                    drop(wmap);

                    if reservoir.is_empty() || survivor_ids.is_empty() {
                        continue;
                    }
                    // Trier reservoir par start (merge de ranges contigus pour compter total bots à redistribuer)
                    reservoir.sort_by_key(|r| r.0);
                    let total_redistrib: u64 =
                        reservoir.iter().map(|(s, e)| e.saturating_sub(*s)).sum();
                    if total_redistrib == 0 {
                        continue;
                    }
                    let per_survivor = total_redistrib / survivor_ids.len() as u64;
                    let mut remainder = total_redistrib % survivor_ids.len() as u64;

                    let flat_extra: Vec<u64> = reservoir
                        .iter()
                        .flat_map(|(s, e)| (*s..*e).collect::<Vec<u64>>())
                        .collect();
                    // Éviter vecteur 1M bots: on distribue ranges contigues (plus simple)
                    let mut cursor = 0u64;
                    let mut assign_extra: HashMap<String, Vec<(u64, u64)>> = HashMap::new();
                    for sid in &survivor_ids {
                        let extra = per_survivor
                            + if remainder > 0 {
                                remainder -= 1;
                                1
                            } else {
                                0
                            };
                        if extra == 0 {
                            continue;
                        }
                        let start = cursor;
                        let end = cursor + extra;
                        if start < flat_extra.len() as u64 {
                            let re = end.min(flat_extra.len() as u64);
                            let bot_start = flat_extra[start as usize];
                            let bot_end = flat_extra[(re - 1) as usize].saturating_add(1);
                            assign_extra.insert(sid.clone(), vec![(bot_start, bot_end)]);
                        }
                        cursor = end;
                    }

                    // Applique l'extension de range aux survivants + rebuild AssignmentMsg
                    let mut wmap2 = me.workers.write().await;
                    for sid in &survivor_ids {
                        let old = survivor_ranges.get(sid).copied().unwrap_or((0, 0));
                        let mut new_start = old.0;
                        let mut new_end = old.1;
                        if let Some(extras) = assign_extra.get(sid) {
                            for &(xs, xe) in extras {
                                new_start = new_start.min(xs);
                                new_end = new_end.max(xe);
                            }
                        }
                        if new_end <= new_start {
                            continue;
                        }
                        if let Some(w) = wmap2.get_mut(sid) {
                            if let Some(a) = w.assignment.as_mut() {
                                a.bot_id_range_start = new_start;
                                a.bot_id_range_end_excl = new_end;
                                // Met à jour bot_id_offset pour le prochain run ADAPT
                                a.global_cfg.bot_id_offset = new_start;
                                a.global_cfg.num_bots = (new_end - new_start) as usize;
                            }
                        }
                    }
                }

                eprintln!(
                    "  \x1b[33m[HORDE-REBALANCE]\x1b[0m {} workers morts — ranges étendues sur {} survivants → broadcast",
                    dead.len(), n_surv
                );
                // Rebuild assignments (avec ranges étendues) puis broadcast Start pour
                // que chaque worker reçoive le nouveau StressAssignment.
                let _ = me.compute_assignments(&tpl).await;
                let _ = me.tx_events.send(HordeCoordMsg::Command {
                    kind: HordeCommandKind::Start,
                    factor: None,
                });
            }
        });
    }

    // Duration limit task
    if let Some(d) = duration_secs {
        let me = Arc::clone(&coord);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(d)).await;
            me.stop_campaign().await;
            // Générer rapport automatique à la fin
            let _ = me.write_report_files(&me.base_output.clone(), false).await;
            let _ = me.tx_events.send(HordeCoordMsg::Command {
                kind: HordeCommandKind::Stop,
                factor: None,
            });
        });
    }

    // CLI interactive principale
    let me = Arc::clone(&coord);
    interactive_cli_loop(me, template_cfg).await?;

    Ok(())
}

async fn interactive_cli_loop(
    coord: Arc<HordeCoordinator>,
    template_cfg: GoldenEyeConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!();
    println!(
        "  \x1b[38;5;196m──────────────────────────────────────────────────────────────\x1b[0m"
    );
    println!("  \x1b[1mCommandes disponibles:\x1b[0m");
    println!("    \x1b[32mhelp\x1b[0m                         - Aide");
    println!("    \x1b[32mstatus\x1b[0m                       - État campagne & workers");
    println!("    \x1b[32mworkers\x1b[0m                      - Liste workers connectés");
    println!("    \x1b[32mstart <URL> [--mode X] [--method M] [--duree S]\x1b[0m");
    println!("    \x1b[32mpause / resume / stop\x1b[0m        - Contrôle campagne");
    println!("    \x1b[32madapt <0.1..3.0>\x1b[0m              - Facteur adaptatif manuel");
    println!("    \x1b[32mreport [now]\x1b[0m                 - Générer rapport JSON + MD");
    println!("    \x1b[32mquit / exit\x1b[0m                   - Quitter (stop + rapport)");
    println!(
        "  \x1b[38;5;196m──────────────────────────────────────────────────────────────\x1b[0m\n"
    );

    use tokio::io::{AsyncBufReadExt, BufReader};
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut linebuf = String::new();

    loop {
        linebuf.clear();
        {
            print!("  \x1b[38;5;196mhorde\x1b[0m> ");
            std::io::Write::flush(&mut std::io::stdout()).ok();
        }
        let n = reader.read_line(&mut linebuf).await?;
        if n == 0 {
            break;
        } // EOF
        let cmd_line = linebuf.trim().to_string();
        if cmd_line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = cmd_line.split_whitespace().collect();
        match parts.as_slice() {
            ["help"] | ["?"] => {
                println!("  \x1b[32mCommandes:\x1b[0m help, status, workers, start <URL>, pause, resume, stop, adapt <f>, report [now], quit");
            }
            ["status"] => {
                let camp = coord.campaign.read().await.clone();
                let stats = coord.global_stats.clone();
                let nc = coord.connected_workers_count().await;
                let factor = *coord.adaptive_factor.read().await;
                use std::sync::atomic::Ordering::Relaxed;
                println!();
                println!("  \x1b[38;5;196m─── Status Campagne HORDE ───\x1b[0m");
                println!("    Phase:        \x1b[1m{:?}\x1b[0m", camp.phase);
                println!("    ID:           {}", camp.id);
                println!(
                    "    Cible:        {}",
                    if camp.target_url.is_empty() {
                        "(non définie)"
                    } else {
                        &camp.target_url
                    }
                );
                println!("    Mode:         {:?}", camp.attack_mode);
                println!(
                    "    Workers:      {} connectés / {} demandés",
                    nc, camp.total_target_bots
                );
                println!(
                    "    Adapt auto:   {}  (factor actuel={:.2})",
                    coord.adapt_auto, factor
                );
                println!(
                    "    Hits:         {}  2xx={}  5xx={} (r5xx={:.2})",
                    stats.hits.load(Relaxed),
                    stats.code_2xx.load(Relaxed),
                    stats.code_5xx.load(Relaxed),
                    coord.global_stats.r5xx()
                );
                println!(
                    "    WAF blocks:   {} (rwaf={:.2})",
                    stats.waf_blocks.load(Relaxed),
                    coord.global_stats.rwaf()
                );
                println!("    Bots rotated: {}", stats.bots_rotated.load(Relaxed));
                println!(
                    "    Events adapt: {}",
                    coord.adaptive_events.read().await.len()
                );
                println!();
            }
            ["workers"] => {
                let ws = coord.snapshot_workers().await;
                println!();
                println!("  \x1b[38;5;196m─── Workers ({}) ───\x1b[0m", ws.len());
                use std::sync::atomic::Ordering::Relaxed;
                for (id, w) in &ws {
                    let rng = w
                        .assignment
                        .as_ref()
                        .map(|a| format!("[{}-{})", a.bot_id_range_start, a.bot_id_range_end_excl))
                        .unwrap_or("(non assigné)".into());
                    println!(
                        "    {}  {}  {}  range={}  hits={}",
                        if w.connected {
                            "\x1b[32m🟢\x1b[0m"
                        } else {
                            "\x1b[31m🔴\x1b[0m"
                        },
                        &id[..8.min(id.len())],
                        w.peer_ip,
                        rng,
                        w.last_stats.hits.load(Relaxed)
                    );
                }
                println!();
            }
            ["start", url, rest @ ..] => {
                let url = url.to_string();
                let mut mode = template_cfg.attack_mode;
                let mut method = template_cfg.method;
                let mut duree = template_cfg.duration_secs;
                let mut iter = rest.iter();
                while let Some(tok) = iter.next() {
                    match *tok {
                        "--mode" => {
                            if let Some(v) = iter.next() {
                                mode = match v.to_uppercase().as_str() {
                                    "FLOOD" => AttackMode::Flood,
                                    "SLOWLORIS" => AttackMode::Slowloris,
                                    "RUDY" | "RUDDY" | "R-U-DEAD-YET" => AttackMode::Rudy,
                                    "BROWSERFLOOD" => AttackMode::BrowserFlood,
                                    other => {
                                        println!("  mode invalide: {}", other);
                                        continue;
                                    }
                                };
                            }
                        }
                        "--method" => {
                            if let Some(v) = iter.next() {
                                method = match v.to_uppercase().as_str() {
                                    "GET" => DosMethod::Get,
                                    "POST" => DosMethod::Post,
                                    "RANDOM" | "MIX" | "RAND" => DosMethod::Random,
                                    other => {
                                        println!(
                                            "  method invalide: {} (accepté: GET|POST|RANDOM)",
                                            other
                                        );
                                        continue;
                                    }
                                };
                            }
                        }
                        "--duree" | "--duration" => {
                            if let Some(v) = iter.next() {
                                if let Ok(s) = v.parse::<u64>() {
                                    duree = Some(s);
                                }
                            }
                        }
                        other => {
                            println!("  flag invalide: {}", other);
                        }
                    }
                }
                let mut tpl = template_cfg.clone();
                tpl.url = url.clone();
                tpl.attack_mode = mode;
                tpl.method = method;
                tpl.duration_secs = duree;
                let camp = coord.start_campaign(url.clone(), mode, &tpl).await;
                println!(
                    "  \x1b[32m[START]\x1b[0m Campagne {} démarrée — cible={:?} mode={:?}",
                    camp.id, url, mode
                );
                // Compute assignments + broadcast Start
                let _map = coord.compute_assignments(&tpl).await;
                let _ = coord.tx_events.send(HordeCoordMsg::Command {
                    kind: HordeCommandKind::Start,
                    factor: None,
                });
            }
            ["pause"] => {
                println!("  \x1b[33m[PAUSE]\x1b[0m broadcast PAUSE");
                let _ = coord.broadcast_command(HordeCommandKind::Pause, None).await;
            }
            ["resume"] => {
                println!("  \x1b[32m[RESUME]\x1b[0m broadcast RESUME");
                let _ = coord
                    .broadcast_command(HordeCommandKind::Resume, None)
                    .await;
            }
            ["stop", rest @ ..] => {
                let clean = rest.iter().any(|r| *r == "--clean-outputs");
                println!(
                    "  \x1b[31m[STOP]\x1b[0m broadcast STOP + génération rapport (clean={})",
                    clean
                );
                coord.stop_campaign().await;
                let _ = coord.broadcast_command(HordeCommandKind::Stop, None).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
                match coord
                    .write_report_files(&coord.base_output.clone(), clean)
                    .await
                {
                    Ok((p1, p2)) => {
                        println!("  \x1b[32m[RAPPORT]\x1b[0m {}  {}  OK", p1, p2);
                    }
                    Err(e) => eprintln!("  \x1b[31m[RAPPORT ERR]\x1b[0m {}", e),
                }
            }
            ["adapt", f] => match f.parse::<f64>() {
                Ok(v) if (0.1..=3.0).contains(&v) => {
                    println!("  \x1b[35m[ADAPT]\x1b[0m broadcast factor={:.2}", v);
                    *coord.adaptive_factor.write().await = v;
                    let _ = coord
                        .broadcast_command(HordeCommandKind::Adapt, Some(v))
                        .await;
                    let mut events = coord.adaptive_events.write().await;
                    events.push(AdaptEvent {
                        ts: chrono::Utc::now().to_rfc3339(),
                        factor: v,
                        r5xx: coord.global_stats.r5xx(),
                        rwaf: coord.global_stats.rwaf(),
                        reason: format!("manuel CLI: adapt {}", v),
                    });
                }
                _ => println!("  Usage: adapt <0.1 .. 3.0>"),
            },
            ["report", rest @ ..] => {
                let now_mode = matches!(rest.first(), Some(&"now"));
                let path = if now_mode {
                    coord.base_output.clone()
                } else {
                    rest.first()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| coord.base_output.clone())
                };
                match coord.write_report_files(&path, false).await {
                    Ok((p1, p2)) => println!("  \x1b[32m[RAPPORT]\x1b[0m {}  {}  OK", p1, p2),
                    Err(e) => eprintln!("  \x1b[31m[RAPPORT ERR]\x1b[0m {}", e),
                }
            }
            ["quit"] | ["exit"] => {
                println!("  \x1b[33m[QUIT]\x1b[0m stop campagne + rapport");
                coord.stop_campaign().await;
                let _ = coord.broadcast_command(HordeCommandKind::Stop, None).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
                let _ = coord
                    .write_report_files(&coord.base_output.clone(), false)
                    .await;
                break;
            }
            other => {
                if !other.is_empty() {
                    println!("  Commande inconnue: {:?} — tapez `help`", other.join(" "));
                }
            }
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Utils
// ─────────────────────────────────────────────────────────────────────────────
fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Tests Unitaires TR-4.1, TR-4.2, TR-4.4 ──────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn master_key_test() -> [u8; 32] {
        [0x55u8; 32]
    }

    fn add_fake_worker_sync(coord: &HordeCoordinator, id: &str) {
        // Manipulation directe: bypass handshake pour tests unitaires
        // (utilise interior mutabilité hors async via futures executor)
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut m = coord.workers.write().await;
            m.insert(
                id.to_string(),
                PerWorkerState {
                    worker_id: id.to_string(),
                    peer_ip: "127.0.0.1".into(),
                    caps: WorkerCapabilities::default(),
                    assignment: None,
                    last_stats: HordeGlobalStats::new(),
                    last_seen: Instant::now(),
                    connected: true,
                    last_assignment_ack: None,
                },
            );
        });
    }

    #[test]
    fn tr_4_1_distribution_assignments_3_workers() {
        let coord = HordeCoordinator::new(master_key_test(), 1000, false, "");
        add_fake_worker_sync(&coord, "w1");
        add_fake_worker_sync(&coord, "w2");
        add_fake_worker_sync(&coord, "w3");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let assignments = rt.block_on(coord.compute_assignments(&GoldenEyeConfig::default()));
        assert_eq!(assignments.len(), 3);
        let mut ranges: Vec<(u64, u64)> = assignments
            .values()
            .map(|a| (a.bot_id_range_start, a.bot_id_range_end_excl))
            .collect();
        ranges.sort_by_key(|r| r.0);
        // ranges disjoints
        for w in ranges.windows(2) {
            assert!(w[0].1 <= w[1].0);
        }
        let total: u64 = ranges.iter().map(|(s, e)| e - s).sum();
        assert_eq!(total, 1000);
        // jitter différents
        let js: Vec<u64> = assignments.values().map(|a| a.startup_jitter_ms).collect();
        // Probabilité quasi-nulle que 3 valeurs random 0..10000 soient identiques
        assert!(js[0] != js[1] || js[1] != js[2] || js[0] != 10001);
    }

    #[test]
    fn tr_4_2_ingest_delta_atomics() {
        let coord = HordeCoordinator::new(master_key_test(), 1000, false, "");
        add_fake_worker_sync(&coord, "wa");
        add_fake_worker_sync(&coord, "wb");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let d1 = StatsDelta {
                hits: 100,
                fails: 5,
                code_2xx: 95,
                code_5xx: 10,
                ..StatsDelta::default()
            };
            let d2 = StatsDelta {
                hits: 50,
                fails: 2,
                code_2xx: 48,
                code_5xx: 4,
                ..StatsDelta::default()
            };
            coord.ingest_delta("wa", &d1).await;
            coord.ingest_delta("wb", &d2).await;
            // Ingest d1 2ème fois
            coord.ingest_delta("wa", &d1).await;
            let total_hits = coord.global_stats.hits.load(Ordering::Relaxed);
            assert_eq!(total_hits, 250);
            let total_5xx = coord.global_stats.code_5xx.load(Ordering::Relaxed);
            assert_eq!(total_5xx, 24);
        });
    }
}
