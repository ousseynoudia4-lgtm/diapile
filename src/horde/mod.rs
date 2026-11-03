//! DIAPILE HORDE — Infrastructure distribuée d'attaques volumétriques
//!
//! Coordinator + Workers distants orchestrant des bots GoldenEye v3.
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES CONTRACTUELLEMENT.

pub mod coordinator;
pub mod crypto;
pub mod report;
pub mod swarm;
pub mod transport;
pub mod worker;

pub use coordinator::*;
pub use crypto::*;
pub use report::*;
pub use swarm::*;
pub use transport::*;
pub use worker::*;

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

use crate::stress::goldeneye::{AttackMode, GoldenEyeConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Capacités déclarées par un worker au check-in
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    pub cpu_cores: usize,
    pub estimated_bw_mbps: u64,
    pub geohint: String,
    pub estimated_bot_capacity: usize,
}

impl Default for WorkerCapabilities {
    fn default() -> Self {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            cpu_cores: cores,
            estimated_bw_mbps: 100,
            geohint: "unknown".into(),
            estimated_bot_capacity: cores * 250,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StressAssignment : tranche de bots assignée à un worker
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressAssignment {
    pub assignment_id: String,
    pub bot_id_range_start: u64,
    pub bot_id_range_end_excl: u64,
    pub startup_jitter_ms: u64,
    pub global_cfg: GoldenEyeConfig,
}
impl StressAssignment {
    #[inline]
    pub fn num_bots(&self) -> usize {
        self.bot_id_range_end_excl
            .saturating_sub(self.bot_id_range_start)
            .max(0) as usize
    }
}
impl Default for StressAssignment {
    fn default() -> Self {
        Self {
            assignment_id: format!("asgn-{}", Uuid::new_v4().simple()),
            bot_id_range_start: 0,
            bot_id_range_end_excl: 0,
            startup_jitter_ms: 0,
            global_cfg: GoldenEyeConfig::default(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StatsDelta : incrément relatif envoyé par worker vers coordinator toutes 500ms
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct StatsDelta {
    pub window_ms: u64,
    pub hits: u64,
    pub fails: u64,
    pub code_2xx: u64,
    pub code_3xx: u64,
    pub code_4xx: u64,
    pub code_5xx: u64,
    pub waf_blocks: u64,
    pub bots_rotated: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// HordeGlobalStats : compteurs lock-free AtomicU64 (hard constraint)
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Default)]
pub struct HordeGlobalStats {
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
    pub rps_peak: Arc<AtomicU64>,
    pub start_ts: Option<Instant>,
}

impl HordeGlobalStats {
    pub fn new() -> Self {
        Self {
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
            rps_peak: Arc::new(AtomicU64::new(0)),
            start_ts: Some(Instant::now()),
        }
    }

    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.fails.load(Ordering::Relaxed),
        )
    }

    pub fn ingest_delta(&self, d: &StatsDelta) {
        self.hits.fetch_add(d.hits, Ordering::Relaxed);
        self.fails.fetch_add(d.fails, Ordering::Relaxed);
        self.code_2xx.fetch_add(d.code_2xx, Ordering::Relaxed);
        self.code_3xx.fetch_add(d.code_3xx, Ordering::Relaxed);
        self.code_4xx.fetch_add(d.code_4xx, Ordering::Relaxed);
        self.code_5xx.fetch_add(d.code_5xx, Ordering::Relaxed);
        self.waf_blocks.fetch_add(d.waf_blocks, Ordering::Relaxed);
        self.bots_rotated
            .fetch_add(d.bots_rotated, Ordering::Relaxed);
        self.bytes_sent.fetch_add(d.bytes_sent, Ordering::Relaxed);
        self.bytes_recv.fetch_add(d.bytes_recv, Ordering::Relaxed);
        // Mise à jour du pic de RPS
        if d.window_ms > 0 {
            let rps = d.hits * 1000 / d.window_ms.max(1);
            let current_peak = self.rps_peak.load(Ordering::Relaxed);
            if rps > current_peak {
                self.rps_peak.store(rps, Ordering::Relaxed);
            }
        }
    }

    pub fn r5xx(&self) -> f64 {
        let c5 = self.code_5xx.load(Ordering::Relaxed);
        let c2 = self.code_2xx.load(Ordering::Relaxed);
        let c3 = self.code_3xx.load(Ordering::Relaxed);
        let c4 = self.code_4xx.load(Ordering::Relaxed);
        let total = c2 + c3 + c4 + c5 + 1;
        c5 as f64 / total as f64
    }

    pub fn rwaf(&self) -> f64 {
        let w = self.waf_blocks.load(Ordering::Relaxed);
        let h = self.hits.load(Ordering::Relaxed);
        w as f64 / (h + 1) as f64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Campagne HORDE (meta)
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CampaignPhase {
    Pending,
    Running,
    Paused,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HordeCampaign {
    pub id: String,
    pub target_url: String,
    pub attack_mode: AttackMode,
    pub total_target_bots: usize,
    pub phase: CampaignPhase,
    pub created_at: String,
    pub started_at: Option<String>,
    pub stopped_at: Option<String>,
}

impl Default for HordeCampaign {
    fn default() -> Self {
        Self {
            id: format!("horde-{}", Uuid::new_v4().simple()),
            target_url: String::new(),
            attack_mode: AttackMode::Flood,
            total_target_bots: 1000,
            phase: CampaignPhase::Pending,
            created_at: chrono::Utc::now().to_rfc3339(),
            started_at: None,
            stopped_at: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PerWorkerState : état d'un worker côté coordinator
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct PerWorkerState {
    pub worker_id: String,
    pub peer_ip: String,
    pub caps: WorkerCapabilities,
    pub assignment: Option<StressAssignment>,
    pub last_stats: HordeGlobalStats,
    pub last_seen: Instant,
    pub connected: bool,
    pub last_assignment_ack: Option<String>,
}

impl Default for PerWorkerState {
    fn default() -> Self {
        Self {
            worker_id: String::new(),
            peer_ip: String::new(),
            caps: WorkerCapabilities::default(),
            assignment: None,
            last_stats: HordeGlobalStats::new(),
            last_seen: Instant::now(),
            connected: false,
            last_assignment_ack: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AdaptEvent : événement adaptatif pour rapport final
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptEvent {
    pub ts: String,
    pub factor: f64,
    pub r5xx: f64,
    pub rwaf: f64,
    pub reason: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocole HORDE — messages Worker → Coordinator
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HordeWorkerMsg {
    Handshake {
        worker_id: String,
        hmac: String,
        caps: WorkerCapabilities,
    },
    Checkin {
        caps: WorkerCapabilities,
    },
    StatsDeltaBox {
        delta: StatsDelta,
    },
    Ack {
        assignment_id: String,
    },
    Ping {
        ts: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocole HORDE — messages Coordinator → Worker
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HordeCoordMsg {
    Challenge {
        nonce_hex: String,
    },
    AssignmentMsg {
        assignment: StressAssignment,
    },
    Command {
        #[serde(rename = "cmd")]
        kind: HordeCommandKind,
        factor: Option<f64>,
    },
    ReportAck,
    Idle,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HordeCommandKind {
    Start,
    Pause,
    Resume,
    Stop,
    Adapt,
}
