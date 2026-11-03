//! HORDE — Générateur de rapports
//!
//! Deux formats produits à l'arrêt de campagne (ou `report now` CLI):
//!   - `goldeneye.horde.json` : structuré, 10 compteurs globaux + per-worker + events adapt
//!   - `goldeneye.horde.md`   : heatmap emoji + tableau markdown + analyse

#![allow(dead_code)]

use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::horde::coordinator::HordeCoordinator;
use crate::horde::{AdaptEvent, CampaignPhase, HordeCampaign, HordeGlobalStats, PerWorkerState};

// ─────────────────────────────────────────────────────────────────────────────
// Report structuré JSON
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HordeReportJson {
    pub campaign_id: String,
    pub target_url: String,
    pub attack_mode: String,
    pub phase: CampaignPhase,
    pub started_at: Option<String>,
    pub stopped_at: Option<String>,
    pub duration_secs: Option<f64>,
    pub total_target_bots: usize,
    pub global_stats: GlobalStatsJson,
    pub per_worker: Vec<PerWorkerReport>,
    pub adaptive_events: Vec<AdaptEvent>,
    pub r5xx_ratio: f64,
    pub rwaf_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalStatsJson {
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
    pub rps_peak: u64,
}

impl GlobalStatsJson {
    fn from_horde(s: &HordeGlobalStats) -> Self {
        let rlx = Ordering::Relaxed;
        Self {
            hits: s.hits.load(rlx),
            fails: s.fails.load(rlx),
            code_2xx: s.code_2xx.load(rlx),
            code_3xx: s.code_3xx.load(rlx),
            code_4xx: s.code_4xx.load(rlx),
            code_5xx: s.code_5xx.load(rlx),
            waf_blocks: s.waf_blocks.load(rlx),
            bots_rotated: s.bots_rotated.load(rlx),
            bytes_sent: s.bytes_sent.load(rlx),
            bytes_recv: s.bytes_recv.load(rlx),
            rps_peak: s.rps_peak.load(rlx),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerWorkerReport {
    pub worker_id: String,
    pub peer_ip: String,
    pub cpu_cores: u8,
    pub connected: bool,
    pub range_start: u64,
    pub range_end: u64,
    pub range_count: u64,
    pub hits: u64,
    pub code_5xx: u64,
    pub waf_blocks: u64,
    pub efficiency: f64, // hits / (expected if even split)
    pub efficiency_grade: String,
}

impl PerWorkerReport {
    fn from_state(state: &PerWorkerState, expected_hits_per_bot: f64) -> Self {
        use Ordering::Relaxed;
        let last = &state.last_stats;
        let hits = last.hits.load(Relaxed);
        let range_count = state
            .assignment
            .as_ref()
            .map(|a| a.bot_id_range_end_excl.saturating_sub(a.bot_id_range_start))
            .unwrap_or(0);
        let expected = if expected_hits_per_bot > 0.0 {
            expected_hits_per_bot * range_count.max(1) as f64
        } else {
            1.0
        };
        let efficiency = hits as f64 / expected;
        let grade = if efficiency >= 1.1 {
            "A".into()
        } else if efficiency >= 0.9 {
            "B".into()
        } else if efficiency >= 0.7 {
            "C".into()
        } else if efficiency >= 0.4 {
            "D".into()
        } else {
            "F".into()
        };
        Self {
            worker_id: state.worker_id.clone(),
            peer_ip: state.peer_ip.clone(),
            cpu_cores: state.caps.cpu_cores as u8,
            connected: state.connected,
            range_start: state
                .assignment
                .as_ref()
                .map(|a| a.bot_id_range_start)
                .unwrap_or(0),
            range_end: state
                .assignment
                .as_ref()
                .map(|a| a.bot_id_range_end_excl)
                .unwrap_or(0),
            range_count,
            hits,
            code_5xx: last.code_5xx.load(Relaxed),
            waf_blocks: last.waf_blocks.load(Relaxed),
            efficiency,
            efficiency_grade: grade,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fonctions publiques
// ─────────────────────────────────────────────────────────────────────────────
impl HordeCoordinator {
    pub async fn generate_report_json(&self) -> HordeReportJson {
        let campaign = self.campaign.read().await.clone();
        let global = GlobalStatsJson::from_horde(&self.global_stats);
        let workers_snap = self.workers.read().await;
        let total_range_bots: u64 = workers_snap
            .values()
            .filter_map(|w| {
                w.assignment
                    .as_ref()
                    .map(|a| a.bot_id_range_end_excl.saturating_sub(a.bot_id_range_start))
            })
            .sum::<u64>()
            .max(1);
        let expected_hits_per_bot = global.hits as f64 / total_range_bots as f64;
        let mut per_worker: Vec<PerWorkerReport> = workers_snap
            .values()
            .map(|w| PerWorkerReport::from_state(w, expected_hits_per_bot))
            .collect();
        per_worker.sort_by(|a, b| {
            b.hits
                .partial_cmp(&a.hits)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        drop(workers_snap);

        let duration = match (campaign.started_at.as_ref(), campaign.stopped_at.as_ref()) {
            (Some(s), Some(e)) => {
                if let (Ok(a), Ok(b)) = (
                    DateTime::parse_from_rfc3339(s),
                    DateTime::parse_from_rfc3339(e),
                ) {
                    let dur = b - a;
                    Some(dur.num_milliseconds() as f64 / 1000.0)
                } else {
                    None
                }
            }
            (Some(s), None) => {
                if let Ok(a) = DateTime::parse_from_rfc3339(s) {
                    let b = Utc::now();
                    let dur = b.signed_duration_since(a.with_timezone(&Utc));
                    Some(dur.num_milliseconds() as f64 / 1000.0)
                } else {
                    None
                }
            }
            _ => None,
        };

        HordeReportJson {
            campaign_id: campaign.id.clone(),
            target_url: campaign.target_url.clone(),
            attack_mode: format!("{:?}", campaign.attack_mode),
            phase: campaign.phase,
            started_at: campaign.started_at.clone(),
            stopped_at: campaign.stopped_at.clone(),
            duration_secs: duration,
            total_target_bots: campaign.total_target_bots,
            r5xx_ratio: self.global_stats.r5xx(),
            rwaf_ratio: self.global_stats.rwaf(),
            global_stats: global,
            per_worker,
            adaptive_events: self.adaptive_events.read().await.clone(),
        }
    }

    pub async fn generate_report_md(&self, report: &HordeReportJson) -> String {
        let mut md = String::new();
        md.push_str(&format!("# Rapport HORDE — {}\n\n", report.campaign_id));
        md.push_str(&format!("**Cible**: `{}`  \n", report.target_url));
        md.push_str(&format!("**Mode**: `{}`  \n", report.attack_mode));
        md.push_str(&format!("**Phase**: `{:?}`  \n", report.phase));
        if let Some(s) = &report.started_at {
            md.push_str(&format!("**Démarré**: {}\n", s));
        }
        if let Some(s) = &report.stopped_at {
            md.push_str(&format!("**Terminé**: {}\n", s));
        }
        if let Some(d) = report.duration_secs {
            md.push_str(&format!("**Durée**: {:.2} s  \n", d));
        }
        md.push_str(&format!(
            "**Bots ciblés**: {}  \n\n",
            report.total_target_bots
        ));

        // KPIs
        md.push_str("## KPIs globaux\n\n");
        let r5 = report.r5xx_ratio;
        let rw = report.rwaf_ratio;
        let overall = format!(
            "| KPI | Valeur |\n|---|---|\n\
             | Requêtes (hits) | {} |\n\
             | Échecs | {} |\n\
             | Code 2xx | {} |\n\
             | Code 5xx | {} (ratio {:.2}%) |\n\
             | WAF blocks | {} (ratio {:.2}%) |\n\
             | Bots rotated | {} |\n\
             | Trafic (envoi) | {} MB |\n\
             | Trafic (réception) | {} MB |\n\
             | RPS pic | {} |\n\n",
            report.global_stats.hits,
            report.global_stats.fails,
            report.global_stats.code_2xx,
            report.global_stats.code_5xx,
            r5 * 100.0,
            report.global_stats.waf_blocks,
            rw * 100.0,
            report.global_stats.bots_rotated,
            report.global_stats.bytes_sent / 1024 / 1024,
            report.global_stats.bytes_recv / 1024 / 1024,
            report.global_stats.rps_peak,
        );
        md.push_str(&overall);

        // Heatmap workers
        md.push_str("## Workers — heatmap efficacité\n\n");
        md.push_str("```\n");
        for w in &report.per_worker {
            let heat = match w.efficiency_grade.as_str() {
                "A" => "🔥🔥🔥",
                "B" => "🔥🔥",
                "C" => "🔥",
                "D" => "▫️",
                _ => "❄️",
            };
            let status = if w.connected { "🟢" } else { "🔴" };
            md.push_str(&format!(
                "{} {:<8} [{}-{:<8}] {} hits={:<8} grade={:<2} {}\n",
                status,
                &w.worker_id[..8.min(w.worker_id.len())],
                w.range_start,
                w.range_end,
                heat,
                w.hits,
                w.efficiency_grade,
                w.peer_ip
            ));
        }
        md.push_str("```\n\n");

        // Table workers
        md.push_str("## Détail workers\n\n");
        md.push_str("| Worker | IP | Range | Hits | 5xx | WAF | Efficacité | Grade |\n|---|---|---|---|---|---|---|---|\n");
        for w in &report.per_worker {
            md.push_str(&format!(
                "| {} | {} | [{}-{}] | {} | {} | {} | {:.2} | {} |\n",
                &w.worker_id[..8.min(w.worker_id.len())],
                w.peer_ip,
                w.range_start,
                w.range_end,
                w.hits,
                w.code_5xx,
                w.waf_blocks,
                w.efficiency,
                w.efficiency_grade,
            ));
        }
        md.push('\n');

        // Adaptive events
        md.push_str("## Événements adaptatifs\n\n");
        if report.adaptive_events.is_empty() {
            md.push_str("_Aucun événement adaptatif déclenché (seuils r5xx/rwaf non atteints)._\n");
        } else {
            md.push_str("| Timestamp | Factor | r5xx | rwaf | Cause |\n|---|---|---|---|---|\n");
            for e in &report.adaptive_events {
                md.push_str(&format!(
                    "| {} | {:.2} | {:.2} | {:.2} | {} |\n",
                    e.ts, e.factor, e.r5xx, e.rwaf, e.reason
                ));
            }
        }

        md.push_str("\n---\n\n*Rapport généré par DIAPILE HORDE Coordinator v3*\n");
        md
    }

    pub async fn write_report_files(
        &self,
        base_output: &str,
        clean_outputs: bool,
    ) -> Result<(String, String)> {
        let json = self.generate_report_json().await;
        let md = self.generate_report_md(&json).await;
        let path_json = format!(
            "{}.goldeneye.horde.json",
            base_output.trim_end_matches('/').trim_end_matches('.')
        );
        let path_md = format!(
            "{}.goldeneye.horde.md",
            base_output.trim_end_matches('/').trim_end_matches('.')
        );
        let json_str = serde_json::to_string_pretty(&json).context("serialise rapport json")?;
        {
            let mut f = fs::File::create(&path_json)
                .await
                .with_context(|| format!("create {}", path_json))?;
            f.write_all(json_str.as_bytes()).await?;
            f.sync_all().await?;
        }
        {
            let mut f = fs::File::create(&path_md)
                .await
                .with_context(|| format!("create {}", path_md))?;
            f.write_all(md.as_bytes()).await?;
            f.sync_all().await?;
        }
        if clean_outputs {
            // Wipe optionnel 3 passes des fichiers sensibles
            let _ = secure_wipe(&path_json).await;
            let _ = secure_wipe(&path_md).await;
        }
        Ok((path_json, path_md))
    }
}

async fn secure_wipe(path: &str) -> Result<()> {
    use std::io::SeekFrom;
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    let meta = fs::metadata(path).await?;
    let size = meta.len() as usize;
    if size == 0 {
        return Ok(());
    }
    let mut f = fs::OpenOptions::new().write(true).open(path).await?;
    for pass in 0u8..3 {
        f.seek(SeekFrom::Start(0)).await?;
        let buf: Vec<u8> = match pass {
            0 => vec![0x00u8; size],
            1 => vec![0xFFu8; size],
            _ => (0..size).map(|_| rand::random::<u8>()).collect(),
        };
        f.write_all(&buf).await?;
        f.sync_all().await?;
    }
    drop(f);
    fs::remove_file(path).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests TR-10.1, TR-10.2
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::stress::goldeneye::GoldenEyeConfig;

    fn fake_coord() -> Arc<HordeCoordinator> {
        let coord = HordeCoordinator::new([0x11; 32], 1000, false, "./test");
        // Simuler 2 workers connectés + stats
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut wmap = coord.workers.write().await;
            let mk_state = |id: &str, hits: u64, waf: u64, range: (u64, u64)| -> PerWorkerState {
                let mut st = PerWorkerState::default();
                st.worker_id = id.into();
                st.connected = true;
                st.caps = crate::horde::WorkerCapabilities::default();
                st.assignment = Some(crate::horde::StressAssignment {
                    assignment_id: format!("a-{}", id),
                    bot_id_range_start: range.0,
                    bot_id_range_end_excl: range.1,
                    startup_jitter_ms: 500,
                    global_cfg: GoldenEyeConfig::default(),
                });
                st.last_stats.hits.store(hits, Ordering::Relaxed);
                st.last_stats.waf_blocks.store(waf, Ordering::Relaxed);
                st.last_stats.code_5xx.store(hits / 10, Ordering::Relaxed);
                st
            };
            wmap.insert("w1".into(), mk_state("w1", 50_000, 200, (0, 500)));
            wmap.insert("w2".into(), mk_state("w2", 40_000, 100, (500, 1000)));
            drop(wmap);
            // Alimenter stats globales
            let d = crate::horde::StatsDelta {
                hits: 90_000,
                fails: 1200,
                code_5xx: 9_000,
                waf_blocks: 300,
                ..crate::horde::StatsDelta::default()
            };
            coord.global_stats.ingest_delta(&d);
        });
        Arc::new(coord)
    }

    #[test]
    fn tr_10_1_report_json_sum_equals_global() {
        let coord = fake_coord();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let r = rt.block_on(coord.generate_report_json());
        let sum_hits: u64 = r.per_worker.iter().map(|w| w.hits).sum();
        assert_eq!(sum_hits, r.global_stats.hits);
        let sum_waf: u64 = r.per_worker.iter().map(|w| w.waf_blocks).sum();
        assert_eq!(sum_waf, r.global_stats.waf_blocks);
    }

    #[test]
    fn tr_10_2_report_md_has_heading_and_markdown_table() {
        let coord = fake_coord();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (r, md) = rt.block_on(async {
            let r = coord.generate_report_json().await;
            let md = coord.generate_report_md(&r).await;
            (r, md)
        });
        assert!(md.starts_with("# Rapport HORDE —"));
        assert!(md.contains("## Détail workers"));
        // Table markdown: ligne d'entête + séparateur + 2 workers
        let lines_with_pipe: Vec<&str> = md.lines().filter(|l| l.starts_with('|')).collect();
        // 2 header lines + N worker lines + adaptive events (if any)
        assert!(lines_with_pipe.len() >= 4, "got {}", lines_with_pipe.len());
    }
}
