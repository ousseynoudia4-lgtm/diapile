//! DIAPILE — Reporting Agent
//!
//! Agent dédié à la production du rapport. Il reçoit une **vue en lecture
//! seule** de la mémoire de campagne : il ne peut ni promouvoir un credential,
//! ni modifier un état d'hôte. C'est la contrepartie du contrat de délégation —
//! l'agrégation finale est isolée du reste de la kill-chain.
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
#![allow(dead_code)]

use crate::agents::{AgentBrief, AgentReport, AgentRole};
use crate::ai::campaign_memory::CampaignMemory;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingAgentConfig {
    pub save_dir: String,
    pub session_id: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// ReportingAgent
// ─────────────────────────────────────────────────────────────────────────────

pub struct ReportingAgent {
    config: ReportingAgentConfig,
}

impl ReportingAgent {
    pub fn new(config: ReportingAgentConfig) -> Self {
        Self { config }
    }

    /// Produit le rapport Markdown local depuis une vue lecture seule de la mémoire.
    /// Le rapport narratif LLM reste piloté par l'orchestrateur (il dépend du planner).
    pub fn run(&self, brief: &AgentBrief, memory: &CampaignMemory) -> AgentReport {
        let mut report =
            AgentReport::new(AgentRole::Reporting, brief.target.clone(), String::new());
        let path = format!(
            "{}/report_{}.md",
            self.config.save_dir, self.config.session_id
        );

        let md = memory.generate_markdown_report();
        match std::fs::write(&path, &md) {
            Ok(_) => {
                println!("   📄 [REPORTING-AGENT] Rapport Markdown : {}", path);
                report.summary = format!("Rapport Markdown généré ({})", path);
                report.findings.push(format!("report_path:{}", path));
            }
            Err(e) => {
                let msg = format!("écriture de {} échouée : {}", path, e);
                println!("   ⚠️  [REPORTING-AGENT] {}", msg);
                report.errors.push(msg);
                report.summary = format!("Rapport {} non généré", path);
            }
        }

        report
    }
}
