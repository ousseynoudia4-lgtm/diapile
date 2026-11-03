//! DIAPILE — Autonomous Agents
//!
//! This module provides three autonomous agents for complete attack automation:
//! - DiscoveryAgent   — autonomous reconnaissance and service fingerprinting
//! - ExploitAgent     — intelligent exploit selection and execution
//! - PostExploitAgent — automated post-exploitation (enum, privesc, persistence)

use serde::{Deserialize, Serialize};

pub mod discovery_agent;
pub mod exploit_agent;
pub mod lateral_agent;
pub mod post_exploit_agent;
pub mod reporting_agent;
pub mod web_analysis_agent;

// Re-export main types
#[allow(unused_imports)]
pub use discovery_agent::{
    CampaignReport, DiscoveryAgent, DiscoveryAgentConfig, HostKnowledge, KnowledgeBase, PhaseReport,
};

#[allow(unused_imports)]
pub use exploit_agent::{ExploitAgent, ExploitAgentConfig, ExploitAgentReport, ExploitAttempt};

#[allow(unused_imports)]
pub use post_exploit_agent::{PostExploitAgent, PostExploitAgentConfig, PostExploitReport};

#[allow(unused_imports)]
pub use lateral_agent::{LateralAgent, LateralAgentConfig};

#[allow(unused_imports)]
pub use reporting_agent::{ReportingAgent, ReportingAgentConfig};

#[allow(unused_imports)]
pub use web_analysis_agent::{WebAnalysisAgent, WebAnalysisAgentConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Contrat de délégation : orchestrateur ↔ sous-agents
// ─────────────────────────────────────────────────────────────────────────────
//
// L'agent généraliste ne transmet JAMAIS la mémoire de campagne entière à un
// sous-agent. Il lui remet un `AgentBrief` **borné** (rôle, cible, objectif,
// hypothèse à tester, preuves de surface rattachées à la cible, budget de
// temps) et ne récupère qu'un `AgentReport` **structuré**. C'est ce qui limite
// la dérive de contexte : le sous-agent ne voit que ce qui le concerne. Et
// comme le rapport est normalisé, l'orchestrateur ingère les trouvailles par un
// point d'entrée unique au lieu de fouiller un rapport ad hoc — et de laisser
// chaque site inventer sa propre politique de promotion (creds, hôtes, privesc).

/// Rôle d'un sous-agent dans la kill-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Recon,
    Web,
    Exploit,
    PostExploit,
    Lateral,
    Reporting,
}

impl std::fmt::Display for AgentRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentRole::Recon => write!(f, "recon"),
            AgentRole::Web => write!(f, "web"),
            AgentRole::Exploit => write!(f, "exploit"),
            AgentRole::PostExploit => write!(f, "post_exploit"),
            AgentRole::Lateral => write!(f, "lateral"),
            AgentRole::Reporting => write!(f, "reporting"),
        }
    }
}

/// Contexte borné remis à un sous-agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBrief {
    pub role: AgentRole,
    pub target: String,
    pub objective: String,
    /// Hypothèse du planner (CVE, classe de vulnérabilité, technique).
    pub hypothesis: Option<String>,
    /// Preuves de surface strictement rattachées à la cible.
    pub surface_evidence: Vec<String>,
    /// Budget de temps alloué au sous-agent.
    pub max_duration_secs: u64,
}

/// Résultat normalisé rendu par un sous-agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentReport {
    pub role: AgentRole,
    pub target: String,
    pub summary: String,
    pub findings: Vec<String>,
    /// (hôte, utilisateur, secret)
    pub credentials: Vec<(String, String, String)>,
    pub internal_hosts: Vec<String>,
    pub privesc_vectors: Vec<String>,
    /// L'hôte est-il considéré comme compromis après cette exécution ?
    pub compromised: bool,
    /// Accès root/administrateur obtenu ?
    pub root: bool,
    pub errors: Vec<String>,
}

impl AgentReport {
    pub fn new(role: AgentRole, target: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            role,
            target: target.into(),
            summary: summary.into(),
            findings: Vec::new(),
            credentials: Vec::new(),
            internal_hosts: Vec::new(),
            privesc_vectors: Vec::new(),
            compromised: false,
            root: false,
            errors: Vec::new(),
        }
    }
}
