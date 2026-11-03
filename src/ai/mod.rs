//! Module IA — Agent autonome Red Team + moteur de recommandations
#![allow(unused_imports, dead_code)]

pub mod attack_planner;
pub mod autonomous_agent;
pub mod campaign_memory;
pub mod capability_registry;
pub mod hypothesis;
pub mod recommendation_engine;
pub mod rl_agent;
pub mod tool_parsers;

pub use attack_planner::{AttackPlan, AttackPlanner, PlannerConfig, RiskLevel};
pub use autonomous_agent::{AgentConfig, AutonomousAgent};
pub use campaign_memory::CampaignMemory;
pub use hypothesis::{HypothesisTracker, SurfaceEvidence, VulnClass};
pub use rl_agent::{
    available_actions, KillChainRLAgent, RLAgentConfig, RewardConfig, StateSignature,
};
