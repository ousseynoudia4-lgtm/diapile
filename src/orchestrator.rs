//! Advanced Attack Orchestrator
//! Advanced Attack Orchestrator
#![allow(unused_variables, dead_code, unused_imports)]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Campaign phases
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CampaignPhase {
    Reconnaissance,
    Scanning,
    Exploitation,
    PostExploitation,
    LateralMovement,
    Exfiltration,
    Cleanup,
}

/// Campaign status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CampaignStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Aborted,
}

/// Target priority level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum TargetPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Target information in the campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignTarget {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub service: String,
    pub version: Option<String>,
    pub os: Option<String>,
    pub priority: TargetPriority,
    pub status: TargetStatus,
    pub risk_score: f32,
    pub cves: Vec<String>,
    pub exploited: bool,
    pub session_id: Option<String>,
    pub lateral_movement_source: bool,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TargetStatus {
    Discovered,
    Scanned,
    Analyzed,
    Exploitable,
    Exploited,
    Compromised,
    Pivoting,
    Completed,
    Failed,
}

/// Active session on a compromised target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    pub session_id: String,
    pub target_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub session_type: String, // shell, meterpreter, webshell, etc.
    pub user: String,
    pub privileges: String,
    pub system_info: String,
    pub created_at: String,
    pub last_activity: String,
    pub alive: bool,
    pub interactive: bool,
}

/// Campaign configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignConfig {
    pub name: String,
    pub description: String,
    pub scope: Vec<String>, // Target networks/hosts
    pub excluded_targets: Vec<String>,
    pub max_parallel_exploits: usize,
    pub stop_on_first_success: bool,
    pub auto_pivot: bool, // Automatically pivot from compromised hosts
    pub max_pivot_depth: usize,
    pub persistence_enabled: bool,
    pub cleanup_enabled: bool,
    pub stealth_mode: bool, // Slow down to avoid detection
    pub log_all_commands: bool,
    pub save_evidence: bool,
    pub lateral_top_k_per_source: usize,
}

impl Default for CampaignConfig {
    fn default() -> Self {
        Self {
            name: "Default Campaign".into(),
            description: String::new(),
            scope: Vec::new(),
            excluded_targets: Vec::new(),
            max_parallel_exploits: 4,
            stop_on_first_success: false,
            auto_pivot: true,
            max_pivot_depth: 3,
            persistence_enabled: false,
            cleanup_enabled: false,
            stealth_mode: false,
            log_all_commands: true,
            save_evidence: false,
            lateral_top_k_per_source: 5,
        }
    }
}

/// Campaign state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignState {
    pub id: String,
    pub config: CampaignConfig,
    pub phase: CampaignPhase,
    pub status: CampaignStatus,
    pub targets: HashMap<String, CampaignTarget>,
    pub sessions: HashMap<String, ActiveSession>,
    pub findings: Vec<CampaignFinding>,
    pub harvested_credentials: Vec<HarvestedCredential>,
    pub lateral_paths: Vec<CampaignPath>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub progress: f32,
    pub statistics: CampaignStatistics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignFinding {
    pub id: String,
    pub target_id: String,
    pub finding_type: String, // vulnerability, credential, config, etc.
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: Option<String>,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CampaignStatistics {
    pub total_targets: usize,
    pub scanned_targets: usize,
    pub exploited_targets: usize,
    pub compromised_targets: usize,
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub findings_count: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub exploits_attempted: usize,
    pub exploits_succeeded: usize,
    pub exploits_failed: usize,
    pub pivot_count: usize,
    pub lateral_paths_evaluated: usize,
    pub lateral_paths_executed: usize,
}

/// Credential / hash harvested during a campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestedCredential {
    pub id: String,
    pub source_host: String,
    pub source_session_id: Option<String>,
    pub credential_type: String, // plaintext, ntlm_hash, aes_key, kerberos_ticket, ssh_key, cookie, etc.
    pub username: Option<String>,
    pub domain: Option<String>,
    pub secret: String,
    pub target_relevance: Vec<String>, // hosts/services this credential likely works for
    pub harvested_at: String,
    pub verified: bool,
}

/// A single lateral-movement hop for tracking within a campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignHopRecord {
    pub hop_id: String,
    pub path_id: String,
    pub from_host: String,
    pub to_host: String,
    pub technique: String,
    pub exploit_id: Option<String>,
    pub evasion_used: Option<String>,
    pub credential_used: Option<String>,
    pub attempted: bool,
    pub succeeded: bool,
    pub detection_alerts: u32,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub resulting_session_id: Option<String>,
    pub notes: String,
}

/// A lateral-movement path tracked through the campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignPath {
    pub path_id: String,
    pub source_host: String,
    pub target_host: String,
    pub hops: Vec<CampaignHopRecord>,
    pub initial_rank: Option<usize>,
    pub predicted_success_probability: f32,
    pub predicted_detection_risk: f32,
    pub status: PathExecutionStatus,
    pub rationale: String,
    pub warnings: Vec<String>,
    pub executed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PathExecutionStatus {
    Queued,
    Running,
    Succeeded,
    Partial,
    Failed,
    Skipped,
}

impl Default for PathExecutionStatus {
    fn default() -> Self {
        PathExecutionStatus::Queued
    }
}

/// Discovery commands that run from a compromised host to find adjacent targets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalDiscoveryPlan {
    pub session_id: String,
    pub host: String,
    pub commands: Vec<DiscoveryCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryCommand {
    pub id: String,
    pub command: String,
    pub category: String, // arp, routing, netstat, domain, users, shares, services
    pub expected_output_pattern: String,
    pub stealth_risk: f32,
}

/// Pick safe discovery commands depending on OS and stealth requirements
pub fn build_discovery_plan(
    session_id: String,
    host: String,
    os: Option<&str>,
    stealth_mode: bool,
) -> InternalDiscoveryPlan {
    let is_windows = os
        .map(|o| o.to_lowercase().contains("windows"))
        .unwrap_or(false);
    let (arp, route, netstat, users, domain, shares, services) = if is_windows {
        (
            "arp -a",
            "route print",
            "netstat -ano",
            "net user /domain 2>nul || net user",
            "net group \"Domain Admins\" /domain 2>nul || echo no-domain",
            "net view /all",
            "sc query type= service state= all | findstr /i \"DISPLAY_NAME\"",
        )
    } else {
        (
            "arp -a || ip neigh show",
            "ip route show || route -n",
            "ss -tulpn || netstat -tulpn",
            "cat /etc/passwd | grep -v nologin",
            "realm list || cat /etc/resolv.conf",
            "showmount -e 127.0.0.1 2>/dev/null || smbclient -L 127.0.0.1 -N 2>/dev/null",
            "systemctl list-units --type=service --state=running",
        )
    };
    let base = vec![
        DiscoveryCommand {
            id: "arp".into(),
            command: arp.into(),
            category: "arp".into(),
            expected_output_pattern: "([0-9]+\\.){3}[0-9]+".into(),
            stealth_risk: 0.05,
        },
        DiscoveryCommand {
            id: "route".into(),
            command: route.into(),
            category: "routing".into(),
            expected_output_pattern: "([0-9]+\\.){3}[0-9]+".into(),
            stealth_risk: 0.05,
        },
        DiscoveryCommand {
            id: "netstat".into(),
            command: netstat.into(),
            category: "netstat".into(),
            expected_output_pattern: "LISTEN|ESTABLISHED".into(),
            stealth_risk: 0.10,
        },
        DiscoveryCommand {
            id: "users".into(),
            command: users.into(),
            category: "users".into(),
            expected_output_pattern: ".*".into(),
            stealth_risk: 0.15,
        },
        DiscoveryCommand {
            id: "domain".into(),
            command: domain.into(),
            category: "domain".into(),
            expected_output_pattern: ".*".into(),
            stealth_risk: 0.20,
        },
        DiscoveryCommand {
            id: "shares".into(),
            command: shares.into(),
            category: "shares".into(),
            expected_output_pattern: ".*".into(),
            stealth_risk: 0.20,
        },
        DiscoveryCommand {
            id: "services".into(),
            command: services.into(),
            category: "services".into(),
            expected_output_pattern: ".*".into(),
            stealth_risk: 0.10,
        },
    ];
    let filtered: Vec<DiscoveryCommand> = if stealth_mode {
        base.into_iter()
            .filter(|c| c.stealth_risk <= 0.10)
            .collect()
    } else {
        base
    };
    InternalDiscoveryPlan {
        session_id,
        host,
        commands: filtered,
    }
}

/// Attack Orchestrator
pub struct AttackOrchestrator {
    pub campaign: Arc<RwLock<CampaignState>>,
    pub config: CampaignConfig,
}

impl AttackOrchestrator {
    /// Create a new campaign
    pub fn new(config: CampaignConfig) -> Self {
        let campaign = CampaignState {
            id: Uuid::new_v4().to_string(),
            config: config.clone(),
            phase: CampaignPhase::Reconnaissance,
            status: CampaignStatus::Pending,
            targets: HashMap::new(),
            sessions: HashMap::new(),
            findings: Vec::new(),
            harvested_credentials: Vec::new(),
            lateral_paths: Vec::new(),
            started_at: None,
            completed_at: None,
            progress: 0.0,
            statistics: CampaignStatistics::default(),
        };

        Self {
            campaign: Arc::new(RwLock::new(campaign)),
            config,
        }
    }

    /// Start the campaign
    pub async fn start(&self) -> Result<(), String> {
        let mut campaign = self.campaign.write().await;
        campaign.status = CampaignStatus::Running;
        campaign.started_at = Some(chrono::Utc::now().to_rfc3339());
        campaign.phase = CampaignPhase::Reconnaissance;
        Ok(())
    }

    /// Add discovered targets
    pub async fn add_targets(&self, targets: Vec<CampaignTarget>) {
        let mut campaign = self.campaign.write().await;
        for target in targets {
            campaign.targets.insert(target.id.clone(), target);
        }
        campaign.statistics.total_targets = campaign.targets.len();
    }

    /// Update target after scanning
    pub async fn update_target_scan(
        &self,
        target_id: &str,
        service: &str,
        version: Option<&str>,
        os: Option<&str>,
        cves: Vec<String>,
        risk_score: f32,
    ) {
        let mut campaign = self.campaign.write().await;
        if let Some(target) = campaign.targets.get_mut(target_id) {
            target.service = service.to_string();
            target.version = version.map(|s| s.to_string());
            target.os = os.map(|s| s.to_string());
            target.cves = cves;
            target.risk_score = risk_score;
            target.status = TargetStatus::Analyzed;

            // Update priority based on risk score
            target.priority = if risk_score >= 8.0 {
                TargetPriority::Critical
            } else if risk_score >= 6.0 {
                TargetPriority::High
            } else if risk_score >= 4.0 {
                TargetPriority::Medium
            } else {
                TargetPriority::Low
            };

            campaign.statistics.scanned_targets += 1;
        }
    }

    /// Mark target as exploitable
    pub async fn mark_exploitable(&self, target_id: &str, exploit_name: &str) {
        let mut campaign = self.campaign.write().await;
        if let Some(target) = campaign.targets.get_mut(target_id) {
            target.status = TargetStatus::Exploitable;
            target
                .notes
                .push_str(&format!("Exploitable via: {} ", exploit_name));
        }
    }

    /// Register a new session after successful exploitation
    pub async fn register_session(&self, session: ActiveSession) {
        let mut campaign = self.campaign.write().await;

        // Update target status
        if let Some(target) = campaign.targets.get_mut(&session.target_id) {
            target.status = TargetStatus::Compromised;
            target.exploited = true;
            target.session_id = Some(session.session_id.clone());
        }

        campaign
            .sessions
            .insert(session.session_id.clone(), session);
        campaign.statistics.total_sessions += 1;
        campaign.statistics.active_sessions += 1;
        campaign.statistics.compromised_targets += 1;
    }

    /// Add a finding
    pub async fn add_finding(&self, finding: CampaignFinding) {
        let mut campaign = self.campaign.write().await;

        match finding.severity.to_lowercase().as_str() {
            "critical" => campaign.statistics.critical_findings += 1,
            "high" => campaign.statistics.high_findings += 1,
            "medium" => campaign.statistics.medium_findings += 1,
            _ => campaign.statistics.low_findings += 1,
        }

        campaign.findings.push(finding);
        campaign.statistics.findings_count += 1;
    }

    /// Get next target to exploit (prioritized)
    pub async fn get_next_target(&self) -> Option<CampaignTarget> {
        let campaign = self.campaign.read().await;

        let mut exploitable: Vec<&CampaignTarget> = campaign
            .targets
            .values()
            .filter(|t| t.status == TargetStatus::Exploitable && !t.exploited)
            .collect();

        // Sort by priority (Critical first)
        exploitable.sort_by(|a, b| b.priority.cmp(&a.priority));

        exploitable.first().map(|t| (*t).clone())
    }

    /// Get all sessions for lateral movement
    pub async fn get_active_sessions(&self) -> Vec<ActiveSession> {
        let campaign = self.campaign.read().await;
        campaign
            .sessions
            .values()
            .filter(|s| s.alive)
            .cloned()
            .collect()
    }

    /// Update campaign phase
    pub async fn set_phase(&self, phase: CampaignPhase) {
        let mut campaign = self.campaign.write().await;
        campaign.phase = phase.clone();

        // Update progress based on phase
        campaign.progress = match phase {
            CampaignPhase::Reconnaissance => 0.1,
            CampaignPhase::Scanning => 0.3,
            CampaignPhase::Exploitation => 0.5,
            CampaignPhase::PostExploitation => 0.7,
            CampaignPhase::LateralMovement => 0.8,
            CampaignPhase::Exfiltration => 0.9,
            CampaignPhase::Cleanup => 0.95,
        };
    }

    /// Complete the campaign
    pub async fn complete(&self) {
        let mut campaign = self.campaign.write().await;
        campaign.status = CampaignStatus::Completed;
        campaign.completed_at = Some(chrono::Utc::now().to_rfc3339());
        campaign.progress = 1.0;
    }

    /// Get campaign report
    pub async fn get_report(&self) -> CampaignState {
        let campaign = self.campaign.read().await;
        campaign.clone()
    }

    /// Pause the campaign
    pub async fn pause(&self) {
        let mut campaign = self.campaign.write().await;
        campaign.status = CampaignStatus::Paused;
    }

    /// Resume the campaign
    pub async fn resume(&self) {
        let mut campaign = self.campaign.write().await;
        campaign.status = CampaignStatus::Running;
    }

    /// Abort the campaign
    pub async fn abort(&self) {
        let mut campaign = self.campaign.write().await;
        campaign.status = CampaignStatus::Aborted;
    }

    /// Record a harvested credential from post-exploitation
    pub async fn harvest_credential(&self, cred: HarvestedCredential) {
        let mut campaign = self.campaign.write().await;
        campaign.harvested_credentials.push(cred);
    }

    /// Enqueue a lateral-movement path into the campaign for later execution
    pub async fn enqueue_lateral_path(&self, path: CampaignPath) {
        let mut campaign = self.campaign.write().await;
        campaign.lateral_paths.push(path);
    }

    /// Get compromised hosts as a set of host strings
    pub async fn compromised_hosts(&self) -> std::collections::HashSet<String> {
        let campaign = self.campaign.read().await;
        let mut out = std::collections::HashSet::new();
        for t in campaign.targets.values() {
            if t.status == TargetStatus::Compromised || t.exploited {
                out.insert(t.host.clone());
            }
        }
        for s in campaign.sessions.values() {
            out.insert(s.target_host.clone());
        }
        out
    }

    /// Get host→risk and host→cves maps used by flows graph builder
    pub async fn host_context(
        &self,
    ) -> (
        std::collections::HashMap<String, f32>,
        std::collections::HashMap<String, Vec<(String, f32, String)>>,
    ) {
        let campaign = self.campaign.read().await;
        let mut risk: std::collections::HashMap<String, f32> = std::collections::HashMap::new();
        let mut cves: std::collections::HashMap<String, Vec<(String, f32, String)>> =
            std::collections::HashMap::new();
        for t in campaign.targets.values() {
            let e = risk.entry(t.host.clone()).or_insert(0.0);
            *e = e.max(t.risk_score);
            let ce = cves.entry(t.host.clone()).or_default();
            for c in &t.cves {
                ce.push((c.clone(), 0.0, String::new()));
            }
        }
        (risk, cves)
    }

    /// Credentials indexed by source host, used to drive credential-reuse scoring
    pub async fn credentials_by_host(&self) -> std::collections::HashMap<String, Vec<String>> {
        let campaign = self.campaign.read().await;
        let mut out: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for c in &campaign.harvested_credentials {
            let line = format!(
                "{}:{}:{}:{}",
                c.credential_type,
                c.username.as_deref().unwrap_or(""),
                c.domain.as_deref().unwrap_or(""),
                c.target_relevance.join("|")
            );
            out.entry(c.source_host.clone()).or_default().push(line);
        }
        out
    }

    /// Save campaign state to file
    pub async fn save_state(&self, path: &str) -> Result<(), std::io::Error> {
        let campaign = self.campaign.read().await;
        let json = serde_json::to_string_pretty(&*campaign)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load campaign state from file
    pub async fn load_state(
        path: &str,
    ) -> Result<CampaignState, Box<dyn std::error::Error + Send + Sync>> {
        let content = std::fs::read_to_string(path)?;
        let state: CampaignState = serde_json::from_str(&content)?;
        Ok(state)
    }
}

/// Pivot manager for lateral movement
pub struct PivotManager {
    orchestrator: Arc<AttackOrchestrator>,
}

impl PivotManager {
    pub fn new(orchestrator: Arc<AttackOrchestrator>) -> Self {
        Self { orchestrator }
    }

    /// Build and return the discovery plan (arp / route / netstat / domain / shares)
    /// for a given session. This is the script that an external agent would run.
    pub async fn build_discovery_plan(
        &self,
        session_id: &str,
    ) -> Result<InternalDiscoveryPlan, String> {
        let campaign = self.orchestrator.campaign.read().await;
        let session = campaign
            .sessions
            .get(session_id)
            .ok_or_else(|| format!("Session {} not found", session_id))?;
        let stealth = campaign.config.stealth_mode;
        let os = campaign
            .targets
            .get(&session.target_id)
            .and_then(|t| t.os.clone());
        Ok(build_discovery_plan(
            session.session_id.clone(),
            session.target_host.clone(),
            os.as_deref(),
            stealth,
        ))
    }

    /// Discover internal network from a compromised host.
    /// Returns newly-discovered CampaignTargets parsed from a caller-supplied
    /// discovery output snapshot. In a real agent this method would be preceded
    /// by `build_discovery_plan` → run commands on-session → feed stdout back here.
    pub async fn discover_from_session(
        &self,
        session_id: &str,
        discovery_output: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<CampaignTarget>, String> {
        let campaign = self.orchestrator.campaign.read().await;
        let session = campaign
            .sessions
            .get(session_id)
            .ok_or_else(|| format!("Session {} not found", session_id))?;

        let mut new_targets: Vec<CampaignTarget> = Vec::new();

        if let Some(outputs) = discovery_output {
            let arp_output = outputs.get("arp").cloned().unwrap_or_default();
            let netstat_output = outputs.get("netstat").cloned().unwrap_or_default();

            let ip_regex = regex::Regex::new(r"(?:\d{1,3}\.){3}\d{1,3}")
                .map_err(|e| format!("regex init error: {}", e))?;
            let mut ips_found: std::collections::HashSet<String> = std::collections::HashSet::new();
            for line in arp_output.lines().chain(netstat_output.lines()) {
                for m in ip_regex.find_iter(line) {
                    let ip = m.as_str().to_string();
                    if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "255.255.255.255" {
                        continue;
                    }
                    ips_found.insert(ip);
                }
            }

            for ip in ips_found {
                if campaign.targets.values().any(|t| t.host == ip) {
                    continue;
                }
                let id = format!(
                    "discovered-{}-{}",
                    session.session_id.get(..8).unwrap_or("sess"),
                    ip.replace('.', "-")
                );
                new_targets.push(CampaignTarget {
                    id,
                    host: ip,
                    port: 0,
                    service: String::new(),
                    version: None,
                    os: None,
                    priority: TargetPriority::Medium,
                    status: TargetStatus::Discovered,
                    risk_score: 0.0,
                    cves: Vec::new(),
                    exploited: false,
                    session_id: None,
                    lateral_movement_source: true,
                    notes: format!(
                        "Discovered from {} via internal discovery",
                        session.target_host
                    ),
                });
            }
        }

        if !new_targets.is_empty() {
            drop(campaign);
            self.orchestrator.add_targets(new_targets.clone()).await;
        }

        Ok(new_targets)
    }

    /// Build the weighted lateral-movement graph for the campaign using:
    ///   - existing FlowLinks (captured / inferred topology)
    ///   - risk.rs per-host scores
    ///   - harvested CVEs
    ///   - compromised hosts as sources
    ///   - credentials harvested for reuse scoring
    pub async fn build_lateral_graph(
        &self,
        flow_links: &[crate::flows::FlowLink],
        target_summaries: &[crate::flows::ScanTargetSummary],
    ) -> Result<crate::flows::LateralGraph, String> {
        let compromised = self.orchestrator.compromised_hosts().await;
        let (risk_per_host, cves_per_host) = self.orchestrator.host_context().await;
        let credentials = self.orchestrator.credentials_by_host().await;

        let graph = crate::flows::LateralGraph::from_flowlinks_and_targets(
            flow_links,
            target_summaries,
            &risk_per_host,
            &cves_per_host,
            &compromised,
            &credentials,
        );
        Ok(graph)
    }

    /// Rank all plausible lateral-movement paths across the campaign using the
    /// Dijkstra-style graph walk. Top paths are stored into the campaign as
    /// `CampaignPath` entries (queued for later execution).
    pub async fn rank_paths(
        &self,
        flow_links: &[crate::flows::FlowLink],
        target_summaries: &[crate::flows::ScanTargetSummary],
    ) -> Result<Vec<crate::flows::LateralPath>, String> {
        let graph = self
            .build_lateral_graph(flow_links, target_summaries)
            .await?;
        let config = {
            let c = self.orchestrator.campaign.read().await;
            c.config.clone()
        };
        let ranked =
            graph.rank_all_campaign_paths(config.max_pivot_depth, config.lateral_top_k_per_source);

        {
            let mut campaign = self.orchestrator.campaign.write().await;
            campaign.statistics.lateral_paths_evaluated += ranked.len();
            for p in &ranked {
                let hops: Vec<CampaignHopRecord> = p
                    .hops
                    .iter()
                    .map(|h| CampaignHopRecord {
                        hop_id: format!(
                            "{}-hop-{}",
                            p.path_id,
                            uuid::Uuid::new_v4().to_string().get(..6).unwrap_or("x")
                        ),
                        path_id: p.path_id.clone(),
                        from_host: h.from_host.clone(),
                        to_host: h.to_host.clone(),
                        technique: h.technique.clone(),
                        exploit_id: h.exploit_id.clone(),
                        evasion_used: None,
                        credential_used: None,
                        attempted: false,
                        succeeded: false,
                        detection_alerts: 0,
                        started_at: None,
                        finished_at: None,
                        resulting_session_id: None,
                        notes: h.notes.clone(),
                    })
                    .collect();
                let cp = CampaignPath {
                    path_id: p.path_id.clone(),
                    source_host: p.source_host.clone(),
                    target_host: p.target_host.clone(),
                    hops,
                    initial_rank: p.rank,
                    predicted_success_probability: p.total_success_probability,
                    predicted_detection_risk: p.aggregate_detection_risk,
                    status: PathExecutionStatus::Queued,
                    rationale: p.rationale.clone(),
                    warnings: p.warnings.clone(),
                    executed_at: None,
                };
                campaign.lateral_paths.push(cp);
            }
        }
        Ok(ranked)
    }

    /// Execute a single hop of a lateral-movement path. This is the shim that
    /// bridges the orchestrator to the exploit engine: it only marks the hop
    /// record as attempted, updates the campaign statistics, and returns a
    /// `Pending` token with the recommended technique + exploit id. Real
    /// integration with metasploit / bloodhound lives in the integrations
    /// modules.
    pub async fn attempt_hop(
        &self,
        path_id: &str,
        hop_index: usize,
        custom_exploit_override: Option<&str>,
    ) -> Result<Option<ActiveSession>, String> {
        let (session_id_placeholder, technique, target_host) = {
            let mut campaign = self.orchestrator.campaign.write().await;
            {
                let path = campaign
                    .lateral_paths
                    .iter_mut()
                    .find(|p| p.path_id == path_id)
                    .ok_or_else(|| format!("Path {} not found", path_id))?;
                if path.status == PathExecutionStatus::Queued {
                    path.status = PathExecutionStatus::Running;
                    path.executed_at = Some(chrono::Utc::now().to_rfc3339());
                }
                let hop = path.hops.get_mut(hop_index).ok_or_else(|| {
                    format!("Hop index {} out of range for path {}", hop_index, path_id)
                })?;
                if let Some(ov) = custom_exploit_override {
                    hop.exploit_id = Some(ov.to_string());
                }
                hop.attempted = true;
                hop.started_at = Some(chrono::Utc::now().to_rfc3339());
            }
            campaign.statistics.pivot_count += 1;
            {
                let path = campaign
                    .lateral_paths
                    .iter()
                    .find(|p| p.path_id == path_id)
                    .ok_or_else(|| format!("Path {} not found after hop mark", path_id))?;
                let hop = path
                    .hops
                    .get(hop_index)
                    .ok_or_else(|| format!("Hop index {} out of range", hop_index))?;
                (
                    format!("pending-{}-{}", path_id, hop_index),
                    hop.technique.clone(),
                    hop.to_host.clone(),
                )
            }
        };

        tracing::info!(target: "pivot", %path_id, %hop_index, %technique, %target_host, "attempting lateral hop");

        // ── Tentative réelle selon la technique ──────────────────────────────
        let hop_result = match technique.as_str() {
            "ssh" | "ssh_keybased" => {
                let cfg = crate::bruteforce::BruteConfig::quick();
                let report = crate::bruteforce::brute_ssh(&target_host, 22, &cfg).await;
                if let Some(success) = report.successes.first() {
                    Some(crate::orchestrator::ActiveSession {
                        session_id: uuid::Uuid::new_v4().to_string(),
                        target_id: format!("{}:{}", target_host, 22),
                        target_host: target_host.clone(),
                        target_port: 22,
                        session_type: "ssh".into(),
                        user: success.username.clone(),
                        privileges: "user".into(),
                        system_info: String::new(),
                        created_at: chrono::Utc::now().to_rfc3339(),
                        last_activity: chrono::Utc::now().to_rfc3339(),
                        alive: true,
                        interactive: true,
                    })
                } else {
                    tracing::warn!("SSH bruteforce échoué sur {}", target_host);
                    None
                }
            }
            "smb" | "pass_the_hash" => {
                tracing::info!(
                    "SMB pivot sur {} — utilisez : impacket-psexec domain/user:pass@{}",
                    target_host,
                    target_host
                );
                None
            }
            "http" | "webshell" => {
                let opts = HashMap::new();
                let result = crate::exploit_engine::exploit_buffer_overflow(
                    &target_host,
                    80,
                    "apache_mod_cgi",
                    &opts,
                )
                .await;
                match result {
                    crate::exploit_engine::ExploitResult::Success {
                        session_id,
                        user,
                        system_info,
                        ..
                    } => Some(crate::orchestrator::ActiveSession {
                        session_id,
                        target_id: format!("{}:{}", target_host, 80),
                        target_host: target_host.clone(),
                        target_port: 80,
                        session_type: "webshell".into(),
                        user,
                        privileges: "www-data".into(),
                        system_info,
                        created_at: chrono::Utc::now().to_rfc3339(),
                        last_activity: chrono::Utc::now().to_rfc3339(),
                        alive: true,
                        interactive: false,
                    }),
                    _ => None,
                }
            }
            _ => {
                tracing::warn!("Technique '{}' non supportée — ignorée", technique);
                None
            }
        };

        Ok(hop_result)
    }

    /// Commit the result of an attempted hop: success + resulting session, or failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_hop_result(
        &self,
        path_id: &str,
        hop_index: usize,
        succeeded: bool,
        resulting_session: Option<ActiveSession>,
        detection_alerts: u32,
        evasion_used: Option<&str>,
        credential_used: Option<&str>,
        notes: Option<&str>,
    ) -> Result<(), String> {
        let mut campaign = self.orchestrator.campaign.write().await;
        {
            let path = campaign
                .lateral_paths
                .iter_mut()
                .find(|p| p.path_id == path_id)
                .ok_or_else(|| format!("Path {} not found", path_id))?;
            let hop = path.hops.get_mut(hop_index).ok_or_else(|| {
                format!("Hop index {} out of range for path {}", hop_index, path_id)
            })?;
            hop.succeeded = succeeded;
            hop.finished_at = Some(chrono::Utc::now().to_rfc3339());
            hop.detection_alerts = detection_alerts;
            if let Some(e) = evasion_used {
                hop.evasion_used = Some(e.to_string());
            }
            if let Some(c) = credential_used {
                hop.credential_used = Some(c.to_string());
            }
            if let Some(n) = notes {
                hop.notes.push_str(" | ");
                hop.notes.push_str(n);
            }
        }

        if let Some(session) = resulting_session {
            let sid = session.session_id.clone();
            {
                let path = campaign
                    .lateral_paths
                    .iter_mut()
                    .find(|p| p.path_id == path_id)
                    .ok_or_else(|| format!("Path {} not found during session attach", path_id))?;
                let hop = path
                    .hops
                    .get_mut(hop_index)
                    .ok_or_else(|| format!("Hop index {} out of range", hop_index))?;
                hop.resulting_session_id = Some(sid.clone());
            }
            campaign.sessions.insert(sid, session);
            campaign.statistics.total_sessions += 1;
            campaign.statistics.active_sessions += 1;
        }

        let (all_done, all_ok, any_ok) = {
            let path = campaign
                .lateral_paths
                .iter()
                .find(|p| p.path_id == path_id)
                .ok_or_else(|| format!("Path {} not found during final status check", path_id))?;
            (
                path.hops.iter().all(|h| h.attempted),
                path.hops.iter().all(|h| h.succeeded),
                path.hops.iter().any(|h| h.succeeded),
            )
        };
        if all_done {
            let new_status = if all_ok {
                campaign.statistics.lateral_paths_executed += 1;
                PathExecutionStatus::Succeeded
            } else if any_ok {
                PathExecutionStatus::Partial
            } else {
                PathExecutionStatus::Failed
            };
            if let Some(path) = campaign
                .lateral_paths
                .iter_mut()
                .find(|p| p.path_id == path_id)
            {
                path.status = new_status;
            }
        }
        Ok(())
    }

    /// Perform lateral movement to a new target (convenience wrapper that
    /// enqueues a 1-hop path, executes the hop, and leaves the caller to
    /// commit the result via `commit_hop_result`).
    pub async fn lateral_move(
        &self,
        source_session_id: &str,
        target_host: &str,
        exploit_name: &str,
    ) -> Result<Option<ActiveSession>, String> {
        let (source_host, source_target_id) = {
            let c = self.orchestrator.campaign.read().await;
            let sess = c
                .sessions
                .get(source_session_id)
                .ok_or_else(|| format!("Session {} not found", source_session_id))?;
            (sess.target_host.clone(), sess.target_id.clone())
        };

        let path_id = format!(
            "single-hop-{}-{}",
            source_session_id.get(..8).unwrap_or("sess"),
            target_host.replace('.', "-")
        );
        let cp = CampaignPath {
            path_id: path_id.clone(),
            source_host: source_host.clone(),
            target_host: target_host.to_string(),
            hops: vec![CampaignHopRecord {
                hop_id: format!("{}-hop-0", path_id),
                path_id: path_id.clone(),
                from_host: source_host.clone(),
                to_host: target_host.to_string(),
                technique: format!("direct via {}", exploit_name),
                exploit_id: Some(exploit_name.to_string()),
                evasion_used: None,
                credential_used: None,
                attempted: false,
                succeeded: false,
                detection_alerts: 0,
                started_at: None,
                finished_at: None,
                resulting_session_id: None,
                notes: format!(
                    "Source session {} target id {}",
                    source_session_id, source_target_id
                ),
            }],
            initial_rank: None,
            predicted_success_probability: 0.5,
            predicted_detection_risk: 0.5,
            status: PathExecutionStatus::Queued,
            rationale: format!(
                "Direct lateral from {} to {} with {}",
                source_host, target_host, exploit_name
            ),
            warnings: Vec::new(),
            executed_at: None,
        };
        self.orchestrator.enqueue_lateral_path(cp).await;
        self.attempt_hop(&path_id, 0, Some(exploit_name)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_orchestrator_creation() {
        let config = CampaignConfig {
            name: "Test Campaign".to_string(),
            description: "Test".to_string(),
            scope: vec!["192.168.1.0/24".to_string()],
            excluded_targets: vec![],
            max_parallel_exploits: 4,
            stop_on_first_success: false,
            auto_pivot: true,
            max_pivot_depth: 3,
            persistence_enabled: true,
            cleanup_enabled: false,
            stealth_mode: false,
            log_all_commands: true,
            save_evidence: true,
            lateral_top_k_per_source: 5,
        };

        let orchestrator = AttackOrchestrator::new(config);
        assert_eq!(
            orchestrator.campaign.read().await.status,
            CampaignStatus::Pending
        );
    }

    #[tokio::test]
    async fn test_add_targets() {
        let config = CampaignConfig {
            name: "Test".to_string(),
            description: "Test".to_string(),
            scope: vec![],
            excluded_targets: vec![],
            max_parallel_exploits: 1,
            stop_on_first_success: false,
            auto_pivot: false,
            max_pivot_depth: 0,
            persistence_enabled: false,
            cleanup_enabled: false,
            stealth_mode: false,
            log_all_commands: false,
            save_evidence: false,
            lateral_top_k_per_source: 5,
        };

        let orchestrator = AttackOrchestrator::new(config);

        let targets = vec![CampaignTarget {
            id: "target1".to_string(),
            host: "192.168.1.10".to_string(),
            port: 22,
            service: "ssh".to_string(),
            version: Some("OpenSSH 7.4".to_string()),
            os: Some("Linux".to_string()),
            priority: TargetPriority::Medium,
            status: TargetStatus::Discovered,
            risk_score: 5.0,
            cves: vec![],
            exploited: false,
            session_id: None,
            lateral_movement_source: false,
            notes: String::new(),
        }];

        orchestrator.add_targets(targets).await;

        let campaign = orchestrator.campaign.read().await;
        assert_eq!(campaign.targets.len(), 1);
        assert_eq!(campaign.statistics.total_targets, 1);
    }
}
