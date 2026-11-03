//! Autonomous Discovery Agent

use crate::agents::{AgentBrief, AgentReport, AgentRole};
use crate::llm_exploit::{LLMConfig, LLMExploitAnalyzer};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct DiscoveryAgent {
    llm_analyzer: Option<LLMExploitAnalyzer>,
    config: DiscoveryAgentConfig,
    knowledge_base: Arc<RwLock<KnowledgeBase>>,
    state: Arc<RwLock<AgentState>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryAgentConfig {
    pub max_targets: usize,
    pub max_depth: usize,
    pub llm_enabled: bool,
    pub auto_prioritize: bool,
    pub aggressive_mode: bool,
    pub stealth_mode: bool,
    pub learn_from_findings: bool,
}

impl Default for DiscoveryAgentConfig {
    fn default() -> Self {
        Self {
            max_targets: 1000,
            max_depth: 3,
            llm_enabled: true,
            auto_prioritize: true,
            aggressive_mode: false,
            stealth_mode: true,
            learn_from_findings: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentState {
    pub targets_discovered: usize,
    pub targets_scanned: usize,
    pub targets_exploitable: usize,
    pub findings_count: usize,
    pub current_phase: String,
    pub learning_iterations: usize,
    pub confidence_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KnowledgeBase {
    pub discovered_hosts: HashMap<String, HostKnowledge>,
    pub service_patterns: HashMap<String, ServicePattern>,
    pub vulnerability_patterns: HashMap<String, VulnerabilityPattern>,
    pub attack_success_rates: HashMap<String, f32>,
    pub learned_strategies: Vec<LearnedStrategy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostKnowledge {
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub services: Vec<String>,
    pub open_ports: Vec<u16>,
    pub risk_score: f32,
    pub discovered_at: String,
    pub last_updated: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePattern {
    pub service: String,
    pub version: String,
    pub common_vulnerabilities: Vec<String>,
    pub exploitation_difficulty: f32,
    pub success_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityPattern {
    pub cve: String,
    pub service: String,
    pub exploit_available: bool,
    pub exploit_complexity: String,
    pub success_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedStrategy {
    pub description: String,
    pub success_rate: f32,
    pub conditions: HashMap<String, String>,
    pub actions: Vec<String>,
}

impl DiscoveryAgent {
    pub fn new(config: DiscoveryAgentConfig, llm_config: Option<LLMConfig>) -> Result<Self> {
        let llm_analyzer = if config.llm_enabled {
            if let Some(cfg) = llm_config {
                Some(LLMExploitAnalyzer::new(cfg)?)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            llm_analyzer,
            config,
            knowledge_base: Arc::new(RwLock::new(KnowledgeBase::default())),
            state: Arc::new(RwLock::new(AgentState::default())),
        })
    }

    /// Entrée conforme au contrat de délégation : un `AgentBrief` borné entre,
    /// un `AgentReport` structuré sort. L'agent ne touche jamais la mémoire de
    /// campagne ni l'orchestrateur — il remonte ses trouvailles, l'orchestrateur
    /// décide de leur promotion.
    pub async fn run_brief(&self, brief: &AgentBrief) -> AgentReport {
        let mut report = AgentReport::new(AgentRole::Recon, brief.target.clone(), String::new());

        let targets: Vec<String> = vec![brief.target.clone()];
        match self.run_autonomous_campaign(&targets).await {
            Ok(campaign) => {
                let mut phases: Vec<String> = Vec::new();
                for phase in &campaign.phases {
                    let kv: Vec<String> = phase
                        .metrics
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect();
                    phases.push(format!("{} [{}]", phase.name, kv.join(",")));
                    for f in &phase.findings {
                        report.findings.push(f.clone());
                    }
                }
                report.summary = format!(
                    "Reconnaissance bornée sur {} — {}",
                    brief.target,
                    phases.join(" | ")
                );
            }
            Err(e) => {
                report.errors.push(e.to_string());
                report.summary = format!("Reconnaissance échouée sur {}", brief.target);
                return report;
            }
        }

        // Hôtes découverts : remontés au titre d'hôtes internes, l'orchestrateur
        // les ingère par son point d'entrée unique (`ingest_agent_report`).
        let kb = self.knowledge_base.read().await;
        report.internal_hosts = kb.discovered_hosts.keys().cloned().collect();

        report
    }

    pub async fn run_autonomous_campaign(
        &self,
        initial_targets: &[String],
    ) -> Result<CampaignReport> {
        let mut report = CampaignReport::new();

        report.add_phase(
            "Initial Reconnaissance",
            self.phase_reconnaissance(initial_targets).await?,
        );
        report.add_phase("Intelligent Scanning", self.phase_scanning().await?);
        report.add_phase(
            "Vulnerability Analysis",
            self.phase_vulnerability_analysis().await?,
        );

        if let Some(phase) = self.phase_exploit_recommendation().await? {
            report.add_phase("Exploit Recommendation", phase);
        }

        // NB: calculer le score AVANT de prendre le write lock — calculate_confidence_score()
        // acquiert un read lock sur self.state ; le détenir sous un write lock provoquerait
        // un deadlock (RwLock tokio non réentrant).
        let confidence = self.calculate_confidence_score().await;
        let mut state = self.state.write().await;
        state.current_phase = "Completed".to_string();
        state.confidence_score = confidence;

        Ok(report)
    }

    async fn phase_reconnaissance(&self, targets: &[String]) -> Result<PhaseReport> {
        let mut report = PhaseReport::new("Reconnaissance");
        let mut state = self.state.write().await;
        state.current_phase = "Reconnaissance".to_string();

        for target in targets {
            let discovered = self.discover_hosts(target).await?;
            for host in discovered {
                let mut kb = self.knowledge_base.write().await;
                kb.discovered_hosts.insert(host.ip.clone(), host);
                state.targets_discovered += 1;
            }
        }

        report.add_metric("hosts_discovered", state.targets_discovered as i32);
        Ok(report)
    }

    async fn phase_scanning(&self) -> Result<PhaseReport> {
        let mut report = PhaseReport::new("Scanning");
        let mut state = self.state.write().await;
        state.current_phase = "Scanning".to_string();

        // Collect hosts first, then drop read lock before taking write lock
        let hosts: Vec<HostKnowledge> = {
            let kb = self.knowledge_base.read().await;
            kb.discovered_hosts.values().cloned().collect()
        };

        let host_refs: Vec<&HostKnowledge> = hosts.iter().collect();
        let prioritized: Vec<HostKnowledge> = self
            .prioritize_hosts(&host_refs)
            .await
            .into_iter()
            .cloned()
            .collect();

        for host in &prioritized {
            let scan_result = self.scan_host(host).await?;
            let mut kb = self.knowledge_base.write().await;
            if let Some(h) = kb.discovered_hosts.get_mut(&host.ip) {
                h.services = scan_result.services;
                h.open_ports = scan_result.open_ports;
                h.risk_score = scan_result.risk_score;
                h.last_updated = chrono::Utc::now().to_rfc3339();
            }
            state.targets_scanned += 1;
        }

        report.add_metric("hosts_scanned", state.targets_scanned as i32);
        Ok(report)
    }

    async fn phase_vulnerability_analysis(&self) -> Result<PhaseReport> {
        let mut report = PhaseReport::new("Vulnerability Analysis");
        let mut state = self.state.write().await;
        state.current_phase = "Vulnerability Analysis".to_string();

        let hosts: Vec<HostKnowledge> = {
            let kb = self.knowledge_base.read().await;
            kb.discovered_hosts.values().cloned().collect()
        };

        let mut exploitable_count = 0usize;
        for host in &hosts {
            let vulnerabilities = self.analyze_host_vulnerabilities(host).await?;
            if !vulnerabilities.is_empty() {
                exploitable_count += 1;
                for vuln in &vulnerabilities {
                    // Aucune écriture directe dans l'orchestrateur : le sous-agent
                    // remonte la trouvaille, l'orchestrateur la promeut lui-même.
                    report
                        .findings
                        .push(format!("exploitable:{}:{}", host.ip, vuln.cve));
                }
            }
        }

        state.targets_exploitable = exploitable_count;
        report.add_metric("exploitable_hosts", exploitable_count as i32);
        Ok(report)
    }

    async fn phase_exploit_recommendation(&self) -> Result<Option<PhaseReport>> {
        if self.llm_analyzer.is_none() || !self.config.llm_enabled {
            return Ok(None);
        }

        let mut report = PhaseReport::new("Exploit Recommendation");
        {
            let mut state = self.state.write().await;
            state.current_phase = "Exploit Recommendation".to_string();
        }

        let hosts: Vec<HostKnowledge> = {
            let kb = self.knowledge_base.read().await;
            kb.discovered_hosts.values().cloned().collect()
        };

        let mut rec_count = 0usize;
        for host in &hosts {
            if host.risk_score >= 5.0 {
                if let Some(analyzer) = &self.llm_analyzer {
                    let _rec = analyzer
                        .analyze_target(
                            &host.ip,
                            host.open_ports.first().copied().unwrap_or(0),
                            host.services
                                .first()
                                .map(|s| s.as_str())
                                .unwrap_or("unknown"),
                            None,
                            None,
                            host.os.as_deref(),
                            &[],
                        )
                        .await
                        .map_err(|e| anyhow::anyhow!("{}", e))?;
                    rec_count += 1;
                }
            }
        }

        report.add_metric("recommendations_generated", rec_count as i32);
        Ok(Some(report))
    }

    /// Discover hosts in a target range via TCP probing
    async fn discover_hosts(&self, target: &str) -> Result<Vec<HostKnowledge>> {
        use std::collections::HashSet;
        use std::net::IpAddr;
        use std::time::Duration;

        let mut out = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        let mut cidrs: Vec<ipnetwork::IpNetwork> = Vec::new();
        if target.contains('/') {
            if let Ok(net) = target.parse::<ipnetwork::IpNetwork>() {
                cidrs.push(net);
            }
        } else if let Ok(ip) = target.parse::<IpAddr>() {
            if let IpAddr::V4(v4) = ip {
                let mask = if v4.octets()[3] == 0 { 24u8 } else { 32u8 };
                if let Ok(net) = ipnetwork::Ipv4Network::new(v4, mask) {
                    cidrs.push(ipnetwork::IpNetwork::V4(net));
                }
            }
        }

        for net in cidrs {
            // Collect all IPs first to avoid holding references across await points
            let all_ips: Vec<IpAddr> = net.iter().collect();
            for host_ip in all_ips {
                let ip_s = host_ip.to_string();
                if !seen.insert(ip_s.clone()) {
                    continue;
                }

                let probes: &[u16] = if self.config.aggressive_mode {
                    &[80, 443, 22, 445, 3389, 135]
                } else {
                    &[80, 443, 22, 445]
                };

                let mut reachable = false;
                for &p in probes {
                    let ok = tokio::time::timeout(
                        Duration::from_millis(300),
                        tokio::net::TcpStream::connect(format!("{}:{}", ip_s, p)),
                    )
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false);
                    if ok {
                        reachable = true;
                        break;
                    }
                }

                if reachable {
                    let tags = if let IpAddr::V4(v4) = host_ip {
                        let mut t = Vec::new();
                        if v4.is_private() {
                            t.push("private".to_string());
                        }
                        if v4.octets()[3] == 1 {
                            t.push("gw-candidate".to_string());
                        }
                        t
                    } else {
                        vec![]
                    };

                    out.push(HostKnowledge {
                        ip: ip_s,
                        hostname: None,
                        os: None,
                        services: vec![],
                        open_ports: vec![],
                        risk_score: 0.0,
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                        last_updated: chrono::Utc::now().to_rfc3339(),
                        tags,
                    });
                }
            }
        }

        Ok(out)
    }

    async fn prioritize_hosts<'a>(&self, hosts: &[&'a HostKnowledge]) -> Vec<&'a HostKnowledge> {
        let mut scored: Vec<(&'a HostKnowledge, f32)> = Vec::new();
        for &host in hosts {
            let score = self.calculate_host_priority(host).await;
            scored.push((host, score));
        }
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.into_iter().map(|(h, _)| h).collect()
    }

    async fn calculate_host_priority(&self, host: &HostKnowledge) -> f32 {
        let mut score = host.open_ports.len() as f32 * 0.5;
        let high_value = ["ssh", "rdp", "smb", "winrm", "http", "https"];
        for svc in &host.services {
            if high_value.contains(&svc.as_str()) {
                score += 2.0;
            }
        }
        if let Some(os) = &host.os {
            let os_l = os.to_lowercase();
            if os_l.contains("windows") {
                score += 1.5;
            }
            if os_l.contains("server") {
                score += 1.0;
            }
        }
        for tag in &host.tags {
            match tag.as_str() {
                "gw-candidate" => score += 0.8,
                "private" => score += 0.2,
                _ => {}
            }
        }
        score
    }

    async fn scan_host(&self, host: &HostKnowledge) -> Result<ScanResult> {
        use crate::scanner::{extract_version, grab_http_banner, grab_tcp_banner, port_to_service};
        use std::time::Duration;

        let default_ports: Vec<u16> = if self.config.aggressive_mode {
            vec![
                21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993,
                995, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5985, 5986, 6379, 8000, 8080, 8443,
                8888, 9200, 27017,
            ]
        } else {
            vec![
                21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 1433, 3306, 3389,
                5432, 6379, 8080, 8443, 27017,
            ]
        };

        let mut open_ports: Vec<u16> = Vec::new();
        let mut services: Vec<String> = Vec::new();
        let mut risk_acc = 0.0f32;

        let conn_timeout = if self.config.stealth_mode {
            Duration::from_millis(900)
        } else {
            Duration::from_millis(400)
        };

        for port in default_ports {
            let addr = format!("{}:{}", host.ip, port);
            let connected =
                tokio::time::timeout(conn_timeout, tokio::net::TcpStream::connect(&addr))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false);

            if !connected {
                continue;
            }

            open_ports.push(port);
            let svc = port_to_service(port).to_string();

            // Grab banner using the actual scanner API signatures
            let _banner: String = if matches!(svc.as_str(), "http" | "https") {
                let url = format!("{}://{}:{}", svc, host.ip, port);
                match tokio::time::timeout(Duration::from_secs(3), grab_http_banner(&url, 2, false))
                    .await
                {
                    Ok(Ok(b)) => b.banner.unwrap_or_default(),
                    _ => String::new(),
                }
            } else {
                match tokio::time::timeout(
                    Duration::from_secs(3),
                    grab_tcp_banner(&host.ip, port, 2),
                )
                .await
                {
                    Ok(Ok(b)) => b.banner.unwrap_or_default(),
                    _ => String::new(),
                }
            };

            let _version = extract_version(&svc, &_banner);
            if !svc.is_empty() && !services.contains(&svc) {
                services.push(svc.clone());
            }

            if [
                22u16, 445, 3389, 5985, 5986, 135, 139, 3306, 5432, 6379, 27017, 1433, 1521,
            ]
            .contains(&port)
            {
                risk_acc += 1.5;
            } else if [80u16, 443, 8080, 8443].contains(&port) {
                risk_acc += 1.0;
            } else {
                risk_acc += 0.5;
            }
        }

        Ok(ScanResult {
            services,
            open_ports,
            risk_score: (risk_acc / 3.0).min(10.0),
        })
    }

    async fn analyze_host_vulnerabilities(
        &self,
        host: &HostKnowledge,
    ) -> Result<Vec<VulnerabilityInfo>> {
        use crate::cve::{find_cves_for_version, load_cve_db, CveDatabase};

        let mut out = Vec::new();

        // Build version map from knowledge base service patterns
        let versions_map: HashMap<String, String> = {
            let kb = self.knowledge_base.read().await;
            host.services
                .iter()
                .filter_map(|svc| {
                    kb.service_patterns
                        .get(svc)
                        .filter(|p| !p.version.is_empty())
                        .map(|p| (svc.clone(), p.version.clone()))
                })
                .collect()
        };

        if versions_map.is_empty() {
            // No version info — flag high-value services for manual review
            let high = [
                "ssh", "smb", "rdp", "winrm", "ftp", "telnet", "mssql", "mysql", "postgres",
                "mongodb", "redis", "http", "https",
            ];
            for svc in &host.services {
                if high.contains(&svc.as_str()) {
                    out.push(VulnerabilityInfo {
                        cve: format!("MANUAL-{}-REVIEW", svc.to_uppercase()),
                        description: format!(
                            "Service '{}' exposed; manual review required for known CVEs and default credentials", svc
                        ),
                        severity: 5.0,
                        exploit_available: false,
                    });
                }
            }
            return Ok(out);
        }

        // load_cve_db is synchronous. Le chemin est résolu comme pour le reste
        // du binaire (relatif au CWD puis depuis le répertoire de l'exécutable
        // en remontant) : un chemin nu laissait la corrélation CVE muette dès
        // que le processus tournait hors du répertoire du projet.
        let cve_db: Option<CveDatabase> =
            load_cve_db(&crate::resolve_config_path("cve_db.json")).ok();
        if let Some(ref db) = cve_db {
            for (svc, ver) in &versions_map {
                // find_cves_for_version returns Vec<(String, f32, String, String)>
                // tuple fields: (cve_id, severity, description, vector)
                // L'ordre est déjà priorisé KEV/exploit-public ; on le conserve.
                for (cve_id, severity, description, _vector) in find_cves_for_version(db, svc, ver)
                {
                    let exploit_available = crate::cve::lookup_cve(db, &cve_id)
                        .map(|e| e.exploit_public || e.kev)
                        .unwrap_or(false);
                    out.push(VulnerabilityInfo {
                        cve: cve_id,
                        description,
                        severity,
                        exploit_available,
                    });
                }
            }
        }

        // Ne PAS écraser la priorisation : exploit disponible d'abord, puis sévérité.
        out.sort_by(|a, b| {
            b.exploit_available.cmp(&a.exploit_available).then(
                b.severity
                    .partial_cmp(&a.severity)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        });
        Ok(out)
    }

    async fn calculate_confidence_score(&self) -> f32 {
        let state = self.state.read().await;
        if state.targets_discovered == 0 {
            return 0.0;
        }
        let scan_coverage = state.targets_scanned as f32 / state.targets_discovered as f32;
        let exploitation_rate = if state.targets_scanned > 0 {
            state.targets_exploitable as f32 / state.targets_scanned as f32
        } else {
            0.0
        };
        (scan_coverage * 0.6 + exploitation_rate * 0.4) * 100.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub services: Vec<String>,
    pub open_ports: Vec<u16>,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub cve: String,
    pub description: String,
    pub severity: f32,
    pub exploit_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CampaignReport {
    pub phases: Vec<PhaseReport>,
    pub total_duration_ms: u128,
    pub started_at: String,
    pub completed_at: String,
}

impl CampaignReport {
    pub fn new() -> Self {
        Self {
            phases: Vec::new(),
            total_duration_ms: 0,
            started_at: chrono::Utc::now().to_rfc3339(),
            completed_at: String::new(),
        }
    }

    pub fn add_phase(&mut self, _name: &str, report: PhaseReport) {
        self.phases.push(report);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseReport {
    pub name: String,
    pub metrics: HashMap<String, i32>,
    pub duration_ms: u128,
    pub findings: Vec<String>,
}

impl PhaseReport {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            metrics: HashMap::new(),
            duration_ms: 0,
            findings: Vec::new(),
        }
    }

    pub fn add_metric(&mut self, key: &str, value: i32) {
        self.metrics.insert(key.to_string(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_discovery_agent_creation() {
        let config = DiscoveryAgentConfig::default();
        let agent = DiscoveryAgent::new(config, None);
        assert!(agent.is_ok());
    }
}
