//! DIAPILE — Web Analysis Agent
//!
//! Agent dédié à l'analyse web : crawl de surface (spider), empreinte,
//! énumération des paramètres/formulaires/endpoints et détection des
//! vulnérabilités d'injection. Il consomme un `AgentBrief` borné et rend un
//! `AgentReport` — il n'écrit jamais dans la mémoire de campagne et ne déclenche
//! aucune exploitation (celle-ci reste pilotée par l'orchestrateur).
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
#![allow(dead_code)]

use crate::agents::{AgentBrief, AgentReport, AgentRole};
use crate::web_attack::{full_web_scan, WebAttackConfig};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAnalysisAgentConfig {
    /// HTTP Request Smuggling — opt-in (sonde lente, confiance faible).
    pub test_smuggling: bool,
    /// Crawl multi-pages pour la découverte de surface.
    pub spider: bool,
    pub max_pages: usize,
    pub max_depth: usize,
}

impl Default for WebAnalysisAgentConfig {
    fn default() -> Self {
        Self {
            test_smuggling: false,
            spider: true,
            max_pages: 30,
            max_depth: 3,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WebAnalysisAgent
// ─────────────────────────────────────────────────────────────────────────────

pub struct WebAnalysisAgent {
    config: WebAnalysisAgentConfig,
}

impl WebAnalysisAgent {
    pub fn new(config: WebAnalysisAgentConfig) -> Self {
        Self { config }
    }

    /// Analyse la surface web d'une cible et remonte le résultat normalisé.
    ///
    /// Le rapport expose des marqueurs **typés** que l'orchestrateur consomme
    /// pour la phase d'exploitation :
    /// - `endpoint:<url>` / `form:<method>:<action>:<inputs>`
    /// - `web_vuln:<severity>:<type>:<param>:<evidence>`
    /// - `sqli_candidate:<param>:<type>` / `lfi_candidate:<param>`
    /// - `web_secret:<provider>:<kind>:from=<source>` (+ valeur brute dans `credentials`)
    pub async fn run(&self, brief: &AgentBrief) -> AgentReport {
        let url = if brief.target.starts_with("http") {
            brief.target.clone()
        } else {
            format!("http://{}", brief.target)
        };

        let mut report = AgentReport::new(AgentRole::Web, url.clone(), String::new());

        let mut cfg = WebAttackConfig::default();
        cfg.spider = self.config.spider;
        cfg.max_pages = self.config.max_pages;
        cfg.max_depth = self.config.max_depth;
        cfg.test_smuggling = self.config.test_smuggling;

        println!(
            "   🌐 [WEB-ANALYSIS-AGENT] Analyse de {} — objectif={}",
            url, brief.objective
        );
        let scan = full_web_scan(&url, &cfg).await;

        let crit = scan
            .vulns
            .iter()
            .filter(|v| v.severity == "CRITICAL")
            .count();
        let high = scan.vulns.iter().filter(|v| v.severity == "HIGH").count();

        // ── Surface : endpoints et formulaires ───────────────────────────────
        for e in &scan.endpoints {
            report.findings.push(format!("endpoint:{}", e));
        }
        for f in &scan.forms {
            report.findings.push(format!(
                "form:{}:{}:{}",
                f.method,
                f.action,
                f.inputs.join(",")
            ));
        }

        // ── Vulnérabilités + candidats d'exploitation ────────────────────────
        for v in &scan.vulns {
            report.findings.push(format!(
                "web_vuln:{}:{}:{}:{}",
                v.severity,
                v.vuln_type,
                v.parameter,
                v.evidence.chars().take(200).collect::<String>()
            ));
            let vt = v.vuln_type.to_lowercase();
            if vt.contains("sql") {
                report
                    .findings
                    .push(format!("sqli_candidate:{}:{}", v.parameter, v.vuln_type));
            }
            if vt.contains("lfi") || vt.contains("path traversal") || vt.contains("file inclusion")
            {
                report
                    .findings
                    .push(format!("lfi_candidate:{}", v.parameter));
            }
        }

        // ── Secrets chaînés (SSRF → métadonnées cloud) ───────────────────────
        // La valeur brute n'apparaît jamais dans les findings (qui sont loggés) :
        // elle voyage dans `credentials`, promue puis masquée par l'orchestrateur.
        for s in &scan.secrets {
            report.findings.push(format!(
                "web_secret:{}:{}:from={}",
                s.provider, s.kind, s.source
            ));
            report.credentials.push((
                normalize_host(&url),
                format!("{}/{}", s.provider, s.kind),
                s.value.clone(),
            ));
        }

        report.summary = format!(
            "Analyse web {} — {} page(s), {} endpoint(s), {} formulaire(s), {} vuln(s) ({} CRITICAL, {} HIGH), {} secret(s)",
            url,
            scan.pages_tested,
            scan.endpoints.len(),
            scan.forms.len(),
            scan.vulns.len(),
            crit,
            high,
            scan.secrets.len()
        );

        report
    }
}

/// `http://host:port/path` → `host`
fn normalize_host(url: &str) -> String {
    let rest = url.splitn(2, "://").nth(1).unwrap_or(url);
    let hostport = rest.split('/').next().unwrap_or(rest);
    hostport.split(':').next().unwrap_or(hostport).to_string()
}
