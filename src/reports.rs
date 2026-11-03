use crate::flows::FlowLink;
use chrono::Local;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub risk: i32,
    pub services: Vec<String>,
    pub banner: String,
    pub version: String,
    pub protocol: String,
    pub product: String,
    pub cves: Vec<(String, f32, String, String)>,
    pub risk_reasons: Vec<String>,
    pub host: String,
    pub port: u16,
    pub reachable: bool,
    #[serde(default)]
    pub waf_name: Option<String>,
    #[serde(default)]
    pub waf_confidence: f32,
    #[serde(default)]
    pub waf_indicators: Vec<String>,
    #[serde(default)]
    pub os_type: Option<String>,
    #[serde(default)]
    pub os_confidence: f32,
    #[serde(default)]
    pub os_evidence: Vec<String>,
    #[serde(default)]
    pub tech_stack_web_server: Option<String>,
    #[serde(default)]
    pub tech_stack_framework: Option<String>,
    #[serde(default)]
    pub tech_stack_language: Option<String>,
    #[serde(default)]
    pub tech_stack_cms: Option<String>,
    #[serde(default)]
    pub tech_stack_js_frameworks: Vec<String>,
    #[serde(default)]
    pub missing_security_headers: Vec<String>,
    #[serde(default)]
    pub weak_headers: Vec<(String, String)>,
    #[serde(default)]
    pub insecure_cookies: Vec<String>,
    #[serde(default)]
    pub default_creds_likely: bool,
    #[serde(default)]
    pub tls_self_signed: bool,
    #[serde(default)]
    pub tls_expired: bool,
    #[serde(default)]
    pub tls_fingerprint: Option<String>,
    #[serde(default)]
    pub page_title: Option<String>,
    #[serde(default)]
    pub dns_validated: bool,
    #[serde(default)]
    pub silent_port: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanGraph {
    pub nodes: Vec<GraphNode>,
    pub links: Vec<FlowLink>,
    pub metadata: ScanMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub generated_at: String,
    pub version: String,
    pub scan_id: String,
    #[serde(default)]
    pub scope: Option<String>,
    pub total_targets: usize,
    pub total_cves: usize,
    pub risk_breakdown: [usize; 5],
    pub most_critical: Option<String>,
    pub scan_duration_ms: u128,
    #[serde(default)]
    pub pentest_summary: Option<Value>,
    #[serde(default)]
    pub ai_enriched: bool,
    #[serde(default)]
    pub ai_targets_analyzed: usize,
}

pub fn write_json(graph: &ScanGraph, path: &str) -> anyhow::Result<()> {
    let pretty = serde_json::to_string_pretty(graph)?;
    fs::write(path, pretty)?;
    Ok(())
}

pub fn write_csv(graph: &ScanGraph, path: &str) -> anyhow::Result<()> {
    let mut w = csv::Writer::from_path(path)?;
    w.write_record([
        "id",
        "host",
        "port",
        "protocol",
        "service",
        "product",
        "version",
        "risk",
        "banner",
        "reachable",
        "cve_count",
        "cve_ids",
        "cve_max_severity",
    ])?;

    for n in &graph.nodes {
        let cve_ids: Vec<String> = n.cves.iter().map(|c| c.0.clone()).collect();
        let cve_max = n.cves.iter().map(|c| c.1).fold(0.0f32, f32::max);
        w.write_record([
            n.id.as_str(),
            n.host.as_str(),
            n.port.to_string().as_str(),
            n.protocol.as_str(),
            n.services.first().map(|s| s.as_str()).unwrap_or("-"),
            n.product.as_str(),
            n.version.as_str(),
            n.risk.to_string().as_str(),
            n.banner.as_str(),
            if n.reachable { "YES" } else { "NO" },
            n.cves.len().to_string().as_str(),
            cve_ids.join(" | ").as_str(),
            format!("{:.1}", cve_max).as_str(),
        ])?;
    }
    w.flush()?;
    Ok(())
}

fn risk_label(r: i32) -> &'static str {
    match r {
        1 => "LOW",
        2 => "INFO",
        3 => "MEDIUM",
        4 => "HIGH",
        5 => "CRITICAL",
        _ => "UNKNOWN",
    }
}

fn severity_rating(s: f32) -> &'static str {
    if s >= 9.0 {
        "CRITICAL"
    } else if s >= 7.0 {
        "HIGH"
    } else if s >= 4.0 {
        "MEDIUM"
    } else if s > 0.0 {
        "LOW"
    } else {
        "NONE"
    }
}

pub fn write_markdown(graph: &ScanGraph, path: &str) -> anyhow::Result<()> {
    let meta = &graph.metadata;
    let mut md = String::new();
    md.push_str("# Network Risk Scan Report\n\n");
    md.push_str(&format!("**Generated:** {}\n\n", meta.generated_at));
    md.push_str(&format!(
        "**Tool:** network_redteam_grapher v{}\n\n",
        meta.version
    ));
    md.push_str("---\n\n");

    md.push_str("## 📊 Executive Summary\n\n");
    md.push_str(&format!("- **Targets scanned:** {}\n", meta.total_targets));
    md.push_str(&format!("- **Total CVEs found:** {}\n", meta.total_cves));
    if let Some(ref crit) = meta.most_critical {
        md.push_str(&format!("- **Most critical target:** `{}`\n", crit));
    }
    md.push_str("- **Risk breakdown:**\n");
    let labels = [
        "LOW (1)",
        "INFO (2)",
        "MEDIUM (3)",
        "HIGH (4)",
        "CRITICAL (5)",
    ];
    for (i, label) in labels.iter().enumerate() {
        md.push_str(&format!(
            "  - {}: **{}** node(s)\n",
            label, meta.risk_breakdown[i]
        ));
    }
    md.push_str(&format!(
        "\n**Scan duration:** {:.2}s\n\n",
        meta.scan_duration_ms as f64 / 1000.0
    ));
    md.push_str("---\n\n");

    md.push_str("## 🎯 Detailed Findings\n\n");

    let mut sorted_nodes: Vec<&GraphNode> = graph.nodes.iter().collect();
    sorted_nodes.sort_by(|a, b| b.risk.cmp(&a.risk));

    for node in sorted_nodes {
        let sev_emoji = match node.risk {
            5 => "🔴",
            4 => "🟠",
            3 => "🟡",
            2 => "🔵",
            _ => "🟢",
        };
        md.push_str(&format!(
            "### {} {} — Risk **{}/5** ({})\n\n",
            sev_emoji,
            node.label,
            node.risk,
            risk_label(node.risk)
        ));
        md.push_str(&format!("- **Host:** `{}:{}`\n", node.host, node.port));
        md.push_str(&format!("- **Protocol:** `{}`\n", node.protocol));
        md.push_str(&format!(
            "- **Service(s):** `{}`\n",
            node.services.join(", ")
        ));
        md.push_str(&format!(
            "- **Product/Version:** `{}` / `{}`\n",
            node.product, node.version
        ));
        md.push_str(&format!("- **Banner:** `{}`\n", node.banner));
        md.push_str(&format!(
            "- **Reachable:** {}\n",
            if node.reachable { "✅ YES" } else { "❌ NO" }
        ));
        if !node.cves.is_empty() {
            md.push_str("\n**Vulnerabilities found:**\n\n");
            md.push_str("| CVE | Severity | Rating | Description |\n");
            md.push_str("|-----|----------|--------|-------------|\n");
            for c in &node.cves {
                md.push_str(&format!(
                    "| `{}` | {:.1} | **{}** | {} |\n",
                    c.0,
                    c.1,
                    severity_rating(c.1),
                    c.2.replace('|', "\\|")
                ));
            }
            md.push('\n');
        }
        if !node.risk_reasons.is_empty() {
            md.push_str("**Risk factors:**\n\n");
            for reason in &node.risk_reasons {
                md.push_str(&format!("- {}\n", reason));
            }
            md.push('\n');
        }
        md.push_str("---\n\n");
    }

    if !graph.links.is_empty() {
        md.push_str("## 🔗 Topology Links\n\n");
        md.push_str(&format!("**Total links:** {}\n\n", graph.links.len()));
        md.push_str("| Source | Target | Type | Weight | Label |\n");
        md.push_str("|--------|--------|------|--------|-------|\n");
        let mut sorted_links: Vec<&FlowLink> = graph.links.iter().collect();
        sorted_links.sort_by(|a, b| {
            b.weight
                .partial_cmp(&a.weight)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for l in sorted_links.iter().take(50) {
            md.push_str(&format!(
                "| `{}` | `{}` | {} | {:.1} | {} |\n",
                l.source, l.target, l.link_type, l.weight, l.label
            ));
        }
        md.push('\n');
    }

    md.push_str(
        "---\n\n> ⚠️ Operational Report: Confidential - For authorized Red Team use only.\n",
    );

    fs::write(path, md)?;
    Ok(())
}

pub fn build_metadata(
    nodes: &[GraphNode],
    duration_ms: u128,
    scope: Option<String>,
) -> ScanMetadata {
    let mut risk_breakdown = [0usize; 5];
    let mut total_cves = 0usize;
    let mut most_critical: Option<(String, i32, usize)> = None;

    for n in nodes {
        let idx = ((n.risk - 1).clamp(0, 4)) as usize;
        risk_breakdown[idx] += 1;
        total_cves += n.cves.len();

        let score = (n.risk, n.cves.len());
        match most_critical {
            None => most_critical = Some((n.label.clone(), n.risk, n.cves.len())),
            Some((_, r, c)) if (n.risk, n.cves.len()) > (r, c) => {
                most_critical = Some((n.label.clone(), score.0, score.1));
            }
            _ => {}
        }
    }

    ScanMetadata {
        generated_at: Local::now().format("%Y-%m-%d %H:%M:%S %z").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        scan_id: format!("scan-{}", Uuid::new_v4()),
        scope,
        total_targets: nodes.len(),
        total_cves,
        risk_breakdown,
        most_critical: most_critical.map(|(l, _, _)| l),
        scan_duration_ms: duration_ms,
        pentest_summary: None,
        ai_enriched: false,
        ai_targets_analyzed: 0,
    }
}

#[allow(dead_code)]
pub fn graph_to_value(g: &ScanGraph) -> Value {
    serde_json::to_value(g).unwrap_or(Value::Null)
}
