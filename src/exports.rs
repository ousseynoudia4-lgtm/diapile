//! Report export — JSON, CSV, standalone HTML (DIAPILE-branded dark theme)

use crate::cve::CveEntry;
use crate::flows::FlowLink;
use serde::{Deserialize, Serialize};
use std::io::Write;

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
    Csv,
    Html,
}

#[derive(Debug, Serialize)]
pub struct ApiReport {
    pub scan_id: String,
    pub timestamp: String,
    pub target: String,
    pub summary: ScanSummary,
    pub hosts: Vec<HostReport>,
    pub vulnerabilities: Vec<VulnerabilityReport>,
    pub flows: Vec<FlowReport>,
    pub risks: Vec<RiskReport>,
}

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub total_hosts: usize,
    pub total_ports: usize,
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub overall_risk_score: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostReport {
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub ports: Vec<PortReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortReport {
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VulnerabilityReport {
    pub cve_id: String,
    pub cvss_score: f32,
    pub severity: String,
    pub affected_hosts: Vec<String>,
    pub description: String,
    pub references: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct FlowReport {
    pub source: String,
    pub target: String,
    pub link_type: String,
    pub weight: f64,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub label: String,
}

#[derive(Debug, Serialize)]
pub struct RiskReport {
    pub host: String,
    pub risk_score: i32,
    pub risk_level: String,
    pub factors: Vec<String>,
    pub recommendations: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder
// ─────────────────────────────────────────────────────────────────────────────

pub fn generate_api_report(
    scan_id: &str,
    target: &str,
    hosts: &[HostReport],
    cve_entries: &[CveEntry],
    risk_evals: &[(String, i32, Vec<String>)],
    flows: &[FlowLink],
) -> ApiReport {
    let mut vulnerabilities = Vec::new();
    let mut critical_count = 0usize;
    let mut high_count = 0usize;
    let mut medium_count = 0usize;
    let mut low_count = 0usize;

    for cve in cve_entries {
        let severity = match cve.severity {
            s if s >= 9.0 => {
                critical_count += 1;
                "CRITICAL"
            }
            s if s >= 7.0 => {
                high_count += 1;
                "HIGH"
            }
            s if s >= 4.0 => {
                medium_count += 1;
                "MEDIUM"
            }
            _ => {
                low_count += 1;
                "LOW"
            }
        };
        vulnerabilities.push(VulnerabilityReport {
            cve_id: cve.cve.clone(),
            cvss_score: cve.severity,
            severity: severity.into(),
            affected_hosts: vec![target.to_string()],
            description: cve.desc.clone(),
            references: vec![cve.vector.clone()],
        });
    }

    let flow_reports = flows
        .iter()
        .map(|f| FlowReport {
            source: f.source.clone(),
            target: f.target.clone(),
            link_type: f.link_type.clone(),
            weight: *f.weight,
            src_port: f.src_port,
            dst_port: f.dst_port,
            label: f.label.clone(),
        })
        .collect();

    let risk_reports = risk_evals
        .iter()
        .map(|(host, score, factors)| {
            let level = match score {
                s if *s >= 8 => "CRITICAL",
                s if *s >= 6 => "HIGH",
                s if *s >= 4 => "MEDIUM",
                _ => "LOW",
            };
            RiskReport {
                host: host.clone(),
                risk_score: *score,
                risk_level: level.into(),
                factors: factors.clone(),
                recommendations: vec!["Review and remediate identified risks".into()],
            }
        })
        .collect();

    let total_ports = hosts.iter().map(|h| h.ports.len()).sum();
    let overall_risk = if risk_evals.is_empty() {
        0.0
    } else {
        risk_evals.iter().map(|(_, s, _)| *s as f32).sum::<f32>() / risk_evals.len() as f32
    };

    ApiReport {
        scan_id: scan_id.into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        target: target.into(),
        summary: ScanSummary {
            total_hosts: hosts.len(),
            total_ports,
            total_vulnerabilities: cve_entries.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            overall_risk_score: overall_risk,
        },
        hosts: hosts.to_vec(),
        vulnerabilities,
        flows: flow_reports,
        risks: risk_reports,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// File writers
// ─────────────────────────────────────────────────────────────────────────────

pub fn export_json(report: &ApiReport, path: &str) -> Result<(), std::io::Error> {
    let json = serde_json::to_string_pretty(report)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let mut f = std::fs::File::create(path)?;
    f.write_all(json.as_bytes())
}

pub fn export_csv(hosts: &[HostReport], path: &str) -> Result<(), std::io::Error> {
    let mut f = std::fs::File::create(path)?;
    writeln!(f, "IP,Port,Protocol,Service,Version,Banner")?;
    for host in hosts {
        for p in &host.ports {
            writeln!(
                f,
                "{},{},{},{},{},\"{}\"",
                host.ip,
                p.port,
                p.protocol,
                p.service,
                p.version.as_deref().unwrap_or(""),
                p.banner.as_deref().unwrap_or("").replace('"', "'"),
            )?;
        }
    }
    Ok(())
}

pub fn export_html(report: &ApiReport, path: &str) -> Result<(), std::io::Error> {
    let html = generate_html_report(report);
    let mut f = std::fs::File::create(path)?;
    f.write_all(html.as_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// DIAPILE standalone HTML report (dark cyberpunk theme, no CDN)
// ─────────────────────────────────────────────────────────────────────────────

fn risk_color_css(score: f32) -> (&'static str, &'static str) {
    // (bg, text)
    match score as u32 {
        9..=10 | 8 => ("#7f1d1d", "#fca5a5"), // critical — deep red
        7 => ("#7c2d12", "#fdba74"),          // high     — orange
        5 | 6 => ("#713f12", "#fde047"),      // medium   — amber
        _ => ("#14532d", "#86efac"),          // low      — green
    }
}

fn sev_badge(sev: &str) -> String {
    let (bg, fg) = match sev {
        "CRITICAL" => ("#dc2626", "#fff"),
        "HIGH" => ("#ea580c", "#fff"),
        "MEDIUM" => ("#ca8a04", "#fff"),
        _ => ("#16a34a", "#fff"),
    };
    format!(
        r#"<span style="background:{bg};color:{fg};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.5px;">{sev}</span>"#
    )
}

fn generate_html_report(report: &ApiReport) -> String {
    let risk = report.summary.overall_risk_score;
    let (risk_bg, risk_fg) = risk_color_css(risk);
    let _ = risk_bg; // used in stat card only, not in main format string

    // ── DIAPILE ASCII fire demon (inline SVG-like text art) ─────────────────
    let demon = r#"
      ██████╗ ██╗ █████╗ ██████╗ ██╗██╗     ███████╗
      ██╔══██╗██║██╔══██╗██╔══██╗██║██║     ██╔════╝
      ██║  ██║██║███████║██████╔╝██║██║     █████╗
      ██║  ██║██║██╔══██║██╔═══╝ ██║██║     ██╔══╝
      ██████╔╝██║██║  ██║██║     ██║███████╗███████╗
      ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝"#;

    // ── Summary cards ────────────────────────────────────────────────────────
    let cards = format!(
        r#"
      <div class="cards">
        {card}
        {card2}
        {card3}
        {card4}
        {card5}
        {card6}
      </div>"#,
        card = stat_card(
            "🖥️",
            "Hosts",
            &report.summary.total_hosts.to_string(),
            "#22d3ee",
            "#0e7490"
        ),
        card2 = stat_card(
            "🔌",
            "Open Ports",
            &report.summary.total_ports.to_string(),
            "#a78bfa",
            "#5b21b6"
        ),
        card3 = stat_card(
            "🔓",
            "CVEs",
            &report.summary.total_vulnerabilities.to_string(),
            "#f87171",
            "#991b1b"
        ),
        card4 = stat_card(
            "🔴",
            "Critical",
            &report.summary.critical_count.to_string(),
            "#f87171",
            "#7f1d1d"
        ),
        card5 = stat_card(
            "🟠",
            "High",
            &report.summary.high_count.to_string(),
            "#fb923c",
            "#7c2d12"
        ),
        card6 = stat_card(
            "⚡",
            "Risk Score",
            &format!("{:.1}/10", risk),
            risk_fg,
            risk_bg
        ),
    );

    // ── Host table rows ───────────────────────────────────────────────────────
    let host_rows: String = report
        .hosts
        .iter()
        .map(|h| {
            let ports_str = h
                .ports
                .iter()
                .map(|p| {
                    format!(
                        r#"<span class="badge">{}/{}</span>"#,
                        p.port,
                        p.version.as_deref().unwrap_or(&p.service)
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            let banners: String = h
                .ports
                .iter()
                .filter_map(|p| p.banner.as_ref())
                .take(3)
                .map(|b| format!(r#"<code class="banner-code">{}</code>"#, html_escape(b)))
                .collect::<Vec<_>>()
                .join("<br>");
            let os = h.os.as_deref().unwrap_or("Unknown");
            format!(
                r#"<tr>
          <td class="mono bright">{ip}</td>
          <td>{os}</td>
          <td class="wrap-badges">{ports}</td>
          <td class="banner-cell">{banners}</td>
        </tr>"#,
                ip = h.ip,
                os = os,
                ports = ports_str,
                banners = banners
            )
        })
        .collect();

    // ── CVE table rows ────────────────────────────────────────────────────────
    let vuln_rows: String = {
        let mut sorted = report.vulnerabilities.iter().collect::<Vec<_>>();
        sorted.sort_by(|a, b| {
            b.cvss_score
                .partial_cmp(&a.cvss_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.iter().map(|v| {
            let desc = if v.description.len() > 90 {
                format!("{}…", &v.description[..90])
            } else { v.description.clone() };
            format!(r#"<tr>
              <td class="mono bright"><a class="nvd-link" href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank">{cve}</a></td>
              <td>{badge}</td>
              <td class="mono">{cvss:.1}</td>
              <td class="dim" title="{full}">{desc}</td>
            </tr>"#,
                cve   = v.cve_id,
                badge = sev_badge(&v.severity),
                cvss  = v.cvss_score,
                full  = html_escape(&v.description),
                desc  = html_escape(&desc),
            )
        }).collect()
    };

    // ── Risk table rows ───────────────────────────────────────────────────────
    let risk_rows: String = {
        let mut sorted = report.risks.iter().collect::<Vec<_>>();
        sorted.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
        sorted.iter().map(|r| {
            let (bg, fg) = risk_color_css(r.risk_score as f32);
            let factors = r.factors.iter()
                .map(|f| format!(r#"<li>{}</li>"#, html_escape(f)))
                .collect::<Vec<_>>()
                .join("");
            format!(r#"<tr>
              <td class="mono bright">{host}</td>
              <td><span style="background:{bg};color:{fg};padding:2px 10px;border-radius:4px;font-weight:700;">{score}/10</span></td>
              <td>{level}</td>
              <td><ul class="factor-list">{factors}</ul></td>
            </tr>"#,
                host   = r.host,
                bg = bg, fg = fg,
                score  = r.risk_score,
                level  = sev_badge(&r.risk_level),
                factors = factors,
            )
        }).collect()
    };

    // ── Network flow rows ─────────────────────────────────────────────────────
    let flow_rows: String = report
        .flows
        .iter()
        .take(50)
        .map(|f| {
            format!(
                r#"<tr>
          <td class="mono">{src}</td>
          <td class="mono">{dst}</td>
          <td><span class="badge">{t}</span></td>
          <td class="mono dim">{w:.2}</td>
        </tr>"#,
                src = f.source,
                dst = f.target,
                t = f.link_type,
                w = f.weight
            )
        })
        .collect();

    let flow_section = if report.flows.is_empty() {
        String::new()
    } else {
        format!(
            r#"
    <section class="card">
      <h2>🌐 Network Flows <span class="count">({n})</span></h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Source</th><th>Destination</th><th>Type</th><th>Weight</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </section>"#,
            n = report.flows.len(),
            rows = flow_rows
        )
    };

    // ── Timestamp & scan ID ───────────────────────────────────────────────────
    let ts = &report.timestamp;
    let scan_id = &report.scan_id;
    let target = &report.target;

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>DIAPILE — Red Team Report</title>
  <style>
    /* ── Reset & base ── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg:     #0a0a0f;
      --bg2:    #0f0f1a;
      --bg3:    #141428;
      --border: #1e1e3a;
      --fire1:  #ff4500;
      --fire2:  #ff6a00;
      --fire3:  #ffa500;
      --fire4:  #ffd700;
      --cyan:   #22d3ee;
      --violet: #a78bfa;
      --matrix: #00ff9c;
      --dim:    #6b7280;
      --text:   #e2e8f0;
      --mono:   'Courier New', monospace;
    }}
    html {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }}
    body {{ min-height: 100vh; padding: 0 0 60px 0; }}

    /* ── Header / banner ── */
    .site-header {{
      background: linear-gradient(180deg, #0a0010 0%, #0a0a0f 100%);
      border-bottom: 1px solid var(--border);
      padding: 28px 40px 20px;
      position: relative;
      overflow: hidden;
    }}
    .site-header::before {{
      content: '';
      position: absolute; inset: 0;
      background: radial-gradient(ellipse 60% 80% at 50% -20%, rgba(255,69,0,.18) 0%, transparent 70%);
      pointer-events: none;
    }}
    .demon-art {{
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.3;
      white-space: pre;
      background: linear-gradient(135deg, var(--fire1), var(--fire2), var(--fire3), var(--fire4));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      margin-bottom: 12px;
    }}
    .site-title {{
      font-size: 28px;
      font-weight: 800;
      letter-spacing: 2px;
      background: linear-gradient(90deg, var(--fire1) 0%, var(--fire3) 50%, var(--fire4) 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }}
    .site-subtitle {{ color: var(--dim); font-size: 13px; margin-top: 4px; }}
    .meta-row {{ display: flex; gap: 24px; margin-top: 14px; flex-wrap: wrap; }}
    .meta-chip {{
      background: var(--bg3);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 4px 12px;
      font-size: 12px;
      font-family: var(--mono);
      color: var(--cyan);
    }}
    .meta-chip span {{ color: var(--dim); margin-right: 6px; }}

    /* ── Layout ── */
    .main {{ max-width: 1300px; margin: 0 auto; padding: 32px 24px; }}
    section.card {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 28px;
      overflow: hidden;
    }}
    section.card h2 {{
      font-size: 15px;
      font-weight: 700;
      letter-spacing: .5px;
      padding: 14px 20px;
      border-bottom: 1px solid var(--border);
      background: var(--bg3);
      color: var(--text);
    }}
    .count {{ color: var(--dim); font-weight: 400; font-size: 13px; }}

    /* ── Stat cards ── */
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }}
    .stat-card {{
      border-radius: 10px;
      padding: 18px 20px;
      border: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      gap: 6px;
    }}
    .stat-icon {{ font-size: 22px; }}
    .stat-label {{ font-size: 11px; letter-spacing: .5px; text-transform: uppercase; opacity: .7; }}
    .stat-value {{ font-size: 28px; font-weight: 800; font-family: var(--mono); }}

    /* ── Tables ── */
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; }}
    thead tr {{ background: var(--bg3); }}
    th {{ padding: 10px 16px; text-align: left; font-size: 11px; letter-spacing: .5px; text-transform: uppercase; color: var(--dim); border-bottom: 1px solid var(--border); }}
    td {{ padding: 10px 16px; border-bottom: 1px solid #1a1a2e; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: rgba(255,255,255,.025); }}

    /* ── Typography helpers ── */
    .mono   {{ font-family: var(--mono); font-size: 12px; }}
    .bright {{ color: var(--cyan); }}
    .dim    {{ color: var(--dim); font-size: 12px; }}
    .wrap-badges {{ max-width: 320px; line-height: 2; }}

    /* ── Badges ── */
    .badge {{
      display: inline-block;
      background: rgba(34,211,238,.12);
      color: var(--cyan);
      border: 1px solid rgba(34,211,238,.25);
      border-radius: 4px;
      padding: 1px 7px;
      font-size: 11px;
      font-family: var(--mono);
      margin: 1px;
    }}

    /* ── Banner code ── */
    .banner-code {{
      display: block;
      font-family: var(--mono);
      font-size: 11px;
      color: var(--matrix);
      opacity: .75;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 360px;
    }}
    .banner-cell {{ max-width: 380px; }}

    /* ── CVE links ── */
    .nvd-link {{ color: var(--cyan); text-decoration: none; }}
    .nvd-link:hover {{ text-decoration: underline; color: var(--fire3); }}

    /* ── Factor list ── */
    .factor-list {{ list-style: none; padding: 0; }}
    .factor-list li::before {{ content: "▸ "; color: var(--fire2); }}
    .factor-list li {{ font-size: 12px; color: var(--dim); }}

    /* ── Footer ── */
    footer {{
      text-align: center;
      padding: 28px;
      color: var(--dim);
      font-size: 12px;
      border-top: 1px solid var(--border);
    }}
    footer strong {{ color: var(--fire3); }}

    /* ── Progress bar (risk gauge) ── */
    .risk-bar-wrap {{ padding: 16px 20px 20px; }}
    .risk-label {{ font-size: 12px; color: var(--dim); margin-bottom: 6px; }}
    .risk-bar-bg {{
      height: 10px;
      background: #1e1e3a;
      border-radius: 99px;
      overflow: hidden;
    }}
    .risk-bar-fill {{
      height: 100%;
      border-radius: 99px;
      background: linear-gradient(90deg, #16a34a 0%, #ca8a04 40%, #ea580c 70%, #dc2626 100%);
      transition: width .6s ease;
    }}
    .sev-row {{ display: flex; gap: 8px; padding: 10px 20px 14px; flex-wrap: wrap; }}

    @media (max-width: 640px) {{
      .demon-art {{ font-size: 7px; }}
      .site-title {{ font-size: 20px; }}
      .cards {{ grid-template-columns: repeat(2, 1fr); }}
    }}
  </style>
</head>
<body>

<!-- ═══════════════════════════════════ HEADER ═══════════════════════════════ -->
<header class="site-header">
  <div class="demon-art">{demon}</div>
  <div class="site-title">D I A P I L E</div>
  <div class="site-subtitle">Network Redteam Grapher — AI-Powered Offensive Security Framework</div>
  <div class="meta-row">
    <div class="meta-chip"><span>TARGET</span>{target}</div>
    <div class="meta-chip"><span>SCAN ID</span>{scan_id}</div>
    <div class="meta-chip"><span>DATE</span>{ts}</div>
  </div>
</header>

<!-- ═══════════════════════════════════ MAIN ════════════════════════════════ -->
<main class="main">

  <!-- Risk gauge -->
  <section class="card">
    <h2>⚡ Overall Risk Score</h2>
    <div class="risk-bar-wrap">
      <div class="risk-label">Score: <strong style="color:{risk_fg}">{risk:.1} / 10</strong></div>
      <div class="risk-bar-bg">
        <div class="risk-bar-fill" style="width:{risk_pct}%"></div>
      </div>
    </div>
    <div class="sev-row">
      <span>{badge_crit}</span>&nbsp;{crit} Critical &nbsp;
      <span>{badge_high}</span>&nbsp;{high} High &nbsp;
      <span>{badge_med}</span>&nbsp;{med} Medium &nbsp;
      <span>{badge_low}</span>&nbsp;{low} Low
    </div>
  </section>

  <!-- Summary cards -->
  {cards}

  <!-- Hosts -->
  <section class="card">
    <h2>🖥️ Discovered Hosts <span class="count">({host_count})</span></h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>IP / Host</th><th>OS</th><th>Ports / Services</th><th>Banner</th></tr></thead>
        <tbody>{host_rows}</tbody>
      </table>
    </div>
  </section>

  <!-- CVEs -->
  <section class="card">
    <h2>🔓 Vulnerabilities (CVEs) <span class="count">({vuln_count})</span></h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Description</th></tr></thead>
        <tbody>{vuln_rows}</tbody>
      </table>
    </div>
  </section>

  <!-- Risk breakdown -->
  <section class="card">
    <h2>⚠️ Risk Breakdown by Host</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Host</th><th>Score</th><th>Level</th><th>Risk Factors</th></tr></thead>
        <tbody>{risk_rows}</tbody>
      </table>
    </div>
  </section>

  <!-- Flows (optional) -->
  {flow_section}

</main>

<footer>
  Generated by <strong>DIAPILE</strong> — Network Redteam Grapher &nbsp;|&nbsp;
  <strong>FOR AUTHORIZED RED TEAM ENGAGEMENTS ONLY</strong> &nbsp;|&nbsp;
  MIT License
</footer>

</body>
</html>"##,
        demon = demon,
        target = html_escape(target),
        scan_id = html_escape(scan_id),
        ts = html_escape(ts),
        risk = risk,
        risk_pct = ((risk / 10.0) * 100.0).clamp(0.0, 100.0),
        risk_fg = risk_fg,
        badge_crit = sev_badge("CRITICAL"),
        badge_high = sev_badge("HIGH"),
        badge_med = sev_badge("MEDIUM"),
        badge_low = sev_badge("LOW"),
        crit = report.summary.critical_count,
        high = report.summary.high_count,
        med = report.summary.medium_count,
        low = report.summary.low_count,
        cards = cards,
        host_count = report.hosts.len(),
        host_rows = host_rows,
        vuln_count = report.vulnerabilities.len(),
        vuln_rows = vuln_rows,
        risk_rows = risk_rows,
        flow_section = flow_section,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn stat_card(icon: &str, label: &str, value: &str, fg: &str, bg: &str) -> String {
    format!(
        r#"<div class="stat-card" style="background:{bg}22;border-color:{bg}55;">
      <div class="stat-icon">{icon}</div>
      <div class="stat-label">{label}</div>
      <div class="stat-value" style="color:{fg};">{value}</div>
    </div>"#
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_report() -> ApiReport {
        ApiReport {
            scan_id: "test-001".into(),
            timestamp: "2026-08-29T12:00:00Z".into(),
            target: "192.168.1.0/24".into(),
            summary: ScanSummary {
                total_hosts: 2,
                total_ports: 4,
                total_vulnerabilities: 1,
                critical_count: 1,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                overall_risk_score: 8.5,
            },
            hosts: vec![HostReport {
                ip: "192.168.1.1".into(),
                hostname: None,
                os: Some("Linux/Unix".into()),
                ports: vec![PortReport {
                    port: 22,
                    protocol: "tcp".into(),
                    service: "ssh".into(),
                    version: Some("7.2".into()),
                    banner: Some("SSH-2.0-OpenSSH_7.2p2".into()),
                }],
            }],
            vulnerabilities: vec![VulnerabilityReport {
                cve_id: "CVE-2016-6515".into(),
                cvss_score: 7.8,
                severity: "HIGH".into(),
                affected_hosts: vec!["192.168.1.1".into()],
                description: "OpenSSH 7.2 denial of service via crafted auth requests".into(),
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2016-6515".into()],
            }],
            flows: vec![],
            risks: vec![RiskReport {
                host: "192.168.1.1".into(),
                risk_score: 4,
                risk_level: "MEDIUM".into(),
                factors: vec!["SSH exposed".into(), "Old OpenSSH version".into()],
                recommendations: vec!["Upgrade OpenSSH".into()],
            }],
        }
    }

    #[test]
    fn test_html_contains_diapile() {
        let html = generate_html_report(&dummy_report());
        assert!(html.contains("DIAPILE"));
        assert!(html.contains("192.168.1.1"));
        assert!(html.contains("CVE-2016-6515"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("Tom & Jerry"), "Tom &amp; Jerry");
    }

    #[test]
    fn test_sev_badge_critical() {
        let b = sev_badge("CRITICAL");
        assert!(b.contains("CRITICAL"));
        assert!(b.contains("#dc2626"));
    }

    #[test]
    fn test_export_json_roundtrip() {
        let report = dummy_report();
        let tmp = std::env::temp_dir().join("diapile_test.json");
        let path = tmp.to_string_lossy().to_string();
        export_json(&report, &path).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("test-001"));
        let _ = std::fs::remove_file(&path);
    }
}
