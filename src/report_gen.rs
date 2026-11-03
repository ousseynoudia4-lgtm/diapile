//! DIAPILE — Générateur de rapport professionnel
//!
//! Rapport de pentest complet : executive summary, kill-chain timeline,
//! findings avec preuves, plan de remédiation. Export HTML/Markdown/JSON.
#![allow(dead_code)]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json;
use std::io::Write;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PentestReport {
    pub meta: ReportMeta,
    pub executive: ExecutiveSummary,
    pub scope: Scope,
    pub methodology: Vec<String>,
    pub timeline: Vec<TimelineEvent>,
    pub findings: Vec<Finding>,
    pub remediation: RemediationPlan,
    pub appendices: Vec<Appendix>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMeta {
    pub title: String,
    pub client: String,
    pub date: String,
    pub version: String,
    pub classification: String,
    pub authors: Vec<String>,
    pub scan_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub overall_risk: String, // CRITICAL / HIGH / MEDIUM / LOW
    pub risk_score: f32,      // 0.0–10.0
    pub summary_text: String,
    pub key_findings: Vec<String>,
    pub top_risks: Vec<String>,
    pub quick_wins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub in_scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub start_date: String,
    pub end_date: String,
    pub test_type: String, // Black Box / Grey Box / White Box
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub phase: String, // Recon / Scan / Exploit / Post-Exploit / C2
    pub description: String,
    pub target: Option<String>,
    pub technique: Option<String>, // MITRE ATT&CK technique ID
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub cvss_score: f32,
    pub cvss_vector: String,
    pub cve: Option<String>,
    pub affected: Vec<String>,
    pub description: String,
    pub impact: String,
    pub business_risk: String, // Explication business non-technique
    pub evidence: Vec<Evidence>,
    pub remediation: String,
    pub references: Vec<String>,
    pub mitre_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: String, // command / screenshot / log / network_capture
    pub description: String,
    pub content: String, // commande ou description de screenshot
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub immediate: Vec<RemAction>,   // 0-24h
    pub short_term: Vec<RemAction>,  // 1-7 jours
    pub medium_term: Vec<RemAction>, // 1-4 semaines
    pub long_term: Vec<RemAction>,   // 1-3 mois
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemAction {
    pub finding_id: String,
    pub action: String,
    pub effort: String,   // Low / Medium / High
    pub priority: String, // Critical / High / Medium / Low
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Appendix {
    pub title: String,
    pub content: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder
// ─────────────────────────────────────────────────────────────────────────────

pub struct ReportBuilder {
    report: PentestReport,
}

impl ReportBuilder {
    pub fn new(client: &str, scan_id: &str, test_type: &str) -> Self {
        let now = Utc::now();
        Self {
            report: PentestReport {
                meta: ReportMeta {
                    title: format!("Rapport de Test d'Intrusion — {}", client),
                    client: client.to_string(),
                    date: now.format("%d/%m/%Y").to_string(),
                    version: "1.0".into(),
                    classification: "CONFIDENTIEL — USAGE INTERNE".into(),
                    authors: vec!["DIAPILE Red Team".into()],
                    scan_id: scan_id.to_string(),
                },
                executive: ExecutiveSummary {
                    overall_risk: "UNKNOWN".into(),
                    risk_score: 0.0,
                    summary_text: String::new(),
                    key_findings: Vec::new(),
                    top_risks: Vec::new(),
                    quick_wins: Vec::new(),
                },
                scope: Scope {
                    in_scope: Vec::new(),
                    out_of_scope: Vec::new(),
                    start_date: now.format("%d/%m/%Y").to_string(),
                    end_date: now.format("%d/%m/%Y").to_string(),
                    test_type: test_type.to_string(),
                },
                methodology: vec![
                    "1. Reconnaissance passive (OSINT)".into(),
                    "2. Découverte des actifs (scan réseau)".into(),
                    "3. Énumération des services (fingerprinting)".into(),
                    "4. Analyse des vulnérabilités".into(),
                    "5. Exploitation (probes actifs)".into(),
                    "6. Post-exploitation et pivoting".into(),
                    "7. Rapport et recommandations".into(),
                ],
                timeline: Vec::new(),
                findings: Vec::new(),
                remediation: RemediationPlan {
                    immediate: Vec::new(),
                    short_term: Vec::new(),
                    medium_term: Vec::new(),
                    long_term: Vec::new(),
                },
                appendices: Vec::new(),
            },
        }
    }

    pub fn add_target(mut self, target: &str) -> Self {
        self.report.scope.in_scope.push(target.to_string());
        self
    }

    pub fn add_finding(mut self, finding: Finding) -> Self {
        self.report.findings.push(finding);
        self
    }

    pub fn add_event(mut self, event: TimelineEvent) -> Self {
        self.report.timeline.push(event);
        self
    }

    pub fn compute_executive_summary(mut self) -> Self {
        let findings = &self.report.findings;
        let critical = findings.iter().filter(|f| f.severity == "CRITICAL").count();
        let high = findings.iter().filter(|f| f.severity == "HIGH").count();
        let medium = findings.iter().filter(|f| f.severity == "MEDIUM").count();

        let max_cvss = findings.iter().map(|f| f.cvss_score).fold(0.0f32, f32::max);
        let overall = match max_cvss as u32 {
            9..=10 => "CRITIQUE",
            7..=8 => "ÉLEVÉ",
            4..=6 => "MODÉRÉ",
            _ => "FAIBLE",
        };

        self.report.executive.overall_risk = overall.to_string();
        self.report.executive.risk_score = max_cvss;
        self.report.executive.summary_text = format!(
            "L'évaluation de sécurité a identifié {} finding(s) au total, dont {} critique(s), {} élevé(s) et {} modéré(s). \
             Le score de risque global est de {:.1}/10, classifié {}. \
             Des actions immédiates sont requises pour les vulnérabilités critiques.",
            findings.len(), critical, high, medium, max_cvss, overall
        );

        // Key findings (top 5 by severity)
        let mut sorted = findings.clone();
        sorted.sort_by(|a, b| {
            b.cvss_score
                .partial_cmp(&a.cvss_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        self.report.executive.key_findings = sorted
            .iter()
            .take(5)
            .map(|f| {
                format!(
                    "[{}] {} — {}",
                    f.severity,
                    f.title,
                    f.affected.first().cloned().unwrap_or_default()
                )
            })
            .collect();

        // Quick wins (low effort, high impact)
        self.report.executive.quick_wins = vec![
            "Changer les mots de passe par défaut sur tous les équipements".into(),
            "Appliquer les patches de sécurité critiques en attente".into(),
            "Désactiver les services non nécessaires exposés sur le réseau".into(),
            "Activer l'authentification multi-facteur sur les accès privilégiés".into(),
        ];

        self
    }

    pub fn build(self) -> PentestReport {
        self.report
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Export Markdown (rapport texte professionnel)
// ─────────────────────────────────────────────────────────────────────────────

pub fn export_markdown(report: &PentestReport, path: &str) -> Result<(), std::io::Error> {
    let mut f = std::fs::File::create(path)?;
    let md = render_markdown(report);
    f.write_all(md.as_bytes())
}

fn render_markdown(r: &PentestReport) -> String {
    let mut out = String::new();

    // Cover
    out.push_str(&format!("# {}\n\n", r.meta.title));
    out.push_str(&format!("**Client :** {}  \n", r.meta.client));
    out.push_str(&format!("**Date :** {}  \n", r.meta.date));
    out.push_str(&format!("**Version :** {}  \n", r.meta.version));
    out.push_str(&format!(
        "**Classification :** {}  \n",
        r.meta.classification
    ));
    out.push_str(&format!("**Scan ID :** `{}`\n\n", r.meta.scan_id));
    out.push_str("---\n\n");

    // Executive Summary
    out.push_str("## 1. Résumé Exécutif\n\n");
    out.push_str(&format!(
        "**Risque global : {}** (Score : {:.1}/10)\n\n",
        r.executive.overall_risk, r.executive.risk_score
    ));
    out.push_str(&format!("{}\n\n", r.executive.summary_text));

    if !r.executive.key_findings.is_empty() {
        out.push_str("### Findings principaux\n\n");
        for f in &r.executive.key_findings {
            out.push_str(&format!("- {}\n", f));
        }
        out.push('\n');
    }

    if !r.executive.quick_wins.is_empty() {
        out.push_str("### Actions rapides recommandées\n\n");
        for q in &r.executive.quick_wins {
            out.push_str(&format!("- {}\n", q));
        }
        out.push('\n');
    }

    // Scope
    out.push_str("## 2. Périmètre\n\n");
    out.push_str(&format!("**Type de test :** {}  \n", r.scope.test_type));
    out.push_str(&format!(
        "**Période :** {} → {}\n\n",
        r.scope.start_date, r.scope.end_date
    ));
    out.push_str("### Dans le périmètre\n\n");
    for t in &r.scope.in_scope {
        out.push_str(&format!("- `{}`\n", t));
    }
    out.push('\n');

    // Methodology
    out.push_str("## 3. Méthodologie\n\n");
    for m in &r.methodology {
        out.push_str(&format!("{}\n\n", m));
    }

    // Timeline
    if !r.timeline.is_empty() {
        out.push_str("## 4. Timeline d'attaque\n\n");
        out.push_str("| Timestamp | Phase | Description | Cible | MITRE |\n");
        out.push_str("|---|---|---|---|---|\n");
        for e in &r.timeline {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                &e.timestamp[..19.min(e.timestamp.len())],
                e.phase,
                e.description,
                e.target.as_deref().unwrap_or("—"),
                e.technique.as_deref().unwrap_or("—"),
            ));
        }
        out.push('\n');
    }

    // Findings
    out.push_str("## 5. Vulnérabilités Identifiées\n\n");
    let severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    for sev in &severity_order {
        let sev_findings: Vec<_> = r
            .findings
            .iter()
            .filter(|f| f.severity.as_str() == *sev)
            .collect();
        if sev_findings.is_empty() {
            continue;
        }
        out.push_str(&format!("### {} ({})\n\n", sev, sev_findings.len()));
        for f in &sev_findings {
            let emoji = match f.severity.as_str() {
                "CRITICAL" => "🔴",
                "HIGH" => "🟠",
                "MEDIUM" => "🟡",
                _ => "🟢",
            };
            out.push_str(&format!("#### {} {} — {}\n\n", emoji, f.id, f.title));
            out.push_str(&format!(
                "**Sévérité :** {} | **CVSS :** {:.1} | **CVE :** {}\n\n",
                f.severity,
                f.cvss_score,
                f.cve.as_deref().unwrap_or("N/A")
            ));
            out.push_str(&format!(
                "**Systèmes affectés :** {}\n\n",
                f.affected.join(", ")
            ));
            out.push_str(&format!("**Description :** {}\n\n", f.description));
            out.push_str(&format!("**Impact :** {}\n\n", f.impact));
            out.push_str(&format!("**Risque business :** {}\n\n", f.business_risk));

            if !f.evidence.is_empty() {
                out.push_str("**Preuves :**\n\n");
                for e in &f.evidence {
                    out.push_str(&format!("- *{}* : `{}`\n", e.description, e.content));
                }
                out.push('\n');
            }

            out.push_str(&format!("**Remédiation :** {}\n\n", f.remediation));
            out.push_str("---\n\n");
        }
    }

    // Remediation plan
    out.push_str("## 6. Plan de Remédiation\n\n");
    let sections = [
        ("Immédiat (0-24h)", &r.remediation.immediate),
        ("Court terme (1-7 jours)", &r.remediation.short_term),
        ("Moyen terme (1-4 semaines)", &r.remediation.medium_term),
        ("Long terme (1-3 mois)", &r.remediation.long_term),
    ];
    for (title, actions) in &sections {
        if actions.is_empty() {
            continue;
        }
        out.push_str(&format!("### {}\n\n", title));
        out.push_str("| Priorité | Effort | Finding | Action |\n");
        out.push_str("|---|---|---|---|\n");
        for a in *actions {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                a.priority, a.effort, a.finding_id, a.action
            ));
        }
        out.push('\n');
    }

    // Footer
    out.push_str("---\n\n");
    out.push_str(&format!(
        "*Rapport généré par DIAPILE v2.0 — {} — CONFIDENTIEL*\n",
        r.meta.date
    ));

    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Export HTML (rapport standalone)
// ─────────────────────────────────────────────────────────────────────────────

pub fn export_html_report(report: &PentestReport, path: &str) -> Result<(), std::io::Error> {
    let html = render_html(report);
    let mut f = std::fs::File::create(path)?;
    f.write_all(html.as_bytes())
}

fn render_html(r: &PentestReport) -> String {
    let critical = r
        .findings
        .iter()
        .filter(|f| f.severity == "CRITICAL")
        .count();
    let high = r.findings.iter().filter(|f| f.severity == "HIGH").count();
    let medium = r.findings.iter().filter(|f| f.severity == "MEDIUM").count();
    let low = r.findings.iter().filter(|f| f.severity == "LOW").count();

    let findings_html: String = r
        .findings
        .iter()
        .map(|f| {
            let color = match f.severity.as_str() {
                "CRITICAL" => "#dc2626",
                "HIGH" => "#ea580c",
                "MEDIUM" => "#ca8a04",
                _ => "#16a34a",
            };
            let evidence_html: String = f
                .evidence
                .iter()
                .map(|e| {
                    format!(
                        "<div class='evidence'><strong>{}</strong><pre><code>{}</code></pre></div>",
                        e.description, e.content
                    )
                })
                .collect();

            format!(
                r#"<div class="finding">
  <div class="finding-header" style="border-left:4px solid {color}">
    <span class="sev-badge" style="background:{color}">{sev}</span>
    <h3>{id} — {title}</h3>
    <span class="cvss">CVSS {cvss:.1}</span>
  </div>
  <div class="finding-body">
    <p><strong>Systèmes :</strong> {affected}</p>
    <p><strong>Description :</strong> {desc}</p>
    <p><strong>Impact :</strong> {impact}</p>
    <p><strong>Risque Business :</strong> <em>{biz}</em></p>
    {evidence}
    <p class="remediation"><strong>Remédiation :</strong> {rem}</p>
  </div>
</div>"#,
                color = color,
                sev = f.severity,
                id = f.id,
                title = f.title,
                cvss = f.cvss_score,
                affected = f.affected.join(", "),
                desc = f.description,
                impact = f.impact,
                biz = f.business_risk,
                evidence = evidence_html,
                rem = f.remediation,
            )
        })
        .collect();

    let timeline_html: String = r.timeline.iter().map(|e| format!(
        "<div class='tl-event'><div class='tl-time'>{}</div><div class='tl-phase'>{}</div><div>{}{}</div></div>",
        &e.timestamp[..19.min(e.timestamp.len())],
        e.phase, e.description,
        e.target.as_ref().map(|t| format!(" → <code>{}</code>", t)).unwrap_or_default()
    )).collect();

    format!(
        r##"<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0a0f;color:#e2e8f0;line-height:1.6}}
  .cover{{background:linear-gradient(135deg,#0a0010,#0a0a0f);padding:60px 48px;border-bottom:1px solid #1e1e3a}}
  .fire-title{{font-size:42px;font-weight:800;letter-spacing:3px;background:linear-gradient(90deg,#ff4500,#ff8c00,#ffd700);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
  .meta-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-top:24px}}
  .meta-item{{background:#0f0f1a;border:1px solid #1e1e3a;border-radius:8px;padding:12px 16px}}
  .meta-item label{{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:#6b7280}}
  .meta-item span{{display:block;font-size:14px;font-weight:600;color:#22d3ee;margin-top:2px}}
  main{{max-width:1100px;margin:0 auto;padding:40px 24px}}
  h2{{font-size:22px;font-weight:700;margin:40px 0 16px;color:#f97316;border-bottom:1px solid #1e1e3a;padding-bottom:8px}}
  h3{{font-size:16px;font-weight:700;color:#e2e8f0;margin:24px 0 8px}}
  .risk-banner{{background:#7f1d1d;border:1px solid #dc2626;border-radius:10px;padding:20px 24px;margin:24px 0;display:flex;align-items:center;gap:20px}}
  .risk-score{{font-size:48px;font-weight:900;color:#fca5a5;font-family:monospace}}
  .risk-text p{{color:#fca5a5;font-size:15px}}
  .stat-cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}}
  .stat-card{{border-radius:8px;padding:16px;text-align:center}}
  .stat-card .num{{font-size:32px;font-weight:800;font-family:monospace}}
  .stat-card .lbl{{font-size:11px;text-transform:uppercase;opacity:.7}}
  .finding{{background:#0f0f1a;border:1px solid #1e1e3a;border-radius:10px;margin-bottom:16px;overflow:hidden}}
  .finding-header{{padding:14px 20px;background:#141428;display:flex;align-items:center;gap:12px}}
  .sev-badge{{padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;color:#fff}}
  .finding-header h3{{flex:1;font-size:15px;color:#e2e8f0}}
  .cvss{{font-family:monospace;font-size:13px;color:#f97316}}
  .finding-body{{padding:16px 20px}}
  .finding-body p{{margin-bottom:8px;font-size:14px}}
  .evidence{{background:#0a0a0f;border-radius:6px;padding:12px;margin:8px 0}}
  pre code{{font-family:monospace;font-size:12px;color:#22d3ee;white-space:pre-wrap}}
  .remediation{{color:#3bd58a!important;font-style:italic}}
  .timeline{{display:grid;gap:8px}}
  .tl-event{{display:grid;grid-template-columns:180px 100px 1fr;gap:12px;align-items:start;padding:10px 14px;background:#0f0f1a;border-radius:6px;border:1px solid #1e1e3a}}
  .tl-time{{font-family:monospace;font-size:11px;color:#6b7280}}
  .tl-phase{{font-size:11px;font-weight:700;color:#f97316}}
  footer{{text-align:center;padding:32px;color:#6b7280;font-size:12px;border-top:1px solid #1e1e3a;margin-top:60px}}
</style>
</head>
<body>
<div class="cover">
  <div class="fire-title">D I A P I L E</div>
  <div style="color:#9ca3af;margin-top:4px">Network Redteam Grapher — Rapport d'Intrusion</div>
  <div class="meta-grid">
    <div class="meta-item"><label>Client</label><span>{client}</span></div>
    <div class="meta-item"><label>Date</label><span>{date}</span></div>
    <div class="meta-item"><label>Type de test</label><span>{test_type}</span></div>
    <div class="meta-item"><label>Scan ID</label><span style="font-size:11px">{scan_id}</span></div>
    <div class="meta-item"><label>Classification</label><span>{classif}</span></div>
    <div class="meta-item"><label>Version</label><span>{version}</span></div>
  </div>
</div>

<main>
  <h2>1. Résumé Exécutif</h2>
  <div class="risk-banner">
    <div class="risk-score">{risk_score:.1}</div>
    <div class="risk-text">
      <p><strong style="font-size:20px">Risque Global : {overall_risk}</strong></p>
      <p>{summary}</p>
    </div>
  </div>

  <div class="stat-cards">
    <div class="stat-card" style="background:#7f1d1d22;border:1px solid #7f1d1d">
      <div class="num" style="color:#fca5a5">{critical}</div>
      <div class="lbl" style="color:#fca5a5">Critiques</div>
    </div>
    <div class="stat-card" style="background:#7c2d1222;border:1px solid #7c2d12">
      <div class="num" style="color:#fdba74">{high}</div>
      <div class="lbl" style="color:#fdba74">Élevés</div>
    </div>
    <div class="stat-card" style="background:#71361222;border:1px solid #713612">
      <div class="num" style="color:#fde68a">{medium}</div>
      <div class="lbl" style="color:#fde68a">Modérés</div>
    </div>
    <div class="stat-card" style="background:#14532d22;border:1px solid #14532d">
      <div class="num" style="color:#86efac">{low}</div>
      <div class="lbl" style="color:#86efac">Faibles</div>
    </div>
  </div>

  <h2>2. Vulnérabilités</h2>
  {findings}

  <h2>3. Timeline d'attaque</h2>
  <div class="timeline">{timeline}</div>

</main>

<footer>
  Généré par <strong style="color:#f97316">DIAPILE</strong> v2.0 — {date} — CONFIDENTIEL — USAGE RED TEAM AUTORISÉ UNIQUEMENT
</footer>
</body>
</html>"##,
        title = r.meta.title,
        client = r.meta.client,
        date = r.meta.date,
        test_type = r.scope.test_type,
        scan_id = r.meta.scan_id,
        classif = r.meta.classification,
        version = r.meta.version,
        risk_score = r.executive.risk_score,
        overall_risk = r.executive.overall_risk,
        summary = r.executive.summary_text,
        critical = critical,
        high = high,
        medium = medium,
        low = low,
        findings = findings_html,
        timeline = timeline_html,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: créer un finding depuis les données de scan DIAPILE
// ─────────────────────────────────────────────────────────────────────────────

pub fn finding_from_cve(
    id: &str,
    cve: &str,
    cvss: f32,
    affected: &[String],
    banner: &str,
) -> Finding {
    Finding {
        id:          id.to_string(),
        title:       format!("{} — Service vulnérable détecté", cve),
        severity:    cvss_to_severity(cvss),
        cvss_score:  cvss,
        cvss_vector: "CVSS:3.1/AV:N".into(),
        cve:         Some(cve.to_string()),
        affected:    affected.to_vec(),
        description: format!("La version du service détectée est affectée par {}.", cve),
        impact:      "Potentielle exécution de code distant ou accès non autorisé.".into(),
        business_risk: "Compromission possible des systèmes concernés pouvant impacter la confidentialité et la disponibilité des données.".into(),
        evidence:    vec![Evidence {
            evidence_type: "banner".into(),
            description:   "Banner du service détectée".into(),
            content:       banner.chars().take(200).collect(),
        }],
        remediation: format!("Appliquer le patch pour {}. Voir https://nvd.nist.gov/vuln/detail/{}", cve, cve),
        references:  vec![format!("https://nvd.nist.gov/vuln/detail/{}", cve)],
        mitre_id:    None,
    }
}

pub fn cvss_to_severity(cvss: f32) -> String {
    match cvss as u32 {
        9..=10 => "CRITICAL",
        7..=8 => "HIGH",
        4..=6 => "MEDIUM",
        _ => "LOW",
    }
    .to_string()
}

// ═════════════════════════════════════════════════════════════════════════════
// MITRE ATT&CK Mapping automatique
//
// Mappe automatiquement les types de vulnérabilités / techniques d'exploit
// vers les Technique IDs ATT&CK Enterprise v14.
// ═════════════════════════════════════════════════════════════════════════════

/// Entrée MITRE ATT&CK
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub technique_id: String,          // ex: "T1190"
    pub sub_technique: Option<String>, // ex: ".001"
    pub name: String,
    pub tactic: String, // Initial Access, Execution, etc.
    pub url: String,
    pub description: String,
    pub detection_hint: String,
}

/// Mappe un type de vulnérabilité vers les techniques ATT&CK correspondantes
pub fn map_to_attack(vuln_type: &str) -> Vec<MitreTechnique> {
    let vt = vuln_type.to_lowercase();
    let mut techniques = Vec::new();

    // ── Initial Access ────────────────────────────────────────────────────────
    if vt.contains("sqli") || vt.contains("sql injection") {
        techniques.push(MitreTechnique {
            technique_id:   "T1190".into(),
            sub_technique:  None,
            name:           "Exploit Public-Facing Application".into(),
            tactic:         "Initial Access".into(),
            url:            "https://attack.mitre.org/techniques/T1190/".into(),
            description:    "SQL Injection permet d'exploiter une application exposée pour extraire des données ou exécuter du code.".into(),
            detection_hint: "Surveiller les logs SQL pour des patterns UNION/SELECT/-- anormaux.".into(),
        });
    }
    if vt.contains("xss") {
        techniques.push(MitreTechnique {
            technique_id: "T1059".into(),
            sub_technique: Some(".007".into()),
            name: "JavaScript Execution via XSS".into(),
            tactic: "Execution".into(),
            url: "https://attack.mitre.org/techniques/T1059/007/".into(),
            description:
                "XSS permet l'exécution de JavaScript arbitraire dans le navigateur de la victime."
                    .into(),
            detection_hint: "CSP strict-mode, WAF avec règles XSS, validation côté serveur.".into(),
        });
        techniques.push(MitreTechnique {
            technique_id:   "T1185".into(),
            sub_technique:  None,
            name:           "Browser Session Hijacking".into(),
            tactic:         "Collection".into(),
            url:            "https://attack.mitre.org/techniques/T1185/".into(),
            description:    "XSS stored peut être utilisé pour voler des cookies de session ou intercepter des requêtes.".into(),
            detection_hint: "Monitorer les accès à document.cookie, les requêtes vers des domaines externes.".into(),
        });
    }
    if vt.contains("ssti") {
        techniques.push(MitreTechnique {
            technique_id: "T1190".into(),
            sub_technique: None,
            name: "Exploit Public-Facing Application (SSTI→RCE)".into(),
            tactic: "Initial Access".into(),
            url: "https://attack.mitre.org/techniques/T1190/".into(),
            description:
                "SSTI peut mener à une exécution de code côté serveur via le moteur de templates."
                    .into(),
            detection_hint:
                "Surveiller les logs applicatifs pour des expressions template dans les paramètres."
                    .into(),
        });
        techniques.push(MitreTechnique {
            technique_id:   "T1059".into(),
            sub_technique:  None,
            name:           "Command and Scripting Interpreter".into(),
            tactic:         "Execution".into(),
            url:            "https://attack.mitre.org/techniques/T1059/".into(),
            description:    "SSTI peut exécuter des commandes arbitraires via os.system() ou subprocess.".into(),
            detection_hint: "Audit des appels système depuis le processus du serveur web.".into(),
        });
    }
    if vt.contains("ssrf") {
        techniques.push(MitreTechnique {
            technique_id:   "T1090".into(),
            sub_technique:  None,
            name:           "Proxy via SSRF".into(),
            tactic:         "Command and Control".into(),
            url:            "https://attack.mitre.org/techniques/T1090/".into(),
            description:    "SSRF permet de faire envoyer des requêtes par le serveur vers des ressources internes.".into(),
            detection_hint: "Surveiller les requêtes HTTP sortantes du serveur, bloquer les plages RFC1918.".into(),
        });
    }
    if vt.contains("lfi") || vt.contains("path traversal") || vt.contains("file inclus") {
        techniques.push(MitreTechnique {
            technique_id: "T1083".into(),
            sub_technique: None,
            name: "File and Directory Discovery".into(),
            tactic: "Discovery".into(),
            url: "https://attack.mitre.org/techniques/T1083/".into(),
            description:
                "LFI permet de lire des fichiers arbitraires sur le système de fichiers du serveur."
                    .into(),
            detection_hint: "Alerter sur des patterns ../ dans les paramètres de requêtes.".into(),
        });
    }
    if vt.contains("cmd") || vt.contains("command injection") || vt.contains("cmdi") {
        techniques.push(MitreTechnique {
            technique_id: "T1059".into(),
            sub_technique: None,
            name: "Command and Scripting Interpreter".into(),
            tactic: "Execution".into(),
            url: "https://attack.mitre.org/techniques/T1059/".into(),
            description: "Command Injection permet d'exécuter des commandes OS arbitraires.".into(),
            detection_hint:
                "Alerter sur des appels shell avec des entrées utilisateur non sanitisées.".into(),
        });
    }
    if vt.contains("xxe") {
        techniques.push(MitreTechnique {
            technique_id: "T1005".into(),
            sub_technique: None,
            name: "Data from Local System via XXE".into(),
            tactic: "Collection".into(),
            url: "https://attack.mitre.org/techniques/T1005/".into(),
            description: "XXE permet d'exfiltrer des fichiers locaux via des entités XML externes."
                .into(),
            detection_hint: "Désactiver le traitement des entités externes dans les parseurs XML."
                .into(),
        });
    }

    // ── Credential Access ─────────────────────────────────────────────────────
    if vt.contains("brute") || vt.contains("credential") || vt.contains("password spray") {
        techniques.push(MitreTechnique {
            technique_id:   "T1110".into(),
            sub_technique:  if vt.contains("spray") { Some(".003".into()) } else { Some(".001".into()) },
            name:           if vt.contains("spray") { "Password Spraying" } else { "Password Brute Force" }.into(),
            tactic:         "Credential Access".into(),
            url:            "https://attack.mitre.org/techniques/T1110/".into(),
            description:    "Attaque par force brute ou pulvérisation de mots de passe pour obtenir des credentials valides.".into(),
            detection_hint: "Alerter sur les échecs d'authentification répétés. Account lockout policy.".into(),
        });
    }
    if vt.contains("lsass")
        || vt.contains("sam")
        || vt.contains("ntlm")
        || vt.contains("secretsdump")
    {
        techniques.push(MitreTechnique {
            technique_id: "T1003".into(),
            sub_technique: if vt.contains("lsass") {
                Some(".001".into())
            } else {
                Some(".002".into())
            },
            name: "OS Credential Dumping".into(),
            tactic: "Credential Access".into(),
            url: "https://attack.mitre.org/techniques/T1003/".into(),
            description: "Extraction des hashes de mots de passe depuis LSASS ou la ruche SAM."
                .into(),
            detection_hint: "Monitorer les accès à lsass.exe. Activer Credential Guard.".into(),
        });
    }
    if vt.contains("kerberoast") || vt.contains("as-rep") {
        techniques.push(MitreTechnique {
            technique_id:   "T1558".into(),
            sub_technique:  if vt.contains("kerberoast") { Some(".003".into()) } else { Some(".004".into()) },
            name:           if vt.contains("kerberoast") { "Kerberoasting" } else { "AS-REP Roasting" }.into(),
            tactic:         "Credential Access".into(),
            url:            "https://attack.mitre.org/techniques/T1558/".into(),
            description:    "Extraction et cassage offline de tickets Kerberos pour obtenir des mots de passe.".into(),
            detection_hint: "Monitorer les requêtes TGS pour des comptes de service. AES uniquement sur les comptes sensibles.".into(),
        });
    }
    if vt.contains("jwt") {
        techniques.push(MitreTechnique {
            technique_id:   "T1550".into(),
            sub_technique:  Some(".001".into()),
            name:           "Use Alternate Authentication Material — JWT Forgery".into(),
            tactic:         "Defense Evasion / Lateral Movement".into(),
            url:            "https://attack.mitre.org/techniques/T1550/".into(),
            description:    "Falsification ou manipulation de tokens JWT pour accéder à des ressources sans credentials.".into(),
            detection_hint: "Valider la signature JWT côté serveur. Rejeter alg:none. Utiliser RS256.".into(),
        });
    }

    // ── Discovery ─────────────────────────────────────────────────────────────
    if vt.contains("scan") || vt.contains("network") || vt.contains("port") {
        techniques.push(MitreTechnique {
            technique_id: "T1046".into(),
            sub_technique: None,
            name: "Network Service Discovery".into(),
            tactic: "Discovery".into(),
            url: "https://attack.mitre.org/techniques/T1046/".into(),
            description: "Scan réseau pour identifier les services actifs et les ports ouverts."
                .into(),
            detection_hint: "IDS/IPS avec signatures de scan. Honeypots sur ports inactifs.".into(),
        });
    }
    if vt.contains("snmp") {
        techniques.push(MitreTechnique {
            technique_id: "T1602".into(),
            sub_technique: Some(".001".into()),
            name: "SNMP MIB Dump".into(),
            tactic: "Collection".into(),
            url: "https://attack.mitre.org/techniques/T1602/001/".into(),
            description:
                "Dump de la MIB SNMP pour obtenir des informations sur la configuration réseau."
                    .into(),
            detection_hint:
                "Utiliser SNMPv3 avec authentification. Bloquer SNMP sur les interfaces publiques."
                    .into(),
        });
    }

    // ── Lateral Movement ─────────────────────────────────────────────────────
    if vt.contains("pass-the-hash") || vt.contains("pth") {
        techniques.push(MitreTechnique {
            technique_id: "T1550".into(),
            sub_technique: Some(".002".into()),
            name: "Pass the Hash".into(),
            tactic: "Lateral Movement".into(),
            url: "https://attack.mitre.org/techniques/T1550/002/".into(),
            description:
                "Utilisation de hashes NTLM pour s'authentifier sans connaître le mot de passe."
                    .into(),
            detection_hint:
                "Monitorer les connexions SMB/RPC avec des hashes. Protected Users group.".into(),
        });
    }
    if vt.contains("dcsync") {
        techniques.push(MitreTechnique {
            technique_id: "T1003".into(),
            sub_technique: Some(".006".into()),
            name: "DCSync".into(),
            tactic: "Credential Access".into(),
            url: "https://attack.mitre.org/techniques/T1003/006/".into(),
            description: "Simulation d'un DC pour répliquer les hashes depuis Active Directory."
                .into(),
            detection_hint: "Alerter sur les opérations DRSGetNCChanges depuis des non-DCs.".into(),
        });
    }
    if vt.contains("smb") || vt.contains("eternalblue") || vt.contains("ms17") {
        techniques.push(MitreTechnique {
            technique_id: "T1021".into(),
            sub_technique: Some(".002".into()),
            name: "SMB/Windows Admin Shares".into(),
            tactic: "Lateral Movement".into(),
            url: "https://attack.mitre.org/techniques/T1021/002/".into(),
            description:
                "Exploitation SMB pour le mouvement latéral ou l'exécution de code à distance."
                    .into(),
            detection_hint:
                "Désactiver SMBv1. Surveiller les connexions IPC$ et les transferts de fichiers."
                    .into(),
        });
    }

    // ── C2 ────────────────────────────────────────────────────────────────────
    if vt.contains("c2") || vt.contains("reverse shell") || vt.contains("beacon") {
        techniques.push(MitreTechnique {
            technique_id: "T1071".into(),
            sub_technique: Some(".001".into()),
            name: "Web Protocols C2".into(),
            tactic: "Command and Control".into(),
            url: "https://attack.mitre.org/techniques/T1071/001/".into(),
            description:
                "Communication C2 via HTTP/HTTPS/WebSocket pour masquer le trafic malveillant."
                    .into(),
            detection_hint:
                "Analyser les patterns de beaconing (intervalles réguliers). Proxy SSL inspection."
                    .into(),
        });
    }

    // ── Persistence ───────────────────────────────────────────────────────────
    if vt.contains("persist")
        || vt.contains("crontab")
        || vt.contains("service")
        || vt.contains("registry")
    {
        techniques.push(MitreTechnique {
            technique_id: "T1053".into(),
            sub_technique: if vt.contains("crontab") {
                Some(".003".into())
            } else {
                Some(".005".into())
            },
            name: if vt.contains("crontab") {
                "Cron Job Persistence"
            } else {
                "Scheduled Task"
            }
            .into(),
            tactic: "Persistence".into(),
            url: "https://attack.mitre.org/techniques/T1053/".into(),
            description:
                "Utilisation de tâches planifiées pour maintenir l'accès après redémarrage.".into(),
            detection_hint:
                "Auditer les crontabs et tâches planifiées. Alerter sur les modifications.".into(),
        });
    }

    // ── Defense Evasion ───────────────────────────────────────────────────────
    if vt.contains("amsi") || vt.contains("etw") || vt.contains("hook") || vt.contains("edr") {
        techniques.push(MitreTechnique {
            technique_id: "T1562".into(),
            sub_technique: Some(".001".into()),
            name: "Disable or Modify Tools (AMSI/ETW)".into(),
            tactic: "Defense Evasion".into(),
            url: "https://attack.mitre.org/techniques/T1562/001/".into(),
            description:
                "Désactivation de mécanismes de sécurité (AMSI, ETW) pour éviter la détection."
                    .into(),
            detection_hint: "Surveiller les écritures mémoire dans amsi.dll et ntdll.dll.".into(),
        });
    }
    if vt.contains("obfuscat") || vt.contains("encod") || vt.contains("poly") {
        techniques.push(MitreTechnique {
            technique_id: "T1027".into(),
            sub_technique: None,
            name: "Obfuscated Files or Information".into(),
            tactic: "Defense Evasion".into(),
            url: "https://attack.mitre.org/techniques/T1027/".into(),
            description: "Obfuscation du code malveillant pour contourner les signatures AV/EDR."
                .into(),
            detection_hint:
                "Analyse comportementale plutôt que signatures statiques. AMSI pour PS1.".into(),
        });
    }

    // ── Impact ────────────────────────────────────────────────────────────────
    if vt.contains("dos") || vt.contains("smuggling") || vt.contains("amplif") {
        techniques.push(MitreTechnique {
            technique_id: "T1499".into(),
            sub_technique: None,
            name: "Endpoint Denial of Service".into(),
            tactic: "Impact".into(),
            url: "https://attack.mitre.org/techniques/T1499/".into(),
            description: "Exploitation de vulnérabilités pour provoquer un déni de service.".into(),
            detection_hint: "Rate limiting, WAF, surveillance des anomalies de trafic.".into(),
        });
    }

    // Déduplication par technique_id
    techniques
        .dedup_by(|a, b| a.technique_id == b.technique_id && a.sub_technique == b.sub_technique);
    techniques
}

/// Mappe automatiquement une liste de findings et enrichit chacun avec son MITRE ID
pub fn enrich_findings_with_attack(findings: &mut Vec<Finding>) {
    for finding in findings.iter_mut() {
        let techniques = map_to_attack(&finding.title);
        if let Some(first) = techniques.first() {
            if finding.mitre_id.is_none() {
                finding.mitre_id = Some(format!(
                    "{}{} — {}",
                    first.technique_id,
                    first.sub_technique.as_deref().unwrap_or(""),
                    first.name
                ));
            }
        }
    }
}

/// Génère la section MITRE ATT&CK Navigator Layer (JSON) pour visualisation
pub fn generate_attack_navigator_layer(findings: &[Finding], campaign_name: &str) -> String {
    let mut techniques_json = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for finding in findings {
        let all_techs = map_to_attack(&finding.title);
        for tech in all_techs {
            let key = format!(
                "{}{}",
                tech.technique_id,
                tech.sub_technique.as_deref().unwrap_or("")
            );
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key.clone());

            let color = match finding.severity.as_str() {
                "CRITICAL" => "#dc2626",
                "HIGH" => "#ea580c",
                "MEDIUM" => "#ca8a04",
                _ => "#16a34a",
            };
            let full_id = format!(
                "{}{}",
                tech.technique_id,
                tech.sub_technique.as_deref().unwrap_or("")
            );
            techniques_json.push(format!(
                r#"{{"techniqueID":"{id}","tactic":"{tactic}","color":"{color}","comment":"{comment}","enabled":true}}"#,
                id      = full_id,
                tactic  = tech.tactic.to_lowercase().replace(' ', "-"),
                color   = color,
                comment = finding.title.replace('"', "'"),
            ));
        }
    }

    format!(
        r##"{{
  "name": "DIAPILE — {name}",
  "versions": {{"attack": "14", "navigator": "4.9", "layer": "4.5"}},
  "domain": "enterprise-attack",
  "description": "Techniques ATT&CK detectees lors du pentest {name}",
  "filters": {{"platforms": ["Windows","Linux","macOS","Network"]}},
  "sorting": 0,
  "layout": {{"layout": "side","aggregateFunction": "average","showID": true,"showName": true}},
  "hideDisabled": false,
  "techniques": [{techniques}],
  "gradient": {{"colors": ["#ffffff","#ff6666"],"minValue": 0,"maxValue": 100}},
  "legendItems": [
    {{"label":"CRITICAL","color":"#dc2626"}},
    {{"label":"HIGH","color":"#ea580c"}},
    {{"label":"MEDIUM","color":"#ca8a04"}},
    {{"label":"LOW","color":"#16a34a"}}
  ],
  "showTacticRowBackground": true,
  "tacticRowBackground": "#191919",
  "selectTechniquesAcrossTactics": true
}}"##,
        name = campaign_name,
        techniques = techniques_json.join(",\n  "),
    )
}

/// Sauvegarde le layer ATT&CK Navigator au format JSON
pub fn export_attack_layer(
    findings: &[Finding],
    campaign_name: &str,
    path: &str,
) -> Result<(), std::io::Error> {
    let layer = generate_attack_navigator_layer(findings, campaign_name);
    std::fs::write(path, layer)
}

// ═════════════════════════════════════════════════════════════════════════════
// Risk Matrix — vue visuelle CVSS / nombre de findings par sévérité
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskMatrix {
    pub critical: Vec<RiskEntry>,
    pub high: Vec<RiskEntry>,
    pub medium: Vec<RiskEntry>,
    pub low: Vec<RiskEntry>,
    pub info: Vec<RiskEntry>,
    /// Score global agrégé (0–100)
    pub risk_score: f32,
    /// Texte synthétique
    pub narrative: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEntry {
    pub id: String,
    pub title: String,
    pub cvss: f32,
    pub affected: usize,
    pub mitre_id: Option<String>,
    pub exploited: bool, // exploitation confirmée pendant le test
}

/// Construit la risk matrix depuis une liste de findings
pub fn build_risk_matrix(findings: &[Finding]) -> RiskMatrix {
    let mut matrix = RiskMatrix {
        critical: Vec::new(),
        high: Vec::new(),
        medium: Vec::new(),
        low: Vec::new(),
        info: Vec::new(),
        risk_score: 0.0,
        narrative: String::new(),
    };

    for f in findings {
        let entry = RiskEntry {
            id: f.id.clone(),
            title: f.title.clone(),
            cvss: f.cvss_score,
            affected: f.affected.len(),
            mitre_id: f.mitre_id.clone(),
            exploited: f.evidence.iter().any(|e| {
                e.evidence_type == "exploit" || e.description.to_lowercase().contains("exploit")
            }),
        };
        match f.severity.as_str() {
            "CRITICAL" => matrix.critical.push(entry),
            "HIGH" => matrix.high.push(entry),
            "MEDIUM" => matrix.medium.push(entry),
            "LOW" => matrix.low.push(entry),
            _ => matrix.info.push(entry),
        }
    }

    // Score agrégé pondéré : CRITICAL×10 + HIGH×7 + MEDIUM×4 + LOW×1
    let weighted = matrix.critical.len() as f32 * 10.0
        + matrix.high.len() as f32 * 7.0
        + matrix.medium.len() as f32 * 4.0
        + matrix.low.len() as f32 * 1.0;
    matrix.risk_score = (weighted / (findings.len().max(1) as f32)).min(10.0);

    let exploited_count = findings.len(); // conservative
    matrix.narrative = format!(
        "Le périmètre présente {} finding(s) : {} CRITICAL, {} HIGH, {} MEDIUM, {} LOW. \
         Score de risque global : {:.1}/10. \
         Les vulnérabilités critiques permettent une compromission directe du système \
         ou une élévation de privilèges vers un accès administrateur.",
        findings.len(),
        matrix.critical.len(),
        matrix.high.len(),
        matrix.medium.len(),
        matrix.low.len(),
        matrix.risk_score,
    );

    matrix
}

/// Génère le HTML de la risk matrix pour inclusion dans le rapport
pub fn render_risk_matrix_html(matrix: &RiskMatrix) -> String {
    let render_row = |entries: &[RiskEntry], sev: &str, color: &str| -> String {
        if entries.is_empty() {
            return String::new();
        }
        let rows: String = entries.iter().map(|e| format!(
            "<tr><td><code>{}</code></td><td>{}</td><td style='color:{c}'>{:.1}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
            e.id, e.title, e.cvss, e.affected,
            e.mitre_id.as_deref().unwrap_or("—"),
            if e.exploited { "✅ OUI" } else { "—" },
            c = color,
        )).collect();
        format!(
            "<tr class='sev-header'><td colspan='6' style='background:{color}22;color:{color};font-weight:bold'>▶ {} ({})</td></tr>{rows}",
            sev, entries.len()
        )
    };

    format!(
        r#"
<div class="risk-matrix">
  <h3>Risk Matrix</h3>
  <div class="risk-score-badge" style="background:#1a1a2e;border:2px solid #f97316;border-radius:8px;padding:12px;margin-bottom:16px;text-align:center">
    <div style="font-size:2.5em;color:#f97316;font-weight:bold">{score:.1}</div>
    <div style="color:#9ca3af">Score de risque global / 10</div>
  </div>
  <table class="findings-table" style="width:100%;border-collapse:collapse">
    <thead>
      <tr style="background:#111827">
        <th>ID</th><th>Titre</th><th>CVSS</th><th>Systèmes</th><th>MITRE ATT&CK</th><th>Exploité</th>
      </tr>
    </thead>
    <tbody>
      {critical}
      {high}
      {medium}
      {low}
    </tbody>
  </table>
  <p style="color:#9ca3af;font-style:italic;margin-top:12px">{narrative}</p>
</div>"#,
        score = matrix.risk_score,
        critical = render_row(&matrix.critical, "CRITICAL", "#dc2626"),
        high = render_row(&matrix.high, "HIGH", "#ea580c"),
        medium = render_row(&matrix.medium, "MEDIUM", "#ca8a04"),
        low = render_row(&matrix.low, "LOW", "#16a34a"),
        narrative = matrix.narrative,
    )
}

/// Version complète : enrichit les findings, génère risk matrix + layer ATT&CK,
/// exporte le rapport Markdown + HTML + JSON ATT&CK layer dans `output_dir`.
pub fn export_full_report(
    report: &mut PentestReport,
    output_dir: &str,
) -> Result<Vec<String>, std::io::Error> {
    std::fs::create_dir_all(output_dir)?;
    let mut files = Vec::new();

    // 1. Enrichissement MITRE ATT&CK
    enrich_findings_with_attack(&mut report.findings);

    // 2. Risk matrix
    let matrix = build_risk_matrix(&report.findings);
    let matrix_path = format!("{}/risk_matrix.json", output_dir);
    std::fs::write(
        &matrix_path,
        serde_json::to_string_pretty(&matrix).unwrap_or_default(),
    )?;
    files.push(matrix_path);

    // 3. ATT&CK Navigator layer
    let layer_path = format!("{}/attack_layer.json", output_dir);
    export_attack_layer(&report.findings, &report.meta.scan_id, &layer_path)?;
    files.push(layer_path);

    // 4. Markdown report
    let md_path = format!("{}/report.md", output_dir);
    export_markdown(report, &md_path)?;
    files.push(md_path);

    // 5. HTML report
    let html_path = format!("{}/report.html", output_dir);
    export_html_report(report, &html_path)?;
    files.push(html_path);

    // 6. JSON brut (machine-readable)
    let json_path = format!("{}/report.json", output_dir);
    std::fs::write(
        &json_path,
        serde_json::to_string_pretty(report).unwrap_or_default(),
    )?;
    files.push(json_path);

    println!(
        "\n  \x1b[32m[REPORT]\x1b[0m {} fichiers générés dans {}",
        files.len(),
        output_dir
    );
    for f in &files {
        println!("  → {}", f);
    }

    Ok(files)
}
