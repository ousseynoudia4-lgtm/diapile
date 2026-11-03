//! DIAPILE — Auto-Installer Module (version intelligente)
//!
//! Détection et installation **opt-in** des outils tiers dont l'agent a besoin
//! pendant une mission (sshpass, impacket, hydra, nmap, …) sur toutes les
//! plateformes (apt / dnf / yum / pacman / zypper / apk / brew / winget / pip).
//!
//! Philosophie :
//!   • native-first   — l'agent privilégie ses moteurs Rust embarqués ;
//!   • fail-closed    — sans `--auto-install`, rien n'est installé : on suggère
//!     la commande exacte puis on poursuit la mission (aucun blocage) ;
//!   • any-tool       — un binaire inconnu est tenté avec son propre nom comme
//!     paquet, ce qui permet d'installer *n'importe quel* outil ;
//!   • self-diagnosing — un échec n'est pas juste un code de sortie : le module
//!     lit le stderr, identifie la cause probable, et agit en conséquence
//!     (retry, repli, ou message actionnable) ;
//!   • auditable      — chaque tentative d'installation est journalisée ;
//!   • executable     — un outil garanti présent peut être **réellement
//!     exécuté** par l'agent (`run_tool`), avec un plafond dur, au lieu de
//!     se limiter à suggérer une commande.
//!
//! ⚠️ L'installation système peut nécessiter des droits sudo/administrateur.

use crate::ansi::*;
use anyhow::{anyhow, Result};
use std::env;
use std::fs::OpenOptions;
use std::io::Read as IoRead;
use std::io::Write as IoWrite;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Détection & cache du gestionnaire de paquets
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Apt,    // Debian, Ubuntu, Kali
    Dnf,    // Fedora
    Yum,    // CentOS, RHEL
    Pacman, // Arch
    Zypper, // openSUSE
    Apk,    // Alpine
    Brew,   // macOS
    Choco,  // Windows (Chocolatey)
    Winget, // Windows (winget)
    Unknown,
}

/// Cache process-local : la détection du PM ne coûte qu'un seul scan PATH
/// par exécution, même si `ensure_tool` est appelé pour 20 binaires.
static PM_CACHE: OnceLock<PackageManager> = OnceLock::new();

impl PackageManager {
    /// Commande d'installation. Chaque gestionnaire a sa propre syntaxe —
    /// Choco et Winget ne sont PAS interchangeables malgré leur air de famille.
    pub fn get_install_cmd(&self, package: &str, assume_yes: bool) -> Option<Vec<String>> {
        let mut cmd: Vec<String> = match self {
            PackageManager::Apt => vec!["apt-get".into(), "install".into()],
            PackageManager::Dnf => vec!["dnf".into(), "install".into()],
            PackageManager::Yum => vec!["yum".into(), "install".into()],
            PackageManager::Pacman => vec!["pacman".into(), "-S".into()],
            PackageManager::Zypper => vec!["zypper".into(), "install".into()],
            PackageManager::Apk => vec!["apk".into(), "add".into()],
            PackageManager::Brew => vec!["brew".into(), "install".into()],
            PackageManager::Choco => vec!["choco".into(), "install".into()],
            PackageManager::Winget => vec!["winget".into(), "install".into()],
            PackageManager::Unknown => return None,
        };

        if assume_yes {
            match self {
                PackageManager::Apt
                | PackageManager::Dnf
                | PackageManager::Yum
                | PackageManager::Apk
                | PackageManager::Zypper => cmd.push("-y".into()),
                PackageManager::Pacman => cmd.push("--noconfirm".into()),
                PackageManager::Choco => cmd.push("-y".into()),
                PackageManager::Winget => {
                    cmd.push("--accept-package-agreements".into());
                    cmd.push("--accept-source-agreements".into());
                    cmd.push("--silent".into());
                }
                _ => {}
            }
        }

        cmd.push(package.to_string()); // jamais de split_whitespace sur le paquet : un nom composé reste intact
        Some(cmd)
    }

    pub fn needs_sudo(&self) -> bool {
        matches!(
            self,
            PackageManager::Apt
                | PackageManager::Dnf
                | PackageManager::Yum
                | PackageManager::Pacman
                | PackageManager::Zypper
                | PackageManager::Apk
        )
    }
}

/// Détecte le gestionnaire de paquets, avec mise en cache process-local.
pub fn detect_package_manager() -> PackageManager {
    *PM_CACHE.get_or_init(|| {
        if cfg!(target_os = "windows") {
            // winget est préféré (plus moderne) ; choco en repli explicite, pas confondu.
            if which_in_path("winget") {
                return PackageManager::Winget;
            }
            if which_in_path("choco") {
                return PackageManager::Choco;
            }
        } else if cfg!(target_os = "macos") {
            if which_in_path("brew") {
                return PackageManager::Brew;
            }
        } else if cfg!(target_os = "linux") {
            // Ordre de préférence : gestionnaires modernes d'abord (évite les faux
            // positifs sur les systèmes avec plusieurs PM installés simultanément).
            for (bin, pm) in [
                ("apt-get", PackageManager::Apt),
                ("dnf", PackageManager::Dnf),
                ("yum", PackageManager::Yum),
                ("pacman", PackageManager::Pacman),
                ("zypper", PackageManager::Zypper),
                ("apk", PackageManager::Apk),
            ] {
                if which_in_path(bin) {
                    return pm;
                }
            }
        }
        PackageManager::Unknown
    })
}

pub fn which_in_path(prog: &str) -> bool {
    env::var("PATH")
        .ok()
        .map(|p| {
            env::split_paths(&p)
                .any(|dir| dir.join(prog).exists() || dir.join(format!("{}.exe", prog)).exists())
        })
        .unwrap_or(false)
}

// ============================================================================
// Résolution binaire → paquet
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallKind {
    System,
    Pip,
}

pub fn install_spec(binary: &str) -> (InstallKind, String) {
    if binary.starts_with("impacket-") {
        return (InstallKind::Pip, "impacket".to_string());
    }

    match binary {
        "sshpass" => (InstallKind::System, "sshpass".into()),
        "hydra" => (InstallKind::System, "hydra".into()),
        "medusa" => (InstallKind::System, "medusa".into()),
        "nmap" => (InstallKind::System, "nmap".into()),
        "masscan" => (InstallKind::System, "masscan".into()),
        "nc" | "ncat" => (InstallKind::System, "netcat".into()),
        "tcpdump" => (InstallKind::System, "tcpdump".into()),
        "smbclient" | "rpcclient" => (InstallKind::System, "smbclient".into()),
        "ldapsearch" => (InstallKind::System, "ldap-utils".into()),
        "kinit" => (InstallKind::System, "krb5-user".into()),
        // Utilitaires réseau OS — noms de paquets réels (ne PAS laisser le
        // repli générique mapper « ip » → paquet « ip », qui n'existe pas).
        "ip" | "ss" => (InstallKind::System, "iproute2".into()),
        "netstat" | "route" | "ifconfig" | "arp" => (InstallKind::System, "net-tools".into()),
        "nxc" | "netexec" => (InstallKind::Pip, "netexec".into()),
        "bloodhound-python" => (InstallKind::Pip, "bloodhound".into()),
        "responder" => (InstallKind::Pip, "responder".into()),
        "gobuster" => (InstallKind::System, "gobuster".into()),
        "ffuf" => (InstallKind::System, "ffuf".into()),
        "sqlmap" => (InstallKind::System, "sqlmap".into()),
        "nikto" => (InstallKind::System, "nikto".into()),
        "whatweb" => (InstallKind::System, "whatweb".into()),
        "wpscan" => (InstallKind::System, "wpscan".into()),
        "john" => (InstallKind::System, "john".into()),
        "hashcat" => (InstallKind::System, "hashcat".into()),
        "msfvenom" | "msfconsole" => (InstallKind::System, "metasploit-framework".into()),
        "xfreerdp" => (InstallKind::System, "freerdp2-x11".into()),
        "redis-cli" => (InstallKind::System, "redis-tools".into()),
        "snmpwalk" => (InstallKind::System, "snmp".into()),
        other => (InstallKind::System, other.to_string()),
    }
}

/// Un repli pip pour les outils Python-based qui existent aussi comme paquet
/// système sur certaines distros mais pas d'autres. Utilisé si l'install
/// système échoue et qu'un équivalent pip est plausible.
fn pip_fallback_for(binary: &str) -> Option<&'static str> {
    match binary {
        "sqlmap" => Some("sqlmap"),
        "wpscan" => None, // gem-based, pas de fallback pip pertinent
        "responder" => Some("responder"),
        _ => None,
    }
}

// ============================================================================
// Classification de risque — garde-fou pour l'auto-initiative de l'agent
// ============================================================================

/// Niveau de risque estimé d'un outil, utilisé pour décider si une
/// confirmation humaine est OBLIGATOIRE, indépendamment de `assume_yes`.
///
/// Principe : plus un outil s'éloigne de la liste connue et documentée
/// (`install_spec`), moins on peut présumer que son installation autonome
/// est sûre. L'agent garde la liberté de *proposer* n'importe quel outil,
/// mais ne peut plus l'installer sans supervision explicite s'il sort du
/// périmètre connu ou touche une catégorie sensible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskTier {
    Low,     // utilitaires réseau/diagnostic de base (nmap, tcpdump…)
    Medium,  // outils offensifs documentés et largement utilisés en pentest autorisé
    High,    // frameworks d'exploitation / post-exploitation à fort impact
    Unknown, // binaire hors de toute liste connue — jamais présumé sûr
}

/// Mots-clés associés à un impact offensif élevé (post-exploitation, RCE,
/// frameworks complets). Un binaire inconnu contenant l'un de ces motifs
/// est classé High plutôt que Unknown, même sans entrée explicite.
const HIGH_IMPACT_MARKERS: &[&str] = &[
    "metasploit",
    "msf",
    "cobaltstrike",
    "cobalt-strike",
    "empire",
    "mimikatz",
    "ransom",
    "exploit-db",
    "exploitdb",
    "c2",
    "beacon",
];

fn classify_risk(binary: &str, kind: InstallKind) -> RiskTier {
    let b = binary.to_lowercase();

    if HIGH_IMPACT_MARKERS.iter().any(|m| b.contains(m)) {
        return RiskTier::High;
    }

    match binary {
        // Diagnostic / reconnaissance passive — impact limité
        "nmap" | "tcpdump" | "ldapsearch" | "redis-cli" | "snmpwalk" | "whatweb" | "smbclient"
        | "rpcclient" | "sshpass" | "nc" | "ncat" | "ip" | "ss" | "netstat" | "route"
        | "ifconfig" | "arp" => RiskTier::Low,

        // Offensif documenté, usage standard en test d'intrusion autorisé
        "hydra" | "medusa" | "masscan" | "gobuster" | "ffuf" | "sqlmap" | "nikto" | "wpscan"
        | "john" | "hashcat" | "kinit" | "xfreerdp" => RiskTier::Medium,

        // Post-exploitation / mouvement latéral / frameworks à fort impact
        "msfvenom" | "msfconsole" | "nxc" | "netexec" | "bloodhound-python" | "responder" => {
            RiskTier::High
        }

        _ if binary.starts_with("impacket-") => RiskTier::Medium,

        // Binaire absent de toute table connue → résolu par le repli
        // générique `other` dans install_spec : on ne lui fait jamais
        // confiance par défaut, quel que soit InstallKind.
        _ => {
            let _ = kind; // kind n'influence pas le tiers par défaut, réservé pour extension future
            RiskTier::Unknown
        }
    }
}

/// Un outil Medium+ ou Unknown exige toujours une confirmation humaine,
/// même avec `assume_yes = true` — **sauf en mode autonome explicite**
/// (`--autonomous`). Seul Low peut être auto-confirmé sans condition.
fn requires_mandatory_confirmation(tier: RiskTier) -> bool {
    tier >= RiskTier::Medium
}

// ============================================================================
// Mode autonome (opt-in global, activé une fois au démarrage par le CLI)
// ============================================================================

/// Mode autonome : lève le verrou de confirmation humaine obligatoire pour les
/// outils `Medium`/`High`/inconnus, afin de permettre une exécution totalement
/// non-interactive (agent, orchestration, CI). Désactivé par défaut.
static AUTONOMOUS: AtomicBool = AtomicBool::new(false);

/// Active/désactive le mode autonome. Appelé une seule fois au démarrage,
/// selon le flag CLI `--autonomous`.
pub fn set_autonomous(on: bool) {
    AUTONOMOUS.store(on, Ordering::Relaxed);
}

/// Indique si le mode autonome est actif pour ce processus.
pub fn is_autonomous() -> bool {
    AUTONOMOUS.load(Ordering::Relaxed)
}

// ============================================================================
// Résolution par similarité (tolérance aux fautes / variations de nommage)
// ============================================================================

/// Décompose une chaîne en trigrammes de caractères (fenêtres glissantes de 3).
/// Base de la similarité de Jaccard utilisée ci-dessous.
fn trigrams(s: &str) -> std::collections::HashSet<String> {
    let chars: Vec<char> = s.to_lowercase().chars().collect();
    if chars.len() < 3 {
        return std::collections::HashSet::from([s.to_lowercase()]);
    }
    chars.windows(3).map(|w| w.iter().collect()).collect()
}

/// Indice de Jaccard entre deux ensembles de trigrammes : |A∩B| / |A∪B|.
/// Tolère les fautes de frappe et les variations de nommage inter-distros
/// (ex. "freerdp2-x11" vs "freerdp") bien mieux qu'une comparaison exacte.
fn jaccard_similarity(a: &str, b: &str) -> f64 {
    let ta = trigrams(a);
    let tb = trigrams(b);
    let intersection = ta.intersection(&tb).count() as f64;
    let union = ta.union(&tb).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

/// Catalogue de noms de paquets connus, utilisé uniquement pour suggérer une
/// correction si l'installation échoue avec `PackageNotFound` — jamais pour
/// décider automatiquement d'installer autre chose que ce qui a été demandé.
const KNOWN_PACKAGE_CATALOG: &[&str] = &[
    "sshpass",
    "hydra",
    "medusa",
    "nmap",
    "masscan",
    "netcat",
    "tcpdump",
    "smbclient",
    "ldap-utils",
    "krb5-user",
    "iproute2",
    "net-tools",
    "gobuster",
    "ffuf",
    "sqlmap",
    "nikto",
    "whatweb",
    "wpscan",
    "john",
    "hashcat",
    "metasploit-framework",
    "freerdp2-x11",
    "redis-tools",
    "snmp",
    "impacket",
    "netexec",
    "bloodhound",
    "responder",
];

/// Suggère le paquet connu le plus proche par similarité trigramme, utile
/// quand `diagnose()` renvoie `PackageNotFound` pour un nom mal orthographié
/// ou spécifique à une autre distro. Seuil de 0.3 pour éviter les faux positifs.
fn suggest_closest_known(package: &str) -> Option<(&'static str, f64)> {
    KNOWN_PACKAGE_CATALOG
        .iter()
        .map(|&known| (known, jaccard_similarity(package, known)))
        .filter(|(_, score)| *score >= 0.3)
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
}

// ============================================================================
// Estimation bayésienne de succès (apprentissage depuis le journal d'audit)
// ============================================================================

/// Estime P(succès | paquet) à partir de l'historique d'audit, avec un prior
/// de Laplace (lissage additif) pour éviter les probabilités 0/1 sur peu
/// d'observations. Permet de prioriser ou d'avertir avant une tentative
/// connue pour échouer fréquemment sur cette machine.
fn estimate_success_probability(package: &str) -> f64 {
    let (successes, failures) = read_audit_outcomes(package);
    // Lissage de Laplace : (succès + 1) / (total + 2) → prior neutre à 0.5
    // en l'absence de données, converge vers le taux réel avec l'historique.
    (successes as f64 + 1.0) / (successes as f64 + failures as f64 + 2.0)
}

fn read_audit_outcomes(package: &str) -> (u32, u32) {
    let mut successes = 0u32;
    let mut failures = 0u32;
    if let Ok(content) = std::fs::read_to_string("diapile_installs.log") {
        for line in content.lines() {
            if !line.contains(&format!("package={package}")) {
                continue;
            }
            if line.contains("outcome=success") {
                successes += 1;
            } else if line.contains("outcome=failed") {
                failures += 1;
            }
        }
    }
    (successes, failures)
}

// ============================================================================
// Validation anti-injection
// ============================================================================

/// Un nom de paquet/binaire légitime ne contient que des caractères
/// alphanumériques, tirets, underscores, points et deux-points (pour les
/// versions type `paquet=1.2.3` sur certains PM). Tout le reste est rejeté
/// avant de toucher `Command` — on ne fait jamais confiance à une chaîne
/// qui finira dans un argv système, même construite en interne.
fn validate_package_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 128 {
        return Err(anyhow!("nom de paquet invalide (longueur)"));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '+' | '@' | '='));
    if !ok {
        return Err(anyhow!(
            "nom de paquet '{name}' contient des caractères non autorisés"
        ));
    }
    Ok(())
}

// ============================================================================
// Diagnostic d'échec
// ============================================================================

/// Catégorise une sortie d'échec pour décider de l'action suivante plutôt
/// que de simplement relayer un code de sortie opaque à l'utilisateur.
#[derive(Debug, PartialEq, Eq)]
enum FailureKind {
    LockHeld,         // "could not get lock", "another process" — transitoire, retry utile
    NetworkIssue,     // "could not resolve", "connection timed out" — transitoire
    RepoUnavailable,  // "404", "repository not found" — pas transitoire
    PermissionDenied, // "permission denied", besoin de sudo
    PackageNotFound,  // "unable to locate package", "no package" — pas transitoire
    Unknown,
}

fn diagnose(output: &Output) -> FailureKind {
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
    let text = format!("{stderr} {stdout}");

    if text.contains("could not get lock")
        || text.contains("resource temporarily unavailable")
        || text.contains("another process is using")
    {
        FailureKind::LockHeld
    } else if text.contains("could not resolve")
        || text.contains("connection timed out")
        || text.contains("network is unreachable")
        || text.contains("temporary failure resolving")
    {
        FailureKind::NetworkIssue
    } else if text.contains("404") || (text.contains("repository") && text.contains("not found")) {
        FailureKind::RepoUnavailable
    } else if text.contains("permission denied") || text.contains("are you root") {
        FailureKind::PermissionDenied
    } else if text.contains("unable to locate package")
        || text.contains("no package")
        || text.contains("not found in")
        || text.contains("no match found")
    {
        FailureKind::PackageNotFound
    } else {
        FailureKind::Unknown
    }
}

fn advice_for(kind: &FailureKind, package: &str) -> String {
    match kind {
        FailureKind::LockHeld =>
            format!("Un autre gestionnaire de paquets est probablement en cours d'exécution. Nouvelle tentative après un court délai…"),
        FailureKind::NetworkIssue =>
            format!("Problème réseau détecté vers le dépôt de paquets. Nouvelle tentative…"),
        FailureKind::RepoUnavailable =>
            format!("Le dépôt ne contient pas (ou plus) '{package}'. Vérifiez vos sources (`sources.list`, dépôts tiers nécessaires ?)."),
        FailureKind::PermissionDenied =>
            format!("Droits insuffisants pour installer '{package}'. Relancez avec les privilèges administrateur."),
        FailureKind::PackageNotFound =>
            format!("'{package}' n'existe pas sous ce nom dans les dépôts configurés. Vérifiez l'orthographe ou cherchez un paquet alternatif (ex: `apt search {package}`)."),
        FailureKind::Unknown =>
            format!("Échec non identifié lors de l'installation de '{package}'. Voir le journal d'audit pour le détail complet."),
    }
}

/// Transitoire = ça vaut la peine de retenter ; sinon on arrête tout de suite
/// plutôt que de gaspiller 3 tentatives sur une cause structurelle.
fn is_transient(kind: &FailureKind) -> bool {
    matches!(kind, FailureKind::LockHeld | FailureKind::NetworkIssue)
}

// ============================================================================
// Journal d'audit
// ============================================================================

fn audit_log(binary: &str, package: &str, outcome: &str, risk: RiskTier) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line =
        format!("{ts}\tbinary={binary}\tpackage={package}\trisk={risk:?}\toutcome={outcome}\n");

    // Best-effort : un échec d'écriture du log ne doit jamais bloquer la mission.
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("diapile_installs.log")
    {
        let _ = f.write_all(line.as_bytes());
    }
}

// ============================================================================
// Exécution
// ============================================================================

fn confirm(question: &str) -> Result<bool> {
    println!("  {CYAN}{question}{RESET}");
    print!("  (y/n) : ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_lowercase().starts_with('y'))
}

fn run_captured(parts: &[String], use_sudo: bool) -> Result<Output> {
    let output = if use_sudo && cfg!(unix) {
        Command::new("sudo").args(parts).output()?
    } else {
        let (program, rest) = parts
            .split_first()
            .ok_or_else(|| anyhow!("commande d'installation vide"))?;
        Command::new(program).args(rest).output()?
    };
    Ok(output)
}

/// Installation avec retry intelligent : seuls les échecs transitoires
/// (lock, réseau) sont retentés.
///
/// Le délai suit un principe AIMD (Additive Increase / Multiplicative
/// Decrease, inspiré du contrôle de congestion TCP) plutôt qu'un exponentiel
/// fixe : un `LockHeld` (contention locale, se libère vite) attend peu ;
/// un `NetworkIssue` (latence/indisponibilité réseau) double son délai à
/// chaque tentative, car la cause met généralement plus longtemps à se résorber.
///
/// Un échec structurel (paquet introuvable, droits insuffisants) s'arrête
/// immédiatement — retenter n'y changerait rien.
///
/// Note : `run_captured` bloque déjà sur `Command::output()`. Le sommeil est
/// donc volontairement synchrone (`std::thread::sleep`) — cela permet
/// d'exposer à la fois une API synchrone (`ensure_tool_blocking`) et
/// asynchrone (`ensure_tool`) sans dupliquer la logique.
fn run_install_smart(parts: &[String], use_sudo: bool, package: &str) -> Result<()> {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_kind = FailureKind::Unknown;
    let mut delay = Duration::from_millis(500);

    for attempt in 1..=MAX_ATTEMPTS {
        let output = run_captured(parts, use_sudo)?;
        if output.status.success() {
            return Ok(());
        }

        let kind = diagnose(&output);
        println!(
            "  {AMBER}⚠{RESET} Tentative {attempt}/{MAX_ATTEMPTS} échouée : {}",
            advice_for(&kind, package)
        );

        if kind == FailureKind::PackageNotFound {
            if let Some((suggestion, score)) = suggest_closest_known(package) {
                println!(
                    "  {CYAN}→{RESET} Vouliez-vous dire '{suggestion}' ? (similarité {:.0}%)",
                    score * 100.0
                );
            }
        }

        if !is_transient(&kind) || attempt == MAX_ATTEMPTS {
            last_kind = kind;
            break;
        }

        delay = match kind {
            FailureKind::LockHeld => delay + Duration::from_millis(500), // additive : la contention locale se résorbe vite
            FailureKind::NetworkIssue => delay * 2, // multiplicative : laisser le réseau/miroir se rétablir
            _ => delay * 2,
        };
        std::thread::sleep(delay);
        last_kind = kind;
    }

    Err(anyhow!("{}", advice_for(&last_kind, package)))
}

// ============================================================================
// API publique
// ============================================================================

/// Garantit qu'un outil tiers est disponible — **implémentation synchrone**.
///
/// Comportement :
/// 1. Déjà présent → `true`, rien à faire.
/// 2. `auto_install == false` → fail-closed : commande suggérée, `false`.
/// 3. Classification de risque : un outil Medium/High, ou totalement
///    inconnu (hors `install_spec`), exige une confirmation humaine
///    EXPLICITE — `assume_yes` ne peut plus la contourner, sauf si le
///    **mode autonome** a été activé (`--autonomous`), qui lève ce verrou
///    pour permettre une exécution non-interactive. Seuls les utilitaires
///    Low (diagnostic réseau de base) restent auto-confirmables sans cela.
///    Ce garde-fou s'applique quelle que soit l'origine de la demande —
///    y compris une initiative autonome de l'agent pour un outil non
///    mentionné dans la table connue.
/// 4. Sinon → validation du nom de paquet, confirmation, installation avec
///    retry intelligent, vérification post-install, repli pip si pertinent,
///    journalisation (y compris le tiers de risque, pour audit ultérieur).
pub fn ensure_tool_blocking(binary: &str, auto_install: bool, assume_yes: bool) -> bool {
    if which_in_path(binary) {
        return true;
    }

    let (kind, package) = install_spec(binary);
    let pm = detect_package_manager();
    let risk = classify_risk(binary, kind);

    println!("  {AMBER}⚠{RESET} Outil tiers '{binary}' absent du PATH. [risque: {risk:?}]");

    if let Err(e) = validate_package_name(&package) {
        eprintln!("  {RED}✗{RESET} Nom de paquet rejeté : {e}");
        audit_log(binary, &package, "rejected_invalid_name", risk);
        return false;
    }

    let success_prob = estimate_success_probability(&package);
    if success_prob < 0.5 {
        println!("  {AMBER}📊{RESET} Historique défavorable pour '{package}' (succès estimé {:.0}%) — échecs passés probablement structurels.", success_prob * 100.0);
    }

    // Garde-fou : un outil Medium+ ou Unknown ne peut jamais être installé
    // en silence, même en mode `assume_yes` — sauf si le mode autonome
    // explicite (`--autonomous`) a été demandé au démarrage.
    let effective_assume_yes = if requires_mandatory_confirmation(risk) && !is_autonomous() {
        if assume_yes {
            println!("  {AMBER}🛡{RESET} Outil classé {risk:?} — confirmation obligatoire malgré --yes (utilisez --autonomous pour automatiser).");
        }
        false
    } else {
        if requires_mandatory_confirmation(risk) && is_autonomous() {
            println!("  {AMBER}⚡{RESET} Mode autonome — installation de '{package}' ({risk:?}) sans confirmation.");
        }
        assume_yes
    };

    if risk == RiskTier::Unknown {
        println!("  {AMBER}🛡{RESET} '{binary}' n'est dans aucune table connue (install_spec) — origine et impact non vérifiés.");
    }

    if !auto_install {
        match kind {
            InstallKind::Pip => println!("  {GRIS}→ Installez-le : pip3 install {package}{RESET}"),
            InstallKind::System => match pm.get_install_cmd(&package, true) {
                Some(cmd) => {
                    let shown = if pm.needs_sudo() { format!("sudo {}", cmd.join(" ")) } else { cmd.join(" ") };
                    println!("  {GRIS}→ Installez-le : {shown}{RESET}");
                }
                None => println!("  {GRIS}→ Installez '{package}' manuellement (gestionnaire de paquets non détecté).{RESET}"),
            },
        }
        println!("  {GRIS}→ (relancez avec --auto-install pour automatiser){RESET}");
        return false;
    }

    let success = match kind {
        InstallKind::Pip => {
            let cmd = vec!["pip3".to_string(), "install".to_string(), package.clone()];
            if !effective_assume_yes
                && !confirm(&format!(
                    "Installer '{package}' via pip3 ? [risque: {risk:?}]"
                ))
                .unwrap_or(false)
            {
                audit_log(binary, &package, "declined_by_user", risk);
                return false;
            }
            println!("  {MATRIX}▍{RESET} Installation de {package} (pip3)…");
            run_install_smart(&cmd, false, &package).is_ok()
        }
        InstallKind::System => {
            let Some(cmd) = pm.get_install_cmd(&package, effective_assume_yes) else {
                eprintln!("  {RED}✗{RESET} Gestionnaire de paquets non détecté — installez '{package}' manuellement.");
                audit_log(binary, &package, "no_package_manager", risk);
                return false;
            };
            if !effective_assume_yes {
                let shown = if pm.needs_sudo() {
                    format!("sudo {}", cmd.join(" "))
                } else {
                    cmd.join(" ")
                };
                if !confirm(&format!(
                    "Installer '{package}' via « {shown} » ? [risque: {risk:?}]"
                ))
                .unwrap_or(false)
                {
                    audit_log(binary, &package, "declined_by_user", risk);
                    return false;
                }
            }
            println!("  {MATRIX}▍{RESET} Installation de {package}…");
            match run_install_smart(&cmd, pm.needs_sudo(), &package) {
                Ok(()) => true,
                Err(e) => {
                    // Repli intelligent : si l'install système échoue et qu'un
                    // équivalent pip existe, on le propose automatiquement
                    // plutôt que d'abandonner sèchement.
                    if let Some(pip_pkg) = pip_fallback_for(binary) {
                        println!("  {AMBER}↻{RESET} Échec système ({e}). Tentative de repli via pip3 ({pip_pkg})…");
                        let pip_cmd = vec![
                            "pip3".to_string(),
                            "install".to_string(),
                            pip_pkg.to_string(),
                        ];
                        run_install_smart(&pip_cmd, false, pip_pkg).is_ok()
                    } else {
                        eprintln!("  {RED}✗{RESET} {e}");
                        false
                    }
                }
            }
        }
    };

    let now_available = success && which_in_path(binary);
    let outcome = if now_available {
        "success"
    } else if success {
        "installed_but_not_in_path"
    } else {
        "failed"
    };

    if outcome == "installed_but_not_in_path" {
        println!("  {AMBER}⚠{RESET} {package} installé mais '{binary}' reste introuvable dans le PATH (vérifiez ~/.local/bin ou redémarrez le shell).");
    } else if outcome == "success" {
        println!("  {MATRIX}✓{RESET} {binary} installé et vérifié.");
    }

    audit_log(binary, &package, outcome, risk);
    now_available
}

/// Garantit qu'un outil tiers est disponible — **API asynchrone**.
///
/// Simple délégation à [`ensure_tool_blocking`] : l'installation est un
/// sous-processus bloquant par nature, il n'y a rien à paralléliser.
pub async fn ensure_tool(binary: &str, auto_install: bool, assume_yes: bool) -> bool {
    ensure_tool_blocking(binary, auto_install, assume_yes)
}

// ============================================================================
// Exécution d'un outil tiers par l'agent
// ============================================================================

/// Résultat de l'exécution d'un outil tiers (installé à la demande au besoin).
#[derive(Debug, Clone)]
pub struct ToolRun {
    pub tool: String,
    pub args: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl ToolRun {
    pub fn success(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }

    /// Sortie combinée (stdout puis stderr), bornée à `max_chars` **caractères**
    /// — la troncature se fait sur les `char` pour ne jamais couper un
    /// caractère UTF-8 multi-octets au milieu.
    pub fn combined(&self, max_chars: usize) -> String {
        let mut s = String::new();
        if !self.stdout.trim().is_empty() {
            s.push_str(self.stdout.trim_end());
        }
        if !self.stderr.trim().is_empty() {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str("[stderr] ");
            s.push_str(self.stderr.trim_end());
        }
        if s.chars().count() > max_chars {
            let truncated: String = s.chars().take(max_chars).collect();
            format!("{truncated}… (sortie tronquée)")
        } else {
            s
        }
    }
}

/// Exécute un outil tiers — **implémentation synchrone**.
///
/// C'est le point d'entrée qui permet à l'agent d'**utiliser réellement** un
/// outil tiers au lieu de se contenter d'en suggérer la commande :
/// 1. l'outil est d'abord garanti présent (`ensure_tool_blocking` — donc
///    fail-closed sans `--auto-install`, et soumis au garde-fou de risque) ;
///    s'il reste indisponible, rien n'est lancé ;
/// 2. il est ensuite exécuté avec un **plafond dur** : un outil réseau peut
///    rester bloqué sur une cible silencieuse (tarpit), on le tue plutôt que
///    d'attendre indéfiniment.
pub fn run_tool_blocking(
    tool: &str,
    args: &[String],
    auto_install: bool,
    assume_yes: bool,
    timeout: Duration,
) -> Result<ToolRun> {
    if !ensure_tool_blocking(tool, auto_install, assume_yes) {
        return Err(anyhow!(
            "outil '{tool}' indisponible — installez-le ou relancez avec --auto-install"
        ));
    }

    println!("  {MATRIX}▸{RESET} Exécution : {tool} {}", args.join(" "));

    let mut child = Command::new(tool)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("échec du lancement de '{tool}' : {e}"))?;

    // Drainage des pipes dans des threads dédiés : un outil bavard (nmap, ffuf,
    // sqlmap…) remplirait le tampon du pipe et se bloquerait en écriture, ce qui
    // rendrait la surveillance d'échéance inopérante (interblocage).
    let mut out_pipe = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("stdout non pipé"))?;
    let mut err_pipe = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("stderr non pipé"))?;
    let h_out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out_pipe.read_to_end(&mut buf);
        buf
    });
    let h_err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        buf
    });

    let began = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if began.elapsed() >= timeout => {
                let _ = child.kill();
                timed_out = true;
                println!(
                    "  {AMBER}⏱{RESET} '{tool}' interrompu après {}s (plafond dur).",
                    timeout.as_secs()
                );
                break child.wait()?;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(anyhow!("erreur d'attente sur '{tool}' : {e}")),
        }
    };

    let stdout = String::from_utf8_lossy(&h_out.join().unwrap_or_default()).to_string();
    let stderr = String::from_utf8_lossy(&h_err.join().unwrap_or_default()).to_string();

    Ok(ToolRun {
        tool: tool.to_string(),
        args: args.to_vec(),
        exit_code: status.code(),
        stdout,
        stderr,
        timed_out,
    })
}

/// Exécute un outil tiers — **API asynchrone**.
///
/// Simple délégation à [`run_tool_blocking`] : l'exécution est bloquante par
/// nature, il n'y a rien à paralléliser ici. L'appelant qui ne veut pas bloquer
/// l'exécuteur doit l'encadrer d'un `spawn_blocking`.
pub async fn run_tool(
    tool: &str,
    args: &[String],
    auto_install: bool,
    assume_yes: bool,
    timeout: Duration,
) -> Result<ToolRun> {
    run_tool_blocking(tool, args, auto_install, assume_yes, timeout)
}
