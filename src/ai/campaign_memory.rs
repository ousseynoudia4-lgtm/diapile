//! Campaign Memory — mémoire persistante de campagne Red Team
//!
//! Stocke sur disque tout l'état d'une opération :
//!   - Hôtes découverts et leur état de compromission
//!   - Credentials récoltés (testés sur toutes les cibles)
//!   - Sessions actives (shells, meterpreter)
//!   - Tentatives échouées (pour ne pas répéter)
//!   - Timeline des actions (audit / rapport narratif)
//!   - Contexte LLM (historique de conversation multi-turn)

#![allow(dead_code)]

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use super::hypothesis::{HypothesisTracker, SurfaceEvidence, VulnClass};

// ── Types de base ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostState {
    Discovered,
    Scanned,
    Vulnerable,
    Exploited,
    Compromised, // shell actif
    Pivoting,    // utilisé comme pivot
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    Plaintext,
    NtlmHash,
    SshKey,
    KerberosTicket,
    AsRepHash,
    KerberosTgsHash,
    ApiToken,
    Cookie,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostMemory {
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub state: HostState,
    /// services découverts : "ssh/22", "http/80", etc.
    pub services: Vec<String>,
    /// CVEs confirmés sur cet hôte
    pub confirmed_cves: Vec<String>,
    /// Exploits tentés → résultat (true = succès)
    pub exploit_attempts: HashMap<String, bool>,
    pub session_id: Option<String>,
    pub pivot_depth: u8,
    pub notes: Vec<String>,
    pub first_seen: String,
    pub last_updated: String,
    /// Surface d'attaque web cartographiée (crawl passif). Absente tant que
    /// l'hôte n'a pas d'HTTP exposé ou n'a pas été crawlé.
    #[serde(default)]
    pub web_surface: Option<WebSurface>,
}

/// Inventaire de la surface d'attaque web d'un hôte, produit par le crawl
/// passif du `WebSpider`.
///
/// C'est la donnée qui manquait à la boucle de décision : sans inventaire de
/// formulaires, paramètres et endpoints, « tester une SQLi » reste un mot et le
/// LLM ne peut que se rabattre sur la seule vulnérabilité qu'il connaît, la CVE
/// corrélée au scan réseau.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebSurface {
    pub pages: usize,
    pub forms: usize,
    /// Noms de paramètres observés (pages + formulaires injectables).
    pub params: Vec<String>,
    /// Endpoints découverts, format `METHOD url`.
    pub endpoints: Vec<String>,
    /// Indices technologiques (WordPress, Laravel, Express…).
    #[serde(default)]
    pub tech_hints: Vec<String>,
    #[serde(default)]
    pub crawled_at: Option<String>,
}

impl WebSurface {
    /// Résumé compact pour l'affichage / le prompt.
    pub fn render(&self) -> String {
        let mut parts = vec![format!("{} page(s)", self.pages)];
        if self.forms > 0 {
            parts.push(format!("{} formulaire(s)", self.forms));
        }
        parts.push(format!("{} paramètre(s)", self.params.len()));
        if !self.endpoints.is_empty() {
            let sample: Vec<&str> = self.endpoints.iter().take(4).map(|s| s.as_str()).collect();
            parts.push(format!("endpoints=[{}]", sample.join(", ")));
        }
        if !self.tech_hints.is_empty() {
            let hints: Vec<&str> = self.tech_hints.iter().take(4).map(|s| s.as_str()).collect();
            parts.push(format!("techno={}", hints.join("/")));
        }
        parts.join(", ")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub cred_type: CredentialType,
    pub username: Option<String>,
    pub secret: String, // hash ou mot de passe (masqué dans logs)
    pub domain: Option<String>,
    pub source_host: String,
    pub service: String, // "ssh", "smb", "http-basic", etc.
    /// Hôtes où ce cred a été testé avec succès
    pub valid_on: Vec<String>,
    pub harvested_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    pub session_id: String,
    pub host: String,
    pub session_type: String, // "ssh", "shell", "meterpreter", "webshell"
    pub username: String,
    pub privileges: String, // "user", "admin", "root", "SYSTEM"
    pub opened_at: String,
    pub last_active: String,
    pub alive: bool,
    pub commands_run: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub phase: String, // "recon", "exploit", "postexploit", "lateral", etc.
    pub action: String,
    pub target: Option<String>,
    pub result: String, // "success", "failure", "partial"
    pub details: String,
    pub operator: String, // "ai_agent" | "human"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmMessage {
    pub role: String, // "system" | "user" | "assistant"
    pub content: String,
    pub timestamp: String,
}

// ── Structure principale ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignMemory {
    // Identité de la campagne
    pub session_id: String,
    pub campaign_name: String,
    pub objective: String,
    pub started_at: String,
    pub last_updated: String,
    pub completed: bool,

    // Scope
    pub initial_targets: Vec<String>,
    pub allowed_networks: Vec<String>,

    // Hôtes
    pub hosts: HashMap<String, HostMemory>,

    // Credentials récoltés
    pub credentials: Vec<Credential>,

    // Sessions actives
    pub sessions: HashMap<String, ActiveSession>,

    // Tentatives échouées : hôte (SANS port) → [technique canonique, ...]
    pub failed_attempts: HashMap<String, Vec<String>>,

    // Hôtes exclus (hors scope, déjà traités)
    pub excluded_hosts: Vec<String>,

    // Timeline complète des actions
    pub timeline: Vec<TimelineEntry>,

    // Contexte LLM multi-turn (historique de conversation)
    pub llm_context: Vec<LlmMessage>,

    // Statistiques
    pub stats: CampaignStats,

    /// Bandit d'hypothèses : postérieures Beta par `(hôte, classe de
    /// vulnérabilité)`. Persisté pour que l'exploration capitalise d'une
    /// campagne à l'autre au lieu de repartir de zéro.
    #[serde(default)]
    pub hypotheses: HypothesisTracker,

    // Chemin du fichier de persistance
    #[serde(skip)]
    pub persistence_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CampaignStats {
    pub hosts_discovered: usize,
    pub hosts_compromised: usize,
    pub credentials_harvested: usize,
    pub exploits_attempted: usize,
    pub exploits_succeeded: usize,
    pub pivots_executed: usize,
    pub ai_decisions: usize,
    pub human_confirmations: usize,
    pub human_rejections: usize,
}

// ── Canonicalisation (anti-boucle : dédup des tentatives) ────────────────────

/// Clé d'hôte normalisée : on retire systématiquement le port (`host:port` →
/// `host`) pour que les échecs soient enregistrés sous une clé unique quel que
/// soit le chemin de code appelant.
pub fn normalize_host_key(ip: &str) -> String {
    // Cas URL complète : on retire d'abord le schéma ("http://host:80/x" → "host:80/x").
    let no_scheme = match ip.split_once("://") {
        Some((_scheme, rest)) => rest,
        None => ip,
    };
    let h = no_scheme.splitn(2, '/').next().unwrap_or(no_scheme); // retire un éventuel "/path"
                                                                  // IPv6 entre crochets : [::1]:888 → ::1
    if let Some(rest) = h.strip_prefix('[') {
        if let Some((addr, _)) = rest.split_once(']') {
            return addr.to_string();
        }
    }
    // IPv4/nom d'hôte : host:port → host (on ne coupe qu'un seul ':')
    match h.split_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host.to_string(),
        _ => h.to_string(),
    }
}

/// Canonicalise un libellé de technique pour permettre la déduplication malgré
/// les variations de formulation du LLM.
///
/// Ex. : `"CVE-2014-6271 (Shellshock)"` et `"Shellshock (CVE-2014-6271)"`
///       → tous deux `"cve-2014-6271"`.
///       `"exploit/shellshock"` → `"shellshock"`.
pub fn canonical_technique(technique: &str) -> String {
    let t = technique.to_lowercase();

    // 1. Priorité absolue à l'identifiant CVE (le plus discriminant).
    if let Ok(re) = regex::Regex::new(r"cve-\d{4}-\d{4,7}") {
        if let Some(m) = re.find(&t) {
            return m.as_str().to_string();
        }
    }

    // 2. Familles connues (alias → clé stable).
    const FAMILIES: [(&str, &str); 20] = [
        ("shellshock", "shellshock"),
        ("log4shell", "log4shell"),
        ("log4j", "log4shell"),
        ("spring4shell", "spring4shell"),
        ("eternalblue", "ms17-010"),
        ("ms17-010", "ms17-010"),
        ("heartbleed", "heartbleed"),
        ("vsftpd", "vsftpd-backdoor"),
        ("proftpd", "proftpd"),
        ("smuggling", "http-smuggling"),
        ("traversal", "path-traversal"),
        ("kerberoast", "kerberoast"),
        ("as-rep", "asrep-roast"),
        ("dcsync", "dcsync"),
        ("ssti", "ssti"),
        ("ssrf", "ssrf"),
        ("xxe", "xxe"),
        ("sqli", "sqli"),
        ("sql injection", "sqli"),
        ("xss", "xss"),
    ];
    for (needle, canon) in FAMILIES {
        if t.contains(needle) {
            return canon.to_string();
        }
    }

    // 3. Repli : alphanumérique normalisé (évite que "exploit/shellshock" et
    //    "exploit_shellshock_v2" soient vus comme deux techniques distinctes).
    let norm: String = t.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if norm.is_empty() {
        t
    } else {
        norm
    }
}

/// Parse un libellé de service de la forme `"nom/port"` (ex. `"http/80"`,
/// `"https/443"`) en `(nom_normalisé, port)`.
///
/// Tolère les variantes produites par les différents scanners :
/// `"ssl/http/443"`, `"tcp/80"`, `"http-alt/8080"`, ou l'absence de port.
/// Le port vaut `0` quand il n'est pas présent dans le libellé.
pub fn parse_service(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Le port est le dernier segment purement numérique (`nom/port`).
    let mut name = s.to_string();
    let mut port: u16 = 0;
    if let Some((head, tail)) = s.rsplit_once('/') {
        if let Ok(p) = tail.trim().parse::<u16>() {
            port = p;
            name = head.to_string();
        }
    }

    // Normalise le nom : minuscules, on jette les qualificatifs de transport
    // (`tcp/`, `udp/`, `ssl/`, `tls/`) et on garde le dernier segment parlant.
    let lower = name.to_lowercase();
    let normalized = lower
        .split(|c| c == '/' || c == ':')
        .filter(|seg| !seg.is_empty() && !matches!(*seg, "tcp" | "udp" | "ssl" | "tls"))
        .last()
        .unwrap_or(lower.as_str())
        .to_string();

    if normalized.is_empty() {
        return None;
    }
    Some((normalized, port))
}

#[cfg(test)]
mod service_parse_tests {
    use super::parse_service;

    #[test]
    fn parses_common_service_labels() {
        assert_eq!(parse_service("http/80"), Some(("http".to_string(), 80)));
        assert_eq!(parse_service("https/443"), Some(("https".to_string(), 443)));
        assert_eq!(
            parse_service("ssl/http/443"),
            Some(("http".to_string(), 443))
        );
        assert_eq!(parse_service("tcp/22"), Some(("tcp".to_string(), 22)));
        assert_eq!(
            parse_service("http-alt/8080"),
            Some(("http-alt".to_string(), 8080))
        );
        assert_eq!(parse_service("ssh"), Some(("ssh".to_string(), 0)));
        assert_eq!(parse_service("   "), None);
    }
}

// ── Implémentation ────────────────────────────────────────────────────────────

impl CampaignMemory {
    /// Créer une nouvelle campagne ou reprendre depuis le disque
    pub fn load_or_create(
        session_id: &str,
        campaign_name: &str,
        objective: &str,
        initial_targets: Vec<String>,
        save_dir: &str,
    ) -> Result<Self> {
        let path = PathBuf::from(save_dir).join(format!("campaign_{}.json", session_id));

        // Reprendre une campagne existante
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let mut mem: CampaignMemory = serde_json::from_str(&content)?;
            mem.persistence_path = path;
            println!(
                "📂 Campagne reprise : {} ({} hôtes, {} creds)",
                mem.session_id,
                mem.hosts.len(),
                mem.credentials.len()
            );
            return Ok(mem);
        }

        // Nouvelle campagne
        std::fs::create_dir_all(save_dir)?;
        let now = Utc::now().to_rfc3339();
        let mem = Self {
            session_id: session_id.to_string(),
            campaign_name: campaign_name.to_string(),
            objective: objective.to_string(),
            started_at: now.clone(),
            last_updated: now,
            completed: false,
            initial_targets,
            allowed_networks: vec![],
            hosts: HashMap::new(),
            credentials: vec![],
            sessions: HashMap::new(),
            failed_attempts: HashMap::new(),
            excluded_hosts: vec![],
            timeline: vec![],
            llm_context: vec![],
            stats: CampaignStats::default(),
            hypotheses: HypothesisTracker::new(),
            persistence_path: path,
        };

        mem.save()?;
        println!(
            "🆕 Nouvelle campagne : {} — objectif: {}",
            session_id, objective
        );
        Ok(mem)
    }

    /// Sauvegarder l'état sur disque
    pub fn save(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        // Écriture atomique via fichier temporaire
        let tmp = self.persistence_path.with_extension("tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &self.persistence_path)?;
        Ok(())
    }

    // ── Gestion des hôtes ────────────────────────────────────────────────────

    pub fn add_host(&mut self, ip: &str, services: Vec<String>) {
        let now = Utc::now().to_rfc3339();
        self.hosts
            .entry(ip.to_string())
            .or_insert_with(|| HostMemory {
                ip: ip.to_string(),
                hostname: None,
                os: None,
                state: HostState::Discovered,
                services,
                confirmed_cves: vec![],
                exploit_attempts: HashMap::new(),
                session_id: None,
                pivot_depth: 0,
                notes: vec![],
                first_seen: now.clone(),
                last_updated: now,
                web_surface: None,
            });
        self.stats.hosts_discovered = self.hosts.len();
    }

    /// Enregistre (ou remplace) l'inventaire de surface web d'un hôte.
    ///
    /// Si la surface s'est **étendue** (nouveaux paramètres ou endpoints), les
    /// classes d'injection déjà marquées comme testées sont réouvertes : un
    /// nouveau point d'injection rouvre l'hypothèse, alors que l'ancien échec
    /// portait sur une surface différente. C'est la version web de l'adage
    /// « un échec ne vaut que pour la surface testée ».
    pub fn set_web_surface(&mut self, ip: &str, surface: WebSurface) {
        let host = normalize_host_key(ip);
        let grew = match self.hosts.get(&host).and_then(|h| h.web_surface.as_ref()) {
            Some(old) => {
                surface.params.len() > old.params.len()
                    || surface.endpoints.len() > old.endpoints.len()
                    || surface.forms > old.forms
            }
            None => false,
        };

        if let Some(h) = self.hosts.get_mut(&host) {
            h.web_surface = Some(surface);
            h.last_updated = Utc::now().to_rfc3339();
        }

        if grew {
            if let Some(tried) = self.hypotheses.tried.get_mut(&host) {
                tried.remove(&VulnClass::SqlInjection);
                tried.remove(&VulnClass::Xss);
                tried.remove(&VulnClass::Ssti);
                tried.remove(&VulnClass::CmdInjection);
                tried.remove(&VulnClass::Lfi);
                tried.remove(&VulnClass::Ssrf);
                tried.remove(&VulnClass::OpenRedirect);
                tried.remove(&VulnClass::Xxe);
                tried.remove(&VulnClass::FileUpload);
            }
        }
    }

    /// Preuves de surface utilisées par le gating d'applicabilité du bandit.
    pub fn surface_evidence(&self, ip: &str) -> SurfaceEvidence {
        let host = normalize_host_key(ip);
        let Some(h) = self.hosts.get(&host) else {
            return SurfaceEvidence::default();
        };
        let has_cve = !h.confirmed_cves.is_empty();
        match &h.web_surface {
            Some(s) => SurfaceEvidence::from_surface(s, has_cve),
            // Surface pas encore crawlée : on se rabat sur les services connus
            // pour ne pas exclure à tort les classes purement HTTP.
            None => SurfaceEvidence {
                has_http: h.services.iter().any(|s| {
                    parse_service(s)
                        .map(|(name, _)| name.starts_with("http"))
                        .unwrap_or(false)
                }),
                has_confirmed_cve: has_cve,
                ..Default::default()
            },
        }
    }

    /// Nombre de paramètres et endpoints uniques cartographiés, tous hôtes
    /// confondus. Signal de nouveauté (couverture) pour le moteur RL.
    pub fn surface_coverage(&self) -> u32 {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for h in self.hosts.values() {
            if let Some(s) = &h.web_surface {
                for p in &s.params {
                    seen.insert(p.as_str());
                }
                for e in &s.endpoints {
                    seen.insert(e.as_str());
                }
            }
        }
        seen.len() as u32
    }

    /// Hôtes exposant un service HTTP.
    pub fn http_hosts(&self) -> Vec<String> {
        self.hosts
            .values()
            .filter(|h| {
                h.services.iter().any(|s| {
                    parse_service(s)
                        .map(|(name, _)| name.starts_with("http"))
                        .unwrap_or(false)
                })
            })
            .map(|h| h.ip.clone())
            .collect()
    }

    /// Enregistre une observation du bandit d'hypothèses (hôte, classe).
    pub fn record_hypothesis(&mut self, ip: &str, class: VulnClass, success: bool) {
        let host = normalize_host_key(ip);
        self.hypotheses.record(&host, class, success);
    }

    pub fn update_host_state(&mut self, ip: &str, state: HostState) {
        if let Some(h) = self.hosts.get_mut(ip) {
            h.state = state.clone();
            h.last_updated = Utc::now().to_rfc3339();
            if state == HostState::Compromised || state == HostState::Exploited {
                self.stats.hosts_compromised = self
                    .hosts
                    .values()
                    .filter(|h| matches!(h.state, HostState::Compromised | HostState::Exploited))
                    .count();
            }
        }
    }

    /// True si l'hôte appartient au périmètre autorisé de la campagne.
    ///
    /// Règles (fail-closed côté périmètre) :
    ///   - `excluded_hosts` (deny-list) est prioritaire → hors scope si correspondance ;
    ///   - `allowed_networks` vide → aucune restriction (tout est autorisé) ;
    ///   - sinon l'hôte doit appartenir à au moins une entrée (CIDR, IP exacte
    ///     ou domaine, avec correspondance des sous-domaines).
    pub fn is_in_scope(&self, host: &str) -> bool {
        let h = normalize_host_key(host).to_lowercase();
        if h.is_empty() {
            return true;
        }

        let matches = |pattern: &str| -> bool {
            let p = pattern.trim().to_lowercase();
            if p.is_empty() {
                return false;
            }
            if let Ok(net) = p.parse::<ipnetwork::IpNetwork>() {
                return h
                    .parse::<std::net::IpAddr>()
                    .map(|ip| net.contains(ip))
                    .unwrap_or(false);
            }
            h == p || h.ends_with(&format!(".{}", p))
        };

        if self.excluded_hosts.iter().any(|e| matches(e)) {
            return false;
        }
        if self.allowed_networks.is_empty() {
            return true;
        }
        self.allowed_networks.iter().any(|a| matches(a))
    }

    pub fn record_exploit_attempt(&mut self, ip: &str, exploit_id: &str, success: bool) {
        // Clé d'hôte unifiée (sans port) + technique canonique : garantit qu'un
        // même exploit échoué est compté une seule fois quel que soit le chemin
        // d'appel (host vs host:port, libellés LLM variables).
        let host_key = normalize_host_key(ip);
        let tech_key = canonical_technique(exploit_id);

        if let Some(h) = self.hosts.get_mut(&host_key) {
            h.exploit_attempts.insert(tech_key.clone(), success);
        }
        self.stats.exploits_attempted += 1;
        if success {
            self.stats.exploits_succeeded += 1;
            // Un succès annule l'échec correspondant (l'exploit finit par marcher).
            if let Some(v) = self.failed_attempts.get_mut(&host_key) {
                v.retain(|t| t != &tech_key);
            }
        } else {
            let entry = self.failed_attempts.entry(host_key).or_default();
            if !entry.contains(&tech_key) {
                entry.push(tech_key); // dédup
            }
        }
    }

    /// Vérifier si un exploit a déjà été tenté (et échoué) sur un hôte.
    /// Comparaison sur clés canoniques → insensible au port et à la formulation.
    pub fn already_tried(&self, ip: &str, exploit_id: &str) -> bool {
        let host_key = normalize_host_key(ip);
        let tech_key = canonical_technique(exploit_id);
        self.failed_attempts
            .get(&host_key)
            .map(|v| v.contains(&tech_key))
            .unwrap_or(false)
    }

    /// Nombre de techniques distinctes déjà échouées sur un hôte.
    pub fn failed_count(&self, ip: &str) -> usize {
        self.failed_attempts
            .get(&normalize_host_key(ip))
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Liste (hôte → [techniques canoniques échouées]) pour l'injection LLM.
    pub fn failed_techniques_by_host(&self) -> Vec<(String, Vec<String>)> {
        let mut v: Vec<(String, Vec<String>)> = self
            .failed_attempts
            .iter()
            .filter(|(_, list)| !list.is_empty())
            .map(|(h, l)| (h.clone(), l.clone()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Toutes les techniques canoniques déjà échouées (tous hôtes confondus).
    pub fn all_failed_techniques(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for list in self.failed_attempts.values() {
            for t in list {
                if !out.contains(t) {
                    out.push(t.clone());
                }
            }
        }
        out
    }

    // ── Credentials ──────────────────────────────────────────────────────────

    pub fn add_credential(&mut self, cred: Credential) {
        // Éviter les doublons
        if !self
            .credentials
            .iter()
            .any(|c| c.secret == cred.secret && c.username == cred.username)
        {
            self.credentials.push(cred);
            self.stats.credentials_harvested = self.credentials.len();
        }
    }

    pub fn mark_credential_valid(&mut self, username: &str, secret: &str, host: &str) {
        if let Some(c) = self
            .credentials
            .iter_mut()
            .find(|c| c.username.as_deref() == Some(username) && c.secret == secret)
        {
            if !c.valid_on.contains(&host.to_string()) {
                c.valid_on.push(host.to_string());
            }
        }
    }

    /// Récupérer tous les credentials non encore testés sur un hôte
    pub fn untested_credentials(&self, host: &str) -> Vec<&Credential> {
        self.credentials
            .iter()
            .filter(|c| !c.valid_on.contains(&host.to_string()))
            .collect()
    }

    // ── Sessions ─────────────────────────────────────────────────────────────

    pub fn open_session(&mut self, session: ActiveSession) {
        self.stats.hosts_compromised += 1;
        if let Some(h) = self.hosts.get_mut(&session.host) {
            h.session_id = Some(session.session_id.clone());
            h.state = HostState::Compromised;
        }
        self.sessions.insert(session.session_id.clone(), session);
    }

    pub fn active_sessions(&self) -> Vec<&ActiveSession> {
        self.sessions.values().filter(|s| s.alive).collect()
    }

    pub fn compromised_hosts(&self) -> Vec<&HostMemory> {
        self.hosts
            .values()
            .filter(|h| matches!(h.state, HostState::Compromised | HostState::Pivoting))
            .collect()
    }

    // ── Timeline ─────────────────────────────────────────────────────────────

    pub fn log(
        &mut self,
        phase: &str,
        action: &str,
        target: Option<&str>,
        result: &str,
        details: &str,
        operator: &str,
    ) {
        self.timeline.push(TimelineEntry {
            timestamp: Utc::now().to_rfc3339(),
            phase: phase.to_string(),
            action: action.to_string(),
            target: target.map(|s| s.to_string()),
            result: result.to_string(),
            details: details.to_string(),
            operator: operator.to_string(),
        });
        self.last_updated = Utc::now().to_rfc3339();
    }

    // ── Contexte LLM multi-turn ───────────────────────────────────────────────

    pub fn push_llm_message(&mut self, role: &str, content: &str) {
        self.llm_context.push(LlmMessage {
            role: role.to_string(),
            content: content.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        });
        // Garder les 40 derniers messages pour éviter les contextes trop longs
        if self.llm_context.len() > 40 {
            // Garder toujours le message système (index 0)
            let system = self.llm_context.first().cloned();
            self.llm_context = self.llm_context.split_off(self.llm_context.len() - 39);
            if let Some(sys) = system {
                self.llm_context.insert(0, sys);
            }
        }
    }

    pub fn llm_messages_for_api(&self) -> Vec<serde_json::Value> {
        self.llm_context
            .iter()
            .map(|m| serde_json::json!({ "role": m.role, "content": m.content }))
            .collect()
    }

    // ── Résumé pour le LLM ───────────────────────────────────────────────────

    /// Génère un résumé compact de l'état actuel pour le contexte LLM
    pub fn state_summary(&self) -> String {
        let compromised: Vec<String> = self
            .compromised_hosts()
            .iter()
            .map(|h| h.ip.clone())
            .collect();

        let vuln_hosts: Vec<String> = self
            .hosts
            .values()
            .filter(|h| matches!(h.state, HostState::Vulnerable))
            .map(|h| format!("{}({})", h.ip, h.confirmed_cves.join(",")))
            .collect();

        let creds_summary: Vec<String> = self
            .credentials
            .iter()
            .take(5)
            .map(|c| {
                format!(
                    "{}@{}({})",
                    c.username.as_deref().unwrap_or("?"),
                    c.service,
                    c.source_host
                )
            })
            .collect();

        // Levier A : le LLM doit connaître la LISTE réelle des techniques
        // échouées (et non un simple compteur) pour ne pas les reproposer.
        let failed_list = self.failed_techniques_by_host();
        let failed_text = if failed_list.is_empty() {
            "aucune".to_string()
        } else {
            failed_list
                .iter()
                .map(|(h, l)| format!("{} → [{}]", h, l.join(", ")))
                .collect::<Vec<_>>()
                .join(" | ")
        };

        // Levier B : inventaire de la surface d'attaque web. Sans lui, le LLM
        // ne peut raisonner qu'en termes de CVE (« rien ne dit que c'est la
        // bonne faille ») alors que le vecteur réel est souvent applicatif.
        let surface_text = self.attack_surface_summary();

        // Levier C : hypothèses classées par Thompson sampling. On expose au
        // LLM une *liste ordonnée* de classes plausibles, pas une conclusion.
        let hyp_text = self.hypothesis_summary(4);

        format!(
            "ÉTAT CAMPAGNE [{}] objectif={}\n\
             Hôtes: {}/{} découverts, {} compromis\n\
             Compromis: {}\n\
             Vulnérables (CVE corrélées): {}\n\
             Credentials: {} ({} ...)\n\
             Sessions actives: {}\n\
             Techniques DÉJÀ ÉCHOUÉES (NE JAMAIS reproposer à l'identique) : {}\n\
             SURFACE WEB CARTOGRAPHIÉE : {}\n\
             HYPOTHÈSES PRIORITAIRES (bandit bayésien — à tester en priorité, \
             l'exploit CVE n'est qu'UNE hypothèse parmi d'autres) : {}",
            self.session_id,
            self.objective,
            self.hosts.len(),
            self.initial_targets.len(),
            compromised.len(),
            if compromised.is_empty() {
                "aucun".to_string()
            } else {
                compromised.join(", ")
            },
            if vuln_hosts.is_empty() {
                "aucun".to_string()
            } else {
                vuln_hosts.join(", ")
            },
            self.credentials.len(),
            creds_summary.join(", "),
            self.active_sessions().len(),
            failed_text,
            surface_text,
            hyp_text,
        )
    }

    /// Inventaire compact des surfaces web connues (hôtes non compromis).
    pub fn attack_surface_summary(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        for h in self.hosts.values() {
            if matches!(h.state, HostState::Compromised | HostState::Done) {
                continue;
            }
            let has_http = h.services.iter().any(|s| {
                parse_service(s)
                    .map(|(n, _)| n.starts_with("http"))
                    .unwrap_or(false)
            });
            if !has_http {
                continue;
            }
            match &h.web_surface {
                Some(ws) => lines.push(format!("{} → {}", h.ip, ws.render())),
                None => lines.push(format!(
                    "{} → service HTTP détecté, surface non encore crawlée",
                    h.ip
                )),
            }
        }
        if lines.is_empty() {
            "aucune cible HTTP active".to_string()
        } else {
            lines.join(" | ")
        }
    }

    /// Hypothèses les plus probables par hôte HTTP, classées par le bandit.
    pub fn hypothesis_summary(&self, top_n: usize) -> String {
        let mut lines: Vec<String> = Vec::new();
        for h in self.hosts.values() {
            if matches!(h.state, HostState::Compromised | HostState::Done) {
                continue;
            }
            let ev = self.surface_evidence(&h.ip);
            if !ev.has_http {
                continue;
            }
            let (name, _) = self.host_http_endpoint(&h.ip);
            let target = name.unwrap_or_else(|| h.ip.clone());
            lines.push(format!(
                "{} → {}",
                target,
                self.hypotheses.summary_for(&h.ip, &ev, top_n)
            ));
        }
        if lines.is_empty() {
            "aucune hypothèse (pas de surface web identifiée)".to_string()
        } else {
            lines.join(" | ")
        }
    }

    /// (nom d'hôte lisible, port) de la première exposition HTTP d'un hôte.
    pub fn host_http_endpoint(&self, ip: &str) -> (Option<String>, u16) {
        let host = normalize_host_key(ip);
        let Some(h) = self.hosts.get(&host) else {
            return (None, 0);
        };
        let label = h.hostname.clone().unwrap_or_else(|| h.ip.clone());

        // Deux passes : on privilégie un service HTTP en clair (port 80) sur
        // HTTPS. Un endpoint HTTPS peut accepter la connexion TCP tout en
        // bloquant la poignée de main TLS (pare-feu applicatif, tarpit) : tout
        // crawl échoue alors que le service en clair répond. Si HTTPS redirige
        // vers un TLS fonctionnel, le client suit la redirection — choisir le
        // clair ne fait donc rien perdre.
        let mut tls_fallback: Option<(String, u16)> = None;
        for s in &h.services {
            let Some((name, port)) = parse_service(s) else {
                continue;
            };
            if !name.starts_with("http") {
                continue;
            }
            let is_tls = port == 443 || name == "https";
            let scheme = if is_tls { "https" } else { "http" };
            let candidate = (format!("{}://{}", scheme, label), port);
            if is_tls {
                if tls_fallback.is_none() {
                    tls_fallback = Some(candidate);
                }
            } else {
                return (Some(candidate.0), candidate.1);
            }
        }
        match tls_fallback {
            Some((url, port)) => (Some(url), port),
            None => (None, 0),
        }
    }

    /// Générer un rapport narratif Markdown
    pub fn generate_markdown_report(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!(
            "# Rapport de campagne — {}\n\n",
            self.campaign_name
        ));
        md.push_str(&format!("**Session** : `{}`  \n", self.session_id));
        md.push_str(&format!("**Objectif** : {}  \n", self.objective));
        md.push_str(&format!("**Démarré** : {}  \n", self.started_at));
        md.push_str(&format!("**Dernière MAJ** : {}  \n\n", self.last_updated));

        md.push_str("## Statistiques\n\n");
        md.push_str(&format!("| Métrique | Valeur |\n|---|---|\n"));
        md.push_str(&format!(
            "| Hôtes découverts | {} |\n",
            self.stats.hosts_discovered
        ));
        md.push_str(&format!(
            "| Hôtes compromis | {} |\n",
            self.stats.hosts_compromised
        ));
        md.push_str(&format!(
            "| Credentials récoltés | {} |\n",
            self.stats.credentials_harvested
        ));
        md.push_str(&format!(
            "| Exploits tentés | {} |\n",
            self.stats.exploits_attempted
        ));
        md.push_str(&format!(
            "| Exploits réussis | {} |\n",
            self.stats.exploits_succeeded
        ));
        md.push_str(&format!("| Décisions IA | {} |\n", self.stats.ai_decisions));
        md.push_str(&format!(
            "| Confirmations humaines | {} |\n\n",
            self.stats.human_confirmations
        ));

        md.push_str("## Hôtes compromis\n\n");
        for h in self.compromised_hosts() {
            md.push_str(&format!("### {}\n", h.ip));
            if let Some(os) = &h.os {
                md.push_str(&format!("- OS : {}\n", os));
            }
            md.push_str(&format!("- Services : {}\n", h.services.join(", ")));
            md.push_str(&format!("- CVEs : {}\n", h.confirmed_cves.join(", ")));
            if let Some(sid) = &h.session_id {
                md.push_str(&format!("- Session : `{}`\n", sid));
            }
            md.push('\n');
        }

        md.push_str("## Timeline\n\n");
        md.push_str("| Heure | Phase | Action | Cible | Résultat |\n");
        md.push_str("|---|---|---|---|---|\n");
        for e in &self.timeline {
            let ts = &e.timestamp[11..19]; // HH:MM:SS
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                ts,
                e.phase,
                e.action,
                e.target.as_deref().unwrap_or("-"),
                e.result
            ));
        }

        md
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — anti-boucle (dédup des tentatives)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_host_key_strips_port() {
        // Le bug observé : `localhost` et `localhost:888` créaient 2 entrées.
        assert_eq!(normalize_host_key("localhost:888"), "localhost");
        assert_eq!(normalize_host_key("localhost"), "localhost");
        assert_eq!(normalize_host_key("192.0.2.10:443"), "192.0.2.10");
        assert_eq!(normalize_host_key("[2001:db8::1]:8080"), "2001:db8::1");
        assert_eq!(normalize_host_key("http://example.org:80/x"), "example.org");
    }

    #[test]
    fn test_canonical_technique_unifies_llm_wording() {
        // Les deux formulations vues dans le log doivent converger.
        assert_eq!(
            canonical_technique("CVE-2014-6271 (Shellshock)"),
            "cve-2014-6271"
        );
        assert_eq!(
            canonical_technique("Shellshock (CVE-2014-6271)"),
            "cve-2014-6271"
        );
        assert_eq!(canonical_technique("CVE-2017-15715"), "cve-2017-15715");
        assert_eq!(
            canonical_technique("CVE-2021-41773 (Apache Path Traversal RCE)"),
            "cve-2021-41773"
        );
        // Sans CVE : repli sur la famille.
        assert_eq!(canonical_technique("exploit/shellshock"), "shellshock");
        assert_eq!(canonical_technique("nrtg_exploit_log4shell"), "log4shell");
    }

    #[test]
    fn test_record_and_already_tried_dedup() {
        let tmp = std::env::temp_dir().join("nrtg_test_dedup");
        let _ = std::fs::remove_dir_all(&tmp); // test hermétique
        let mut mem = CampaignMemory::load_or_create(
            "test-dedup",
            "Test dédup",
            "objectif test",
            vec!["localhost:888".into()],
            tmp.to_str().unwrap(),
        )
        .expect("création campagne");

        // Deux échecs formulés différemment sur le même hôte → 1 seule entrée.
        mem.record_exploit_attempt("localhost", "CVE-2014-6271 (Shellshock)", false);
        mem.record_exploit_attempt("localhost:888", "Shellshock (CVE-2014-6271)", false);

        assert_eq!(
            mem.failed_count("localhost"),
            1,
            "les variantes doivent être dédupliquées"
        );
        assert!(
            !mem.already_tried("localhost:888", "exploit/shellshock"),
            "shellshock sans CVE est une clé distincte d'un CVE-id"
        );
        assert!(mem.already_tried("localhost", "Shellshock (CVE-2014-6271)"));

        // Un succès doit annuler l'échec correspondant.
        mem.record_exploit_attempt("localhost", "CVE-2014-6271", true);
        assert_eq!(mem.failed_count("localhost"), 0);
        assert!(!mem.already_tried("localhost", "CVE-2014-6271 (Shellshock)"));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
