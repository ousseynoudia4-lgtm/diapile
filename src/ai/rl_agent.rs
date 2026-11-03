//! DIAPILE — Reinforcement Learning Agent sur la Kill-Chain

//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.

#![allow(dead_code, unused_imports, unused_variables)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::attack_planner::{ActionType, AttackPlan, PlannedAction};
use super::campaign_memory::{canonical_technique, CampaignMemory, HostState};

// ─────────────────────────────────────────────────────────────────────────────
// 1. Représentation d'état (signature compacte + hachable)
// ─────────────────────────────────────────────────────────────────────────────

/// Signature d'état compacte et déterministe extraite de la `CampaignMemory`.
/// C'est l'entrée de la Q-table. On évite les floats pour garantir
/// l'égalité parfaite (clé de HashMap).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct StateSignature {
    /// Nombre d'hôtes dans chaque état.
    pub hosts_discovered: u32,
    pub hosts_scanned: u32,
    pub hosts_vulnerable: u32,
    pub hosts_exploited: u32,
    pub hosts_compromised: u32,
    /// Ressources récoltées.
    pub credentials: u32,
    pub active_sessions: u32,
    /// Niveau de bruit estimé (0=furtif, 1=bruyant).
    /// Quantifié en 4 paliers pour rester discretisable.
    pub noise_bucket: NoiseBucket,
    /// Phase actuelle de la kill-chain.
    pub phase: KillChainPhase,
    /// Objectif atteint ?
    pub objective_reached: bool,
    /// Palier de nouveauté de la surface d'attaque cartographiée (paramètres et
    /// endpoints uniques, tous hôtes confondus). C'est l'analogue du signal de
    /// *coverage* d'AFL : progresser de palier prouve que les actions
    /// découvrent réellement de nouveaux points d'entrée au lieu de reboucler.
    pub surface_novelty: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum NoiseBucket {
    /// Aucun échec et aucune détection WAF : état le plus discret.
    Silent,
    Low,      // 1-2 échecs
    Medium,   // 3-5 échecs
    High,     // 6+ échecs
    WafBlock, // Blocage WAF détecté (prioritaire sur High)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum KillChainPhase {
    Recon,
    Scanning,
    Enumeration,
    Exploitation,
    PostExploitation,
    LateralMovement,
    ObjectiveReached,
}

impl StateSignature {
    /// Construit la signature depuis une campagne en cours.
    pub fn from_memory(mem: &CampaignMemory) -> Self {
        let mut discovered = 0u32;
        let mut scanned = 0u32;
        let mut vulnerable = 0u32;
        let mut exploited = 0u32;
        let mut compromised = 0u32;

        for h in mem.hosts.values() {
            match h.state {
                HostState::Discovered => discovered += 1,
                HostState::Scanned => scanned += 1,
                HostState::Vulnerable => vulnerable += 1,
                HostState::Exploited => exploited += 1,
                HostState::Compromised | HostState::Pivoting => compromised += 1,
                HostState::Done => {}
            }
        }

        let total_failed: usize = mem.failed_attempts.values().map(|v| v.len()).sum();

        // Détection de blocage WAF dans la timeline ou les échecs récents
        let has_waf = mem.timeline.iter().any(|e| {
            e.details.to_lowercase().contains("waf")
                || e.details.to_lowercase().contains("403 forbidden")
                || e.details.to_lowercase().contains("429 too many")
        });

        let noise_bucket = if has_waf {
            NoiseBucket::WafBlock
        } else if total_failed == 0 {
            NoiseBucket::Silent
        } else if total_failed <= 2 {
            NoiseBucket::Low
        } else if total_failed <= 5 {
            NoiseBucket::Medium
        } else {
            NoiseBucket::High
        };

        let phase = if compromised > 0 {
            KillChainPhase::PostExploitation
        } else if exploited > 0 {
            KillChainPhase::Exploitation
        } else if vulnerable > 0 {
            KillChainPhase::Enumeration
        } else if scanned > 0 {
            KillChainPhase::Scanning
        } else {
            KillChainPhase::Recon
        };

        Self {
            hosts_discovered: discovered,
            hosts_scanned: scanned,
            hosts_vulnerable: vulnerable,
            hosts_exploited: exploited,
            hosts_compromised: compromised,
            credentials: mem.credentials.len() as u32,
            active_sessions: mem.sessions.values().filter(|s| s.alive).count() as u32,
            noise_bucket,
            phase,
            objective_reached: mem.completed,
            surface_novelty: Self::bucket(mem.surface_coverage()),
        }
    }

    /// Palier logarithmique d'un compteur : deux états de magnitude voisine
    /// partagent la même clé. C'est le mécanisme de **généralisation** du
    /// Q-learning tabulaire — sans lui, l'agent ne fait que mémoriser chaque
    /// combinaison exacte de compteurs et ne transfert rien entre cibles.
    fn bucket(n: u32) -> u8 {
        match n {
            0 => 0,
            1 => 1,
            2..=3 => 2,
            4..=7 => 3,
            8..=15 => 4,
            16..=31 => 5,
            _ => 6,
        }
    }

    /// Clé textuelle **agrégée** pour la Q-table.
    ///
    /// Les compteurs bruts sont remplacés par des paliers (`bucket`) : une
    /// politique apprise sur une cible à 3 hôtes se réutilise sur une cible à 5
    /// hôtes. `objective_reached` fait désormais partie de la clé — sinon un
    /// état terminé serait confondu avec un état en cours.
    pub fn key(&self) -> String {
        format!(
            "d{}_s{}_vuln{}_own{}_cred{}_sess{}_cov{}_noise{:?}_phase{:?}{}",
            Self::bucket(self.hosts_discovered),
            Self::bucket(self.hosts_scanned),
            Self::bucket(self.hosts_vulnerable),
            Self::bucket(self.hosts_exploited + self.hosts_compromised),
            Self::bucket(self.credentials),
            Self::bucket(self.active_sessions),
            self.surface_novelty,
            self.noise_bucket,
            self.phase,
            if self.objective_reached { "_done" } else { "" },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Fonction de récompense
// ─────────────────────────────────────────────────────────────────────────────

/// Poids de récompense ajustables. L'opérateur peut les tuner selon
/// l'objectif (stealth vs vitesse).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardConfig {
    pub shell_acquired: f32,       // nouveau shell/session
    pub credential_harvested: f32, // cred volé
    pub exploit_success: f32,      // exploit réussi (sans shell)
    pub host_vulnerable: f32,      // nouvel hôte jugé vulnérable
    pub host_discovered: f32,      // nouvel hôte découvert
    pub exploit_failed: f32,       // exploit échoué
    pub detection_signal: f32,     // WAF/IDS/IP ban détecté
    pub repeated_failure: f32,     // retenter un exploit déjà échoué
    pub action_cost: f32,          // coût fixe par action (efficacité)
    pub curiosity_bonus: f32,      // bonus pour explorer de nouveaux états
    pub stealth_bonus: f32,        // bonus pour chaque action réussie sans bruit
    pub objective_reached: f32,    // objectif de campagne atteint
    pub surface_novelty: f32,      // nouveaux points d'entrée cartographiés (type AFL)
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            shell_acquired: 100.0,
            credential_harvested: 50.0,
            exploit_success: 20.0,
            host_vulnerable: 15.0,
            host_discovered: 10.0,
            exploit_failed: -10.0,
            detection_signal: -50.0, // Pénalité plus forte pour la détection
            repeated_failure: -20.0,
            action_cost: -2.0, // Coût réduit pour encourager l'exploration
            curiosity_bonus: 5.0,
            stealth_bonus: 10.0,
            objective_reached: 500.0,
            surface_novelty: 8.0,
        }
    }
}

/// Calcule la récompense de la transition `prev` → `curr` suite à `action`.
pub fn compute_reward(
    prev: &StateSignature,
    curr: &StateSignature,
    action: &ActionType,
    cfg: &RewardConfig,
    detection: bool,
    repeated_failure: bool,
) -> f32 {
    let mut r = cfg.action_cost;

    // Shell acquis
    if curr.active_sessions > prev.active_sessions
        || curr.hosts_compromised > prev.hosts_compromised
    {
        r += cfg.shell_acquired;
    }
    // Credentials
    if curr.credentials > prev.credentials {
        r += cfg.credential_harvested * (curr.credentials - prev.credentials) as f32;
    }
    // Exploit réussi
    if curr.hosts_exploited > prev.hosts_exploited {
        r += cfg.exploit_success;
    }
    // Hôte vulnérable
    if curr.hosts_vulnerable > prev.hosts_vulnerable {
        r += cfg.host_vulnerable;
    }
    // Hôte découvert
    if curr.hosts_discovered > prev.hosts_discovered {
        r += cfg.host_discovered;
    }
    // Échec d'exploit
    if matches!(action, ActionType::Exploit)
        && curr.hosts_exploited == prev.hosts_exploited
        && curr.active_sessions == prev.active_sessions
    {
        r += cfg.exploit_failed;
    }
    // Détection
    if detection {
        r += cfg.detection_signal;
    } else {
        // Bonus de furtivité si aucune détection sur une action sensible
        if matches!(
            action,
            ActionType::Exploit | ActionType::BruteForce | ActionType::Pivot
        ) {
            r += cfg.stealth_bonus;
        }
    }

    // Bonus de curiosité (découverte de nouveaux horizons)
    if curr.hosts_discovered > prev.hosts_discovered || curr.hosts_scanned > prev.hosts_scanned {
        r += cfg.curiosity_bonus;
    }

    // Nouveauté de surface (couverture type AFL) : chaque nouveau palier de
    // points d'entrée cartographiés est récompensé. C'est ce signal qui rend
    // l'exploration applicative rentable — sans lui, l'agent n'a aucune raison
    // de préférer découvrir un paramètre injectable plutôt que de reboucler.
    if curr.surface_novelty > prev.surface_novelty {
        r += cfg.surface_novelty * (curr.surface_novelty - prev.surface_novelty) as f32;
    }

    // Échec répété
    if repeated_failure {
        r += cfg.repeated_failure;
    }
    // Objectif atteint
    if curr.objective_reached && !prev.objective_reached {
        r += cfg.objective_reached;
    }

    r
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Expérience (SARSA-like) + buffer de replay priorisé
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Experience {
    pub state_key: String,
    pub action: ActionType,
    /// Famille de technique canonique exécutée (granularité P4).
    /// `None` = apprentissage au niveau `ActionType` uniquement.
    #[serde(default)]
    pub technique: Option<String>,
    pub reward: f32,
    pub next_state_key: String,
    pub done: bool,
    /// Priorité = |TD-error|, mise à jour pendant l'apprentissage.
    #[serde(default)]
    pub priority: f32,
}

impl Experience {
    pub fn new(
        state: &StateSignature,
        action: ActionType,
        reward: f32,
        next_state: &StateSignature,
        done: bool,
    ) -> Self {
        Self {
            state_key: state.key(),
            action,
            technique: None,
            reward,
            next_state_key: next_state.key(),
            done,
            priority: reward.abs().max(1.0), // priorité initiale = |r|
        }
    }

    /// Attache la technique canonique à l'expérience (granularité P4).
    pub fn with_technique(mut self, technique: Option<&str>) -> Self {
        self.technique = technique
            .filter(|t| !t.trim().is_empty())
            .map(|t| t.to_string());
        self
    }
}

/// Buffer de replay avec échantillonnage pondéré par priorité.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBuffer {
    pub experiences: Vec<Experience>,
    pub capacity: usize,
}

impl ReplayBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            experiences: Vec::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, exp: Experience) {
        if self.experiences.len() >= self.capacity {
            // FIFO : retire la moins prioritaire si le buffer est plein
            // (on garde les expériences à fort signal)
            if let Some(min_idx) = self
                .experiences
                .iter()
                .enumerate()
                .min_by(|a, b| {
                    a.1.priority
                        .partial_cmp(&b.1.priority)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(i, _)| i)
            {
                self.experiences.swap_remove(min_idx);
            }
        }
        self.experiences.push(exp);
    }

    pub fn len(&self) -> usize {
        self.experiences.len()
    }

    pub fn is_empty(&self) -> bool {
        self.experiences.is_empty()
    }

    /// Échantillonne `n` expériences pondérées par leur priorité.
    pub fn sample(&self, n: usize) -> Vec<&Experience> {
        use rand::seq::SliceRandom;
        use rand::thread_rng;

        if self.experiences.is_empty() {
            return Vec::new();
        }
        let n = n.min(self.experiences.len());

        // Poids = priorité + epsilon (évite les zéros)
        let total: f32 = self.experiences.iter().map(|e| e.priority + 1e-6).sum();
        let mut rng = thread_rng();
        let mut picked = HashSet::new();
        let mut result = Vec::with_capacity(n);

        while result.len() < n {
            let r: f32 = rand::Rng::gen_range(&mut rng, 0.0..total);
            let mut cum = 0.0;
            for (i, e) in self.experiences.iter().enumerate() {
                cum += e.priority + 1e-6;
                if cum >= r && !picked.contains(&i) {
                    picked.insert(i);
                    result.push(e);
                    break;
                }
            }
            // Sécurité anti-boucle infinie si n > expériences uniques
            if picked.len() >= self.experiences.len() {
                break;
            }
        }
        result
    }

    /// Échantillonne `n` **indices** d'expériences pondérés par priorité.
    /// Permet de mettre à jour la priorité (|TD-error|) après l'apprentissage.
    pub fn sample_indices(&self, n: usize) -> Vec<usize> {
        use rand::thread_rng;

        if self.experiences.is_empty() {
            return Vec::new();
        }
        let n = n.min(self.experiences.len());

        let total: f32 = self.experiences.iter().map(|e| e.priority + 1e-6).sum();
        let mut rng = thread_rng();
        let mut picked = HashSet::new();
        let mut result = Vec::with_capacity(n);

        while result.len() < n {
            let r: f32 = rand::Rng::gen_range(&mut rng, 0.0..total);
            let mut cum = 0.0;
            for (i, e) in self.experiences.iter().enumerate() {
                cum += e.priority + 1e-6;
                if cum >= r && !picked.contains(&i) {
                    picked.insert(i);
                    result.push(i);
                    break;
                }
            }
            if picked.len() >= self.experiences.len() {
                break;
            }
        }
        result
    }

    /// Persiste le buffer de replay sur disque (transfert d'expériences
    /// inter-campagne). La priorité (|TD-error|) est conservée, ce qui permet
    /// de reprendre l'échantillonnage priorisé sans « réchauffage ».
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Charge un buffer de replay depuis le disque. Retourne un buffer vide si
    /// le fichier est absent ou illisible. La capacité effective imposée par
    /// `capacity` prime sur celle du fichier : en cas de dépassement, les
    /// expériences à plus faible priorité sont écartées (même politique que
    /// `push`).
    pub fn load(path: &Path, capacity: usize) -> Self {
        let mut buffer = match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str::<ReplayBuffer>(&content)
                .unwrap_or_else(|_| ReplayBuffer::new(capacity)),
            Err(_) => ReplayBuffer::new(capacity),
        };
        buffer.capacity = capacity;
        buffer.trim_to_capacity();
        buffer
    }

    /// Réduit le buffer à sa capacité en conservant les priorités les plus
    /// élevées. Sans effet si le buffer est déjà dans les limites.
    fn trim_to_capacity(&mut self) {
        if self.experiences.len() <= self.capacity {
            return;
        }
        self.experiences.sort_by(|a, b| {
            b.priority
                .partial_cmp(&a.priority)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        self.experiences.truncate(self.capacity);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Q-table persistante (le cœur de l'innovation inter-campagne)
// ─────────────────────────────────────────────────────────────────────────────

/// Q-table : `state_key -> (action -> Q-valeur)`.
/// Persistée sur disque → **transfert d'apprentissage entre campagnes**.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QTable {
    pub values: HashMap<String, HashMap<String, f32>>,
}

impl QTable {
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    pub fn get(&self, state_key: &str, action: &ActionType) -> f32 {
        self.values
            .get(state_key)
            .and_then(|m| m.get(&action_key(action)))
            .copied()
            .unwrap_or(0.0)
    }

    pub fn set(&mut self, state_key: &str, action: &ActionType, value: f32) {
        self.values
            .entry(state_key.to_string())
            .or_default()
            .insert(action_key(action), value);
    }

    /// Q-valeur au niveau **action + famille de technique** (granularité P4).
    pub fn get_tech(&self, state_key: &str, action: &ActionType, technique: Option<&str>) -> f32 {
        self.values
            .get(state_key)
            .and_then(|m| m.get(&action_key_tech(action, technique)))
            .copied()
            .unwrap_or(0.0)
    }

    /// Écriture au niveau **action + famille de technique** (granularité P4).
    pub fn set_tech(
        &mut self,
        state_key: &str,
        action: &ActionType,
        technique: Option<&str>,
        value: f32,
    ) {
        self.values
            .entry(state_key.to_string())
            .or_default()
            .insert(action_key_tech(action, technique), value);
    }

    /// Meilleure action pour un état donné (argmax).
    ///
    /// La comparaison agrège la clé simple (`action`) et les clés fines
    /// (`action:technique`) : une politique écrite au niveau technique via
    /// `set_tech` reste ainsi visible par une lecture au niveau type, sinon
    /// `select_action` retomberait à tort sur l'exploration uniforme.
    pub fn best_action(&self, state_key: &str, available: &[ActionType]) -> Option<ActionType> {
        self.values.get(state_key)?;
        available
            .iter()
            .max_by(|a, b| {
                let qa = self.type_max_q(state_key, a);
                let qb = self.type_max_q(state_key, b);
                qa.partial_cmp(&qb).unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned()
    }

    /// Q-valeur agrégée au niveau **type d'action** : maximum sur la clé simple
    /// (`action`) et toutes les clés fines (`action:technique`). `None` si
    /// l'action n'a jamais été vue pour cet état.
    pub fn type_max_q(&self, state_key: &str, action: &ActionType) -> Option<f32> {
        let map = self.values.get(state_key)?;
        let base = action_key(action);
        let prefix = format!("{}:", base);
        let mut best: Option<f32> = None;
        for (k, v) in map {
            if k.as_str() == base.as_str() || k.starts_with(&prefix) {
                best = Some(best.map_or(*v, |b| b.max(*v)));
            }
        }
        best
    }

    /// Argmax sur des candidats `(ActionType, technique)` — granularité P4.
    /// Permet à l'agent d'apprendre *quelle* technique réussit, et pas seulement
    /// quel type d'action.
    pub fn best_plan_action(
        &self,
        state_key: &str,
        candidates: &[(ActionType, String)],
    ) -> Option<(ActionType, String)> {
        candidates
            .iter()
            .max_by(|a, b| {
                let qa = self.get_tech(state_key, &a.0, Some(&a.1));
                let qb = self.get_tech(state_key, &b.0, Some(&b.1));
                qa.partial_cmp(&qb).unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned()
    }

    /// Sauvegarde la Q-table sur disque (persistance inter-campagne).
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Charge la Q-table depuis le disque. Retourne une table vide si absent.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::new(),
        }
    }

    pub fn size(&self) -> usize {
        self.values.values().map(|m| m.len()).sum()
    }
}

/// État ε persisté sur disque (valeur courante + décisions vues).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpsilonState {
    pub epsilon: f32,
    #[serde(default)]
    pub decisions_seen: u32,
}

/// Charge l'état ε persisté. `None` si absent ou illisible — l'appelant
/// retombe alors sur le calcul depuis `epsilon_start`.
fn load_epsilon_state(path: &Path) -> Option<EpsilonState> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Écrit l'état ε sur disque (crée le dossier parent si nécessaire).
fn save_epsilon_state(path: &Path, state: &EpsilonState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_string_pretty(state)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Clé textuelle pour une action (sérialisation stable).
fn action_key(a: &ActionType) -> String {
    format!("{:?}", a).to_ascii_lowercase()
}

/// Clé d'action **fine** : `ActionType` + famille de technique canonique.
///
/// Sans cela, toutes les actions `Exploit` sont indistinguables pour la
/// Q-table : l'agent apprend qu'« exploiter » marche, jamais *quoi* exploiter.
/// La technique est canonisée via `canonical_technique` pour que
/// `"CVE-2014-6271 (Shellshock)"` et `"Shellshock"` partagent la même clé.
fn action_key_tech(a: &ActionType, technique: Option<&str>) -> String {
    match technique.map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => format!("{}:{}", action_key(a), canonical_technique(t)),
        None => action_key(a),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Agent RL principal
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RLAgentConfig {
    /// Taux d'apprentissage α.
    pub learning_rate: f32,
    /// Facteur d'actualisation γ.
    pub discount: f32,
    /// Probabilité d'exploration initiale.
    pub epsilon_start: f32,
    /// Probabilité d'exploration minimale.
    pub epsilon_min: f32,
    /// Facteur de décroissance d'ε appliqué à **chaque décision** (transition
    /// observée) et non plus une fois par campagne. La politique apprise est
    /// ainsi réellement exploitée après quelques dizaines/centaines d'actions,
    /// au lieu d'attendre des centaines de campagnes.
    pub epsilon_decay: f32,
    /// Taille du buffer de replay.
    pub replay_capacity: usize,
    /// Taille du mini-batch d'apprentissage.
    pub batch_size: usize,
    /// Nombre de campagnes vues (statistiques uniquement ; ε ne dépend plus
    /// de ce compteur mais du nombre de décisions).
    pub campaigns_seen: u32,
    /// Chemin de persistance de la Q-table.
    pub qtable_path: PathBuf,
    /// Chemin de persistance du buffer de replay (expériences inter-campagne).
    pub replay_path: PathBuf,
    /// Chemin de persistance de l'état ε (ε courant + décisions vues). Permet à
    /// la décroissance d'ε de survivre au redémarrage, sinon elle repartirait à
    /// `epsilon_start` à chaque lancement.
    pub epsilon_path: PathBuf,
}

impl Default for RLAgentConfig {
    fn default() -> Self {
        Self {
            learning_rate: 0.1,
            discount: 0.95,
            epsilon_start: 0.9,
            epsilon_min: 0.05,
            epsilon_decay: 0.99,
            replay_capacity: 10_000,
            batch_size: 32,
            campaigns_seen: 0,
            qtable_path: PathBuf::from("sessions/rl_qtable.json"),
            replay_path: PathBuf::from("sessions/rl_replay.json"),
            epsilon_path: PathBuf::from("sessions/rl_epsilon.json"),
        }
    }
}

/// Agent RL qui apprend la kill-chain par Q-learning + replay priorisé.
pub struct KillChainRLAgent {
    pub config: RLAgentConfig,
    pub rewards: RewardConfig,
    pub qtable: QTable,
    pub replay: ReplayBuffer,
    pub epsilon: f32,
    /// Nombre total de décisions (transitions observées) depuis l'origine —
    /// porte la décroissance d'ε et est persisté avec celui-ci.
    pub decisions_seen: u32,
}

impl KillChainRLAgent {
    /// Crée un agent et charge la Q-table et le buffer de replay persistés
    /// (transfert inter-campagne).
    pub fn new(config: RLAgentConfig, rewards: RewardConfig) -> Self {
        let qtable = QTable::load(&config.qtable_path);
        let replay = ReplayBuffer::load(&config.replay_path, config.replay_capacity);

        // Reprise de l'état ε persisté (décroissance par décision). En l'absence
        // de fichier, on retombe sur le calcul historique depuis `campaigns_seen`
        // pour rester compatible avec les installations existantes.
        let persisted = load_epsilon_state(&config.epsilon_path);
        let (epsilon, decisions_seen) = match persisted {
            Some(state) => (state.epsilon.max(config.epsilon_min), state.decisions_seen),
            None => (
                (config.epsilon_start * config.epsilon_decay.powi(config.campaigns_seen as i32))
                    .max(config.epsilon_min),
                config.campaigns_seen,
            ),
        };

        Self {
            qtable,
            replay,
            epsilon,
            decisions_seen,
            config,
            rewards,
        }
    }

    /// Epsilon courant (pour l'affichage / debug).
    pub fn epsilon(&self) -> f32 {
        self.epsilon
    }

    /// Sélectionne une action selon la stratégie ε-greedy, guidée par la Q-table
    /// réellement apprise, avec le plan LLM comme « conseil expert » de repli
    /// (Expert Advice) pour les états encore inconnus.
    pub fn select_action(
        &mut self,
        state: &StateSignature,
        available: &[ActionType],
        llm_plan: Option<&AttackPlan>,
    ) -> ActionType {
        use rand::seq::SliceRandom;
        use rand::thread_rng;

        if available.is_empty() {
            return ActionType::Scan;
        }

        let mut rng = thread_rng();

        // Actions valides proposées par le plan LLM (conseil expert)
        let llm_actions: Vec<ActionType> = llm_plan
            .map(|p| {
                p.actions
                    .iter()
                    .map(|a| a.action_type.clone())
                    .filter(|at| available.contains(at))
                    .collect()
            })
            .unwrap_or_default();

        // ── Exploration ε-greedy ──────────────────────────────────────────
        if rand::random::<f32>() < self.epsilon {
            if let Some(a) = llm_actions.choose(&mut rng) {
                return a.clone();
            }
            return available
                .choose(&mut rng)
                .cloned()
                .unwrap_or(ActionType::Scan);
        }

        // ── Exploitation : argmax réel sur la Q-table apprise ─────────────
        let state_key = state.key();
        let known = available
            .iter()
            .any(|a| self.qtable.type_max_q(&state_key, a).is_some());

        if known {
            if let Some(best) = self.qtable.best_action(&state_key, available) {
                return best;
            }
        }

        // État encore inconnu (ou Q-table vide) : on suit le plan LLM,
        // sinon exploration uniforme de l'espace d'action (curiosité).
        if let Some(a) = llm_actions.choose(&mut rng) {
            return a.clone();
        }
        available
            .choose(&mut rng)
            .cloned()
            .unwrap_or(ActionType::Scan)
    }

    /// Sélection **fine** (granularité P4) : choisit un couple
    /// `(ActionType, technique)` parmi les candidats issus du plan LLM.
    ///
    /// L'intérêt par rapport à `select_action` : la technique retenue est
    /// conservée et propagée jusqu'à l'exécution, ce qui permet à la Q-table
    /// d'apprendre *quelle* technique réussit. L'exploration reste bornée aux
    /// candidats du plan → jamais d'exécution aveugle.
    pub fn select_action_with_technique(
        &mut self,
        state: &StateSignature,
        candidates: &[(ActionType, String)],
        available: &[ActionType],
        llm_plan: Option<&AttackPlan>,
    ) -> (ActionType, String) {
        use rand::seq::SliceRandom;
        use rand::thread_rng;

        // Aucun candidat exploitable : repli sur la sélection au niveau type.
        if candidates.is_empty() {
            return (
                self.select_action(state, available, llm_plan),
                String::new(),
            );
        }

        let mut rng = thread_rng();

        // ── Exploration ε-greedy parmi les candidats du plan ──────────────
        if rand::random::<f32>() < self.epsilon {
            if let Some(c) = candidates.choose(&mut rng) {
                return c.clone();
            }
        }

        // ── Exploitation : argmax sur les clés fines connues ─────────────
        let state_key = state.key();
        let known = self
            .qtable
            .values
            .get(&state_key)
            .map(|m| {
                candidates
                    .iter()
                    .any(|(at, tech)| m.contains_key(&action_key_tech(at, Some(tech))))
            })
            .unwrap_or(false);

        if known {
            if let Some(best) = self.qtable.best_plan_action(&state_key, candidates) {
                return best;
            }
        }

        // État inconnu : on suit le conseil expert (premier candidat du plan).
        candidates
            .first()
            .cloned()
            .unwrap_or((ActionType::Scan, String::new()))
    }

    /// Observe le résultat d'une action : calcule la récompense, stocke
    /// l'expérience et met à jour la Q-table (Q-learning + replay).
    ///
    /// `technique` est la famille de technique réellement exécutée (granularité
    /// P4) ; `None` pour un repli générique (ex. `recon_fallback`).
    pub fn observe(
        &mut self,
        prev_state: &StateSignature,
        action: ActionType,
        technique: Option<&str>,
        curr_state: &StateSignature,
        detection: bool,
        repeated_failure: bool,
    ) -> f32 {
        let reward = compute_reward(
            prev_state,
            curr_state,
            &action,
            &self.rewards,
            detection,
            repeated_failure,
        );

        let done = curr_state.objective_reached;
        let exp = Experience::new(prev_state, action.clone(), reward, curr_state, done)
            .with_technique(technique);
        self.replay.push(exp);

        // Mise à jour immédiate Q-learning sur cette transition
        self.q_learning_update(prev_state, &action, technique, reward, curr_state, done);

        // Replay priorisé sur un mini-batch
        self.replay_learn();

        // Décroissance d'ε au niveau **décision** : une transition apprise = une
        // marche vers l'exploitation de la politique.
        self.decay_epsilon();

        reward
    }

    /// Décroît ε d'un cran (par décision) et persiste l'état ε.
    pub fn decay_epsilon(&mut self) {
        self.decisions_seen = self.decisions_seen.saturating_add(1);
        self.epsilon = (self.epsilon * self.config.epsilon_decay).max(self.config.epsilon_min);
        let _ = self.persist_epsilon();
    }

    /// Écrit l'état ε (valeur + décisions vues) sur disque.
    fn persist_epsilon(&self) -> anyhow::Result<()> {
        save_epsilon_state(
            &self.config.epsilon_path,
            &EpsilonState {
                epsilon: self.epsilon,
                decisions_seen: self.decisions_seen,
            },
        )
    }

    /// Mise à jour Q-learning standard :
    /// Q(s,a) ← Q(s,a) + α [ r + γ · max_a' Q(s',a') − Q(s,a) ]
    fn q_learning_update(
        &mut self,
        state: &StateSignature,
        action: &ActionType,
        technique: Option<&str>,
        reward: f32,
        next_state: &StateSignature,
        done: bool,
    ) {
        let state_key = state.key();
        let next_key = next_state.key();

        let q_current = self.qtable.get_tech(&state_key, action, technique);

        let max_future = if done {
            0.0
        } else {
            // max_a' Q(s', a') sur toutes les actions connues pour s'
            // (NEG_INFINITY si l'état est vide → ramené à 0.0 pour éviter -inf)
            self.qtable
                .values
                .get(&next_key)
                .map(|m| m.values().cloned().fold(f32::NEG_INFINITY, f32::max))
                .filter(|v| v.is_finite())
                .unwrap_or(0.0)
        };

        let target = reward + self.config.discount * max_future;
        let td_error = target - q_current;
        let new_q = q_current + self.config.learning_rate * td_error;

        self.qtable.set_tech(&state_key, action, technique, new_q);
    }

    /// Apprend sur un mini-batch échantillonné par priorité, puis met à jour
    /// la priorité de chaque expérience (= |TD-error|) pour le prochain tirage.
    fn replay_learn(&mut self) {
        if self.replay.len() < self.config.batch_size {
            return;
        }

        // On échantillonne par INDICES pour pouvoir muter les priorités ensuite
        // (le tirage `sample()` retourne des références immuables).
        let indices = self.replay.sample_indices(self.config.batch_size);

        for idx in indices {
            let (state_key, next_key, action, technique, reward, done) = {
                let exp = &self.replay.experiences[idx];
                (
                    exp.state_key.clone(),
                    exp.next_state_key.clone(),
                    exp.action.clone(),
                    exp.technique.clone(),
                    exp.reward,
                    exp.done,
                )
            };

            let q_current = self
                .qtable
                .get_tech(&state_key, &action, technique.as_deref());
            let max_future = if done {
                0.0
            } else {
                self.qtable
                    .values
                    .get(&next_key)
                    .map(|m| m.values().cloned().fold(f32::NEG_INFINITY, f32::max))
                    .filter(|v| v.is_finite())
                    .unwrap_or(0.0)
            };

            let target = reward + self.config.discount * max_future;
            let td_error = target - q_current;
            let new_q = q_current + self.config.learning_rate * td_error;
            self.qtable
                .set_tech(&state_key, &action, technique.as_deref(), new_q);

            // Priorité = |TD-error| (+ constante pour éviter les zéros)
            if let Some(exp) = self.replay.experiences.get_mut(idx) {
                exp.priority = td_error.abs() + 1e-3;
            }
        }
    }

    /// Sauvegarde la Q-table, le buffer de replay **et** l'état ε sur disque,
    /// afin que l'expérience capitalisée et la décroissance d'ε d'une campagne
    /// servent la suivante.
    pub fn save(&self) -> anyhow::Result<()> {
        self.qtable.save(&self.config.qtable_path)?;
        self.replay.save(&self.config.replay_path)?;
        self.persist_epsilon()?;
        Ok(())
    }

    /// Clôture de campagne : incrémente le compteur de campagnes et persiste
    /// l'état. La décroissance d'ε n'est **plus** appliquée ici — elle l'est à
    /// chaque décision (`decay_epsilon`), sinon ε décroîtrait deux fois.
    pub fn end_campaign(&mut self) {
        self.config.campaigns_seen += 1;
        let _ = self.save();
    }

    /// Statistiques pour le terminal / le rapport.
    pub fn stats(&self) -> RLStats {
        RLStats {
            qtable_entries: self.qtable.size(),
            replay_size: self.replay.len(),
            epsilon: self.epsilon,
            campaigns_seen: self.config.campaigns_seen,
        }
    }

    /// Agrège la Q-valeur moyenne par action sur toute la Q-table.
    /// Retourne les `n` actions les mieux notées (`avg_q` décroissant).
    /// Sert à visualiser ce que l'agent a réellement appris.
    pub fn top_actions(&self, n: usize) -> Vec<(String, f64, usize)> {
        let mut sum: HashMap<String, f64> = HashMap::new();
        let mut count: HashMap<String, usize> = HashMap::new();
        for actions in self.qtable.values.values() {
            for (action, q) in actions {
                *sum.entry(action.clone()).or_insert(0.0) += *q as f64;
                *count.entry(action.clone()).or_insert(0) += 1;
            }
        }
        let mut scored: Vec<(String, f64, usize)> = sum
            .into_iter()
            .map(|(action, s)| {
                let c = count.get(&action).copied().unwrap_or(1).max(1);
                (action, s / c as f64, c)
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(n);
        scored
    }

    /// Répartition des états connus de la Q-table par phase de kill-chain.
    /// Extrait `phaseXxx` de la clé d'état (cf. `StateSignature::key`).
    pub fn phase_counts(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for state_key in self.qtable.values.keys() {
            if let Some(idx) = state_key.rfind("_phase") {
                let raw = &state_key[idx + "_phase".len()..];
                if !raw.is_empty() {
                    *counts.entry(raw.to_string()).or_insert(0) += 1;
                }
            }
        }
        let mut out: Vec<(String, usize)> = counts.into_iter().collect();
        out.sort_by(|a, b| b.1.cmp(&a.1));
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RLStats {
    pub qtable_entries: usize,
    pub replay_size: usize,
    pub epsilon: f32,
    pub campaigns_seen: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Pont avec l'agent autonome existant
// ─────────────────────────────────────────────────────────────────────────────

/// Curriculum : actions autorisées par phase de kill-chain.
///
/// Restreint l'espace d'action pour accélérer l'apprentissage : le RL ne peut
/// pas sélectionner une capacité hors-séquence (ex. exfiltration en phase de
/// reconnaissance), ce qui évite les actions absurdes et les détections inutiles.
pub fn phase_curriculum(phase: KillChainPhase) -> &'static [ActionType] {
    use ActionType::*;
    match phase {
        // WebAttack est autorisé dès la reconnaissance : pour une cible web,
        // cartographier la surface applicative (endpoints, formulaires, classes
        // de vulnérabilités) *est* de la reconnaissance. L'exclure en phase
        // Recon filtrait le plan du LLM et faisait dériver le RL hors-plan.
        KillChainPhase::Recon => &[Scan, Enumerate, Osint, WebAttack, AdversaryEmulation],
        KillChainPhase::Scanning => &[
            Scan,
            AdvancedScan,
            Enumerate,
            Osint,
            WebAttack,
            IotScada,
            KerberosAttack,
            AdAttack,
            AdversaryEmulation,
            StressTest,
            HordeAttack,
        ],
        KillChainPhase::Enumeration => &[
            Scan,
            AdvancedScan,
            Enumerate,
            Osint,
            WebAttack,
            IotScada,
            KerberosAttack,
            AdAttack,
            AdversaryEmulation,
        ],
        KillChainPhase::Exploitation => &[
            Scan,
            Enumerate,
            WebAttack,
            IotScada,
            KerberosAttack,
            AdAttack,
            Exploit,
            BruteForce,
            Evasion,
            C2,
            Integration,
            StressTest,
            HordeAttack,
        ],
        KillChainPhase::PostExploitation | KillChainPhase::LateralMovement => &[
            Scan,
            Enumerate,
            Exploit,
            BruteForce,
            PostExploit,
            Evasion,
            C2,
            CredentialReuse,
            Pivot,
            Exfiltrate,
            Integration,
            AdversaryEmulation,
            Cleanup,
        ],
        KillChainPhase::ObjectiveReached => &[Cleanup, Exfiltrate, Report, Complete, Pause],
    }
}

/// Actions disponibles selon l'état de la campagne.
/// Implémente la logique "tu ne peux pas exfiltrer sans shell".
pub fn available_actions(state: &StateSignature) -> Vec<ActionType> {
    let mut actions = vec![ActionType::Scan];

    // ── Reconnaissance ────────────────────────────────────────────────────
    if state.hosts_discovered > 0 {
        actions.push(ActionType::Enumerate);
        actions.push(ActionType::WebAttack);
        actions.push(ActionType::IotScada);
        actions.push(ActionType::KerberosAttack);
        actions.push(ActionType::AdAttack);
    }
    if state.hosts_scanned > 0 {
        actions.push(ActionType::AdvancedScan);
    }
    // OSINT externe : toujours disponible (reconnaissance passive, sans cible interne)
    actions.push(ActionType::Osint);

    // ── Accès initial ─────────────────────────────────────────────────────
    if state.hosts_vulnerable > 0 || state.hosts_scanned > 0 {
        actions.push(ActionType::Exploit);
        actions.push(ActionType::BruteForce);
    }

    // ── Post-compromission ────────────────────────────────────────────────
    if state.hosts_exploited > 0 || state.active_sessions > 0 {
        actions.push(ActionType::PostExploit);
        actions.push(ActionType::Evasion);
        actions.push(ActionType::C2);
    }
    if state.credentials > 0 {
        actions.push(ActionType::CredentialReuse);
    }
    if state.active_sessions > 0 {
        actions.push(ActionType::Pivot);
        actions.push(ActionType::Exfiltrate);
    }

    // ── Capacités transverses (planification / outils tiers) ──────────────
    if state.hosts_discovered > 0 {
        actions.push(ActionType::AdversaryEmulation);
        actions.push(ActionType::StressTest);
        actions.push(ActionType::HordeAttack);
    }
    if state.credentials > 0 || state.hosts_exploited > 0 {
        actions.push(ActionType::Integration);
    }

    if state.hosts_compromised > 0 {
        actions.push(ActionType::Cleanup);
    }

    // ── Curriculum par phase (P4) : on retire les capacités hors-séquence ─
    let curriculum = phase_curriculum(state.phase);
    actions.retain(|a| curriculum.contains(a));

    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_memory() -> CampaignMemory {
        CampaignMemory {
            session_id: "test".into(),
            campaign_name: "test".into(),
            objective: "test".into(),
            started_at: "now".into(),
            last_updated: "now".into(),
            completed: false,
            initial_targets: vec![],
            allowed_networks: vec![],
            hosts: HashMap::new(),
            credentials: vec![],
            sessions: HashMap::new(),
            failed_attempts: HashMap::new(),
            excluded_hosts: vec![],
            timeline: vec![],
            llm_context: vec![],
            stats: Default::default(),
            hypotheses: Default::default(),
            persistence_path: PathBuf::from("/tmp/test.json"),
        }
    }

    #[test]
    fn state_signature_stable_key() {
        let mem = dummy_memory();
        let s = StateSignature::from_memory(&mem);
        let k1 = s.key();
        let k2 = s.key();
        assert_eq!(k1, k2);
    }

    #[test]
    fn state_key_generalizes_over_magnitude_and_marks_completion() {
        let mut small = rich_state();
        small.hosts_discovered = 4;
        small.hosts_scanned = 4;

        // Magnitudes voisines (4..7 → même palier) : même clé → la politique
        // apprise se réutilise d'une cible à l'autre.
        let mut near = small.clone();
        near.hosts_discovered = 7;
        near.hosts_scanned = 6;
        assert_eq!(
            small.key(),
            near.key(),
            "magnitudes voisines doivent partager la même clé (généralisation)"
        );

        // Ordre de grandeur différent → clé différente.
        let mut far = small.clone();
        far.hosts_discovered = 40;
        far.hosts_scanned = 40;
        assert_ne!(small.key(), far.key());

        // L'objectif atteint ne doit plus être confondu avec un état en cours.
        let mut done = small.clone();
        done.objective_reached = true;
        assert_ne!(small.key(), done.key());
    }

    #[test]
    fn reward_for_shell() {
        let prev = StateSignature {
            hosts_discovered: 1,
            hosts_scanned: 1,
            hosts_vulnerable: 1,
            hosts_exploited: 0,
            hosts_compromised: 0,
            credentials: 0,
            active_sessions: 0,
            noise_bucket: NoiseBucket::Silent,
            phase: KillChainPhase::Exploitation,
            objective_reached: false,
            surface_novelty: 0,
        };
        let mut curr = prev.clone();
        curr.active_sessions = 1;
        curr.hosts_compromised = 1;

        let r = compute_reward(
            &prev,
            &curr,
            &ActionType::Exploit,
            &RewardConfig::default(),
            false,
            false,
        );
        // shell_acquired(100) + action_cost(-5) = 95
        assert!(r > 50.0, "reward should be high for shell, got {r}");
    }

    #[test]
    fn qtable_persist_roundtrip() {
        let mut q = QTable::new();
        q.set(
            "d1_s0_v0_e0_c0_cred0_sess0_noiseSilent_phaseRecon",
            &ActionType::Scan,
            42.0,
        );
        let path = std::env::temp_dir().join("nrtg_test_qtable.json");
        q.save(&path).unwrap();
        let loaded = QTable::load(&path);
        let v = loaded.get(
            "d1_s0_v0_e0_c0_cred0_sess0_noiseSilent_phaseRecon",
            &ActionType::Scan,
        );
        assert!((v - 42.0).abs() < 1e-6);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn replay_buffer_persist_roundtrip() {
        let path = std::env::temp_dir().join("nrtg_test_replay.json");
        let _ = std::fs::remove_file(&path);

        let state = rich_state();
        let mut rb = ReplayBuffer::new(16);
        rb.push(
            Experience::new(&state, ActionType::Scan, 7.5, &state, false)
                .with_technique(Some("CVE-2021-44228")),
        );
        rb.save(&path).unwrap();

        let loaded = ReplayBuffer::load(&path, 16);
        assert_eq!(loaded.len(), 1);
        let e = &loaded.experiences[0];
        assert_eq!(e.action, ActionType::Scan);
        assert_eq!(e.technique.as_deref(), Some("CVE-2021-44228"));
        assert!((e.reward - 7.5).abs() < 1e-6);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn replay_load_trims_to_capacity_keeping_high_priority() {
        let path = std::env::temp_dir().join("nrtg_test_replay_trim.json");
        let _ = std::fs::remove_file(&path);

        let state = rich_state();
        let mut rb = ReplayBuffer::new(8);
        for r in [1.0f32, 9.0, 3.0, 5.0] {
            let mut e = Experience::new(&state, ActionType::Scan, r, &state, false);
            e.priority = r; // dans cet exemple la priorité reflète le signal
            rb.push(e);
        }
        rb.save(&path).unwrap();

        // Capacité réduite : seules les deux plus hautes priorités survivent.
        let loaded = ReplayBuffer::load(&path, 2);
        assert_eq!(loaded.len(), 2);
        assert!(loaded.experiences.iter().all(|e| e.priority >= 5.0));
        let _ = std::fs::remove_file(&path);
    }

    fn rich_state() -> StateSignature {
        StateSignature {
            hosts_discovered: 6, // état "riche" : déclenchait l'ancien court-circuit heuristique
            hosts_scanned: 6,
            hosts_vulnerable: 0,
            hosts_exploited: 1,
            hosts_compromised: 0,
            credentials: 0,
            active_sessions: 0,
            noise_bucket: NoiseBucket::Low,
            phase: KillChainPhase::Exploitation,
            objective_reached: false,
            surface_novelty: 0,
        }
    }

    #[test]
    fn qtable_governs_action_selection_on_rich_state() {
        // Chemins temporaires : sans cela, le test hérite de l'état ε persisté
        // d'une campagne réelle (`sessions/rl_epsilon.json`) et explore au lieu
        // d'exploiter, ce qui rend l'assertion non déterministe.
        let cfg = RLAgentConfig {
            epsilon_start: 0.0,
            epsilon_min: 0.0,
            qtable_path: std::env::temp_dir().join("nrtg_test_qtable_sel.json"),
            replay_path: std::env::temp_dir().join("nrtg_test_replay_sel.json"),
            epsilon_path: std::env::temp_dir().join("nrtg_test_epsilon_sel.json"),
            ..Default::default()
        };
        let _ = std::fs::remove_file(&cfg.epsilon_path);
        let mut agent = KillChainRLAgent::new(cfg, RewardConfig::default());

        let state = rich_state();
        // La Q-table apprise doit primer sur toute heuristique codée en dur.
        agent.qtable.set(&state.key(), &ActionType::Exploit, 99.0);

        let available = vec![
            ActionType::Scan,
            ActionType::Enumerate,
            ActionType::Exploit,
            ActionType::Pivot,
        ];
        assert_eq!(
            agent.select_action(&state, &available, None),
            ActionType::Exploit
        );
    }

    #[test]
    fn replay_learn_updates_priorities() {
        let cfg = RLAgentConfig {
            batch_size: 1,
            qtable_path: std::env::temp_dir().join("nrtg_test_qtable_prio.json"),
            ..Default::default()
        };
        let mut agent = KillChainRLAgent::new(cfg, RewardConfig::default());

        let prev = StateSignature {
            hosts_discovered: 1,
            hosts_scanned: 1,
            hosts_vulnerable: 1,
            hosts_exploited: 0,
            hosts_compromised: 0,
            credentials: 0,
            active_sessions: 0,
            noise_bucket: NoiseBucket::Silent,
            phase: KillChainPhase::Enumeration,
            objective_reached: false,
            surface_novelty: 0,
        };
        let exp = Experience::new(&prev, ActionType::Scan, 50.0, &prev, false);
        let initial_priority = exp.priority; // = |r| = 50.0
        agent.replay.push(exp);

        // Étape interne du replay : avec une seule expérience, l'index 0 est tiré
        // de façon déterministe → la priorité doit être recalculée depuis |TD-error|.
        agent.replay_learn();

        let p = agent.replay.experiences[0].priority;
        assert!(p.is_finite() && p > 0.0);
        assert!(
            (p - initial_priority).abs() > 1e-9,
            "la priorité doit être recalculée depuis |TD-error| (initiale={initial_priority}, après={p})"
        );
    }

    #[test]
    fn phase_curriculum_excludes_out_of_sequence_actions() {
        // En phase de reconnaissance, ni exploitation ni exfiltration.
        let recon = StateSignature {
            hosts_discovered: 3,
            hosts_scanned: 0,
            hosts_vulnerable: 0,
            hosts_exploited: 0,
            hosts_compromised: 0,
            credentials: 0,
            active_sessions: 0,
            noise_bucket: NoiseBucket::Silent,
            phase: KillChainPhase::Recon,
            objective_reached: false,
            surface_novelty: 0,
        };
        let avail = available_actions(&recon);
        assert!(avail.contains(&ActionType::Scan));
        assert!(!avail.contains(&ActionType::Exploit));
        assert!(!avail.contains(&ActionType::Exfiltrate));
        assert!(!avail.contains(&ActionType::Cleanup));
    }

    #[test]
    fn phase_curriculum_allows_lateral_movement_after_compromise() {
        let post = StateSignature {
            hosts_discovered: 3,
            hosts_scanned: 3,
            hosts_vulnerable: 1,
            hosts_exploited: 1,
            hosts_compromised: 1,
            credentials: 1,
            active_sessions: 1,
            noise_bucket: NoiseBucket::Low,
            phase: KillChainPhase::PostExploitation,
            objective_reached: false,
            surface_novelty: 0,
        };
        let avail = available_actions(&post);
        assert!(avail.contains(&ActionType::Pivot));
        assert!(avail.contains(&ActionType::CredentialReuse));
        assert!(avail.contains(&ActionType::Exfiltrate));
    }

    #[test]
    fn canonical_technique_key_unifies_llm_wording() {
        assert_eq!(
            action_key_tech(&ActionType::Exploit, Some("Shellshock (CVE-2014-6271)")),
            action_key_tech(&ActionType::Exploit, Some("CVE-2014-6271 (Shellshock)"))
        );
    }

    #[test]
    fn rl_learns_best_technique_family_not_just_action_type() {
        // Chemins temporaires (idem ci-dessus) : isole le test de l'état ε
        // persisté d'une campagne réelle, sinon l'exploration rend le choix
        // aléatoire et l'assertion non déterministe.
        let cfg = RLAgentConfig {
            epsilon_start: 0.0,
            epsilon_min: 0.0,
            qtable_path: std::env::temp_dir().join("nrtg_test_qtable_tech.json"),
            replay_path: std::env::temp_dir().join("nrtg_test_replay_tech.json"),
            epsilon_path: std::env::temp_dir().join("nrtg_test_epsilon_tech.json"),
            ..Default::default()
        };
        let _ = std::fs::remove_file(&cfg.epsilon_path);
        let mut agent = KillChainRLAgent::new(cfg, RewardConfig::default());

        let state = rich_state();
        let log4shell = "CVE-2021-44228 (Log4Shell)".to_string();
        let candidates = vec![
            (ActionType::Exploit, log4shell.clone()),
            (
                ActionType::Exploit,
                "CVE-2017-0144 (EternalBlue)".to_string(),
            ),
        ];

        // La Q-table fine doit distinguer deux techniques du même ActionType.
        agent
            .qtable
            .set_tech(&state.key(), &ActionType::Exploit, Some(&log4shell), 88.0);

        let available = vec![ActionType::Exploit];
        let (at, tech) = agent.select_action_with_technique(&state, &candidates, &available, None);
        assert_eq!(at, ActionType::Exploit);
        assert_eq!(tech, log4shell);
    }

    #[test]
    fn sample_indices_returns_distinct_valid_indices() {
        let mut rb = ReplayBuffer::new(10);
        let s = StateSignature {
            hosts_discovered: 1,
            hosts_scanned: 0,
            hosts_vulnerable: 0,
            hosts_exploited: 0,
            hosts_compromised: 0,
            credentials: 0,
            active_sessions: 0,
            noise_bucket: NoiseBucket::Silent,
            phase: KillChainPhase::Recon,
            objective_reached: false,
            surface_novelty: 0,
        };
        for r in [1.0, 5.0, 9.0, 3.0, 7.0] {
            rb.push(Experience::new(&s, ActionType::Scan, r, &s, false));
        }
        let idx = rb.sample_indices(3);
        assert_eq!(idx.len(), 3);
        let mut uniq = idx.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(
            uniq.len(),
            3,
            "les indices échantillonnés doivent être distincts"
        );
        assert!(idx.iter().all(|&i| i < rb.len()));
    }

    // ── Décroissance d'ε par décision (et non par campagne) ──────────────

    fn eps_test_config(decay: f32, tag: &str) -> RLAgentConfig {
        let tmp = std::env::temp_dir();
        RLAgentConfig {
            epsilon_start: 1.0,
            epsilon_min: 0.01,
            epsilon_decay: decay,
            qtable_path: tmp.join(format!("nrtg_test_{tag}_qtable.json")),
            replay_path: tmp.join(format!("nrtg_test_{tag}_replay.json")),
            epsilon_path: tmp.join(format!("nrtg_test_{tag}_epsilon.json")),
            ..Default::default()
        }
    }

    fn cleanup_eps_files(tag: &str) {
        let tmp = std::env::temp_dir();
        for suffix in ["qtable", "replay", "epsilon"] {
            let _ = std::fs::remove_file(tmp.join(format!("nrtg_test_{tag}_{suffix}.json")));
        }
    }

    #[test]
    fn epsilon_decays_per_decision_not_per_campaign() {
        cleanup_eps_files("eps_per_dec");
        let mut agent =
            KillChainRLAgent::new(eps_test_config(0.5, "eps_per_dec"), RewardConfig::default());
        assert!((agent.epsilon() - 1.0).abs() < 1e-6);

        let s = rich_state();
        // Chaque décision observée fait décroître ε d'un cran.
        agent.observe(&s, ActionType::Scan, None, &s, false, false);
        assert!(
            (agent.epsilon() - 0.5).abs() < 1e-6,
            "ε doit décroître à chaque décision, obtenu {}",
            agent.epsilon()
        );
        agent.observe(&s, ActionType::Scan, None, &s, false, false);
        assert!((agent.epsilon() - 0.25).abs() < 1e-6);

        // Fin de campagne : aucune double décroissance.
        agent.end_campaign();
        assert!(
            (agent.epsilon() - 0.25).abs() < 1e-6,
            "end_campaign ne doit plus décroître ε, obtenu {}",
            agent.epsilon()
        );

        // Plancher ε_min respecté.
        for _ in 0..10 {
            agent.observe(&s, ActionType::Scan, None, &s, false, false);
        }
        assert!((agent.epsilon() - 0.01).abs() < 1e-6);

        cleanup_eps_files("eps_per_dec");
    }

    #[test]
    fn epsilon_state_persists_across_restart() {
        cleanup_eps_files("eps_persist");
        let cfg = eps_test_config(0.5, "eps_persist");
        let mut agent = KillChainRLAgent::new(cfg.clone(), RewardConfig::default());

        let s = rich_state();
        agent.observe(&s, ActionType::Scan, None, &s, false, false);
        agent.observe(&s, ActionType::Scan, None, &s, false, false);
        assert!((agent.epsilon() - 0.25).abs() < 1e-6);
        assert_eq!(agent.decisions_seen, 2);

        // Redémarrage : un nouvel agent doit reprendre ε là où il a été laissé,
        // sinon la décroissance serait perdue à chaque lancement.
        let reloaded = KillChainRLAgent::new(cfg, RewardConfig::default());
        assert!(
            (reloaded.epsilon() - 0.25).abs() < 1e-6,
            "ε doit survivre au redémarrage, obtenu {}",
            reloaded.epsilon()
        );
        assert_eq!(reloaded.decisions_seen, 2);

        cleanup_eps_files("eps_persist");
    }
}
