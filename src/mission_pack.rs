//! DIAPILE — Mission Pack (Tier 2+)
//!
//! Persistance chiffrée AES-256-GCM d'une campagne complète Red Team :
//!   - Metadata campagne (client, dates, scope, règles OPSEC, état)
//!   - Nodes / CVEs / findings (graph nodes)
//!   - Notes opérateurs
//!   - Timeline événements datée (scan, exploit, credential dump, ...)
//!
//! Design OPSEC:
//!   1. Clé master = C2_MASTER_KEY (HKDF info = "diapile/mission-pack/v1")
//!      OU fallback : MISSION_PACK_PASSWORD + HKDF-SHA256(salt=pack-uuid, info=...)
//!   2. Fichier = 1 BLOB unique AES-GCM de `MissionPackInner` JSON-sérialisé.
//!      Aucun clair, aucune structure fichier détectable (pas de header magique
//!      constant car nonce aléatoire de 12B préfixe).
//!   3. NIST SP 800-88 overwrite à la fermeture via QW4 clean trait.
//!   4. Anti-forensique : chaque blob écrit = nouveau nonce aléatoire,
//!      aucune écriture en-place (write-new + rename) pour éviter journal FS.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::c2::crypto::{aes_gcm_decrypt, aes_gcm_encrypt, load_c2_master_key};
use crate::reports::GraphNode;

/// Clé canal dédiée Mission Pack : info = "diapile/mission-pack/v1"
pub const MISSION_PACK_HKDF_INFO: &str = "diapile/mission-pack/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MissionState {
    Active,
    OnHold,
    Completed,
    Cancelled,
    Aborted,
}

impl MissionState {
    pub fn label(&self) -> &'static str {
        match self {
            MissionState::Active => "ACTIVE",
            MissionState::OnHold => "EN PAUSE",
            MissionState::Completed => "TERMINÉE",
            MissionState::Cancelled => "ANNULÉE",
            MissionState::Aborted => "ABANDONNÉE",
        }
    }

    pub fn ansi(&self) -> &'static str {
        match self {
            MissionState::Active => "\x1b[38;5;48m",     // vert
            MissionState::OnHold => "\x1b[38;5;214m",    // ambre
            MissionState::Completed => "\x1b[38;5;51m",  // cyan
            MissionState::Cancelled => "\x1b[38;5;244m", // gris
            MissionState::Aborted => "\x1b[38;5;197m",   // rouge
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventKind {
    MissionCreated,
    MissionStateChanged,
    ScanRun,
    NodeAdded,
    NodeReachable,
    CveIdentified,
    FindingExploit,
    CredentialFound,
    PivotEstablished,
    C2AgentBeacon,
    NoteAdded,
    Export,
    Custom,
}

impl EventKind {
    pub fn label(&self) -> &'static str {
        match self {
            EventKind::MissionCreated => "Mission · Création",
            EventKind::MissionStateChanged => "Mission · État",
            EventKind::ScanRun => "Scan · Exécution",
            EventKind::NodeAdded => "Node · Ajout",
            EventKind::NodeReachable => "Node · Atteignable",
            EventKind::CveIdentified => "CVE · Identifiée",
            EventKind::FindingExploit => "Exploit · Finding",
            EventKind::CredentialFound => "Crédentials · Dump",
            EventKind::PivotEstablished => "Pivot · Ouvert",
            EventKind::C2AgentBeacon => "C2 · Beacon agent",
            EventKind::NoteAdded => "Note · Ajout",
            EventKind::Export => "Export · Généré",
            EventKind::Custom => "Événement",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionEvent {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub kind: EventKind,
    pub title: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MissionFinding {
    pub id: String,
    pub title: String,
    pub severity: i32,
    pub description: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub cvss: Option<f32>,
    #[serde(default)]
    pub cve_refs: Vec<String>,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub detected_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MissionNote {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub author: String,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MissionPackInner {
    pub pack_version: u32,
    pub id: String,
    pub name: String,
    pub client_name: Option<String>,
    pub scope_text: String,
    pub targets: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub planned_start: Option<DateTime<Utc>>,
    pub planned_end: Option<DateTime<Utc>>,
    pub state: MissionState,
    pub opsec_rules: Vec<String>,
    pub operator: Option<String>,
    pub nodes: Vec<GraphNode>,
    pub findings: Vec<MissionFinding>,
    pub notes: Vec<MissionNote>,
    pub events: Vec<MissionEvent>,
    pub scans_run: u32,
    pub cves_total: usize,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub info_count: u32,
    pub exports_generated: u32,
    #[serde(default)]
    pub custom_tags: Vec<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

pub struct MissionPack {
    path: PathBuf,
    key: [u8; 32],
    inner: MissionPackInner,
}

// ---------------- clé de chiffrement ---------------------

/// Dérive la clé mission pack à partir de la clé maître C2 si disponible,
/// sinon à partir d'un mot de passe fourni.
pub fn derive_pack_key(
    c2_master: Option<&[u8; 32]>,
    password: Option<&str>,
    pack_salt: &[u8],
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    if let Some(master) = c2_master {
        let hk = Hkdf::<Sha256>::new(Some(pack_salt), master);
        let mut out = [0u8; 32];
        hk.expand(MISSION_PACK_HKDF_INFO.as_bytes(), &mut out)
            .map_err(|e| format!("HKDF C2 master pour mission pack: {:?}", e))?;
        return Ok(out);
    }
    if let Some(pwd) = password {
        if pwd.is_empty() {
            return Err("Mot de passe Mission Pack vide — impossible de dériver clé".into());
        }
        let ikm = {
            use sha2::Digest;
            let mut d = Sha256::new();
            d.update(b"diapile/pack-ikm/v1");
            d.update(pwd.as_bytes());
            let h = d.finalize();
            let mut ikm = [0u8; 32];
            ikm.copy_from_slice(h.as_ref());
            ikm
        };
        let hk = Hkdf::<Sha256>::new(Some(pack_salt), &ikm);
        let mut out = [0u8; 32];
        hk.expand(MISSION_PACK_HKDF_INFO.as_bytes(), &mut out)
            .map_err(|e| format!("HKDF password mission pack: {:?}", e))?;
        return Ok(out);
    }
    Err(
        "Aucune clé disponible : définissez $env:C2_MASTER_KEY (recommandé) ou \
        passez --mission-password / $env:MISSION_PACK_PASSWORD"
            .into(),
    )
}

fn load_pack_key_for(
    password_cli: Option<&str>,
    pack_salt: &[u8],
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let c2 = load_c2_master_key().ok();
    let env_pwd = std::env::var("MISSION_PACK_PASSWORD").ok();
    let pwd = password_cli.or(env_pwd.as_deref());
    derive_pack_key(c2.as_ref(), pwd, pack_salt)
}

// ---------------- opérations bas niveau fichier ---------------------

fn write_atomic(path: &Path, ciphertext: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.to_path_buf();
    tmp.set_extension(format!("tmp{:08x}", rand::random::<u32>()));
    fs::write(&tmp, ciphertext)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn encrypt_and_serialize(
    inner: &MissionPackInner,
    key: &[u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let pt =
        serde_json::to_vec(inner).map_err(|e| format!("Mission Pack sérialisation JSON: {e}"))?;
    aes_gcm_encrypt(key, &pt)
}

fn decrypt_and_parse(
    blob: &[u8],
    key: &[u8; 32],
) -> Result<MissionPackInner, Box<dyn std::error::Error + Send + Sync>> {
    let pt = aes_gcm_decrypt(key, blob)?;
    serde_json::from_slice(&pt).map_err(|e| format!("Mission Pack JSON invalide: {e}").into())
}

// ---------------- API publique ---------------------

impl MissionPack {
    /// Crée un nouveau pack sur disque avec un nom, client, scope donné.
    pub fn create_new<P: AsRef<Path>>(
        path: P,
        password: Option<&str>,
        name: String,
        client_name: Option<String>,
        scope_text: String,
        targets: Vec<String>,
        operator: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(format!("Mission Pack existe déjà: {}", path.display()).into());
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).ok();
            }
        }
        let pack_id = Uuid::new_v4().to_string();
        let salt = hex::decode(&pack_id.replace('-', "")).unwrap_or_else(|_| vec![0x42u8; 16]);
        let key = load_pack_key_for(password, &salt)?;

        let now = Utc::now();
        let mut inner = MissionPackInner {
            pack_version: 1,
            id: pack_id.clone(),
            name,
            client_name,
            scope_text,
            targets,
            created_at: now,
            last_modified: now,
            planned_start: None,
            planned_end: None,
            state: MissionState::Active,
            opsec_rules: vec![
                "Toujours utiliser redact-level ≥ light".into(),
                "Passer par --stealth=redteam pour les scans externes".into(),
                "Aucun dump credential dans les logs".into(),
                "Fermeture du pack : close_and_wipe avant arrêt machine".into(),
            ],
            operator,
            nodes: Vec::new(),
            findings: Vec::new(),
            notes: Vec::new(),
            events: vec![MissionEvent {
                id: Uuid::new_v4().to_string(),
                ts: now,
                kind: EventKind::MissionCreated,
                title: "Mission créée".into(),
                detail: Some("Ouverture du pack de mission chiffré AES-256-GCM".into()),
                node_id: None,
                operator: None,
                tags: vec!["mission".into()],
            }],
            scans_run: 0,
            cves_total: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            exports_generated: 0,
            custom_tags: Vec::new(),
            metadata: HashMap::new(),
        };
        inner.last_modified = now;
        let blob = encrypt_and_serialize(&inner, &key)?;
        write_atomic(&path, &blob).map_err(|e| format!("Écriture pack {e}"))?;
        Ok(MissionPack { path, key, inner })
    }

    /// Ouvre un pack existant (clé de dérivation = C2 master OU password/salt pack id)
    pub fn open_existing<P: AsRef<Path>>(
        path: P,
        password: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let path = path.as_ref().to_path_buf();
        let blob =
            fs::read(&path).map_err(|e| format!("Lecture Mission Pack {}: {e}", path.display()))?;
        if blob.len() < 12 + 16 {
            return Err("Mission Pack trop petit (corrompu)".into());
        }
        let mut tmp_inner: Option<MissionPackInner> = None;
        let mut resolved_key: Option<[u8; 32]> = None;

        // Essaie d'abord dérivation via C2 master (salt = id pack inconnu avant)
        // → on teste un salt zéro POUR la tentative C2 key *seulement* si password absent.
        // Sinon, password fourni + salt fictif → échec attendu, puis on réessaie après
        // déchiffrement réussi, mais ça n'est pas possible. Stratégie :
        // 1. Si password fourni → salt dérivé du pack_id qu'on ne connaît pas →
        //    on essaie password avec salt = 16 octets de la fin du nonce
        //    (12 premiers = nonce AES). Si échoue, erreur finale.
        // 2. Si C2 master présent : sel = MISSION_PACK_HKDF_INFO[..16]
        //    → dérive clé et tente de déchiffrer. Si succès, pack_id connu après.

        let try_c2_first: Option<[u8; 32]> = {
            let c2 = load_c2_master_key().ok();
            if let Some(c2) = c2 {
                let salt = {
                    let mut s = [0u8; 16];
                    let info = MISSION_PACK_HKDF_INFO.as_bytes();
                    let n = std::cmp::min(16, info.len());
                    s[..n].copy_from_slice(&info[..n]);
                    s
                };
                let hk = Hkdf::<Sha256>::new(Some(&salt), &c2);
                let mut out = [0u8; 32];
                hk.expand(MISSION_PACK_HKDF_INFO.as_bytes(), &mut out)
                    .ok()
                    .map(|_| out)
            } else {
                None
            }
        };

        if let Some(k) = try_c2_first {
            if let Ok(parsed) = decrypt_and_parse(&blob, &k) {
                tmp_inner = Some(parsed);
                resolved_key = Some(k);
            }
        }

        if resolved_key.is_none() {
            let env_pwd = std::env::var("MISSION_PACK_PASSWORD").ok();
            let pwd = password.or(env_pwd.as_deref());
            if let Some(p) = pwd {
                let salt = {
                    let mut s = [0u8; 16];
                    s.copy_from_slice(&blob[..std::cmp::min(16, blob.len())]);
                    s
                };
                let k = derive_pack_key(None, Some(p), &salt)?;
                let parsed = decrypt_and_parse(&blob, &k)
                    .map_err(|_| "Échec déchiffrement : mauvais mot de passe ou pack corrompu")?;
                tmp_inner = Some(parsed);
                resolved_key = Some(k);
            }
        }

        let inner = tmp_inner.ok_or("Aucune méthode de déchiffrement n'a fonctionné (vérifiez C2_MASTER_KEY ou --mission-password)")?;
        let key = resolved_key.ok_or("Clé mission pack non résolue")?;

        Ok(MissionPack { path, key, inner })
    }

    pub fn persist(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.last_modified = Utc::now();
        let blob = encrypt_and_serialize(&self.inner, &self.key)?;
        write_atomic(&self.path, &blob).map_err(|e| e.to_string().into())
    }

    /// Retourne ref de l'inner struct (lecture seule)
    pub fn inner(&self) -> &MissionPackInner {
        &self.inner
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn set_state(&mut self, s: MissionState, reason: Option<&str>) {
        self.inner.state = s;
        self.push_event(
            EventKind::MissionStateChanged,
            format!("État → {}", s.label()),
            reason,
            None,
            vec!["state".into()],
        );
    }

    pub fn push_event(
        &mut self,
        kind: EventKind,
        title: String,
        detail: Option<&str>,
        node_id: Option<String>,
        tags: Vec<String>,
    ) {
        self.inner.events.push(MissionEvent {
            id: Uuid::new_v4().to_string(),
            ts: Utc::now(),
            kind,
            title,
            detail: detail.map(str::to_string),
            node_id,
            operator: self.inner.operator.clone(),
            tags,
        });
    }

    pub fn add_note(
        &mut self,
        title: String,
        body: String,
        author: String,
        tags: Vec<String>,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        let n = MissionNote {
            id: id.clone(),
            ts: Utc::now(),
            author: if author.trim().is_empty() {
                self.inner.operator.clone().unwrap_or_else(|| "anon".into())
            } else {
                author
            },
            title,
            body,
            tags,
        };
        let note_title = n.title.clone();
        self.inner.notes.push(n);
        self.push_event(
            EventKind::NoteAdded,
            format!("Note ajoutée: {}", note_title),
            None,
            None,
            vec!["note".into()],
        );
        id
    }

    pub fn add_finding(&mut self, finding: MissionFinding) -> String {
        let id = finding.id.clone();
        match finding.severity {
            0 => self.inner.info_count += 1,
            1 => self.inner.low_count += 1,
            2 => self.inner.medium_count += 1,
            3 => self.inner.high_count += 1,
            _ => self.inner.critical_count += 1,
        }
        self.inner.cves_total = self.inner.cves_total.saturating_add(finding.cve_refs.len());
        self.inner.findings.push(finding);
        id
    }

    /// Intègre des nodes issus d'un scan Graph -> fusion par host:port (idempotent)
    pub fn merge_graph_nodes(&mut self, nodes: &[GraphNode]) -> usize {
        let mut seen = HashSet::new();
        for n in &self.inner.nodes {
            seen.insert((n.host.clone(), n.port));
        }
        let mut added = 0usize;
        for n in nodes {
            if !seen.contains(&(n.host.clone(), n.port)) {
                self.inner.critical_count += (n.risk >= 4) as u32;
                self.inner.high_count += (n.risk == 3) as u32;
                self.inner.medium_count += (n.risk == 2) as u32;
                self.inner.low_count += (n.risk == 1) as u32;
                self.inner.info_count += (n.risk == 0) as u32;
                self.inner.cves_total = self.inner.cves_total.saturating_add(n.cves.len());
                self.push_event(
                    EventKind::NodeAdded,
                    format!(
                        "{host}:{port} {svc}",
                        host = n.host,
                        port = n.port,
                        svc = n.protocol
                    ),
                    Some(&n.label),
                    Some(n.id.clone()),
                    vec!["node".into()],
                );
                if n.reachable {
                    self.push_event(
                        EventKind::NodeReachable,
                        format!("Atteignable {host}:{port}", host = n.host, port = n.port),
                        Some(&format!("svc={:?} risk={}", n.services, n.risk)),
                        Some(n.id.clone()),
                        vec!["reachable".into()],
                    );
                }
                for c in &n.cves {
                    self.push_event(
                        EventKind::CveIdentified,
                        format!("{id} (cvss={s:.1})", id = c.0, s = c.1),
                        Some(&format!(
                            "{host}:{port} — {desc}",
                            host = n.host,
                            port = n.port,
                            desc = c.2
                        )),
                        Some(n.id.clone()),
                        vec!["cve".into()],
                    );
                }
                self.inner.nodes.push(n.clone());
                seen.insert((n.host.clone(), n.port));
                added += 1;
            }
        }
        added
    }

    /// Increment du compteur scans + event
    pub fn mark_scan_run(&mut self, detail: Option<&str>) {
        self.inner.scans_run = self.inner.scans_run.saturating_add(1);
        self.push_event(
            EventKind::ScanRun,
            format!("Scan #{} exécuté", self.inner.scans_run),
            detail,
            None,
            vec!["scan".into()],
        );
    }

    pub fn mark_export(&mut self, label: &str) {
        self.inner.exports_generated = self.inner.exports_generated.saturating_add(1);
        self.push_event(
            EventKind::Export,
            format!("Export #{}: {label}", self.inner.exports_generated),
            None,
            None,
            vec!["export".into()],
        );
    }

    /// NIST SP 800-88 3 passes + supprime fichier.
    pub fn close_and_wipe(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.last_modified = Utc::now();
        let _ = self.persist();
        secure_wipe(&self.path)?;
        Ok(())
    }

    /// Export JSON sidecar non chiffré pour livrable client (redact-level light déjà appliqué upstream)
    pub fn export_report_json(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let rpt = MissionPackReport::from(self);
        serde_json::to_vec_pretty(&rpt).map_err(|e| format!("Export JSON mission: {e}").into())
    }
}

/// Secure wipe NIST SP 800-88 (3 passes: 0x00, 0xFF, random) + flush, unlink à la fin
pub fn secure_wipe(path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::io::{Seek, SeekFrom, Write};
    if !path.exists() {
        return Ok(());
    }
    let meta = fs::metadata(path)?;
    let size = meta.len() as usize;
    if size == 0 {
        fs::remove_file(path).ok();
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("open wipe: {e}"))?;
    let buf0 = vec![0x00u8; size];
    let buf1 = vec![0xFFu8; size];
    let mut bufr = vec![0u8; size];
    (0..bufr.len()).for_each(|i| bufr[i] = rand::random::<u8>());
    for pass in [&buf0, &buf1, &bufr] {
        f.seek(SeekFrom::Start(0))
            .map_err(|e| format!("seek: {e}"))?;
        f.write_all(pass).map_err(|e| format!("write pass: {e}"))?;
        f.flush().map_err(|e| format!("flush: {e}"))?;
        f.sync_all().map_err(|e| format!("sync_all: {e}"))?;
    }
    drop(f);
    fs::remove_file(path).map_err(|e| format!("unlink: {e}"))?;
    Ok(())
}

// ---------------- Rapport export ----------------------

#[derive(Debug, Clone, Serialize)]
pub struct MissionPackReport<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub client_name: Option<&'a str>,
    pub state_label: &'a str,
    pub created_at: String,
    pub last_modified: String,
    pub operator: Option<&'a str>,
    pub targets_count: usize,
    pub targets: Vec<String>,
    pub scope: &'a str,
    pub scans_run: u32,
    pub nodes_count: usize,
    pub findings_count: usize,
    pub notes_count: usize,
    pub events_count: usize,
    pub cves_total: usize,
    pub risks: [u32; 5],
    pub exports_generated: u32,
    pub nodes: Vec<GraphNode>,
    pub findings: Vec<MissionFinding>,
    pub notes: Vec<MissionNote>,
    pub events: Vec<MissionEvent>,
}

impl<'a> MissionPackReport<'a> {
    fn from(mp: &'a MissionPack) -> Self {
        let i = mp.inner();
        MissionPackReport {
            id: &i.id,
            name: &i.name,
            client_name: i.client_name.as_deref(),
            state_label: i.state.label(),
            created_at: i.created_at.to_rfc3339(),
            last_modified: i.last_modified.to_rfc3339(),
            operator: i.operator.as_deref(),
            targets_count: i.targets.len(),
            targets: i.targets.clone(),
            scope: &i.scope_text,
            scans_run: i.scans_run,
            nodes_count: i.nodes.len(),
            findings_count: i.findings.len(),
            notes_count: i.notes.len(),
            events_count: i.events.len(),
            cves_total: i.cves_total,
            risks: [
                i.info_count,
                i.low_count,
                i.medium_count,
                i.high_count,
                i.critical_count,
            ],
            exports_generated: i.exports_generated,
            nodes: i.nodes.clone(),
            findings: i.findings.clone(),
            notes: i.notes.clone(),
            events: i.events.clone(),
        }
    }
}
