//! DIAPILE — Live Dashboard WebSocket (127.0.0.1:24601 SEULEMENT)
//!
//! 🚨 OPSEC CRITIQUE : Ce serveur ne s'autobind JAMAIS sur 0.0.0.0.
//! TOUTES les connexions autre que loopback sont instantanément rejetées
//! (on vérifie l'IP source sur TcpStream::peer_addr() avant même upgrade HTTP).
//!
//! Zero dépendances externes : implémentation main à base de `tokio::net::TcpListener`
//! + `sha1` + `base64` (déjà présents) pour le handshake Sec-WebSocket-Accept.
//! Ecritures en frames WebSocket TEXT non-masquées (server→client).
//!
//! Usage :
//! ```rust,ignore
//!     let hub = LiveHub::bind(127.0.0.1:24601).await?;
//!     let emitter = hub.emitter();
//!     tokio::spawn(async move { hub.serve().await });
//!     // ensuite dans le scan :
//!     emitter.send_node(&graph_node).await;
//!     emitter.send_progress(total, done, start).await;
//! ```

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex};

use crate::reports::GraphNode;

// -----------------------------------------------------------------------
// Espace publicitaire 1s : évènements sérialisés en JSON
// -----------------------------------------------------------------------
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum DashboardEvent {
    /// Status initial, envoyé en premier à toute nouvelle connexion
    Hello {
        port: u16,
        started_at: u64,
        nrtg_version: &'static str,
    },
    /// Nouveau noeud scanné (reach. ou non — l'appli décide de l'afficher)
    NodeScanned { node: GraphNode },
    /// Barre de progression globale (appelé ~1x/100ms tant que non fini)
    Progress {
        total: usize,
        done: usize,
        eta_seconds: f32,
        reachable: usize,
        total_cves: usize,
    },
    /// Fin du scan — garde-fou côté navigateur (stop anims)
    Finished {
        total_nodes: usize,
        reachable: usize,
        elapsed_ms: u128,
    },
    /// Signal pulse — Risk=5 a été détecté (popup côté D3)
    HighRiskAlert {
        id: String,
        host: String,
        port: u16,
        risk: u8,
        top_cve: String,
    },
    /// Tick DDoS/GoldenEye — compteurs bots + erreurs + adaptation (~500 ms)
    DdosTick {
        /// UTC Unix millis
        t: u64,
        target: String,
        method: String,
        bots_spawned: u64,
        bots_concurrent: u64,
        rps: f64,
        rps_peak: f64,
        ok_pct: f64,
        hits: u64,
        fails: u64,
        code_2xx: u64,
        code_3xx: u64,
        code_4xx: u64,
        code_5xx: u64,
        waf_blocks: u64,
        r5xx: f64,
        rwaf: f64,
        bots_rotated: u64,
        adapt_factor: f64,
        adapt_state: String,
        bytes_sent_mb: f64,
        bytes_recv_mb: f64,
        /// Worker heatmap slice (mode HORDE) — vide si mode standalone
        workers: Vec<DdosWorkerRow>,
    },
    /// Graphe OSINT : snapshot complet (tous nœuds + liens) envoyé en début/fin
    OsintGraphSnapshot(OsintGraphSnapshot),
    /// Graphe OSINT : ajout incrémental (nœuds + liens) au fil de la recon
    OsintGraphDelta(OsintGraphDelta),
    /// Ping keep-alive (navigateur ferme la WS si 30s de silence)
    Ping { t: u64 },
    /// Log de l'agent IA ou du système
    Log {
        t: u64,
        level: String,
        source: String,
        message: String,
    },
    /// Décision de l'agent IA (action retenue) couplée au résultat RL.
    AgentDecision {
        t: u64,
        /// Origine : "rl" (exploitation Q-table) ou "llm" (plan expert)
        origin: String,
        action: String,
        target: String,
        technique: String,
        /// Phase de kill-chain (Recon, Exploitation, PostExploitation, ...)
        phase: String,
        /// Récompense RL de la transition (peut être négative)
        reward: f64,
        /// ε courant au moment de la décision
        epsilon: f64,
        /// Q-valeur apprise pour (état, action)
        q_value: f64,
        /// Résultat textuel de l'action (tronqué)
        outcome: String,
    },
    /// Agrégats d'apprentissage RL (envoyé périodiquement, ~1x/itération)
    RlStats {
        t: u64,
        epsilon: f64,
        qtable_entries: usize,
        replay_size: usize,
        campaigns_seen: u32,
        /// Top actions apprises (moyenne Q décroissante)
        top_actions: Vec<RlActionScore>,
        /// Répartition des états connus par phase de kill-chain
        phases: Vec<RlPhaseCount>,
    },
}

/// Score moyen d'une action dans la Q-table (vue agrégée dashboard).
#[derive(Debug, Clone, Serialize)]
pub struct RlActionScore {
    pub action: String,
    pub avg_q: f64,
    pub count: usize,
}

/// Nombre d'états connus par phase de kill-chain.
#[derive(Debug, Clone, Serialize)]
pub struct RlPhaseCount {
    pub phase: String,
    pub count: usize,
}

/// Une ligne de heatmap worker DDoS (HORDE coordinator)
#[derive(Debug, Clone, Serialize)]
pub struct DdosWorkerRow {
    pub id_short: String,
    pub peer_ip: String,
    pub connected: bool,
    pub range: (u64, u64),
    pub hits: u64,
    pub code_5xx: u64,
    pub waf_blocks: u64,
    pub efficiency: f64,
    pub grade: String,
}

// -----------------------------------------------------------------------
// OSINT Graph : structures typées pour le graphe de liens temps réel
// -----------------------------------------------------------------------
/// Catégorie d'un nœud OSINT — détermine couleur, taille, icône côté D3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OsintNodeKind {
    /// Domaine racine (cible) — nœud central le plus gros
    RootDomain,
    /// Sous-domaine (valide, issu CT / brute / résolution)
    Subdomain,
    /// Adresse IPv4 / IPv6
    IpAddr,
    /// Adresse email extraite de records SOA / MX / TXT / leaks
    Email,
    /// Record DNS (MX=10 mx.dom, TXT="v=spf1...", NS=ns1.dom, SOA, AAAA, CAA)
    DnsRecord,
    /// Technologie détectée (nginx, PHP, WordPress, Apache...)
    Technology,
    /// Port ouvert (issu Shodan)
    OpenPort,
    /// Fuite / leak GitHub (repos, snippets référencant le domaine)
    Leak,
    /// Breach HIBP
    Breach,
    /// URL historique (Wayback / archive)
    HistoricalUrl,
}

/// Un nœud du graphe OSINT
#[derive(Debug, Clone, Serialize)]
pub struct OsintGraphNode {
    /// Identifiant stable global (ex: `sub:www.example.org`, `ip:10.0.0.1`, `email:a@b.c`)
    pub id: String,
    /// Libellé affiché
    pub label: String,
    /// Catégorie (couleur + taille)
    pub kind: OsintNodeKind,
    /// Poids (influence la taille du cercle D3), typiquement 1.0
    pub weight: f32,
    /// Champ libre enrichi (optionnel)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Timestamp de découverte (pour animation temps réel)
    pub t: u64,
}

/// Type de lien entre deux nœuds OSINT
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OsintEdgeKind {
    /// `RootDomain` → `Subdomain` (hiérarchie DNS)
    HasSubdomain,
    /// `Subdomain` ↔ `IpAddr` (résolution A/AAAA)
    ResolvesTo,
    /// `RootDomain` / `Subdomain` → `DnsRecord` (MX, NS, SOA, TXT, CAA)
    HasDnsRecord,
    /// `DnsRecord` (type MX) → `IpAddr` du serveur mail si résolu
    MailServerIp,
    /// `DnsRecord` (type TXT/SOA) → `Email` contenu
    ContainsEmail,
    /// `IpAddr` → `OpenPort` (Shodan)
    HasOpenPort,
    /// `IpAddr` / `Subdomain` → `Technology`
    RunsTechnology,
    /// `Subdomain` / `RootDomain` → `Leak` (GitHub leak)
    ReferencedInLeak,
    /// `Email` → `Breach` (HIBP)
    SeenInBreach,
    /// `Subdomain` → `HistoricalUrl` (Wayback)
    HasHistoricalEntry,
}

/// Un lien (edge) du graphe OSINT
#[derive(Debug, Clone, Serialize)]
pub struct OsintGraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub kind: OsintEdgeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Évènement graphe OSINT — snapshot complet (premier message).
#[derive(Debug, Clone, Serialize)]
pub struct OsintGraphSnapshot {
    pub target: String,
    pub generated_at: u64,
    pub nodes: Vec<OsintGraphNode>,
    pub edges: Vec<OsintGraphEdge>,
    pub stats: OsintGraphStats,
}

/// Évènement graphe OSINT — ajout incrémental.
#[derive(Debug, Clone, Serialize)]
pub struct OsintGraphDelta {
    pub target: String,
    pub at: u64,
    #[serde(default)]
    pub add_nodes: Vec<OsintGraphNode>,
    #[serde(default)]
    pub add_edges: Vec<OsintGraphEdge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats_update: Option<OsintGraphStats>,
}

/// Compteurs affichés dans la légende côté client.
#[derive(Debug, Clone, Default, Serialize)]
pub struct OsintGraphStats {
    pub total_subdomains: usize,
    pub active_subdomains: usize,
    pub total_ips: usize,
    pub total_emails: usize,
    pub total_records: usize,
    pub total_techs: usize,
    pub total_ports: usize,
    pub total_leaks: usize,
    pub total_breaches: usize,
    pub total_historical: usize,
}

// -----------------------------------------------------------------------
// Snapshot d'état — rejoué à chaque nouvelle connexion WebSocket
// -----------------------------------------------------------------------
/// Le navigateur met 1 à 3 s à démarrer puis à ouvrir sa WS : tous les
/// évènements publiés avant son abonnement étaient perdus (`broadcast::subscribe`
/// ne délivre que les messages postérieurs à l'abonnement). On conserve donc ici
/// le dernier état utile et on le rejoue dès la connexion du client.
#[derive(Default)]
struct SnapshotState {
    /// Nœuds scannés, dédupliqués par id (le dernier état gagne)
    nodes: Vec<GraphNode>,
    node_index: HashMap<String, usize>,
    /// Derniers évènements « singleton » déjà sérialisés en JSON
    last_progress: Option<String>,
    last_ddos_tick: Option<String>,
    last_rl_stats: Option<String>,
}

impl SnapshotState {
    /// Mémorise les évènements porteurs d'état (les autres sont transitoires).
    fn record(&mut self, ev: &DashboardEvent) {
        match ev {
            DashboardEvent::NodeScanned { node } => {
                if let Some(&i) = self.node_index.get(&node.id) {
                    self.nodes[i] = node.clone();
                } else {
                    self.node_index.insert(node.id.clone(), self.nodes.len());
                    self.nodes.push(node.clone());
                }
            }
            DashboardEvent::Progress { .. } => {
                self.last_progress = serde_json::to_string(ev).ok();
            }
            DashboardEvent::DdosTick { .. } => {
                self.last_ddos_tick = serde_json::to_string(ev).ok();
            }
            DashboardEvent::RlStats { .. } => {
                self.last_rl_stats = serde_json::to_string(ev).ok();
            }
            _ => {}
        }
    }

    /// Sérialise l'état courant, dans l'ordre d'affichage attendu côté client.
    fn replay(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(self.nodes.len() + 3);
        for node in &self.nodes {
            if let Ok(s) =
                serde_json::to_string(&DashboardEvent::NodeScanned { node: node.clone() })
            {
                out.push(s);
            }
        }
        if let Some(s) = &self.last_progress {
            out.push(s.clone());
        }
        if let Some(s) = &self.last_ddos_tick {
            out.push(s.clone());
        }
        if let Some(s) = &self.last_rl_stats {
            out.push(s.clone());
        }
        out
    }
}

// -----------------------------------------------------------------------
// Poignée d'émission — clonable à travers les tasks scan
// -----------------------------------------------------------------------
#[derive(Clone)]
pub struct DashboardEmitter {
    tx: broadcast::Sender<DashboardEvent>,
    total_nodes_guess: Arc<Mutex<usize>>,
    snapshot: Arc<Mutex<SnapshotState>>,
}

impl DashboardEmitter {
    pub async fn send(&self, ev: DashboardEvent) {
        // Mémoriser l'état AVANT de publier : un client peut se connecter
        // juste après et rejouera ce snapshot.
        {
            let mut st = self.snapshot.lock().await;
            st.record(&ev);
        }
        // broadcast ne doit jamais bloquer le scan : fire & forget
        let _ = self.tx.send(ev);
    }

    /// Envoyer un tick de monitoring DDoS (500 ms typique)
    pub async fn send_ddos_tick(&self, tick: DashboardEvent) {
        {
            let mut st = self.snapshot.lock().await;
            st.record(&tick);
        }
        let _ = self.tx.send(tick);
    }

    pub async fn send_node(&self, node: &GraphNode) {
        let ev = DashboardEvent::NodeScanned { node: node.clone() };
        {
            let mut st = self.snapshot.lock().await;
            st.record(&ev);
        }
        let _ = self.tx.send(ev);
        if node.risk >= 5 {
            let top = node
                .cves
                .first()
                .map(|(id, _sev, _desc, _x)| id.clone())
                .unwrap_or_else(|| "n/a".into());
            let alert = DashboardEvent::HighRiskAlert {
                id: node.id.clone(),
                host: node.host.clone(),
                port: node.port,
                risk: node.risk as u8,
                top_cve: top,
            };
            let _ = self.tx.send(alert);
        }
    }

    pub async fn set_estimated_total(&self, n: usize) {
        let mut g = self.total_nodes_guess.lock().await;
        *g = n;
    }

    // -------- OSINT Graph émission --------
    pub async fn send_osint_snapshot(&self, snap: OsintGraphSnapshot) {
        let _ = self.tx.send(DashboardEvent::OsintGraphSnapshot(snap));
    }

    pub async fn send_osint_delta(&self, delta: OsintGraphDelta) {
        let _ = self.tx.send(DashboardEvent::OsintGraphDelta(delta));
    }
}

// -----------------------------------------------------------------------
// Hub : bind TCP + pool de connexions WS
// -----------------------------------------------------------------------
pub struct LiveHub {
    listener: TcpListener,
    bind_port: u16,
    tx: broadcast::Sender<DashboardEvent>,
    started_at: u64,
    /// Jeton de session WS (128 bits, hex) — exigé à l'upgrade `/ws?t=<token>`.
    /// Empêche une page web tierce d'ouvrir une WS vers le dashboard loopback
    /// (la same-origin policy ne s'applique PAS aux WebSocket).
    token: String,
    /// Connexions TCP en cours — pour shutdown gracile (drop = abort)
    #[allow(clippy::type_complexity)]
    active_streams: Arc<Mutex<HashSet<SocketAddr>>>,
    /// État rejoué aux clients WS qui se connectent en retard
    snapshot: Arc<Mutex<SnapshotState>>,
}

impl LiveHub {
    pub const BIND_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    pub const DEFAULT_PORT: u16 = 24601;
    pub const WS_MAGIC: &'static str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    pub const HELLO_VERSION: &'static str = env!("CARGO_PKG_VERSION");

    /// Bind EXCLUSIVEMENT sur 127.0.0.1:port. Refuse catégoriquement 0.0.0.0
    /// même si le caller tente de le forcer (on réécrit par sécurité).
    pub async fn bind(port: u16) -> Result<Self, std::io::Error> {
        let addr = SocketAddr::V4(SocketAddrV4::new(Self::BIND_IP, port));
        let listener = TcpListener::bind(addr).await?;
        let bound = listener.local_addr()?;
        let bind_port = bound.port();
        let (tx, _rx) = broadcast::channel::<DashboardEvent>(512);
        Ok(Self {
            listener,
            bind_port,
            tx,
            started_at: unix_secs(),
            // 128 bits d'entropie, rendus en hex (32 car.) — non devinable,
            // régénéré à chaque lancement (pas de secret persistant sur disque).
            token: format!(
                "{:016x}{:016x}",
                rand::random::<u64>(),
                rand::random::<u64>()
            ),
            active_streams: Arc::new(Mutex::new(HashSet::new())),
            snapshot: Arc::new(Mutex::new(SnapshotState::default())),
        })
    }

    pub fn bind_port(&self) -> u16 {
        self.bind_port
    }

    /// Cloner une poignée émettrice — à passer au scan task
    pub fn emitter(&self) -> DashboardEmitter {
        DashboardEmitter {
            tx: self.tx.clone(),
            total_nodes_guess: Arc::new(Mutex::new(0)),
            snapshot: self.snapshot.clone(),
        }
    }

    /// Boucle serveur — tokio::spawn() ça. Accepte les TcpStream, upgrade en
    /// WebSocket seulement si peer = 127.0.0.1, puis forwarde `broadcast`.
    pub async fn serve(self) {
        let started_at = self.started_at;
        let port = self.bind_port;
        let token = self.token.clone();
        let active = self.active_streams.clone();
        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    // OPSEC: pas d'eprintln! bruyant (réduit fingerprint console)
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
            };

            // ── REJET SOURCE NON LOOPBACK ─────────────────────────────────
            let peer_ip_ok = match peer {
                SocketAddr::V4(v4) => v4.ip().is_loopback(),
                SocketAddr::V6(v6) => v6.ip().is_loopback(),
            };
            if !peer_ip_ok {
                // Refus silencieux : RST immédiat (drop TcpStream sans write)
                drop(stream);
                continue;
            }

            let tx = self.tx.clone();
            let active_c = active.clone();
            let snapshot_c = self.snapshot.clone();
            let token_c = token.clone();
            active_c.lock().await.insert(peer);
            tokio::spawn(async move {
                handle_ws_upgrade(stream, peer, tx, snapshot_c, started_at, port, token_c).await;
                active_c.lock().await.remove(&peer);
            });
        }
    }
}

// -----------------------------------------------------------------------
// Handshake HTTP → WebSocket (server-side minimal)
// -----------------------------------------------------------------------
async fn handle_ws_upgrade(
    mut stream: TcpStream,
    peer: SocketAddr,
    tx: broadcast::Sender<DashboardEvent>,
    snapshot: Arc<Mutex<SnapshotState>>,
    started_at: u64,
    port: u16,
    token: String,
) {
    let mut rx = tx.subscribe();
    let (reader, mut writer) = stream.split();
    let mut buf_reader = BufReader::new(reader);
    let mut head_line = String::new();

    // 1) Lire la request line — timeout 3s sinon close
    let head =
        tokio::time::timeout(Duration::from_secs(3), buf_reader.read_line(&mut head_line)).await;
    if head.is_err() || !head_line.to_uppercase().starts_with("GET ") {
        let _ = writer.shutdown().await;
        return;
    }

    // 2) Parser les headers — recherche Sec-WebSocket-Key
    let mut ws_key: Option<String> = None;
    let mut accept_upgrade = false;
    // En-tête `Origin` — validé plus loin (défense contre les pages web tierces
    // qui ouvriraient une WebSocket vers le dashboard loopback).
    let mut origin: Option<String> = None;
    loop {
        let mut line = String::new();
        let r = tokio::time::timeout(Duration::from_secs(2), buf_reader.read_line(&mut line)).await;
        match r {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                let trimmed = line.trim_end_matches(|c| c == '\r' || c == '\n');
                if trimmed.is_empty() {
                    break;
                }
                let lower = trimmed.to_ascii_lowercase();
                if lower.starts_with("sec-websocket-key:") {
                    ws_key = Some(
                        trimmed
                            .split_once(':')
                            .map(|(_, v)| v.trim().to_string())
                            .unwrap_or_default(),
                    );
                }
                if lower.starts_with("upgrade:") && lower.contains("websocket") {
                    accept_upgrade = true;
                }
                if lower.starts_with("origin:") {
                    origin = Some(
                        trimmed
                            .split_once(':')
                            .map(|(_, v)| v.trim().to_string())
                            .unwrap_or_default(),
                    );
                }
            }
            _ => {
                let _ = writer.shutdown().await;
                return;
            }
        }
    }

    // 3) Décider : "/" → dashboard HTML ; "*.json" → fichier statique ; "/ws" → upgrade WS
    // Extrait le chemin de la requête (sans query string)
    let req_path = head_line.split_whitespace().nth(1).unwrap_or("/");
    let path_no_query: &str = req_path.split('?').next().unwrap_or("/");

    let wants_ws = path_no_query == "/ws" || accept_upgrade;
    let wants_root = path_no_query == "/" || path_no_query == "/dashboard.html";
    let wants_json = path_no_query.ends_with(".json");
    let wants_vendor = path_no_query.starts_with("/vendor/");

    if wants_root && !wants_ws {
        serve_dashboard_html(&mut writer, &token, port).await;
        let _ = writer.flush().await;
        let _ = writer.shutdown().await;
        return;
    }

    // Servir les fichiers JSON statiques (graph.json, *.extras.json, etc.)
    if wants_json && !wants_ws {
        serve_json_file(&mut writer, path_no_query).await;
        let _ = writer.flush().await;
        let _ = writer.shutdown().await;
        return;
    }

    // Servir les librairies JS vendorisées (d3 / three.js) — même origine,
    // zéro dépendance CDN. Liste blanche stricte, pas de traversal possible.
    if wants_vendor && !wants_ws {
        serve_vendor_file(&mut writer, path_no_query).await;
        let _ = writer.flush().await;
        let _ = writer.shutdown().await;
        return;
    }

    // 4) Upgrade WS — Sec-WebSocket-Accept = base64(sha1(key ++ MAGIC))
    let Some(key) = ws_key else {
        let _ = writer
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\nmissing Sec-WebSocket-Key")
            .await;
        let _ = writer.shutdown().await;
        return;
    };

    // ── OPSEC : jeton de session obligatoire (`/ws?t=<token>`) ────────────
    // Sans ce jeton, toute page web ouverte dans le navigateur de l'opérateur
    // pourrait se connecter au dashboard loopback et lire le flux de campagne.
    let req_token = req_path
        .split_once('?')
        .and_then(|(_, q)| {
            q.split('&').find_map(|kv| {
                kv.split_once('=')
                    .filter(|(k, _)| *k == "t")
                    .map(|(_, v)| v)
            })
        })
        .unwrap_or("");
    if !ct_eq(req_token, &token) {
        let _ = writer
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        let _ = writer.shutdown().await;
        return;
    }

    // ── OPSEC : `Origin` doit être une origine loopback ───────────────────
    // Un navigateur envoie toujours Origin pour une WebSocket ; on le refuse
    // s'il est absent ou non-loopback (curl/outils tiers devront le forger,
    // ce qui est dissuasif).
    match origin.as_deref() {
        Some(o) if is_loopback_origin(o, port) => {}
        _ => {
            let _ = writer
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = writer.shutdown().await;
            return;
        }
    }

    let accept_token = ws_accept(&key);

    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         Sec-WebSocket-Protocol: diapile-live\r\n\r\n",
        accept_token
    );
    if writer.write_all(resp.as_bytes()).await.is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    let _ = writer.flush().await;

    // 5) Envoyer HELLO au nouveau client
    let hello = DashboardEvent::Hello {
        port,
        started_at,
        nrtg_version: LiveHub::HELLO_VERSION,
    };
    if ws_send_text(
        &mut writer,
        &serde_json::to_string(&hello).unwrap_or_default(),
    )
    .await
    .is_err()
    {
        let _ = writer.shutdown().await;
        return;
    }

    // 5b) Rejouer l'état courant (nœuds déjà scannés + dernier Progress /
    //     DdosTick / RlStats). Sans ce backfill, un client connecté en retard
    //     voyait une page vide : `broadcast` ne livre que les messages publiés
    //     après son abonnement.
    let replay = {
        let st = snapshot.lock().await;
        st.replay()
    };
    for msg in replay {
        if ws_send_text(&mut writer, &msg).await.is_err() {
            let _ = writer.shutdown().await;
            return;
        }
    }

    // 6) Boucle forwarder broadcast + ping 15s
    let mut ping_ticker = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            _ = ping_ticker.tick() => {
                let p = DashboardEvent::Ping { t: unix_secs() };
                let s = match serde_json::to_string(&p) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if ws_send_text(&mut writer, &s).await.is_err() {
                    break;
                }
            }
            msg = rx.recv() => {
                let ev = match msg {
                    Ok(ev) => ev,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                let s = match serde_json::to_string(&ev) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if ws_send_text(&mut writer, &s).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = writer.shutdown().await;
    let _ = peer; // used for set tracking, silence unused
}

// -----------------------------------------------------------------------
// Encoder une frame WebSocket TEXT (server→client: non masqué).
// Fragmentation inutile : nos messages JSON font généralement < 4KB.
// -----------------------------------------------------------------------
async fn ws_send_text<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    text: &str,
) -> Result<(), std::io::Error> {
    const OPCODE_TEXT: u8 = 0x01;
    const FIN: u8 = 0x80;
    let bytes = text.as_bytes();
    let len = bytes.len();
    if len < 126 {
        let mut head = [0u8; 2];
        head[0] = FIN | OPCODE_TEXT;
        head[1] = len as u8;
        w.write_all(&head).await?;
    } else if len <= 65535 {
        let mut head = [0u8; 4];
        head[0] = FIN | OPCODE_TEXT;
        head[1] = 126;
        let be = (len as u16).to_be_bytes();
        head[2..4].copy_from_slice(&be);
        w.write_all(&head).await?;
    } else {
        let mut head = [0u8; 10];
        head[0] = FIN | OPCODE_TEXT;
        head[1] = 127;
        let be = (len as u64).to_be_bytes();
        head[2..10].copy_from_slice(&be);
        w.write_all(&head).await?;
    }
    w.write_all(bytes).await?;
    w.flush().await?;
    Ok(())
}

fn base64_encode_bytes(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// -----------------------------------------------------------------------
// Sécurité de l'upgrade WS (helpers purs, testables)
// -----------------------------------------------------------------------
/// `Sec-WebSocket-Accept` = base64(SHA-1(key ++ GUID RFC 6455)).
fn ws_accept(key: &str) -> String {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(LiveHub::WS_MAGIC.as_bytes());
    base64_encode_bytes(&hasher.finalize())
}

/// Comparaison de chaînes à temps constant (évite une attaque temporelle sur
/// le jeton de session). Renvoie `false` si les longueurs diffèrent.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Vérifie qu'une origine HTTP est bien loopback et sur le bon port.
/// Accepte `http://127.0.0.1:<port>`, `http://localhost:<port>` et
/// `http://[::1]:<port>`. Un port omis est accepté (défaut du navigateur).
fn is_loopback_origin(origin: &str, port: u16) -> bool {
    let rest = match origin.strip_prefix("http://") {
        Some(r) => r,
        None => return false,
    };
    // IPv6 littéral : « [::1]:port »
    let (host, p) = if let Some(rest6) = rest.strip_prefix('[') {
        match rest6.split_once(']') {
            Some((h, tail)) => (format!("[{h}]"), tail.trim_start_matches(':')),
            None => return false,
        }
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p),
            None => (rest.to_string(), ""),
        }
    };
    let host_ok = matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]");
    let port_ok = p.is_empty() || p == port.to_string();
    host_ok && port_ok
}

// -----------------------------------------------------------------------
// Résolution du chemin dashboard.html
// -----------------------------------------------------------------------
/// Cherche dashboard.html dans plusieurs emplacements, par ordre de priorité :
///   1. CWD (dossier de lancement, pour backwards-compat)
///   2. Dossier contenant l'exécutable (ex: target/release/)
///   3. Parents du dossier de l'exécutable (target/ puis racine projet)
/// Retourne None si aucun fichier trouvé → serveur renverra le fallback.
fn resolve_dashboard_path() -> Option<std::path::PathBuf> {
    resolve_asset("dashboard.html")
}

/// Résout un actif (dashboard.html, vendor/…) relativement aux mêmes dossiers
/// candidats : CWD, dossier de l'exécutable et ses parents, sous-dossiers du CWD.
fn resolve_asset(rel: &str) -> Option<std::path::PathBuf> {
    use std::path::PathBuf;

    let mut dirs: Vec<PathBuf> = Vec::new();

    // 1. CWD
    dirs.push(PathBuf::from("."));

    // 2. Dossier du binaire + 3. parents (jusqu'à 3 niveaux)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let mut d = exe_dir.to_path_buf();
            for _ in 0..4 {
                dirs.push(d.clone());
                if let Some(parent) = d.parent() {
                    d = parent.to_path_buf();
                } else {
                    break;
                }
            }
        }
    }

    // 4. Sous-dossiers immédiats du CWD
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(rd) = std::fs::read_dir(&cwd) {
            for entry in rd.flatten() {
                if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                    dirs.push(entry.path());
                }
            }
        }
    }

    dirs.into_iter()
        .map(|d| d.join(rel))
        .find(|p| p.exists() && p.is_file())
}

// -----------------------------------------------------------------------
// Renvoyer le dashboard LIVE HTML à "/". On lit dashboard.html sur disque
// si présent, sinon on renvoie un bootstrap minimal qui reconnecte WS
// et qui explique à l'opérateur de laisser tourner la console.
// -----------------------------------------------------------------------
async fn serve_dashboard_html<W: AsyncWriteExt + Unpin>(w: &mut W, token: &str, port: u16) {
    // Le jeton de session et le port sont injectés AVANT le patch WS : le
    // bootstrap JS les lit dans `window.__NRTD_LIVE_*`. Le jeton n'est en hex
    // que (aucun échappement HTML nécessaire).
    let boot = format!(
        "<script>window.__NRTD_LIVE_TOKEN__=\"{}\";window.__NRTD_LIVE_PORT__={};</script>",
        token, port
    );
    let mut body: Vec<u8> = match resolve_dashboard_path().and_then(|p| std::fs::read(p).ok()) {
        Some(b) => {
            // Injecter le petit patch WS dans le dashboard s'il n'est pas
            // déjà en mode live — remplacement sécuriste par surimpression
            // d'un script inline au milieu du <head>.
            let patch_str = format!("{boot}{WS_BOOTSTRAP}");
            let patch = patch_str.as_bytes();
            let mut merged = Vec::with_capacity(b.len() + patch.len() + 64);
            match find_head_close(&b) {
                Some(pos) => {
                    merged.extend_from_slice(&b[..pos]);
                    merged.extend_from_slice(patch);
                    merged.extend_from_slice(&b[pos..]);
                }
                None => {
                    // pas trouvé </head> : fallback ajouter patch avant </html>
                    match b.windows(b"</html>".len()).position(|w| w == b"</html>") {
                        Some(i) => {
                            merged.extend_from_slice(&b[..i]);
                            merged.extend_from_slice(patch);
                            merged.extend_from_slice(&b[i..]);
                        }
                        None => {
                            merged.extend_from_slice(&b);
                            merged.extend_from_slice(patch);
                        }
                    }
                }
            }
            merged
        }
        None => {
            // Fichier absent : squelette embarqué + injection du jeton/port
            // (sans le bootstrap complet : le squelette gère sa propre WS).
            let fb = FALLBACK_HTML.as_bytes();
            let mut merged = Vec::with_capacity(fb.len() + boot.len() + 16);
            match find_head_close(fb) {
                Some(pos) => {
                    merged.extend_from_slice(&fb[..pos]);
                    merged.extend_from_slice(boot.as_bytes());
                    merged.extend_from_slice(&fb[pos..]);
                }
                None => {
                    merged.extend_from_slice(fb);
                    merged.extend_from_slice(boot.as_bytes());
                }
            }
            merged
        }
    };

    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store, no-cache\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         Content-Security-Policy: {}\r\n\
         Connection: close\r\n\r\n",
        body.len(),
        CSP_POLICY
    );
    let _ = w.write_all(header.as_bytes()).await;
    let _ = w.write_all(&mut body).await;
}

/// Politique CSP : tout est restreint à la même origine, sauf les Google Fonts
/// (CSS uniquement, non exécutable). Pas de `unsafe-eval`. `frame-ancestors`
/// interdit l'inclusion du dashboard dans une iframe tierce (anti-clickjacking
/// et anti-exfiltration du jeton de session).
const CSP_POLICY: &str = "default-src 'self'; \
     script-src 'self' 'unsafe-inline'; \
     style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
     font-src 'self' data: https://fonts.gstatic.com; \
     img-src 'self' data: blob:; \
     connect-src 'self' ws://127.0.0.1:* ws://localhost:* https://fonts.googleapis.com https://fonts.gstatic.com; \
     base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

// -----------------------------------------------------------------------
// Servir un fichier JSON statique depuis le CWD (graph.json, *.extras.json,
// etc.). Utilisé par le dashboard qui fetch() ces fichiers en HTTP.
// Sécurité : refuse les chemins contenant ".." ou des backslashes pour
// éviter le path traversal (le serveur est bindé 127.0.0.1 mais par
// principe de défense en profondeur).
// -----------------------------------------------------------------------
async fn serve_json_file<W: AsyncWriteExt + Unpin>(w: &mut W, url_path: &str) {
    let rel = url_path.trim_start_matches('/');

    // Défense contre le path traversal
    if rel.contains("..") || rel.contains('\\') {
        let _ = w
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return;
    }

    let path = std::path::Path::new(rel);
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-store, no-cache\r\n\
                 Connection: close\r\n\r\n",
                bytes.len()
            );
            let _ = w.write_all(header.as_bytes()).await;
            let _ = w.write_all(&bytes).await;
        }
        Err(_) => {
            let _ = w
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        }
    }
}

// -----------------------------------------------------------------------
// Servir une librairie JS vendorisée (`/vendor/<name>`) — même origine, donc
// aucune dépendance CDN. Liste blanche stricte : seuls les deux fichiers
// embarqués sont servis, ce qui rend tout path traversal impossible.
// -----------------------------------------------------------------------
async fn serve_vendor_file<W: AsyncWriteExt + Unpin>(w: &mut W, url_path: &str) {
    let name = url_path.trim_start_matches('/').strip_prefix("vendor/");
    let rel = match name {
        Some("d3.v7.min.js") => "vendor/d3.v7.min.js",
        Some("three.min.js") => "vendor/three.min.js",
        _ => {
            let _ = w
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return;
        }
    };

    match resolve_asset(rel).and_then(|p| std::fs::read(p).ok()) {
        Some(bytes) => {
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/javascript; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-store, no-cache\r\n\
                 X-Content-Type-Options: nosniff\r\n\
                 Connection: close\r\n\r\n",
                bytes.len()
            );
            let _ = w.write_all(header.as_bytes()).await;
            let _ = w.write_all(&bytes).await;
        }
        None => {
            let _ = w
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        }
    }
}

fn find_head_close(hay: &[u8]) -> Option<usize> {
    // Chercher la PREMIÈRE occurrence de "</head>" (insensible à la casse)
    let needle = b"</head>";
    for i in 0..hay.len().saturating_sub(needle.len()) {
        let w = &hay[i..i + needle.len()];
        if w.eq_ignore_ascii_case(needle) {
            return Some(i);
        }
    }
    None
}

// -----------------------------------------------------------------------
// Patch JS injecté dans dashboard.html pour activer le mode LIVE
// -----------------------------------------------------------------------
const WS_BOOTSTRAP: &str = r##"
<!-- DIAPILE LIVE DASHBOARD INJECT (patch serveur 127.0.0.1:24601) -->
<script id="__nrtg_live__" type="module">
(() => {
  const PORT  = window.__NRTD_LIVE_PORT__ || 24601;
  const TOKEN = window.__NRTD_LIVE_TOKEN__ || "";
  const URL   = `ws://127.0.0.1:${PORT}/ws?t=${encodeURIComponent(TOKEN)}`;
  let ws, closed = false, retries = 0;
  const MAX_RETRIES = 30;
  const liveNodes = new Map();
  const alertsPending = [];
  // Éléments DOM créés dynamiquement (progress bar + alert overlay)
  const ui = boot_ui();
  window.__NRTD_LIVE__ = { ui, nodes: liveNodes, pushNode, pushProgress, alertHighRisk };

  connect();
  function connect() {
    try { ws = new WebSocket(URL, "diapile-live"); }
    catch(e){ setTimeout(connect, 1500); return; }
    ws.onopen    = () => { ui.setStatus("LIVE", "#00ff66"); retries = 0; };
    ws.onmessage = (ev) => { try { handleMsg(JSON.parse(ev.data)); } catch(e){} };
    ws.onclose   = () => {
      ui.setStatus("RECONNECT", "#ffaa00");
      if (!closed && retries++ < MAX_RETRIES) setTimeout(connect, 1500);
      else ui.setStatus("SCAN END", "#8888ff");
    };
    ws.onerror   = () => { try{ ws.close(); }catch(e){} };
  }

  function handleMsg(msg){
    switch (msg.type) {
      case "Hello":
        ui.setStartedAt(msg.data.started_at);
        break;
      case "NodeScanned":
        pushNode(msg.data.node);
        break;
      case "Progress":
        pushProgress(msg.data);
        break;
      case "Finished":
        ui.setTotal(msg.data.total_nodes, msg.data.reachable, msg.data.elapsed_ms);
        closed = true;
        setTimeout(()=>{ try{ ws.close(); }catch(e){} }, 500);
        break;
      case "HighRiskAlert":
        alertHighRisk(msg.data);
        break;
      case "DdosTick":
        // Bridge: forward tick to dashboard renderer (CustomEvent)
        window.dispatchEvent(new CustomEvent("nrtg:ddos_tick", { detail: msg.data }));
        // Inject quick info into LIVE top bar too
        try {
          const dd = msg.data;
          const metricsEl = document.getElementById("nrtg-metrics");
          if (metricsEl && dd.rps !== undefined) {
            const wafPct = Math.round((dd.rwaf || 0) * 1000) / 10;
            const fivePct = Math.round((dd.r5xx || 0) * 1000) / 10;
            metricsEl.innerHTML =
              `🤖BOTS:<span style="color:#ffcc55;">${Math.round(dd.bots_concurrent||0)}</span> · ` +
              `💨RPS:<span style="color:#ffae6b;">${Math.round(dd.rps||0)}</span> · ` +
              `5xx:<span style="color:${fivePct>=30?'#ff5555':'#ffaa55'};">${fivePct}%</span> · ` +
              `WAF:<span style="color:${wafPct>=15?'#ff5555':'#5bb0ff'};">${wafPct}%</span> · ` +
              `FCT:<span style="color:#${(dd.adapt_factor||1)>=1?'00ff66':'ffaa00'};">x${(dd.adapt_factor||1).toFixed(1)}</span>`;
          }
        } catch (_e) {}
        break;
      case "OsintGraphSnapshot":
        window.__OSINT_GRAPH__ || boot_osint_graph();
        window.__OSINT_GRAPH__.renderSnapshot(msg.data);
        break;
      case "OsintGraphDelta":
        window.__OSINT_GRAPH__ || boot_osint_graph();
        window.__OSINT_GRAPH__.applyDelta(msg.data);
        break;
      case "Log":
        // Bridge: journal IA/système → terminal côté dashboard
        window.dispatchEvent(new CustomEvent("nrtg:agent_log", { detail: msg.data }));
        break;
      case "AgentDecision":
        // Bridge: décision de l'agent (action + résultat RL)
        window.dispatchEvent(new CustomEvent("nrtg:agent_decision", { detail: msg.data }));
        break;
      case "RlStats":
        // Bridge: agrégats d'apprentissage RL (Q-table, ε, top actions, phases)
        window.dispatchEvent(new CustomEvent("nrtg:rl_stats", { detail: msg.data }));
        break;
      case "Ping":
        break;
    }
  }

  // ---------- OSINT GRAPHE FORCE-DIRECTED D3.js ----------
  // Créé paresseusement: onglet + panneau latéral avec SVG D3, légende, tooltip,
  // zoom/drag. D3.js injecté dynamiquement si pas déjà chargé sur le host HTML.
  function boot_osint_graph() {
    if (window.__OSINT_GRAPH__) return window.__OSINT_GRAPH__;

    // --- palette de couleurs strictement typée par `kind` ---
    const KIND_COLOR = {
      root_domain:    "#ff1744",
      subdomain:      "#00e5ff",
      ip_addr:        "#b388ff",
      email:          "#ffea00",
      dns_record:     "#69f0ae",
      technology:     "#ff9100",
      open_port:      "#ff6d00",
      leak:           "#e040fb",
      breach:         "#ff1744",
      historical_url: "#7c4dff",
    };
    const KIND_LABEL = {
      root_domain:    "Root domain",
      subdomain:      "Subdomaine",
      ip_addr:        "IP",
      email:          "Email",
      dns_record:     "Record DNS",
      technology:     "Technologie",
      open_port:      "Port ouvert",
      leak:           "Leak GitHub",
      breach:         "Breach HIBP",
      historical_url: "URL historique",
    };
    const EDGE_COLOR = {
      has_subdomain:       "#00e5ffaa",
      resolves_to:         "#b388ffcc",
      has_dns_record:      "#69f0aecc",
      mail_server_ip:      "#ffff66cc",
      contains_email:      "#ffea00cc",
      has_open_port:       "#ff6d00cc",
      runs_technology:     "#ff9100cc",
      referenced_in_leak:  "#e040fbcc",
      seen_in_breach:      "#ff1744cc",
      has_historical_entry:"#7c4dffcc",
    };

    // Inject D3.js if missing
    let d3Ready = false;
    const pending = [];
    function withD3(fn){ if (d3Ready) fn(); else pending.push(fn); }
    if (typeof window.d3 === "undefined" || !window.d3 || !window.d3.select) {
      const s = document.createElement("script");
      // D3 servi en local (même origine) — aucune dépendance CDN, fonctionne
      // hors-ligne/air-gap. L'ancien SRI CDN était invalide (63 car. au lieu
      // des 64 attendus) et bloquait systématiquement le script.
      s.src = "/vendor/d3.v7.min.js";
      s.onload = () => { d3Ready = true; pending.splice(0).forEach(fn=>fn()); };
      s.onerror = () => { console.warn("[OSINT] D3 local indisponible — graphe désactivé"); };
      document.head.appendChild(s);
    } else {
      d3Ready = true;
    }

    // Onglet panneau OSINT
    const panel = document.createElement("div");
    panel.id = "__nrtg_osint_panel__";
    panel.style.cssText = `
      position:fixed; right:12px; bottom:12px; width:min(62vw, 1000px);
      height:min(78vh, 820px); background: linear-gradient(180deg, #020a12ee 0%, #050e1ff0 100%);
      backdrop-filter: blur(6px);
      border: 1px solid #00e5ff66; border-radius: 14px; z-index: 2147483644;
      box-shadow: 0 25px 80px rgba(0, 229, 255, 0.08), 0 0 0 1px #00e5ff22 inset;
      display:flex; flex-direction:column;
      transition: transform .25s ease, opacity .25s ease;
      color:#cfe;
      font-family: ui-monospace, 'JetBrains Mono', 'Fira Code', Consolas, monospace;
      resize: both; overflow: hidden; min-width: 400px; min-height: 300px;
    `;
    panel.innerHTML = `
      <div id="__nrtg_osint_head__" style="display:flex;align-items:center;gap:14px;
           padding:10px 14px;border-bottom:1px solid #00e5ff44;user-select:none;cursor:move;">
        <div style="color:#00e5ff;font-weight:900;letter-spacing:1px;">
          ▍OSINT · GRAPH LIVE
        </div>
        <div id="__nrtg_osint_target__" style="padding:2px 8px;border:1px solid #ff1744aa;
             border-radius:999px;color:#ff5577;font-size:11px;">target: ?</div>
        <div id="__nrtg_osint_counts__" style="font-size:11px;opacity:.75;"></div>
        <div style="flex:1"></div>
        <button id="__nrtg_osint_fs__" title="Plein écran" style="background:#001a33;color:#00e5ff;
             border:1px solid #00e5ff66;border-radius:6px;cursor:pointer;padding:3px 10px;font-size:11px;">🗖</button>
        <button id="__nrtg_osint_min__" style="background:#001a33;color:#00e5ff;border:1px solid #00e5ff66;
             border-radius:6px;cursor:pointer;padding:3px 10px;font-size:11px;">— minimiser</button>
        <button id="__nrtg_osint_reset__" title="Recentrer / réchauffer layout"
             style="background:transparent;color:#cfe;border:1px solid #335;border-radius:6px;
             cursor:pointer;padding:3px 10px;font-size:11px;">⟳ Reset</button>
        <button id="__nrtg_osint_png__" title="Exporter le graphe en PNG haute résolution"
             style="background:#003322;color:#69f0ae;border:1px solid #69f0ae66;border-radius:6px;
             cursor:pointer;padding:3px 10px;font-size:11px;">📷 PNG</button>
        <button id="__nrtg_osint_close__" style="background:transparent;color:#ff9999;
             border:1px solid #533;border-radius:6px;cursor:pointer;padding:3px 10px;
             font-size:11px;">✕</button>
      </div>
      <div id="__nrtg_osint_body__" style="flex:1;position:relative;overflow:hidden;">
        <svg id="__nrtg_osint_svg__" style="width:100%;height:100%;"></svg>
        <div id="__nrtg_osint_tooltip__" style="position:absolute;visibility:hidden;
             padding:8px 10px;background:#001a2aee;border:1px solid #00e5ffaa;border-radius:6px;
             font-size:11px;max-width:360px;pointer-events:none;z-index:2;
             box-shadow:0 6px 24px #000;"></div>
        <div id="__nrtg_osint_legend__" style="position:absolute;left:10px;top:10px;
             background:#020a12cc;border:1px solid #00e5ff33;border-radius:10px;
             padding:8px 10px;font-size:10.5px;backdrop-filter: blur(4px);"></div>
      </div>
      <div id="__nrtg_osint_footer__" style="padding:6px 12px;border-top:1px solid #00e5ff33;
           font-size:11px;color:#79a;display:flex;gap:12px;">
        <span>🖱 drag nœuds · molette zoom · clique isoler · 📷 export PNG</span>
        <span style="flex:1"></span>
        <span id="__nrtg_osint_status__">attente snapshot…</span>
      </div>
    `;
    document.body.appendChild(panel);

    // Drag barre titre
    (function makeDraggable(){
      const head = panel.querySelector("#__nrtg_osint_head__");
      let sx=0,sy=0,ox=0,oy=0,dragging=false;
      head.addEventListener("mousedown", (e)=>{
        dragging=true; sx=e.clientX; sy=e.clientY;
        const r=panel.getBoundingClientRect(); ox=r.left; oy=r.top;
        panel.style.left=ox+"px"; panel.style.top=oy+"px";
        panel.style.right="auto"; panel.style.bottom="auto";
      });
      window.addEventListener("mousemove",(e)=>{
        if(!dragging)return;
        panel.style.left=(ox+e.clientX-sx)+"px";
        panel.style.top=(oy+e.clientY-sy)+"px";
      });
      window.addEventListener("mouseup",()=>dragging=false);
    })();

    // Boutons header
    panel.querySelector("#__nrtg_osint_close__").addEventListener("click",()=>{
      panel.remove(); delete window.__OSINT_GRAPH__;
    });

    const btnFs = panel.querySelector("#__nrtg_osint_fs__");
    const btnMin = panel.querySelector("#__nrtg_osint_min__");
    const bodyEl = panel.querySelector("#__nrtg_osint_body__");
    const footEl = panel.querySelector("#__nrtg_osint_footer__");
    let minimized = false;
    let fullscreen = false;
    // Mémoriser la hauteur initiale pour la restauration
    const originalHeight = panel.style.height || "min(78vh, 820px)";
    const originalWidth = panel.style.width || "min(62vw, 1000px)";

    btnFs.addEventListener("click", () => {
      fullscreen = !fullscreen;
      if (fullscreen) {
        panel.style.width = "100vw";
        panel.style.height = "100vh";
        panel.style.left = "0";
        panel.style.top = "0";
        panel.style.right = "auto";
        panel.style.bottom = "auto";
        panel.style.borderRadius = "0";
        btnFs.textContent = "🗗";
        btnFs.title = "Restaurer";
      } else {
        panel.style.width = originalWidth;
        panel.style.height = originalHeight;
        panel.style.left = "";
        panel.style.top = "";
        panel.style.right = "12px";
        panel.style.bottom = "12px";
        panel.style.borderRadius = "14px";
        btnFs.textContent = "🗖";
        btnFs.title = "Plein écran";
      }
      // Trigger D3 resize
      window.dispatchEvent(new Event("resize"));
    });

    btnMin.addEventListener("click", ()=>{
      minimized = !minimized;
      bodyEl.style.display = minimized ? "none" : "block";
      footEl.style.display = minimized ? "none" : "flex";
      panel.style.height = minimized ? "auto" : (fullscreen ? "100vh" : originalHeight);
      btnMin.textContent = minimized ? "+ agrandir" : "— minimiser";
      btnFs.style.display = minimized ? "none" : "block";
      // Si on agrandit, on relance un petit tick de simulation pour replacer
      if (!minimized && window.__OSINT_GRAPH__) {
          window.__OSINT_GRAPH__.simulation?.alpha(0.1).restart();
          window.dispatchEvent(new Event("resize"));
      }
    });

    // Observer pour le redimensionnement manuel (resize: both)
    const resizeObserver = new ResizeObserver(() => {
        if (!minimized) {
            window.dispatchEvent(new Event("resize"));
        }
    });
    resizeObserver.observe(panel);

    // Legend
    const legendEl = panel.querySelector("#__nrtg_osint_legend__");
    legendEl.innerHTML = Object.keys(KIND_LABEL).map(k => `
      <div style="display:flex;align-items:center;gap:6px;padding:2px 0;">
        <span style="width:10px;height:10px;border-radius:50%;background:${KIND_COLOR[k]};
          box-shadow:0 0 6px ${KIND_COLOR[k]};"></span>
        <span>${KIND_LABEL[k]}</span>
      </div>`).join("") + `
      <div style="margin-top:6px;padding-top:6px;border-top:1px solid #00e5ff33;">
        <div style="display:flex;align-items:center;gap:6px;padding:2px 0;">
          <span style="width:10px;height:10px;border-radius:50%;background:#1a3a4a;
            border:1.3px dashed #3a7a9a;opacity:.5;"></span>
          <span style="font-size:10px;opacity:.8;">Subdomaine passif (CT only)</span>
        </div>
        <div style="display:flex;align-items:center;gap:6px;padding:2px 0;">
          <span style="width:10px;height:10px;border-radius:50%;background:${KIND_COLOR.subdomain};
            box-shadow:0 0 6px ${KIND_COLOR.subdomain};"></span>
          <span style="font-size:10px;opacity:.8;">Subdomaine actif (résolu)</span>
        </div>
      </div>`;

    const tooltipEl = panel.querySelector("#__nrtg_osint_tooltip__");
    const statusEl  = panel.querySelector("#__nrtg_osint_status__");
    const countEl   = panel.querySelector("#__nrtg_osint_counts__");
    const targetEl  = panel.querySelector("#__nrtg_osint_target__");

    // State
    const byId = new Map();
    const edgeById = new Map();
    let stats = {};

    function updateCounts(){
      countEl.textContent =
        `nœuds=${byId.size} · liens=${edgeById.size} · sub=${stats.total_subdomains||0} · `+
        `actifs=${stats.active_subdomains||0} · IP=${stats.total_ips||0} · emails=${stats.total_emails||0} · `+
        `ports=${stats.total_ports||0} · leaks=${stats.total_leaks||0}`;
    }

    // Échappe les caractères HTML pour éviter l'injection dans le tooltip
    // et le panneau de détail (le snippet de code peut contenir du HTML).
    function escapeHtml(s){
      if (s == null) return "";
      return String(s)
        .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
        .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
    }

    // Panneau de détail persistant affiché au clic sur un nœud.
    // Pour les fuites GitHub, il montre le snippet (mot de passe / token)
    // qui n'est visible ni dans le label ni dans le tooltip court.
    let detailEl = null;
    function showNodeDetail(d){
      if (!detailEl){
        detailEl = document.createElement("div");
        detailEl.style.cssText = `
          position:fixed; left:50%; top:50%; transform:translate(-50%,-50%);
          width:min(680px, 90vw); max-height:80vh; overflow:auto;
          background: linear-gradient(180deg, #0a0f1eee 0%, #050a14f0 100%);
          border:1px solid #00e5ff66; border-radius:14px; z-index:2147483645;
          box-shadow: 0 30px 90px rgba(0,0,0,.8), 0 0 0 1px #00e5ff22 inset;
          color:#cfe; font-family: ui-monospace, 'JetBrains Mono', Consolas, monospace;
          font-size:13px; padding:0;`;
        document.body.appendChild(detailEl);
      }
      const kindColor = KIND_COLOR[d.kind] || "#888";
      const kindLabel = KIND_LABEL[d.kind] || d.kind;
      // Pour les fuites, le detail contient "type:X · commit Y\n--- snippet ---\n..."
      // On sépare le header du snippet pour un rendu clair.
      let headerInfo = "";
      let snippet = "";
      if (d.detail){
        const parts = String(d.detail).split("\n--- snippet ---\n");
        headerInfo = parts[0] || "";
        snippet = parts[1] || (parts[0] && parts[0].includes("snippet") ? "" : "");
      }
      detailEl.innerHTML = `
        <div style="display:flex;align-items:center;gap:10px;padding:12px 16px;
             border-bottom:1px solid #00e5ff44;background:#020a12cc;">
          <span style="width:12px;height:12px;border-radius:50%;background:${kindColor};
            box-shadow:0 0 8px ${kindColor};"></span>
          <span style="color:${kindColor};font-weight:800;letter-spacing:.5px;">${escapeHtml(kindLabel)}</span>
          <span style="flex:1"></span>
          <button data-close style="background:transparent;color:#ff9999;border:1px solid #533;
            border-radius:6px;cursor:pointer;padding:2px 10px;font-size:11px;">✕ fermer</button>
        </div>
        <div style="padding:16px 18px;">
          <div style="font-size:15px;color:#fff;font-weight:700;margin-bottom:10px;word-break:break-all;">
            ${escapeHtml(d.label)}
          </div>
          ${headerInfo ? `<div style="opacity:.8;margin-bottom:12px;">${escapeHtml(headerInfo)}</div>` : ""}
          ${snippet ? `
            <div style="margin-top:10px;">
              <div style="color:#ff6b6b;font-weight:700;margin-bottom:6px;font-size:11px;letter-spacing:.5px;">
                ⚠️  CONTENU FUITÉ (SNIPPET)
              </div>
              <pre style="background:#0a0505;border:1px solid #ff444433;border-radius:8px;
                padding:12px 14px;overflow-x:auto;color:#ffb4b4;white-space:pre-wrap;
                word-break:break-all;font-size:12px;line-height:1.5;">${escapeHtml(snippet)}</pre>
            </div>` : ""}
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:14px;font-size:11px;">
            <div style="background:#001a2a55;border:1px solid #00e5ff33;border-radius:6px;padding:6px 10px;">
              <span style="opacity:.6;">ID</span><br><span style="color:#00e5ff;">${escapeHtml(d.id)}</span>
            </div>
            <div style="background:#001a2a55;border:1px solid #00e5ff33;border-radius:6px;padding:6px 10px;">
              <span style="opacity:.6;">Poids</span><br><span style="color:#69f0ae;">${d.weight?.toFixed(1) || "1.0"}</span>
            </div>
          </div>
        </div>`;
      detailEl.style.display = "block";
      detailEl.querySelector("[data-close]").addEventListener("click", ()=>{
        detailEl.style.display = "none";
      });
    }

    withD3(()=>{
      const svg = d3.select(panel.querySelector("#__nrtg_osint_svg__"));
      const W = () => svg.node().clientWidth;
      const H = () => svg.node().clientHeight;
      svg.attr("viewBox", [0,0,W(),H()]);

      const defs = svg.append("defs");
      // Arrows markers par type d'edge
      Object.keys(EDGE_COLOR).forEach(k => {
        defs.append("marker")
          .attr("id","arr-"+k).attr("viewBox","0 -5 10 10").attr("refX",18).attr("refY",0)
          .attr("markerWidth",5).attr("markerHeight",5).attr("orient","auto-start-reverse")
          .append("path").attr("d","M0,-5L10,0L0,5").attr("fill", EDGE_COLOR[k]||"#aaa");
      });
      // Glow (drop-shadow fe)
      const f = defs.append("filter").attr("id","__nrtg_glow__").attr("x","-50%").attr("y","-50%").attr("width","200%").attr("height","200%");
      f.append("feGaussianBlur").attr("stdDeviation","3").attr("result","b");
      const m = f.append("feMerge");
      m.append("feMergeNode").attr("in","b");
      m.append("feMergeNode").attr("in","SourceGraphic");

      // Containers
      const layerEdges = svg.append("g");
      const layerNodes = svg.append("g");
      const layerLabels = svg.append("g");
      const zoomLayer = svg.append("g").attr("class","zroot").call(()=>{});
      // On réorganise en une seule racine pour zoom
      svg.selectAll("g").remove();
      const rootG = svg.append("g").attr("class","__rt__");
      const gEdges = rootG.append("g").attr("class","edges");
      const gNodes = rootG.append("g").attr("class","nodes");

      // Zoom
      const zoom = d3.zoom().scaleExtent([0.2, 4]).on("zoom", (e)=>{
        rootG.attr("transform", e.transform);
      });
      svg.call(zoom);

      // Niveau hiérarchique par type de nœud → rayon dans le layout radial
      // 0 = centre (root), 1 = sous-domaines / records DNS,
      // 2 = IPs / emails / techno, 3 = ports / leaks / breaches / URLs
      const LEVEL = {
        root_domain: 0, subdomain: 1, dns_record: 1,
        ip_addr: 2, email: 2, technology: 2,
        open_port: 3, leak: 3, breach: 3, historical_url: 3,
      };
      const RING = () => Math.min(W(), H()) * 0.46;
      const force = d3.forceSimulation()
        .force("link", d3.forceLink().id(d => d.id).distance(d => {
          // Liens inter-anneaux plus longs pour renforcer la hiérarchie
          const sl = LEVEL[(d.source.kind||d.source)] || 1;
          const tl = LEVEL[(d.target.kind||d.target)] || 1;
          return 40 + Math.abs(sl - tl) * 55;
        }).strength(0.5))
        .force("charge", d3.forceManyBody().strength(-140))
        .force("center", d3.forceCenter(W()/2, H()/2).strength(0.06))
        .force("collide", d3.forceCollide().radius(d => 7 + (d.weight||1) * 1.7))
        .force("rad", d3.forceRadial(
          d => RING() * ((LEVEL[d.kind] || 1) / 3),
          W()/2, H()/2
        ).strength(0.88))
        .alpha(0.7).alphaDecay(0.028);

      window.addEventListener("resize", ()=>{
        svg.attr("viewBox", [0,0,W(),H()]);
        force.force("center", d3.forceCenter(W()/2, H()/2));
        force.alpha(0.25).restart();
      });

      panel.querySelector("#__nrtg_osint_reset__").addEventListener("click", ()=>{
        svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
        force.force("center", d3.forceCenter(W()/2, H()/2));
        force.alpha(0.6).restart();
      });

      // Export PNG haute résolution (x2) avec fond opaque
      panel.querySelector("#__nrtg_osint_png__").addEventListener("click", () => {
        const svgEl = panel.querySelector("#__nrtg_osint_svg__");
        const bb = svgEl.getBoundingClientRect();
        const clone = svgEl.cloneNode(true);

        // ── OPSEC : Inliner les styles pour éviter un export vide ou cassé ──
        // On récupère les styles CSS du document pour les injecter dans le SVG
        const styles = document.querySelectorAll("style");
        const defs = clone.querySelector("defs") || clone.insertBefore(document.createElementNS("http://www.w3.org/2000/svg", "defs"), clone.firstChild);
        styles.forEach(s => {
            const styleCopy = s.cloneNode(true);
            defs.appendChild(styleCopy);
        });

        clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
        clone.setAttribute("width", Math.round(bb.width));
        clone.setAttribute("height", Math.round(bb.height));
        clone.setAttribute("viewBox", svgEl.getAttribute("viewBox") || `0 0 ${bb.width} ${bb.height}`);

        const svgData = new XMLSerializer().serializeToString(clone);
        const blob = new Blob([svgData], { type: "image/svg+xml;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const img = new Image();

        img.onload = () => {
          const scale = 2;
          const canvas = document.createElement("canvas");
          canvas.width = Math.round(bb.width * scale);
          canvas.height = Math.round(bb.height * scale);
          const ctx = canvas.getContext("2d");
          // Fond sombre identique au dashboard pour un rendu pro
          ctx.fillStyle = "#020a12";
          ctx.fillRect(0, 0, canvas.width, canvas.height);
          ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
          URL.revokeObjectURL(url);
          canvas.toBlob(b => {
            if (!b) return;
            const a = document.createElement("a");
            a.href = URL.createObjectURL(b);
            a.download = `osint-graph-${targetEl.textContent.replace(/[^a-z0-9]/gi,"_").slice(0,40)}-${Date.now()}.png`;
            a.click();
            URL.revokeObjectURL(a.href);
            statusEl.textContent = "✓ PNG exporté";
            setTimeout(() => { statusEl.textContent = "prêt"; }, 2000);
          }, "image/png");
        };
        img.onerror = (e) => {
            console.error("PNG Export Error:", e);
            statusEl.textContent = "⚠ export PNG échoué (SVG taint ou CSS)";
            URL.revokeObjectURL(url);
        };
        img.src = url;
      });

      let linkSel = gEdges.selectAll("line");
      let nodeSel = gNodes.selectAll("g");

      function restitch(){
        const nodes = Array.from(byId.values());
        const edges = Array.from(edgeById.values());
        // Sous-domaines "actifs" = ceux qui ont un edge resolves_to vers une IP
        const activeSubs = new Set();
        edges.forEach(e => {
          if (e.kind === "resolves_to") {
            const s = e.source?.id || e.source;
            activeSubs.add(s);
          }
        });
        const isPassive = d => d.kind === "subdomain" && !activeSubs.has(d.id);

        force.nodes(nodes);
        force.force("link").links(edges);

        linkSel = linkSel.data(edges, d => d.id);
        linkSel.exit().remove();
        const linkEnter = linkSel.enter().append("line")
          .attr("stroke", d => EDGE_COLOR[d.kind] || "#555")
          .attr("stroke-width", d => d.kind === "has_subdomain" ? 1.6 : 0.9)
          .attr("stroke-opacity", 0.78)
          .attr("stroke-dasharray", d => {
            if (d.kind === "has_subdomain") {
              const tgt = d.target?.id || d.target;
              return activeSubs.has(tgt) ? null : "4 3";
            }
            return null;
          })
          .attr("marker-end", d => `url(#arr-${d.kind})`);
        linkSel = linkEnter.merge(linkSel);

        nodeSel = nodeSel.data(nodes, d => d.id);
        nodeSel.exit().remove();
        const ng = nodeSel.enter().append("g")
          .attr("cursor","grab")
          .call(d3.drag()
            .on("start",(e,d)=>{if(!e.active)force.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;})
            .on("drag",(e,d)=>{d.fx=e.x; d.fy=e.y;})
            .on("end",(e,d)=>{if(!e.active)force.alphaTarget(0);d.fx=null;d.fy=null;}));
        ng.append("circle")
          .attr("r", d => {
            const base = Math.max(3.5, 3 + (d.weight||1) * 1.45);
            return isPassive(d) ? base * 0.72 : base;
          })
          .attr("fill", d => isPassive(d) ? "#1a3a4a" : KIND_COLOR[d.kind] || "#888")
          .attr("stroke", d => {
            if (d.kind === "root_domain") return "#fff";
            if (isPassive(d)) return "#3a7a9a";
            return "#00000099";
          })
          .attr("stroke-width", d => {
            if (d.kind === "root_domain") return 1.8;
            if (isPassive(d)) return 1.3;
            return 0.6;
          })
          .attr("stroke-dasharray", d => isPassive(d) ? "3 2" : null)
          .attr("filter", d => d.kind === "root_domain" ? "url(#__nrtg_glow__)" : null)
          .attr("opacity", d => isPassive(d) ? 0.5 : 0.95)
          .on("mouseover", (e,d)=>{
            tooltipEl.style.visibility = "visible";
            const stateBadge = isPassive(d)
              ? `<div style="color:#6a9bb5;margin-top:2px;font-size:10px;">◌ passif (CT logs, non résolu)</div>`
              : (d.kind === "subdomain" ? `<div style="color:#69f0ae;margin-top:2px;font-size:10px;">● actif (résolu DNS)</div>` : "");
            // Aperçu du detail (sauts de ligne → <br>) ; pour les fuites on
            // montre un extrait court dans le tooltip, le panneau de détail
            // au clic affichera le snippet complet.
            const detailHtml = d.detail
              ? `<div style="margin-top:4px;opacity:.8;white-space:pre-wrap;max-height:120px;overflow:hidden;">${escapeHtml(d.detail)}</div>`
              : "";
            tooltipEl.innerHTML = `<div style="color:${KIND_COLOR[d.kind]||'#fff'};
              font-weight:800;margin-bottom:4px;">${KIND_LABEL[d.kind]||d.kind}</div>
              <div style="color:#fff;">${escapeHtml(d.label)}</div>
              ${stateBadge}
              ${detailHtml}`;
          })
          .on("mousemove", (e)=>{
            const r = bodyEl.getBoundingClientRect();
            tooltipEl.style.left = (e.clientX - r.left + 12) + "px";
            tooltipEl.style.top  = (e.clientY - r.top  + 12) + "px";
          })
          .on("mouseout", () => tooltipEl.style.visibility = "hidden")
          .on("click", (e,d)=>{
            // Isolation: griser tous sauf voisins
            const adj = new Set([d.id]);
            edges.forEach(l => { if (l.source.id?l.source.id===d.id:l.source===d.id) adj.add(l.target.id?l.target.id:l.target);
                                  if (l.target.id?l.target.id===d.id:l.target===d.id) adj.add(l.source.id?l.source.id:l.source);});
            nodeSel.selectAll("circle").transition().duration(200)
              .attr("opacity", n => adj.has(n.id)?1:0.12);
            linkSel.transition().duration(200)
              .attr("stroke-opacity", l => {
                const s = l.source.id?l.source.id:l.source, t=l.target.id?l.target.id:l.target;
                return (s===d.id||t===d.id)?0.95:0.08;
              });
            setTimeout(()=>{
              nodeSel.selectAll("circle").transition().duration(500).attr("opacity", 0.95);
              linkSel.transition().duration(500).attr("stroke-opacity", 0.78);
            }, 3200);
            // Ouvrir le panneau de détail persistant
            showNodeDetail(d);
          });
        // Label sous le nœud (root + poids>=5, toujours)
        ng.append("text")
          .text(d => {
            if (d.kind === "root_domain") return d.label;
            if ((d.weight||1) >= 4.5) return d.label.length>32 ? d.label.slice(0,32)+"…" : d.label;
            return "";
          })
          .attr("text-anchor","middle")
          .attr("dy", d => (d.kind==="root_domain"?-10:12) + (3 + (d.weight||1)*1.45))
          .attr("font-size", d => d.kind==="root_domain" ? "13px" : "9.5px")
          .attr("fill", d => d.kind==="root_domain" ? "#ff99a8" : "#9cd")
          .attr("pointer-events","none")
          .attr("paint-order","stroke")
          .attr("stroke","#000b")
          .attr("stroke-width",2.2);

        nodeSel = ng.merge(nodeSel);

        force.alpha(0.55).restart();
      }

      force.on("tick", ()=>{
        linkSel
          .attr("x1", d => d.source.x ?? 0)
          .attr("y1", d => d.source.y ?? 0)
          .attr("x2", d => d.target.x ?? 0)
          .attr("y2", d => d.target.y ?? 0);
        nodeSel.attr("transform", d => `translate(${d.x ?? 0},${d.y ?? 0})`);
      });

      // Exposer au WS handler
      Object.assign(window.__OSINT_GRAPH__ = {
        _restitch: restitch,
        renderSnapshot(snap){
          targetEl.textContent = "cible: " + (snap.target || "?");
          byId.clear(); edgeById.clear();
          (snap.nodes||[]).forEach(n => byId.set(n.id, Object.assign({}, n)));
          (snap.edges||[]).forEach(e => edgeById.set(e.id, Object.assign({}, e)));
          stats = Object.assign({}, snap.stats || {});
          updateCounts();
          statusEl.textContent = `snapshot ${snap.generated_at?"@"+new Date(snap.generated_at).toLocaleTimeString():""} — OK (${byId.size}/${edgeById.size})`;
          withD3(restitch);
        },
        applyDelta(delta){
          targetEl.textContent = "cible: " + (delta.target || targetEl.textContent.replace(/^cible: /,""));
          (delta.add_nodes||[]).forEach(n => { if(!byId.has(n.id)) byId.set(n.id, Object.assign({}, n)); });
          (delta.add_edges||[]).forEach(e => { if(!edgeById.has(e.id)) edgeById.set(e.id, Object.assign({}, e)); });
          if (delta.stats_update) { stats = Object.assign({}, stats, delta.stats_update); }
          updateCounts();
          statusEl.textContent = `delta @${new Date(delta.at||Date.now()).toLocaleTimeString()} · +${delta.add_nodes?.length||0}n +${delta.add_edges?.length||0}e`;
          withD3(restitch);
        },
      }, {});
    });

    return window.__OSINT_GRAPH__;
  }

  function pushNode(node) {
    liveNodes.set(node.id, node);
    ui.addNodeLive(node);
    // Hook D3.js s'il existe — merge dans window.nodes window.links avant
    // de redessiner : on utilise un coalescing RAF 60ms
    schedule_redraw();
  }

  function pushProgress(p) {
    ui.setProgress(p.total, p.done, p.eta_seconds, p.reachable, p.total_cves);
  }

  function alertHighRisk(a) {
    ui.pulseRed();
    alertsPending.push(a);
    ui.renderAlert(a);
  }

  let redrawPending = false;
  function schedule_redraw() {
    if (redrawPending) return;
    redrawPending = true;
    requestAnimationFrame(() => {
      redrawPending = false;
      if (typeof window.__NRTD_REFRESH_GRAPH__ === "function") {
        try { window.__NRTD_REFRESH_GRAPH__(
          Array.from(liveNodes.values()),
          window.links || []
        );} catch(e){}
      } else if (typeof window.renderGraph === "function") {
        try { window.renderGraph(); } catch(e){}
      } else {
        // fallback last: reload pas sympa, on laisse les éléments en liste
      }
    });
  }

  // ---------- mini UI cyberpunk ----------
  function boot_ui() {
    const host = document.createElement("div");
    host.style.cssText = "position:fixed;top:0;left:0;right:0;padding:10px 18px;z-index:2147483647;\
      background:linear-gradient(180deg, rgba(0,10,0,.92), rgba(0,10,0,.65));\
      border-bottom:1px solid #00ff6655;backdrop-filter:blur(4px);color:#cfe;\
      font-family: ui-monospace, 'JetBrains Mono', 'Fira Code', Consolas, monospace;";
    host.innerHTML = `
      <div style="display:flex;gap:18px;align-items:center;">
        <div id="nrtg-logo" style="font-weight:900;color:#00ff66;letter-spacing:1px;">
          ▍DIAPILE · LIVE
        </div>
        <div id="nrtg-status" style="padding:3px 10px;border:1px solid #00ff66aa;color:#00ff66;\
          border-radius:999px;font-size:12px;">CONNECTING…</div>
        <div id="nrtg-progress-wrap" style="flex:1;height:12px;background:#001a00;border:1px solid #005522;\
          border-radius:6px;overflow:hidden;position:relative;min-width:220px;">
          <div id="nrtg-progress-bar" style="height:100%;width:0%;\
            background:linear-gradient(90deg,#003300,#00ff66);box-shadow:0 0 10px #00ff66 inset;\
            transition:width .2s linear;"></div>
          <div id="nrtg-progress-label" style="position:absolute;inset:0;display:flex;\
            align-items:center;justify-content:center;font-size:11px;color:#adf;"></div>
        </div>
        <div id="nrtg-metrics" style="font-size:12px;opacity:.9;white-space:nowrap;">
          <span id="nrtg-done">0</span>/<span id="nrtg-total">0</span> ·
          open:<span id="nrtg-open" style="color:#ffcc00;">0</span> ·
          CVEs:<span id="nrtg-cves" style="color:#ff6699;">0</span> ·
          ETA:<span id="nrtg-eta" style="color:#00ff99;">--:--</span>
        </div>
        <button id="nrtg-close" title="Masquer la barre live"
          style="background:transparent;color:#adf;border:1px solid #335;border-radius:4px;\
          padding:3px 8px;font-size:11px;cursor:pointer;opacity:.7;">hide</button>
      </div>
      <div id="nrtg-alert-host" style="position:fixed;top:56px;right:20px;display:flex;\
        flex-direction:column;gap:10px;pointer-events:none;"></div>
    `;
    document.body.appendChild(host);
    host.querySelector("#nrtg-close").addEventListener("click", () => {
      host.style.display = "none";
    });

    // Barre pulse global pour Risk=5 — overlay
    const pulse = document.createElement("div");
    pulse.style.cssText = "position:fixed;inset:0;border:0px solid #ff1a1a;pointer-events:none;\
      z-index:2147483646;transition:box-shadow .25s ease, border-width .25s ease;";
    document.body.appendChild(pulse);

    // Animation CSS injectée une seule fois
    if (!document.getElementById("__nrtg_live_anim__")) {
      const st = document.createElement("style");
      st.id = "__nrtg_live_anim__";
      st.textContent = `
        @keyframes __nrtg_pulse_red {
          0%,100% { box-shadow: inset 0 0 0 0 rgba(255,26,26,0); border-width:0;}
          15%     { box-shadow: inset 0 0 140px 8px rgba(255,26,26,.55); border-width:6px;}
          100%    { box-shadow: inset 0 0 0 0 rgba(255,26,26,0); border-width:0;}
        }
        @keyframes __nrtg_slidein {
          from { transform: translateX(120%); opacity: 0;}
          to   { transform: translateX(0);     opacity: 1;}
        }
        .__nrtg_alert {
          animation: __nrtg_slidein .25s ease both;
          width: 340px; background: linear-gradient(135deg, #300 0%, #100 100%);
          border: 1px solid #ff1a1aaa; color: #ffe3e3;
          padding: 10px 14px; border-radius: 8px; font-size: 12px;
          box-shadow: 0 6px 30px rgba(255,30,30,.25), 0 0 0 1px #ff2a2a33 inset;
        }
        .__nrtg_alert h3 { margin:0 0 6px 0; font-size:13px; color:#ff6a6a; letter-spacing:.5px;}
        .__nrtg_alert code { background:#220; padding:1px 5px; border-radius:3px;}
        .__nrtg_alert .cve { color:#ffaa00; font-weight:bold;}
      `;
      document.head.appendChild(st);
    }

    return {
      setStatus: (label, color) => {
        const s = host.querySelector("#nrtg-status");
        s.textContent = label; s.style.color = color; s.style.borderColor = color + "aa";
      },
      setStartedAt: (ts) => {},
      setProgress: (total, done, eta, reach, cves) => {
        const frac = total > 0 ? done / total : 0;
        host.querySelector("#nrtg-progress-bar").style.width = (frac*100).toFixed(1)+"%";
        host.querySelector("#nrtg-progress-label").textContent =
          (frac*100).toFixed(0)+"%";
        host.querySelector("#nrtg-done").textContent = done;
        host.querySelector("#nrtg-total").textContent = total;
        host.querySelector("#nrtg-open").textContent = reach;
        host.querySelector("#nrtg-cves").textContent = cves;
        if (Number.isFinite(eta) && eta >= 0) {
          const s = Math.min(eta, 359999);
          const mm = Math.floor(s/60), ss = Math.floor(s%60);
          host.querySelector("#nrtg-eta").textContent =
            `${String(mm).padStart(2,'0')}:${String(ss).padStart(2,'0')}`;
        }
      },
      setTotal: (n, reach, elapsed_ms) => {
        host.querySelector("#nrtg-done").textContent = n;
        host.querySelector("#nrtg-total").textContent = n;
        host.querySelector("#nrtg-progress-bar").style.width = "100%";
        host.querySelector("#nrtg-progress-label").textContent =
          `SCANNED ${n} · OPEN ${reach} · ${(elapsed_ms/1000).toFixed(1)}s`;
        host.querySelector("#nrtg-eta").textContent = "00:00";
        host.querySelector("#nrtg-status").textContent = "FINISHED";
        host.querySelector("#nrtg-status").style.color = "#87f0ff";
        host.querySelector("#nrtg-status").style.borderColor = "#87f0ff88";
      },
      addNodeLive: (node) => {
        // No-op: D3 refresh prend en charge via liveNodes
      },
      pulseRed: () => {
        pulse.style.animation = "none";
        // trigger reflow
        void pulse.offsetWidth;
        pulse.style.animation = "__nrtg_pulse_red 2s ease 0s 1";
      },
      renderAlert: (a) => {
        const div = document.createElement("div");
        div.className = "__nrtg_alert";
        div.innerHTML = `<h3>⚠ HIGH-RISK NODE · RISK=${a.risk}</h3>
          <div><code>${a.host}:${a.port}</code></div>
          <div style="margin-top:4px;">CVE clé: <span class="cve">${a.top_cve}</span></div>
          <div style="margin-top:6px;opacity:.6;font-size:10px;">${new Date().toLocaleTimeString()}</div>`;
        host.querySelector("#nrtg-alert-host").appendChild(div);
        setTimeout(() => { div.style.transition = "opacity .4s"; div.style.opacity = "0";
          setTimeout(()=>div.remove(), 500); }, 8000);
      }
    };
  }
})();
</script>
"##;

const FALLBACK_HTML: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>DIAPILE LIVE · 127.0.0.1:24601</title></head>
<body style="background:#000a00;color:#cfe;font-family:ui-monospace,Consolas,monospace;">
<div style="padding:40px;max-width:720px;margin:0 auto;">
<pre style="color:#00ff66;">
  ▍DIAPILE — LIVE DASHBOARD (mode bootstrap)
  ══════════════════════════════════════════════════════════════
  Le fichier dashboard.html est absent du dossier de lancement.
  Mode LIVE toujours opérationnel ci-dessous (nodes en temps réel).
  Pour le graphe D3, relancez nrtg depuis un dossier contenant
  dashboard.html ou générez-le une première fois avec un petit
  scan en mode offline.
</pre>
<h3>Live nodes:</h3>
<div id="n" style="display:grid;grid-template-columns:repeat(4, 1fr);gap:8px;"></div>
<script>
const $ = id => document.getElementById(id);
const __port = window.__NRTD_LIVE_PORT__ || 24601;
const __tok  = window.__NRTD_LIVE_TOKEN__ || "";
const WS = new WebSocket(`ws://127.0.0.1:${__port}/ws?t=${encodeURIComponent(__tok)}`,"diapile-live");
WS.onmessage = ev => {
  const m = JSON.parse(ev.data);
  if (m.type === "NodeScanned") {
    const n = m.data.node;
    const row = document.createElement("div");
    row.style.cssText = "border:1px solid #00330055;padding:8px;border-radius:6px;background:#001a00;";
    row.innerHTML = `<div style="color:${n.reachable?'#00ff66':'#444'};font-weight:bold;">${n.host}:${n.port}</div>
      <div style="color:#888;font-size:11px;">svc: ${n.services[0]||''} · risk: ${n.risk}</div>`;
    $("n").prepend(row);
  }
  if (m.type === "HighRiskAlert") {
    document.body.style.boxShadow = "inset 0 0 120px #ff1a1a88";
    setTimeout(() => { document.body.style.boxShadow = ""; }, 2000);
  }
};
</script>
</div></body></html>"##;

// -----------------------------------------------------------------------
// API utilitaire : calcule ETA par lissage exponentiel
// (évite les ETA "2s puis 5min" typiques des scans avec timeout)
// -----------------------------------------------------------------------
pub fn eta_smoothed(smoothed: Option<f32>, done: usize, total: usize, start_ts: u128) -> f32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let elapsed = now.saturating_sub(start_ts) as f32 / 1000.0;
    if done == 0 || total == 0 {
        return smoothed.unwrap_or(0.0);
    }
    let frac = (done as f32).min(total as f32) / (total as f32);
    let eta = if frac > 0.0 {
        (elapsed / frac) - elapsed
    } else {
        0.0
    };
    // Lissage alpha = 0.3 vers le bas (nouveau dominant)
    match smoothed {
        None => eta.max(0.0),
        Some(prev) => (prev * 0.7 + eta * 0.3).max(0.0),
    }
}

// -----------------------------------------------------------------------
// Auto-open navigateur (multi-plateforme)
// -----------------------------------------------------------------------
/// Ouvre l'URL du dashboard dans le navigateur par défaut de l'utilisateur.
/// Windows → cmd.exe /C start "" "http://..."
/// WSL  → wslview (fallback explorer.exe via /mnt/c/Windows/System32)
/// Linux → xdg-open
/// macOS → open
pub fn open_browser(url: &str) -> Result<(), String> {
    use std::process::Command;
    let candidates: &[&[&str]] = if cfg!(windows) {
        &[&["cmd.exe", "/C", "start", "", url]]
    } else if cfg!(target_os = "macos") {
        &[&["open", url]]
    } else {
        &[
            &["wslview", url],
            &["xdg-open", url],
            &["/mnt/c/Windows/System32/cmd.exe", "/C", "start", "", url],
        ]
    };
    for args in candidates {
        let (bin, rest) = match args.split_first() {
            Some(x) => x,
            None => continue,
        };
        let status = Command::new(bin)
            .args(rest)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if let Ok(s) = status {
            if s.success() {
                return Ok(());
            }
        }
    }
    Err(String::from(
        "aucune méthode d'ouverture de navigateur disponible sur cette plateforme",
    ))
}

// -----------------------------------------------------------------------
// Tests — snapshot rejoué aux clients WS tardifs
// -----------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, risk: i32) -> GraphNode {
        GraphNode {
            id: id.to_string(),
            risk,
            ..Default::default()
        }
    }

    #[test]
    fn snapshot_dedups_nodes_by_id_keeping_latest() {
        let mut st = SnapshotState::default();
        st.record(&DashboardEvent::NodeScanned {
            node: node("a:80", 1),
        });
        st.record(&DashboardEvent::NodeScanned {
            node: node("b:443", 2),
        });
        st.record(&DashboardEvent::NodeScanned {
            node: node("a:80", 5),
        });

        assert_eq!(
            st.nodes.len(),
            2,
            "les nœuds doivent être dédupliqués par id"
        );

        let replay = st.replay();
        assert_eq!(replay.len(), 2);
        let a = replay
            .iter()
            .find(|s| s.contains("\"a:80\""))
            .expect("le nœud a:80 doit être présent dans le replay");
        assert!(
            a.contains("\"risk\":5"),
            "le dernier état doit gagner : {a}"
        );
    }

    #[test]
    fn snapshot_keeps_only_last_singleton_event() {
        let mut st = SnapshotState::default();
        st.record(&DashboardEvent::Progress {
            total: 10,
            done: 3,
            eta_seconds: 1.0,
            reachable: 2,
            total_cves: 4,
        });
        st.record(&DashboardEvent::Progress {
            total: 10,
            done: 9,
            eta_seconds: 0.5,
            reachable: 5,
            total_cves: 7,
        });

        let replay = st.replay();
        assert_eq!(
            replay.len(),
            1,
            "seul le dernier Progress doit être conservé"
        );
        assert!(replay[0].contains("\"done\":9"));
    }
}
