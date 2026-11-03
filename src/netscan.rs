//! DIAPILE — Moteur de scan réseau inspiré de nmap (réécriture Rust ORIGINALE).
//!
//! Complète `scanner.rs` (connect scan basique) avec les briques nmap
//! manquantes qui restent exécutables **sans privilèges root** :
//!   * templates de timing `-T0..-T5` (furtivité ↔ vitesse) ;
//!   * découverte d'hôtes (TCP ping sur ports courants) ;
//!   * scan UDP avec classification `open` / `closed` (via ICMP
//!     port-unreachable remonté par la pile locale) / `open|filtered` ;
//!   * sondes UDP spécifiques par protocole (DNS / NTP / SNMP / SSDP / mDNS).
//!
//! ⚠️ Aucun code ni base nmap (GPLv2) n'est repris : réimplémentation
//! indépendante des *concepts*. Usage réservé aux opérations Red Team
//! autorisées sous contrat (périmètre explicite).
#![allow(dead_code)]

use std::collections::HashSet;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use rand::seq::SliceRandom;
use rand::Rng;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::time::timeout;

// `pnet_packet` est disponible sur toutes les plateformes (contrairement à
// `pnet`, réservé à `cfg(unix)`) : on l'utilise pour les flags TCP de l'API
// publique `TcpScanMode`, exposée indépendamment du système d'exploitation.
use pnet_packet::tcp::TcpFlags;

// ─────────────────────────────────────────────────────────────────────────────
// États de port (nomenclature alignée sur nmap)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// Un service écoute et répond.
    Open,
    /// Aucun service (RST / ICMP port-unreachable).
    Closed,
    /// Aucune réponse : filtré par un pare-feu (ou hôte injoignable).
    Filtered,
    /// Indéterminé : ouvert *ou* filtré (typique du scan UDP / scans furtifs).
    OpenFiltered,
    /// Le port est joignable mais son état est indéterminé (scan ACK : RST reçu,
    /// donc aucune règle de pare-feu ne bloque la sonde — nmap `unfiltered`).
    Unfiltered,
}

impl PortState {
    /// Rendu textuel identique à nmap (`open`, `closed`, `filtered`,
    /// `open|filtered`, `unfiltered`).
    pub fn as_nmap(self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
            PortState::Unfiltered => "unfiltered",
        }
    }

    /// Un port mérite-t-il d'être remonté à l'opérateur ?
    pub fn is_interesting(self) -> bool {
        matches!(
            self,
            PortState::Open | PortState::OpenFiltered | PortState::Unfiltered
        )
    }
}

/// Raison de la classification d'un port, alignée sur les codes `reason` de nmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortReason {
    /// Réponse SYN/ACK (port ouvert, scan SYN).
    SynAck,
    /// Connexion TCP établie (scan connect).
    ConnEstablished,
    /// RST reçu (port fermé) ou connexion refusée.
    Reset,
    /// Connexion refusée (RST ou ICMP port-unreachable).
    Refused,
    /// ICMP unreachable reçu pour un port UDP.
    IcmpUnreachable,
    /// Donnée applicative reçue (port UDP ouvert).
    Response,
    /// Aucune réponse dans le délai imparti.
    NoResponse,
}

impl PortReason {
    /// Rendu textuel identique aux codes `reason` de nmap.
    pub fn as_nmap(self) -> &'static str {
        match self {
            PortReason::SynAck => "syn-ack",
            PortReason::ConnEstablished => "conn-established",
            PortReason::Reset => "reset",
            PortReason::Refused => "conn-refused",
            PortReason::IcmpUnreachable => "icmp-unreach",
            PortReason::Response => "response",
            PortReason::NoResponse => "no-response",
        }
    }
}

/// Résultat de scan pour un port donné.
#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    /// Cause de la classification (parité avec le champ `reason` de nmap).
    pub reason: PortReason,
    /// Bannière / première réponse applicative, si capturée.
    pub banner: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Templates de timing (modèle -T0..-T5 de nmap, valeurs propres)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingTemplate {
    Paranoid,
    Sneaky,
    Polite,
    Normal,
    Aggressive,
    Insane,
}

#[derive(Debug, Clone)]
pub struct TimingParams {
    /// Connexions/sondes simultanées.
    pub max_parallelism: usize,
    /// Délai max d'attente d'une réponse avant de conclure `filtered`.
    pub connect_timeout: Duration,
    /// Pause imposée entre deux sondes (furtivité).
    pub scan_delay: Duration,
    /// Nombre de tentatives avant de conclure `filtered`.
    pub retries: u32,
}

impl TimingTemplate {
    /// Convertit un niveau CLI (`--timing 0..5`). Toute valeur hors plage tombe sur `Aggressive`.
    pub fn from_u8(n: u8) -> Self {
        match n {
            0 => TimingTemplate::Paranoid,
            1 => TimingTemplate::Sneaky,
            2 => TimingTemplate::Polite,
            3 => TimingTemplate::Normal,
            5 => TimingTemplate::Insane,
            _ => TimingTemplate::Aggressive,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TimingTemplate::Paranoid => "T0 (paranoid)",
            TimingTemplate::Sneaky => "T1 (sneaky)",
            TimingTemplate::Polite => "T2 (polite)",
            TimingTemplate::Normal => "T3 (normal)",
            TimingTemplate::Aggressive => "T4 (aggressive)",
            TimingTemplate::Insane => "T5 (insane)",
        }
    }

    /// Paramètres concrets : à mesure que le niveau monte, le parallélisme
    /// augmente et le silence entre sondes diminue (comme nmap).
    pub fn params(self) -> TimingParams {
        match self {
            TimingTemplate::Paranoid => TimingParams {
                max_parallelism: 1,
                connect_timeout: Duration::from_secs(10),
                scan_delay: Duration::from_secs(5),
                retries: 3,
            },
            TimingTemplate::Sneaky => TimingParams {
                max_parallelism: 1,
                connect_timeout: Duration::from_secs(8),
                scan_delay: Duration::from_secs(1),
                retries: 3,
            },
            TimingTemplate::Polite => TimingParams {
                max_parallelism: 4,
                connect_timeout: Duration::from_secs(6),
                scan_delay: Duration::from_millis(300),
                retries: 2,
            },
            TimingTemplate::Normal => TimingParams {
                max_parallelism: 16,
                connect_timeout: Duration::from_secs(4),
                scan_delay: Duration::ZERO,
                retries: 2,
            },
            TimingTemplate::Aggressive => TimingParams {
                max_parallelism: 128,
                connect_timeout: Duration::from_secs(2),
                scan_delay: Duration::ZERO,
                retries: 1,
            },
            TimingTemplate::Insane => TimingParams {
                max_parallelism: 512,
                connect_timeout: Duration::from_secs(1),
                scan_delay: Duration::ZERO,
                retries: 0,
            },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Jeux de ports par défaut
// ─────────────────────────────────────────────────────────────────────────────

/// Ports TCP les plus fréquemment ouverts (sélection « top ports » type nmap).
pub fn top_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 161, 179, 389, 443, 445, 465, 500,
        514, 515, 548, 587, 623, 631, 636, 873, 902, 993, 995, 1080, 1194, 1433, 1521, 1701, 1723,
        1883, 2049, 2082, 2083, 2181, 2222, 2375, 2376, 3000, 3128, 3260, 3306, 3389, 3478, 4000,
        4443, 5000, 5060, 5222, 5432, 5555, 5601, 5672, 5900, 5984, 5985, 5986, 6379, 6443, 6667,
        7001, 7077, 8000, 8009, 8080, 8081, 8088, 8090, 8443, 8500, 8529, 8888, 9000, 9042, 9092,
        9200, 9300, 9418, 10000, 10250, 11211, 15672, 27017, 27018, 50000, 61616,
    ]
}

/// Ports UDP souvent porteurs de services exploitables.
pub fn default_udp_ports() -> Vec<u16> {
    vec![
        53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 500, 514, 520, 623, 1900, 4500, 5353, 11211,
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Sondes UDP spécifiques par protocole
// ─────────────────────────────────────────────────────────────────────────────

/// SNMPv1 GetRequest pour l'OID `1.3.6.1.2.1.1.1.0` (sysDescr), community `public`.
const SNMP_SYS_DESCR: &[u8] = &[
    0x30, 0x24, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x17, 0x02,
    0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06,
    0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
];

/// Construit une requête DNS minimale (enregistrement A) pour un domaine donné.
fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(32);
    p.extend_from_slice(&[0x1a, 0x2b]); // ID
    p.extend_from_slice(&[0x01, 0x00]); // flags : recursion desired
    p.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    for label in name.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0x00); // fin du QNAME
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    p
}

/// Requête client NTP (mode 3, version 3) : 48 octets, seul le premier est non nul.
fn ntp_client_request() -> Vec<u8> {
    let mut p = vec![0u8; 48];
    p[0] = 0x1b; // LI=0, VN=3, Mode=3 (client)
    p
}

/// M-SEARCH SSDP/UPnP (découverte unicast d'un device).
fn ssdp_msearch() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n".to_vec()
}

/// Charge utile UDP adaptée au port (comme `nmap-service-probes`, octets maison).
/// Retourne `None` pour les ports sans sonde connue (datagramme vide envoyé).
pub fn udp_probe_payload(port: u16) -> Option<Vec<u8>> {
    match port {
        7 => Some(b"DIAPILE\r\n".to_vec()),
        19 => Some(vec![b'a'; 1]),
        53 => Some(dns_query("example.com", 1)),
        123 => Some(ntp_client_request()),
        161 => Some(SNMP_SYS_DESCR.to_vec()),
        1900 => Some(ssdp_msearch()),
        5353 => Some(dns_query("_services._dns-sd._udp.local", 12)),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Découverte d'hôtes (TCP ping)
// ─────────────────────────────────────────────────────────────────────────────

/// Un hôte est « vivant » si au moins un des ports de ping répond — qu'il soit
/// ouvert (SYN/ACK) **ou** fermé (RST) : dans les deux cas la pile répond.
pub async fn host_is_alive(host: IpAddr, ping_ports: &[u16], t: &TimingParams) -> bool {
    for &p in ping_ports {
        let addr = SocketAddr::new(host, p);
        match timeout(t.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => return true,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => return true,
            _ => continue,
        }
    }
    false
}

/// Ping sweep sur un ensemble d'adresses ; retourne les hôtes vivants.
///
/// Ordre de préférence des sondes (fidélité décroissante) :
/// 1. **ARP** — non falsifiable sur le même segment L2 (sockets bruts) ;
/// 2. **ICMP echo** `-PE`, puis **timestamp** `-PP` et **netmask** `-PM`
///    (sockets bruts) ;
/// 3. **ACK ping** `-PA` — RST renvoyé même si les SYN entrants sont filtrés ;
/// 4. **TCP ping** — repli non privilégié (SYN/connect sur 80/443/22/445/3389) ;
/// 5. **UDP ping** `-PU` — dernier repli non privilégié (ICMP port-unreachable).
pub async fn discover_hosts(targets: &[IpAddr], t: &TimingParams) -> Vec<IpAddr> {
    let mut alive: HashSet<IpAddr> = discover_hosts_native(targets, t)
        .await
        .into_iter()
        .collect();
    let remaining: Vec<IpAddr> = targets
        .iter()
        .copied()
        .filter(|ip| !alive.contains(ip))
        .collect();
    if !remaining.is_empty() {
        alive.extend(discover_hosts_tcp_ping(&remaining, t).await);
    }
    let remaining: Vec<IpAddr> = targets
        .iter()
        .copied()
        .filter(|ip| !alive.contains(ip))
        .collect();
    if !remaining.is_empty() {
        alive.extend(discover_hosts_udp_ping(&remaining, t).await);
    }
    // On restitue l'ordre initial de la cible pour un rendu stable.
    targets
        .iter()
        .copied()
        .filter(|ip| alive.contains(ip))
        .collect()
}

/// Sondes natives ARP (même sous-réseau L2), ICMP echo/timestamp/netmask puis
/// ACK ping — `CAP_NET_RAW` requis.
#[cfg(unix)]
async fn discover_hosts_native(targets: &[IpAddr], t: &TimingParams) -> Vec<IpAddr> {
    if !raw_sockets_supported() || !raw_sockets_usable() {
        return Vec::new();
    }
    let v4: Vec<std::net::Ipv4Addr> = targets
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v) => Some(*v),
            _ => None,
        })
        .collect();
    if v4.is_empty() {
        return Vec::new();
    }
    let to = t.connect_timeout.max(Duration::from_millis(500));

    // 1. ARP — non falsifiable par le pare-feu d'hôte sur le segment local.
    let v4_arp = v4.clone();
    let arp: HashSet<std::net::Ipv4Addr> =
        tokio::task::spawn_blocking(move || raw::arp_sweep_v4(&v4_arp, to))
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();

    let mut out: Vec<IpAddr> = arp.iter().copied().map(IpAddr::V4).collect();

    // 2. ICMP echo (-PE) puis timestamp (-PP) puis netmask (-PM), uniquement
    //    sur les cibles encore muettes (chaque sonde a un coût réseau).
    let mut remaining: Vec<std::net::Ipv4Addr> =
        v4.into_iter().filter(|ip| !arp.contains(ip)).collect();
    for probe in [
        raw::IcmpProbe::Echo,
        raw::IcmpProbe::Timestamp,
        raw::IcmpProbe::Netmask,
    ] {
        if remaining.is_empty() {
            break;
        }
        let batch = remaining.clone();
        let found: HashSet<std::net::Ipv4Addr> =
            tokio::task::spawn_blocking(move || raw::icmp_probe_sweep_v4(&batch, to, probe))
                .await
                .unwrap_or_default()
                .into_iter()
                .collect();
        out.extend(found.iter().copied().map(IpAddr::V4));
        remaining.retain(|ip| !found.contains(ip));
    }

    // 3. ACK ping (-PA) : RST renvoyé même si un pare-feu filtre les SYN.
    if !remaining.is_empty() {
        let acked =
            tokio::task::spawn_blocking(move || raw::ack_ping_v4(&remaining, &[80, 443, 22], to))
                .await
                .unwrap_or_default();
        out.extend(acked.into_iter().map(IpAddr::V4));
    }
    out
}

#[cfg(not(unix))]
async fn discover_hosts_native(_targets: &[IpAddr], _t: &TimingParams) -> Vec<IpAddr> {
    Vec::new()
}

/// UDP ping (`nmap -PU`) : envoie un datagramme vers un port très probablement
/// fermé ; un ICMP « port unreachable » renvoyé par la pile locale prouve que
/// l'hôte est vivant. Sonde non privilégiée (socket UDP connecté).
async fn udp_ping_host(host: IpAddr, port: u16, t: &TimingParams) -> bool {
    let bind: SocketAddr = if host.is_ipv4() {
        SocketAddr::from(([0u8, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let Ok(sock) = UdpSocket::bind(bind).await else {
        return false;
    };
    if sock.connect(SocketAddr::new(host, port)).await.is_err() {
        return false;
    }
    // Premier datagramme : amorce le chemin ; le second voit l'éventuel
    // ICMP unreachable remonté par la pile (errno ECONNREFUSED).
    if sock.send(&[0u8]).await.is_err() {
        return false;
    }
    tokio::time::sleep(Duration::from_millis(25)).await;
    matches!(
        timeout(t.connect_timeout, sock.send(&[0u8])).await,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused
    )
}

/// Repli UDP ping (`nmap -PU`) sur les cibles encore muettes. Port volontairement
/// haut et improbable en service, comme nmap.
async fn discover_hosts_udp_ping(targets: &[IpAddr], t: &TimingParams) -> Vec<IpAddr> {
    const UDP_PING_PORT: u16 = 40125;
    let parallelism = t.max_parallelism.max(1);
    stream::iter(targets.iter().copied().map(|ip| {
        let t = t.clone();
        async move {
            if udp_ping_host(ip, UDP_PING_PORT, &t).await {
                Some(ip)
            } else {
                None
            }
        }
    }))
    .buffer_unordered(parallelism)
    .filter_map(|x| async move { x })
    .collect()
    .await
}

/// Repli non privilégié : TCP ping (SYN/connect vers des ports courants).
async fn discover_hosts_tcp_ping(targets: &[IpAddr], t: &TimingParams) -> Vec<IpAddr> {
    let ping_ports = [80u16, 443, 22, 445, 3389];
    let parallelism = t.max_parallelism.max(1);
    stream::iter(targets.iter().copied().map(|ip| {
        let ports = ping_ports;
        let t = t.clone();
        async move {
            if host_is_alive(ip, &ports, &t).await {
                Some(ip)
            } else {
                None
            }
        }
    }))
    .buffer_unordered(parallelism)
    .filter_map(|x| async move { x })
    .collect()
    .await
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan TCP connect (multi-port, parallèle, piloté par le timing)
// ─────────────────────────────────────────────────────────────────────────────

async fn grab_banner(stream: &mut TcpStream, port: u16, t: &TimingParams) -> Option<String> {
    // Pour les ports web classiques, forcer une réponse avec une requête HEAD.
    if matches!(port, 80 | 8080 | 8000 | 8081 | 8088 | 8888 | 3000 | 5000) {
        let _ = stream
            .write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: DIAPILE\r\n\r\n")
            .await;
    }
    let mut buf = vec![0u8; 512];
    match timeout(
        Duration::from_millis(800).min(t.connect_timeout),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => {
            let s = String::from_utf8_lossy(&buf[..n]).to_string();
            Some(s.chars().take(200).collect())
        }
        _ => None,
    }
}

async fn connect_one(host: IpAddr, port: u16, t: &TimingParams) -> PortResult {
    if !t.scan_delay.is_zero() {
        tokio::time::sleep(t.scan_delay).await;
    }
    let addr = SocketAddr::new(host, port);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match timeout(t.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let banner = grab_banner(&mut stream, port, t).await;
                return PortResult {
                    port,
                    state: PortState::Open,
                    reason: PortReason::ConnEstablished,
                    banner,
                };
            }
            Ok(Err(e)) => {
                let reason = if is_conn_refused(&e) {
                    PortReason::Refused
                } else {
                    PortReason::Reset
                };
                return PortResult {
                    port,
                    state: PortState::Closed,
                    reason,
                    banner: None,
                };
            }
            Err(_) => {
                // Timeout : réessayer, puis conclure « filtered ».
                if attempt > t.retries {
                    return PortResult {
                        port,
                        state: PortState::Filtered,
                        reason: PortReason::NoResponse,
                        banner: None,
                    };
                }
            }
        }
    }
}

/// Scan TCP connect sur une liste de ports.
pub async fn connect_scan(host: IpAddr, ports: &[u16], t: &TimingParams) -> Vec<PortResult> {
    let parallelism = t.max_parallelism.max(1);
    let mut results = stream::iter(ports.iter().copied().map(|port| {
        let t = t.clone();
        async move { connect_one(host, port, &t).await }
    }))
    .buffer_unordered(parallelism)
    .collect::<Vec<_>>()
    .await;
    results.sort_by_key(|r| r.port);
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan UDP (classification via ICMP port-unreachable)
// ─────────────────────────────────────────────────────────────────────────────

/// Détecte l'erreur remontée par la pile locale quand un port UDP est fermé
/// (ICMP type 3 code 3). Codes : 111 (Linux), 10054/10061 (Windows).
fn is_conn_refused(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::ConnectionRefused
        || matches!(e.raw_os_error(), Some(111) | Some(10054) | Some(10061))
}

async fn udp_one(host: IpAddr, port: u16, t: &TimingParams) -> PortResult {
    let bind_addr = if host.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(_) => {
            return PortResult {
                port,
                state: PortState::Filtered,
                reason: PortReason::NoResponse,
                banner: None,
            }
        }
    };
    if sock.connect(SocketAddr::new(host, port)).await.is_err() {
        return PortResult {
            port,
            state: PortState::Filtered,
            reason: PortReason::NoResponse,
            banner: None,
        };
    }
    if !t.scan_delay.is_zero() {
        tokio::time::sleep(t.scan_delay).await;
    }
    let payload = udp_probe_payload(port).unwrap_or_default();
    if sock.send(&payload).await.is_err() {
        return PortResult {
            port,
            state: PortState::OpenFiltered,
            reason: PortReason::NoResponse,
            banner: None,
        };
    }
    let mut buf = vec![0u8; 1024];
    match timeout(t.connect_timeout, sock.recv(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let s = String::from_utf8_lossy(&buf[..n]).to_string();
            PortResult {
                port,
                state: PortState::Open,
                reason: PortReason::Response,
                banner: Some(s.chars().take(200).collect()),
            }
        }
        Ok(Ok(_)) => PortResult {
            port,
            state: PortState::Open,
            reason: PortReason::Response,
            banner: None,
        },
        Ok(Err(e)) if is_conn_refused(&e) => PortResult {
            port,
            state: PortState::Closed,
            reason: PortReason::IcmpUnreachable,
            banner: None,
        },
        // Autre erreur IO (ex. hôte injoignable) ou timeout → indéterminé.
        _ => PortResult {
            port,
            state: PortState::OpenFiltered,
            reason: PortReason::NoResponse,
            banner: None,
        },
    }
}

/// Scan UDP sur une liste de ports.
pub async fn udp_scan(host: IpAddr, ports: &[u16], t: &TimingParams) -> Vec<PortResult> {
    let parallelism = t.max_parallelism.max(1);
    let mut results = stream::iter(ports.iter().copied().map(|port| {
        let t = t.clone();
        async move { udp_one(host, port, &t).await }
    }))
    .buffer_unordered(parallelism)
    .collect::<Vec<_>>()
    .await;
    results.sort_by_key(|r| r.port);
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Détection de version de service (modèle `-sV`) — signatures maison
// ─────────────────────────────────────────────────────────────────────────────

/// Résultat d'identification d'un service à partir d'une bannière.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMatch {
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub cpe: Option<String>,
    /// Confiance 0..=100 (spécificité du motif + cohérence avec le port).
    pub confidence: u8,
}

impl ServiceMatch {
    /// Rendu style nmap : `nginx 1.24.0` puis CPE entre crochets.
    pub fn render(&self) -> String {
        let mut s = self.service.clone();
        if let Some(p) = &self.product {
            s.push(' ');
            s.push_str(p);
        }
        if let Some(v) = &self.version {
            s.push(' ');
            s.push_str(v);
        }
        if let Some(c) = &self.cpe {
            s.push_str(" [");
            s.push_str(c);
            s.push(']');
        }
        s
    }
}

/// Signature de détection : motif regex sur la bannière + métadonnées CPE.
struct VersionSig {
    service: &'static str,
    regex: &'static str,
    default_product: Option<&'static str>,
    cpe_base: Option<&'static str>,
    confidence: u8,
    /// Groupe de capture (1-indexé) portant le numéro de version.
    version_group: Option<usize>,
    /// Groupe de capture (1-indexé) portant le nom du produit.
    product_group: Option<usize>,
}

/// Table des signatures (réimplémentation originale, aucune donnée nmap).
const VERSION_SIGS: &[VersionSig] = &[
    VersionSig {
        service: "ssh",
        regex: r"^SSH-\d+\.\d+-(\S+)",
        default_product: Some("OpenSSH"),
        cpe_base: Some("cpe:/a:openbsd:openssh"),
        confidence: 92,
        version_group: None,
        product_group: Some(1),
    },
    VersionSig {
        service: "http",
        regex: r"(?i)server:\s*nginx(?:/(\S+))?",
        default_product: Some("nginx"),
        cpe_base: Some("cpe:/a:igor_sysoev:nginx"),
        confidence: 92,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "http",
        regex: r"(?i)server:\s*apache(?:/(\S+))?",
        default_product: Some("Apache httpd"),
        cpe_base: Some("cpe:/a:apache:http_server"),
        confidence: 90,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "http",
        regex: r"(?i)server:\s*microsoft-iis(?:/(\S+))?",
        default_product: Some("Microsoft IIS"),
        cpe_base: Some("cpe:/a:microsoft:iis"),
        confidence: 90,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "http",
        regex: r"(?i)server:\s*apache-coyote(?:/(\S+))?",
        default_product: Some("Apache Tomcat"),
        cpe_base: Some("cpe:/a:apache:tomcat"),
        confidence: 82,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "http",
        regex: r"(?i)server:\s*cloudflare",
        default_product: Some("Cloudflare"),
        cpe_base: None,
        confidence: 70,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "http",
        regex: r"(?i)x-jenkins:\s*(\S+)",
        default_product: Some("Jenkins"),
        cpe_base: Some("cpe:/a:jenkins:jenkins"),
        confidence: 92,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "http",
        regex: r#"(?i)"database"\s*:\s*"ok".{0,120}"version"\s*:\s*"([\d.]+)""#,
        default_product: Some("Grafana"),
        cpe_base: Some("cpe:/a:grafana:grafana"),
        confidence: 85,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "http",
        regex: r#"(?i)"cluster_name"\s*:\s*"([^"]+)".{0,240}"number"\s*:\s*"([\d.]+)""#,
        default_product: Some("Elasticsearch"),
        cpe_base: Some("cpe:/a:elastic:elasticsearch"),
        confidence: 86,
        version_group: Some(2),
        product_group: None,
    },
    VersionSig {
        service: "http",
        regex: r#"(?i)"gitVersion"\s*:\s*"v?([\d.]+)""#,
        default_product: Some("Kubernetes"),
        cpe_base: Some("cpe:/a:kubernetes:kubernetes"),
        confidence: 88,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "docker",
        regex: r"(?i)api-version:\s*(\S+)",
        default_product: Some("Docker Engine"),
        cpe_base: Some("cpe:/a:docker:docker"),
        confidence: 80,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "http",
        regex: r"(?i)x-powered-by:\s*php(?:/(\S+))?",
        default_product: Some("PHP"),
        cpe_base: Some("cpe:/a:php:php"),
        confidence: 85,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "http",
        regex: r"(?i)x-powered-by:\s*express",
        default_product: Some("Express"),
        cpe_base: Some("cpe:/a:expressjs:express"),
        confidence: 72,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "http",
        regex: r"^HTTP/1\.[01]\s+(\d{3})",
        default_product: Some("HTTP"),
        cpe_base: None,
        confidence: 60,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "ftp",
        regex: r"(?i)^220[- ].*vsftpd\s*([\d.]*)",
        default_product: Some("vsftpd"),
        cpe_base: Some("cpe:/a:vsftpd:vsftpd"),
        confidence: 90,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "ftp",
        regex: r"(?i)^220[- ].*proftpd\s*([\d.]*)",
        default_product: Some("ProFTPD"),
        cpe_base: Some("cpe:/a:proftpd:proftpd"),
        confidence: 88,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "ftp",
        regex: r"(?i)^220[- ].*filezilla",
        default_product: Some("FileZilla Server"),
        cpe_base: Some("cpe:/a:filezilla:filezilla_server"),
        confidence: 85,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "ftp",
        regex: r"^220[- ]",
        default_product: None,
        cpe_base: None,
        confidence: 45,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "smtp",
        regex: r"(?i)^220[- ].*postfix",
        default_product: Some("Postfix"),
        cpe_base: Some("cpe:/a:wietse_venema:postfix"),
        confidence: 85,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "smtp",
        regex: r"(?i)^220[- ].*exim\s*([\d.]*)",
        default_product: Some("Exim"),
        cpe_base: Some("cpe:/a:exim:exim"),
        confidence: 85,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "smtp",
        regex: r"(?i)^220[- ].*sendmail",
        default_product: Some("Sendmail"),
        cpe_base: Some("cpe:/a:sendmail:sendmail"),
        confidence: 84,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "smtp",
        regex: r"(?i)^220[- ].*microsoft esmtp",
        default_product: Some("Microsoft ESMTP"),
        cpe_base: Some("cpe:/a:microsoft:exchange_server"),
        confidence: 84,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "smtp",
        regex: r"^220[- ]",
        default_product: None,
        cpe_base: None,
        confidence: 42,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "pop3",
        regex: r"^\+OK",
        default_product: None,
        cpe_base: None,
        confidence: 50,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "imap",
        regex: r"^\* OK",
        default_product: None,
        cpe_base: None,
        confidence: 50,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "memcached",
        regex: r"^VERSION\s+(\S+)",
        default_product: Some("Memcached"),
        cpe_base: Some("cpe:/a:memcached:memcached"),
        confidence: 92,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "redis",
        regex: r"(?i)^-ERR unknown command",
        default_product: Some("Redis"),
        cpe_base: Some("cpe:/a:redislabs:redis"),
        confidence: 85,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "redis",
        regex: r"^-(NOAUTH|DENIED|WRONGPASS)",
        default_product: Some("Redis"),
        cpe_base: Some("cpe:/a:redislabs:redis"),
        confidence: 80,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "mongodb",
        regex: r#"(?i)"maxBsonObjectSize""#,
        default_product: Some("MongoDB"),
        cpe_base: Some("cpe:/a:mongodb:mongodb"),
        confidence: 78,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "vnc",
        regex: r"(?i)^RFB\s+(\d+\.\d+)",
        default_product: Some("VNC"),
        cpe_base: Some("cpe:/a:realvnc:vnc"),
        confidence: 95,
        version_group: Some(1),
        product_group: None,
    },
    VersionSig {
        service: "rtsp",
        regex: r"(?i)^RTSP/1\.0\s+(\d{3})",
        default_product: None,
        cpe_base: None,
        confidence: 85,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "sip",
        regex: r"(?i)^SIP/2\.0\s+(\d{3})",
        default_product: None,
        cpe_base: None,
        confidence: 85,
        version_group: None,
        product_group: None,
    },
    VersionSig {
        service: "telnet",
        regex: r"(?i)login:\s*$",
        default_product: None,
        cpe_base: None,
        confidence: 40,
        version_group: None,
        product_group: None,
    },
];

lazy_static::lazy_static! {
    /// Signatures compilées une seule fois.
    static ref COMPILED_SIGS: Vec<(&'static VersionSig, regex::Regex)> = VERSION_SIGS
        .iter()
        .filter_map(|s| regex::Regex::new(s.regex).ok().map(|re| (s, re)))
        .collect();

    /// Extraction du `<title>` HTML (multi-ligne, insensible à la casse).
    static ref TITLE_RE: regex::Regex = compile_title_re();
}

/// Motif `<title>` littéral — compilation infaillible (couvert par tests).
#[allow(clippy::unwrap_used)]
fn compile_title_re() -> regex::Regex {
    regex::Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap()
}

/// Nom de service conventionnel associé à un port (`top_ports`).
pub fn port_service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        67 | 68 => "dhcp",
        69 => "tftp",
        80 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        137 | 138 => "netbios-ns",
        139 => "netbios-ssn",
        143 => "imap",
        161 | 162 => "snmp",
        179 => "bgp",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        500 => "isakmp",
        514 => "shell",
        515 => "printer",
        548 => "afpovertcp",
        587 => "submission",
        623 => "asf-rmcp",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1194 => "openvpn",
        1433 => "ms-sql-s",
        1521 => "oracle",
        1723 => "pptp",
        1883 => "mqtt",
        2049 => "nfs",
        2181 => "zookeeper",
        2375 | 2376 => "docker",
        3000 => "grafana",
        3128 => "squid",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        3478 => "stun",
        4500 => "ipsec-nat-t",
        5060 => "sip",
        5222 => "xmpp-client",
        5432 => "postgresql",
        5601 => "kibana",
        5672 => "amqp",
        5900 => "vnc",
        5984 => "couchdb",
        5985 | 5986 => "wsman",
        6379 => "redis",
        6443 => "kubernetes-api",
        6667 => "irc",
        7001 => "afs3-callback",
        8000 | 8009 | 8080 | 8081 | 8088 | 8090 | 8888 => "http-proxy",
        8443 => "https-alt",
        8500 => "consul",
        8529 => "arangodb",
        9000 => "cslistener",
        9042 => "cassandra",
        9092 => "kafka",
        9200 | 9300 => "elasticsearch",
        9418 => "git",
        10000 => "webmin",
        10250 => "kubelet",
        11211 => "memcached",
        15672 => "rabbitmq-management",
        27017 | 27018 => "mongod",
        50000 => "sap",
        61616 => "activemq",
        _ => return None,
    })
}

/// Découpe une chaîne logicielle style `OpenSSH_9.6p1` en (produit, version).
fn split_software(sw: &str) -> (String, Option<String>) {
    if let Some((prod, ver)) = sw.split_once('_') {
        if !prod.is_empty() && !ver.is_empty() {
            return (prod.to_string(), Some(ver.to_string()));
        }
    }
    if let Some((prod, ver)) = sw.split_once('-') {
        if prod
            .chars()
            .next()
            .map(|c| c.is_alphabetic())
            .unwrap_or(false)
            && ver
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        {
            return (prod.to_string(), Some(ver.to_string()));
        }
    }
    (sw.to_string(), None)
}

/// Construit un CPE 2.2 en suffixant la version si disponible.
fn cpe_for(base: &str, version: Option<&str>) -> String {
    match version {
        Some(v) if !v.is_empty() => format!("{base}:{v}"),
        _ => base.to_string(),
    }
}

/// Identifie un service à partir du port et de la bannière capturée.
/// Retourne `None` si aucun indice exploitable.
pub fn identify_service(port: u16, banner: &str) -> Option<ServiceMatch> {
    let mut best: Option<ServiceMatch> = None;

    if !banner.trim().is_empty() {
        for (sig, re) in COMPILED_SIGS.iter() {
            if let Some(c) = re.captures(banner) {
                let mut product = sig.default_product.map(|s| s.to_string());
                if let Some(g) = sig.product_group {
                    if let Some(m) = c.get(g) {
                        product = Some(m.as_str().to_string());
                    }
                }
                let version = sig
                    .version_group
                    .and_then(|g| c.get(g))
                    .map(|m| m.as_str().to_string())
                    .filter(|v| !v.is_empty());

                // Cas SSH : la bannière porte le logiciel, pas la version protocole.
                if sig.service == "ssh" {
                    if let Some(sw) = &product {
                        let (p, v) = split_software(sw);
                        let cpe = sig.cpe_base.map(|b| cpe_for(b, v.as_deref()));
                        let m = ServiceMatch {
                            service: "ssh".into(),
                            product: Some(p),
                            version: v,
                            cpe,
                            confidence: sig.confidence,
                        };
                        if best
                            .as_ref()
                            .map(|b| m.confidence > b.confidence)
                            .unwrap_or(true)
                        {
                            best = Some(m);
                        }
                        continue;
                    }
                }

                let cpe = sig.cpe_base.map(|b| cpe_for(b, version.as_deref()));
                let m = ServiceMatch {
                    service: sig.service.to_string(),
                    product,
                    version,
                    cpe,
                    confidence: sig.confidence,
                };
                if best
                    .as_ref()
                    .map(|b| m.confidence > b.confidence)
                    .unwrap_or(true)
                {
                    best = Some(m);
                }
            }
        }
    }

    // Repli : nom de service conventionnel du port, confiance faible.
    if best.is_none() {
        if let Some(name) = port_service_name(port) {
            return Some(ServiceMatch {
                service: name.to_string(),
                product: None,
                version: None,
                cpe: None,
                confidence: 25,
            });
        }
    }
    best
}

// ─────────────────────────────────────────────────────────────────────────────
// Empreinte système d'exploitation (heuristique TTL, modèle `-O` simplifié)
// ─────────────────────────────────────────────────────────────────────────────

/// Estimation du système d'exploitation à partir des signaux de la pile IP/TCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsGuess {
    pub family: &'static str,
    /// TTL initial supposé de la pile distante.
    pub initial_ttl: u8,
    /// Nombre de sauts estimé entre l'émetteur et la cible.
    pub hops: u8,
    /// Signature affinée par la fenêtre TCP / le flag DF, si connus.
    pub variant: Option<&'static str>,
    /// Fenêtre TCP observée sur un SYN/ACK (`None` si aucun port ouvert).
    pub window: Option<u16>,
    /// Flag « Don't Fragment » observé sur la réponse.
    pub df: Option<bool>,
    /// MSS annoncée par la pile (option TCP 2), si observée.
    pub mss: Option<u16>,
    /// Facteur d'échelle de fenêtre (option TCP 3), si observé.
    pub window_scale: Option<u8>,
    /// Classe de génération de l'ISN TCP, si échantillonnée.
    pub isn_class: Option<IsnClass>,
    pub confidence: u8,
}

/// Signaux bruts collectés par sondage SYN actif (modèle `-O` simplifié).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsFingerprint {
    pub ttl: Option<u8>,
    pub window: Option<u16>,
    pub df: Option<bool>,
    /// Options TCP observées sur un SYN/ACK (tests T2–T4 de nmap, simplifiés).
    pub options: Option<TcpOptionProfile>,
    /// TTL observé sur une réponse ICMP echo (test ICMP de nmap).
    pub icmp_ttl: Option<u8>,
    /// Classe de génération de l'ISN TCP (test SEQ simplifié).
    pub isn_class: Option<IsnClass>,
}

impl OsFingerprint {
    pub fn is_empty(&self) -> bool {
        self.ttl.is_none()
            && self.window.is_none()
            && self.df.is_none()
            && self.options.is_none()
            && self.icmp_ttl.is_none()
            && self.isn_class.is_none()
    }
}

/// Profil d'options TCP observé sur un SYN/ACK (test de pile, parité nmap).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpOptionProfile {
    /// Taille maximale de segment annoncée (option 2).
    pub mss: Option<u16>,
    /// Facteur d'échelle de fenêtre (option 3, RFC 1323).
    pub window_scale: Option<u8>,
    /// Option SACK permise (option 4) présente.
    pub sack_permitted: bool,
    /// Option TCP timestamps (option 8) présente.
    pub timestamps: bool,
}

/// Classe de génération de l'ISN TCP (test SEQ simplifié de nmap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsnClass {
    /// ISN identiques sur des échantillons successifs (pile embarquée/déterministe).
    Constant,
    /// ISN croissants selon un pas régulier (BSDs / UNIX anciens).
    Incremental,
    /// ISN imprévisibles (piles modernes durcies).
    Random,
}

impl IsnClass {
    /// Rendu textuel court (pour l'affichage).
    pub fn label(self) -> &'static str {
        match self {
            IsnClass::Constant => "constant",
            IsnClass::Incremental => "incremental",
            IsnClass::Random => "random",
        }
    }
}

fn family_from_initial_ttl(initial: u8) -> &'static str {
    match initial {
        32 => "Embedded / UNIX ancien",
        64 => "Linux / UNIX / Android",
        128 => "Windows",
        _ => "Équipement réseau (Cisco / Juniper / BSD)",
    }
}

/// Déduit une famille d'OS depuis le TTL seul d'une réponse (SYN/ACK ou RST).
pub fn guess_os_from_ttl(ttl: u8) -> Option<OsGuess> {
    if ttl == 0 {
        return None;
    }
    const INITIALS: [u8; 4] = [32, 64, 128, 255];
    let initial = INITIALS.iter().copied().find(|&i| i >= ttl)?;
    let hops = initial - ttl;
    // Plus il y a de sauts, moins l'inférence est fiable.
    let confidence = if hops <= 8 {
        60
    } else if hops <= 16 {
        45
    } else {
        30
    };
    Some(OsGuess {
        family: family_from_initial_ttl(initial),
        initial_ttl: initial,
        hops,
        variant: None,
        window: None,
        df: None,
        mss: None,
        window_scale: None,
        isn_class: None,
        confidence,
    })
}

/// Inférence d'OS v3 : combine TTL (TCP ou ICMP), taille de fenêtre TCP, flag
/// DF, options TCP (MSS / window scale / SACK / timestamps) et classe d'ISN.
///
/// La table de signatures reprend des valeurs publiques de `nmap-os-db`
/// (aucune donnée GPL n'est copiée : ce sont des constantes de piles).
pub fn fingerprint_os(fp: &OsFingerprint) -> Option<OsGuess> {
    // Priorité au TTL TCP ; à défaut, TTL de la réponse ICMP (test ICMP de nmap).
    let ttl = fp.ttl.or(fp.icmp_ttl)?;
    let mut guess = guess_os_from_ttl(ttl)?;
    guess.window = fp.window;
    guess.df = fp.df;
    guess.mss = fp.options.and_then(|o| o.mss);
    guess.window_scale = fp.options.and_then(|o| o.window_scale);
    guess.isn_class = fp.isn_class;

    if let Some(w) = fp.window {
        let sig = match (guess.initial_ttl, w) {
            (128, 8192) => Some("Windows 7 / Server 2008 R2"),
            (128, 64240) => Some("Windows 10 / Server 2016+"),
            (128, 65535) => Some("Windows (pile moderne)"),
            (64, 29200) => Some("Linux 4.x / 5.x"),
            (64, 5840) => Some("Linux 2.4"),
            (64, 65535) => Some("Linux 2.6 / Android"),
            (255, 4128) => Some("Cisco IOS"),
            (255, 16384) => Some("FreeBSD / macOS"),
            _ => None,
        };
        if let Some(v) = sig {
            guess.variant = Some(v);
            guess.confidence = guess.confidence.saturating_add(15).min(90);
        }
    }
    // MSS sous la valeur Ethernet standard (1460) : tunnel/VPN ou embarqué.
    if let Some(mss) = guess.mss {
        if mss < 1400 {
            guess.confidence = guess.confidence.saturating_sub(5);
        }
    }
    // Un window scale > 0 (RFC 1323) atteste une pile moderne.
    if guess.window_scale.is_some_and(|ws| ws > 0) {
        guess.confidence = guess.confidence.saturating_add(5).min(92);
    }
    if let Some(opts) = fp.options {
        if opts.timestamps && opts.sack_permitted {
            guess.confidence = guess.confidence.saturating_add(5).min(92);
        }
    }
    if fp.df == Some(true) {
        // Quasi toutes les piles modernes posent DF : signal faible mais non nul.
        guess.confidence = guess.confidence.saturating_add(5).min(90);
    }
    // TTL TCP et TTL ICMP divergents : routage asymétrique, confiance réduite.
    if let (Some(a), Some(b)) = (fp.ttl, fp.icmp_ttl) {
        if a != b {
            guess.confidence = guess.confidence.saturating_sub(10);
        }
    }
    // Classe d'ISN : imprévisible → pile durcie ; régulière → pile ancienne.
    if let Some(isn) = fp.isn_class {
        match isn {
            IsnClass::Random => {}
            IsnClass::Incremental => {
                guess.variant = guess.variant.or(Some("ISN incrémental (pile ancienne)"));
            }
            IsnClass::Constant => {
                guess.variant = guess.variant.or(Some("ISN constant (embarqué)"));
                guess.confidence = guess.confidence.saturating_sub(5);
            }
        }
    }
    Some(guess)
}

impl OsGuess {
    pub fn render(&self) -> String {
        let mut detail = format!("TTL initial {}", self.initial_ttl);
        if let Some(w) = self.window {
            detail.push_str(&format!(", fenêtre {w}"));
        }
        if let Some(mss) = self.mss {
            detail.push_str(&format!(", MSS {mss}"));
        }
        if let Some(ws) = self.window_scale {
            detail.push_str(&format!(", scale {ws}"));
        }
        if let Some(isn) = self.isn_class {
            detail.push_str(&format!(", ISN {}", isn.label()));
        }
        if self.df == Some(true) {
            detail.push_str(", DF");
        }
        let label = match self.variant {
            Some(v) => format!("{} ({v})", self.family),
            None => self.family.to_string(),
        };
        format!(
            "{label} — {detail}, {} saut(s), confiance {}%",
            self.hops, self.confidence
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Évasion réseau (fragmentation, leurres, usurpation, ordonnancement)
// ─────────────────────────────────────────────────────────────────────────────

/// En-têtes IPv4 + TCP : surcoût incompressible pour le calcul de fragmentation.
pub const IPV4_TCP_OVERHEAD: usize = 40;

/// Options d'évasion, activables via `--evasion <spec>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvasionOptions {
    /// Fragmente les sondes (atténue certains IDS/IPS).
    pub fragment: bool,
    /// MTU utilisé pour la fragmentation.
    pub mtu: Option<u16>,
    /// Nombre de leurres (adresses sources factices) insérés avant la sonde.
    pub decoys: usize,
    /// Usurpe l'adresse source des sondes (exige `CAP_NET_RAW`).
    pub spoof_source: Option<IpAddr>,
    /// Randomise l'ordre d'émission des ports.
    pub randomize_order: bool,
    /// Force un port source fixe.
    pub source_port: Option<u16>,
}

impl EvasionOptions {
    /// Analyse une spécification `fragment,mtu=576,decoys=8,spoof=10.0.0.9,randomize`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut o = EvasionOptions::default();
        for raw in spec.split(',') {
            let tok = raw.trim();
            if tok.is_empty() {
                continue;
            }
            let (key, val) = match tok.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim())),
                None => (tok, None),
            };
            match key {
                "fragment" | "frag" => o.fragment = true,
                "randomize" | "rand" => o.randomize_order = true,
                "decoys" | "decoy" => {
                    let v = val.ok_or_else(|| "decoys=<n> requiert une valeur".to_string())?;
                    let n: usize = v
                        .parse()
                        .map_err(|_| "decoys : entier attendu".to_string())?;
                    if n > 256 {
                        return Err("decoys : maximum 256".into());
                    }
                    o.decoys = n;
                }
                "mtu" => {
                    let v = val.ok_or_else(|| "mtu=<n> requiert une valeur".to_string())?;
                    let n: u16 = v.parse().map_err(|_| "mtu : entier attendu".to_string())?;
                    if !(68..=9000).contains(&n) {
                        return Err("mtu hors plage (68..=9000)".into());
                    }
                    o.mtu = Some(n);
                    o.fragment = true;
                }
                "spoof" | "source" => {
                    let v = val.ok_or_else(|| "spoof=<ip> requiert une valeur".to_string())?;
                    let ip: IpAddr = v
                        .parse()
                        .map_err(|_| "spoof : adresse IP invalide".to_string())?;
                    o.spoof_source = Some(ip);
                }
                "source-port" | "sport" => {
                    let v = val.ok_or_else(|| "source-port=<n> requiert une valeur".to_string())?;
                    let n: u16 = v
                        .parse()
                        .map_err(|_| "source-port : entier attendu".to_string())?;
                    o.source_port = Some(n);
                }
                other => return Err(format!("option d'évasion inconnue : {other}")),
            }
        }
        Ok(o)
    }

    pub fn is_enabled(&self) -> bool {
        self.fragment
            || self.decoys > 0
            || self.spoof_source.is_some()
            || self.randomize_order
            || self.source_port.is_some()
    }

    /// MTU effectif retenu pour la fragmentation.
    pub fn effective_mtu(&self) -> u16 {
        self.mtu.unwrap_or(576)
    }

    /// Taille de la charge utile IP par fragment (multiple de 8 octets).
    ///
    /// * `fragment` seul ⇒ **8 octets/fragment** (comportement `nmap -f`) ;
    /// * `mtu=N` ⇒ `N - 40` aligné sur 8 (vraie fragmentation MTU).
    pub fn fragment_chunk(&self) -> usize {
        match self.mtu {
            None => 8,
            Some(m) => {
                let mut c = (m as usize).saturating_sub(IPV4_TCP_OVERHEAD);
                c -= c % 8;
                c.max(8)
            }
        }
    }

    /// L'évasion par leurres/usurpation/fragmentation exige des paquets bruts.
    pub fn requires_raw_sockets(&self) -> bool {
        self.fragment || self.decoys > 0 || self.spoof_source.is_some()
    }

    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.fragment {
            match self.mtu {
                Some(m) => parts.push(format!("fragmentation (MTU {m})")),
                None => parts.push(format!(
                    "fragmentation ({} octets/fragment, style nmap -f)",
                    self.fragment_chunk()
                )),
            }
        }
        if self.decoys > 0 {
            parts.push(format!("{} leurre(s)", self.decoys));
        }
        if let Some(ip) = self.spoof_source {
            parts.push(format!("usurpation source {ip}"));
        }
        if self.randomize_order {
            parts.push("ordre aléatoire".into());
        }
        if let Some(p) = self.source_port {
            parts.push(format!("port source {p}"));
        }
        if parts.is_empty() {
            "aucune".to_string()
        } else {
            parts.join(" · ")
        }
    }
}

/// Découpe une charge utile en fragments respectant l'alignement sur 8 octets
/// imposé aux fragments IPv4 non finaux.
pub fn fragment_payload(payload: &[u8], mtu: u16) -> Vec<Vec<u8>> {
    let mtu = mtu as usize;
    if mtu <= IPV4_TCP_OVERHEAD {
        return vec![payload.to_vec()];
    }
    let mut chunk = mtu - IPV4_TCP_OVERHEAD;
    chunk -= chunk % 8;
    if chunk == 0 || payload.len() <= chunk {
        return vec![payload.to_vec()];
    }
    payload.chunks(chunk).map(|c| c.to_vec()).collect()
}

/// Génère `count` adresses de leurres dans des plages privées (RFC 1918).
pub fn decoy_addresses(count: usize, target: IpAddr) -> Vec<IpAddr> {
    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(count);
    match target {
        IpAddr::V4(_) => {
            for _ in 0..count {
                let a = rng.gen_range(0..3);
                let ip = match a {
                    0 => std::net::Ipv4Addr::new(10, rng.gen(), rng.gen(), rng.gen_range(1..=254)),
                    1 => std::net::Ipv4Addr::new(
                        172,
                        rng.gen_range(16..=31),
                        rng.gen(),
                        rng.gen_range(1..=254),
                    ),
                    _ => std::net::Ipv4Addr::new(192, 168, rng.gen(), rng.gen_range(1..=254)),
                };
                out.push(IpAddr::V4(ip));
            }
        }
        // Pas de leurres IPv6 : la génération aléatoire serait indiscernable du bruit.
        IpAddr::V6(_) => {}
    }
    out
}

/// Mélange l'ordre des ports (neutralise les signatures de balayage séquentiel).
pub fn shuffle_ports(ports: &[u16]) -> Vec<u16> {
    let mut v = ports.to_vec();
    v.shuffle(&mut rand::thread_rng());
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// Moteur de scripts à catégories (modèle NSE simplifié)
// ─────────────────────────────────────────────────────────────────────────────

/// Catégories de scripts, alignées sur la nomenclature NSE de nmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptCategory {
    Default,
    Safe,
    Discovery,
    Version,
    Auth,
    Brute,
    Intrusive,
    Vuln,
    Exploit,
    Dos,
    Fuzzer,
    Malware,
    External,
}

impl ScriptCategory {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "default" => ScriptCategory::Default,
            "safe" => ScriptCategory::Safe,
            "discovery" => ScriptCategory::Discovery,
            "version" => ScriptCategory::Version,
            "auth" => ScriptCategory::Auth,
            "brute" => ScriptCategory::Brute,
            "intrusive" => ScriptCategory::Intrusive,
            "vuln" => ScriptCategory::Vuln,
            "exploit" => ScriptCategory::Exploit,
            "dos" => ScriptCategory::Dos,
            "fuzzer" => ScriptCategory::Fuzzer,
            "malware" => ScriptCategory::Malware,
            "external" => ScriptCategory::External,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            ScriptCategory::Default => "default",
            ScriptCategory::Safe => "safe",
            ScriptCategory::Discovery => "discovery",
            ScriptCategory::Version => "version",
            ScriptCategory::Auth => "auth",
            ScriptCategory::Brute => "brute",
            ScriptCategory::Intrusive => "intrusive",
            ScriptCategory::Vuln => "vuln",
            ScriptCategory::Exploit => "exploit",
            ScriptCategory::Dos => "dos",
            ScriptCategory::Fuzzer => "fuzzer",
            ScriptCategory::Malware => "malware",
            ScriptCategory::External => "external",
        }
    }

    /// Une catégorie « agressive » modifie l'état de la cible ou la sollicite
    /// lourdement : à n'activer qu'avec accord explicite du périmètre.
    pub fn is_aggressive(self) -> bool {
        matches!(
            self,
            ScriptCategory::Intrusive
                | ScriptCategory::Vuln
                | ScriptCategory::Exploit
                | ScriptCategory::Dos
                | ScriptCategory::Fuzzer
                | ScriptCategory::Brute
                | ScriptCategory::Malware
        )
    }
}

/// Description d'un script disponible dans le registre.
pub struct ScriptSpec {
    pub name: &'static str,
    pub categories: &'static [ScriptCategory],
    pub description: &'static str,
    /// Ports sur lesquels le script est pertinent (vide = tous les ports ouverts).
    pub ports: &'static [u16],
}

/// Registre des scripts embarqués.
pub static BUILTIN_SCRIPTS: &[ScriptSpec] = &[
    ScriptSpec {
        name: "banner",
        categories: &[
            ScriptCategory::Default,
            ScriptCategory::Safe,
            ScriptCategory::Discovery,
        ],
        description: "Lit la bannière brute du service.",
        ports: &[],
    },
    ScriptSpec {
        name: "http-title",
        categories: &[
            ScriptCategory::Default,
            ScriptCategory::Safe,
            ScriptCategory::Discovery,
        ],
        description: "Récupère le <title> d'une page HTTP.",
        ports: &[80, 3000, 5000, 8000, 8080, 8081, 8088, 8888],
    },
    ScriptSpec {
        name: "http-headers",
        categories: &[ScriptCategory::Safe, ScriptCategory::Discovery],
        description: "Extrait les en-têtes serveur (Server, X-Powered-By, …).",
        ports: &[80, 3000, 5000, 8000, 8080, 8081, 8088, 8888],
    },
    ScriptSpec {
        name: "ssh-hostkey",
        categories: &[
            ScriptCategory::Safe,
            ScriptCategory::Discovery,
            ScriptCategory::Version,
        ],
        description: "Bannière SSH + produit/version/CPE.",
        ports: &[22, 2222],
    },
    ScriptSpec {
        name: "ftp-anon",
        categories: &[ScriptCategory::Auth, ScriptCategory::Intrusive],
        description: "Teste l'accès FTP anonyme (USER anonymous).",
        ports: &[21, 2121],
    },
    ScriptSpec {
        name: "redis-info",
        categories: &[ScriptCategory::Safe, ScriptCategory::Discovery],
        description: "Interroge INFO server (version, état d'authentification).",
        ports: &[6379],
    },
    ScriptSpec {
        name: "memcached-stats",
        categories: &[ScriptCategory::Safe, ScriptCategory::Discovery],
        description: "Interroge `stats` (version).",
        ports: &[11211],
    },
];

/// Registre complet des scripts embarqués.
pub fn script_registry() -> &'static [ScriptSpec] {
    BUILTIN_SCRIPTS
}

/// Sélectionne les scripts via une spécification `safe,discovery` (catégories)
/// ou `banner,http-title` (noms). Vide → catégorie `default`.
pub fn select_scripts(spec: &str) -> Vec<&'static ScriptSpec> {
    let tokens: Vec<String> = spec
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if tokens.is_empty() {
        return BUILTIN_SCRIPTS
            .iter()
            .filter(|s| s.categories.contains(&ScriptCategory::Default))
            .collect();
    }
    let cats: Vec<ScriptCategory> = tokens
        .iter()
        .filter_map(|t| ScriptCategory::parse(t))
        .collect();
    let names: Vec<&String> = tokens
        .iter()
        .filter(|t| ScriptCategory::parse(t).is_none())
        .collect();
    BUILTIN_SCRIPTS
        .iter()
        .filter(|s| {
            s.categories.iter().any(|c| cats.contains(c))
                || names.iter().any(|n| s.name == n.as_str())
        })
        .collect()
}

/// Constat produit par un script sur un port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptFinding {
    pub script: String,
    pub port: u16,
    pub output: String,
}

/// Connexion TCP, écriture optionnelle d'une sonde, lecture d'une réponse.
async fn tcp_probe(
    host: IpAddr,
    port: u16,
    send: Option<&[u8]>,
    read_timeout: Duration,
) -> Option<String> {
    let mut stream = timeout(
        read_timeout,
        TcpStream::connect(SocketAddr::new(host, port)),
    )
    .await
    .ok()?
    .ok()?;
    if let Some(payload) = send {
        let _ = timeout(read_timeout, stream.write_all(payload)).await;
    }
    let mut buf = vec![0u8; 2048];
    match timeout(read_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(String::from_utf8_lossy(&buf[..n]).to_string()),
        _ => None,
    }
}

/// Test d'accès FTP anonyme. Aucun identifiant réel n'est utilisé ni journalisé.
async fn ftp_anon_probe(host: IpAddr, port: u16, rt: Duration) -> Option<String> {
    let mut stream = timeout(rt, TcpStream::connect(SocketAddr::new(host, port)))
        .await
        .ok()?
        .ok()?;
    let mut buf = vec![0u8; 512];

    let n = timeout(rt, stream.read(&mut buf)).await.ok()?.ok()?;
    let greet = String::from_utf8_lossy(&buf[..n]).to_string();
    if !greet.starts_with("220") {
        let first = greet.lines().next().unwrap_or("").trim().to_string();
        return Some(format!("bannière non-FTP : {first}"));
    }

    let _ = timeout(rt, stream.write_all(b"USER anonymous\r\n")).await;
    let n2 = timeout(rt, stream.read(&mut buf)).await.ok()?.ok()?;
    let resp = String::from_utf8_lossy(&buf[..n2]).to_string();
    let code = resp.get(0..3).unwrap_or("").to_string();

    Some(match code.as_str() {
        "331" => "login anonyme accepté (mot de passe demandé)".to_string(),
        "230" => "login anonyme accepté sans mot de passe".to_string(),
        "" => "réponse absente".to_string(),
        other => format!("login anonyme refusé ({other})"),
    })
}

/// Exécute un script identifié par son nom sur un port donné.
async fn execute_script(name: &str, host: IpAddr, port: u16, t: &TimingParams) -> Option<String> {
    let rt = t.connect_timeout.min(Duration::from_secs(3));
    match name {
        "banner" => {
            let b = tcp_probe(host, port, None, rt).await?;
            let one = b.replace(['\n', '\r'], " ").trim().to_string();
            if one.is_empty() {
                None
            } else {
                Some(one.chars().take(160).collect())
            }
        }
        "http-title" => {
            let b = tcp_probe(
                host,
                port,
                Some(b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: DIAPILE\r\n\r\n"),
                rt,
            )
            .await?;
            TITLE_RE
                .captures(&b)
                .map(|c| c[1].split_whitespace().collect::<Vec<_>>().join(" "))
        }
        "http-headers" => {
            let b = tcp_probe(
                host,
                port,
                Some(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
                rt,
            )
            .await?;
            let keep: Vec<String> = b
                .lines()
                .filter(|l| {
                    let ll = l.to_ascii_lowercase();
                    ll.starts_with("server:")
                        || ll.starts_with("x-powered-by:")
                        || ll.starts_with("content-type:")
                        || ll.starts_with("x-jenkins:")
                        || ll.starts_with("api-version:")
                })
                .map(|l| l.trim().to_string())
                .collect();
            if keep.is_empty() {
                None
            } else {
                Some(keep.join(" | "))
            }
        }
        "ssh-hostkey" => {
            let b = tcp_probe(host, port, None, rt).await?;
            identify_service(port, &b).map(|m| m.render())
        }
        "ftp-anon" => ftp_anon_probe(host, port, rt).await,
        "redis-info" => {
            let b = tcp_probe(host, port, Some(b"INFO server\r\n"), rt).await?;
            let ver = b
                .lines()
                .find_map(|l| l.strip_prefix("redis_version:"))
                .map(|v| v.trim().to_string());
            Some(match ver {
                Some(v) => format!("redis_version={v}"),
                None if b.contains("NOAUTH") => "authentification requise (NOAUTH)".to_string(),
                None if b.contains("-ERR") => {
                    format!("réponse : {}", b.lines().next().unwrap_or("").trim())
                }
                None => "INFO sans version exploitable".to_string(),
            })
        }
        "memcached-stats" => {
            let b = tcp_probe(host, port, Some(b"stats\r\n"), rt).await?;
            match b
                .lines()
                .find_map(|l| l.strip_prefix("STAT version "))
                .map(|v| v.trim().to_string())
            {
                Some(v) => Some(format!("version={v}")),
                None => Some("stats sans version".into()),
            }
        }
        _ => None,
    }
}

/// Exécute les scripts sélectionnés sur les ports ouverts détectés.
pub async fn run_scripts(
    host: IpAddr,
    open_ports: &[PortResult],
    scripts: &[&'static ScriptSpec],
    t: &TimingParams,
) -> Vec<ScriptFinding> {
    let mut jobs = Vec::new();
    for s in scripts {
        for pr in open_ports {
            if !pr.state.is_interesting() {
                continue;
            }
            if !s.ports.is_empty() && !s.ports.contains(&pr.port) {
                continue;
            }
            jobs.push((*s, pr.port));
        }
    }
    let parallelism = t.max_parallelism.max(1);
    let mut out: Vec<ScriptFinding> = stream::iter(jobs.into_iter().map(|(s, port)| {
        let t = t.clone();
        async move {
            execute_script(s.name, host, port, &t)
                .await
                .map(|output| ScriptFinding {
                    script: s.name.to_string(),
                    port,
                    output,
                })
        }
    }))
    .buffer_unordered(parallelism)
    .filter_map(|x| async move { x })
    .collect()
    .await;
    out.sort_by_key(|f| (f.port, f.script.clone()));
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Sockets bruts (SYN scan, traceroute, empreinte TTL) — WSL/Linux uniquement
// ─────────────────────────────────────────────────────────────────────────────

/// Un saut de traceroute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceHop {
    pub ttl: u8,
    pub addr: Option<IpAddr>,
    pub rtt_ms: Option<u64>,
    /// La destination finale a été atteinte à ce saut.
    pub reached: bool,
}

impl TraceHop {
    pub fn render(&self) -> String {
        match (&self.addr, self.rtt_ms) {
            (Some(a), Some(r)) => format!("{a}  {r} ms"),
            (Some(a), None) => format!("{a}"),
            (None, _) => "* * *".to_string(),
        }
    }
}

/// Sortie d'un scan SYN brut : états de port + signaux d'empreinte observés
/// sur les réponses (TTL, fenêtre TCP, flag DF).
#[derive(Debug, Clone, Default)]
pub struct SynScanOutcome {
    pub results: Vec<PortResult>,
    pub observed_ttl: Option<u8>,
    /// Fenêtre TCP lue sur un SYN/ACK (port ouvert) — base de l'inférence d'OS v2.
    pub observed_window: Option<u16>,
    /// Flag « Don't Fragment » observé sur la réponse.
    pub observed_df: Option<bool>,
    /// Options TCP lues sur un SYN/ACK (MSS, window scale, SACK, timestamps).
    pub observed_options: Option<TcpOptionProfile>,
}

/// Technique de scan TCP par paquets bruts — parité nmap `-sS/-sF/-sN/-sX/-sA/-sM/-sW`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpScanMode {
    /// SYN (half-open) : SYN/ACK ⇒ ouvert, RST ⇒ fermé.
    Syn,
    /// FIN furtif : RST ⇒ fermé, silence ⇒ ouvert|filtré.
    Fin,
    /// NULL furtif (aucun flag).
    Null,
    /// XMAS furtif (FIN+PUSH+URG).
    Xmas,
    /// ACK : cartographie du pare-feu — RST ⇒ unfiltered, silence ⇒ filtered.
    Ack,
    /// Maimon (FIN+ACK) : RST ⇒ fermé, silence ⇒ ouvert|filtré.
    Maimon,
    /// Window : ACK dont la fenêtre du RST distingue ouvert/fermé.
    Window,
}

impl TcpScanMode {
    /// Flags TCP émis dans la sonde.
    pub fn probe_flags(self) -> u8 {
        match self {
            TcpScanMode::Syn => TcpFlags::SYN,
            TcpScanMode::Fin => TcpFlags::FIN,
            TcpScanMode::Null => 0,
            TcpScanMode::Xmas => TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
            TcpScanMode::Ack => TcpFlags::ACK,
            TcpScanMode::Maimon => TcpFlags::FIN | TcpFlags::ACK,
            TcpScanMode::Window => TcpFlags::ACK,
        }
    }

    /// Nom court de la technique (pour l'affichage).
    pub fn label(self) -> &'static str {
        match self {
            TcpScanMode::Syn => "syn",
            TcpScanMode::Fin => "fin",
            TcpScanMode::Null => "null",
            TcpScanMode::Xmas => "xmas",
            TcpScanMode::Ack => "ack",
            TcpScanMode::Maimon => "maimon",
            TcpScanMode::Window => "window",
        }
    }

    /// Résout une technique depuis la CLI (`--scan-type`).
    pub fn from_cli(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "syn" => Some(TcpScanMode::Syn),
            "fin" => Some(TcpScanMode::Fin),
            "null" => Some(TcpScanMode::Null),
            "xmas" | "christmas" => Some(TcpScanMode::Xmas),
            "ack" => Some(TcpScanMode::Ack),
            "maimon" => Some(TcpScanMode::Maimon),
            "window" => Some(TcpScanMode::Window),
            _ => None,
        }
    }
}

/// Les sockets bruts nécessitent `CAP_NET_RAW` (root) et un noyau Linux.
pub fn raw_sockets_supported() -> bool {
    cfg!(unix)
}

/// Teste réellement l'ouverture d'un socket brut TCP (donc la présence de
/// `CAP_NET_RAW`/root). `false` sur plateforme non-kernel-Linux ou sans privilège.
#[cfg(unix)]
pub fn raw_sockets_usable() -> bool {
    raw::raw_probe_available()
}

#[cfg(not(unix))]
pub fn raw_sockets_usable() -> bool {
    false
}

#[cfg(unix)]
mod raw {
    //! Implémentation bas niveau : construction manuelle des en-têtes IP/TCP/UDP.
    use super::{
        EvasionOptions, IsnClass, PortReason, PortResult, PortState, SynScanOutcome,
        TcpOptionProfile, TcpScanMode, TimingParams, TraceHop,
    };
    use pnet::datalink::{self, Config};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
    use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOptionNumbers, TcpPacket};
    use pnet::packet::udp::MutableUdpPacket;
    use pnet::packet::MutablePacket;
    use pnet::transport::{self, TransportChannelType};
    use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
    use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet_packet::icmp::{IcmpPacket, IcmpTypes};
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::Packet;
    use rand::Rng;
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr, UdpSocket};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// Tente d'ouvrir un socket brut TCP pour sonder la capacité réelle
    /// (`CAP_NET_RAW`/root). Ne renvoie aucun paquet.
    pub fn raw_probe_available() -> bool {
        transport::transport_channel(
            128,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
        )
        .is_ok()
    }

    /// Somme de contrôle de l'en-tête IPv4 (le champ checksum doit être nul).
    fn ipv4_header_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < header.len() {
            sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
            i += 2;
        }
        if i < header.len() {
            sum += (header[i] as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Détermine l'adresse source locale réellement utilisée vers `dst`
    /// (via une socket UDP « connectée » qui n'émet aucun paquet).
    fn local_source_ipv4(dst: Ipv4Addr) -> Option<Ipv4Addr> {
        let s = UdpSocket::bind("0.0.0.0:0").ok()?;
        s.connect((dst, 9)).ok()?;
        match s.local_addr().ok()?.ip() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        }
    }

    /// Construit un paquet IPv4/TCP complet prêt à être envoyé.
    ///
    /// `tcp_flags` permet de couvrir toutes les techniques de scan furtif
    /// (SYN, FIN, NULL, XMAS, ACK, Maimon). `df` contrôle le bit IP *Don't
    /// Fragment* (signal d'empreinte d'OS).
    // Tampon de taille exacte (40 octets) : `MutableIpv4Packet::new` ne peut
    // échouer que si le tampon est trop court — impossible ici.
    #[allow(clippy::unwrap_used)]
    fn build_ipv4_tcp(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        seq: u32,
        ttl: u8,
        ident: u16,
        tcp_flags: u8,
        df: bool,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 40];
        {
            let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(40);
            ip.set_identification(ident);
            ip.set_flags(if df { Ipv4Flags::DontFragment } else { 0 });
            ip.set_fragment_offset(0);
            ip.set_ttl(ttl);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(src);
            ip.set_destination(dst);
            ip.set_checksum(0);
            {
                let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
                tcp.set_source(sport);
                tcp.set_destination(dport);
                tcp.set_sequence(seq);
                tcp.set_acknowledgement(0);
                tcp.set_data_offset(5);
                tcp.set_flags(tcp_flags);
                tcp.set_window(64240);
                tcp.set_urgent_ptr(0);
                tcp.set_checksum(0);
                let imm = tcp.to_immutable();
                let csum = pnet_packet::tcp::ipv4_checksum(&imm, &src, &dst);
                tcp.set_checksum(csum);
            }
            let hc = ipv4_header_checksum(ip.packet());
            ip.set_checksum(hc);
        }
        buf
    }

    /// Extrait le profil d'options TCP d'un segment (typiquement un SYN/ACK) :
    /// MSS, facteur d'échelle de fenêtre, SACK permise, TCP timestamps.
    fn parse_tcp_options(tcp: &TcpPacket) -> TcpOptionProfile {
        let mut profile = TcpOptionProfile::default();
        for opt in tcp.get_options_iter() {
            match opt.get_number() {
                TcpOptionNumbers::MSS => {
                    let d = opt.payload();
                    if d.len() >= 2 {
                        profile.mss = Some(u16::from_be_bytes([d[0], d[1]]));
                    }
                }
                TcpOptionNumbers::WSCALE => {
                    if let Some(&ws) = opt.payload().first() {
                        profile.window_scale = Some(ws);
                    }
                }
                TcpOptionNumbers::SACK_PERMITTED => profile.sack_permitted = true,
                TcpOptionNumbers::TIMESTAMPS => profile.timestamps = true,
                _ => {}
            }
        }
        profile
    }

    /// Construit un paquet IPv4/UDP complet (sonde de traceroute).
    // Tampon de taille exacte (28 octets) : `MutableIpv4Packet::new` ne peut
    // échouer que si le tampon est trop court — impossible ici.
    #[allow(clippy::unwrap_used)]
    fn build_ipv4_udp(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        ttl: u8,
        ident: u16,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 28];
        {
            let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(28);
            ip.set_identification(ident);
            ip.set_flags(Ipv4Flags::DontFragment);
            ip.set_fragment_offset(0);
            ip.set_ttl(ttl);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip.set_source(src);
            ip.set_destination(dst);
            ip.set_checksum(0);
            {
                let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
                udp.set_source(sport);
                udp.set_destination(dport);
                udp.set_length(8);
                udp.set_checksum(0);
                let imm = udp.to_immutable();
                let csum = pnet_packet::udp::ipv4_checksum(&imm, &src, &dst);
                udp.set_checksum(csum);
            }
            let hc = ipv4_header_checksum(ip.packet());
            ip.set_checksum(hc);
        }
        buf
    }

    /// Nature de la sonde ICMP utilisée pour la découverte d'hôtes — parité
    /// nmap `-PE` (echo) / `-PP` (timestamp) / `-PM` (netmask).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum IcmpProbe {
        /// Echo request (type 8) → echo reply (type 0) — `nmap -PE`.
        Echo,
        /// Timestamp request (type 13) → timestamp reply (type 14) — `nmap -PP`.
        Timestamp,
        /// Address-mask request (type 17) → mask reply (type 18) — `nmap -PM`.
        Netmask,
    }

    impl IcmpProbe {
        /// Type ICMP de la requête émise.
        fn request_type(self) -> u8 {
            match self {
                IcmpProbe::Echo => IcmpTypes::EchoRequest.0,
                IcmpProbe::Timestamp => 13,
                IcmpProbe::Netmask => 17,
            }
        }

        /// Type ICMP de la réponse attendue.
        fn reply_type(self) -> u8 {
            match self {
                IcmpProbe::Echo => IcmpTypes::EchoReply.0,
                IcmpProbe::Timestamp => 14,
                IcmpProbe::Netmask => 18,
            }
        }

        /// Longueur totale du paquet IP (20 d'en-tête + message ICMP complet).
        fn total_len(self) -> usize {
            match self {
                // 8 (hdr) + 8 données.
                IcmpProbe::Echo => 36,
                // 8 (hdr) + 12 (orig/recv/xmit timestamps).
                IcmpProbe::Timestamp => 40,
                // 8 (hdr) + 4 (masque de demande, nul).
                IcmpProbe::Netmask => 32,
            }
        }
    }

    /// Millisecondes écoulées depuis minuit UTC (champ `originate time` de
    /// l'ICMP timestamp, RFC 792). En cas d'horloge antérieure à l'epoch, 0.
    fn utc_millis_since_midnight() -> u32 {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        (since_epoch.as_millis() % 86_400_000) as u32
    }

    /// Construit un paquet IPv4/ICMP générique (echo, timestamp ou netmask).
    ///
    /// L'identifiant et le numéro de séquence occupent les octets 4..8 du
    /// message ICMP ; la suite dépend du type (données, timestamps, masque).
    // Tampon de taille exacte : `MutableIpv4Packet::new` ne peut échouer que
    // si le tampon est trop court — impossible ici.
    #[allow(clippy::unwrap_used)]
    fn build_ipv4_icmp_probe(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ident: u16,
        seq: u16,
        ttl: u8,
        probe: IcmpProbe,
    ) -> Vec<u8> {
        let total = probe.total_len();
        let mut buf = vec![0u8; total];
        {
            let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(total as u16);
            ip.set_identification(seq);
            ip.set_flags(0);
            ip.set_fragment_offset(0);
            ip.set_ttl(ttl);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip.set_source(src);
            ip.set_destination(dst);
            ip.set_checksum(0);
            {
                let payload = ip.payload_mut();
                payload[0] = probe.request_type();
                payload[1] = 0;
                payload[2..4].copy_from_slice(&[0, 0]);
                payload[4..6].copy_from_slice(&ident.to_be_bytes());
                payload[6..8].copy_from_slice(&seq.to_be_bytes());
                match probe {
                    IcmpProbe::Echo => payload[8..16].copy_from_slice(b"DIAPILE!"),
                    IcmpProbe::Timestamp => {
                        let ms = utc_millis_since_midnight();
                        payload[8..12].copy_from_slice(&ms.to_be_bytes());
                    }
                    IcmpProbe::Netmask => {} // masque de demande = 0
                }
                let csum = match IcmpPacket::new(payload) {
                    Some(p) => pnet_packet::icmp::checksum(&p),
                    None => 0,
                };
                payload[2] = (csum >> 8) as u8;
                payload[3] = (csum & 0xff) as u8;
            }
            let hc = ipv4_header_checksum(ip.packet());
            ip.set_checksum(hc);
        }
        buf
    }

    /// Construit un paquet IPv4/ICMP echo request (type 8, code 0).
    fn build_ipv4_icmp_echo(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ident: u16,
        seq: u16,
        ttl: u8,
    ) -> Vec<u8> {
        build_ipv4_icmp_probe(src, dst, ident, seq, ttl, IcmpProbe::Echo)
    }

    /// Fragmente un paquet IPv4 complet (en-tête 20 octets + segment) en
    /// fragments de `chunk` octets de charge utile (multiple de 8).
    ///
    /// Le paquet d'origine est renvoyé tel quel s'il tient dans un seul
    /// fragment. La somme de contrôle TCP/UDP reste valide : la réassemblage
    /// restitue le segment octet pour octet.
    // Tampon de taille exacte : `MutableIpv4Packet::new` ne peut échouer.
    #[allow(clippy::unwrap_used)]
    fn fragment_ipv4_packet(full: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        const IP_HDR: usize = 20;
        let Some(ip0) = Ipv4Packet::new(full) else {
            return vec![full.to_vec()];
        };
        if full.len() <= IP_HDR || chunk == 0 {
            return vec![full.to_vec()];
        }
        let segment = &full[IP_HDR..];
        if segment.len() <= chunk {
            return vec![full.to_vec()];
        }

        let src = ip0.get_source();
        let dst = ip0.get_destination();
        let ident = ip0.get_identification();
        let ttl = ip0.get_ttl();
        let proto = ip0.get_next_level_protocol();

        let total_frags = (segment.len() + chunk - 1) / chunk;
        let mut out: Vec<Vec<u8>> = Vec::with_capacity(total_frags);
        let mut offset_units: u16 = 0;
        for (i, part) in segment.chunks(chunk).enumerate() {
            let more = i + 1 < total_frags;
            let total = IP_HDR + part.len();
            let mut buf = vec![0u8; total];
            {
                let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
                ip.set_version(4);
                ip.set_header_length(5);
                ip.set_total_length(total as u16);
                ip.set_identification(ident);
                ip.set_flags(if more { Ipv4Flags::MoreFragments } else { 0 });
                ip.set_fragment_offset(offset_units);
                ip.set_ttl(ttl);
                ip.set_next_level_protocol(proto);
                ip.set_source(src);
                ip.set_destination(dst);
                ip.set_checksum(0);
                ip.payload_mut().copy_from_slice(part);
                let hc = ipv4_header_checksum(ip.packet());
                ip.set_checksum(hc);
            }
            out.push(buf);
            offset_units += (part.len() / 8) as u16;
        }
        out
    }

    /// Émet une sonde TCP brute, en la fragmentant si l'évasion le demande.
    fn emit_probe(
        tx: &mut transport::TransportSender,
        pkt: &[u8],
        dst: Ipv4Addr,
        evasion: &EvasionOptions,
        frag_chunk: usize,
    ) {
        if evasion.fragment && frag_chunk > 0 {
            for frag in fragment_ipv4_packet(pkt, frag_chunk) {
                if let Some(ip) = Ipv4Packet::new(&frag) {
                    let _ = tx.send_to(ip, IpAddr::V4(dst));
                }
            }
        } else if let Some(ip) = Ipv4Packet::new(pkt) {
            let _ = tx.send_to(ip, IpAddr::V4(dst));
        }
    }

    /// Sweep ICMP echo sur plusieurs cibles via un unique socket brut.
    /// Retourne les adresses ayant répondu (type 0) avec identifiant concordant.
    pub fn icmp_sweep_v4(targets: &[Ipv4Addr], timeout: Duration) -> Vec<Ipv4Addr> {
        icmp_probe_sweep_v4(targets, timeout, IcmpProbe::Echo)
    }

    /// Sweep ICMP timestamp (type 13) — `nmap -PP` : certains hôtes qui
    /// filtrent l'echo répondent toutefois au timestamp.
    pub fn icmp_timestamp_sweep_v4(targets: &[Ipv4Addr], timeout: Duration) -> Vec<Ipv4Addr> {
        icmp_probe_sweep_v4(targets, timeout, IcmpProbe::Timestamp)
    }

    /// Sweep ICMP address-mask (type 17) — `nmap -PM` : sonde de dernière
    /// chance pour les piles qui ne la filtrent pas explicitement.
    pub fn icmp_netmask_sweep_v4(targets: &[Ipv4Addr], timeout: Duration) -> Vec<Ipv4Addr> {
        icmp_probe_sweep_v4(targets, timeout, IcmpProbe::Netmask)
    }

    /// Sweep ICMP générique (echo / timestamp / netmask) via un unique socket
    /// brut. Retourne les adresses ayant renvoyé la réponse attendue avec un
    /// identifiant concordant (les trois types réutilisent ident+seq en 4..8).
    pub fn icmp_probe_sweep_v4(
        targets: &[Ipv4Addr],
        timeout: Duration,
        probe: IcmpProbe,
    ) -> Vec<Ipv4Addr> {
        if targets.is_empty() {
            return Vec::new();
        }
        let Ok((mut tx, mut rx)) = transport::transport_channel(
            4096,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp),
        ) else {
            return Vec::new();
        };
        let Some(src) = local_source_ipv4(targets[0]) else {
            return Vec::new();
        };

        let ident = (std::process::id() & 0xffff) as u16;
        let mut rng = rand::thread_rng();
        let mut by_seq: HashMap<u16, Ipv4Addr> = HashMap::new();
        for &dst in targets {
            let mut seq: u16 = rng.gen();
            for _ in 0..8 {
                if !by_seq.contains_key(&seq) {
                    break;
                }
                seq = rng.gen();
            }
            if by_seq.contains_key(&seq) {
                continue;
            }
            by_seq.insert(seq, dst);
            let pkt = build_ipv4_icmp_probe(src, dst, ident, seq, 64, probe);
            if let Some(ip) = Ipv4Packet::new(&pkt) {
                let _ = tx.send_to(ip, IpAddr::V4(dst));
            }
        }

        let mut alive: Vec<Ipv4Addr> = Vec::new();
        let mut seen: HashSet<u16> = HashSet::new();
        let mut iter = transport::ipv4_packet_iter(&mut rx);
        let deadline = Instant::now() + timeout;
        let mut idle = 0u32;
        while Instant::now() < deadline && seen.len() < by_seq.len() {
            match iter.next_with_timeout(Duration::from_millis(200)) {
                Ok(Some((ip, _))) => {
                    idle = 0;
                    if ip.get_version() != 4 {
                        continue;
                    }
                    let Some(icmp) = IcmpPacket::new(ip.payload()) else {
                        continue;
                    };
                    if icmp.get_icmp_type().0 != probe.reply_type() {
                        continue;
                    }
                    // pnet_packet expose le message ICMP comme : en-tête fixe
                    // (type/code/checksum, 4o) + payload. L'identifiant et le
                    // numéro de séquence occupent les 4 premiers octets du
                    // payload (rest-of-header RFC 792) — identiques pour les
                    // réponses echo/timestamp/netmask.
                    let rest = icmp.payload();
                    if rest.len() < 4 {
                        continue;
                    }
                    let rid = u16::from_be_bytes([rest[0], rest[1]]);
                    let rseq = u16::from_be_bytes([rest[2], rest[3]]);
                    if rid != ident {
                        continue;
                    }
                    if let Some(&dst) = by_seq.get(&rseq) {
                        if seen.insert(rseq) {
                            alive.push(dst);
                        }
                    }
                }
                Ok(None) => {
                    idle += 1;
                    if idle > 15 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        alive
    }

    /// ACK ping (`nmap -PA`) : émet un TCP ACK sans SYN vers des ports
    /// courants ; toute réponse (RST attendu) prouve que l'hôte est vivant,
    /// y compris lorsqu'un pare-feu filtre les SYN entrants.
    pub fn ack_ping_v4(targets: &[Ipv4Addr], ports: &[u16], timeout: Duration) -> Vec<Ipv4Addr> {
        if targets.is_empty() {
            return Vec::new();
        }
        let Ok((mut tx, mut rx)) = transport::transport_channel(
            4096,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
        ) else {
            return Vec::new();
        };
        let Some(src) = local_source_ipv4(targets[0]) else {
            return Vec::new();
        };

        let mut pending: HashSet<Ipv4Addr> = targets.iter().copied().collect();
        let mut rng = rand::thread_rng();
        for &dst in targets {
            for &dport in ports {
                let sport: u16 = rng.gen_range(40000..61000);
                let seq: u32 = rng.gen();
                let pkt = build_ipv4_tcp(
                    src,
                    dst,
                    sport,
                    dport,
                    seq,
                    64,
                    rng.gen(),
                    TcpFlags::ACK,
                    false,
                );
                if let Some(ip) = Ipv4Packet::new(&pkt) {
                    let _ = tx.send_to(ip, IpAddr::V4(dst));
                }
            }
        }

        let mut alive: Vec<Ipv4Addr> = Vec::new();
        let mut iter = transport::ipv4_packet_iter(&mut rx);
        let deadline = Instant::now() + timeout;
        let mut idle = 0u32;
        while Instant::now() < deadline && !pending.is_empty() {
            match iter.next_with_timeout(Duration::from_millis(200)) {
                Ok(Some((ip, _))) => {
                    idle = 0;
                    if ip.get_version() != 4 {
                        continue;
                    }
                    let Some(tcp) = TcpPacket::new(ip.payload()) else {
                        continue;
                    };
                    // Une réponse RST (ou toute autre) atteste d'une pile active.
                    if tcp.get_flags() & TcpFlags::RST == 0 {
                        continue;
                    }
                    let from = ip.get_source();
                    if pending.remove(&from) {
                        alive.push(from);
                    }
                }
                Ok(None) => {
                    idle += 1;
                    if idle > 15 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        alive
    }

    /// Envoie un echo ICMP et renvoie le TTL de la réponse (test ICMP de nmap,
    /// utilisé comme signal d'empreinte d'OS secondaire).
    pub fn icmp_echo_ttl_v4(host: Ipv4Addr, timeout: Duration) -> Option<u8> {
        let (mut tx, mut rx) = transport::transport_channel(
            4096,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp),
        )
        .ok()?;
        let src = local_source_ipv4(host)?;
        let ident = (std::process::id() & 0xffff) as u16;
        let seq: u16 = rand::thread_rng().gen();
        let pkt = build_ipv4_icmp_echo(src, host, ident, seq, 64);
        let ip = Ipv4Packet::new(&pkt)?;
        tx.send_to(ip, IpAddr::V4(host)).ok()?;

        let mut iter = transport::ipv4_packet_iter(&mut rx);
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match iter.next_with_timeout(Duration::from_millis(200)) {
                Ok(Some((ip, _))) => {
                    if ip.get_version() != 4 || ip.get_source() != host {
                        continue;
                    }
                    let Some(icmp) = IcmpPacket::new(ip.payload()) else {
                        continue;
                    };
                    if icmp.get_icmp_type().0 != IcmpProbe::Echo.reply_type() {
                        continue;
                    }
                    let rest = icmp.payload();
                    if rest.len() < 4 {
                        continue;
                    }
                    let rid = u16::from_be_bytes([rest[0], rest[1]]);
                    let rseq = u16::from_be_bytes([rest[2], rest[3]]);
                    if rid == ident && rseq == seq {
                        return Some(ip.get_ttl());
                    }
                }
                Ok(None) => continue,
                Err(_) => return None,
            }
        }
        None
    }

    /// Échantillonne la génération de l'ISN TCP (test SEQ simplifié de nmap) :
    /// émet plusieurs SYN vers un port ouvert et classe la progression des
    /// numéros de séquence renvoyés dans les SYN/ACK.
    pub fn os_seq_sample_v4(
        host: Ipv4Addr,
        port: u16,
        samples: usize,
        timeout: Duration,
    ) -> Option<IsnClass> {
        if samples < 2 {
            return None;
        }
        let (mut tx, mut rx) = transport::transport_channel(
            4096,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
        )
        .ok()?;
        let src = local_source_ipv4(host)?;
        let mut rng = rand::thread_rng();
        let mut sport: u16 = rng.gen_range(40000..61000);
        let mut isns: Vec<u32> = Vec::with_capacity(samples);
        let mut iter = transport::ipv4_packet_iter(&mut rx);
        for _ in 0..samples {
            sport = sport.wrapping_add(1);
            let pkt = build_ipv4_tcp(
                src,
                host,
                sport,
                port,
                rng.gen(),
                64,
                rng.gen(),
                TcpFlags::SYN,
                false,
            );
            if let Some(ip) = Ipv4Packet::new(&pkt) {
                let _ = tx.send_to(ip, IpAddr::V4(host));
            }
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                match iter.next_with_timeout(Duration::from_millis(200)) {
                    Ok(Some((ip, _))) => {
                        if ip.get_source() != host {
                            continue;
                        }
                        let Some(tcp) = TcpPacket::new(ip.payload()) else {
                            continue;
                        };
                        if tcp.get_source() != port {
                            continue;
                        }
                        let is_syn_ack = tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK)
                            == (TcpFlags::SYN | TcpFlags::ACK);
                        if !is_syn_ack {
                            continue;
                        }
                        isns.push(tcp.get_sequence());
                        break;
                    }
                    Ok(None) => continue,
                    Err(_) => break,
                }
            }
        }
        classify_isn(&isns)
    }

    /// Classe une série d'ISN : constant (identiques), incrémental (pas régulier
    /// ou progression monotone bornée), ou aléatoire (sauts imprévisibles).
    fn classify_isn(isns: &[u32]) -> Option<IsnClass> {
        if isns.len() < 2 {
            return None;
        }
        if isns.iter().all(|&x| x == isns[0]) {
            return Some(IsnClass::Constant);
        }
        let deltas: Vec<i64> = isns.windows(2).map(|w| w[1] as i64 - w[0] as i64).collect();
        let first = deltas.first().copied().unwrap_or(0);
        if first != 0 && deltas.iter().all(|&d| d == first) {
            return Some(IsnClass::Incremental);
        }
        // Progression monotone croissante et bornée : signature incrémentale.
        let bounded_increasing = deltas.iter().all(|&d| d > 0 && d < 100_000);
        if bounded_increasing {
            Some(IsnClass::Incremental)
        } else {
            Some(IsnClass::Random)
        }
    }

    /// Masque réseau depuis un préfixe CIDR (clampé à 32).
    fn prefix_mask(prefix: u8) -> u32 {
        let p = prefix.min(32) as u32;
        if p == 0 {
            0
        } else {
            (!0u32) << (32 - p)
        }
    }

    /// Sweep ARP sur le segment L2 local (non falsifiable par le pare-feu
    /// d'hôte, comme `nmap -PR`). Retourne les cibles ayant répondu.
    // Tampon de taille exacte (42 octets) : `MutableEthernetPacket::new` /
    // `MutableArpPacket::new` ne peuvent échouer que sur tampon trop court.
    #[allow(clippy::unwrap_used)]
    pub fn arp_sweep_v4(targets: &[Ipv4Addr], timeout: Duration) -> Vec<Ipv4Addr> {
        if targets.is_empty() {
            return Vec::new();
        }
        let mut alive: Vec<Ipv4Addr> = Vec::new();
        for iface in datalink::interfaces() {
            if iface.is_loopback() {
                continue;
            }
            let Some(src_mac) = iface.mac else {
                continue;
            };
            for ipnet in &iface.ips {
                let IpAddr::V4(local) = ipnet.ip() else {
                    continue;
                };
                if local.is_loopback() {
                    continue;
                }
                let mask = prefix_mask(ipnet.prefix());
                let net = u32::from(local) & mask;
                let batch: Vec<Ipv4Addr> = targets
                    .iter()
                    .copied()
                    .filter(|t| u32::from(*t) & mask == net && *t != local)
                    .collect();
                if batch.is_empty() {
                    continue;
                }
                let cfg = Config {
                    read_timeout: Some(timeout),
                    ..Config::default()
                };
                let (mut tx, mut rx) = match datalink::channel(&iface, cfg) {
                    Ok(datalink::Channel::Ethernet(t, r)) => (t, r),
                    _ => continue,
                };

                let broadcast = datalink::MacAddr::broadcast();
                for &target in &batch {
                    let mut buf = vec![0u8; 42];
                    {
                        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
                        eth.set_destination(broadcast);
                        eth.set_source(src_mac);
                        eth.set_ethertype(EtherTypes::Arp);
                        let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
                        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
                        arp.set_protocol_type(EtherTypes::Ipv4);
                        arp.set_hw_addr_len(6);
                        arp.set_proto_addr_len(4);
                        arp.set_operation(ArpOperations::Request);
                        arp.set_sender_hw_addr(src_mac);
                        arp.set_sender_proto_addr(local);
                        arp.set_target_hw_addr(datalink::MacAddr::zero());
                        arp.set_target_proto_addr(target);
                    }
                    let _ = tx.send_to(&buf, None);
                }

                let mut seen: HashSet<Ipv4Addr> = HashSet::new();
                let deadline = Instant::now() + timeout;
                while Instant::now() < deadline {
                    let frame = match rx.next() {
                        Ok(f) => f,
                        Err(_) => break,
                    };
                    let Some(eth) = EthernetPacket::new(frame) else {
                        continue;
                    };
                    if eth.get_ethertype() != EtherTypes::Arp {
                        continue;
                    }
                    let Some(arp) = ArpPacket::new(eth.payload()) else {
                        continue;
                    };
                    if arp.get_operation() != ArpOperations::Reply {
                        continue;
                    }
                    let ip = arp.get_sender_proto_addr();
                    if batch.contains(&ip) && seen.insert(ip) {
                        alive.push(ip);
                    }
                }
            }
        }
        alive
    }

    /// Scan TCP brut générique, paramétré par la technique (`TcpScanMode`).
    ///
    /// - `Syn` : SYN/ACK ⇒ `open` (reason `syn-ack`), RST ⇒ `closed` ;
    /// - `Fin`/`Null`/`Xmas`/`Maimon` : RST ⇒ `closed`, silence ⇒ `open|filtered` ;
    /// - `Ack` : RST ⇒ `unfiltered` (pare-feu transparent), silence ⇒ `filtered` ;
    /// - `Window` : fenêtre du RST > 0 ⇒ `open`, sinon `closed`.
    ///
    /// Récupère aussi les signaux d'empreinte (TTL, fenêtre, DF) — uniquement
    /// pertinents en mode `Syn` — et applique l'évasion : leurres à source
    /// usurpée émis avant chaque sonde réelle, et fragmentation IP optionnelle
    /// (`nmap -f` / `--mtu`).
    pub fn raw_tcp_scan_v4(
        host: Ipv4Addr,
        ports: &[u16],
        t: &TimingParams,
        evasion: &EvasionOptions,
        mode: TcpScanMode,
    ) -> Result<SynScanOutcome, String> {
        if ports.is_empty() {
            return Ok(SynScanOutcome::default());
        }
        let (mut tx, mut rx) = transport::transport_channel(
            4096,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
        )
        .map_err(|e| format!("socket brut TCP indisponible (root/CAP_NET_RAW requis) : {e}"))?;

        let src =
            local_source_ipv4(host).ok_or_else(|| "IP source locale introuvable".to_string())?;

        let mut rng = rand::thread_rng();
        // Ports cibles en attente de réponse (clé = port scanné).
        let mut pending: HashSet<u16> = HashSet::new();
        let probe_delay = t.scan_delay.min(Duration::from_millis(50));
        let frag_chunk = evasion.fragment_chunk();
        let probe_flags = mode.probe_flags();

        // Pool de leurres : adresses privées ; `spoof=` fixe la première.
        let mut decoy_pool: Vec<Ipv4Addr> =
            super::decoy_addresses(evasion.decoys, IpAddr::V4(host))
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v) => Some(v),
                    IpAddr::V6(_) => None,
                })
                .collect();
        if let Some(IpAddr::V4(spoof)) = evasion.spoof_source {
            if decoy_pool.is_empty() {
                decoy_pool.push(spoof);
            } else {
                decoy_pool[0] = spoof;
            }
        }

        // Ordre d'émission aléatoire si demandé (anti-signature séquentielle).
        let mut order: Vec<u16> = ports.to_vec();
        if evasion.randomize_order {
            use rand::seq::SliceRandom;
            order.shuffle(&mut rng);
        }

        for port in order {
            if !pending.insert(port) {
                continue;
            }
            let sport: u16 = evasion
                .source_port
                .unwrap_or_else(|| rng.gen_range(1024..=65535));

            // 1) Leurres : sondes à source usurpée, émises avant la sonde réelle.
            for &dsrc in &decoy_pool {
                let pkt = build_ipv4_tcp(
                    dsrc,
                    host,
                    sport,
                    port,
                    rng.gen(),
                    64,
                    rng.gen(),
                    probe_flags,
                    true,
                );
                emit_probe(&mut tx, &pkt, host, evasion, frag_chunk);
            }
            // 2) Sonde réelle (source locale) : seule à collecter l'état.
            let pkt = build_ipv4_tcp(
                src,
                host,
                sport,
                port,
                rng.gen(),
                64,
                rng.gen(),
                probe_flags,
                true,
            );
            emit_probe(&mut tx, &pkt, host, evasion, frag_chunk);

            if !probe_delay.is_zero() {
                std::thread::sleep(probe_delay);
            }
        }

        let mut states: HashMap<u16, PortState> = HashMap::new();
        let mut reasons: HashMap<u16, PortReason> = HashMap::new();
        let mut observed_ttl: Option<u8> = None;
        let mut observed_window: Option<u16> = None;
        let mut observed_df: Option<bool> = None;
        let mut observed_options: Option<TcpOptionProfile> = None;
        let mut iter = transport::ipv4_packet_iter(&mut rx);
        let deadline = Instant::now() + t.connect_timeout + Duration::from_millis(500);
        let mut idle = 0u32;

        while Instant::now() < deadline && states.len() < pending.len() {
            match iter.next_with_timeout(Duration::from_millis(200)) {
                Ok(Some((ip, _addr))) => {
                    idle = 0;
                    if ip.get_version() != 4 || ip.get_source() != host {
                        continue;
                    }
                    observed_ttl = Some(ip.get_ttl());
                    observed_df = Some(ip.get_flags() & Ipv4Flags::DontFragment != 0);
                    let Some(tcp) = TcpPacket::new(ip.payload()) else {
                        continue;
                    };
                    // La réponse provient du port scanné (source) vers notre port.
                    let scanned = tcp.get_source();
                    if !pending.contains(&scanned) {
                        continue;
                    }
                    let flags = tcp.get_flags();
                    if let Some((state, reason)) = classify_tcp_reply(mode, flags, tcp.get_window())
                    {
                        if mode == TcpScanMode::Syn && state == PortState::Open {
                            observed_window = Some(tcp.get_window());
                            if observed_options.is_none() {
                                observed_options = Some(parse_tcp_options(&tcp));
                            }
                        }
                        states.insert(scanned, state);
                        reasons.insert(scanned, reason);
                    }
                }
                Ok(None) => {
                    idle += 1;
                    if idle > 12 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let results = ports
            .iter()
            .map(|&port| {
                let default_state = default_state_for_mode(mode);
                PortResult {
                    port,
                    state: states.get(&port).copied().unwrap_or(default_state),
                    reason: reasons
                        .get(&port)
                        .copied()
                        .unwrap_or(PortReason::NoResponse),
                    banner: None,
                }
            })
            .collect();

        Ok(SynScanOutcome {
            results,
            observed_ttl,
            observed_window,
            observed_df,
            observed_options,
        })
    }

    /// Interprète une réponse TCP selon la technique de scan.
    fn classify_tcp_reply(
        mode: TcpScanMode,
        flags: u8,
        window: u16,
    ) -> Option<(PortState, PortReason)> {
        let is_syn_ack = flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK);
        let is_rst = flags & TcpFlags::RST != 0;
        match mode {
            TcpScanMode::Syn => {
                if is_syn_ack {
                    Some((PortState::Open, PortReason::SynAck))
                } else if is_rst {
                    Some((PortState::Closed, PortReason::Reset))
                } else {
                    None
                }
            }
            TcpScanMode::Fin | TcpScanMode::Null | TcpScanMode::Xmas | TcpScanMode::Maimon => {
                if is_rst {
                    Some((PortState::Closed, PortReason::Reset))
                } else {
                    None
                }
            }
            TcpScanMode::Ack => {
                if is_rst {
                    Some((PortState::Unfiltered, PortReason::Reset))
                } else {
                    None
                }
            }
            TcpScanMode::Window => {
                if is_rst {
                    if window > 0 {
                        Some((PortState::Open, PortReason::Reset))
                    } else {
                        Some((PortState::Closed, PortReason::Reset))
                    }
                } else {
                    None
                }
            }
        }
    }

    /// État attribué aux ports restés silencieux, selon la technique.
    fn default_state_for_mode(mode: TcpScanMode) -> PortState {
        match mode {
            TcpScanMode::Syn | TcpScanMode::Ack | TcpScanMode::Window => PortState::Filtered,
            TcpScanMode::Fin | TcpScanMode::Null | TcpScanMode::Xmas | TcpScanMode::Maimon => {
                PortState::OpenFiltered
            }
        }
    }

    /// Traceroute TTL : sondes UDP avec TTL croissant, réponses ICMP analysées.
    pub fn traceroute_raw(
        dst: Ipv4Addr,
        max_hops: u8,
        probe_timeout: Duration,
    ) -> Result<Vec<TraceHop>, String> {
        let (mut tx, _rx_udp) = transport::transport_channel(
            4096,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Udp),
        )
        .map_err(|e| format!("socket brut UDP indisponible (root/CAP_NET_RAW requis) : {e}"))?;
        let (_tx_icmp, mut rx) = transport::transport_channel(
            4096,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp),
        )
        .map_err(|e| format!("socket brut ICMP indisponible (root/CAP_NET_RAW requis) : {e}"))?;

        let src =
            local_source_ipv4(dst).ok_or_else(|| "IP source locale introuvable".to_string())?;
        let mut iter = transport::ipv4_packet_iter(&mut rx);
        let mut rng = rand::thread_rng();
        let mut hops: Vec<TraceHop> = Vec::new();

        for ttl in 1..=max_hops {
            let sport: u16 = rng.gen_range(33434..=33500);
            let pkt = build_ipv4_udp(src, dst, sport, 33434, ttl, rng.gen());
            let Some(ip) = Ipv4Packet::new(&pkt) else {
                break;
            };
            if tx.send_to(ip, IpAddr::V4(dst)).is_err() {
                break;
            }
            let start = Instant::now();
            let mut hop = TraceHop {
                ttl,
                addr: None,
                rtt_ms: None,
                reached: false,
            };

            for _ in 0..2 {
                match iter.next_with_timeout(probe_timeout) {
                    Ok(Some((ip, _))) => {
                        if ip.get_version() != 4 {
                            continue;
                        }
                        let payload = ip.payload();
                        let Some(icmp) = IcmpPacket::new(payload) else {
                            continue;
                        };
                        // Le message ICMP encapsule l'en-tête IP + 8 octets de la sonde.
                        let inner = &payload[8..];
                        let inner_dst = Ipv4Packet::new(inner).map(|p| p.get_destination());
                        if inner_dst != Some(dst) {
                            continue;
                        }
                        hop.addr = Some(IpAddr::V4(ip.get_source()));
                        hop.rtt_ms = Some(start.elapsed().as_millis() as u64);
                        match icmp.get_icmp_type() {
                            IcmpTypes::TimeExceeded => {}
                            IcmpTypes::DestinationUnreachable => hop.reached = true,
                            _ => {}
                        }
                        break;
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }

            let done = hop.reached;
            hops.push(hop);
            if done {
                break;
            }
        }
        Ok(hops)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use pnet::packet::tcp::TcpOption;

        #[test]
        fn classify_isn_detects_constant_incremental_random() {
            // Un seul échantillon ne suffit pas à conclure.
            assert_eq!(classify_isn(&[7]), None);
            assert_eq!(classify_isn(&[]), None);
            // ISN identiques → constant.
            assert_eq!(classify_isn(&[5, 5, 5]), Some(IsnClass::Constant));
            // Pas régulier mais monotone croissant et borné → incrémental.
            assert_eq!(classify_isn(&[10, 20, 30]), Some(IsnClass::Incremental));
            assert_eq!(classify_isn(&[1, 100, 1000]), Some(IsnClass::Incremental));
            // Sauts imprévisibles ou décroissants → aléatoire.
            assert_eq!(classify_isn(&[10, 5, 900]), Some(IsnClass::Random));
            assert_eq!(
                classify_isn(&[42, 4_000_000_000, 7]),
                Some(IsnClass::Random)
            );
        }

        #[test]
        fn icmp_probe_types_and_lengths_match_rfc() {
            assert_eq!(IcmpProbe::Echo.request_type(), 8);
            assert_eq!(IcmpProbe::Echo.reply_type(), 0);
            assert_eq!(IcmpProbe::Timestamp.request_type(), 13);
            assert_eq!(IcmpProbe::Timestamp.reply_type(), 14);
            assert_eq!(IcmpProbe::Netmask.request_type(), 17);
            assert_eq!(IcmpProbe::Netmask.reply_type(), 18);
            // En-tête IP (20) + en-tête ICMP (8) + corps propre à chaque sonde.
            assert_eq!(IcmpProbe::Echo.total_len(), 36);
            assert_eq!(IcmpProbe::Timestamp.total_len(), 40);
            assert_eq!(IcmpProbe::Netmask.total_len(), 32);
        }

        #[test]
        fn parse_tcp_options_extracts_known_stack_options() {
            // 20 octets d'en-tête + 20 octets d'options (data_offset = 10 mots).
            let mut buf = vec![0u8; 40];
            {
                let mut tcp = MutableTcpPacket::new(&mut buf).expect("tampon TCP valide");
                tcp.set_data_offset(10);
                tcp.set_options(&vec![
                    TcpOption::mss(1460),
                    TcpOption::wscale(7),
                    TcpOption::sack_perm(),
                    TcpOption::timestamp(0x1122_3344, 0),
                ]);
            }
            let tcp = TcpPacket::new(&buf).expect("tampon TCP lisible");
            let profile = parse_tcp_options(&tcp);
            assert_eq!(profile.mss, Some(1460));
            assert_eq!(profile.window_scale, Some(7));
            assert!(profile.sack_permitted);
            assert!(profile.timestamps);
        }

        #[test]
        fn parse_tcp_options_defaults_without_options() {
            // data_offset = 5 → aucune option.
            let mut buf = vec![0u8; 20];
            {
                let mut tcp = MutableTcpPacket::new(&mut buf).expect("tampon TCP valide");
                tcp.set_data_offset(5);
            }
            let tcp = TcpPacket::new(&buf).expect("tampon TCP lisible");
            assert_eq!(parse_tcp_options(&tcp), TcpOptionProfile::default());
        }

        #[test]
        fn build_ipv4_icmp_probe_has_expected_shape() {
            let src = Ipv4Addr::new(10, 0, 0, 1);
            let dst = Ipv4Addr::new(10, 0, 0, 2);
            let pkt = build_ipv4_icmp_probe(src, dst, 0x1234, 1, 64, IcmpProbe::Timestamp);
            assert_eq!(pkt.len(), IcmpProbe::Timestamp.total_len());
            let ip = Ipv4Packet::new(&pkt).expect("paquet IPv4");
            assert_eq!(ip.get_version(), 4);
            assert_eq!(ip.get_ttl(), 64);
            assert_eq!(ip.get_source(), src);
            assert_eq!(ip.get_destination(), dst);
            let icmp = IcmpPacket::new(ip.payload()).expect("charge ICMP");
            assert_eq!(icmp.get_icmp_type().0, 13); // Timestamp Request
        }
    }
}

/// Indique si le scan SYN est disponible sur cette plateforme.
pub fn syn_scan_supported() -> bool {
    cfg!(unix)
}

/// Scan SYN par paquets bruts (WSL/Linux, root requis). Vide si indisponible.
#[cfg(unix)]
pub async fn syn_scan(host: IpAddr, ports: &[u16], t: &TimingParams) -> Vec<PortResult> {
    stealth_scan(host, ports, t, &EvasionOptions::default(), TcpScanMode::Syn).await
}

/// Scan SYN avec évasion réelle (leurres émis, fragmentation IP).
#[cfg(unix)]
pub async fn syn_scan_evasive(
    host: IpAddr,
    ports: &[u16],
    t: &TimingParams,
    evasion: &EvasionOptions,
) -> Vec<PortResult> {
    stealth_scan(host, ports, t, evasion, TcpScanMode::Syn).await
}

/// Scan TCP brut générique (`-sS/-sF/-sN/-sX/-sA/-sM/-sW`) avec évasion réelle.
/// Vide si les paquets bruts sont indisponibles (nécessite WSL/Linux + root).
#[cfg(unix)]
pub async fn stealth_scan(
    host: IpAddr,
    ports: &[u16],
    t: &TimingParams,
    evasion: &EvasionOptions,
    mode: TcpScanMode,
) -> Vec<PortResult> {
    let IpAddr::V4(v4) = host else {
        return Vec::new();
    };
    let ports = ports.to_vec();
    let t2 = t.clone();
    let ev = evasion.clone();
    tokio::task::spawn_blocking(move || {
        raw::raw_tcp_scan_v4(v4, &ports, &t2, &ev, mode)
            .map(|o| o.results)
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

/// Scan SYN par paquets bruts (WSL/Linux, root requis). Vide si indisponible.
#[cfg(not(unix))]
pub async fn syn_scan(_host: IpAddr, _ports: &[u16], _t: &TimingParams) -> Vec<PortResult> {
    Vec::new()
}

#[cfg(not(unix))]
pub async fn syn_scan_evasive(
    _host: IpAddr,
    _ports: &[u16],
    _t: &TimingParams,
    _evasion: &EvasionOptions,
) -> Vec<PortResult> {
    Vec::new()
}

#[cfg(not(unix))]
pub async fn stealth_scan(
    _host: IpAddr,
    _ports: &[u16],
    _t: &TimingParams,
    _evasion: &EvasionOptions,
    _mode: TcpScanMode,
) -> Vec<PortResult> {
    Vec::new()
}

/// Empreinte TTL active seule (compatibilité) : TTL de la réponse la plus proche.
#[cfg(unix)]
pub async fn os_probe_ttl(host: IpAddr, t: &TimingParams) -> Option<u8> {
    os_probe_fingerprint(host, t).await.and_then(|f| f.ttl)
}

/// Empreinte active d'OS v3 : sonde les ports ouverts (fenêtre TCP, DF, options
/// TCP), des ports fermés (TTL de RST), un echo ICMP (TTL) et la génération de
/// l'ISN sur un port ouvert, puis agrège les signaux observés.
#[cfg(unix)]
pub async fn os_probe_fingerprint(host: IpAddr, t: &TimingParams) -> Option<OsFingerprint> {
    let IpAddr::V4(v4) = host else { return None };
    let t2 = t.clone();
    tokio::task::spawn_blocking(move || {
        // Ports ouverts probables pour capturer un SYN/ACK (fenêtre, DF, options),
        // puis ports très probablement fermés pour obtenir un RST (TTL).
        let ports = [80u16, 443, 22, 445, 3389, 65001, 12345, 65533];
        let outcome = raw::raw_tcp_scan_v4(
            v4,
            &ports,
            &t2,
            &EvasionOptions::default(),
            TcpScanMode::Syn,
        )
        .ok();
        let probe_to = t2.connect_timeout.max(Duration::from_millis(500));
        // Test ICMP : TTL de la réponse echo, si la pile répond à l'ICMP.
        let icmp_ttl = raw::icmp_echo_ttl_v4(v4, probe_to);
        // Test SEQ : ISN d'un port ouvert, s'il y en a un.
        let open_port = outcome.as_ref().and_then(|o| {
            o.results
                .iter()
                .find(|r| r.state == PortState::Open)
                .map(|r| r.port)
        });
        let isn_class = open_port.and_then(|p| raw::os_seq_sample_v4(v4, p, 4, probe_to));

        Some(OsFingerprint {
            ttl: outcome.as_ref().and_then(|o| o.observed_ttl),
            window: outcome.as_ref().and_then(|o| o.observed_window),
            df: outcome.as_ref().and_then(|o| o.observed_df),
            options: outcome.as_ref().and_then(|o| o.observed_options),
            icmp_ttl,
            isn_class,
        })
        .filter(|f| !f.is_empty())
    })
    .await
    .ok()
    .flatten()
}

#[cfg(not(unix))]
pub async fn os_probe_ttl(_host: IpAddr, _t: &TimingParams) -> Option<u8> {
    None
}

#[cfg(not(unix))]
pub async fn os_probe_fingerprint(_host: IpAddr, _t: &TimingParams) -> Option<OsFingerprint> {
    None
}

/// Traceroute par paquets bruts (WSL/Linux, root requis).
#[cfg(unix)]
pub async fn traceroute(
    host: IpAddr,
    max_hops: u8,
    t: &TimingParams,
) -> Result<Vec<TraceHop>, String> {
    let IpAddr::V4(v4) = host else {
        return Err("traceroute : IPv4 uniquement".to_string());
    };
    let probe_timeout = t.connect_timeout.max(Duration::from_millis(500));
    tokio::task::spawn_blocking(move || raw::traceroute_raw(v4, max_hops, probe_timeout))
        .await
        .unwrap_or_else(|e| Err(format!("traceroute interrompu : {e}")))
}

#[cfg(not(unix))]
pub async fn traceroute(
    _host: IpAddr,
    _max_hops: u8,
    _t: &TimingParams,
) -> Result<Vec<TraceHop>, String> {
    Err("traceroute nécessite des sockets bruts (WSL/Linux, root)".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (noyau pur — aucun accès réseau)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_state_nmap_rendering() {
        assert_eq!(PortState::Open.as_nmap(), "open");
        assert_eq!(PortState::Closed.as_nmap(), "closed");
        assert_eq!(PortState::Filtered.as_nmap(), "filtered");
        assert_eq!(PortState::OpenFiltered.as_nmap(), "open|filtered");
        assert_eq!(PortState::Unfiltered.as_nmap(), "unfiltered");
    }

    #[test]
    fn only_open_states_are_interesting() {
        assert!(PortState::Open.is_interesting());
        assert!(PortState::OpenFiltered.is_interesting());
        assert!(PortState::Unfiltered.is_interesting());
        assert!(!PortState::Closed.is_interesting());
        assert!(!PortState::Filtered.is_interesting());
    }

    #[test]
    fn port_reason_matches_nmap_codes() {
        assert_eq!(PortReason::SynAck.as_nmap(), "syn-ack");
        assert_eq!(PortReason::ConnEstablished.as_nmap(), "conn-established");
        assert_eq!(PortReason::Reset.as_nmap(), "reset");
        assert_eq!(PortReason::Refused.as_nmap(), "conn-refused");
        assert_eq!(PortReason::IcmpUnreachable.as_nmap(), "icmp-unreach");
        assert_eq!(PortReason::Response.as_nmap(), "response");
        assert_eq!(PortReason::NoResponse.as_nmap(), "no-response");
    }

    #[test]
    fn tcp_scan_mode_cli_roundtrip_and_flags() {
        // Alias « christmas » accepté pour Xmas.
        assert_eq!(TcpScanMode::from_cli("XMAS"), Some(TcpScanMode::Xmas));
        assert_eq!(
            TcpScanMode::from_cli(" christmas "),
            Some(TcpScanMode::Xmas)
        );
        assert_eq!(TcpScanMode::from_cli("fin"), Some(TcpScanMode::Fin));
        assert_eq!(TcpScanMode::from_cli("null"), Some(TcpScanMode::Null));
        assert_eq!(TcpScanMode::from_cli("maimon"), Some(TcpScanMode::Maimon));
        assert_eq!(TcpScanMode::from_cli("window"), Some(TcpScanMode::Window));
        // Technique inconnue → None (le validateur CLI gère le message d'erreur).
        assert_eq!(TcpScanMode::from_cli("bogus"), None);

        // Flags émis conformes à la sémantique de chaque technique.
        assert_eq!(TcpScanMode::Null.probe_flags(), 0);
        assert_eq!(TcpScanMode::Fin.probe_flags(), TcpFlags::FIN);
        assert_eq!(TcpScanMode::Syn.probe_flags(), TcpFlags::SYN);
        assert_eq!(
            TcpScanMode::Xmas.probe_flags(),
            TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG
        );
        assert_eq!(
            TcpScanMode::Maimon.probe_flags(),
            TcpFlags::FIN | TcpFlags::ACK
        );

        // Les libellés restent stables (utilisés dans l'affichage/les rapports).
        assert_eq!(TcpScanMode::Ack.label(), "ack");
        assert_eq!(TcpScanMode::Window.label(), "window");
    }

    #[test]
    fn timing_templates_are_monotonic() {
        let p0 = TimingTemplate::from_u8(0).params();
        let p5 = TimingTemplate::from_u8(5).params();
        // T0 : lent et discret ; T5 : rapide et agressif.
        assert!(p0.scan_delay > p5.scan_delay);
        assert!(p0.max_parallelism <= p5.max_parallelism);
        assert!(p0.connect_timeout >= p5.connect_timeout);
        // Mapping hors plage → Aggressive.
        assert_eq!(TimingTemplate::from_u8(9), TimingTemplate::Aggressive);
        assert_eq!(TimingTemplate::from_u8(0), TimingTemplate::Paranoid);
        assert_eq!(TimingTemplate::from_u8(5), TimingTemplate::Insane);
    }

    #[test]
    fn top_ports_contains_expected_services() {
        let ports = top_ports();
        assert!(ports.contains(&22));
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&3389));
        assert!(default_udp_ports().contains(&161));
    }

    #[test]
    fn dns_probe_is_wellformed() {
        let q = udp_probe_payload(53).expect("sonde DNS");
        assert_eq!(&q[0..2], &[0x1a, 0x2b]); // ID
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1); // QDCOUNT = 1
        assert_eq!(q.last().copied(), Some(0x01)); // QCLASS = IN
                                                   // QNAME doit se terminer par un octet nul avant QTYPE.
        assert!(q.contains(&0x00));
    }

    #[test]
    fn ntp_and_snmp_probes_have_expected_shapes() {
        let ntp = udp_probe_payload(123).expect("sonde NTP");
        assert_eq!(ntp.len(), 48);
        assert_eq!(ntp[0], 0x1b);

        let snmp = udp_probe_payload(161).expect("sonde SNMP");
        assert!(snmp.len() > 20);
        assert_eq!(snmp[0], 0x30); // SEQUENCE BER
        assert_eq!(snmp[snmp.len() - 1], 0x00); // NULL final du VarBind
    }

    #[test]
    fn ssdp_and_unknown_probes() {
        let ssdp = udp_probe_payload(1900).expect("sonde SSDP");
        assert!(ssdp.starts_with(b"M-SEARCH * HTTP/1.1"));
        // Port sans sonde connue.
        assert!(udp_probe_payload(12345).is_none());
    }

    #[test]
    fn conn_refused_matches_linux_and_windows_codes() {
        let linux = std::io::Error::from_raw_os_error(111);
        let win = std::io::Error::from_raw_os_error(10054);
        assert!(is_conn_refused(&linux));
        assert!(is_conn_refused(&win));
        let timeout = std::io::Error::new(std::io::ErrorKind::TimedOut, "t");
        assert!(!is_conn_refused(&timeout));
    }

    #[test]
    fn fingerprint_os_requires_a_ttl_signal() {
        // Aucun signal TTL (ni TCP ni ICMP) → pas d'inférence possible.
        assert!(fingerprint_os(&OsFingerprint::default()).is_none());
        // TTL TCP nul → invalide, comme `guess_os_from_ttl`.
        let fp = OsFingerprint {
            ttl: Some(0),
            ..Default::default()
        };
        assert!(fingerprint_os(&fp).is_none());
    }

    #[test]
    fn fingerprint_os_falls_back_to_icmp_ttl() {
        // Seul le TTL ICMP est connu (test ICMP de nmap) : l'inférence doit tenir.
        let fp = OsFingerprint {
            icmp_ttl: Some(64),
            ..Default::default()
        };
        let guess = fingerprint_os(&fp).expect("inférence depuis TTL ICMP");
        assert_eq!(guess.initial_ttl, 64);
        assert_eq!(guess.hops, 0);
        assert_eq!(guess.family, "Linux / UNIX / Android");
    }

    #[test]
    fn fingerprint_os_confidence_reacts_to_stack_signals() {
        let base = OsFingerprint {
            ttl: Some(64),
            ..Default::default()
        };
        let base_conf = fingerprint_os(&base).expect("base").confidence;

        // Options TCP modernes (window scale > 0 + SACK + timestamps) → confiance accrue.
        let modern = OsFingerprint {
            ttl: Some(64),
            options: Some(TcpOptionProfile {
                mss: Some(1460),
                window_scale: Some(7),
                sack_permitted: true,
                timestamps: true,
            }),
            ..Default::default()
        };
        assert!(fingerprint_os(&modern).expect("modern").confidence > base_conf);

        // MSS sous 1400 (tunnel/VPN/embarqué) → confiance réduite.
        let tunnel = OsFingerprint {
            ttl: Some(64),
            options: Some(TcpOptionProfile {
                mss: Some(1360),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(fingerprint_os(&tunnel).expect("tunnel").confidence < base_conf);

        // TTL TCP et ICMP divergents (routage asymétrique) → confiance réduite.
        let asym = OsFingerprint {
            ttl: Some(64),
            icmp_ttl: Some(60),
            ..Default::default()
        };
        assert!(fingerprint_os(&asym).expect("asym").confidence < base_conf);
    }

    #[test]
    fn fingerprint_os_maps_isn_class_to_variant() {
        // ISN incrémental : signature d'une pile ancienne.
        let incr = OsFingerprint {
            ttl: Some(64),
            isn_class: Some(IsnClass::Incremental),
            ..Default::default()
        };
        let g = fingerprint_os(&incr).expect("incrémental");
        assert!(g.variant.unwrap_or_default().contains("incrémental"));

        // ISN constant : pile déterministe/embarquée, confiance réduite.
        let konst = OsFingerprint {
            ttl: Some(64),
            isn_class: Some(IsnClass::Constant),
            ..Default::default()
        };
        let base_conf = fingerprint_os(&OsFingerprint {
            ttl: Some(64),
            ..Default::default()
        })
        .expect("base")
        .confidence;
        let gc = fingerprint_os(&konst).expect("constant");
        assert!(gc.variant.unwrap_or_default().contains("constant"));
        assert!(gc.confidence < base_conf);

        // ISN aléatoire : aucune variante ajoutée.
        let rnd = OsFingerprint {
            ttl: Some(64),
            isn_class: Some(IsnClass::Random),
            ..Default::default()
        };
        assert!(fingerprint_os(&rnd).expect("aléatoire").variant.is_none());
    }

    #[test]
    fn os_guess_render_includes_stack_details() {
        let fp = OsFingerprint {
            ttl: Some(64),
            window: Some(29200),
            df: Some(true),
            options: Some(TcpOptionProfile {
                mss: Some(1460),
                window_scale: Some(7),
                sack_permitted: true,
                timestamps: true,
            }),
            isn_class: Some(IsnClass::Random),
            ..Default::default()
        };
        let rendered = fingerprint_os(&fp).expect("inférence").render();
        assert!(rendered.contains("MSS 1460"));
        assert!(rendered.contains("scale 7"));
        assert!(rendered.contains("ISN random"));
        assert!(rendered.contains("DF"));
        assert!(rendered.contains("confiance"));
    }
}
