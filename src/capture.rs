// capture.rs — live packet capture via pnet
// On Windows without NPCAP, all capture functions return an informative error.
// The scanner (TCP connect + HTTP,HTTPS,RSTP,ETC) works fully without this module.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{atomic::AtomicBool, Arc};

use crate::flows::{FlowLink, WeightedFloat};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedFlow {
    pub src_ip: String,
    pub src_port: Option<u16>,
    pub dst_ip: String,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub app_banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureResult {
    pub flows: Vec<CapturedFlow>,
    pub duration_ms: u64,
    pub interface: String,
    pub total_packets: u64,
    pub total_bytes: u64,
}

// ── Platform-specific implementations ──────────────────────────────────────

#[cfg(unix)]
mod native {
    use super::*;
    use pnet::datalink::{self, Config, NetworkInterface};
    use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet_packet::ip::IpNextHeaderProtocols;
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::ipv6::Ipv6Packet;
    use pnet_packet::tcp::TcpPacket;
    use pnet_packet::udp::UdpPacket;
    use pnet_packet::Packet;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::{atomic::Ordering, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    pub fn list_interfaces() -> Vec<String> {
        datalink::interfaces()
            .into_iter()
            .filter(|i| !i.ips.is_empty())
            .map(|i| i.name)
            .collect()
    }

    fn pick_default_interface() -> Option<NetworkInterface> {
        let mut ifaces = datalink::interfaces();
        ifaces.retain(|i| !i.ips.is_empty());
        ifaces.sort_by_key(|i| {
            let v4 = i
                .ips
                .iter()
                .filter(|ip| matches!(ip.ip(), IpAddr::V4(_)))
                .count();
            (
                i.is_loopback() as usize,
                std::cmp::Reverse(v4),
                i.name.clone(),
            )
        });
        ifaces.into_iter().next()
    }

    fn extract_banner(
        payload: &[u8],
        src_port: Option<u16>,
        _dst_port: Option<u16>,
    ) -> Option<String> {
        if payload.is_empty() {
            return None;
        }
        let cleaned: String = payload
            .iter()
            .take(256)
            .filter(|b| (**b as char).is_ascii_graphic() || **b == b' ' || **b == b'\n')
            .map(|b| *b as char)
            .collect();
        let trimmed = cleaned.trim().to_string();
        if trimmed.len() < 4 {
            return None;
        }
        if src_port.unwrap_or(9999) >= 1024 {
            return None;
        }
        Some(trimmed.lines().next().unwrap_or("").trim().to_string())
    }

    // ── Tiny BPF-subset compiler ──────────────────────────────────────────────
    // Supports: tcp | udp | icmp | ip
    //           port N | src port N | dst port N
    //           host IP | src host IP | dst host IP
    //           net A.B.C.D/M
    //           and | or | not | ( ... )
    type BpfFn = Box<dyn Fn(IpAddr, IpAddr, Option<u16>, Option<u16>, &str) -> bool + Send + Sync>;

    #[derive(Debug)]
    enum BpfPrim {
        Proto(String),
        Port(Option<u16>, Option<u16>), // (src, dst) — only one is Some
        Host(Option<IpAddr>, Option<IpAddr>), // (src, dst)
        Net(Option<(u32, u32)>, Option<(u32, u32)>), // (src net/mask, dst net/mask)
    }

    fn ip_to_u32(ip: IpAddr) -> Option<u32> {
        match ip {
            IpAddr::V4(v4) => Some(u32::from(v4)),
            _ => None,
        }
    }

    fn parse_ipv4_cidr(s: &str) -> Option<(u32, u32)> {
        let (ip_s, prefix) = match s.split_once('/') {
            Some((a, b)) => (a, b.parse::<u8>().ok()?),
            None => (s, 32u8),
        };
        let ip: std::net::Ipv4Addr = ip_s.parse().ok()?;
        let bits = u32::from(ip);
        let mask = if prefix == 0 {
            0u32
        } else {
            (!0u32) << (32 - prefix)
        };
        Some((bits & mask, mask))
    }

    fn compile_bpf(expr: &str) -> BpfFn {
        let tokens = tokenize_bpf(expr);
        let mut pos = 0usize;
        let ast = parse_or(&tokens, &mut pos);
        Box::new(move |src, dst, sp, dp, proto| eval_bpf(&ast, src, dst, sp, dp, proto))
    }

    fn tokenize_bpf(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        for ch in s.chars() {
            if ch == '(' || ch == ')' {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                out.push(ch.to_string());
            } else if ch.is_whitespace() {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            } else {
                cur.push(ch);
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }

    fn parse_or(tokens: &[String], pos: &mut usize) -> BpfExpr {
        let mut left = parse_and(tokens, pos);
        while *pos < tokens.len() && tokens[*pos].eq_ignore_ascii_case("or") {
            *pos += 1;
            let right = parse_and(tokens, pos);
            left = BpfExpr::Or(Box::new(left), Box::new(right));
        }
        left
    }

    fn parse_and(tokens: &[String], pos: &mut usize) -> BpfExpr {
        let mut left = parse_not(tokens, pos);
        while *pos < tokens.len() && tokens[*pos].eq_ignore_ascii_case("and") {
            *pos += 1;
            let right = parse_not(tokens, pos);
            left = BpfExpr::And(Box::new(left), Box::new(right));
        }
        left
    }

    fn parse_not(tokens: &[String], pos: &mut usize) -> BpfExpr {
        if *pos < tokens.len() && tokens[*pos].eq_ignore_ascii_case("not") {
            *pos += 1;
            let inner = parse_not(tokens, pos);
            return BpfExpr::Not(Box::new(inner));
        }
        parse_primary(tokens, pos)
    }

    fn parse_primary(tokens: &[String], pos: &mut usize) -> BpfExpr {
        if *pos >= tokens.len() {
            return BpfExpr::Const(true);
        }
        let tok = &tokens[*pos];
        if tok == "(" {
            *pos += 1;
            let inner = parse_or(tokens, pos);
            if *pos < tokens.len() && tokens[*pos] == ")" {
                *pos += 1;
            }
            return inner;
        }
        let low = tok.to_lowercase();
        match low.as_str() {
            "tcp" | "udp" | "icmp" | "ip" => {
                *pos += 1;
                BpfExpr::Prim(BpfPrim::Proto(low))
            }
            "src" | "dst" => {
                *pos += 1;
                if *pos >= tokens.len() {
                    return BpfExpr::Const(true);
                }
                let dir = low.as_str();
                let next = tokens[*pos].to_lowercase();
                match next.as_str() {
                    "port" => {
                        *pos += 1;
                        let p = tokens
                            .get(*pos)
                            .and_then(|t| t.parse::<u16>().ok())
                            .unwrap_or(0);
                        *pos += 1;
                        match dir {
                            "src" => BpfExpr::Prim(BpfPrim::Port(Some(p), None)),
                            _ => BpfExpr::Prim(BpfPrim::Port(None, Some(p))),
                        }
                    }
                    "host" => {
                        *pos += 1;
                        let ip = tokens.get(*pos).and_then(|t| t.parse::<IpAddr>().ok());
                        *pos += 1;
                        match dir {
                            "src" => BpfExpr::Prim(BpfPrim::Host(ip, None)),
                            _ => BpfExpr::Prim(BpfPrim::Host(None, ip)),
                        }
                    }
                    "net" => {
                        *pos += 1;
                        let net = tokens.get(*pos).and_then(|t| parse_ipv4_cidr(t));
                        *pos += 1;
                        match dir {
                            "src" => BpfExpr::Prim(BpfPrim::Net(net, None)),
                            _ => BpfExpr::Prim(BpfPrim::Net(None, net)),
                        }
                    }
                    _ => BpfExpr::Const(true),
                }
            }
            "port" => {
                *pos += 1;
                let p = tokens
                    .get(*pos)
                    .and_then(|t| t.parse::<u16>().ok())
                    .unwrap_or(0);
                *pos += 1;
                BpfExpr::Prim(BpfPrim::Port(Some(p), Some(p)))
            }
            "host" => {
                *pos += 1;
                let ip = tokens.get(*pos).and_then(|t| t.parse::<IpAddr>().ok());
                *pos += 1;
                BpfExpr::Prim(BpfPrim::Host(ip, ip))
            }
            "net" => {
                *pos += 1;
                let net = tokens.get(*pos).and_then(|t| parse_ipv4_cidr(t));
                *pos += 1;
                BpfExpr::Prim(BpfPrim::Net(net, net))
            }
            _ => {
                *pos += 1;
                BpfExpr::Const(true)
            }
        }
    }

    #[derive(Debug)]
    enum BpfExpr {
        Const(bool),
        Prim(BpfPrim),
        And(Box<BpfExpr>, Box<BpfExpr>),
        Or(Box<BpfExpr>, Box<BpfExpr>),
        Not(Box<BpfExpr>),
    }

    fn eval_bpf(
        e: &BpfExpr,
        src: IpAddr,
        dst: IpAddr,
        sp: Option<u16>,
        dp: Option<u16>,
        proto: &str,
    ) -> bool {
        match e {
            BpfExpr::Const(b) => *b,
            BpfExpr::And(a, b) => {
                eval_bpf(a, src, dst, sp, dp, proto) && eval_bpf(b, src, dst, sp, dp, proto)
            }
            BpfExpr::Or(a, b) => {
                eval_bpf(a, src, dst, sp, dp, proto) || eval_bpf(b, src, dst, sp, dp, proto)
            }
            BpfExpr::Not(a) => !eval_bpf(a, src, dst, sp, dp, proto),
            BpfExpr::Prim(p) => match p {
                BpfPrim::Proto(want) => proto.eq_ignore_ascii_case(want.as_str()),
                // BPF semantics: "port N" (no direction) matches src OR dst port.
                // "src port N" / "dst port N" match only the given direction.
                // When both s and d are Some => undirected => OR. When only one is Some => directional.
                BpfPrim::Port(s, d) => match (s, d) {
                    (Some(p1), Some(p2)) => sp == Some(*p1) || dp == Some(*p2),
                    (Some(p), None) => sp == Some(*p),
                    (None, Some(p)) => dp == Some(*p),
                    (None, None) => true,
                },
                BpfPrim::Host(s, d) => match (s, d) {
                    (Some(ip1), Some(ip2)) => src == *ip1 || dst == *ip2,
                    (Some(ip), None) => src == *ip,
                    (None, Some(ip)) => dst == *ip,
                    (None, None) => true,
                },
                BpfPrim::Net(s, d) => match (s, d) {
                    (Some((n1, m1)), Some((n2, m2))) => {
                        let ok_s = ip_to_u32(src).map_or(false, |v| (v & m1) == *n1);
                        let ok_d = ip_to_u32(dst).map_or(false, |v| (v & m2) == *n2);
                        ok_s || ok_d
                    }
                    (Some((n, m)), None) => ip_to_u32(src).map_or(false, |v| (v & m) == *n),
                    (None, Some((n, m))) => ip_to_u32(dst).map_or(false, |v| (v & m) == *n),
                    (None, None) => true,
                },
            },
        }
    }

    pub fn run_capture(
        interface_name: Option<&str>,
        duration_sec: u64,
        filter_ports: Option<&HashSet<u16>>,
        max_flows: usize,
        stop_signal: Option<Arc<AtomicBool>>,
        promiscuous: bool,
        bpf_filter: Option<&str>,
    ) -> anyhow::Result<CaptureResult> {
        let ports: HashSet<u16> = filter_ports.cloned().unwrap_or_default();
        let filter_active = !ports.is_empty();

        // Compile the (subset of) BPF expression into an evaluator.
        let bpf = match bpf_filter {
            Some(expr) if !expr.trim().is_empty() => Some(compile_bpf(expr)),
            _ => None,
        };

        let interface = match interface_name {
            Some(n) => datalink::interfaces()
                .into_iter()
                .find(|i| i.name == n)
                .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", n))?,
            None => pick_default_interface()
                .ok_or_else(|| anyhow::anyhow!("No usable interface found"))?,
        };
        let iface_name = interface.name.clone();
        let cfg = Config {
            read_timeout: Some(Duration::from_millis(100)),
            promiscuous,
            ..Config::default()
        };
        let (_tx, mut rx) = match datalink::channel(&interface, cfg)
            .map_err(|e| anyhow::anyhow!("datalink channel: {}", e))?
        {
            datalink::Channel::Ethernet(t, r) => (t, r),
            _ => return Err(anyhow::anyhow!("Unsupported datalink type")),
        };

        let flows: Arc<Mutex<HashMap<String, CapturedFlow>>> = Arc::new(Mutex::new(HashMap::new()));
        let total_pkts = Arc::new(Mutex::new(0u64));
        let total_bytes = Arc::new(Mutex::new(0u64));
        let stop = stop_signal.unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        let stop2 = stop.clone();
        let flows2 = flows.clone();
        let tp2 = total_pkts.clone();
        let tb2 = total_bytes.clone();

        let worker = thread::Builder::new().name("pcap".into()).spawn(move || {
            let start = Instant::now();
            let deadline = start + Duration::from_secs(duration_sec.saturating_add(10));
            while !stop2.load(Ordering::Acquire) && start.elapsed().as_secs() < duration_sec {
                if Instant::now() >= deadline {
                    break;
                }
                // next() est potentiellement bloquant (read_timeout non honoré sous WSL2 /
                // certaines configurations pcap). On évite donc un hang infini en sortant
                // de toute façon à la deadline (duration + 10s) via check en haut de boucle.
                // Sous Linux/pnet normal, read_timeout 100ms (cfg L100) réveille rx.next()
                // ~10 fois par seconde.
                let pkt = match rx.next() {
                    Ok(p) => p,
                    Err(_) => {
                        thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                };
                let eth = match EthernetPacket::new(pkt) {
                    Some(e) => e,
                    None => continue,
                };
                let plen = pkt.len() as u64;
                *tp2.lock().unwrap_or_else(|e| e.into_inner()) += 1;
                *tb2.lock().unwrap_or_else(|e| e.into_inner()) += plen;

                let parsed = match eth.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let ip = match Ipv4Packet::new(eth.payload()) {
                            Some(i) => i,
                            None => continue,
                        };
                        let (src, dst) = (
                            IpAddr::V4(ip.get_source()),
                            IpAddr::V4(ip.get_destination()),
                        );
                        match ip.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                let t = match TcpPacket::new(ip.payload()) {
                                    Some(x) => x,
                                    None => continue,
                                };
                                Some((
                                    src,
                                    dst,
                                    "tcp",
                                    Some(t.get_source()),
                                    Some(t.get_destination()),
                                    t.payload().to_vec(),
                                ))
                            }
                            IpNextHeaderProtocols::Udp => {
                                let u = match UdpPacket::new(ip.payload()) {
                                    Some(x) => x,
                                    None => continue,
                                };
                                Some((
                                    src,
                                    dst,
                                    "udp",
                                    Some(u.get_source()),
                                    Some(u.get_destination()),
                                    u.payload().to_vec(),
                                ))
                            }
                            IpNextHeaderProtocols::Icmp => {
                                Some((src, dst, "icmp", None, None, vec![]))
                            }
                            _ => None,
                        }
                    }
                    EtherTypes::Ipv6 => {
                        let ip = match Ipv6Packet::new(eth.payload()) {
                            Some(i) => i,
                            None => continue,
                        };
                        let (src, dst) = (
                            IpAddr::V6(ip.get_source()),
                            IpAddr::V6(ip.get_destination()),
                        );
                        match ip.get_next_header() {
                            IpNextHeaderProtocols::Tcp => {
                                let t = match TcpPacket::new(ip.payload()) {
                                    Some(x) => x,
                                    None => continue,
                                };
                                Some((
                                    src,
                                    dst,
                                    "tcp",
                                    Some(t.get_source()),
                                    Some(t.get_destination()),
                                    t.payload().to_vec(),
                                ))
                            }
                            IpNextHeaderProtocols::Udp => {
                                let u = match UdpPacket::new(ip.payload()) {
                                    Some(x) => x,
                                    None => continue,
                                };
                                Some((
                                    src,
                                    dst,
                                    "udp",
                                    Some(u.get_source()),
                                    Some(u.get_destination()),
                                    u.payload().to_vec(),
                                ))
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };

                let (si, di, proto, sp, dp, payload) = match parsed {
                    Some(x) => x,
                    None => continue,
                };
                if filter_active {
                    let ok = sp.map(|p| ports.contains(&p)).unwrap_or(false)
                        || dp.map(|p| ports.contains(&p)).unwrap_or(false);
                    if !ok {
                        continue;
                    }
                }
                if let Some(bpf_fn) = bpf.as_ref() {
                    if !bpf_fn(si, di, sp, dp, proto) {
                        continue;
                    }
                }

                let (a, b, _c, _d) = if si < di {
                    (si, di, sp, dp)
                } else {
                    (di, si, dp, sp)
                };
                let key = format!("{}|{}|{:?}|{:?}|{}", a, b, _c, _d, proto);
                let now_ms = (start.elapsed().as_secs_f64() * 1000.0) as u64;
                let banner = extract_banner(&payload, sp, dp);

                let mut fm = flows2.lock().unwrap_or_else(|e| e.into_inner());
                if fm.len() >= max_flows && !fm.contains_key(&key) {
                    continue;
                }
                fm.entry(key)
                    .and_modify(|f| {
                        f.packets += 1;
                        f.bytes += plen;
                        f.last_seen = now_ms;
                        if f.app_banner.is_none() {
                            f.app_banner = banner.clone();
                        }
                    })
                    .or_insert(CapturedFlow {
                        src_ip: a.to_string(),
                        src_port: _c,
                        dst_ip: b.to_string(),
                        dst_port: _d,
                        protocol: proto.to_string(),
                        packets: 1,
                        bytes: plen,
                        first_seen: now_ms,
                        last_seen: now_ms,
                        app_banner: banner,
                    });
            }
        })?;

        // Attendre la fin de la capture AVEC UN WATCHDOG GARANTI pour éviter tout hang:
        // 1. Un thread ticker signale stop au bout de (duration + 12s) maximum.
        // 2. On join le worker via un channel mpsc + recv_timeout, ce qui ne bloque jamais
        //    plus de (duration + 15s) — même si rx.next() bloque à l'infini.
        let watchdog_secs = duration_sec.saturating_add(15);
        let stop_wd = stop.clone();
        let _watchdog = thread::Builder::new()
            .name("pcap-wd".into())
            .spawn(move || {
                for _ in 0..watchdog_secs {
                    if stop_wd.load(Ordering::Acquire) {
                        return;
                    }
                    thread::sleep(Duration::from_secs(1));
                }
                stop_wd.store(true, Ordering::Release);
            });

        // Attendre N secondes OU stop
        for _ in 0..duration_sec {
            if stop.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        stop.store(true, Ordering::Release);

        // Join via channel + recv_timeout (10s hard). Évite hang sur rx.next() bloquant.
        {
            use std::sync::mpsc;
            let (tx, rx) = mpsc::channel();
            let _ = thread::Builder::new()
                .name("pcap-join".into())
                .spawn(move || {
                    let _ = worker.join();
                    let _ = tx.send(());
                });
            // On ignore l'erreur de timeout: le thread pcap reste peut-être bloqué sur
            // rx.next(), mais nous rendons la main au caller.
            let _ = rx.recv_timeout(Duration::from_secs(12));
        }

        let captured_flows: Vec<CapturedFlow> = {
            let guard = flows.lock().unwrap_or_else(|e| e.into_inner());
            guard.values().cloned().collect()
        };
        let pkt_count = {
            let guard = total_pkts.lock().unwrap_or_else(|e| e.into_inner());
            *guard
        };
        let byte_count = {
            let guard = total_bytes.lock().unwrap_or_else(|e| e.into_inner());
            *guard
        };

        Ok(CaptureResult {
            flows: captured_flows,
            duration_ms: duration_sec * 1000,
            interface: iface_name,
            total_packets: pkt_count,
            total_bytes: byte_count,
        })
    }
}

// ── Windows stub — no WinPcap/NPCAP required ──────────────────────────────

#[cfg(windows)]
mod native {
    use super::*;

    pub fn list_interfaces() -> Vec<String> {
        // On Windows, live capture requires NPCAP to be installed.
        // Install NPCAP from https://npcap.com/ then re-run nrtg --list-ifaces
        vec!["[NPCAP not installed — install from https://npcap.com/]".to_string()]
    }

    pub fn run_capture(
        _interface_name: Option<&str>,
        _duration_sec: u64,
        _filter_ports: Option<&HashSet<u16>>,
        _max_flows: usize,
        _stop_signal: Option<Arc<AtomicBool>>,
        _promiscuous: bool,
        _bpf_filter: Option<&str>,
    ) -> anyhow::Result<CaptureResult> {
        Err(anyhow::anyhow!(
            "Live capture requires NPCAP on Windows.\n\
             Install from: https://npcap.com/#download\n\
             Check 'Install Npcap in WinPcap API-compatible Mode' during setup.\n\
             The TCP/HTTP scanner works without NPCAP."
        ))
    }
}

// ── Public API (delegates to platform impl) ────────────────────────────────

pub fn list_interfaces() -> Vec<String> {
    native::list_interfaces()
}

pub fn run_capture(
    interface_name: Option<&str>,
    duration_sec: u64,
    filter_ports: Option<&HashSet<u16>>,
    max_flows: usize,
    stop_signal: Option<Arc<AtomicBool>>,
    promiscuous: bool,
    bpf_filter: Option<&str>,
) -> anyhow::Result<CaptureResult> {
    native::run_capture(
        interface_name,
        duration_sec,
        filter_ports,
        max_flows,
        stop_signal,
        promiscuous,
        bpf_filter,
    )
}

pub fn capture_to_links(result: &CaptureResult) -> Vec<FlowLink> {
    let mut out = Vec::new();
    for flow in &result.flows {
        let source = match flow.src_port {
            Some(p) => format!("{}:{}", flow.src_ip, p),
            None => flow.src_ip.clone(),
        };
        let target = match flow.dst_port {
            Some(p) => format!("{}:{}", flow.dst_ip, p),
            None => flow.dst_ip.clone(),
        };
        let w = (1.0 + (flow.packets as f64).log2() + (flow.bytes as f64).log2() / 10.0)
            .clamp(1.0, 10.0);
        let label = flow
            .app_banner
            .as_ref()
            .map(|b| {
                format!(
                    "{} [{}]",
                    flow.protocol,
                    b.chars().take(48).collect::<String>()
                )
            })
            .unwrap_or_else(|| format!("{} flow ({} pkts)", flow.protocol, flow.packets));
        out.push(FlowLink {
            source,
            target,
            link_type: format!("captured-{}", flow.protocol),
            weight: WeightedFloat::from(w),
            src_port: flow.src_port,
            dst_port: flow.dst_port,
            label,
        });
    }
    out.sort_by(|a, b| {
        b.weight
            .partial_cmp(&a.weight)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

pub fn write_capture_json(result: &CaptureResult, path: &str) -> anyhow::Result<()> {
    let json = serde_json::json!({
        "interface": result.interface,
        "duration_ms": result.duration_ms,
        "total_packets": result.total_packets,
        "total_bytes": result.total_bytes,
        "links": capture_to_links(result),
        "flows_raw": result.flows,
    });
    std::fs::write(path, serde_json::to_string_pretty(&json)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_to_links_basic() {
        let cr = CaptureResult {
            flows: vec![CapturedFlow {
                src_ip: "10.0.0.1".into(),
                src_port: Some(80),
                dst_ip: "10.0.0.2".into(),
                dst_port: Some(44444),
                protocol: "tcp".into(),
                packets: 42,
                bytes: 9000,
                first_seen: 0,
                last_seen: 5000,
                app_banner: Some("Server: nginx/1.14.0".into()),
            }],
            duration_ms: 5000,
            interface: "eth0".into(),
            total_packets: 100,
            total_bytes: 50000,
        };
        let links = capture_to_links(&cr);
        assert_eq!(links.len(), 1);
        assert!(links[0].label.contains("nginx"));
    }
}
