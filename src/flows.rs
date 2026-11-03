use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, PartialOrd)]
pub struct WeightedFloat(f64);

impl Eq for WeightedFloat {}

impl std::hash::Hash for WeightedFloat {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

impl From<f64> for WeightedFloat {
    fn from(f: f64) -> Self {
        WeightedFloat(f)
    }
}

impl From<WeightedFloat> for f64 {
    fn from(w: WeightedFloat) -> Self {
        w.0
    }
}

impl std::fmt::Display for WeightedFloat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.1}", self.0)
    }
}

impl std::ops::Deref for WeightedFloat {
    type Target = f64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FlowLink {
    pub source: String,
    pub target: String,
    #[serde(rename = "type", default = "default_link_type")]
    pub link_type: String,
    #[serde(default)]
    pub weight: WeightedFloat,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralEdge {
    pub source: String,
    pub target: String,
    pub exploitability_score: f32,
    pub detection_risk: f32,
    pub credential_reuse: f32,
    pub cvss_combined: f32,
    pub ai_confidence: f32,
    pub suggested_technique: Option<String>,
    pub suggested_exploit_id: Option<String>,
    pub link_type: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub raw_weight: WeightedFloat,
}

impl LateralEdge {
    pub fn composite_score(&self) -> f32 {
        self.exploitability_score * 0.35
            + (1.0 - self.detection_risk) * 0.25
            + self.credential_reuse * 0.20
            + (self.cvss_combined / 10.0) * 0.10
            + self.ai_confidence * 0.10
    }

    pub fn cost_for_dijkstra(&self) -> f64 {
        let s = self.composite_score().clamp(0.001, 1.0);
        (1.0 / s) as f64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralHop {
    pub from_host: String,
    pub to_host: String,
    pub technique: String,
    pub exploit_id: Option<String>,
    pub expected_success_prob: f32,
    pub expected_detection_risk: f32,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralPath {
    pub path_id: String,
    pub hops: Vec<LateralHop>,
    pub source_host: String,
    pub target_host: String,
    pub total_success_probability: f32,
    pub aggregate_detection_risk: f32,
    pub expected_minutes_estimate: u32,
    pub score: f32,
    pub rank: Option<usize>,
    pub rationale: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct LateralGraph {
    pub adjacency: HashMap<String, Vec<LateralEdge>>,
    pub node_meta: HashMap<String, NodeMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeMetadata {
    pub host: String,
    pub os: Option<String>,
    pub is_domain_controller: bool,
    pub is_critical: bool,
    pub compromised: bool,
    pub risk_score: f32,
    #[serde(default, skip_serializing, skip_deserializing)]
    pub tags: HashSet<String>,
}

impl LateralGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, id: String, meta: NodeMetadata) {
        self.adjacency.entry(id.clone()).or_default();
        self.node_meta.insert(id, meta);
    }

    pub fn add_edge(&mut self, edge: LateralEdge) {
        self.adjacency
            .entry(edge.source.clone())
            .or_default()
            .push(edge);
    }

    pub fn nodes(&self) -> Vec<String> {
        self.adjacency.keys().cloned().collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_flowlinks_and_targets(
        links: &[FlowLink],
        targets: &[ScanTargetSummary],
        risk_per_host: &HashMap<String, f32>,
        cves_per_host: &HashMap<String, Vec<(String, f32, String)>>,
        compromised_hosts: &HashSet<String>,
        credentials_found: &HashMap<String, Vec<String>>,
    ) -> Self {
        let mut g = LateralGraph::new();

        let host_ports: HashMap<String, Vec<(u16, String, i32)>> = {
            let mut m: HashMap<String, Vec<(u16, String, i32)>> = HashMap::new();
            for t in targets {
                m.entry(t.host.clone())
                    .or_default()
                    .push((t.port, t.service.clone(), t.risk));
            }
            m
        };

        for t in targets {
            let is_crit = t.risk >= 4 || is_db_like_service(&t.service);
            let meta = NodeMetadata {
                host: t.host.clone(),
                os: None,
                is_domain_controller: false,
                is_critical: is_crit,
                compromised: compromised_hosts.contains(&t.host),
                risk_score: t.risk as f32,
                tags: HashSet::new(),
            };
            g.add_node(t.id.clone(), meta);
        }

        for link in links {
            let src_host = targets
                .iter()
                .find(|t| t.id == link.source)
                .map(|t| t.host.clone());
            let dst_host = targets
                .iter()
                .find(|t| t.id == link.target)
                .map(|t| t.host.clone());
            let (Some(src_h), Some(dst_h)) = (src_host.as_ref(), dst_host.as_ref()) else {
                continue;
            };

            let base_w: f64 = link.weight.into();
            let base_prob = (base_w / 5.0).clamp(0.1, 1.0) as f32;

            let dst_risk = *risk_per_host.get(dst_h).unwrap_or(&0.0);
            let dst_cvss = cves_per_host
                .get(dst_h)
                .map(|v| v.iter().map(|(_, s, _)| *s).fold(0.0_f32, f32::max))
                .unwrap_or(0.0);

            let cred_reuse = if let Some(creds) = credentials_found.get(src_h) {
                if creds.iter().any(|c| {
                    c.to_lowercase().contains(&dst_h.to_lowercase())
                        || c.to_lowercase().contains("admin")
                        || c.to_lowercase().contains("local admin")
                }) {
                    0.85
                } else {
                    0.15
                }
            } else {
                0.15
            };

            let dst_svc = link.dst_port.and_then(|p| {
                host_ports
                    .get(dst_h)
                    .and_then(|v| v.iter().find(|(pp, _, _)| *pp == p))
                    .map(|(_, svc, _)| svc.as_str())
            });

            let (tech, explo_id) =
                suggest_lateral_technique(link.dst_port, &link.link_type, dst_svc);

            let det_risk = match link.link_type.as_str() {
                "same-host" => 0.1,
                "same-subnet" => 0.35,
                "app-tier" => 0.25,
                "admin-hop" => 0.5,
                "mx-edge" => 0.4,
                _ => 0.45,
            };

            let edge = LateralEdge {
                source: link.source.clone(),
                target: link.target.clone(),
                exploitability_score: base_prob.max(dst_risk / 5.0).min(0.95),
                detection_risk: det_risk,
                credential_reuse: cred_reuse,
                cvss_combined: dst_cvss,
                ai_confidence: 0.5,
                suggested_technique: Some(tech.to_string()),
                suggested_exploit_id: explo_id.map(|s| s.to_string()),
                link_type: link.link_type.clone(),
                src_port: link.src_port,
                dst_port: link.dst_port,
                raw_weight: link.weight,
            };

            g.add_edge(edge);
        }

        g
    }

    pub fn top_k_paths(
        &self,
        source: &str,
        max_depth: usize,
        k: usize,
        prefer_critical: bool,
    ) -> Vec<LateralPath> {
        let mut out: Vec<LateralPath> = Vec::new();

        // State: (cost, depth, hops, current_node, prob_acc, risk_acc, mins_acc)
        // Use Vec as a manual min-priority queue (sorted by cost) to avoid
        // the Ord requirement that BinaryHeap imposes on f64/f32.
        type State = (f64, usize, Vec<LateralHop>, String, f32, f32, u32);
        let mut queue: Vec<State> = Vec::new();

        queue.push((
            0.0_f64,
            0_usize,
            Vec::new(),
            source.to_string(),
            1.0_f32,
            0.0_f32,
            0u32,
        ));

        let mut visited_state: HashMap<(String, usize), f64> = HashMap::new();

        while !queue.is_empty() {
            // Pop minimum-cost entry (Dijkstra: always expand cheapest first)
            queue.sort_unstable_by(|a, b| {
                a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal)
            });
            let (cost, depth, hops, current, prob_acc, risk_acc, mins) = queue.remove(0);

            if depth > max_depth {
                continue;
            }

            if depth > 0 {
                let Some(last_hop) = hops.last() else {
                    continue;
                };
                let target_host = last_hop.to_host.clone();
                let meta = self.node_meta.get(&target_host);
                let is_crit = meta.map(|m| m.is_critical).unwrap_or(false);
                let crit_bonus = if prefer_critical && is_crit {
                    0.15_f32
                } else {
                    0.0_f32
                };
                let path_score = (prob_acc + crit_bonus).min(0.99) - risk_acc * 0.5;

                let rationale = build_path_rationale(&hops, prob_acc, risk_acc);
                let warnings = build_path_warnings(&hops, risk_acc);
                let lp = LateralPath {
                    path_id: format!("path-{}-{}", source, out.len()),
                    hops: hops.clone(),
                    source_host: source.to_string(),
                    target_host,
                    total_success_probability: prob_acc,
                    aggregate_detection_risk: risk_acc,
                    expected_minutes_estimate: mins,
                    score: path_score,
                    rank: None,
                    rationale,
                    warnings,
                };
                out.push(lp);
                if out.len() >= k * 3 {
                    break;
                }
            }

            let key = (current.clone(), depth);
            if let Some(&prev_best) = visited_state.get(&key) {
                if cost >= prev_best {
                    continue;
                }
            }
            visited_state.insert(key, cost);

            let Some(edges) = self.adjacency.get(&current) else {
                continue;
            };
            for e in edges {
                let mut new_hops = hops.clone();
                let next_prob = prob_acc * e.composite_score().clamp(0.05, 0.99);
                let next_risk = (risk_acc + e.detection_risk).min(1.0);
                let next_mins = mins + estimate_hop_minutes(&e.link_type);
                let hop = LateralHop {
                    from_host: current.clone(),
                    to_host: e.target.clone(),
                    technique: e
                        .suggested_technique
                        .clone()
                        .unwrap_or_else(|| "generic".into()),
                    exploit_id: e.suggested_exploit_id.clone(),
                    expected_success_prob: e.composite_score(),
                    expected_detection_risk: e.detection_risk,
                    src_port: e.src_port,
                    dst_port: e.dst_port,
                    notes: format!(
                        "type={} cvss={:.1} cred-reuse={:.0}%",
                        e.link_type,
                        e.cvss_combined,
                        e.credential_reuse * 100.0
                    ),
                };
                new_hops.push(hop);
                let new_cost = cost + e.cost_for_dijkstra();
                queue.push((
                    new_cost,
                    depth + 1,
                    new_hops,
                    e.target.clone(),
                    next_prob,
                    next_risk,
                    next_mins,
                ));
            }
        }

        out.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out.truncate(k);
        for (i, p) in out.iter_mut().enumerate() {
            p.rank = Some(i + 1);
        }
        out
    }

    pub fn rank_all_campaign_paths(
        &self,
        max_depth: usize,
        k_per_source: usize,
    ) -> Vec<LateralPath> {
        let sources: Vec<String> = self
            .node_meta
            .iter()
            .filter(|(_, m)| m.compromised)
            .map(|(id, _)| id.clone())
            .collect();

        let mut all = Vec::new();
        for src in sources {
            let mut paths = self.top_k_paths(&src, max_depth, k_per_source, true);
            all.append(&mut paths);
        }
        all.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for (i, p) in all.iter_mut().enumerate() {
            p.rank = Some(i + 1);
        }
        all
    }
}

fn estimate_hop_minutes(link_type: &str) -> u32 {
    match link_type {
        "same-host" => 1,
        "same-subnet" => 3,
        "app-tier" => 5,
        "admin-hop" => 8,
        "mx-edge" => 10,
        _ => 6,
    }
}

fn suggest_lateral_technique(
    dst_port: Option<u16>,
    _link_type: &str,
    service: Option<&str>,
) -> (&'static str, Option<&'static str>) {
    match (dst_port, service) {
        (Some(445), _) | (_, Some("smb")) => ("SMB Relay / PsExec", Some("SMB-PSEXEC-ADMIN")),
        (Some(22), _) | (_, Some("ssh")) => {
            ("SSH Pass-the-Key / lateral-ssh", Some("SSH-LATERAL-KEY"))
        }
        (Some(3389), _) | (_, Some("rdp")) => ("RDP Pass-the-Hash", Some("RDP-PTH-LATERAL")),
        (Some(5985), _) | (Some(5986), _) | (_, Some("winrm")) => {
            ("WinRM / WMI lateral", Some("WINRM-WMI-LATERAL"))
        }
        (Some(3306), _) | (_, Some("mysql")) => {
            ("MySQL lateral via creds reuse", Some("MYSQL-CREDS-REUSE"))
        }
        (Some(5432), _) | (_, Some("postgresql")) => {
            ("Postgres lateral via creds", Some("PG-CREDS-REUSE"))
        }
        (Some(6379), _) | (_, Some("redis")) => {
            ("Redis replication / module load", Some("REDIS-ANON-PING"))
        }
        (Some(27017), _) | (_, Some("mongodb")) => {
            ("Mongo lateral via creds", Some("MONGO-NOAUTH"))
        }
        (Some(21), _) | (_, Some("ftp")) => ("FTP pivot + cred harvest", Some("FTP-ANON-LOGIN")),
        (Some(80), _) | (Some(443), _) | (_, Some("http")) | (_, Some("https")) => (
            "Web app-tier pivot session/admin-hop",
            Some("HTTP-DEFAULT-ADMIN-BASIC"),
        ),
        _ => ("Generic lateral enumerate-then-probe", None),
    }
}

fn build_path_rationale(hops: &[LateralHop], prob: f32, risk: f32) -> String {
    let chain: Vec<String> = hops
        .iter()
        .map(|h| format!("{}--[{}]-->{}", h.from_host, h.technique, h.to_host))
        .collect();
    format!(
        "Path: {} success={:.0}% detection-risk={:.0}% hops={}",
        chain.join(" → "),
        prob * 100.0,
        risk * 100.0,
        hops.len()
    )
}

fn build_path_warnings(hops: &[LateralHop], aggregate_risk: f32) -> Vec<String> {
    let mut w = Vec::new();
    if aggregate_risk > 0.7 {
        w.push("High aggregate detection risk; consider slower stealthier alternatives".into());
    }
    if hops.iter().any(|h| h.dst_port == Some(445)) {
        w.push("SMB hop: monitor for EDR on target endpoints".into());
    }
    if hops.len() > 3 {
        w.push("Deep chain (>3 hops); session maintenance risk increases with each pivot".into());
    }
    w
}

#[derive(Debug, Clone)]
pub struct ScanTargetSummary {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub service: String,
    pub risk: i32,
}

fn same_subnet(a: &str, b: &str) -> bool {
    let a_parts: Vec<&str> = a.split('.').collect();
    let b_parts: Vec<&str> = b.split('.').collect();
    if a_parts.len() != 4 || b_parts.len() != 4 {
        return a == b;
    }
    a_parts[0] == b_parts[0] && a_parts[1] == b_parts[1] && a_parts[2] == b_parts[2]
}

fn is_db_like_service(svc: &str) -> bool {
    matches!(
        svc.to_lowercase().as_str(),
        "redis" | "mysql" | "postgresql" | "mongodb" | "mssql"
    )
}

fn is_web_like_service(svc: &str) -> bool {
    matches!(svc.to_lowercase().as_str(), "http" | "https")
}

fn is_access_gateway(svc: &str) -> bool {
    matches!(
        svc.to_lowercase().as_str(),
        "ssh" | "telnet" | "rdp" | "ftp"
    )
}

fn is_mail_like_service(svc: &str) -> bool {
    matches!(svc.to_lowercase().as_str(), "smtp" | "pop3" | "imap")
}

fn default_link_type() -> String {
    "inferred".into()
}

pub fn load_flows_json(path: &str) -> Option<Vec<FlowLink>> {
    let content = fs::read_to_string(path).ok()?;
    let data: Value = serde_json::from_str(&content).ok()?;
    let mut out = Vec::new();

    if let Some(arr) = data.get("links").and_then(|v| v.as_array()) {
        for link in arr {
            let src = link["source"].as_str()?.to_string();
            let tgt = link["target"].as_str()?.to_string();
            let ltype = link["type"]
                .as_str()
                .or_else(|| link.get("link_type").and_then(|v| v.as_str()))
                .unwrap_or("captured")
                .to_string();
            let weight = WeightedFloat::from(link["weight"].as_f64().unwrap_or(1.0));
            let src_port = link["src_port"].as_u64().map(|n| n as u16);
            let dst_port = link["dst_port"].as_u64().map(|n| n as u16);
            let label = link["label"]
                .as_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "pcap".into());
            out.push(FlowLink {
                source: src,
                target: tgt,
                link_type: ltype,
                weight,
                src_port,
                dst_port,
                label,
            });
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

pub fn infer_links_from_targets(targets: &[ScanTargetSummary]) -> Vec<FlowLink> {
    let mut links_set: HashSet<FlowLink> = HashSet::new();
    let mut links = Vec::new();

    let hosts: Vec<&ScanTargetSummary> = targets.iter().collect();

    for i in 0..hosts.len() {
        for j in (i + 1)..hosts.len() {
            let a = hosts[i];
            let b = hosts[j];
            let (label, w, ltype) = if a.host == b.host {
                (
                    format!("localhost:{} ⇄ {}:{}", a.port, b.service, b.port),
                    WeightedFloat::from(3.0),
                    "same-host",
                )
            } else if same_subnet(&a.host, &b.host) {
                (
                    format!("subnet /24: {} ⇄ {}", a.service, b.service),
                    WeightedFloat::from(2.2),
                    "same-subnet",
                )
            } else if (is_web_like_service(&a.service) && is_db_like_service(&b.service))
                || (is_web_like_service(&b.service) && is_db_like_service(&a.service))
            {
                (
                    format!("web ⇄ db: {} ⇄ {}", a.service, b.service),
                    WeightedFloat::from(2.5),
                    "app-tier",
                )
            } else if (is_web_like_service(&a.service) || is_db_like_service(&a.service))
                && is_access_gateway(&b.service)
                || (is_web_like_service(&b.service) || is_db_like_service(&b.service))
                    && is_access_gateway(&a.service)
            {
                (
                    format!("mgmt access: {} ⇄ {}", a.service, b.service),
                    WeightedFloat::from(1.8),
                    "admin-hop",
                )
            } else if (is_mail_like_service(&a.service) && is_web_like_service(&b.service))
                || (is_mail_like_service(&b.service) && is_web_like_service(&a.service))
            {
                (
                    format!("mail-web: {} ⇄ {}", a.service, b.service),
                    WeightedFloat::from(1.4),
                    "mx-edge",
                )
            } else {
                continue;
            };

            let (s, t, sp, dp) = if a.port <= b.port {
                (a.id.clone(), b.id.clone(), Some(a.port), Some(b.port))
            } else {
                (b.id.clone(), a.id.clone(), Some(b.port), Some(a.port))
            };

            let link = FlowLink {
                source: s,
                target: t,
                link_type: ltype.into(),
                weight: WeightedFloat::from(w),
                src_port: sp,
                dst_port: dp,
                label,
            };
            if !links_set.contains(&link) {
                links_set.insert(link.clone());
                links.push(link);
            }
        }
    }

    links.sort_by(|a, b| {
        b.weight
            .0
            .partial_cmp(&a.weight.0)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    links
}

pub fn merge_links(captured: Option<Vec<FlowLink>>, inferred: Vec<FlowLink>) -> Vec<FlowLink> {
    let mut set: HashSet<FlowLink> = HashSet::new();
    let mut merged = Vec::new();

    if let Some(cap) = captured {
        for l in cap {
            if !set.contains(&l) {
                set.insert(l.clone());
                merged.push(l);
            }
        }
    }
    for l in inferred {
        if !set.contains(&l) {
            set.insert(l.clone());
            merged.push(l);
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(id: &str, host: &str, port: u16, service: &str, risk: i32) -> ScanTargetSummary {
        ScanTargetSummary {
            id: id.into(),
            host: host.into(),
            port,
            service: service.into(),
            risk,
        }
    }

    #[test]
    fn test_same_host_links() {
        let tgts = vec![
            target("h1", "10.0.0.1", 80, "http", 3),
            target("h1", "10.0.0.1", 3306, "mysql", 4),
        ];
        let links = infer_links_from_targets(&tgts);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_type, "same-host");
    }

    #[test]
    fn test_web_db_links() {
        let tgts = vec![
            target("web", "10.0.0.1", 80, "http", 3),
            target("db", "10.0.1.5", 27017, "mongodb", 4),
        ];
        let links = infer_links_from_targets(&tgts);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_type, "app-tier");
    }

    #[test]
    fn test_same_subnet_links() {
        let tgts = vec![
            target("a", "192.168.1.10", 22, "ssh", 4),
            target("b", "192.168.1.20", 21, "ftp", 3),
        ];
        let links = infer_links_from_targets(&tgts);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_type, "same-subnet");
    }

    #[test]
    fn test_unrelated_no_links() {
        let tgts = vec![
            target("a", "1.1.1.1", 53, "dns", 2),
            target("b", "8.8.8.8", 443, "https", 3),
        ];
        let links = infer_links_from_targets(&tgts);
        assert!(links.is_empty());
    }

    #[test]
    fn test_lateral_graph_from_flowlinks_and_targets() {
        let tgts = vec![
            target("a", "10.0.0.10", 22, "ssh", 4),
            target("b", "10.0.0.20", 445, "smb", 5),
            target("c", "10.0.1.50", 3306, "mysql", 4),
        ];
        let links = infer_links_from_targets(&tgts);
        let risk_per_host: HashMap<String, f32> = HashMap::from([
            ("10.0.0.10".into(), 4.0),
            ("10.0.0.20".into(), 5.0),
            ("10.0.1.50".into(), 4.0),
        ]);
        let cves_per_host: HashMap<String, Vec<(String, f32, String)>> = HashMap::new();
        let mut compromised: HashSet<String> = HashSet::new();
        compromised.insert("10.0.0.10".into());
        let creds: HashMap<String, Vec<String>> = HashMap::new();

        let g = LateralGraph::from_flowlinks_and_targets(
            &links,
            &tgts,
            &risk_per_host,
            &cves_per_host,
            &compromised,
            &creds,
        );

        assert!(!g.adjacency.is_empty());
        assert_eq!(g.node_meta.len(), 3);
        assert!(g.node_meta.get("a").unwrap().compromised);
    }

    #[test]
    fn test_composite_score_weights() {
        let edge = LateralEdge {
            source: "a".into(),
            target: "b".into(),
            exploitability_score: 0.8,
            detection_risk: 0.2,
            credential_reuse: 0.5,
            cvss_combined: 7.5,
            ai_confidence: 0.7,
            suggested_technique: None,
            suggested_exploit_id: None,
            link_type: "same-subnet".into(),
            src_port: None,
            dst_port: None,
            raw_weight: WeightedFloat::from(2.0),
        };
        let s = edge.composite_score();
        assert!(s > 0.0 && s <= 1.0);
    }

    #[test]
    fn test_top_k_paths_single_hop() {
        let tgts = vec![
            target("a", "10.0.0.10", 22, "ssh", 4),
            target("b", "10.0.0.20", 445, "smb", 5),
        ];
        let links = infer_links_from_targets(&tgts);
        let risk_per_host: HashMap<String, f32> =
            HashMap::from([("10.0.0.10".into(), 4.0), ("10.0.0.20".into(), 5.0)]);
        let cves_per_host: HashMap<String, Vec<(String, f32, String)>> = HashMap::new();
        let mut compromised: HashSet<String> = HashSet::new();
        compromised.insert("10.0.0.10".into());
        let creds: HashMap<String, Vec<String>> = HashMap::new();

        let g = LateralGraph::from_flowlinks_and_targets(
            &links,
            &tgts,
            &risk_per_host,
            &cves_per_host,
            &compromised,
            &creds,
        );

        let paths = g.rank_all_campaign_paths(2, 5);
        assert!(!paths.is_empty());
        for p in &paths {
            assert!(!p.hops.is_empty());
            assert!(p.rank.is_some());
        }
    }
}
