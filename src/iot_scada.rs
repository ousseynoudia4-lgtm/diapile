//! DIAPILE — IoT/SCADA Attack Module
//!
//! Protocoles industriels et IoT :
//! - Modbus TCP (port 502) — lecture/écriture registres
//! - DNP3 (port 20000) — SCADA utilities
//! - BACnet (port 47808 UDP) — building automation
//! - CoAP (port 5683 UDP) — constrained IoT
//! - OPC-UA (port 4840) — industrial
//! - MQTT deep scan (broker hijack, topic enumération)
//! - EtherNet/IP (port 44818) — Rockwell PLCs
//! - Siemens S7 (port 102) — S7comm protocol
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
//! ⚠️ LES SYSTÈMES SCADA/ICS PEUVENT ÊTRE DANGEREUX À TESTER.
//!    NE JAMAIS ÉCRIRE SUR DES PLCs EN PRODUCTION.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotDevice {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub description: Option<String>,
    pub vulns: Vec<IotVuln>,
    pub data: Vec<(String, String)>, // (register/object, value)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotVuln {
    pub vuln_type: String,
    pub description: String,
    pub severity: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IotScanReport {
    pub devices: Vec<IotDevice>,
    pub open_ports: Vec<(String, u16, String)>, // (host, port, protocol)
}

// ─────────────────────────────────────────────────────────────────────────────
// Ports IoT/SCADA à scanner
// ─────────────────────────────────────────────────────────────────────────────

pub fn iot_scada_ports() -> Vec<(u16, &'static str)> {
    vec![
        (102, "siemens-s7"),
        (502, "modbus"),
        (1911, "foxboro"),
        (2222, "ssh-iot"),
        (4000, "emerson-deltav"),
        (4840, "opc-ua"),
        (5006, "melsec-q"),
        (5007, "melsec-q"),
        (5094, "bacnet-ip"),
        (9600, "omron-fins"),
        (18245, "ge-srtp"),
        (18246, "ge-srtp"),
        (20000, "dnp3"),
        (34962, "profinet-rt"),
        (34963, "profinet-rt"),
        (34964, "profinet-rt"),
        (44818, "ethernet-ip"),
        (47808, "bacnet"),
        (55000, "modbus-alt"),
        // MQTT
        (1883, "mqtt"),
        (8883, "mqtt-tls"),
        (9001, "mqtt-ws"),
        // Zigbee/Z-Wave gateways
        (8080, "zigbee-gateway"),
        (8888, "iot-gateway"),
        // CoAP (UDP handled separately)
        (5683, "coap-udp"),
        (5684, "coap-dtls"),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Modbus TCP (port 502)
// ─────────────────────────────────────────────────────────────────────────────

/// Lit les registres Modbus TCP d'un appareil
pub async fn scan_modbus(host: &str, port: u16) -> Option<IotDevice> {
    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    let mut device = IotDevice {
        host: host.to_string(),
        port,
        protocol: "Modbus TCP".into(),
        vendor: None,
        model: None,
        firmware: None,
        description: None,
        vulns: Vec::new(),
        data: Vec::new(),
    };

    // Requête Modbus : Read Holding Registers (FC=3)
    // Transaction ID=1, Protocol ID=0, Length=6, Unit ID=1, FC=3, Start=0, Count=10
    let read_holding: &[u8] = &[
        0x00, 0x01, // Transaction ID
        0x00, 0x00, // Protocol ID (Modbus)
        0x00, 0x06, // Length
        0x01, // Unit ID
        0x03, // Function Code: Read Holding Registers
        0x00, 0x00, // Starting Address
        0x00, 0x0A, // Quantity (10 registers)
    ];

    timeout(Duration::from_secs(3), stream.write_all(read_holding))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 256];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n >= 9 {
        let byte_count = buf[8] as usize;
        let reg_data = &buf[9..9 + byte_count.min(n - 9)];

        // Décoder les registres
        for i in (0..reg_data.len().saturating_sub(1)).step_by(2) {
            let reg_val = u16::from_be_bytes([reg_data[i], reg_data[i + 1]]);
            device.data.push((
                format!("Holding Register {}", i / 2),
                format!("{}", reg_val),
            ));
        }

        // Vulnérabilité critique : Modbus sans auth permet lecture ET écriture
        device.vulns.push(IotVuln {
            vuln_type:   "Modbus No Authentication".into(),
            description: "Modbus TCP n'implémente aucune authentification. N'importe qui peut lire ET écrire les registres, contrôler les sorties physiques.".into(),
            severity:    "CRITICAL".into(),
            evidence:    format!("Lecture réussie de {} registres sans credentials", byte_count / 2),
        });

        println!(
            "  \x1b[38;5;196m[MODBUS]\x1b[0m {}:{} — {} registres lus ⚠️ NO AUTH",
            host,
            port,
            byte_count / 2
        );
    }

    // Requête Device Identification (FC=43)
    let device_id: &[u8] = &[
        0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2B, 0x0E, 0x01, 0x00,
    ];
    if timeout(Duration::from_secs(2), stream.write_all(device_id))
        .await
        .is_ok()
    {
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .ok()?
            .ok()?;
        if n > 10 {
            let info = String::from_utf8_lossy(&buf[8..n]).to_string();
            device.vendor = Some(info.split('\0').next().unwrap_or("?").to_string());
        }
    }

    Some(device)
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Siemens S7 (port 102) — TPKT/COTP/S7comm
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_siemens_s7(host: &str, port: u16) -> Option<IotDevice> {
    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    // TPKT + COTP Connection Request (CR)
    let cotp_cr: &[u8] = &[
        0x03, 0x00, 0x00, 0x16, // TPKT: version=3, length=22
        0x11, // COTP: length=17
        0xE0, // COTP: Connection Request
        0x00, 0x00, // Destination reference
        0x00, 0x01, // Source reference
        0x00, // Class
        0xC0, 0x01, 0x0A, // TPDU-size option
        0xC1, 0x02, 0x01, 0x00, // Source TSAP
        0xC2, 0x02, 0x01, 0x02, // Destination TSAP (S7: slot 2)
    ];

    timeout(Duration::from_secs(3), stream.write_all(cotp_cr))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 512];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n < 5 || buf[4] != 0xD0 {
        return None;
    } // D0 = CC (Connection Confirm)

    // S7 Setup Communication
    let s7_setup: &[u8] = &[
        0x03, 0x00, 0x00, 0x19, // TPKT
        0x02, 0xF0, 0x80, // COTP Data
        0x32, 0x01, 0x00, 0x00, // S7 header: protocol=0x32, ROSCTR=1 (Job)
        0x00, 0x00, 0x00, 0x08, // PDU reference + parameter length
        0x00, 0x00, // Data length
        0xF0, 0x00, // Function: Setup Communication
        0x00, 0x01, // Max AMQ caller
        0x00, 0x01, // Max AMQ callee
        0x01, 0xE0, // PDU length
    ];

    timeout(Duration::from_secs(3), stream.write_all(s7_setup))
        .await
        .ok()?
        .ok()?;
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n < 7 {
        return None;
    }

    let mut device = IotDevice {
        host: host.to_string(),
        port,
        protocol: "Siemens S7 (S7comm)".into(),
        vendor: Some("Siemens".into()),
        model: None,
        firmware: None,
        description: None,
        vulns: Vec::new(),
        data: Vec::new(),
    };

    // S7 Read SZL (System Status List) — Device Info
    let szl_req: &[u8] = &[
        0x03, 0x00, 0x00, 0x21, 0x02, 0xF0, 0x80, 0x32, 0x07, 0x00, 0x00, 0x05, 0x00, 0x00, 0x08,
        0x00, 0x08, 0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00, 0xFF, 0x09, 0x00, 0x04, 0x00,
        0x11, 0x00, 0x01, // SZL-ID: 0x0011 (Module identification)
    ];

    if timeout(Duration::from_secs(3), stream.write_all(szl_req))
        .await
        .is_ok()
    {
        if let Ok(Ok(n)) = timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
            if n > 30 {
                let szl_data = &buf[32..n];
                let info = String::from_utf8_lossy(szl_data)
                    .chars()
                    .filter(|c| c.is_ascii_graphic())
                    .collect::<String>();
                if !info.is_empty() {
                    device.model = Some(info.chars().take(50).collect());
                    device.data.push((
                        "SZL Module Info".into(),
                        device.model.clone().unwrap_or_default(),
                    ));
                }
            }
        }
    }

    device.vulns.push(IotVuln {
        vuln_type:   "Siemens S7 Unauthenticated Access".into(),
        description: "S7comm (port 102) accessible sans authentification — lecture/écriture des données process possible. CVE-2019-13945 applicable selon firmware.".into(),
        severity:    "CRITICAL".into(),
        evidence:    format!("Setup Communication réussi sur {}:{}", host, port),
    });

    println!(
        "  \x1b[38;5;196m[S7-PLC]\x1b[0m {}:{} — Siemens PLC détecté ⚠️ CRITIQUE",
        host, port
    );

    Some(device)
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. EtherNet/IP (port 44818) — Allen Bradley / Rockwell
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_ethernet_ip(host: &str, port: u16) -> Option<IotDevice> {
    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    // EtherNet/IP List Identity (0x63)
    let list_identity: &[u8] = &[
        0x63, 0x00, // Command: List Identity
        0x00, 0x00, // Length
        0x00, 0x00, 0x00, 0x00, // Session Handle
        0x00, 0x00, 0x00, 0x00, // Status
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender Context
        0x00, 0x00, 0x00, 0x00, // Options
    ];

    timeout(Duration::from_secs(3), stream.write_all(list_identity))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 1024];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n < 24 {
        return None;
    }

    let mut device = IotDevice {
        host: host.to_string(),
        port,
        protocol: "EtherNet/IP (CIP)".into(),
        vendor: None,
        model: None,
        firmware: None,
        description: None,
        vulns: Vec::new(),
        data: Vec::new(),
    };

    // Parser la réponse List Identity
    if n > 44 {
        // Vendor ID (offset 36-37)
        let vendor_id = u16::from_le_bytes([buf[36], buf[37]]);
        device.vendor = Some(format!("Vendor ID: {}", vendor_id));

        // Product type (offset 38-39)
        let product_type = u16::from_le_bytes([buf[38], buf[39]]);
        device
            .data
            .push(("Product Type".into(), format!("{}", product_type)));

        // Product name (variable length at end)
        if n > 50 {
            let name_len = buf[50] as usize;
            if 51 + name_len <= n {
                let name = String::from_utf8_lossy(&buf[51..51 + name_len]).to_string();
                device.model = Some(name.clone());
                device.data.push(("Product Name".into(), name));
            }
        }

        // Firmware revision (offset 40-41)
        let fw_maj = buf[40];
        let fw_min = buf[41];
        device.firmware = Some(format!("{}.{}", fw_maj, fw_min));
    }

    device.vulns.push(IotVuln {
        vuln_type:   "EtherNet/IP Unauthenticated".into(),
        description: "EtherNet/IP CIP exposé sans authentification — identification complète de l'appareil, lecture des tags process.".into(),
        severity:    "HIGH".into(),
        evidence:    format!("List Identity réussi: {} bytes retournés", n),
    });

    println!(
        "  \x1b[38;5;196m[EtherNet/IP]\x1b[0m {}:{} — PLC Rockwell/Allen-Bradley",
        host, port
    );

    Some(device)
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. CoAP (port 5683 UDP) — IoT constrained devices
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_coap(host: &str, port: u16) -> Option<IotDevice> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let addr = format!("{}:{}", host, port);

    // CoAP GET /.well-known/core (resource discovery)
    // Version=1, Type=CON(0), TKL=1, Code=0.01(GET), MID=0x0001
    let coap_get: &[u8] = &[
        0x41, // Version=1, Type=CON, TKL=1
        0x01, // Code: GET (0.01)
        0x00, 0x01, // Message ID
        0xAB, // Token
        0xB8, // Option Delta=11 (Uri-Path), Length=8
        b'.', b'w', b'e', b'l', b'l', b'-', b'k', b'n', b'o', b'w', b'n',
        0x04, // Option Delta=0, Length=4
        b'c', b'o', b'r', b'e',
    ];

    sock.send_to(coap_get, &addr).await.ok()?;

    let mut buf = vec![0u8; 2048];
    let n = match timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };

    if n < 4 {
        return None;
    }

    let code = buf[1];
    let mut device = IotDevice {
        host: host.to_string(),
        port,
        protocol: "CoAP (RFC 7252)".into(),
        vendor: None,
        model: None,
        firmware: None,
        description: None,
        vulns: Vec::new(),
        data: Vec::new(),
    };

    // Parser la réponse
    let code_str = format!("{}.{:02}", (code >> 5) & 0x07, code & 0x1F);
    device
        .data
        .push(("CoAP Response Code".into(), code_str.clone()));

    // Extraire le payload (après le header + options)
    // Simplification : chercher 0xFF marker (end of options)
    if let Some(payload_start) = buf[4..n].iter().position(|&b| b == 0xFF).map(|p| p + 5) {
        let payload = String::from_utf8_lossy(&buf[payload_start..n]).to_string();
        if !payload.is_empty() {
            device.description = Some(payload.chars().take(200).collect());
            device.data.push((
                "Resources".into(),
                device.description.clone().unwrap_or_default(),
            ));
        }
    }

    device.vulns.push(IotVuln {
        vuln_type:   "CoAP Resource Discovery Unauthenticated".into(),
        description: "CoAP permet la découverte des ressources sans authentification. Les ressources exposées peuvent inclure des capteurs, actuateurs, configuration.".into(),
        severity:    "MEDIUM".into(),
        evidence:    format!("CoAP .well-known/core response: {} bytes, code={}", n, code_str),
    });

    println!(
        "  \x1b[36m[CoAP]\x1b[0m {}:{}/UDP — {} bytes, code={}",
        host, port, n, code_str
    );

    Some(device)
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. BACnet (port 47808 UDP) — Building Automation
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_bacnet(host: &str, port: u16) -> Option<IotDevice> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let addr = format!("{}:{}", host, port);

    // BACnet Who-Is request (broadcast device discovery)
    let who_is: &[u8] = &[
        0x81, 0x0B, 0x00,
        0x0C, // BVLC: Type=BACnet/IP, Function=Original-Unicast-NPDU, Length=12
        0x01, 0x20, 0xFF, 0xFF, // NPDU: version=1, control=0x20 (expecting reply)
        0x00, 0xFF, // DNET=0xFFFF (broadcast)
        0x10, 0x08, // BACnet APDU: unconfirmed service = Who-Is (8)
    ];

    sock.send_to(who_is, &addr).await.ok()?;

    let mut buf = vec![0u8; 1024];
    let n = match timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };

    if n < 6 {
        return None;
    }

    let mut device = IotDevice {
        host: host.to_string(),
        port,
        protocol: "BACnet/IP".into(),
        vendor: None,
        model: None,
        firmware: None,
        description: None,
        vulns: Vec::new(),
        data: Vec::new(),
    };

    // Parser la réponse I-Am (APDU type 0x10, service 0x00)
    if n > 10 {
        device
            .data
            .push(("BACnet Response".into(), format!("{} bytes", n)));

        // Essayer de lire les propriétés de l'objet Device
        let read_prop: &[u8] = &[
            0x81, 0x0A, 0x00, 0x11, // BVLC
            0x01, 0x04, // NPDU
            0x00, 0x30, 0x01, // APDU: Confirmed Request, invoke-id=1
            0x0C, // Service: Read Property
            0x0C, 0x02, 0x00, 0x00, 0x00, // Object ID: Device, instance 0
            0x19, 0x4B, // Property: Model Name
        ];

        if sock.send_to(read_prop, &addr).await.is_ok() {
            if let Ok(Ok(n2)) = timeout(Duration::from_secs(2), sock.recv(&mut buf)).await {
                if n2 > 14 {
                    let model_raw = &buf[11..n2];
                    let model = model_raw
                        .iter()
                        .filter(|&&b| b.is_ascii_graphic())
                        .map(|&b| b as char)
                        .collect::<String>();
                    if !model.is_empty() {
                        device.model = Some(model.clone());
                        device.data.push(("Model Name".into(), model));
                    }
                }
            }
        }
    }

    device.vulns.push(IotVuln {
        vuln_type:   "BACnet Unauthenticated Discovery".into(),
        description: "BACnet n'implémente pas d'authentification par défaut. Permet de découvrir tous les appareils du bâtiment (HVAC, éclairage, accès) et potentiellement de les contrôler.".into(),
        severity:    "HIGH".into(),
        evidence:    format!("Who-Is répondu par {}:{} ({} bytes)", host, port, n),
    });

    println!(
        "  \x1b[36m[BACnet]\x1b[0m {}:{}/UDP — Building automation device",
        host, port
    );

    Some(device)
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. DNP3 (port 20000) — Utilities SCADA
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_dnp3(host: &str, port: u16) -> Option<IotDevice> {
    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    // DNP3 Data Link Layer + Application Layer : Read Class 0 data
    let dnp3_request: &[u8] = &[
        // Data Link Layer Header
        0x05, 0x64, // Start bytes
        0x0B, // Length
        0xC4, // Control: DIR=1, PRM=1, FCV=0, FCB=0, FC=4 (Unconfirmed User Data)
        0xFF, 0xFF, // Destination address (broadcast)
        0x00, 0x03, // Source address = 0x0300
        // CRC (simplified)
        0xB3, 0x8E, // Application Layer
        0xC0, 0x01, // App control + function code: READ (1)
        0x3C, 0x01, // Object 60-1: Class 0 Data
        0x06, // Qualifier: all objects
        // Tail CRC
        0x3A, 0xF4,
    ];

    timeout(Duration::from_secs(3), stream.write_all(dnp3_request))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 1024];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n < 6 {
        return None;
    }

    let mut device = IotDevice {
        host: host.to_string(),
        port,
        protocol: "DNP3 (IEEE 1815)".into(),
        vendor: None,
        model: None,
        firmware: None,
        description: None,
        vulns: Vec::new(),
        data: Vec::new(),
    };

    device
        .data
        .push(("DNP3 Response".into(), format!("{} bytes received", n)));

    device.vulns.push(IotVuln {
        vuln_type:   "DNP3 Unauthenticated".into(),
        description: "DNP3 sans Secure Authentication v5 (SAv5) — contrôle de RTUs/IEDs électriques sans authentification. Permet lecture de mesures et envoi de commandes (trip breakers).".into(),
        severity:    "CRITICAL".into(),
        evidence:    format!("DNP3 répondu sur {}:{} ({} bytes)", host, port, n),
    });

    println!(
        "  \x1b[38;5;196m[DNP3]\x1b[0m {}:{} — SCADA/Utilities IED ⚠️ CRITIQUE",
        host, port
    );

    Some(device)
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. MQTT Deep Scan — Enumération topics + hijack
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttTopicResult {
    pub topic: String,
    pub message: Option<String>,
    pub retained: bool,
}

pub async fn scan_mqtt_topics(host: &str, port: u16) -> (Vec<MqttTopicResult>, Vec<IotVuln>) {
    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut stream)) = timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await
    else {
        return (Vec::new(), Vec::new());
    };

    let mut topics = Vec::new();
    let mut vulns = Vec::new();

    // MQTT CONNECT (anonymous)
    let connect: &[u8] = &[
        0x10, 0x11, // CONNECT, remaining=17
        0x00, 0x04, b'M', b'Q', b'T', b'T', // Protocol name
        0x04, // Protocol level 4
        0x02, // Flags: clean session
        0x00, 0x3C, // Keepalive=60s
        0x00, 0x07, b'D', b'I', b'A', b'P', b'I', b'L', b'E', // Client ID
    ];

    if timeout(Duration::from_secs(3), stream.write_all(connect))
        .await
        .is_err()
    {
        return (topics, vulns);
    };

    let mut buf = vec![0u8; 512];
    let Ok(Ok(n)) = timeout(Duration::from_secs(3), stream.read(&mut buf)).await else {
        return (topics, vulns);
    };

    if n < 4 || buf[0] != 0x20 || buf[3] != 0x00 {
        return (topics, vulns); // CONNACK rejected
    }

    // Connexion acceptée — broker vulnérable
    vulns.push(IotVuln {
        vuln_type:   "MQTT Anonymous Access".into(),
        description: "Broker MQTT accepte les connexions sans authentification. Subscription à tous les topics possible.".into(),
        severity:    "HIGH".into(),
        evidence:    "CONNACK rc=0 (Connection Accepted) sans credentials".into(),
    });

    // Souscrire à # (tous les topics)
    let subscribe: &[u8] = &[
        0x82, // SUBSCRIBE
        0x08, // Remaining length
        0x00, 0x01, // Packet ID
        0x00, 0x01, b'#', // Topic filter: # (all)
        0x00, // QoS 0
    ];

    let _ = timeout(Duration::from_secs(2), stream.write_all(subscribe)).await;

    // Lire les messages pendant 3 secondes
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut msg_buf = vec![0u8; 4096];

    while tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(500), stream.read(&mut msg_buf)).await {
            Ok(Ok(n)) if n > 4 => {
                if msg_buf[0] & 0xF0 == 0x30 {
                    // PUBLISH packet
                    let retained = (msg_buf[0] & 0x01) != 0;
                    let topic_len = u16::from_be_bytes([msg_buf[2], msg_buf[3]]) as usize;
                    if topic_len + 4 <= n {
                        let topic = String::from_utf8_lossy(&msg_buf[4..4 + topic_len]).to_string();
                        let msg = String::from_utf8_lossy(&msg_buf[4 + topic_len..n]).to_string();
                        let msg_opt = if msg.is_empty() {
                            None
                        } else {
                            Some(msg.chars().take(200).collect())
                        };

                        println!(
                            "  \x1b[36m[MQTT TOPIC]\x1b[0m {} → {}",
                            topic,
                            msg_opt.as_deref().unwrap_or("(empty)")
                        );
                        topics.push(MqttTopicResult {
                            topic,
                            message: msg_opt,
                            retained,
                        });

                        // Détecter topics sensibles
                        if topics.len() > 100 {
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Détecter topics sensibles
    let sensitive_patterns = [
        "password",
        "credential",
        "token",
        "key",
        "admin",
        "secret",
        "config",
    ];
    for t in &topics {
        if sensitive_patterns
            .iter()
            .any(|p| t.topic.to_lowercase().contains(p))
        {
            vulns.push(IotVuln {
                vuln_type: "MQTT Sensitive Topic Exposed".into(),
                description: format!(
                    "Topic sensible '{}' accessible sans authentification",
                    t.topic
                ),
                severity: "CRITICAL".into(),
                evidence: t
                    .message
                    .as_deref()
                    .unwrap_or("(no message)")
                    .chars()
                    .take(100)
                    .collect(),
            });
        }
    }

    // Disconnect proprement
    let _ = stream.write_all(&[0xE0, 0x00]).await;

    (topics, vulns)
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. OPC-UA (port 4840)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_opcua(host: &str, port: u16) -> Option<IotDevice> {
    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    // OPC-UA Hello Message
    let hello: &[u8] = &[
        b'H', b'E', b'L', b'F', // Message type: HELF
        0x28, 0x00, 0x00, 0x00, // Message size = 40
        0x00, 0x00, 0x00, 0x00, // Protocol version
        0x00, 0x00, 0x01, 0x00, // Receive buffer size
        0x00, 0x00, 0x01, 0x00, // Send buffer size
        0x00, 0x00, 0x00, 0x00, // Max message size
        0x00, 0x00, 0x00, 0x00, // Max chunk count
        // Endpoint URL: "opc.tcp://localhost:4840"
        0x16, 0x00, 0x00, 0x00, b'o', b'p', b'c', b'.', b't', b'c', b'p', b':', b'/', b'/', b'l',
        b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', b':', b'4', b'8', b'4', b'0',
    ];

    timeout(Duration::from_secs(3), stream.write_all(hello))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 512];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n < 8 {
        return None;
    }

    let msg_type = String::from_utf8_lossy(&buf[..4]).to_string();

    let mut device = IotDevice {
        host: host.to_string(),
        port,
        protocol: "OPC-UA".into(),
        vendor: None,
        model: None,
        firmware: None,
        description: None,
        vulns: Vec::new(),
        data: Vec::new(),
    };

    device
        .data
        .push(("OPC-UA Message Type".into(), msg_type.clone()));
    device
        .data
        .push(("Response Size".into(), format!("{} bytes", n)));

    if msg_type.starts_with("ACK") || msg_type.starts_with("ERR") {
        device.vulns.push(IotVuln {
            vuln_type:   "OPC-UA Server Exposed".into(),
            description: "Serveur OPC-UA accessible — tenter GetEndpoints sans auth pour découvrir les services industriels disponibles.".into(),
            severity:    "HIGH".into(),
            evidence:    format!("OPC-UA Hello responded: {} ({}B)", msg_type, n),
        });
        println!(
            "  \x1b[36m[OPC-UA]\x1b[0m {}:{} — Industrial server ({})",
            host, port, msg_type
        );
    }

    Some(device)
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Scan IoT/SCADA complet
// ─────────────────────────────────────────────────────────────────────────────

pub async fn full_iot_scan(hosts: &[&str]) -> IotScanReport {
    let mut report = IotScanReport::default();

    println!(
        "\n  \x1b[38;5;196m[IOT/SCADA]\x1b[0m Scan sur {} hôte(s)",
        hosts.len()
    );

    for &host in hosts {
        print!("  → {} ... ", host);

        let protocols: Vec<(&str, u16)> = vec![
            ("modbus", 502),
            ("siemens-s7", 102),
            ("dnp3", 20000),
            ("ethernet-ip", 44818),
            ("opc-ua", 4840),
            ("mqtt", 1883),
            ("bacnet", 47808),
            ("coap", 5683),
        ];

        let mut found = 0usize;

        for (proto, port) in &protocols {
            match *proto {
                "modbus" => {
                    if let Some(dev) = scan_modbus(host, *port).await {
                        report
                            .open_ports
                            .push((host.to_string(), *port, "Modbus TCP".into()));
                        report.devices.push(dev);
                        found += 1;
                    }
                }
                "siemens-s7" => {
                    if let Some(dev) = scan_siemens_s7(host, *port).await {
                        report
                            .open_ports
                            .push((host.to_string(), *port, "Siemens S7".into()));
                        report.devices.push(dev);
                        found += 1;
                    }
                }
                "dnp3" => {
                    if let Some(dev) = scan_dnp3(host, *port).await {
                        report
                            .open_ports
                            .push((host.to_string(), *port, "DNP3".into()));
                        report.devices.push(dev);
                        found += 1;
                    }
                }
                "ethernet-ip" => {
                    if let Some(dev) = scan_ethernet_ip(host, *port).await {
                        report
                            .open_ports
                            .push((host.to_string(), *port, "EtherNet/IP".into()));
                        report.devices.push(dev);
                        found += 1;
                    }
                }
                "opc-ua" => {
                    if let Some(dev) = scan_opcua(host, *port).await {
                        report
                            .open_ports
                            .push((host.to_string(), *port, "OPC-UA".into()));
                        report.devices.push(dev);
                        found += 1;
                    }
                }
                "mqtt" => {
                    let (topics, vulns) = scan_mqtt_topics(host, *port).await;
                    if !vulns.is_empty() {
                        report
                            .open_ports
                            .push((host.to_string(), *port, "MQTT".into()));
                        report.devices.push(IotDevice {
                            host: host.to_string(),
                            port: *port,
                            protocol: "MQTT".into(),
                            vendor: None,
                            model: None,
                            firmware: None,
                            description: Some(format!("{} topics découverts", topics.len())),
                            vulns,
                            data: topics
                                .iter()
                                .map(|t| (t.topic.clone(), t.message.clone().unwrap_or_default()))
                                .collect(),
                        });
                        found += 1;
                    }
                }
                "bacnet" => {
                    if let Some(dev) = scan_bacnet(host, *port).await {
                        report
                            .open_ports
                            .push((host.to_string(), *port, "BACnet".into()));
                        report.devices.push(dev);
                        found += 1;
                    }
                }
                "coap" => {
                    if let Some(dev) = scan_coap(host, *port).await {
                        report
                            .open_ports
                            .push((host.to_string(), *port, "CoAP".into()));
                        report.devices.push(dev);
                        found += 1;
                    }
                }
                _ => {}
            }
        }

        if found == 0 {
            println!("\x1b[90maucun appareil IoT/SCADA détecté\x1b[0m");
        } else {
            println!("\x1b[38;5;196m{} appareil(s) trouvé(s) ⚠️\x1b[0m", found);
        }
    }

    let total_vulns: usize = report.devices.iter().map(|d| d.vulns.len()).sum();
    println!(
        "\n  \x1b[36m[IOT/SCADA]\x1b[0m {} appareil(s), {} vuln(s)",
        report.devices.len(),
        total_vulns
    );

    report
}
