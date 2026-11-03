//! Multi-provider LLM client for the Network Redteam Grapher.
//! LLM client multi-provider (OpenAI, OpenRouter, Ollama)
#![allow(unused_imports, dead_code)]
//! - Single trait `LlmClient` with a canonical async `chat` method → String.
//! - Exponential backoff + full-jitter retries for transient failures.
//! - Prompt templates are embedded Rust `format!` strings (versioned with the
//!   code). Structured outputs are requested via JSON-mode / system prompt
//!   JSON schema, with an offline regex-based fallback extractor so the caller
//!   always gets a parseable JSON value even when the model rambles.

use async_trait::async_trait;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

// ---------------------------------------------------------------
// Public configuration
// ---------------------------------------------------------------

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LlmProvider {
    OpenAi,
    OpenRouter,
    Ollama,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    pub provider: LlmProvider,
    pub model: String,
    pub api_base: String,
    pub api_key: Option<String>,
    pub temperature: f32,
    pub top_p: f32,
    pub max_tokens: u32,
    pub timeout: Duration,
    pub retries: u32,
    pub json_mode: bool,
}

// ── NVIDIA Nemotron — hiérarchie de modèles officielle (OpenRouter / Ollama) ──
// https://registry.ngc.nvidia.com/orgs/nvidia/teams/nemo/models
// Ordre de fallback : le plus grand dispo → plus petit si indisponible / rate-limité
// NOTE: OpenRouter 2026 — les anciens IDs (nemotron-4-340b, nemotron-4-15b, nemotron-mini)
//       sont RETIRÉS (404). Les IDs valides portent le suffixe :free pour le tier gratuit.
pub const NEMOTRON_OPENROUTER_CASCADE: &[&str] = &[
    "nvidia/nemotron-3-ultra-550b-a55b:free", // Flagship — 1M ctx, meilleure conformité JSON
    "nvidia/nemotron-3-super-120b-a12b:free", // Mid-tier — 256K ctx, bon compromis coût/précision
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free", // Léger — reasoning, low-latence
    "nvidia/nemotron-3.5-lightning:free",     // Dernier recours : ultra-rapide
];
pub const NEMOTRON_OLLAMA_TAGS: &[&str] = &[
    "nemotron:70b-instruct-q4_K_M",
    "nemotron:34b-instruct-q5_K_M",
    "nemotron:12b-instruct-q4_0",
    "nemotron:mini-instruct-q5_K_M",
];

impl Default for LlmConfig {
    fn default() -> Self {
        // Défaut : Nemotron 3 Ultra 550B via OpenRouter (tier gratuit 2026)
        // Lecture des variables d'environnement et construction CLI → effectuée DANS main.rs
        Self {
            provider: LlmProvider::OpenRouter,
            model: "nvidia/nemotron-3-ultra-550b-a55b:free".into(),
            api_base: "https://openrouter.ai/api/v1".into(),
            api_key: None,
            temperature: 0.1,
            top_p: 0.9,
            max_tokens: 4096,
            timeout: Duration::from_secs(120),
            retries: 4,
            json_mode: true,
        }
    }
}

// ---------------------------------------------------------------
// Structured analysis / report outputs
// ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TargetAnalysis {
    pub host: String,
    pub port: u16,
    pub summary: String,
    pub recommended_exploits: Vec<ExploitSuggestion>,
    pub attack_path_notes: Vec<String>,
    pub severity_bump_reasons: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitSuggestion {
    pub id: String,
    pub name: String,
    pub rationale: String,
    pub prerequisites: Vec<String>,
    pub estimated_probability: f32,
    pub impact: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AiReport {
    pub executive_summary: String,
    pub risk_narrative: String,
    pub top_findings: Vec<TopFinding>,
    pub remediation_plan: RemediationPlan,
    pub attacker_scenario: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopFinding {
    pub title: String,
    pub severity: String,
    pub affected: String,
    pub evidence: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RemediationPlan {
    pub immediate: Vec<String>,
    pub short_term: Vec<String>,
    pub long_term: Vec<String>,
}

// ---------------------------------------------------------------
// Trait & providers
// ---------------------------------------------------------------

#[async_trait]
pub trait LlmClient: Send + Sync + 'static {
    async fn chat(&self, messages: Vec<ChatMessage>, expect_json: bool)
        -> Result<String, LlmError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug)]
pub enum LlmError {
    Config(String),
    Network(String),
    Provider(String, u16, String),
    Parse(String),
    RetryExhausted(String),
}
impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmError::Config(s) => write!(f, "LLM config error: {s}"),
            LlmError::Network(s) => write!(f, "LLM network error: {s}"),
            LlmError::Provider(p, c, b) => write!(
                f,
                "LLM provider {p} error HTTP {c}: {}",
                &b[..b.len().min(300)]
            ),
            LlmError::Parse(s) => write!(f, "LLM parse error: {s}"),
            LlmError::RetryExhausted(s) => write!(f, "LLM retries exhausted: {s}"),
        }
    }
}
impl std::error::Error for LlmError {}

/// Client LLM factice : **aucun appel réseau**, réponse déterministe.
/// Activé par `NRTG_TEST_MODE=1` (cf. [`build_client`]). Permet d'exécuter les
/// agents (planification, analyse) en CI/hors-ligne sans clé API ni socket.
///
/// La réponse renvoyée est `{}` (JSON vide, tolérant au parsing) ou la valeur
/// de `NRTG_LLM_MOCK_RESPONSE` si définie — utile pour scripter un plan précis
/// dans un test.
pub struct MockLlmClient {
    response: String,
}

impl MockLlmClient {
    pub fn new() -> Self {
        let response = std::env::var("NRTG_LLM_MOCK_RESPONSE")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "{}".to_string());
        Self { response }
    }
}

impl Default for MockLlmClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LlmClient for MockLlmClient {
    async fn chat(
        &self,
        _messages: Vec<ChatMessage>,
        _expect_json: bool,
    ) -> Result<String, LlmError> {
        Ok(self.response.clone())
    }
}

/// Construit un client LLM en `Box<dyn LlmClient>` à partir d'une `LlmConfig`.
/// Inclut une validation DÉFENSIVE des entrées pour des erreurs explicites
/// immédiates (pas de 401 silencieux, pas d'URL invalide).
///
/// NOTE SUR LA COERCION : On utilise un `let boxed: Box<dyn LlmClient> = Box::new(inner);`
/// avant `Ok(boxed)` pour forcer l'unsized coercion de manière stable et déterministe
/// (évite E0308 / E0606 dans les match multi-branches sur certaines toolchains).
/// Log un avertissement (non-blocking) si Ollama est demandé sur un host non-local.
pub fn build_client(cfg: &LlmConfig) -> Result<Box<dyn LlmClient>, LlmError> {
    build_client_with(cfg, crate::main_helpers::test_mode_enabled())
}

/// Variante testable de [`build_client`] : `test_mode` est injecté (au lieu
/// d'être lu depuis l'environnement) pour des tests déterministes sans mutation
/// de variables globales.
///
/// En `test_mode`, renvoie un [`MockLlmClient`] : AUCUN appel réseau. Les
/// validateurs de provider (api_key obligatoire, etc.) sont volontairement
/// court-circuités — l'objectif est de rendre les agents exécutables en CI.
pub fn build_client_with(cfg: &LlmConfig, test_mode: bool) -> Result<Box<dyn LlmClient>, LlmError> {
    if test_mode {
        let boxed: Box<dyn LlmClient> = Box::new(MockLlmClient::new());
        return Ok(boxed);
    }

    let base = cfg.api_base.to_ascii_lowercase();
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err(LlmError::Config(format!(
            "api_base invalide: '{}' — doit commencer par http:// ou https://",
            cfg.api_base
        )));
    }
    if cfg.timeout == Duration::ZERO {
        return Err(LlmError::Config(
            "timeout LLM invalide (Duration::ZERO) — utiliser minimum 1s".into(),
        ));
    }
    if cfg.max_tokens == 0 {
        return Err(LlmError::Config(
            "max_tokens LLM invalide (0) — minimum 1 token requis".into(),
        ));
    }
    let _ = cfg.temperature.clamp(0.0, 2.0);
    let _ = cfg.top_p.clamp(0.0, 1.0);

    match cfg.provider {
        LlmProvider::OpenAi | LlmProvider::OpenRouter => {
            if cfg.api_key.is_none() {
                return Err(LlmError::Config(format!(
                    "provider {:?} nécessite api_key — renseigner --llm-api-key ou vars env OPENROUTER_API_KEY / OPENAI_API_KEY",
                    cfg.provider
                )));
            }
            let inner = OpenAiCompatibleClient::new(cfg)?;
            let boxed: Box<dyn LlmClient> = Box::new(inner);
            Ok(boxed)
        }
        LlmProvider::Ollama => {
            if !(base.contains("localhost") || base.contains("127.0.0.1") || base.contains("[::1]"))
            {
                eprintln!(
                    "    ⚠️  LLM provider Ollama mais api_base n'est pas localhost ({}) — proxy distant attendu.",
                    cfg.api_base
                );
            }
            let inner = OllamaClient::new(cfg)?;
            let boxed: Box<dyn LlmClient> = Box::new(inner);
            Ok(boxed)
        }
    }
}

// ---- OpenAI-compatible ----

struct OpenAiCompatibleClient {
    cfg: LlmConfig,
    client: reqwest::Client,
    label: &'static str,
}

impl OpenAiCompatibleClient {
    fn new(cfg: &LlmConfig) -> Result<Self, LlmError> {
        let client = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .connect_timeout(Duration::from_secs(15))
            .user_agent("nrtg-llm/2.0")
            .build()
            .map_err(|e| LlmError::Config(format!("reqwest: {e}")))?;
        let label = match cfg.provider {
            LlmProvider::OpenRouter => "openrouter",
            _ => "openai",
        };
        Ok(Self {
            cfg: cfg.clone(),
            client,
            label,
        })
    }
}

fn should_fallback_model(status: u16, body: &str) -> bool {
    if status == 404 {
        return true;
    }
    if status == 422 && body.contains("No endpoints found") {
        return true;
    }
    if status == 400 && body.contains("model") {
        return true;
    }
    if status == 429 && body.contains("rate limit") {
        return true;
    }
    false
}

fn openrouter_pick_fallback(requested: &str) -> Option<&'static str> {
    let cascade = NEMOTRON_OPENROUTER_CASCADE;
    if let Some(pos) = cascade.iter().position(|m| *m == requested) {
        cascade.get(pos + 1).copied()
    } else {
        cascade.first().copied()
    }
}

pub fn ollama_pick_nemotron_fallback(requested_tag: &str) -> Option<&'static str> {
    let cascade = NEMOTRON_OLLAMA_TAGS;
    if let Some(pos) = cascade.iter().position(|t| *t == requested_tag) {
        cascade.get(pos + 1).copied()
    } else {
        cascade.first().copied()
    }
}

#[async_trait]
impl LlmClient for OpenAiCompatibleClient {
    async fn chat(
        &self,
        messages: Vec<ChatMessage>,
        expect_json: bool,
    ) -> Result<String, LlmError> {
        let mut current_model = self.cfg.model.clone();
        let mut first_error: Option<LlmError> = None;
        let max_attempts = NEMOTRON_OPENROUTER_CASCADE.len().max(2);
        for attempt in 0..max_attempts {
            let result = retry_with_backoff(self.cfg.retries, || async {
                let mut body = json!({
                    "model": current_model.clone(),
                    "messages": messages.clone(),
                    "temperature": self.cfg.temperature,
                    "top_p": self.cfg.top_p,
                    "max_tokens": self.cfg.max_tokens,
                });
                if expect_json && matches!(self.cfg.provider, LlmProvider::OpenAi) {
                    body["response_format"] = json!({ "type": "json_object" });
                }
                let mut req = self
                    .client
                    .post(format!(
                        "{}/chat/completions",
                        self.cfg.api_base.trim_end_matches('/')
                    ))
                    .json(&body);
                if let Some(k) = &self.cfg.api_key {
                    req = req.bearer_auth(k);
                }
                if matches!(self.cfg.provider, LlmProvider::OpenRouter) {
                    req = req
                        .header("HTTP-Referer", "https://nrtg.local")
                        .header("X-Title", "Network Redteam Grapher");
                }
                let resp = req
                    .send()
                    .await
                    .map_err(|e| LlmError::Network(e.to_string()))?;
                let status = resp.status().as_u16();
                let text = resp
                    .text()
                    .await
                    .map_err(|e| LlmError::Network(e.to_string()))?;
                if !(200..=299).contains(&status) {
                    return Err(LlmError::Provider(self.label.into(), status, text));
                }
                let v: Value = serde_json::from_str(&text)
                    .map_err(|e| LlmError::Parse(format!("json: {e}")))?;
                let content = v["choices"][0]["message"]["content"]
                    .as_str()
                    .ok_or_else(|| LlmError::Parse("missing choices[0].message.content".into()))?
                    .to_string();
                Ok(content)
            })
            .await;
            match result {
                Ok(s) => return Ok(s),
                Err(e) => {
                    if matches!(self.cfg.provider, LlmProvider::OpenRouter)
                        && matches!(e, LlmError::Provider(_, s, ref b) if should_fallback_model(s, b))
                    {
                        if let Some(fallback) = openrouter_pick_fallback(&current_model) {
                            if fallback != current_model.as_str() {
                                tracing::warn!(target: "llm",
                                    model=%current_model,
                                    fallback=%fallback,
                                    "OpenRouter model unavailable — switching to fallback model"
                                );
                                eprintln!(
                                    "    ⚠️  Modèle '{}' indisponible (404) → fallback sur '{}'",
                                    current_model, fallback
                                );
                                first_error = Some(e);
                                current_model = fallback.to_string();
                                continue;
                            }
                        }
                    }
                    return Err(e);
                }
            }
        }
        Err(first_error.unwrap_or_else(|| LlmError::Config("fallback exhausted".into())))
    }
}

// ---- Ollama ----

struct OllamaClient {
    cfg: LlmConfig,
    client: reqwest::Client,
}
impl OllamaClient {
    fn new(cfg: &LlmConfig) -> Result<Self, LlmError> {
        let client = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .connect_timeout(Duration::from_secs(15))
            .pool_idle_timeout(Duration::from_secs(60))
            .http1_title_case_headers()
            .user_agent(concat!("nrtg-llm-ollama/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| LlmError::Config(format!("reqwest ollama: {e}")))?;
        Ok(Self {
            cfg: cfg.clone(),
            client,
        })
    }
}

#[async_trait]
impl LlmClient for OllamaClient {
    async fn chat(
        &self,
        messages: Vec<ChatMessage>,
        expect_json: bool,
    ) -> Result<String, LlmError> {
        let mut current_model = self.cfg.model.clone();
        let mut first_error: Option<LlmError> = None;
        let max_attempts = NEMOTRON_OLLAMA_TAGS.len().max(1);
        for attempt in 0..max_attempts {
            let result = retry_with_backoff(self.cfg.retries, || async {
                let mut body = json!({
                    "model": current_model.clone(),
                    "messages": messages.clone(),
                    "stream": false,
                    "options": {
                        "temperature": self.cfg.temperature,
                        "top_p": self.cfg.top_p,
                        "num_predict": self.cfg.max_tokens,
                        "num_ctx": 32768,
                    },
                });
                if expect_json {
                    body["format"] = json!("json");
                }
                let url = format!("{}/api/chat", self.cfg.api_base.trim_end_matches('/'));
                let resp = self
                    .client
                    .post(&url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| LlmError::Network(e.to_string()))?;
                let status = resp.status().as_u16();
                let text = resp
                    .text()
                    .await
                    .map_err(|e| LlmError::Network(e.to_string()))?;
                if !(200..=299).contains(&status) {
                    return Err(LlmError::Provider("ollama".into(), status, text));
                }
                let v: Value = serde_json::from_str(&text)
                    .map_err(|e| LlmError::Parse(format!("json: {e}")))?;
                let content = v["message"]["content"]
                    .as_str()
                    .ok_or_else(|| LlmError::Parse("missing message.content".into()))?
                    .to_string();
                Ok(content)
            })
            .await;
            match result {
                Ok(s) => return Ok(s),
                Err(e) => {
                    let should_fallback = matches!(&e, LlmError::Provider(_, s, b)
                        if *s == 404 || b.contains("model") || b.contains("not found")
                    );
                    if attempt < max_attempts - 1 && should_fallback {
                        if let Some(fb) = ollama_pick_nemotron_fallback(&current_model) {
                            eprintln!(
                                "    ⚠️  Ollama modèle '{}' indisponible → fallback sur '{}'",
                                current_model, fb
                            );
                            first_error = Some(e);
                            current_model = fb.to_string();
                            continue;
                        }
                    }
                    return Err(e);
                }
            }
        }
        Err(first_error
            .unwrap_or_else(|| LlmError::Config("ollama nemotron cascade exhausted".into())))
    }
}

// ---------------------------------------------------------------
// Retry helper: exponential backoff + full jitter
// ---------------------------------------------------------------

async fn retry_with_backoff<Fut, F>(retries: u32, mut f: F) -> Result<String, LlmError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<String, LlmError>>,
{
    let mut last_err: Option<LlmError> = None;
    for attempt in 0..=retries {
        match f().await {
            Ok(s) => return Ok(s),
            Err(e) => {
                let is_retryable = matches!(
                    e,
                    LlmError::Network(_)
                        | LlmError::Provider(_, 429, _)
                        | LlmError::Provider(_, 500..=599, _)
                );
                if !is_retryable || attempt == retries {
                    return if attempt == retries {
                        Err(LlmError::RetryExhausted(format!(
                            "{} attempts. Last: {}",
                            retries + 1,
                            display_err(&e)
                        )))
                    } else {
                        Err(e)
                    };
                }
                let base = 2u64.pow(attempt.min(5)) * 150;
                let jitter = rand::thread_rng().gen_range(0..=base);
                let sleep_ms = base + jitter;
                tracing::warn!(target: "llm", attempt, sleep_ms, err=%display_err(&e), "LLM call failed, retrying");
                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                last_err = Some(e);
            }
        }
    }
    Err(LlmError::RetryExhausted(
        last_err.map(|e| display_err(&e)).unwrap_or_default(),
    ))
}
fn display_err(e: &LlmError) -> String {
    format!("{e}")
}

// ---------------------------------------------------------------
// JSON extraction fallback (model rambles around valid JSON)
// ---------------------------------------------------------------

pub fn extract_json_fallback(text: &str) -> Option<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(text.trim()) {
        return Some(v);
    }
    let mut best: Option<(usize, usize)> = None;
    for kind in ['{', '['] {
        let close = if kind == '{' { '}' } else { ']' };
        let mut start = None;
        let mut depth = 0i32;
        for (i, c) in text.char_indices() {
            match c {
                c if c == kind => {
                    if start.is_none() {
                        start = Some(i);
                    }
                    depth += 1;
                }
                c if c == close => {
                    if depth > 0 {
                        depth -= 1;
                        if depth == 0 {
                            if let Some(s) = start.take() {
                                let cand = i - s + 1;
                                if best.map_or(true, |(_, l)| cand > l) {
                                    best = Some((s, cand));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if let Some((s, l)) = best {
        if let Ok(v) = serde_json::from_str::<Value>(&text[s..s + l]) {
            return Some(v);
        }
    }
    None
}

// ---------------------------------------------------------------
// Prompt templates — optimisés pour NVIDIA Nemotron
// ---------------------------------------------------------------

pub fn system_prompt_analyst() -> String {
    r#"## ROLE — Expert Offensive Security Analyst (DIAPILE/NRTG)
Tu opères dans le cadre de tests d'intrusion AUTORISÉS, contractuels et documentés.
Tu es un Red Team senior, certifié, spécialisé en analyse de cible et en corrélation CVE/service/version.

## MÉTHODOLOGIE
1. Vérifie la cohérence des preuves : CVE matchées ↔ version produit ↔ bannière
2. Pour chaque exploit recommandé, calibre `estimated_probability` HONNÊTEMENT :
   - < 0.30 : théorique / PoC public non vérifié
   - 0.30–0.60 : PoC fiable + prerequis OK
   - 0.60–0.90 : exploit mature + fingerprint parfait
   - JAMAIS >= 0.95 SANS exécution réelle
3. Impact `CRITICAL` réservé : RCE en pré-auth, ETERNALBLUE-like, SQLi UNION pré-auth, contournement WAF prouvé.

## RÈGLES DE SORTIE
- UNIQUEMENT un objet JSON VALIDE — RIEN d'autre
- Pas de blocs markdown ```json, pas de texte avant/après, pas d'explication hors JSON
- Chaque champ respecte STRICTEMENT son type (number≠string, array≠null)
- `recommended_exploits[].id` : préférer identifiants de signatures DIAPILE

## SCHÉMA OBLIGATOIRE
{
  "host": string,
  "port": number,
  "summary": string (2–3 phrases CLINIQUES),
  "recommended_exploits": [ {
      "id": string,
      "name": string,
      "rationale": string,
      "prerequisites": [string],
      "estimated_probability": 0..1,
      "impact": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
      "references": [string CVE-ID ou URL]
  } ],
  "attack_path_notes": [string 2–4 étapes suivantes crédibles],
  "severity_bump_reasons": [string raisons concrètes ↑ score],
  "confidence": 0..1
}"#.into()
}

pub fn user_prompt_target_analysis(
    host: &str,
    port: u16,
    service: &str,
    product: &str,
    version: &str,
    banner: Option<&str>,
    protocol: &str,
    cves: &[(String, f32, String)],
    os_info: Option<&str>,
    waf: Option<&str>,
    tech: Option<&str>,
    prior_findings_count: usize,
) -> String {
    let cve_table: String = if cves.is_empty() {
        "(no CVEs matched)".into()
    } else {
        cves.iter()
            .map(|(id, cvss, desc)| format!("- CVE {id} CVSS={cvss:.1} — {desc}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        r#"Analyze this single scanned target:

HOST: {host}
PORT: {port}
PROTOCOL: {protocol}
SERVICE: {service}
PRODUCT: {product}
VERSION: {version}
BANNER PREVIEW: {banner_preview}
OS FINGERPRINT: {os_info}
WAF DETECTION: {waf}
TECH STACK: {tech}
PRIOR EXPLOIT FINDINGS ON THIS HOST: {prior_findings_count}
MATCHED CVEs:
{cve_table}

Rules:
- recommended_exploits.id: prefer the NRTG exploit signature id format when you can guess it (e.g. REDIS-ANON-PING, HTTP-PATH-TRAV-SAFE, SSH-WEAK-KEX, HTTP-DEFAULT-ADMIN-BASIC, MONGO-NOAUTH, FTP-ANON-LOGIN), otherwise make a sane CVSS-like id.
- estimated_probability: honest estimate 0..1 given the evidence. Always < 0.95 without real execution proof.
- severity_bump_reasons: concrete reasons the score should move up vs default (e.g. "public PoC exists for CVE-2024-XXXX with reliable exploit", "no WAF on admin panel", "default creds for CMS version").
- attack_path_notes: 2–4 plausible lateral-movement or privilege-escalation NEXT-STEPS a red teamer would try, e.g. "if creds harvested on this web host → pivot to adjacent DB tier".
- NEVER include destructive, write, ransomware, or DoS payloads. All recommendations stay READ-ONLY and post-authentication at worst.
- Keep each field concise.
"#,
        banner_preview = banner.map(|b| &b[..b.len().min(240)]).unwrap_or("(none)"),
        os_info = os_info.unwrap_or("unknown"),
        waf = waf.unwrap_or("none detected"),
        tech = tech.unwrap_or("n/a"),
    )
}

pub fn system_prompt_report_writer() -> String {
    r#"## ROLE — Rédacteur Rapport Pentest Senior (DIAPILE/NRTG — Red Team)
Public mixte : DSI/CISO (exécutif) + ingénieurs systèmes & sécurité (technique).
Ton style : **CLINIQUE, PRÉCIS, SANS FUD, SANS HYPERBOLE**.

## MÉTHODOLOGIE DE RAPPORT (ISO 27001 / PTES)
1. **Grounding strict** : tu ne parles QUE des vulnérabilités, ports, services, hôtes PRÉSENTS dans le CONTEXT.
2. **`top_findings` triés par sévérité décroissante** (CRITICAL → INFO), 5 à 8 findings exactement.
3. **`remediation_plan` 3 horizons alignés coût/bénéfice** : immediate / short_term / long_term.
4. **`attacker_scenario`** : scénario RÉALISTE (Kill Chain PTES) utilisant UNIQUEMENT les faiblesses du CONTEXT.

## RÈGLES DE SORTIE
- **UNIQUEMENT un objet JSON VALIDE**, rien d'autre
- Valeurs d'enum exactes : CRITICAL|HIGH|MEDIUM|LOW|INFO

## SCHÉMA OBLIGATOIRE
{
  "executive_summary": string (4–6 phrases — niveau CISO),
  "risk_narrative": string (7–12 phrases — connecte topologie, clusters CVE, frontières de confiance),
  "top_findings": [ {
      "title": string,
      "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO",
      "affected": string,
      "evidence": string,
      "recommendation": string
  } ] (5–8 max, tri severity DESC),
  "remediation_plan": {
      "immediate": [string],
      "short_term": [string],
      "long_term": [string]
  },
  "attacker_scenario": string (5–9 phrases — scénario opérationnel réaliste)
}"#.into()
}

#[allow(clippy::too_many_arguments)]
pub fn user_prompt_report(
    overall_risk_score: f32,
    total_hosts: usize,
    reachable: usize,
    total_ports: usize,
    total_cves: usize,
    crit: usize,
    high: usize,
    med: usize,
    low: usize,
    flow_types: &HashMap<&str, usize>,
    most_critical_targets: &[&str],
    pentest_vulns: usize,
    pentest_would_run: usize,
    pentest_dry_run: bool,
    custom_context: &str,
) -> String {
    let flows_str: String = if flow_types.is_empty() {
        "(no flows captured)".into()
    } else {
        flow_types
            .iter()
            .map(|(k, v)| format!("- {k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let crit_list = if most_critical_targets.is_empty() {
        "(none flagged by score)".into()
    } else {
        most_critical_targets
            .iter()
            .map(|s| format!("- {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        r#"Generate the NRTG professional pentest report for this operational engagement.

CONTEXT:
{custom_context}

KEY METRICS:
- overall_risk_score: {ors:.2} / 5.0
- total_hosts_scanned: {total_hosts} (reachable: {reachable})
- total_open_ports: {total_ports}
- matched_cves: {total_cves} (CRIT={crit} HIGH={high} MED={med} LOW={low})
- flow_links_by_type:
{flows_str}
- most_critical_targets_by_score:
{crit_list}
- exploit_orchestrator: {dry_text}; actual vulnerable findings: {pentest_vulns}; signatures_queued_would_run: {pentest_would_run}

Rules:
- top_findings MUST reference concrete targets and evidence from CONTEXT. Never invent CVEs/ports/services absent from CONTEXT.
- remediation_plan.immediate should be achievable in <24h and address ONLY issues actually present in CONTEXT.
- attacker_scenario MUST provide a realistic narrative of how an adversary would exploit the findings listed in CONTEXT.
- Keep wording clinical and realistic. If evidence is thin, say so.
"#,
        ors = overall_risk_score / 1.0,
        dry_text = if pentest_dry_run {
            "stealth mode / dry-run (reconnaissance only)"
        } else {
            "active exploitation phase (authorized probes)"
        },
    )
}

// ---------------------------------------------------------------
// Lateral-movement path ranking outputs
// ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedLateralPath {
    pub sequence: Vec<String>,
    pub techniques_per_hop: Vec<HopTechnique>,
    pub estimated_success_probability: f32,
    pub estimated_detection_risk: f32,
    pub estimated_minutes: u32,
    pub rationale: String,
    pub warnings: Vec<String>,
    pub recommended_evasions: Vec<String>,
    pub credential_reuse_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopTechnique {
    pub from_host: String,
    pub to_host: String,
    pub technique: String,
    pub exploit_signature_id: Option<String>,
    pub port: Option<u16>,
    pub expected_success: f32,
    pub expected_noise: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LateralPathRanking {
    pub paths: Vec<RankedLateralPath>,
    pub recommended_path_index: usize,
    pub summary: String,
    pub critical_warnings: Vec<String>,
    pub do_before_pivoting: Vec<String>,
}

// ---------------------------------------------------------------
// High-level helpers (typed parsing with fallback extractor)
// ---------------------------------------------------------------

pub async fn analyze_target(
    client: &dyn LlmClient,
    host: &str,
    port: u16,
    service: &str,
    product: &str,
    version: &str,
    banner: Option<&str>,
    protocol: &str,
    cves: &[(String, f32, String)],
    os_info: Option<&str>,
    waf: Option<&str>,
    tech: Option<&str>,
    prior_findings_count: usize,
) -> Result<TargetAnalysis, LlmError> {
    let msgs = vec![
        ChatMessage {
            role: "system".into(),
            content: system_prompt_analyst(),
        },
        ChatMessage {
            role: "user".into(),
            content: user_prompt_target_analysis(
                host,
                port,
                service,
                product,
                version,
                banner,
                protocol,
                cves,
                os_info,
                waf,
                tech,
                prior_findings_count,
            ),
        },
    ];
    let raw = client.chat(msgs, true).await?;
    let v = extract_json_fallback(&raw)
        .ok_or_else(|| LlmError::Parse("could not extract JSON for analysis".into()))?;
    let ta: TargetAnalysis =
        serde_json::from_value(v).map_err(|e| LlmError::Parse(format!("analysis schema: {e}")))?;
    Ok(ta)
}

pub async fn generate_report(
    client: &dyn LlmClient,
    overall_risk_score: f32,
    total_hosts: usize,
    reachable: usize,
    total_ports: usize,
    total_cves: usize,
    crit: usize,
    high: usize,
    med: usize,
    low: usize,
    flow_types: &HashMap<&str, usize>,
    most_critical_targets: &[&str],
    pentest_vulns: usize,
    pentest_would_run: usize,
    pentest_dry_run: bool,
    custom_context: &str,
) -> Result<AiReport, LlmError> {
    let msgs = vec![
        ChatMessage {
            role: "system".into(),
            content: system_prompt_report_writer(),
        },
        ChatMessage {
            role: "user".into(),
            content: user_prompt_report(
                overall_risk_score,
                total_hosts,
                reachable,
                total_ports,
                total_cves,
                crit,
                high,
                med,
                low,
                flow_types,
                most_critical_targets,
                pentest_vulns,
                pentest_would_run,
                pentest_dry_run,
                custom_context,
            ),
        },
    ];
    let raw = client.chat(msgs, true).await?;
    let v = extract_json_fallback(&raw)
        .ok_or_else(|| LlmError::Parse("could not extract JSON for report".into()))?;
    let r: AiReport =
        serde_json::from_value(v).map_err(|e| LlmError::Parse(format!("report schema: {e}")))?;
    Ok(r)
}

// ---------------------------------------------------------------
// Lateral-movement path ranking prompts & helpers
// ---------------------------------------------------------------

pub fn system_prompt_lateral_path_analyst() -> String {
    r#"## ROLE — Analyste Senior Mouvement Latéral (DIAPILE/NRTG)
Classer les chemins latéraux possibles entre hôtes compromis et cibles à haute valeur ajoutée.

## MÉTHODOLOGIE (MITRE ATT&CK + PTES)
1. **3 chemins minimum** dès que le graphe a au moins 2 sources candidates.
2. **Principe de Pareto** : Favoriser réutilisation credentials par-dessus exploitation brute CVE.
3. **Pénaliser port 445 (SMB)** si detection_risk >= 0.50.
4. **Calibrage honnête** : estimated_success_probability < 0.95 JAMAIS sans preuve.

## RÈGLES DE SORTIE
- **UNIQUEMENT un objet JSON VALIDE**
- Tous tableaux non-nullables ont au moins 1 entrée.

## SCHÉMA OBLIGATOIRE
{
  "paths": [ {
      "sequence": [string node_id, ...],
      "techniques_per_hop": [ {
          "from_host": string, "to_host": string, "technique": string,
          "exploit_signature_id": string|null, "port": number|null,
          "expected_success": 0..1, "expected_noise": 0..1
      } ],
      "estimated_success_probability": 0..1,
      "estimated_detection_risk": 0..1,
      "estimated_minutes": integer,
      "rationale": string,
      "warnings": [string],
      "recommended_evasions": [string],
      "credential_reuse_notes": [string]
  } ],
  "recommended_path_index": number,
  "summary": string,
  "critical_warnings": [string],
  "do_before_pivoting": [string]
}"#
    .into()
}

#[allow(clippy::too_many_arguments)]
pub fn user_prompt_rank_lateral_paths(
    compromised_hosts: &[&str],
    critical_targets: &[&str],
    candidate_edges: &[(&str, &str, &str, Option<u16>, f32, &str)],
    harvested_credentials_count: usize,
    hashes_count: usize,
    max_depth: usize,
    stealth_mode: bool,
    available_exploit_signatures: &[&str],
    flow_types: &HashMap<&str, usize>,
    custom_context: &str,
) -> String {
    let compromised = if compromised_hosts.is_empty() {
        "(none flagged yet)".to_string()
    } else {
        compromised_hosts
            .iter()
            .map(|h| format!("- {}", h))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let critical = if critical_targets.is_empty() {
        "(no explicit critical targets)".to_string()
    } else {
        critical_targets
            .iter()
            .map(|h| format!("- {}", h))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let edges: String = if candidate_edges.is_empty() {
        "(no edges supplied)".into()
    } else {
        candidate_edges
            .iter()
            .map(|(src, tgt, ltype, port, w, svc)| {
                format!(
                    "- {} -> {}  type={} port={} weight={:.2} svc={}",
                    src,
                    tgt,
                    ltype,
                    port.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                    w,
                    svc
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let sigs = if available_exploit_signatures.is_empty() {
        "(use NRTG defaults)".into()
    } else {
        available_exploit_signatures
            .iter()
            .map(|s| format!("- {}", s))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let flows = if flow_types.is_empty() {
        "(no flows)".into()
    } else {
        flow_types
            .iter()
            .map(|(k, v)| format!("- {}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        r#"Rank the lateral-movement paths for this authorized Red Team engagement.

COMPROMISED SOURCES:
{compromised}

CRITICAL / HIGH-VALUE TARGETS:
{critical}

CANDIDATE EDGES:
{edges}

HARVESTED INTELLIGENCE:
- harvested_credentials: {creds}
- hashes / tickets: {hashes}

ORCHESTRATOR CONSTRAINTS:
- max_pivot_depth (hops): {max_depth}
- stealth_mode: {stealth}
- available exploit signatures:
{sigs}
- flow links by type observed:
{flows}

ADDITIONAL CONTEXT:
{custom_context}

Produce the ranked lateral-movement plan. Follow the JSON schema exactly."#,
        creds = harvested_credentials_count,
        hashes = hashes_count,
        max_depth = max_depth,
        stealth = if stealth_mode {
            "ENABLED (penalize loud techniques)"
        } else {
            "disabled"
        },
        custom_context = if custom_context.is_empty() {
            "(none)"
        } else {
            custom_context
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn rank_lateral_paths(
    client: &dyn LlmClient,
    compromised_hosts: &[&str],
    critical_targets: &[&str],
    candidate_edges: &[(&str, &str, &str, Option<u16>, f32, &str)],
    harvested_credentials_count: usize,
    hashes_count: usize,
    max_depth: usize,
    stealth_mode: bool,
    available_exploit_signatures: &[&str],
    flow_types: &HashMap<&str, usize>,
    custom_context: &str,
) -> Result<LateralPathRanking, LlmError> {
    let msgs = vec![
        ChatMessage {
            role: "system".into(),
            content: system_prompt_lateral_path_analyst(),
        },
        ChatMessage {
            role: "user".into(),
            content: user_prompt_rank_lateral_paths(
                compromised_hosts,
                critical_targets,
                candidate_edges,
                harvested_credentials_count,
                hashes_count,
                max_depth,
                stealth_mode,
                available_exploit_signatures,
                flow_types,
                custom_context,
            ),
        },
    ];
    let raw = client.chat(msgs, true).await?;
    let v = extract_json_fallback(&raw)
        .ok_or_else(|| LlmError::Parse("could not extract JSON for lateral path ranking".into()))?;
    let r: LateralPathRanking = serde_json::from_value(v)
        .map_err(|e| LlmError::Parse(format!("lateral path ranking schema: {e}")))?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_wrapped_by_text() {
        let t = "blah blah {\n  \"host\": \"10.0.0.1\", \"port\": 80\n} more blah";
        let v = extract_json_fallback(t).expect("extract");
        assert_eq!(v["host"].as_str(), Some("10.0.0.1"));
        assert_eq!(v["port"].as_u64(), Some(80));
    }

    #[test]
    fn extract_json_nested_braces() {
        let t = "prefix {\"a\": {\"b\": [1,2,{\"c\":\"d\"}], \"e\": true}} suffix";
        let v = extract_json_fallback(t).unwrap();
        assert!(v["a"]["e"].as_bool().unwrap());
    }

    #[test]
    fn openrouter_fallback_cascade_present() {
        assert_eq!(NEMOTRON_OPENROUTER_CASCADE.len(), 4);
        assert_eq!(
            openrouter_pick_fallback("any/model:free"),
            Some("nvidia/nemotron-3-ultra-550b-a55b:free")
        );
    }

    #[test]
    fn extract_json_from_invalid_top_level_array() {
        let t = "the results:\n [1, 2, {\"x\":3}]\n done";
        let v = extract_json_fallback(t).unwrap();
        assert!(v.is_array());
    }

    #[test]
    fn default_config_openrouter() {
        let c = LlmConfig::default();
        assert_eq!(c.provider, LlmProvider::OpenRouter);
        assert!(c.json_mode);
        assert!(c.temperature <= 0.3);
    }

    #[test]
    fn build_client_validation_rejects_bad_api_base() {
        let mut cfg = LlmConfig::default();
        cfg.api_base = "not-a-url".into();
        cfg.api_key = Some("sk-test".into());
        // test_mode=false forcé : indépendant de NRTG_TEST_MODE ambiant (CI).
        assert!(matches!(
            build_client_with(&cfg, false),
            Err(LlmError::Config(_))
        ));
    }

    #[test]
    fn build_client_validation_rejects_missing_api_key() {
        let cfg = LlmConfig::default();
        assert!(cfg.api_key.is_none());
        assert!(matches!(
            build_client_with(&cfg, false),
            Err(LlmError::Config(_))
        ));
    }

    #[tokio::test]
    async fn test_mode_builds_mock_client_without_network_or_api_key() {
        // Config volontairement invalide (pas de clé, base bidon) : en mode test
        // le mock DOIT être renvoyé sans validation ni socket.
        let mut cfg = LlmConfig::default();
        cfg.api_base = "not-a-url".into();
        cfg.api_key = None;

        let client = build_client_with(&cfg, true).expect("mock attendu en mode test");
        let out = client
            .chat(
                vec![ChatMessage {
                    role: "user".into(),
                    content: "plan?".into(),
                }],
                true,
            )
            .await
            .expect("le mock ne doit jamais échouer");
        // Réponse par défaut déterministe et parse-tolérante.
        assert_eq!(out, "{}");
    }

    #[test]
    fn llm_client_box_coercion_works() {
        // Test EXPLICITE de la coercition Box<Concrete> → Box<dyn LlmClient>
        // sans `as` : les deux branches build_client branches retournent
        // Ok(Box<Concrete>) converti en Ok(Box<dyn LlmClient>)
        // via le let-binding typé : `let boxed: Box<dyn LlmClient> = Box::new(inner);
        fn _check_boxed_types() {
            fn _needs_dyn(_: Box<dyn LlmClient>) {}
            let cfg = LlmConfig {
                api_key: Some("sk-test".into()),
                ..LlmConfig::default()
            };
            if let Ok(inner) = OpenAiCompatibleClient::new(&cfg) {
                let boxed: Box<dyn LlmClient> = Box::new(inner);
                _needs_dyn(boxed);
            }
            if let Ok(inner) = OllamaClient::new(&cfg) {
                let boxed: Box<dyn LlmClient> = Box::new(inner);
                _needs_dyn(boxed);
            }
        }
    }
}
