//! Attack Planner — planificateur de kill-chains via OpenRouter LLM
//!
//! Le planificateur prend l'état courant de la campagne et demande au LLM
//! (via OpenRouter : Llama3, Mistral, Gemma…) de construire le plan
//! d'attaque optimal pour atteindre l'objectif.
//!
//! Format de décision retourné par le LLM :
//! ```json
//! {
//!   "next_action": "exploit",
//!   "target": "192.168.1.10",
//!   "technique": "CVE-2018-15473",
//!   "tool": "ssh_enum",
//!   "rationale": "SSH 7.6 détecté, enum users avant bruteforce",
//!   "risk_level": "low",
//!   "requires_confirmation": false,
//!   "fallback": "try HTTP-DEFAULT-ADMIN-BASIC on port 8080"
//! }
//! ```

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::campaign_memory::CampaignMemory;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Scan,               // scan réseau/port
    Enumerate,          // énumération de services (users, shares, dirs)
    Exploit,            // exploitation d'une CVE ou misconfiguration
    BruteForce,         // credential stuffing / dictionnaire
    PostExploit,        // enum post-compromission
    CredentialReuse,    // tester les creds récoltés sur d'autres hôtes
    Pivot,              // mouvement latéral depuis un hôte compromis
    Exfiltrate,         // extraction de données
    Cleanup,            // effacement des traces
    Report,             // générer le rapport final
    Pause,              // l'IA demande une pause (attente de résultat)
    Complete,           // objectif atteint
    StressTest,         // test de résilience/stress (GoldenEye / HORDE)
    WebAttack,          // attaque web ciblée (SQLi, XSS, SSTI, CORS, Smuggling)
    AdvancedScan,       // scan protocoles avancés (SNMP, IPMI, K8s, MS-RPC)
    KerberosAttack,     // attaques AD/Kerberos (AS-REP Roast, Kerberoast, Spray, Kerbrute)
    HordeAttack,        // orchestrateur HORDE DDoS distribué
    Evasion,            // techniques d'évasion (Anti-EDR, Sandbox bypass, AMSI)
    AdversaryEmulation, // émulation de groupes APT spécifiques (TTPs)
    AdAttack,           // attaques Active Directory natives (LDAP, AS-REP, Kerberoast, DCSync)
    Osint,              // reconnaissance OSINT externe (sous-domaines, fuites, Shodan)
    IotScada,           // inventaire/exploitation IoT & SCADA (Modbus, S7, BACnet, MQTT)
    C2,                 // déploiement d'agent C2 / beacon + canal d'exfiltration
    Integration,        // outils tiers (Metasploit RPC, BloodHound)
    ExternalTool,       // exécution d'un outil tiers installé à la demande
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Info,     // aucun impact — lecture seule
    Low,      // probe léger, peu de bruit
    Medium,   // peut déclencher des alertes IDS basiques
    High,     // très bruyant, risque de détection EDR
    Critical, // destructif ou irréversible
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Info => write!(f, "INFO"),
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Une action planifiée par l'IA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedAction {
    pub action_type: ActionType,
    pub target: String,    // IP:port ou CIDR
    pub technique: String, // CVE-ID, exploit_id, "ssh-bruteforce", etc.
    pub tool: String,      // module NRTG à utiliser
    pub rationale: String, // justification lisible par le redteameur
    pub risk_level: RiskLevel,
    /// L'IA juge-t-elle nécessaire une confirmation humaine ?
    /// (toujours true pour risk >= High, forcé dans l'agent)
    pub requires_confirmation: bool,
    pub estimated_success_prob: f32,         // 0.0 → 1.0
    pub fallback: Option<String>,            // plan B si cette action échoue
    pub parameters: HashMap<String, String>, // paramètres supplémentaires
}

/// Plan complet retourné par le LLM pour la prochaine étape
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPlan {
    pub phase: String,
    pub actions: Vec<PlannedAction>, // actions ordonnées par priorité
    pub narrative: String,           // explication en langage naturel
    pub stop_if_detected: bool,
    pub max_noise_level: RiskLevel,
}

// ── Configuration OpenRouter ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PlannerConfig {
    pub api_key: String,
    pub model: String, // ex: "google/gemma-2-9b-it" ou "meta-llama/llama-3.1-8b-instruct"
    pub base_url: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub stealth_mode: bool,        // préfère les actions low-noise
    pub max_risk_level: RiskLevel, // refuse de planifier au-delà de ce niveau
}

impl Default for PlannerConfig {
    fn default() -> Self {
        let (llm_provider, _fallback_llm_provider) = (
            std::env::var("NRTG_LLM_PROVIDER").ok(),
            std::env::var("NRTG_LLM_FALLBACK_PROVIDER").ok(),
        );
        let model = std::env::var("NRTG_LLM_MODEL").unwrap_or_else(|_| {
            match llm_provider.as_deref() {
                // Ollama local : Nemotron 70B q4 (≈ 40GB VRAM minimum)
                Some("ollama") | Some("local") => "nemotron:70b-instruct-q4_K_M".to_string(),
                // OpenAI compat : garder GPT-4o-mini (Nemotron n'est pas chez OpenAI)
                Some("openai") | Some("oai") => "gpt-4o-mini".to_string(),
                // Défaut : OpenRouter → Nemotron 4 340B instruct (flagship NVIDIA)
                _ => "nvidia/nemotron-3-ultra-550b-a55b:free".to_string(),
            }
        });
        let base_url = match llm_provider.as_deref() {
            Some("openai") | Some("oai") => "https://api.openai.com/v1".to_string(),
            Some("ollama") | Some("local") => "http://localhost:11434/v1".to_string(),
            _ => "https://openrouter.ai/api/v1".to_string(),
        };
        Self {
            api_key: std::env::var("OPENROUTER_API_KEY")
                .or_else(|_| std::env::var("OPENAI_API_KEY"))
                .unwrap_or_default(),
            model,
            base_url,
            temperature: 0.08, // Très bas : Nemotron 4 planning = déterministe, pas de créativité parasite
            max_tokens: 4096,  // 128K ctx window → on laisse 4K tokens de sortie pour plans longs
            stealth_mode: true,
            max_risk_level: RiskLevel::High,
        }
    }
}

impl PlannerConfig {
    /// Cascade officielle NVIDIA Nemotron pour fallback
    /// OpenRouter : 340B → 15B → Mini → Mistral-Nemo
    /// Ollama     : 70B  → 34B → 12B  → Mini
    pub fn fallback_model(&self) -> &'static str {
        if self.base_url.contains("localhost:11434") || self.base_url.contains("127.0.0.1:11434") {
            "nemotron:34b-instruct-q5_K_M"
        } else if self.base_url.contains("openai.com") {
            "gpt-4o-mini"
        } else {
            "nvidia/nemotron-3-super-120b-a12b:free"
        }
    }

    /// Accès direct à la cascade Nemotron complète OpenRouter (depuis llm.rs)
    pub fn nemotron_openrouter_cascade(&self) -> &'static [&'static str] {
        crate::llm::NEMOTRON_OPENROUTER_CASCADE
    }
}

// ── Planificateur ─────────────────────────────────────────────────────────────

pub struct AttackPlanner {
    config: PlannerConfig,
    client: reqwest::Client,
}

impl AttackPlanner {
    pub fn new(config: PlannerConfig) -> Result<Self> {
        // Une clé n'est requise que pour un endpoint distant. Les backends
        // locaux (Ollama sur `localhost:11434`, endpoint de test) n'ont pas
        // d'authentification : exiger `OPENROUTER_API_KEY` en toutes
        // circonstances rendait l'agent inutilisable en 100 % local
        // (`--llm-provider ollama` échouait sur « OPENROUTER_API_KEY manquant »).
        let is_local_endpoint = config.base_url.contains("localhost")
            || config.base_url.contains("127.0.0.1")
            || config.base_url.contains("0.0.0.0");
        if config.api_key.is_empty() && !is_local_endpoint {
            return Err(anyhow!(
                "OPENROUTER_API_KEY manquant. Définissez-le dans .env ou en variable d'environnement."
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .user_agent("NRTG/2.0 RedTeam-AI")
            .build()?;
        Ok(Self { config, client })
    }

    /// Construire le prompt système (instructions permanentes pour le LLM)
    fn system_prompt(&self) -> String {
        format!(
            r#"Tu es un agent IA spécialisé en opérations Red Team offensives pour des tests de pénétration AUTORISÉS.
Tu assistes un redteameur professionnel dans le cadre d'un engagement contractuel légal.

RÈGLES ABSOLUES :
1. Tu ne planifies JAMAIS d'actions destructives (ransomware, effacement de données, DoS).
2. Tu respectes TOUJOURS le scope défini.
3. Pour toute action de risque HIGH ou CRITICAL, tu dois mettre requires_confirmation=true.
4. En mode stealth ({stealth}), tu préfères les techniques à faible bruit.
5. Tu ne répètes JAMAIS une technique déjà échouée sur la même cible.

MÉTHODOLOGIE D'EXPLORATION (impérative) :
6. Une CVE corrélée par bannière est une HYPOTHÈSE PARMI D'AUTRES, pas une conclusion.
   Une bannière peut mentir (backport, version falsifiée, reverse-proxy) : le vecteur
   réel est souvent APPLICATIF. Ne t'acharne pas sur `known_cve` si des preuves de
   surface web (paramètres, formulaires, endpoints) sont disponibles.
7. Quand un service HTTP est exposé, teste les classes d'attaque web par ordre de
   probabilité. Classes reconnues (utilise EXACTEMENT ces identifiants dans le champ
   "technique" pour que l'agent mette à jour ses croyances) :
   default_creds, misconfig, auth_bypass, lfi, sqli, xss, ssti, cmdi, ssrf,
   file_upload, open_redirect, xxe, jwt, cors, graphql, oauth2, http_smuggling, known_cve.
8. Diversifie : si une classe a échoué sur une cible, essaie une AUTRE classe
   avant de reboucler. La section « HYPOTHÈSES PRIORITAIRES » donne un classement
   bayésien des classes les plus probables : appuie-toi dessus.
9. Sur une cible HTTP sans CVE exploitable, `web_attack` (qui exécute le crawl et
   tous les modules : SQLi, SSTI, SSRF, LFI, XSS, JWT, CORS, GraphQL, OAuth2,
   open-redirect, smuggling) est généralement plus rentable qu'un exploit réseau.
10. `external_tool` exécute un binaire tiers RÉEL : l'agent l'installe s'il est
   absent, puis le lance et **analyse sa sortie** (ports, chemins, identifiants,
   injections confirmées sont automatiquement versés en mémoire de campagne).
   Deux usages :
   — outil explicite : mets le binaire dans "tool" et ses arguments dans
     parameters.args (chaîne, ex. "-sV -p 1-1000 10.0.0.5") et éventuellement
     parameters.timeout_secs ;
   — intention : laisse "tool" vide et décris le besoin en clair dans
     "technique"/"rationale" (« fuzzer les répertoires web », « casser ce hash »,
     « énumérer les partages SMB ») : le registre de capacités choisit le
     meilleur outil présent et génère la commande.
   À privilégier pour ce que les modules natifs ne couvrent pas.

CAPACITÉS RECONNUES (registre d'intentions pour `external_tool` — laisse "tool"
vide et reprends le libellé ci-dessous ; l'agent choisit l'outil réellement
présent sur la machine et génère la commande) :
{capabilities}
FORMAT DE RÉPONSE : JSON strict uniquement (pas de markdown, pas de texte avant/après).
Structure attendue :
{{
  "phase": "string",
  "actions": [
    {{
      "action_type": "scan|enumerate|exploit|brute_force|post_exploit|credential_reuse|pivot|exfiltrate|cleanup|report|complete|stress_test|web_attack|advanced_scan|kerberos_attack|horde_attack|evasion|adversary_emulation|ad_attack|osint|iot_scada|c2|integration|external_tool",
      "target": "IP:port",
      "technique": "nom de la technique ou CVE",
      "tool": "module NRTG",
      "rationale": "justification en français",
      "risk_level": "info|low|medium|high|critical",
      "requires_confirmation": true/false,
      "estimated_success_prob": 0.0-1.0,
      "fallback": "plan B ou null",
      "parameters": {{}}
    }}
  ],
  "narrative": "explication en langage naturel pour le redteameur",
  "stop_if_detected": true/false,
  "max_noise_level": "info|low|medium|high|critical"
}}"#,
            stealth = if self.config.stealth_mode {
                "ACTIVÉ"
            } else {
                "DÉSACTIVÉ"
            },
            capabilities = crate::ai::capability_registry::render_catalog()
        )
    }

    /// Demander au LLM de planifier la prochaine étape
    pub async fn plan_next_step(
        &mut self,
        memory: &CampaignMemory,
        scan_results: &str,
        event: Option<&str>, // ex: "exploit redis réussi sur 10.0.0.5"
    ) -> Result<AttackPlan> {
        // ── Mode test : aucun appel réseau ──────────────────────────────────
        // `AttackPlanner` instancie son propre client HTTP : il ne passe donc
        // PAS par `llm::build_client`, et `NRTG_TEST_MODE` restait sans effet
        // ici — l'agent émettait de vraies requêtes LLM en CI. On court-circuite
        // l'appel : plan scripté via `NRTG_LLM_MOCK_RESPONSE`, sinon plan
        // déterministe de secours.
        if crate::main_helpers::test_mode_enabled() {
            if let Ok(raw) = std::env::var("NRTG_LLM_MOCK_RESPONSE") {
                if !raw.trim().is_empty() {
                    if let Ok(plan) = self.parse_plan_response(&raw) {
                        return Ok(plan);
                    }
                }
            }
            return Ok(self.fallback_plan(memory));
        }

        // Construire le message utilisateur avec tout le contexte
        let user_message = self.build_user_message(memory, scan_results, event);

        // Ajouter au contexte LLM (multi-turn)
        let mut messages: Vec<serde_json::Value> = vec![serde_json::json!({
            "role": "system",
            "content": self.system_prompt()
        })];

        // Ajouter l'historique de conversation
        for msg in memory.llm_messages_for_api() {
            messages.push(msg);
        }

        // Message courant
        messages.push(serde_json::json!({
            "role": "user",
            "content": user_message
        }));

        // Appel OpenRouter
        let response = self.call_openrouter(&messages).await?;

        // Parser la réponse JSON
        let plan = self.parse_plan_response(&response)?;

        Ok(plan)
    }

    /// Plan déterministe de secours, utilisé lorsque le LLM est totalement
    /// indisponible (surcharge fournisseur, réseau coupé, clé invalide).
    ///
    /// Il garantit que l'agent progresse vers l'objectif au lieu de boucler
    /// sans rien exécuter : l'objectif est classé par mots-clés et une action
    /// canonique en est déduite, appliquée à la cible la plus prioritaire.
    pub fn fallback_plan(&self, memory: &CampaignMemory) -> AttackPlan {
        let obj = memory.objective.to_lowercase();

        // Cible : hôte le plus vulnérable connu, avec son port de service.
        // Les clés de `hosts` sont des IP nues ; le port vit dans `services`
        // (`"http/888"`), il faut donc le recomposer pour construire une URL.
        let target = memory
            .hosts
            .values()
            .max_by_key(|h| h.confirmed_cves.len())
            .map(|h| {
                if h.ip.contains(':') {
                    h.ip.clone()
                } else if let Some(port) = h
                    .services
                    .iter()
                    .find_map(|s| s.split('/').nth(1).and_then(|p| p.parse::<u16>().ok()))
                {
                    format!("{}:{}", h.ip, port)
                } else {
                    h.ip.clone()
                }
            })
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let is_dos = [
            "ddos",
            "déni",
            "deni de service",
            "denial",
            "stress",
            "flood",
            "saturation",
        ]
        .iter()
        .any(|k| obj.contains(k));

        let (action_type, technique, tool, risk, prob, rationale) = if is_dos {
            (
                ActionType::HordeAttack,
                "browser_flood".to_string(),
                "horde".to_string(),
                RiskLevel::High,
                0.7_f32,
                "Objectif de déni de service détecté : campagne volumétrique HORDE (plan déterministe, LLM indisponible).",
            )
        } else if !memory.credentials.is_empty() {
            (
                ActionType::CredentialReuse,
                "credential_reuse".to_string(),
                "bruteforce".to_string(),
                RiskLevel::Medium,
                0.5_f32,
                "Credentials disponibles : réutilisation sur les autres hôtes (plan déterministe, LLM indisponible).",
            )
        } else {
            (
                ActionType::AdvancedScan,
                "recon_fallback".to_string(),
                "scanner".to_string(),
                RiskLevel::Low,
                0.9_f32,
                "Aucun contexte exploitable : énumération approfondie pour enrichir la campagne (plan déterministe, LLM indisponible).",
            )
        };

        AttackPlan {
            phase: "fallback".to_string(),
            actions: vec![PlannedAction {
                action_type,
                target,
                technique,
                tool,
                rationale: rationale.to_string(),
                risk_level: risk,
                // Exécution autonome : l'objectif a été fourni explicitement par
                // l'opérateur en ligne de commande. `config.confirm_all` reste
                // prioritaire si l'opérateur l'a activé.
                requires_confirmation: false,
                estimated_success_prob: prob,
                fallback: None,
                parameters: HashMap::new(),
            }],
            narrative:
                "Plan déterministe de secours (LLM indisponible) — objectif interprété par mots-clés."
                    .to_string(),
            stop_if_detected: true,
            max_noise_level: RiskLevel::High,
        }
    }

    fn build_user_message(
        &self,
        memory: &CampaignMemory,
        scan_results: &str,
        event: Option<&str>,
    ) -> String {
        let mut msg = String::new();

        msg.push_str("=== ÉTAT ACTUEL DE LA CAMPAGNE ===\n");
        msg.push_str(&memory.state_summary());
        msg.push('\n');

        if let Some(ev) = event {
            msg.push_str(&format!("\n=== ÉVÉNEMENT RÉCENT ===\n{}\n", ev));
        }

        if !scan_results.is_empty() {
            msg.push_str(&format!(
                "\n=== RÉSULTATS DE LA DERNIÈRE VAGUE D'ACTIONS (sortie brute des outils) ===\n{}\n",
                scan_results
            ));
        }

        msg.push_str(&format!("\n=== OBJECTIF ===\n{}\n", memory.objective));

        msg.push_str("\n=== INSTRUCTION ===\n");
        msg.push_str("Analyse la situation et planifie LA PROCHAINE étape optimale pour atteindre l'objectif.\n");
        msg.push_str(
            "Choisis la cible et la classe de vulnérabilité à tester en te fondant sur les \
             preuves de surface (SURFACE WEB CARTOGRAPHIÉE + HYPOTHÈSES PRIORITAIRES). \
             L'exploit d'une CVE corrélée n'est qu'UNE hypothèse : si la surface web expose \
             des paramètres/formulaires, privilégie les classes applicatives (sqli, ssti, lfi, \
             ssrf, xxe, cmdi, open_redirect, jwt, cors, graphql, oauth2, http_smuggling) via \
             l'action web_attack. Si des identifiants sont disponibles, teste default_creds / \
             credential_reuse. N'ouvre le champ des pivots que depuis un hôte réellement compromis.\n"
        );
        msg.push_str(
            "Renseigne le champ \"technique\" avec l'identifiant canonique de la classe testée \
             (ex. \"sqli\", \"ssti\", \"ssrf\") ou le CVE-ID si tu exploites une CVE.\n",
        );
        msg.push_str("Évite les techniques déjà échouées. Réponds UNIQUEMENT en JSON.\n");

        msg
    }

    async fn call_openrouter(&self, messages: &[serde_json::Value]) -> Result<String> {
        // ── Cascade Nemotron : 340B → 15B → Mini → Mistral-Nemo (OpenRouter) ─
        // ── ou : 70B → 34B → 12B → Mini (Ollama local) ──────────────────────
        // Pool statique partagé + buffer optionnel pour cas OpenAI custom
        let single_model_static: &'static [&'static str] = &["gpt-4o-mini"];
        let cascade: &[&str] = if self.config.base_url.contains("openrouter") {
            crate::llm::NEMOTRON_OPENROUTER_CASCADE
        } else if self.config.base_url.contains("11434") {
            crate::llm::NEMOTRON_OLLAMA_TAGS
        } else {
            // Fallback mono-modèle pour OpenAI ou autres endpoints
            single_model_static
        };

        // Recherche de position : dans cascade statique OU si on peut matcher
        let start_index = cascade
            .iter()
            .position(|m| *m == self.config.model.as_str())
            .unwrap_or(0);

        let mut last_err: Option<anyhow::Error> = None;
        for offset in 0..cascade.len().saturating_sub(start_index).max(1) {
            let idx = (start_index + offset).min(cascade.len() - 1);
            let model = cascade[idx];
            if offset > 0 {
                eprintln!("    ⚠️  Fallback #{offset} Agent → modèle Nemotron '{model}'");
            }

            let use_json_mode = self.config.base_url.contains("openai.com")
                || self.config.base_url.contains("openrouter");

            let mut payload = serde_json::json!({
                "model": model,
                "messages": messages,
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
            });
            if use_json_mode {
                payload["response_format"] = serde_json::json!({ "type": "json_object" });
            }
            // Ollama accepte format:"json" au lieu de response_format
            if self.config.base_url.contains("11434") {
                payload["format"] = serde_json::Value::String("json".into());
            }

            let req = self
                .client
                .post(format!(
                    "{}/chat/completions",
                    self.config.base_url.trim_end_matches('/')
                ))
                .header("Authorization", format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .timeout(std::time::Duration::from_secs(180));
            let req = if self.config.base_url.contains("openrouter") {
                req.header("HTTP-Referer", "https://diapile.redteam.local")
                    .header("X-Title", "DIAPILE RedTeam Autonomous Agent")
            } else {
                req
            };

            match req.json(&payload).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if (200..=299).contains(&status) {
                        let json: serde_json::Value = resp.json().await?;

                        // ── Erreur fournisseur encapsulée dans un corps 2xx ─────
                        // OpenRouter relaie parfois une surcharge amont sous la
                        // forme `{"error":{"code":503,"message":"..."}}` en HTTP
                        // 200. Sans ce garde-fou, la cascade s'arrête au premier
                        // provider saturé au lieu d'essayer le modèle suivant.
                        if let Some(err) = json.get("error") {
                            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                            let msg = err
                                .get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("erreur fournisseur sans message");
                            eprintln!(
                                "    ⚠️  Nemotron '{model}' erreur fournisseur (code {code}) : {msg}"
                            );
                            last_err = Some(anyhow!(
                                "Nemotron '{model}' erreur fournisseur HTTP {status} (code {code}) : {msg}"
                            ));
                            // Surcharge / indisponibilité amont → modèle suivant
                            continue;
                        }

                        // Chemins standards OpenAI-compat & Ollama chat
                        let content = json["choices"][0]["message"]["content"]
                            .as_str()
                            .or_else(|| json["message"]["content"].as_str())
                            .ok_or_else(|| anyhow!("Réponse LLM invalide : {:#}", json))?
                            .to_string();
                        return Ok(content);
                    }
                    // Erreur éligible au fallback : 404 / 422 / 429 / 400 / 5xx
                    let body = resp.text().await.unwrap_or_default();
                    let fallback_eligible = status == 404
                        || (status == 422 && body.contains("No endpoints found"))
                        || (status == 429 && (body.contains("rate") || body.contains("limit")))
                        || (status == 400 && body.contains("model"))
                        || (500..=504).contains(&status);
                    last_err = Some(anyhow!(
                        "Nemotron '{model}' HTTP {status} : {}",
                        &body[..body.len().min(400)]
                    ));
                    if !fallback_eligible {
                        break;
                    }
                }
                Err(e) => {
                    last_err = Some(anyhow!("Erreur réseau appel LLM : {e}"));
                    // Erreur réseau : tenter le modèle suivant
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| anyhow!("Aucun modèle Nemotron n'a pu répondre (cascade épuisée)")))
    }

    fn parse_plan_response(&self, response: &str) -> Result<AttackPlan> {
        // Nettoyer la réponse (parfois le LLM ajoute des backticks)
        let cleaned = response
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        let raw: serde_json::Value = serde_json::from_str(cleaned).map_err(|e| {
            anyhow!(
                "Parse JSON LLM failed: {} — raw: {}",
                e,
                &cleaned[..cleaned.len().min(200)]
            )
        })?;

        let actions = raw["actions"]
            .as_array()
            .ok_or_else(|| anyhow!("Pas de tableau 'actions' dans la réponse"))?
            .iter()
            .map(|a| self.parse_action(a))
            .collect::<Result<Vec<_>>>()?;

        // Forcer requires_confirmation pour les actions HIGH/CRITICAL et filtrer
        let max_risk = self.config.max_risk_level.clone();
        let actions = actions
            .into_iter()
            .filter_map(|mut a| {
                if a.risk_level >= RiskLevel::High {
                    a.requires_confirmation = true;
                }
                if a.risk_level <= max_risk {
                    Some(a)
                } else {
                    None
                }
            })
            .collect();

        Ok(AttackPlan {
            phase: raw["phase"].as_str().unwrap_or("unknown").to_string(),
            actions,
            narrative: raw["narrative"].as_str().unwrap_or("").to_string(),
            stop_if_detected: raw["stop_if_detected"].as_bool().unwrap_or(true),
            max_noise_level: parse_risk_level(raw["max_noise_level"].as_str().unwrap_or("medium")),
        })
    }

    fn parse_action(&self, v: &serde_json::Value) -> Result<PlannedAction> {
        let action_type = match v["action_type"].as_str().unwrap_or("scan") {
            "scan" => ActionType::Scan,
            "enumerate" => ActionType::Enumerate,
            "exploit" => ActionType::Exploit,
            "brute_force" => ActionType::BruteForce,
            "post_exploit" => ActionType::PostExploit,
            "credential_reuse" => ActionType::CredentialReuse,
            "pivot" => ActionType::Pivot,
            "exfiltrate" => ActionType::Exfiltrate,
            "cleanup" => ActionType::Cleanup,
            "report" => ActionType::Report,
            "complete" => ActionType::Complete,
            "stress_test" => ActionType::StressTest,
            "web_attack" => ActionType::WebAttack,
            "advanced_scan" => ActionType::AdvancedScan,
            "kerberos_attack" => ActionType::KerberosAttack,
            "horde_attack" => ActionType::HordeAttack,
            "evasion" => ActionType::Evasion,
            "adversary_emulation" => ActionType::AdversaryEmulation,
            "ad_attack" | "ad" => ActionType::AdAttack,
            "osint" => ActionType::Osint,
            "iot_scada" | "iot" | "scada" => ActionType::IotScada,
            "c2" | "beacon" => ActionType::C2,
            "integration" | "metasploit" | "bloodhound" => ActionType::Integration,
            "external_tool" | "tool" | "run_tool" => ActionType::ExternalTool,
            _ => ActionType::Scan,
        };

        let risk_level = parse_risk_level(v["risk_level"].as_str().unwrap_or("medium"));

        let parameters: HashMap<String, String> = v["parameters"]
            .as_object()
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        Ok(PlannedAction {
            action_type,
            target: v["target"].as_str().unwrap_or("").to_string(),
            technique: v["technique"].as_str().unwrap_or("").to_string(),
            tool: v["tool"].as_str().unwrap_or("nrtg-scan").to_string(),
            rationale: v["rationale"].as_str().unwrap_or("").to_string(),
            risk_level: risk_level.clone(),
            requires_confirmation: risk_level >= RiskLevel::High
                || v["requires_confirmation"].as_bool().unwrap_or(false),
            estimated_success_prob: v["estimated_success_prob"].as_f64().unwrap_or(0.5) as f32,
            fallback: v["fallback"].as_str().map(|s| s.to_string()),
            parameters,
        })
    }

    /// Générer un prompt de résumé narratif de campagne
    pub async fn generate_narrative_report(&self, memory: &CampaignMemory) -> Result<String> {
        let prompt = format!(
            "Tu es un expert en rédaction de rapports de sécurité offensive.\n\
             Rédige un rapport narratif professionnel en français pour cette campagne Red Team.\n\
             Style : factuel, chronologique, avec les preuves de compromission.\n\
             Inclus : objectif, méthodologie, hôtes compromis, credentials, recommandations défensives.\n\
             \n{}\n\nTimeline :\n{}",
            memory.state_summary(),
            memory.timeline.iter()
                .map(|e| format!("[{}] {} → {} ({})", e.timestamp[11..19].to_string(), e.action, e.result, e.target.as_deref().unwrap_or("-")))
                .collect::<Vec<_>>()
                .join("\n")
        );

        let messages = vec![serde_json::json!({ "role": "user", "content": prompt })];

        let response = self.call_openrouter(&messages).await?;
        Ok(response)
    }
}

fn parse_risk_level(s: &str) -> RiskLevel {
    match s.to_lowercase().as_str() {
        "info" => RiskLevel::Info,
        "low" => RiskLevel::Low,
        "medium" => RiskLevel::Medium,
        "high" => RiskLevel::High,
        "critical" => RiskLevel::Critical,
        _ => RiskLevel::Medium,
    }
}

// ── Affichage d'un plan pour la confirmation humaine ─────────────────────────

impl AttackPlan {
    /// Affiche le plan de façon lisible pour que le redteameur confirme
    pub fn display_for_confirmation(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "\n╔══ PLAN IA — Phase : {} ══\n",
            self.phase.to_uppercase()
        ));
        out.push_str(&format!("║\n║ 📋 {}\n║\n", self.narrative));

        for (i, action) in self.actions.iter().enumerate() {
            let risk_icon = match action.risk_level {
                RiskLevel::Info => "🔵",
                RiskLevel::Low => "🟢",
                RiskLevel::Medium => "🟡",
                RiskLevel::High => "🟠",
                RiskLevel::Critical => "🔴",
            };
            let confirm_tag = if action.requires_confirmation {
                "⚠️  CONFIRMATION REQUISE"
            } else {
                "✅ Auto"
            };

            out.push_str(&format!(
                "║\n║  [{:02}] {} {} — Risque: {}\n",
                i + 1,
                risk_icon,
                confirm_tag,
                action.risk_level
            ));
            out.push_str(&format!("║       Action   : {:?}\n", action.action_type));
            out.push_str(&format!("║       Cible    : {}\n", action.target));
            out.push_str(&format!("║       Technique: {}\n", action.technique));
            out.push_str(&format!("║       Outil    : {}\n", action.tool));
            out.push_str(&format!("║       Raison   : {}\n", action.rationale));
            out.push_str(&format!(
                "║       Succès   : {:.0}%\n",
                action.estimated_success_prob * 100.0
            ));
            if let Some(fb) = &action.fallback {
                out.push_str(&format!("║       Fallback : {}\n", fb));
            }
        }
        out.push_str("╚═══════════════════════════════\n");
        out
    }
}
