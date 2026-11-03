//! Metasploit RPC Integration
//!
//! This module provides integration with Metasploit Framework via RPC.
//! Allows launching exploits, managing sessions, and retrieving data.
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metasploit RPC Client
pub struct MetasploitClient {
    client: Client,
    base_url: String,
    auth_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetasploitSession {
    pub id: i32,
    pub uuid: String,
    #[serde(rename = "type")]
    pub session_type: String,
    pub target_host: String,
    pub target_port: i32,
    pub via_exploit: String,
    pub via_payload: String,
    pub workspace: String,
    pub username: Option<String>,
    pub exploit_uuid: String,
    pub arch: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetasploitModule {
    pub name: String,
    pub fullname: String,
    pub rank: i32,
    pub disclosure_date: Option<String>,
    pub description: String,
    pub author: Vec<String>,
    pub platform: Vec<String>,
    pub session_type: String,
    pub targets: Vec<MetasploitTarget>,
    pub payloads: Vec<MetasploitPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetasploitTarget {
    pub id: i32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetasploitPayload {
    pub name: String,
    pub fullname: String,
    pub space: i32,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetasploitJob {
    pub id: i32,
    pub name: String,
    pub target: String,
    pub info: String,
    pub route: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetasploitCred {
    pub id: i32,
    pub origin_type: String,
    pub service_id: i32,
    pub workspace_id: i32,
    pub username: String,
    pub private_data: String,
    pub private_type: String,
    pub jtr_impl: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Résultat léger de `module.search` — msfrpcd ne renvoie qu'un sous-ensemble
/// des champs d'un module (pas de `targets`/`payloads`), d'où un type dédié.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsfSearchHit {
    pub name: String,
    pub fullname: String,
    #[serde(default)]
    pub rank: i32,
    #[serde(default)]
    pub disclosure_date: Option<String>,
}

/// Réduit une bannière de service (« openssh/7.2 », « apache/2.4.49 ») au jeton
/// produit exploitable pour la recherche MSF. Renvoie une chaîne vide si le
/// service est indéterminé (l'appelant ne doit alors PAS lancer de recherche).
pub fn service_search_token(service: &str) -> String {
    service
        .split(|c: char| c == '/' || c == ' ' || c == ':' || c == '_')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase()
}

/// Choisit le module MSF le plus pertinent pour un jeton de service.
/// Exclusion stricte : un module qui ne mentionne pas le jeton (nom ou
/// fullname) est écarté — pas d'exécution aveugle. Départage par rang MSF.
pub fn rank_exploit_hits(token: &str, hits: &[MsfSearchHit]) -> Option<String> {
    let token = token.to_lowercase();
    if token.is_empty() {
        return None;
    }
    let mut best: Option<(&MsfSearchHit, i32)> = None;
    for h in hits {
        let name = h.name.to_lowercase();
        let full = h.fullname.to_lowercase();
        let mut score = if name.contains(&token) {
            100
        } else if full.contains(&token) {
            40
        } else {
            continue;
        };
        score += h.rank.clamp(0, 5);
        if best.map(|(_, s)| score > s).unwrap_or(true) {
            best = Some((h, score));
        }
    }
    best.map(|(h, _)| h.fullname.clone())
}

impl MetasploitClient {
    /// Create a new Metasploit RPC client
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            client: Client::new(),
            base_url: format!("http://{}:{}", host, port),
            auth_token: None,
        }
    }

    /// Login to Metasploit RPC
    pub async fn login(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let response = self
            .client
            .post(&format!("{}/api", self.base_url))
            .json(&serde_json::json!({
                "method": "auth.login",
                "params": [username, password]
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        if response["status"] == "success" {
            self.auth_token = Some(response["token"].as_str().unwrap_or("").to_string());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Logout from Metasploit RPC
    pub async fn logout(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Ok(false),
        };

        let response = self
            .client
            .post(&format!("{}/api/{}", self.base_url, token))
            .json(&serde_json::json!({
                "method": "auth.logout",
                "params": []
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        Ok(response["status"] == "success")
    }

    /// Get all active sessions
    pub async fn get_sessions(
        &self,
    ) -> Result<Vec<MetasploitSession>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let response = self
            .client
            .post(&format!("{}/api/{}", self.base_url, token))
            .json(&serde_json::json!({
                "method": "session.list",
                "params": []
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        // Metasploit msfrpcd retourne les sessions sous la clé racine de l'objet
        // La structure réelle est { "1": {...}, "2": {...} } ou { "sessions": {...} }
        let sessions_root = if let Some(obj) = response.as_object() {
            // Chercher d'abord une clé "sessions", sinon prendre l'objet racine
            if let Some(s) = obj.get("sessions").and_then(|v| v.as_object()) {
                s.clone()
            } else {
                // L'objet racine contient directement les sessions indexées par ID
                obj.iter()
                    .filter(|(k, _)| k.parse::<i32>().is_ok())
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            }
        } else {
            return Err("Invalid sessions response".into());
        };

        let mut sessions = Vec::new();
        for (id_str, value) in &sessions_root {
            if id_str.parse::<i32>().is_ok() {
                if let Ok(session) = serde_json::from_value::<MetasploitSession>(value.clone()) {
                    sessions.push(session);
                }
            }
        }

        Ok(sessions)
    }

    /// Run an exploit module
    pub async fn run_exploit(
        &self,
        module_name: &str,
        target: &str,
        port: u16,
        payload: &str,
        lhost: &str,
        lport: u16,
        options: Option<HashMap<String, String>>,
    ) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let mut params = serde_json::json!({
            "MODULE": module_name,
            "TARGET": target,
            "RHOST": target,
            "RPORT": port,
            "PAYLOAD": payload,
            "LHOST": lhost,
            "LPORT": lport,
        });

        if let Some(opts) = options {
            for (key, value) in opts {
                params[key] = serde_json::json!(value);
            }
        }

        let response = self
            .client
            .post(&format!("{}/api/{}", self.base_url, token))
            .json(&serde_json::json!({
                "method": "module.execute",
                "params": ["exploit", module_name, params]
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        if let Some(job_id) = response["job_id"].as_i64() {
            Ok(job_id as i32)
        } else {
            Err(format!("Failed to launch exploit: {}", response).into())
        }
    }

    /// Get module information
    pub async fn get_module_info(
        &self,
        module_type: &str,
        module_name: &str,
    ) -> Result<MetasploitModule, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let response = self
            .client
            .post(&format!("{}/api/{}", self.base_url, token))
            .json(&serde_json::json!({
                "method": "module.info",
                "params": [module_type, module_name]
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        serde_json::from_value(response).map_err(|e| e.into())
    }

    /// List exploits
    pub async fn list_exploits(
        &self,
    ) -> Result<Vec<MetasploitModule>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let response = self
            .client
            .post(&format!("{}/api/{}", self.base_url, token))
            .json(&serde_json::json!({
                "method": "module.exploits",
                "params": []
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let modules = response.as_array().ok_or("Invalid response format")?;

        let mut exploits = Vec::new();
        for module in modules {
            if let Ok(exploit) = serde_json::from_value::<MetasploitModule>(module.clone()) {
                exploits.push(exploit);
            }
        }

        Ok(exploits)
    }

    /// Get all jobs
    pub async fn get_jobs(
        &self,
    ) -> Result<Vec<MetasploitJob>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let response = self
            .client
            .post(&format!("{}/api/{}", self.base_url, token))
            .json(&serde_json::json!({
                "method": "job.list",
                "params": []
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let jobs_root = if let Some(obj) = response.as_object() {
            if let Some(j) = obj.get("jobs").and_then(|v| v.as_object()) {
                j.clone()
            } else {
                obj.iter()
                    .filter(|(k, _)| k.parse::<i32>().is_ok())
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            }
        } else {
            return Err("Invalid jobs response".into());
        };

        let mut jobs = Vec::new();
        for (id_str, value) in &jobs_root {
            if id_str.parse::<i32>().is_ok() {
                if let Ok(job) = serde_json::from_value::<MetasploitJob>(value.clone()) {
                    jobs.push(job);
                }
            }
        }

        Ok(jobs)
    }

    /// Get credentials from database
    pub async fn get_creds(
        &self,
    ) -> Result<Vec<MetasploitCred>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let response = self
            .client
            .post(&format!("{}/api/{}", self.base_url, token))
            .json(&serde_json::json!({
                "method": "db.get_creds",
                "params": []
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let creds = response.as_array().ok_or("Invalid response format")?;

        let mut credentials = Vec::new();
        for cred in creds {
            if let Ok(credential) = serde_json::from_value::<MetasploitCred>(cred.clone()) {
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }

    /// Read output from a session
    pub async fn session_read(
        &self,
        session_id: i32,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let response = self
            .client
            .post(&format!("{}/api/{}", self.base_url, token))
            .json(&serde_json::json!({
                "method": "session.shell_read",
                "params": [session_id]
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        Ok(response["data"].as_str().unwrap_or("").to_string())
    }

    /// Write to a session
    pub async fn session_write(
        &self,
        session_id: i32,
        cmd: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let response = self
            .client
            .post(&format!("{}/api/{}", self.base_url, token))
            .json(&serde_json::json!({
                "method": "session.shell_write",
                "params": [session_id, cmd]
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        Ok(response["status"] == "success")
    }

    /// Stop a job
    pub async fn job_stop(
        &self,
        job_id: i32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let response = self
            .client
            .post(&format!("{}/api/{}", self.base_url, token))
            .json(&serde_json::json!({
                "method": "job.stop",
                "params": [job_id]
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        Ok(response["status"] == "success")
    }

    /// Get module options
    pub async fn get_module_options(
        &self,
        module_type: &str,
        module_name: &str,
    ) -> Result<HashMap<String, serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let response = self
            .client
            .post(&format!("{}/api/{}", self.base_url, token))
            .json(&serde_json::json!({
                "method": "module.options",
                "params": [module_type, module_name]
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        response
            .as_object()
            .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .ok_or("Invalid response format".into())
    }

    /// Recherche de modules d'exploit via msfrpcd (`module.search`).
    /// `module.search` renvoie tous types confondus → on ne garde que les exploits.
    pub async fn search_exploits(
        &self,
        query: &str,
    ) -> Result<Vec<MsfSearchHit>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let response = self
            .client
            .post(&format!("{}/api/{}", self.base_url, token))
            .json(&serde_json::json!({
                "method": "module.search",
                "params": [query]
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let arr = response.as_array().ok_or("Invalid search response")?;

        let mut hits = Vec::new();
        for m in arr {
            let is_exploit = m
                .get("type")
                .and_then(|t| t.as_str())
                .map(|t| t.eq_ignore_ascii_case("exploit"))
                .unwrap_or(true); // msfrpcd omet parfois `type` — on ne filtre qu'en cas d'exclusion explicite
            if !is_exploit {
                continue;
            }
            if let Ok(h) = serde_json::from_value::<MsfSearchHit>(m.clone()) {
                hits.push(h);
            }
        }

        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metasploit_client_creation() {
        let client = MetasploitClient::new("127.0.0.1", 55553);
        assert_eq!(client.base_url, "http://127.0.0.1:55553");
        assert!(client.auth_token.is_none());
    }

    #[test]
    fn service_token_extracts_product_from_banner() {
        assert_eq!(service_search_token("openssh/7.2"), "openssh");
        assert_eq!(service_search_token("Apache/2.4.49 (Unix)"), "apache");
        assert_eq!(service_search_token("microsoft-iis:10.0"), "microsoft-iis");
        assert_eq!(service_search_token(""), "");
    }

    fn hit(name: &str, fullname: &str, rank: i32) -> MsfSearchHit {
        MsfSearchHit {
            name: name.into(),
            fullname: fullname.into(),
            rank,
            disclosure_date: None,
        }
    }

    #[test]
    fn rank_hits_prefers_name_match_then_rank() {
        let hits = vec![
            hit(
                "apache_cve_2021_41773",
                "exploit/multi/http/apache_cve_2021_41773",
                3,
            ),
            hit(
                "apache_normalize_path",
                "exploit/multi/http/apache_normalize_path_rce",
                4,
            ),
            // Ne mentionne pas « apache » → doit être exclu malgré un rang élevé.
            hit("generic_upload", "exploit/multi/http/generic_upload", 5),
        ];
        // Les deux candidats « apache » matchent par nom ; le rang le plus haut gagne.
        assert_eq!(
            rank_exploit_hits("apache", &hits).as_deref(),
            Some("exploit/multi/http/apache_normalize_path_rce")
        );
    }

    #[test]
    fn rank_hits_excludes_unrelated_and_empty_token() {
        let hits = vec![hit(
            "generic_upload",
            "exploit/multi/http/generic_upload",
            5,
        )];
        assert_eq!(rank_exploit_hits("openssh", &hits), None);
        assert_eq!(rank_exploit_hits("", &hits), None);
    }
}
