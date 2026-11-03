//! Integration modules for external Red Team tools
//!
//! This module provides connectors to popular Red Team tools:
//! - Metasploit Framework (RPC)
//! - BloodHound (API)
//! - Cobalt Strike (Team Server)
//! - Empire/PowerShell Empire
//! - Sliver C2

pub mod bloodhound;
pub mod metasploit;

// Re-export main types
pub use bloodhound::BloodHoundClient;
pub use metasploit::MetasploitClient;

/// Résultat d'une exploitation automatique lancée via Metasploit.
#[derive(Debug, Clone)]
pub struct MsfRunOutcome {
    pub module: String,
    pub job_id: i32,
}

/// Integration manager for coordinating multiple tools
pub struct IntegrationManager {
    metasploit: Option<MetasploitClient>,
    bloodhound: Option<BloodHoundClient>,
    // Add other integrations as they are implemented
}

impl IntegrationManager {
    pub fn new() -> Self {
        Self {
            metasploit: None,
            bloodhound: None,
        }
    }

    /// Configure et connecte l'intégration Metasploit (async — effectue le vrai login)
    pub async fn configure_metasploit(
        &mut self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut client = MetasploitClient::new(host, port);
        // Login réel — récupère le token d'authentification msfrpcd
        match client.login(username, password).await {
            Ok(true) => {
                println!(
                    "  \x1b[32m[Metasploit]\x1b[0m Connecté à {}:{} en tant que {}",
                    host, port, username
                );
                self.metasploit = Some(client);
                Ok(())
            }
            Ok(false) => Err(format!(
                "Metasploit login échoué pour {} — credentials invalides",
                username
            )
            .into()),
            Err(e) => {
                Err(format!("Metasploit connexion échouée sur {}:{} — {}", host, port, e).into())
            }
        }
    }

    /// Configure l'intégration BloodHound (async — effectue le vrai login)
    pub async fn configure_bloodhound(
        &mut self,
        base_url: &str,
        username: &str,
        password: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut client = BloodHoundClient::new(base_url, username, password);
        match client.login().await {
            Ok(true) => {
                println!(
                    "  \x1b[32m[BloodHound]\x1b[0m Connecté à {} en tant que {}",
                    base_url, username
                );
                self.bloodhound = Some(client);
                Ok(())
            }
            Ok(false) => Err("BloodHound login échoué".into()),
            Err(e) => Err(format!("BloodHound connexion échouée — {}", e).into()),
        }
    }

    /// Check if all integrations are configured
    pub fn is_ready(&self) -> bool {
        self.metasploit.is_some() && self.bloodhound.is_some()
    }

    /// Get Metasploit client
    pub fn metasploit(&self) -> Option<&MetasploitClient> {
        self.metasploit.as_ref()
    }

    /// Get BloodHound client
    pub fn bloodhound(&self) -> Option<&BloodHoundClient> {
        self.bloodhound.as_ref()
    }

    /// Boucle « détection → exploitation » : recherche le module Metasploit le
    /// plus pertinent pour le service observé, puis le lance réellement.
    ///
    /// Échoue (sans exécution aveugle) si le service est indéterminé ou si
    /// aucun module ne correspond. L'appelant reste responsable du garde-fou
    /// de confirmation/périmètre en amont.
    pub async fn metasploit_exploit_service(
        &self,
        target: &str,
        port: u16,
        service: &str,
        lhost: &str,
        lport: u16,
        payload: &str,
    ) -> Result<MsfRunOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.metasploit.as_ref().ok_or("Metasploit non configuré")?;

        let token = metasploit::service_search_token(service);
        if token.is_empty() {
            return Err("service indéterminé — recherche MSF non lancée".into());
        }

        let hits = client.search_exploits(&token).await?;
        if hits.is_empty() {
            return Err(format!("aucun module MSF pour « {} »", token).into());
        }

        let module = metasploit::rank_exploit_hits(&token, &hits)
            .ok_or_else(|| format!("aucun module MSF pertinent pour « {} »", token))?;

        let job_id = client
            .run_exploit(&module, target, port, payload, lhost, lport, None)
            .await?;

        Ok(MsfRunOutcome { module, job_id })
    }
}

impl Default for IntegrationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_manager_creation() {
        let manager = IntegrationManager::new();
        assert!(!manager.is_ready());
        assert!(manager.metasploit().is_none());
        assert!(manager.bloodhound().is_none());
    }

    #[tokio::test]
    #[ignore = "nécessite une instance Metasploit (RPC) active"]
    async fn test_configure_metasploit() {
        let mut manager = IntegrationManager::new();
        let result = manager
            .configure_metasploit("127.0.0.1", 55553, "msf", "password")
            .await;
        assert!(result.is_ok());
        assert!(manager.metasploit().is_some());
    }

    #[tokio::test]
    #[ignore = "nécessite une instance BloodHound (Neo4j) active"]
    async fn test_configure_bloodhound() {
        let mut manager = IntegrationManager::new();
        let result = manager
            .configure_bloodhound("http://localhost:7474", "neo4j", "password")
            .await;
        assert!(result.is_ok());
        assert!(manager.bloodhound().is_some());
    }
}
