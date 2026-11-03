use crate::ai::campaign_memory::{Credential, HostMemory, HostState};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Intelligence partagée au sein de l'essaim (Swarm).
/// Permet à plusieurs agents de synchroniser leurs découvertes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SwarmIntelligence {
    pub discovered_hosts: HashMap<String, HostMemory>,
    pub credentials: Vec<Credential>,
    pub active_shells: HashSet<String>, // IDs des agents ayant un shell actif
    pub pwned_targets: HashSet<String>, // IPs/Hostnames compromis
}

pub struct SwarmCoordinator {
    pub intel: Arc<RwLock<SwarmIntelligence>>,
}

impl SwarmCoordinator {
    pub fn new() -> Self {
        Self {
            intel: Arc::new(RwLock::new(SwarmIntelligence::default())),
        }
    }

    /// Synchronise la mémoire locale d'un agent avec l'intelligence de l'essaim.
    pub async fn sync(
        &self,
        local_hosts: &HashMap<String, HostMemory>,
        local_creds: &[Credential],
    ) {
        let mut swarm = self.intel.write().await;

        // Fusion des hôtes découverts
        for (ip, state) in local_hosts {
            swarm
                .discovered_hosts
                .entry(ip.clone())
                .and_modify(|s| {
                    // Fusion des services (dédoublonnage)
                    for svc in &state.services {
                        if !s.services.contains(svc) {
                            s.services.push(svc.clone());
                        }
                    }
                    // Fusion des CVEs confirmées
                    for cve in &state.confirmed_cves {
                        if !s.confirmed_cves.contains(cve) {
                            s.confirmed_cves.push(cve.clone());
                        }
                    }
                    // Héritage d'un shell actif si l'hôte local en possède un
                    if s.session_id.is_none() && state.session_id.is_some() {
                        s.session_id = state.session_id.clone();
                        s.state = HostState::Compromised;
                    }
                })
                .or_insert(state.clone());
        }

        // Fusion des credentials (éviter doublons)
        for cred in local_creds {
            if !swarm
                .credentials
                .iter()
                .any(|c| c.username == cred.username && c.secret == cred.secret)
            {
                swarm.credentials.push(cred.clone());
            }
        }
    }

    /// Récupère l'état global pour un agent.
    pub async fn get_global_intel(&self) -> SwarmIntelligence {
        self.intel.read().await.clone()
    }
}
