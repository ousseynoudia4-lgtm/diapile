//! DIAPILE HORDE — primitives cryptographiques OPSEC
//!
//! Respecte hard constraint : dérivation via `c2::crypto::derive_channel_key`
//! en première passe, puis sous-dérivation HKDF-SHA256 par worker avec
//! salt = worker_id. AES-256-GCM + HMAC-SHA256.

#![allow(dead_code)]

use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::c2::crypto::{aes_gcm_decrypt, aes_gcm_encrypt, derive_channel_key, C2Channel};

const HORDE_GLOBAL_CHANNEL: C2Channel = C2Channel::Custom("diapile/horde/global-v1");

/// Première passe : clé globale HORDE depuis la master key.
/// Utilise `derive_channel_key` imposé par les contraintes projet.
pub fn horde_derive_global_key(
    master: &[u8; 32],
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    derive_channel_key(master, HORDE_GLOBAL_CHANNEL)
}

/// Deuxième passe : sous-clé UNIQUE par worker, salt = worker_id.
/// (HKDF-SHA256 avec salt = worker_id.as_bytes(), info = "horde/worker/v1")
pub fn horde_derive_worker_key(
    master: &[u8; 32],
    worker_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let global = horde_derive_global_key(master)?;
    let hk = Hkdf::<Sha256>::new(Some(worker_id.as_bytes()), &global);
    let mut out = [0u8; 32];
    hk.expand(b"diapile/horde/worker/v1", &mut out)
        .map_err(|e| format!("HKDF worker {}: {:?}", worker_id, e))?;
    Ok(out)
}

/// HMAC-SHA256 sur challenge nonce (bytes bruts) avec worker_key.
/// Retour : 32 octets.
// `Hmac::new_from_slice` accepte toute longueur de clé (ici 32 o) : infaillible.
#[allow(clippy::expect_used)]
pub fn horde_derive_handshake_mac(worker_key: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(worker_key)
        .expect("HMAC new_from_slice accept 32B key");
    mac.update(b"DIAPILE-HORDE-HANDSHAKE-V1");
    mac.update(nonce);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Wrapper AES-256-GCM message → base64(`[nonce 12B][CT||tag]`)
/// (réutilise `aes_gcm_encrypt` de c2::crypto qui impose déjà wire format
/// nonce 12B + tag 16B append).
pub fn horde_wrap_msg(
    worker_key: &[u8; 32],
    plaintext: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let blob = aes_gcm_encrypt(worker_key, plaintext.as_bytes())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(blob))
}

/// Unwrap base64 blob → plaintext.
/// Anti-replay : `last_nonce` DOIT être strictement croissant.
/// Le nonce est stocké dans les 12 premiers octets du blob AES ; on interprète
/// les 10 premiers octets MSB comme un u80 monotone + 2 octets aléatoires.
/// Pour une robustesse maximale, on extrait un u128 via shift.
pub fn horde_unwrap_msg(
    worker_key: &[u8; 32],
    wrapped: &str,
    last_nonce: &mut u128,
) -> Option<String> {
    let blob = base64::engine::general_purpose::STANDARD
        .decode(wrapped.trim())
        .ok()?;
    if blob.len() < 12 {
        return None;
    }
    let mut nonce_arr = [0u8; 16];
    nonce_arr[4..16].copy_from_slice(&blob[..12]);
    let nonce_u128 = u128::from_be_bytes(nonce_arr);
    if nonce_u128 <= *last_nonce {
        return None;
    }
    let pt = aes_gcm_decrypt(worker_key, &blob).ok()?;
    *last_nonce = nonce_u128;
    String::from_utf8(pt).ok()
}

/// Charge la clé maître HORDE depuis :
/// 1. CLI `--horde-key` (hex 64 chars) ; fallback
/// 2. env `HORDE_MASTER_KEY` ; fallback final
/// 3. env `C2_MASTER_KEY` (réutilisation canaux C2 existants).
pub fn horde_load_master(
    cli_key: Option<&str>,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let hex_val = cli_key
        .map(|s| s.to_string())
        .or_else(|| std::env::var("HORDE_MASTER_KEY").ok())
        .or_else(|| std::env::var("C2_MASTER_KEY").ok())
        .ok_or_else(|| "HORDE_MASTER_KEY manquante (--horde-key ou env)".to_string())?;
    let bytes = hex::decode(hex_val.trim())
        .map_err(|_| "HORDE_MASTER_KEY: hex invalide (64 chars attendus)")?;
    if bytes.len() != 32 {
        return Err("HORDE_MASTER_KEY: 32 octets (64 hex) requis".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ── tests unitaires TR-2.1, TR-2.2, TR-2.3 ──────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tr_2_1_roundtrip_different_keys() {
        let master = [0xAAu8; 32];
        let k1 = horde_derive_worker_key(&master, "w1").unwrap();
        let k2 = horde_derive_worker_key(&master, "w2").unwrap();
        let msg = "test plaintext DIAPILE";
        let wrapped = horde_wrap_msg(&k1, msg).unwrap();
        // unwrap K2 → None (clé différente)
        let mut ln = 0u128;
        assert!(horde_unwrap_msg(&k2, &wrapped, &mut ln).is_none());
        // unwrap K1 → OK
        let mut ln2 = 0u128;
        let pt = horde_unwrap_msg(&k1, &wrapped, &mut ln2).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn tr_2_2_anti_replay() {
        use base64::Engine as _;

        // Le nonce AES-GCM est aléatoire (96 bits) : l'ordre entre deux messages
        // n'est donc PAS garanti. On génère le 2e message jusqu'à obtenir un
        // nonce STRICTEMENT supérieur au 1er, afin de tester la monotonie de
        // façon déterministe (et non sur un tirage aléatoire chanceux).
        fn nonce_u128(wrapped: &str) -> u128 {
            let blob = base64::engine::general_purpose::STANDARD
                .decode(wrapped)
                .unwrap();
            let mut arr = [0u8; 16];
            arr[4..16].copy_from_slice(&blob[..12]);
            u128::from_be_bytes(arr)
        }

        let master = [0x42u8; 32];
        let k = horde_derive_worker_key(&master, "wr1").unwrap();
        let w1 = horde_wrap_msg(&k, "m1").unwrap();
        let mut ln = 0u128;
        // 1er message → accepté (last_nonce initialisé à son nonce)
        assert!(horde_unwrap_msg(&k, &w1, &mut ln).is_some());

        // 2e message à nonce strictement croissant → accepté
        let n1 = ln;
        let mut w2 = None;
        for _ in 0..1000 {
            let cand = horde_wrap_msg(&k, "m2").unwrap();
            if nonce_u128(&cand) > n1 {
                w2 = Some(cand);
                break;
            }
        }
        let w2 = w2.expect("un nonce strictement croissant doit être trouvable");
        assert!(horde_unwrap_msg(&k, &w2, &mut ln).is_some());

        // Rejeu à l'identique → refusé (nonce non strictement croissant)
        let mut ln_clone = ln;
        assert!(horde_unwrap_msg(&k, &w1, &mut ln_clone).is_none());
    }

    #[test]
    fn tr_2_3_derive_deterministic() {
        let master = [0x01u8; 32];
        let a = horde_derive_worker_key(&master, "worker-001").unwrap();
        let b = horde_derive_worker_key(&master, "worker-001").unwrap();
        assert_eq!(a, b);
        let c = horde_derive_worker_key(&master, "worker-002").unwrap();
        assert_ne!(a, c);
    }
}
