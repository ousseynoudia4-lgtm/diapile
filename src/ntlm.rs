//! DIAPILE — Primitives NTLM / NTLMSSP / SPNEGO / DES (module partagé)
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
//!
//! Chantier « AD-grade » : briques cryptographiques et codecs de messages
//! nécessaires à l'authentification Windows native, sans dépendre d'un
//! binaire externe (pas d'`impacket`, pas de `smbclient`).
//!
//! ## Contenu
//!
//! - **hash NT** : `MD4(UTF-16LE(mot de passe))` (crate `md4`)
//! - **hash LM** : DES-ECB sur `"KGS!@#$%"` (hérité, nécessaire pour NTLMv1)
//! - **DES-ECB maison** : réutilisé par la réponse NTLMv1 / LM et, plus tard,
//!   par la transformation de clé VNC (security-type 2)
//! - **NTLMv2** : `HMAC-MD5` (hash v2, réponses `LMv2` / `NTv2`, blob `0x01010000`)
//! - **Pass-the-hash** : les réponses sont dérivées du **hash NT** fourni
//!   directement ; aucun mot de passe en clair n'est reconstruit
//! - **NTLMSSP** : construction `Type 1` (NEGOTIATE) et `Type 3` (AUTHENTICATE),
//!   analyse `Type 2` (CHALLENGE : challenge 8 octets, `TargetInfo`, flags)
//! - **SPNEGO / `Negotiate`** : enveloppes `NegTokenInit` / `NegTokenResp`
//!
//! ## OPSEC
//!
//! Aucune fonction de ce module n'écrit sur disque ni ne journalise un secret.
//! Il appartient à l'appelant de masquer toute donnée sensible via `mask_secret`
//! avant affichage ou sérialisation.
#![allow(dead_code)]

use md4::Md4;
use rand::Rng;

// ─────────────────────────────────────────────────────────────────────────────
// Hachages (MD4 / HMAC-MD5)
// ─────────────────────────────────────────────────────────────────────────────

/// `MD4(data)` — primitive du hash NT (et des hash LM hérités).
pub fn md4_digest(data: &[u8]) -> [u8; 16] {
    let mut h = <Md4 as md4::Digest>::new();
    md4::Digest::update(&mut h, data);
    let out = md4::Digest::finalize(h);
    let mut r = [0u8; 16];
    r.copy_from_slice(&out);
    r
}

/// `MD5(data)` — le crate `md5` 0.7 (historique) expose `compute() -> Digest`,
/// sans type compatible avec `hmac` : on récupère les octets bruts.
fn md5_digest(data: &[u8]) -> [u8; 16] {
    md5::compute(data).0
}

const MD5_BLOCK: usize = 64;

/// `HMAC-MD5(key, data)` (RFC 2104) — primitive des réponses NTLMv2.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut k = [0u8; MD5_BLOCK];
    if key.len() > MD5_BLOCK {
        k[..16].copy_from_slice(&md5_digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(MD5_BLOCK + data.len());
    let mut outer = Vec::with_capacity(MD5_BLOCK + 16);
    for i in 0..MD5_BLOCK {
        inner.push(k[i] ^ 0x36);
        outer.push(k[i] ^ 0x5C);
    }
    inner.extend_from_slice(data);
    outer.extend_from_slice(&md5_digest(&inner));
    md5_digest(&outer)
}

/// Encodage UTF-16LE, base de tous les champs texte NTLM/LM.
pub fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// **Hash NT** : `MD4(UTF-16LE(password))`. Également la valeur utilisée
/// telle quelle par le pass-the-hash.
pub fn nt_hash(password: &str) -> [u8; 16] {
    md4_digest(&utf16le(password))
}

// ─────────────────────────────────────────────────────────────────────────────
// DES (ECB, bloc unique) — NTLMv1 / LM / (futur) VNC
// ─────────────────────────────────────────────────────────────────────────────

const IP: [usize; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const FP: [usize; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const E: [usize; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const P: [usize; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

const PC1: [usize; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const PC2: [usize; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const SHIFTS: [usize; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const SBOX: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
        1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
        14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6,
        9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
        13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// Permutation générique : extrait `out_len` bits de `bits_in` (vu sur
/// `in_len` bits, MSB à gauche) selon la table `table` (indices 1-based).
fn permute(bits_in: u64, in_len: usize, table: &[usize], out_len: usize) -> u64 {
    let mut out = 0u64;
    for i in 0..out_len {
        let src = table[i];
        let bit = (bits_in >> (in_len - src)) & 1;
        out = (out << 1) | bit;
    }
    out
}

fn des_key_schedule(key: &[u8; 8]) -> [u64; 16] {
    let k = u64::from_be_bytes(*key);
    let pc1 = permute(k, 64, &PC1, 56);
    let mask = 0x0FFF_FFFFu64;
    let mut c = (pc1 >> 28) & mask;
    let mut d = pc1 & mask;
    let mut ks = [0u64; 16];
    for i in 0..16 {
        let s = SHIFTS[i];
        c = ((c << s) | (c >> (28 - s))) & mask;
        d = ((d << s) | (d >> (28 - s))) & mask;
        ks[i] = permute((c << 28) | d, 56, &PC2, 48);
    }
    ks
}

fn des_f(r: u64, k: u64) -> u64 {
    let er = permute(r, 32, &E, 48) ^ k;
    let mut s_out = 0u64;
    for i in 0..8 {
        let six = ((er >> (42 - 6 * i)) & 0x3F) as usize;
        let row = ((six & 0x20) >> 4) | (six & 1);
        let col = (six >> 1) & 0x0F;
        s_out = (s_out << 4) | SBOX[i][row * 16 + col] as u64;
    }
    permute(s_out, 32, &P, 32)
}

/// DES-ECB sur un bloc unique (chiffrement). Clé de 8 octets (le bit de parité
/// est ignoré par `PC1`).
pub fn des_encrypt_block(key: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    let ks = des_key_schedule(key);
    let m = u64::from_be_bytes(*block);
    let ip = permute(m, 64, &IP, 64);
    let mut l = (ip >> 32) as u32;
    let mut r = (ip & 0xFFFF_FFFF) as u32;
    for i in 0..16 {
        let nl = r;
        let nr = l ^ (des_f(r as u64, ks[i]) as u32);
        l = nl;
        r = nr;
    }
    let pre = ((r as u64) << 32) | (l as u64);
    permute(pre, 64, &FP, 64).to_be_bytes()
}

/// Expansion d'une clé DES « 7 octets » (format LM) en clé 8 octets.
///
/// Les 7 bits de clé sont placés dans les bits 7..1 de chaque octet, le bit 0
/// restant à 0 (bit de parité, éliminé par `PC1`).
fn str_to_key(k7: &[u8]) -> [u8; 8] {
    let k = |i: usize| *k7.get(i).unwrap_or(&0);
    let packed = [
        k(0) >> 1,
        ((k(0) & 0x01) << 6) | (k(1) >> 2),
        ((k(1) & 0x03) << 5) | (k(2) >> 3),
        ((k(2) & 0x07) << 4) | (k(3) >> 4),
        ((k(3) & 0x0F) << 3) | (k(4) >> 5),
        ((k(4) & 0x1F) << 2) | (k(5) >> 6),
        ((k(5) & 0x3F) << 1) | (k(6) >> 7),
        k(6) & 0x7F,
    ];
    let mut out = [0u8; 8];
    for (i, b) in packed.iter().enumerate() {
        out[i] = b << 1;
    }
    out
}

const LM_MAGIC: [u8; 8] = *b"KGS!@#$%";

/// **Hash LM** (hérité) : mot de passe mis en majuscules ASCII, tronqué à
/// 14 octets, complété par des zéros, chiffré en DES-ECB avec `"KGS!@#$%"`.
///
/// Non dérivable d'un hash NT → indisponible en pass-the-hash.
pub fn lm_hash(password: &str) -> [u8; 16] {
    let mut pw: Vec<u8> = password
        .to_ascii_uppercase()
        .into_bytes()
        .into_iter()
        .take(14)
        .collect();
    pw.resize(14, 0);

    let mut out = [0u8; 16];
    for half in 0..2 {
        let k = str_to_key(&pw[half * 7..half * 7 + 7]);
        let enc = des_encrypt_block(&k, &LM_MAGIC);
        out[half * 8..half * 8 + 8].copy_from_slice(&enc);
    }
    out
}

/// Réponse NTLMv1 / LM : le secret (hash LM **ou** NT) complété à 21 octets
/// par des zéros, découpé en trois clés DES, chacune chiffrant le challenge.
pub fn ntlmv1_response(secret_hash: &[u8; 16], challenge: &[u8; 8]) -> [u8; 24] {
    let mut padded = [0u8; 21];
    padded[..16].copy_from_slice(secret_hash);
    let mut out = [0u8; 24];
    for i in 0..3 {
        let k = str_to_key(&padded[i * 7..i * 7 + 7]);
        let enc = des_encrypt_block(&k, challenge);
        out[i * 8..i * 8 + 8].copy_from_slice(&enc);
    }
    out
}

/// Réponse LMv1 (à partir du hash LM).
pub fn lm_response(lm: &[u8; 16], challenge: &[u8; 8]) -> [u8; 24] {
    ntlmv1_response(lm, challenge)
}

// ─────────────────────────────────────────────────────────────────────────────
// NTLMv2
// ─────────────────────────────────────────────────────────────────────────────

/// Hash NTLMv2 : `HMAC-MD5(hash_NT, UTF-16LE(maj(user) + domain))`.
pub fn ntlmv2_hash(nt: &[u8; 16], user: &str, domain: &str) -> [u8; 16] {
    let mut id = utf16le(&user.to_uppercase());
    id.extend_from_slice(&utf16le(domain));
    hmac_md5(nt, &id)
}

/// Réponse `LMv2` (24 octets) : `HMAC-MD5(hash_v2, challenge_srv ‖ challenge_cli) ‖ challenge_cli`.
pub fn lmv2_response(
    v2: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(server_challenge);
    data.extend_from_slice(client_challenge);
    let proof = hmac_md5(v2, &data);
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&proof);
    out.extend_from_slice(client_challenge);
    out
}

/// Réponse `NTv2` : `HMAC-MD5(hash_v2, challenge_srv ‖ blob) ‖ blob`.
///
/// Le `blob` suit la structure MS-NLMP (`0x01010000`, timestamp FILETIME,
/// challenge client, `TargetInfo` serveur).
pub fn ntlmv2_response(
    v2: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    timestamp: u64,
    target_info: &[u8],
) -> Vec<u8> {
    let blob = ntlmv2_blob(client_challenge, timestamp, target_info);
    let mut data = Vec::with_capacity(8 + blob.len());
    data.extend_from_slice(server_challenge);
    data.extend_from_slice(&blob);
    let proof = hmac_md5(v2, &data);

    let mut out = Vec::with_capacity(16 + blob.len());
    out.extend_from_slice(&proof);
    out.extend_from_slice(&blob);
    out
}

/// Corps du blob NTLMv2 (`RespType 0x01`, `HiRespType 0x01`).
pub fn ntlmv2_blob(client_challenge: &[u8; 8], timestamp: u64, target_info: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(32 + target_info.len() + 4);
    b.extend_from_slice(&[0x01, 0x01]); // RespType, HiRespType
    b.extend_from_slice(&[0x00, 0x00]); // Reserved1
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved2
    b.extend_from_slice(&timestamp.to_le_bytes()); // Timestamp (FILETIME)
    b.extend_from_slice(client_challenge); // ChallengeFromClient
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved3
    b.extend_from_slice(target_info); // AvPairs (déjà terminés par AV_EOL)
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved4
    b
}

/// Horodatage FILETIME (100 ns depuis 1601-01-01) utilisé dans le blob v2.
pub fn filetime_now() -> u64 {
    const EPOCH_DELTA_SECS: i64 = 11_644_473_600;
    let now = chrono::Utc::now();
    let secs = now.timestamp() + EPOCH_DELTA_SECS;
    let nanos = now.timestamp_subsec_nanos() as u64;
    (secs.max(0) as u64) * 10_000_000 + nanos / 100
}

/// Challenge client aléatoire de 8 octets.
pub fn random_client_challenge() -> [u8; 8] {
    rand::thread_rng().gen::<[u8; 8]>()
}

// ─────────────────────────────────────────────────────────────────────────────
// Constantes de flags NTLMSSP
// ─────────────────────────────────────────────────────────────────────────────

pub const FLAG_UNICODE: u32 = 0x0000_0001;
pub const FLAG_OEM: u32 = 0x0000_0002;
pub const FLAG_REQUEST_TARGET: u32 = 0x0000_0004;
pub const FLAG_SIGN: u32 = 0x0000_0010;
pub const FLAG_SEAL: u32 = 0x0000_0020;
pub const FLAG_NTLM: u32 = 0x0000_0200;
pub const FLAG_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const FLAG_EXTENDED_SESSION_SECURITY: u32 = 0x0008_0000;
pub const FLAG_TARGET_INFO: u32 = 0x0080_0000;
pub const FLAG_VERSION: u32 = 0x0200_0000;
pub const FLAG_128: u32 = 0x2000_0000;
pub const FLAG_56: u32 = 0x8000_0000;

/// Flags par défaut du message `Type 1` (pas de champ version : en-tête de 32 octets).
pub const TYPE1_FLAGS: u32 = FLAG_UNICODE
    | FLAG_OEM
    | FLAG_REQUEST_TARGET
    | FLAG_NTLM
    | FLAG_ALWAYS_SIGN
    | FLAG_EXTENDED_SESSION_SECURITY
    | FLAG_TARGET_INFO
    | FLAG_128
    | FLAG_56;

/// Flags par défaut du message `Type 3` (pas de champ version : en-tête de 64 octets).
pub const TYPE3_FLAGS: u32 = FLAG_UNICODE
    | FLAG_NTLM
    | FLAG_ALWAYS_SIGN
    | FLAG_EXTENDED_SESSION_SECURITY
    | FLAG_TARGET_INFO
    | FLAG_128
    | FLAG_56;

pub const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// Type de message NTLMSSP (`1` NEGOTIATE, `2` CHALLENGE, `3` AUTHENTICATE).
pub fn ntlmssp_type(blob: &[u8]) -> Option<u32> {
    if blob.len() < 12 || &blob[0..8] != NTLMSSP_SIGNATURE {
        return None;
    }
    Some(u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]))
}

fn le16(v: usize) -> [u8; 2] {
    (v as u16).to_le_bytes()
}

fn le32(v: usize) -> [u8; 4] {
    (v as u32).to_le_bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// Type 1 — NEGOTIATE
// ─────────────────────────────────────────────────────────────────────────────

/// Construit un message `NTLMSSP Type 1` (NEGOTIATE).
///
/// En-tête de 32 octets (sans champ version), suivi des charges
/// `DomainName` (NetBIOS) et `Workstation` en UTF-16LE.
pub fn build_type1(domain: &str, workstation: &str) -> Vec<u8> {
    build_type1_flags(domain, workstation, TYPE1_FLAGS)
}

/// Variante paramétrable des flags du `Type 1`.
pub fn build_type1_flags(domain: &str, workstation: &str, flags: u32) -> Vec<u8> {
    let dom = utf16le(domain);
    let ws = utf16le(workstation);
    let mut out = Vec::with_capacity(32 + dom.len() + ws.len());

    out.extend_from_slice(NTLMSSP_SIGNATURE);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());

    let dom_off = 32usize;
    out.extend_from_slice(&le16(dom.len()));
    out.extend_from_slice(&le16(dom.len()));
    out.extend_from_slice(&le32(dom_off));

    let ws_off = dom_off + dom.len();
    out.extend_from_slice(&le16(ws.len()));
    out.extend_from_slice(&le16(ws.len()));
    out.extend_from_slice(&le32(ws_off));

    out.extend_from_slice(&dom);
    out.extend_from_slice(&ws);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Type 2 — CHALLENGE (analyse)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Type2 {
    pub flags: u32,
    pub challenge: [u8; 8],
    pub target_name: String,
    pub target_info: Vec<u8>,
    pub version: Option<[u8; 8]>,
}

impl Type2 {
    /// `true` si le serveur annonce le support NTLMv2 (`TargetInfo` + ESS).
    pub fn supports_v2(&self) -> bool {
        self.flags & FLAG_TARGET_INFO != 0
            && self.flags & FLAG_EXTENDED_SESSION_SECURITY != 0
            && !self.target_info.is_empty()
    }
}

/// Analyse un message `NTLMSSP Type 2` (CHALLENGE).
pub fn parse_type2(msg: &[u8]) -> Option<Type2> {
    if ntlmssp_type(msg)? != 2 || msg.len() < 32 {
        return None;
    }

    let rd16 = |o: usize| -> usize {
        if o + 2 <= msg.len() {
            u16::from_le_bytes([msg[o], msg[o + 1]]) as usize
        } else {
            0
        }
    };
    let rd32 = |o: usize| -> usize {
        if o + 4 <= msg.len() {
            u32::from_le_bytes([msg[o], msg[o + 1], msg[o + 2], msg[o + 3]]) as usize
        } else {
            0
        }
    };

    let flags = rd32(20) as u32;
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&msg[24..32]);

    // TargetName : longueur en 12, offset en 16.
    let tn_len = rd16(12);
    let tn_off = rd32(16);
    let target_name = if tn_len > 0 && tn_off + tn_len <= msg.len() {
        let raw = &msg[tn_off..tn_off + tn_len];
        if flags & FLAG_UNICODE != 0 {
            String::from_utf16_lossy(
                &raw.chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>(),
            )
        } else {
            String::from_utf8_lossy(raw).to_string()
        }
    } else {
        String::new()
    };

    // TargetInfo : longueur en 40, offset en 44 (présent seulement si ≥ 48 octets).
    let mut target_info = Vec::new();
    if msg.len() >= 48 {
        let ti_len = rd16(40);
        let ti_off = rd32(44);
        if ti_len > 0 && ti_off + ti_len <= msg.len() {
            target_info = msg[ti_off..ti_off + ti_len].to_vec();
        }
    }

    // Champ version : 8 octets juste après TargetInfo (offset 48) si annoncé.
    let version = if flags & FLAG_VERSION != 0 && msg.len() >= 56 {
        let mut v = [0u8; 8];
        v.copy_from_slice(&msg[48..56]);
        Some(v)
    } else {
        None
    };

    Some(Type2 {
        flags,
        challenge,
        target_name,
        target_info,
        version,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Type 3 — AUTHENTICATE
// ─────────────────────────────────────────────────────────────────────────────

/// Secret utilisé pour l'authentification : mot de passe en clair **ou**
/// hash NT (pass-the-hash). Le mot de passe n'est jamais dérivé d'un hash.
#[derive(Debug, Clone)]
pub enum NtlmSecret {
    Password(String),
    NtHash([u8; 16]),
}

impl NtlmSecret {
    /// Hash NT associé (calculé pour un mot de passe, fourni tel quel en PtH).
    pub fn nt_hash(&self) -> [u8; 16] {
        match self {
            NtlmSecret::Password(p) => nt_hash(p),
            NtlmSecret::NtHash(h) => *h,
        }
    }

    /// `true` si l'on opère en pass-the-hash.
    pub fn is_pass_the_hash(&self) -> bool {
        matches!(self, NtlmSecret::NtHash(_))
    }
}

/// Paramètres d'une authentification NTLM.
#[derive(Debug, Clone)]
pub struct NtlmAuth {
    pub user: String,
    pub domain: String,
    pub workstation: String,
    pub secret: NtlmSecret,
    /// `true` → réponses NTLMv2 (défaut recommandé) ; `false` → NTLMv1.
    pub use_v2: bool,
}

impl NtlmAuth {
    pub fn new(user: &str, domain: &str, secret: NtlmSecret) -> Self {
        Self {
            user: user.to_string(),
            domain: domain.to_string(),
            workstation: "DIAPILE".to_string(),
            secret,
            use_v2: true,
        }
    }

    /// Message `Type 1` correspondant (domaine + poste de travail).
    pub fn type1(&self) -> Vec<u8> {
        build_type1(&self.domain, &self.workstation)
    }

    /// Calcule les réponses LM/NT (v1 ou v2) et construit le message `Type 3`.
    pub fn type3(&self, t2: &Type2) -> Vec<u8> {
        self.type3_with_key(t2).0
    }

    /// Comme [`NtlmAuth::type3`], mais retourne en plus la **clé de session**
    /// (`SessionBaseKey`) lorsqu'elle est dérivable — c'est-à-dire en NTLMv2.
    ///
    /// `SessionBaseKey = HMAC-MD5(ResponseKeyNT, NTProofStr)`. Aucun échange de
    /// clé (`NEGOTIATE_KEY_EXCH`) n'étant demandé dans les flags par défaut, la
    /// clé exportée est égale à cette valeur : elle alimente la dérivation des
    /// clés de signature SMB 2/3 ([MS-SMB2] §3.3.5.2.5.1). Le mode NTLMv1
    /// renvoie `None` (dérivation distincte, non implémentée).
    pub fn type3_with_key(&self, t2: &Type2) -> (Vec<u8>, Option<[u8; 16]>) {
        let nt = self.secret.nt_hash();

        let (lm_resp, nt_resp, session_key) = if self.use_v2 && t2.supports_v2() {
            let v2 = ntlmv2_hash(&nt, &self.user, &self.domain);
            let cc = random_client_challenge();
            let nt_resp = ntlmv2_response(&v2, &t2.challenge, &cc, filetime_now(), &t2.target_info);
            let base_key = hmac_md5(&v2, &nt_resp[..16]);
            (
                lmv2_response(&v2, &t2.challenge, &cc),
                nt_resp,
                Some(base_key),
            )
        } else {
            // NTLMv1 : la réponse LM exige le mot de passe en clair (hash LM),
            // indisponible en pass-the-hash → on la laisse vide.
            let lm = match &self.secret {
                NtlmSecret::Password(p) => lm_response(&lm_hash(p), &t2.challenge).to_vec(),
                NtlmSecret::NtHash(_) => vec![0u8; 24],
            };
            (lm, ntlmv1_response(&nt, &t2.challenge).to_vec(), None)
        };

        let msg = build_type3(
            &lm_resp,
            &nt_resp,
            &self.domain,
            &self.user,
            &self.workstation,
            &[],
            TYPE3_FLAGS,
        );
        (msg, session_key)
    }
}

/// Taille de l'en-tête d'un message `Type 3` sans champ version :
/// 8 (signature) + 4 (type) + 48 (6 descripteurs) + 4 (flags).
pub const TYPE3_HEADER: usize = 64;

/// Écrit un descripteur `SecurityBuffer` (longueur, longueur max, offset) à
/// l'emplacement `idx` du tableau de descripteurs, puis avance `off`.
fn put_field(fields: &mut [u8; 48], idx: usize, data: &[u8], off: &mut usize) {
    let d = idx * 8;
    fields[d..d + 2].copy_from_slice(&le16(data.len()));
    fields[d + 2..d + 4].copy_from_slice(&le16(data.len()));
    fields[d + 4..d + 8].copy_from_slice(&le32(*off));
    *off += data.len();
}

/// Assemble un message `NTLMSSP Type 3` (AUTHENTICATE), en-tête de 64 octets
/// (sans champ version).
pub fn build_type3(
    lm_response: &[u8],
    nt_response: &[u8],
    domain: &str,
    user: &str,
    workstation: &str,
    session_key: &[u8],
    flags: u32,
) -> Vec<u8> {
    let dom = utf16le(domain);
    let usr = utf16le(user);
    let ws = utf16le(workstation);

    // 6 descripteurs de sécurité (LM, NT, domaine, utilisateur, poste, clé de
    // session) = 48 octets, suivis des flags → en-tête complet de 64 octets.
    let mut off = TYPE3_HEADER;
    let mut fields = [0u8; 48];
    let mut payload = Vec::new();

    for (idx, data) in [
        lm_response,
        nt_response,
        dom.as_slice(),
        usr.as_slice(),
        ws.as_slice(),
        session_key,
    ]
    .into_iter()
    .enumerate()
    {
        put_field(&mut fields, idx, data, &mut off);
        payload.extend_from_slice(data);
    }

    let mut out = Vec::with_capacity(TYPE3_HEADER + payload.len());
    out.extend_from_slice(NTLMSSP_SIGNATURE);
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&fields);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&payload);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// SPNEGO / Negotiate
// ─────────────────────────────────────────────────────────────────────────────

const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const OID_NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, (n & 0xFF) as u8]
    }
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(content.len() + 4);
    v.push(tag);
    v.extend_from_slice(&der_len(content.len()));
    v.extend_from_slice(content);
    v
}

fn der_oid(oid_body: &[u8]) -> Vec<u8> {
    der(0x06, oid_body)
}

/// Enveloppe SPNEGO `NegTokenInit` autour d'un message `NTLMSSP Type 1`
/// (première trame de `Negotiate`).
pub fn spnego_init(ntlm_token: &[u8]) -> Vec<u8> {
    let mech = der_oid(OID_NTLMSSP);
    let mech_types = der(0xA0, &der(0x30, &mech));
    let mech_token = der(0xA2, &der(0x04, ntlm_token));
    let mut inner = Vec::new();
    inner.extend_from_slice(&mech_types);
    inner.extend_from_slice(&mech_token);

    let neg_token_init = der(0xA0, &der(0x30, &inner));
    let mut content = Vec::new();
    content.extend_from_slice(&der_oid(OID_SPNEGO));
    content.extend_from_slice(&neg_token_init);
    der(0x60, &content)
}

/// Enveloppe SPNEGO `NegTokenResp` autour d'un message `NTLMSSP Type 3`
/// (trame d'authentification). `neg_state` : 1 = `accept-incomplete`.
pub fn spnego_auth(ntlm_token: &[u8]) -> Vec<u8> {
    spnego_auth_state(ntlm_token, 1)
}

/// Variante paramétrable de `spnego_auth` (`neg_state` ASN.1 ENUMERATED).
pub fn spnego_auth_state(ntlm_token: &[u8], neg_state: u8) -> Vec<u8> {
    let state = der(0xA0, &der(0x0A, &[neg_state]));
    let mech = der(0xA1, &der_oid(OID_NTLMSSP));
    let resp = der(0xA2, &der(0x04, ntlm_token));

    let mut inner = Vec::new();
    inner.extend_from_slice(&state);
    inner.extend_from_slice(&mech);
    inner.extend_from_slice(&resp);

    der(0xA1, &der(0x30, &inner))
}

/// Extrait le message NTLMSSP d'une enveloppe SPNEGO (`NegTokenInit` ou
/// `NegTokenResp`) ou d'un jeton brut.
pub fn extract_ntlmssp(blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() >= 8 && &blob[0..8] == NTLMSSP_SIGNATURE {
        return Some(blob.to_vec());
    }
    let pos = blob
        .windows(NTLMSSP_SIGNATURE.len())
        .position(|w| w == NTLMSSP_SIGNATURE)?;
    Some(blob[pos..].to_vec())
}

/// `true` si le blob contient un jeton NTLMSSP (brut ou encapsulé SPNEGO).
pub fn contains_ntlmssp(blob: &[u8]) -> bool {
    extract_ntlmssp(blob).is_some()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn hexs(b: &[u8]) -> String {
        hex::encode(b)
    }

    #[test]
    fn hmac_md5_rfc2202_vectors() {
        // RFC 2202, cas 1 et 2.
        assert_eq!(
            hexs(&hmac_md5(&[0x0b; 16], b"Hi There")),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
        assert_eq!(
            hexs(&hmac_md5(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
    }

    #[test]
    fn nt_hash_known_vectors() {
        assert_eq!(
            hexs(&nt_hash("password")),
            "8846f7eaee8fb117ad06bdd830b7586c"
        );
        assert_eq!(hexs(&nt_hash("")), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn lm_hash_known_vectors() {
        assert_eq!(hexs(&lm_hash("")), "aad3b435b51404eeaad3b435b51404ee");
        assert_eq!(
            hexs(&lm_hash("Password")),
            "e52cac67419a9a224a3b108f3fa6cb6d"
        );
    }

    #[test]
    fn des_block_known_vector() {
        // Exemple FIPS : clé 0x133457799BBCDFF1, clair 0x0123456789ABCDEF.
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let pt = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        assert_eq!(hexs(&des_encrypt_block(&key, &pt)), "85e813540f0ab405");
    }

    #[test]
    fn type1_structure() {
        let t1 = build_type1("DOMAIN", "WS01");
        assert_eq!(ntlmssp_type(&t1), Some(1));
        assert_eq!(
            t1.len(),
            32 + utf16le("DOMAIN").len() + utf16le("WS01").len()
        );
        // L'offset du domaine suit immédiatement l'en-tête (32 octets).
        assert_eq!(u32::from_le_bytes([t1[20], t1[21], t1[22], t1[23]]), 32);
    }

    #[test]
    fn type2_roundtrip() {
        // Type 2 minimal reconstruit à la main : challenge + TargetInfo.
        let target = utf16le("DOMAIN");
        let ti: Vec<u8> = vec![
            0x02, 0x00, 0x0C, 0x00, 0x44, 0x00, 0x6F, 0x00, 0x6D, 0x00, 0x61, 0x00, 0x69, 0x00,
            0x6E, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let flags = TYPE1_FLAGS;
        // En-tête de 48 octets (pas de champ version : NEGOTIATE_VERSION absent),
        // charges utiles à partir de 48.
        let mut m = Vec::new();
        m.extend_from_slice(NTLMSSP_SIGNATURE);
        m.extend_from_slice(&2u32.to_le_bytes());
        m.extend_from_slice(&le16(target.len()));
        m.extend_from_slice(&le16(target.len()));
        m.extend_from_slice(&le32(48));
        m.extend_from_slice(&flags.to_le_bytes());
        m.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        m.extend_from_slice(&[0u8; 8]); // Reserved
        m.extend_from_slice(&le16(ti.len()));
        m.extend_from_slice(&le16(ti.len()));
        m.extend_from_slice(&le32(48 + target.len()));
        m.extend_from_slice(&target);
        m.extend_from_slice(&ti);
        assert_eq!(m.len(), 48 + target.len() + ti.len());

        let t2 = parse_type2(&m).expect("Type 2 analysable");
        assert_eq!(
            t2.challenge,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        );
        assert_eq!(t2.target_name, "DOMAIN");
        assert_eq!(t2.target_info, ti);
        assert!(t2.supports_v2());
    }

    /// Lit le descripteur `SecurityBuffer` n° `idx` d'un message Type 3 :
    /// renvoie `(longueur, offset)`. Les descripteurs commencent à l'octet 12.
    fn sb(msg: &[u8], idx: usize) -> (usize, usize) {
        let d = 12 + idx * 8;
        let len = u16::from_le_bytes([msg[d], msg[d + 1]]) as usize;
        let off = u32::from_le_bytes([msg[d + 4], msg[d + 5], msg[d + 6], msg[d + 7]]) as usize;
        (len, off)
    }

    fn utf16_at(msg: &[u8], len: usize, off: usize) -> String {
        String::from_utf16_lossy(
            &msg[off..off + len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn type3_layout_and_v2_lengths() {
        let t2 = Type2 {
            flags: TYPE1_FLAGS,
            challenge: [0x11; 8],
            target_name: "DOMAIN".into(),
            target_info: vec![0x02, 0x00, 0x0A, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00],
            version: None,
        };
        let auth = NtlmAuth::new("alice", "DOMAIN", NtlmSecret::Password("secret".into()));
        let t3 = auth.type3(&t2);

        assert_eq!(ntlmssp_type(&t3), Some(3));
        let (lm_len, lm_off) = sb(&t3, 0);
        let (nt_len, nt_off) = sb(&t3, 1);
        let (dom_len, dom_off) = sb(&t3, 2);
        let (usr_len, usr_off) = sb(&t3, 3);

        // LMv2 = 24 octets ; NTv2 = 16 (preuve) + blob (32 fixes) + TargetInfo.
        assert_eq!(lm_len, 24);
        assert_eq!(nt_len, 16 + 32 + t2.target_info.len());
        assert_eq!(lm_off, TYPE3_HEADER);
        assert_eq!(nt_off, TYPE3_HEADER + lm_len);
        assert_eq!(utf16_at(&t3, dom_len, dom_off), "DOMAIN");
        assert_eq!(utf16_at(&t3, usr_len, usr_off), "alice");
        // Le blob commence après la preuve HMAC-MD5 (16 octets).
        assert_eq!(&t3[nt_off + 16..nt_off + 18], &[0x01, 0x01]);
    }

    #[test]
    fn pass_the_hash_matches_password() {
        // Le PtH doit produire exactement les mêmes réponses que le mot de passe.
        let t2 = Type2 {
            flags: TYPE1_FLAGS,
            challenge: [0xAB; 8],
            target_name: "D".into(),
            target_info: vec![0x00, 0x00, 0x00, 0x00],
            version: None,
        };
        let nt = nt_hash("P@ssw0rd");

        // NTLMv2 : hash v2 identique quel que soit le secret (mot de passe ou hash NT).
        let by_pw = NtlmSecret::Password("P@ssw0rd".into());
        let by_hash = NtlmSecret::NtHash(nt);
        assert_eq!(
            ntlmv2_hash(&by_pw.nt_hash(), "bob", "D"),
            ntlmv2_hash(&by_hash.nt_hash(), "bob", "D")
        );
        assert!(by_hash.is_pass_the_hash() && !by_pw.is_pass_the_hash());

        // NTLMv1 : même hash NT → réponse NTv1 strictement identique.
        let mut pth = NtlmAuth::new("bob", "D", by_hash);
        let mut pw1 = NtlmAuth::new("bob", "D", by_pw);
        pth.use_v2 = false;
        pw1.use_v2 = false;
        let t3a = pth.type3(&t2);
        let t3b = pw1.type3(&t2);

        let (len_a, off_a) = sb(&t3a, 1);
        let (len_b, off_b) = sb(&t3b, 1);
        assert_eq!(len_a, 24);
        assert_eq!(&t3a[off_a..off_a + len_a], &t3b[off_b..off_b + len_b]);

        // LM en PtH : 24 octets nuls (le hash LM n'est pas dérivable du hash NT).
        let (lm_len_pth, lm_off_pth) = sb(&t3a, 0);
        assert_eq!(lm_len_pth, 24);
        assert!(t3a[lm_off_pth..lm_off_pth + 24].iter().all(|b| *b == 0));
        assert_eq!(
            ntlmv1_response(&nt, &t2.challenge).to_vec(),
            t3a[off_a..off_a + 24].to_vec()
        );
    }

    #[test]
    fn spnego_wrapping_and_extraction() {
        let t1 = build_type1("DOMAIN", "WS01");
        let wrapped = spnego_init(&t1);
        assert_eq!(wrapped[0], 0x60);
        assert!(contains_ntlmssp(&wrapped));
        assert_eq!(extract_ntlmssp(&wrapped).unwrap(), t1);

        let t3 = build_type3(
            &[0u8; 24],
            &[0u8; 32],
            "DOMAIN",
            "alice",
            "WS01",
            &[],
            TYPE3_FLAGS,
        );
        let w3 = spnego_auth(&t3);
        assert_eq!(w3[0], 0xA1);
        assert_eq!(extract_ntlmssp(&w3).unwrap(), t3);

        assert!(extract_ntlmssp(b"\x01\x02\x03").is_none());
    }

    #[test]
    fn filetime_is_plausible() {
        let ft = filetime_now();
        // Après 2020 : ~132 000 000 000 000 000.
        assert!(ft > 132_000_000_000_000_000);
    }
}
