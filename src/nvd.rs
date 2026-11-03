//! NVD (National Vulnerability Database) API client for dynamic CVE fetching.
//! NVD API v2.0 integration — CVE lookup, CPE matching, local DB update
#![allow(unused_imports, dead_code, unused_variables)]

use crate::config::CveConfig;
use crate::cve::{CveDatabase, CveEntry};
use crate::errors::{AppError, ErrorCode, Result};
use chrono::{Duration as ChronoDuration, Utc};
use moka::future::Cache;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

/// NVD API response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdResponse {
    pub results_per_page: u32,
    pub start_index: u32,
    pub total_results: u32,
    pub format: String,
    pub version: String,
    pub timestamp: String,
    pub vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdVulnerability {
    pub cve: NvdCve,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCve {
    pub id: String,
    pub source_identifier: Option<String>,
    pub published: String,
    pub last_modified: String,
    pub descriptions: Vec<NvdDescription>,
    pub metrics: Option<NvdMetrics>,
    pub weaknesses: Option<Vec<NvdWeakness>>,
    pub config: Option<Vec<NvdConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdMetrics {
    pub cvss_metric_v31: Option<Vec<NvdCvssMetric>>,
    pub cvss_metric_v30: Option<Vec<NvdCvssMetric>>,
    pub cvss_metric_v2: Option<Vec<NvdCvssMetricV2>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssMetric {
    pub cvss_data: NvdCvssData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssData {
    pub version: String,
    pub vector_string: String,
    pub attack_vector: Option<String>,
    pub attack_complexity: Option<String>,
    pub privileges_required: Option<String>,
    pub user_interaction: Option<String>,
    pub scope: Option<String>,
    pub confidentiality_impact: Option<String>,
    pub integrity_impact: Option<String>,
    pub availability_impact: Option<String>,
    pub base_score: f64,
    pub base_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssMetricV2 {
    pub cvss_data: NvdCvssDataV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssDataV2 {
    pub version: String,
    pub vector_string: String,
    pub base_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdWeakness {
    pub source: String,
    #[serde(rename = "type")]
    pub weakness_type: String,
    pub description: Vec<NvdDescription>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdConfig {
    pub nodes: Vec<NvdNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdNode {
    pub operator: Option<String>,
    pub negate: Option<bool>,
    pub cpe_match: Vec<NvdCpeMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
    pub match_criteria_id: String,
    pub version_start_excluding: Option<String>,
    pub version_start_including: Option<String>,
    pub version_end_excluding: Option<String>,
    pub version_end_including: Option<String>,
}

/// CPE (Common Platform Enumeration) parser
#[derive(Debug, Clone, Default)]
pub struct Cpe {
    pub part: String, // a=application, h=hardware, o=OS
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub update: String,
    pub edition: String,
    pub language: String,
    pub sw_edition: String,
    pub target_sw: String,
    pub target_hw: String,
    pub other: String,
}

impl Cpe {
    /// Parse a CPE 2.3 URI string
    pub fn parse(cpe_str: &str) -> Option<Self> {
        // CPE 2.3 URI format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        let cpe_str = cpe_str.trim();

        if !cpe_str.starts_with("cpe:2.3:") {
            return None;
        }

        let parts: Vec<&str> = cpe_str.split(':').collect();
        if parts.len() < 12 {
            return None;
        }

        Some(Self {
            part: parts.get(2).copied().unwrap_or("*").to_string(),
            vendor: parts.get(3).copied().unwrap_or("*").to_string(),
            product: parts.get(4).copied().unwrap_or("*").to_string(),
            version: parts.get(5).copied().unwrap_or("*").to_string(),
            update: parts.get(6).copied().unwrap_or("*").to_string(),
            edition: parts.get(7).copied().unwrap_or("*").to_string(),
            language: parts.get(8).copied().unwrap_or("*").to_string(),
            sw_edition: parts.get(9).copied().unwrap_or("*").to_string(),
            target_sw: parts.get(10).copied().unwrap_or("*").to_string(),
            target_hw: parts.get(11).copied().unwrap_or("*").to_string(),
            other: parts.get(12).copied().unwrap_or("*").to_string(),
        })
    }

    /// Create a CPE filter string for NVD API
    pub fn to_filter_string(&self) -> String {
        format!(
            "cpe:2.3:*:{}:{}:{}:*:*:*:*:*:*:*",
            self.vendor, self.product, self.version
        )
    }
}

/// NVD API client
pub struct NvdClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    cache: Cache<String, Vec<CveEntry>>,
    last_sync: Arc<tokio::sync::RwLock<Option<chrono::DateTime<Utc>>>>,
}

impl NvdClient {
    /// Create a new NVD client
    pub fn new(config: &CveConfig) -> Result<Self> {
        let mut headers = HeaderMap::new();
        if let Some(ref api_key) = config.nvd_api_key {
            headers.insert(
                "apiKey",
                HeaderValue::from_str(api_key).map_err(|_| AppError::InvalidInput {
                    code: ErrorCode::InvalidInput,
                    message: "Invalid API key format".into(),
                })?,
            );
        }

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::Http {
                code: ErrorCode::HttpError,
                message: format!("Failed to create HTTP client: {}", e),
                source: Box::new(e),
            })?;

        Ok(Self {
            client,
            base_url: config.nvd_api_url.clone(),
            api_key: config.nvd_api_key.clone(),
            cache: Cache::new(1000),
            last_sync: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }

    /// Search CVEs by product name and version
    pub async fn search_by_product(
        &self,
        product: &str,
        version: &str,
        min_cvss: Option<f64>,
    ) -> Result<Vec<CveEntry>> {
        // Check cache first
        let cache_key = format!("{}:{}", product.to_lowercase(), version.to_lowercase());
        if let Some(cached) = self.cache.get(&cache_key).await {
            debug!("Cache hit for {}:{}", product, version);
            return Ok(cached);
        }

        info!("Searching NVD for {} {}", product, version);

        let url = format!("{}/cves", self.base_url);
        let mut params = vec![("resultsPerPage", "100")];

        // NVD API v2 : utiliser keywordSearch pour recherche textuelle produit+version
        // Format correct : "product version" (simple, pas de AND dupliqué)
        let kw_search = format!("{} {}", product.to_lowercase(), version);
        params.push(("keywordSearch", &kw_search));

        // Add CVSS filter if specified
        let cvss_filter = min_cvss.map(|min| format!("cvssV3BaseMetricGE:{:.1}", min));
        if let Some(ref cvss) = cvss_filter {
            params.push(("cvssV3Metrics", cvss.as_str()));
        }

        let response = self
            .client
            .get(&url)
            .query(&params)
            .send()
            .await
            .map_err(|e| AppError::Http {
                code: ErrorCode::HttpError,
                message: format!("Failed to fetch from NVD API: {}", e),
                source: Box::new(e),
            })?;

        if !response.status().is_success() {
            return Err(AppError::NvdApiError {
                code: ErrorCode::NvdApiError,
                message: format!("NVD API returned status {}", response.status()),
            });
        }

        let data: NvdResponse = response.json().await.map_err(|e| AppError::Json {
            code: ErrorCode::JsonError,
            message: format!("Failed to parse NVD response: {}", e),
            source: Box::new(e),
        })?;

        let cves = self.parse_nvd_response(&data, product, version);

        // Cache results
        self.cache.insert(cache_key, cves.clone()).await;

        // Update last sync time
        *self.last_sync.write().await = Some(Utc::now());

        Ok(cves)
    }

    /// Search CVEs by CPE
    pub async fn search_by_cpe(&self, cpe: &Cpe) -> Result<Vec<CveEntry>> {
        let cache_key = format!("cpe:{}", cpe.to_filter_string());
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let url = format!("{}/cves", self.base_url);
        let cpe_filter = cpe.to_filter_string();
        let params = vec![("cpeName", cpe_filter.as_str()), ("resultsPerPage", "100")];

        let response = self
            .client
            .get(&url)
            .query(&params)
            .send()
            .await
            .map_err(|e| AppError::Http {
                code: ErrorCode::HttpError,
                message: format!("Failed to fetch from NVD API: {}", e),
                source: Box::new(e),
            })?;

        let data: NvdResponse = response.json().await.map_err(|e| AppError::Json {
            code: ErrorCode::JsonError,
            message: format!("Failed to parse NVD response: {}", e),
            source: Box::new(e),
        })?;

        let cves = self.parse_nvd_response(&data, &cpe.vendor, &cpe.version);
        self.cache.insert(cache_key, cves.clone()).await;

        Ok(cves)
    }

    /// Get recent CVEs (last N days)
    pub async fn get_recent(&self, days: u32) -> Result<Vec<CveEntry>> {
        let url = format!("{}/cves", self.base_url);
        let now = Utc::now();
        let start = now - ChronoDuration::days(days as i64);

        // NVD v2 : lastModStartDate < lastModEndDate (start = passé, end = maintenant)
        let start_str = start.format("%Y-%m-%dT%H:%M:%S%.3f").to_string();
        let end_str = now.format("%Y-%m-%dT%H:%M:%S%.3f").to_string();
        let params = vec![
            ("lastModStartDate", start_str.as_str()),
            ("lastModEndDate", end_str.as_str()),
            ("resultsPerPage", "100"),
        ];

        let response = self
            .client
            .get(&url)
            .query(&params)
            .send()
            .await
            .map_err(|e| AppError::Http {
                code: ErrorCode::HttpError,
                message: format!("Failed to fetch recent CVEs: {}", e),
                source: Box::new(e),
            })?;

        let data: NvdResponse = response.json().await.map_err(|e| AppError::Json {
            code: ErrorCode::JsonError,
            message: format!("Failed to parse NVD response: {}", e),
            source: Box::new(e),
        })?;

        Ok(self.parse_nvd_response(&data, "*", "*"))
    }

    /// Check if cache is stale
    pub async fn is_cache_stale(&self, ttl_hours: u64) -> bool {
        match self.last_sync.read().await.as_ref() {
            Some(last) => Utc::now().signed_duration_since(*last).num_hours() > ttl_hours as i64,
            None => true,
        }
    }

    /// Clear the cache
    pub async fn clear_cache(&self) {
        self.cache.invalidate_all();
        *self.last_sync.write().await = None;
        info!("NVD cache cleared");
    }

    fn parse_nvd_response(
        &self,
        data: &NvdResponse,
        product: &str,
        version: &str,
    ) -> Vec<CveEntry> {
        data.vulnerabilities
            .iter()
            .filter_map(|vuln| {
                let cve = &vuln.cve;

                // Get CVSS score
                let (severity, vector) = self.extract_cvss(&cve.metrics);

                // Get description
                let desc = cve
                    .descriptions
                    .iter()
                    .find(|d| d.lang == "en")
                    .map(|d| d.value.clone())
                    .unwrap_or_else(|| "No description available".into());

                // Get affected versions from CPE matches
                let affected_versions =
                    self.extract_affected_versions(&cve.config, product, version);

                if affected_versions.is_empty() {
                    return None;
                }

                Some(CveEntry {
                    cve: cve.id.clone(),
                    severity,
                    desc,
                    affected_versions,
                    vector,
                    ..Default::default()
                })
            })
            .collect()
    }

    fn extract_cvss(&self, metrics: &Option<NvdMetrics>) -> (f32, String) {
        if let Some(m) = metrics {
            // Prefer V3.1, then V3.0, then V2
            if let Some(v31) = &m.cvss_metric_v31 {
                if let Some(metric) = v31.first() {
                    return (
                        metric.cvss_data.base_score as f32,
                        metric.cvss_data.vector_string.clone(),
                    );
                }
            }
            if let Some(v30) = &m.cvss_metric_v30 {
                if let Some(metric) = v30.first() {
                    return (
                        metric.cvss_data.base_score as f32,
                        metric.cvss_data.vector_string.clone(),
                    );
                }
            }
            if let Some(v2) = &m.cvss_metric_v2 {
                if let Some(metric) = v2.first() {
                    return (
                        metric.cvss_data.base_score as f32,
                        metric.cvss_data.vector_string.clone(),
                    );
                }
            }
        }
        (0.0, "UNKNOWN".into())
    }

    fn extract_affected_versions(
        &self,
        config: &Option<Vec<NvdConfig>>,
        product: &str,
        version: &str,
    ) -> Vec<String> {
        let mut versions = Vec::new();

        if let Some(configs) = config {
            for cfg in configs {
                for node in &cfg.nodes {
                    for cpe_match in &node.cpe_match {
                        if !cpe_match.vulnerable {
                            continue;
                        }

                        // Parse CPE and check if it matches our product
                        if let Some(cpe) = Cpe::parse(&cpe_match.criteria) {
                            if cpe.product.to_lowercase().contains(&product.to_lowercase())
                                || product.to_lowercase().contains(&cpe.vendor.to_lowercase())
                            {
                                // Add version range if specified
                                if let Some(start) = &cpe_match.version_start_excluding {
                                    versions.push(format!(">{}", start));
                                }
                                if let Some(start) = &cpe_match.version_start_including {
                                    versions.push(format!(">={}", start));
                                }
                                if let Some(end) = &cpe_match.version_end_excluding {
                                    versions.push(format!("<{}", end));
                                }
                                if let Some(end) = &cpe_match.version_end_including {
                                    versions.push(format!("<={}", end));
                                }

                                // If no range, use the version from CPE
                                if cpe_match.version_start_excluding.is_none()
                                    && cpe_match.version_start_including.is_none()
                                    && cpe_match.version_end_excluding.is_none()
                                    && cpe_match.version_end_including.is_none()
                                {
                                    if cpe.version != "*" && cpe.version != "any" {
                                        versions.push(cpe.version.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // If no specific versions found, add wildcard
        if versions.is_empty() {
            versions.push("*".into());
        }

        versions
    }
}

/// Mise à jour de la base CVE locale depuis l'API NVD v2
/// Télécharge les CVEs pour une liste de produits communs et enrichit cve_db.json.
///
/// Usage : `nrtg --update-cve-db` ou `nrtg --update-cve-db --cve-db /chemin/cve_db.json`
pub async fn update_cve_db_from_nvd(output_path: &str) -> anyhow::Result<usize> {
    use std::collections::HashMap;

    // Produits à interroger — couverture des services scannés par NRTG
    let products = vec![
        ("nginx", vec!["1.14", "1.18", "1.20", "1.24"]),
        ("apache", vec!["2.4.49", "2.4.50", "2.4.51", "2.4.54"]),
        ("openssh", vec!["7.6", "7.7", "8.0", "8.4", "8.9"]),
        ("redis", vec!["5.0", "6.0", "6.2", "7.0"]),
        ("mysql", vec!["5.7", "8.0"]),
        ("postgresql", vec!["12", "13", "14", "15"]),
        ("mongodb", vec!["4.4", "5.0", "6.0"]),
        ("vsftpd", vec!["2.3.4", "3.0"]),
        ("postfix", vec!["3.4", "3.6"]),
        ("samba", vec!["4.10", "4.14", "4.16"]),
        ("openssl", vec!["1.0.2", "1.1.1", "3.0"]),
        ("log4j", vec!["2.14", "2.15", "2.16", "2.17"]),
        ("php", vec!["8.2", "8.3", "8.4", "8.5"]),
    ];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("NRTG/2.0 CVE-DB-Updater")
        .build()?;

    // Charger la DB locale existante
    let mut db: HashMap<String, Vec<serde_json::Value>> =
        if std::path::Path::new(output_path).exists() {
            let content = std::fs::read_to_string(output_path).unwrap_or_default();
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            HashMap::new()
        };

    let mut total_added = 0usize;
    let base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    println!("🔄 Mise à jour CVE DB depuis NVD API v2...");
    println!("   Base : {}", output_path);

    for (product, _versions) in &products {
        print!("   Fetching {}… ", product);
        std::io::Write::flush(&mut std::io::stdout()).ok();

        let params = [("keywordSearch", *product), ("resultsPerPage", "200")];

        let resp = match client.get(base_url).query(&params).send().await {
            Ok(r) => r,
            Err(e) => {
                println!("SKIP ({})", e);
                continue;
            }
        };

        if !resp.status().is_success() {
            println!("SKIP (HTTP {})", resp.status());
            // NVD rate-limit: 5 req/30s sans clé API → attendre
            tokio::time::sleep(std::time::Duration::from_secs(6)).await;
            continue;
        }

        let json: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                println!("SKIP (parse: {})", e);
                continue;
            }
        };

        let vulns = json["vulnerabilities"]
            .as_array()
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let mut added = 0usize;

        for vuln in vulns {
            let cve_obj = &vuln["cve"];
            let cve_id = cve_obj["id"].as_str().unwrap_or("").to_string();
            if cve_id.is_empty() {
                continue;
            }

            // Score CVSS (préférer v3.1 > v3.0 > v2)
            let (severity, vector) = extract_cvss_from_json(cve_obj);
            if severity < 1.0 {
                continue;
            } // ignorer les non-scorées

            // Description anglaise
            let desc = cve_obj["descriptions"]
                .as_array()
                .and_then(|arr| arr.iter().find(|d| d["lang"].as_str() == Some("en")))
                .and_then(|d| d["value"].as_str())
                .unwrap_or("No description")
                .to_string();

            // Affected versions depuis CPE
            let affected = extract_affected_versions_json(cve_obj, product);

            // CISA KEV (p3a) : le champ `cisaExploitAdd` n'est présent que pour
            // les CVE exploitées « in the wild » → priorité maximale pour l'agent.
            let kev = cve_obj["cisaExploitAdd"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false);

            // Exploit public : référence taggée « Exploit » ou source
            // Exploit-DB / Metasploit.
            let exploit_public = cve_obj["references"]
                .as_array()
                .map(|refs| {
                    refs.iter().any(|r| {
                        let url = r["url"].as_str().unwrap_or("").to_lowercase();
                        let tagged = r["tags"]
                            .as_array()
                            .map(|t| t.iter().any(|x| x.as_str() == Some("Exploit")))
                            .unwrap_or(false);
                        tagged || url.contains("exploit-db.com") || url.contains("metasploit")
                    })
                })
                .unwrap_or(false);

            // Identifiants Exploit-DB (EDB-ID) extraits des URLs de référence NVD.
            let edb_ids: Vec<u32> = {
                let mut ids: Vec<u32> = cve_obj["references"]
                    .as_array()
                    .map(|refs| {
                        refs.iter()
                            .filter_map(|r| r["url"].as_str())
                            .filter_map(crate::cve::extract_edb_id)
                            .collect()
                    })
                    .unwrap_or_default();
                ids.sort_unstable();
                ids.dedup();
                ids
            };

            let entry = serde_json::json!({
                "cve":               cve_id,
                "severity":          severity,
                "desc":              desc,
                "vector":            vector,
                "affected_versions": affected,
                "kev":               kev,
                "exploit_public":    exploit_public,
                "edb_ids":           edb_ids,
            });

            let bucket = db.entry(product.to_string()).or_insert_with(Vec::new);
            // Dédupliquer
            if !bucket
                .iter()
                .any(|e| e["cve"].as_str() == Some(&entry["cve"].as_str().unwrap_or("")))
            {
                bucket.push(entry);
                added += 1;
                total_added += 1;
            }
        }

        println!("{} CVEs (+{})", vulns.len(), added);

        // Rate-limit NVD : max 5 req/30s sans clé API
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    }

    // Écrire la DB mise à jour
    let content = serde_json::to_string_pretty(&db)?;
    std::fs::write(output_path, content)?;

    println!(
        "✅ CVE DB mise à jour : {} nouvelles entrées → {}",
        total_added, output_path
    );
    println!(
        "   Total produits : {} | Total entrées : {}",
        db.len(),
        db.values().map(|v| v.len()).sum::<usize>()
    );

    Ok(total_added)
}

fn extract_cvss_from_json(cve: &serde_json::Value) -> (f32, String) {
    let metrics = &cve["metrics"];
    // V3.1
    if let Some(arr) = metrics["cvssMetricV31"].as_array() {
        if let Some(m) = arr.first() {
            let score = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
            let vec = m["cvssData"]["vectorString"]
                .as_str()
                .unwrap_or("UNKNOWN")
                .to_string();
            return (score, vec);
        }
    }
    // V3.0
    if let Some(arr) = metrics["cvssMetricV30"].as_array() {
        if let Some(m) = arr.first() {
            let score = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
            let vec = m["cvssData"]["vectorString"]
                .as_str()
                .unwrap_or("UNKNOWN")
                .to_string();
            return (score, vec);
        }
    }
    // V2
    if let Some(arr) = metrics["cvssMetricV2"].as_array() {
        if let Some(m) = arr.first() {
            let score = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
            let vec = m["cvssData"]["vectorString"]
                .as_str()
                .unwrap_or("UNKNOWN")
                .to_string();
            return (score, vec);
        }
    }
    (0.0, "UNKNOWN".to_string())
}

fn extract_affected_versions_json(cve: &serde_json::Value, product: &str) -> Vec<String> {
    let mut versions = Vec::new();
    if let Some(configs) = cve["configurations"].as_array() {
        for cfg in configs {
            if let Some(nodes) = cfg["nodes"].as_array() {
                for node in nodes {
                    if let Some(matches) = node["cpeMatch"].as_array() {
                        for m in matches {
                            if !m["vulnerable"].as_bool().unwrap_or(false) {
                                continue;
                            }
                            let criteria = m["criteria"].as_str().unwrap_or("");
                            if !criteria.to_lowercase().contains(&product.to_lowercase()) {
                                continue;
                            }
                            // Ranges
                            if let Some(s) = m["versionStartExcluding"].as_str() {
                                versions.push(format!(">{}", s));
                            }
                            if let Some(s) = m["versionStartIncluding"].as_str() {
                                versions.push(format!(">={}", s));
                            }
                            if let Some(e) = m["versionEndExcluding"].as_str() {
                                versions.push(format!("<{}", e));
                            }
                            if let Some(e) = m["versionEndIncluding"].as_str() {
                                versions.push(format!("<={}", e));
                            }
                            // Version exacte depuis CPE
                            let parts: Vec<&str> = criteria.split(':').collect();
                            if let Some(v) = parts.get(5) {
                                if *v != "*" && *v != "-" {
                                    versions.push(v.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if versions.is_empty() {
        versions.push("*".to_string());
    }
    versions.sort();
    versions.dedup();
    versions
}

/// Merge NVD CVEs with local database
pub fn merge_nvd_with_local(
    local: CveDatabase,
    nvd_entries: Vec<CveEntry>,
    product: &str,
) -> CveDatabase {
    let mut merged = local;
    let product_key = product.to_lowercase();

    if !nvd_entries.is_empty() {
        let entries = merged.entry(product_key).or_insert_with(Vec::new);
        for entry in nvd_entries {
            // Avoid duplicates
            if !entries.iter().any(|e| e.cve == entry.cve) {
                entries.push(entry);
            }
        }
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpe_parse() {
        let cpe = Cpe::parse("cpe:2.3:a:nginx:nginx:1.14.0:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.vendor, "nginx");
        assert_eq!(cpe.product, "nginx");
        assert_eq!(cpe.version, "1.14.0");
    }

    #[test]
    fn test_cpe_filter_string() {
        let cpe = Cpe {
            vendor: "nginx".into(),
            product: "nginx".into(),
            version: "1.14.0".into(),
            ..Default::default()
        };
        assert_eq!(
            cpe.to_filter_string(),
            "cpe:2.3:*:nginx:nginx:1.14.0:*:*:*:*:*:*:*"
        );
    }
}
