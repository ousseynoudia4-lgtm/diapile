//! Configuration management for the Network Redteam Grapher.
//!
//! This module provides configuration loading from multiple sources (JSON, YAML, TOML)
//! with validation and hierarchical merging (file < CLI < environment).

use crate::errors::{AppError, ErrorCode, Result};
pub use crate::llm::LlmConfig;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use validator::Validate;

/// Configuration file format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Json,
    Yaml,
    Toml,
}

impl ConfigFormat {
    /// Detect format from file extension
    pub fn from_extension(path: &Path) -> Option<Self> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("json") => Some(ConfigFormat::Json),
            Some("yaml" | "yml") => Some(ConfigFormat::Yaml),
            Some("toml") => Some(ConfigFormat::Toml),
            _ => None,
        }
    }

    /// Get default filename for format
    pub fn default_filename(self) -> &'static str {
        match self {
            ConfigFormat::Json => "config.json",
            ConfigFormat::Yaml => "config.yaml",
            ConfigFormat::Toml => "config.toml",
        }
    }
}

/// Main configuration structure
#[derive(Debug, Clone, Validate, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Target hosts to scan
    #[validate(length(min = 0, max = 10000, message = "Maximum 10000 targets allowed"))]
    pub targets: Vec<String>,

    /// Scan options
    pub options: ScanOptions,

    /// LLM / AI agent options (définition CANONIQUE dans crate::llm::LlmConfig, ré-exporée ici)
    pub llm: LlmConfig,

    /// CVE database configuration
    pub cve: CveConfig,

    /// Risk evaluation configuration
    pub risk: RiskConfig,

    /// Capture configuration
    pub capture: CaptureConfig,

    /// Output configuration
    pub output: OutputConfig,

    /// Logging configuration
    pub logging: LoggingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: vec![
                "http://localhost:8080".into(),
                "http://localhost:3000".into(),
                "127.0.0.1:6379".into(),
                "127.0.0.1:2222".into(),
            ],
            options: ScanOptions::default(),
            llm: LlmConfig::default(),
            cve: CveConfig::default(),
            risk: RiskConfig::default(),
            capture: CaptureConfig::default(),
            output: OutputConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// Scan-specific options
#[derive(Debug, Clone, Validate, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanOptions {
    /// HTTP connection timeout in seconds
    #[validate(range(
        min = 1,
        max = 300,
        message = "HTTP timeout must be between 1 and 300 seconds"
    ))]
    pub http_timeout: u64,

    /// TCP connection timeout in seconds
    #[validate(range(
        min = 1,
        max = 300,
        message = "TCP timeout must be between 1 and 300 seconds"
    ))]
    pub tcp_timeout: u64,

    /// Maximum concurrent scans
    #[validate(range(
        min = 1,
        max = 1000,
        message = "Max concurrency must be between 1 and 1000"
    ))]
    pub max_concurrency: usize,

    /// Rate limit (requests per second, 0 = unlimited)
    #[validate(range(
        min = 0,
        max = 10000,
        message = "Rate limit must be between 0 and 10000"
    ))]
    pub rate_limit: u32,

    /// User agent for HTTP requests
    pub user_agent: String,

    /// Follow HTTP redirects
    pub follow_redirects: bool,

    /// Maximum redirect depth
    pub max_redirects: usize,

    /// Verify TLS certificates
    pub verify_tls: bool,

    /// Retry configuration
    pub retry: RetryConfig,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            http_timeout: 5,
            tcp_timeout: 3,
            max_concurrency: 50,
            rate_limit: 0,
            user_agent: "Mozilla/5.0 (compatible; NRTG/2.0; SecurityScanner)".into(),
            follow_redirects: true,
            max_redirects: 5,
            verify_tls: true,
            retry: RetryConfig::default(),
        }
    }
}

/// Retry configuration
#[derive(Debug, Clone, Validate, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryConfig {
    /// Number of retries on failure
    #[validate(range(min = 0, max = 10, message = "Retries must be between 0 and 10"))]
    pub max_retries: u32,

    /// Initial retry delay in milliseconds
    #[validate(range(
        min = 100,
        max = 60000,
        message = "Initial delay must be between 100ms and 60s"
    ))]
    pub initial_delay_ms: u64,

    /// Maximum retry delay in milliseconds
    #[validate(range(
        min = 1000,
        max = 300000,
        message = "Max delay must be between 1s and 5m"
    ))]
    pub max_delay_ms: u64,

    /// Backoff multiplier
    #[validate(range(
        min = 1.0,
        max = 10.0,
        message = "Backoff must be between 1.0 and 10.0"
    ))]
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 2,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
        }
    }
}

/// CVE database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CveConfig {
    /// Path to local CVE database file
    pub db_path: String,

    /// Enable NVD API synchronization
    pub enable_nvd_sync: bool,

    /// NVD API key (optional)
    pub nvd_api_key: Option<String>,

    /// NVD API base URL
    pub nvd_api_url: String,

    /// Cache TTL for NVD data in hours
    pub nvd_cache_ttl_hours: u64,

    /// Minimum CVSS severity to include
    pub min_cvss_score: f32,

    /// CVE database format
    pub format: String,
}

impl Default for CveConfig {
    fn default() -> Self {
        Self {
            db_path: "cve_db.json".into(),
            enable_nvd_sync: false,
            nvd_api_key: None,
            nvd_api_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
            nvd_cache_ttl_hours: 24,
            min_cvss_score: 0.0,
            format: "json".into(),
        }
    }
}

/// Risk evaluation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskConfig {
    /// Path to risk rules file
    pub rules_path: String,

    /// Maximum risk level
    pub max_risk: i32,

    /// Enable CVSS-based risk adjustment
    pub use_cvss_scoring: bool,

    /// Enable EPSS-based exploitability scoring
    pub use_epss_scoring: bool,

    /// Risk factors weights
    pub weights: RiskWeights,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            rules_path: "risk_rules.json".into(),
            max_risk: 5,
            use_cvss_scoring: true,
            use_epss_scoring: false,
            weights: RiskWeights::default(),
        }
    }
}

/// Risk weight configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskWeights {
    /// Weight for base service risk
    pub base_service: f32,

    /// Weight for version-based risk
    pub version: f32,

    /// Weight for CVE severity
    pub cve_severity: f32,

    /// Weight for exploitability
    pub exploitability: f32,

    /// Weight for exposure
    pub exposure: f32,
}

impl Default for RiskWeights {
    fn default() -> Self {
        Self {
            base_service: 0.3,
            version: 0.2,
            cve_severity: 0.3,
            exploitability: 0.1,
            exposure: 0.1,
        }
    }
}

/// Packet capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    /// Network interface to capture on
    pub interface: Option<String>,

    /// Capture duration in seconds
    pub duration_sec: u64,

    /// Maximum flows to track
    pub max_flows: usize,

    /// Capture filter (BPF syntax)
    pub filter: Option<String>,

    /// Output file for raw capture
    pub output_path: Option<String>,

    /// Enable promiscuous mode
    pub promiscuous: bool,

    /// Snapshot length (0 = default)
    pub snaplen: u32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: None,
            duration_sec: 30,
            max_flows: 500,
            filter: None,
            output_path: None,
            promiscuous: false,
            snaplen: 65535,
        }
    }
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    /// Output file for graph JSON
    pub graph_file: String,

    /// Export CSV report
    pub csv_report: bool,

    /// Export Markdown report
    pub md_report: bool,

    /// Export PDF report
    pub pdf_report: bool,

    /// Export JSON lines format
    pub jsonl_report: bool,

    /// Output directory
    pub output_dir: String,

    /// Pretty print JSON output
    pub pretty_json: bool,

    /// Include raw banners in output
    pub include_raw_banners: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            graph_file: "graph.json".into(),
            csv_report: false,
            md_report: false,
            pdf_report: false,
            jsonl_report: false,
            output_dir: ".".into(),
            pretty_json: true,
            include_raw_banners: false,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,

    /// Log format (json, pretty, compact)
    pub format: String,

    /// Log file path (empty = stdout)
    pub file: Option<String>,

    /// Enable file rotation
    pub rotate: bool,

    /// Maximum log file size in MB
    pub max_size_mb: u64,

    /// Maximum number of log files to keep
    pub keep_files: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: "pretty".into(),
            file: None,
            rotate: false,
            max_size_mb: 100,
            keep_files: 5,
        }
    }
}

/// Configuration loader
pub struct ConfigLoader {
    format: Option<ConfigFormat>,
}

impl ConfigLoader {
    /// Create a new config loader
    pub fn new() -> Self {
        Self { format: None }
    }

    /// Set the configuration format
    pub fn format(mut self, format: ConfigFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Load configuration from file
    pub fn load<P: AsRef<Path>>(self, path: P) -> Result<Config> {
        let path = path.as_ref();
        let format = self.format.or_else(|| ConfigFormat::from_extension(path));

        let content = fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::config_not_found(path.display().to_string())
            } else {
                AppError::from(e)
            }
        })?;

        let config: Config = match format {
            Some(ConfigFormat::Json) => serde_json::from_str(&content)?,
            Some(ConfigFormat::Yaml) => serde_yaml::from_str(&content)?,
            Some(ConfigFormat::Toml) => toml::from_str(&content)?,
            None => serde_json::from_str(&content)
                .or_else(|_| serde_yaml::from_str(&content))
                .or_else(|_| toml::from_str(&content))
                .map_err(|_| AppError::ConfigParseError {
                    code: ErrorCode::ConfigParseError,
                    message: format!("Could not parse config file: {}", path.display()),
                    source: None,
                })?,
        };

        config.validate()?;
        Ok(config)
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Merge CLI arguments into configuration
pub fn merge_cli_config(
    config: &mut Config,
    cli_targets: Option<Vec<String>>,
    cli_options: &CliScanOptions,
) {
    if let Some(targets) = cli_targets {
        if !targets.is_empty() {
            config.targets = targets;
        }
    }

    if cli_options.http_timeout > 0 {
        config.options.http_timeout = cli_options.http_timeout;
    }

    if cli_options.tcp_timeout > 0 {
        config.options.tcp_timeout = cli_options.tcp_timeout;
    }

    if cli_options.max_concurrency > 0 {
        config.options.max_concurrency = cli_options.max_concurrency;
    }

    if let Some(ref cve_db) = cli_options.cve_db {
        config.cve.db_path = cve_db.clone();
    }

    if let Some(ref risk_rules) = cli_options.risk_rules {
        config.risk.rules_path = risk_rules.clone();
    }

    if !cli_options.output.is_empty() {
        config.output.graph_file = cli_options.output.clone();
    }

    config.options.retry.max_retries = cli_options.retries;
    config.options.verify_tls = cli_options.verify_tls;
}

/// CLI scan options for merging
#[derive(Debug, Clone)]
pub struct CliScanOptions {
    pub http_timeout: u64,
    pub tcp_timeout: u64,
    pub max_concurrency: usize,
    pub cve_db: Option<String>,
    pub risk_rules: Option<String>,
    pub output: String,
    pub retries: u32,
    pub verify_tls: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.options.http_timeout, 5);
        assert_eq!(config.options.tcp_timeout, 3);
        assert_eq!(config.options.max_concurrency, 50);
    }

    #[test]
    fn test_config_format_detection() {
        assert_eq!(
            ConfigFormat::from_extension(Path::new("config.json")),
            Some(ConfigFormat::Json)
        );
        assert_eq!(
            ConfigFormat::from_extension(Path::new("config.yaml")),
            Some(ConfigFormat::Yaml)
        );
        assert_eq!(
            ConfigFormat::from_extension(Path::new("config.toml")),
            Some(ConfigFormat::Toml)
        );
    }

    #[test]
    fn test_retry_config_exponential_backoff() {
        let retry = RetryConfig::default();
        let delay = retry.initial_delay_ms * (retry.backoff_multiplier.powi(2) as u64);
        assert!(delay <= retry.max_delay_ms);
    }

    #[test]
    fn llm_config_uses_canonical_llm_module_definition() {
        let cfg = Config::default();
        // Vérifie que Config.llm utilise bien la définition CANONIQUE (llm.rs — 10 champs)
        // et non plus l'ancien doublon (config.rs — 5 champs faux).
        // Preuve: provider (LlmProvider enum), top_p, timeout Duration, retries, json_mode
        // sont TOUS des champs qui n'existaient PAS dans l'ancien config.rs::LlmConfig.
        assert_eq!(cfg.llm.provider, crate::llm::LlmProvider::OpenRouter);
        assert_eq!(cfg.llm.top_p, 0.9);
        assert_eq!(cfg.llm.max_tokens, 4096);
        assert_eq!(cfg.llm.timeout, std::time::Duration::from_secs(120));
        assert_eq!(cfg.llm.retries, 4);
        assert!(cfg.llm.json_mode);
    }
}
