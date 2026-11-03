//! Error types for the Network Redteam Grapher.
//!
//! This module provides a comprehensive error hierarchy with specific error codes,
//! contextual messages, and proper error propagation.

use std::net::{AddrParseError, SocketAddr};
use thiserror::Error;
use validator::ValidationErrors;

/// Error codes for programmatic error handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // Configuration errors (1000-1999)
    ConfigNotFound = 1000,
    ConfigParseError = 1001,
    ConfigValidationError = 1002,

    // Network errors (2000-2999)
    ConnectionTimeout = 2000,
    ConnectionRefused = 2001,
    ConnectionReset = 2002,
    DnsResolutionFailed = 2003,
    InvalidTarget = 2004,
    NetworkUnreachable = 2005,

    // Scanning errors (3000-3999)
    BannerReadFailed = 3000,
    ServiceDetectionFailed = 3001,
    VersionExtractionFailed = 3002,
    ScanInterrupted = 3003,

    // CVE errors (4000-4999)
    CveDbNotFound = 4000,
    CveDbParseError = 4001,
    CveLookupFailed = 4002,
    NvdApiError = 4003,

    // Risk evaluation errors (5000-5999)
    RiskRulesNotFound = 5000,
    RiskRulesParseError = 5001,
    RiskEvaluationFailed = 5002,

    // Capture errors (6000-6999)
    CaptureInterfaceNotFound = 6000,
    CapturePermissionDenied = 6001,
    CaptureFailed = 6002,

    // I/O errors (7000-7999)
    FileNotFound = 7000,
    FileReadError = 7001,
    FileWriteError = 7002,
    SerializationError = 7003,
    DeserializationError = 7004,
    JsonError = 7005,
    HttpError = 7006,

    // Validation errors (8000-8999)
    ValidationError = 8000,
    InvalidInput = 8001,
    RateLimitExceeded = 8002,
    Generic = 9999,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "E{:04}", *self as u32)
    }
}

/// Main error type for the application
#[derive(Error, Debug)]
pub enum AppError {
    // === Configuration Errors ===
    #[error("[{code}] Configuration file not found: {path}")]
    ConfigNotFound { code: ErrorCode, path: String },

    #[error("[{code}] Failed to parse configuration: {message}")]
    ConfigParseError {
        code: ErrorCode,
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("[{code}] Configuration validation failed: {message}")]
    ConfigValidationError { code: ErrorCode, message: String },

    // === Network Errors ===
    #[error("[{code}] Connection to {host}:{port} timed out after {timeout}s")]
    ConnectionTimeout {
        code: ErrorCode,
        host: String,
        port: u16,
        timeout: u64,
    },

    #[error("[{code}] Connection refused to {addr}")]
    ConnectionRefused { code: ErrorCode, addr: SocketAddr },

    #[error("[{code}] Connection reset by peer: {addr}")]
    ConnectionReset { code: ErrorCode, addr: SocketAddr },

    #[error("[{code}] DNS resolution failed for {hostname}: {reason}")]
    DnsResolutionFailed {
        code: ErrorCode,
        hostname: String,
        reason: String,
    },

    #[error("[{code}] Invalid target format '{target}': {reason}")]
    InvalidTarget {
        code: ErrorCode,
        target: String,
        reason: String,
    },

    #[error("[{code}] Network unreachable: {message}")]
    NetworkUnreachable { code: ErrorCode, message: String },

    // === Scanning Errors ===
    #[error("[{code}] Failed to read banner from {host}:{port}: {reason}")]
    BannerReadFailed {
        code: ErrorCode,
        host: String,
        port: u16,
        reason: String,
    },

    #[error("[{code}] Service detection failed for {host}:{port}")]
    ServiceDetectionFailed {
        code: ErrorCode,
        host: String,
        port: u16,
    },

    #[error("[{code}] Failed to extract version from banner: {banner}")]
    VersionExtractionFailed { code: ErrorCode, banner: String },

    #[error("[{code}] Scan interrupted: {reason}")]
    ScanInterrupted { code: ErrorCode, reason: String },

    // === CVE Errors ===
    #[error("[{code}] CVE database not found at {path}")]
    CveDbNotFound { code: ErrorCode, path: String },

    #[error("[{code}] Failed to parse CVE database: {message}")]
    CveDbParseError { code: ErrorCode, message: String },

    #[error("[{code}] CVE lookup failed for {product} {version}: {reason}")]
    CveLookupFailed {
        code: ErrorCode,
        product: String,
        version: String,
        reason: String,
    },

    #[error("[{code}] NVD API error: {message}")]
    NvdApiError { code: ErrorCode, message: String },

    // === Risk Evaluation Errors ===
    #[error("[{code}] Risk rules file not found at {path}")]
    RiskRulesNotFound { code: ErrorCode, path: String },

    #[error("[{code}] Failed to parse risk rules: {message}")]
    RiskRulesParseError { code: ErrorCode, message: String },

    #[error("[{code}] Risk evaluation failed: {reason}")]
    RiskEvaluationFailed { code: ErrorCode, reason: String },

    // === Capture Errors ===
    #[error("[{code}] Network interface '{interface}' not found")]
    CaptureInterfaceNotFound { code: ErrorCode, interface: String },

    #[error("[{code}] Permission denied for packet capture (try running as admin/root)")]
    CapturePermissionDenied { code: ErrorCode },

    #[error("[{code}] Packet capture failed: {reason}")]
    CaptureFailed { code: ErrorCode, reason: String },

    // === I/O Errors ===
    #[error("[{code}] File not found: {path}")]
    FileNotFound { code: ErrorCode, path: String },

    #[error("[{code}] Failed to read file {path}: {reason}")]
    FileReadError {
        code: ErrorCode,
        path: String,
        reason: String,
    },

    #[error("[{code}] Failed to write file {path}: {reason}")]
    FileWriteError {
        code: ErrorCode,
        path: String,
        reason: String,
    },

    #[error("[{code}] Serialization error: {message}")]
    SerializationError { code: ErrorCode, message: String },

    #[error("[{code}] Deserialization error: {message}")]
    DeserializationError { code: ErrorCode, message: String },

    // === Validation Errors ===
    #[error("[{code}] Validation error: {message}")]
    ValidationError { code: ErrorCode, message: String },

    #[error("[{code}] Invalid input: {message}")]
    InvalidInput { code: ErrorCode, message: String },

    #[error("[{code}] Rate limit exceeded for {target}")]
    RateLimitExceeded { code: ErrorCode, target: String },

    // === External Errors (wrapped) ===
    #[error("[E{code}] IO error: {message}")]
    Io {
        code: ErrorCode,
        message: String,
        #[source]
        source: std::io::Error,
    },

    #[error("[E{code}] URL parse error: {message}")]
    UrlParse {
        code: ErrorCode,
        message: String,
        #[source]
        source: url::ParseError,
    },

    #[error("[E{code}] JSON error: {message}")]
    Json {
        code: ErrorCode,
        message: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("[E{code}] YAML error: {message}")]
    YAML {
        code: ErrorCode,
        message: String,
        source_str: String,
    },

    #[error("[E{code}] TOML error: {message}")]
    TOML {
        code: ErrorCode,
        message: String,
        #[source]
        source: toml::de::Error,
    },

    #[error("[E{code}] CSV error: {message}")]
    Csv {
        code: ErrorCode,
        message: String,
        #[source]
        source: csv::Error,
    },

    #[error("[E{code}] HTTP error: {message}")]
    Http {
        code: ErrorCode,
        message: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("[E{code}] Address parse error: {message}")]
    AddrParse {
        code: ErrorCode,
        message: String,
        #[source]
        source: AddrParseError,
    },

    // === Generic Errors ===
    #[error("[{code}] {message}")]
    Generic { code: ErrorCode, message: String },

    #[error("Unexpected error: {0}")]
    Unexpected(String),
}

impl AppError {
    /// Get the error code
    pub fn code(&self) -> ErrorCode {
        match self {
            AppError::ConfigNotFound { code, .. } => *code,
            AppError::ConfigParseError { code, .. } => *code,
            AppError::ConfigValidationError { code, .. } => *code,
            AppError::ConnectionTimeout { code, .. } => *code,
            AppError::ConnectionRefused { code, .. } => *code,
            AppError::ConnectionReset { code, .. } => *code,
            AppError::DnsResolutionFailed { code, .. } => *code,
            AppError::InvalidTarget { code, .. } => *code,
            AppError::NetworkUnreachable { code, .. } => *code,
            AppError::BannerReadFailed { code, .. } => *code,
            AppError::ServiceDetectionFailed { code, .. } => *code,
            AppError::VersionExtractionFailed { code, .. } => *code,
            AppError::ScanInterrupted { code, .. } => *code,
            AppError::CveDbNotFound { code, .. } => *code,
            AppError::CveDbParseError { code, .. } => *code,
            AppError::CveLookupFailed { code, .. } => *code,
            AppError::NvdApiError { code, .. } => *code,
            AppError::RiskRulesNotFound { code, .. } => *code,
            AppError::RiskRulesParseError { code, .. } => *code,
            AppError::RiskEvaluationFailed { code, .. } => *code,
            AppError::CaptureInterfaceNotFound { code, .. } => *code,
            AppError::CapturePermissionDenied { code, .. } => *code,
            AppError::CaptureFailed { code, .. } => *code,
            AppError::FileNotFound { code, .. } => *code,
            AppError::FileReadError { code, .. } => *code,
            AppError::FileWriteError { code, .. } => *code,
            AppError::SerializationError { code, .. } => *code,
            AppError::DeserializationError { code, .. } => *code,
            AppError::ValidationError { code, .. } => *code,
            AppError::InvalidInput { code, .. } => *code,
            AppError::RateLimitExceeded { code, .. } => *code,
            AppError::Io { code, .. } => *code,
            AppError::UrlParse { code, .. } => *code,
            AppError::Json { code, .. } => *code,
            AppError::YAML { code, .. } => *code,
            AppError::TOML { code, .. } => *code,
            AppError::Csv { code, .. } => *code,
            AppError::Http { code, .. } => *code,
            AppError::AddrParse { code, .. } => *code,
            AppError::Generic { code, .. } => *code,
            AppError::Unexpected(_) => ErrorCode::ConfigParseError,
        }
    }

    /// Create a config not found error
    pub fn config_not_found(path: impl Into<String>) -> Self {
        let path = path.into();
        AppError::ConfigNotFound {
            code: ErrorCode::ConfigNotFound,
            path,
        }
    }

    /// Create a connection timeout error
    pub fn connection_timeout(host: impl Into<String>, port: u16, timeout: u64) -> Self {
        AppError::ConnectionTimeout {
            code: ErrorCode::ConnectionTimeout,
            host: host.into(),
            port,
            timeout,
        }
    }

    /// Create an invalid target error
    pub fn invalid_target(target: impl Into<String>, reason: impl Into<String>) -> Self {
        AppError::InvalidTarget {
            code: ErrorCode::InvalidTarget,
            target: target.into(),
            reason: reason.into(),
        }
    }
}

// === From implementations for external errors ===

impl From<ValidationErrors> for AppError {
    fn from(err: ValidationErrors) -> Self {
        AppError::ValidationError {
            code: ErrorCode::ValidationError,
            message: err.to_string(),
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => AppError::FileNotFound {
                code: ErrorCode::FileNotFound,
                path: err.to_string(),
            },
            std::io::ErrorKind::ConnectionRefused => AppError::ConnectionRefused {
                code: ErrorCode::ConnectionRefused,
                addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            },
            std::io::ErrorKind::TimedOut => AppError::ConnectionTimeout {
                code: ErrorCode::ConnectionTimeout,
                host: "unknown".into(),
                port: 0,
                timeout: 0,
            },
            _ => AppError::Io {
                code: ErrorCode::FileReadError,
                message: err.to_string(),
                source: err,
            },
        }
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Json {
            code: ErrorCode::JsonError,
            message: err.to_string(),
            source: Box::new(err),
        }
    }
}

impl From<serde_yaml::Error> for AppError {
    fn from(err: serde_yaml::Error) -> Self {
        AppError::YAML {
            code: ErrorCode::DeserializationError,
            message: err.to_string(),
            source_str: err.to_string(),
        }
    }
}

impl From<toml::de::Error> for AppError {
    fn from(err: toml::de::Error) -> Self {
        AppError::TOML {
            code: ErrorCode::ConfigParseError,
            message: err.to_string(),
            source: err,
        }
    }
}

impl From<csv::Error> for AppError {
    fn from(err: csv::Error) -> Self {
        AppError::Csv {
            code: ErrorCode::SerializationError,
            message: err.to_string(),
            source: err,
        }
    }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        AppError::Http {
            code: ErrorCode::HttpError,
            message: err.to_string(),
            source: Box::new(err),
        }
    }
}

impl From<url::ParseError> for AppError {
    fn from(err: url::ParseError) -> Self {
        AppError::UrlParse {
            code: ErrorCode::InvalidTarget,
            message: err.to_string(),
            source: err,
        }
    }
}

impl From<AddrParseError> for AppError {
    fn from(err: AddrParseError) -> Self {
        AppError::AddrParse {
            code: ErrorCode::InvalidTarget,
            message: err.to_string(),
            source: err,
        }
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for AppError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        AppError::Unexpected(err.to_string())
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            return io_err.kind().into_app_error(err.to_string());
        }
        if let Some(json_err) = err.downcast_ref::<serde_json::Error>() {
            let msg = json_err.to_string();
            return AppError::Json {
                code: ErrorCode::JsonError,
                message: msg.clone(),
                source: Box::new(std::io::Error::other(msg)),
            };
        }
        if let Some(yaml_err) = err.downcast_ref::<serde_yaml::Error>() {
            let msg = yaml_err.to_string();
            return AppError::YAML {
                code: ErrorCode::DeserializationError,
                message: msg.clone(),
                source_str: msg,
            };
        }
        if let Some(toml_err) = err.downcast_ref::<toml::de::Error>() {
            let msg = toml_err.to_string();
            return AppError::TOML {
                code: ErrorCode::ConfigParseError,
                message: msg.clone(),
                source: toml_err.clone(),
            };
        }
        if let Some(url_err) = err.downcast_ref::<url::ParseError>() {
            let msg = url_err.to_string();
            return AppError::UrlParse {
                code: ErrorCode::InvalidTarget,
                message: msg.clone(),
                source: url_err.clone(),
            };
        }
        if let Some(addr_err) = err.downcast_ref::<AddrParseError>() {
            let msg = addr_err.to_string();
            return AppError::AddrParse {
                code: ErrorCode::InvalidTarget,
                message: msg.clone(),
                source: addr_err.clone(),
            };
        }
        if let Some(valid_err) = err.downcast_ref::<ValidationErrors>() {
            return AppError::ValidationError {
                code: ErrorCode::ValidationError,
                message: valid_err.to_string(),
            };
        }
        let msg = err.to_string();
        let lower = msg.to_lowercase();
        let code = if lower.contains("config") || lower.contains("configuration") {
            ErrorCode::ConfigParseError
        } else if lower.contains("cve") {
            ErrorCode::CveLookupFailed
        } else if lower.contains("risk") {
            ErrorCode::RiskEvaluationFailed
        } else if lower.contains("banner") || lower.contains("scan") {
            ErrorCode::BannerReadFailed
        } else if lower.contains("timeout") || lower.contains("timed out") {
            ErrorCode::ConnectionTimeout
        } else if lower.contains("permission") {
            ErrorCode::CapturePermissionDenied
        } else if lower.contains("interface") {
            ErrorCode::CaptureInterfaceNotFound
        } else if lower.contains("serializ") {
            ErrorCode::SerializationError
        } else if lower.contains("deserializ") {
            ErrorCode::DeserializationError
        } else if lower.contains("not found") || lower.contains("no such file") {
            ErrorCode::FileNotFound
        } else if lower.contains("http") {
            ErrorCode::HttpError
        } else {
            ErrorCode::Generic
        };
        AppError::Generic { code, message: msg }
    }
}

trait IntoAppError {
    fn into_app_error(self, msg: String) -> AppError;
}

impl IntoAppError for std::io::ErrorKind {
    fn into_app_error(self, msg: String) -> AppError {
        match self {
            std::io::ErrorKind::NotFound => AppError::FileNotFound {
                code: ErrorCode::FileNotFound,
                path: msg,
            },
            std::io::ErrorKind::PermissionDenied => AppError::CapturePermissionDenied {
                code: ErrorCode::CapturePermissionDenied,
            },
            std::io::ErrorKind::ConnectionRefused => AppError::ConnectionRefused {
                code: ErrorCode::ConnectionRefused,
                addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            },
            std::io::ErrorKind::TimedOut => AppError::ConnectionTimeout {
                code: ErrorCode::ConnectionTimeout,
                host: "unknown".into(),
                port: 0,
                timeout: 0,
            },
            std::io::ErrorKind::ConnectionReset => AppError::ConnectionReset {
                code: ErrorCode::ConnectionReset,
                addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            },
            other => AppError::Io {
                code: if matches!(other, std::io::ErrorKind::WriteZero) {
                    ErrorCode::FileWriteError
                } else {
                    ErrorCode::FileReadError
                },
                message: msg,
                source: std::io::Error::from(other),
            },
        }
    }
}

/// Result type alias for the application
pub type Result<T> = std::result::Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_display() {
        assert_eq!(format!("{}", ErrorCode::ConfigNotFound), "E1000");
        assert_eq!(format!("{}", ErrorCode::ConnectionTimeout), "E2000");
    }

    #[test]
    fn test_config_not_found() {
        let err = AppError::config_not_found("/path/to/config.json");
        assert_eq!(err.code(), ErrorCode::ConfigNotFound);
        assert!(err.to_string().contains("/path/to/config.json"));
    }

    #[test]
    fn test_connection_timeout() {
        let err = AppError::connection_timeout("example.com", 80, 5);
        assert_eq!(err.code(), ErrorCode::ConnectionTimeout);
        assert!(err.to_string().contains("example.com"));
        assert!(err.to_string().contains("80"));
        assert!(err.to_string().contains("5"));
    }
}
