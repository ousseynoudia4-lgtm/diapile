//! Logging configuration for the Network Redteam Grapher.
//!
//! This module provides structured logging with tracing, JSON output support,
//! and optional file output.

use crate::config::LoggingConfig;
use std::fs::File;
use std::sync::Arc;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};

/// Initialize logging based on configuration
pub fn init_logging(
    config: &LoggingConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));

    let subscriber = Registry::default().with(env_filter);

    match config.format.as_str() {
        "json" => {
            let layer = fmt::layer()
                .json()
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true);

            if let Some(ref file) = config.file {
                let writer = File::create(file)?;
                subscriber.with(layer.with_writer(Arc::new(writer))).init();
            } else {
                subscriber.with(layer).init();
            }
        }
        "compact" => {
            let layer = fmt::layer().compact().with_target(false).without_time();

            if let Some(ref file) = config.file {
                let writer = File::create(file)?;
                subscriber.with(layer.with_writer(Arc::new(writer))).init();
            } else {
                subscriber.with(layer).init();
            }
        }
        _ => {
            // Default pretty format
            let layer = fmt::layer()
                .pretty()
                .with_target(true)
                .with_thread_ids(false);

            if let Some(ref file) = config.file {
                let writer = File::create(file)?;
                subscriber.with(layer.with_writer(Arc::new(writer))).init();
            } else {
                subscriber.with(layer).init();
            }
        }
    }

    tracing::info!(
        "Logging initialized with level={} format={}",
        config.level,
        config.format
    );
    Ok(())
}

/// Logging macros for common operations
#[macro_export]
macro_rules! scan_info {
    ($($arg:tt)*) => {
        tracing::info!(target: "scanner", $($arg)*)
    };
}

#[macro_export]
macro_rules! scan_warn {
    ($($arg:tt)*) => {
        tracing::warn!(target: "scanner", $($arg)*)
    };
}

#[macro_export]
macro_rules! scan_error {
    ($($arg:tt)*) => {
        tracing::error!(target: "scanner", $($arg)*)
    };
}

#[macro_export]
macro_rules! scan_debug {
    ($($arg:tt)*) => {
        tracing::debug!(target: "scanner", $($arg)*)
    };
}

#[macro_export]
macro_rules! cve_info {
    ($($arg:tt)*) => {
        tracing::info!(target: "cve", $($arg)*)
    };
}

#[macro_export]
macro_rules! risk_info {
    ($($arg:tt)*) => {
        tracing::info!(target: "risk", $($arg)*)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_init() {
        let config = LoggingConfig {
            level: "info".into(),
            format: "compact".into(),
            file: None,
            rotate: false,
            max_size_mb: 100,
            keep_files: 5,
        };
        // Should not panic
        let _ = init_logging(&config);
    }
}
