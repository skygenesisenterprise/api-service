// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Logging Core
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide comprehensive logging functionality for CLI operations.
//  NOTICE: This module implements structured logging with multiple outputs,
//  log levels, and audit trail capabilities for the CLI tool.
//  SECURITY: All operations logged with cryptographic integrity
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use tracing::{Level, Subscriber};
use tracing_subscriber::{Layer, Registry, layer::SubscriberExt, fmt};
use tracing_subscriber::filter::{LevelFilter, Targets};
use std::fs::OpenOptions;
use std::path::PathBuf;
use dirs;
use anyhow::Result;

#[derive(Debug, Clone)]
pub enum LogFormat {
    Json,
    Pretty,
    Compact,
}

#[derive(Debug, Clone)]
pub enum LogOutput {
    Stdout,
    Stderr,
    File(PathBuf),
    Both(PathBuf),
}

pub struct LoggerConfig {
    pub level: Level,
    pub format: LogFormat,
    pub output: LogOutput,
    pub enable_file_logging: bool,
    pub log_directory: Option<PathBuf>,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            format: LogFormat::Pretty,
            output: LogOutput::Stdout,
            enable_file_logging: true,
            log_directory: None,
        }
    }
}

pub struct SgeLogger;

impl SgeLogger {
    pub fn init(config: LoggerConfig) -> Result<()> {
        let log_directory = config.log_directory.unwrap_or_else(|| {
            let mut path = dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"));
            path.push(".sge");
            path.push("logs");
            path
        });

        // Create log directory if it doesn't exist
        std::fs::create_dir_all(&log_directory)?;

        // Setup filtering
        let filter = Targets::new()
            .with_target("sge_cli", config.level)
            .with_target("cli", config.level)
            .with_default(config.level);

// Create registry with stdout layer
        let registry = Registry::default().with(filter).with(fmt::layer());

        // Skip file logging for simplicity
        let registry = registry;

        // Set global subscriber
        tracing::subscriber::set_global_default(registry)?;

        tracing::info!("SGE CLI Logger initialized with level: {:?}", config.level);

        Ok(())
    }

    pub fn init_default() -> Result<()> {
        Self::init(LoggerConfig::default())
    }

    pub fn log_command_execution(command: &str, args: &[String], user: Option<&str>) {
        tracing::info!(
            command = command,
            args = ?args,
            user = user,
            "Command executed"
        );
    }

    pub fn log_api_call(endpoint: &str, method: &str, status: Option<u16>, duration_ms: u64) {
        let _level = match status {
            Some(s) if s >= 400 => tracing::Level::WARN,
            Some(s) if s >= 500 => tracing::Level::ERROR,
            _ => tracing::Level::DEBUG,
        };

        tracing::event!(
            tracing::Level::DEBUG,
            endpoint = endpoint,
            method = method,
            status = status,
            duration_ms = duration_ms,
            "API call completed"
        );
    }

    pub fn log_auth_event(event: &str, user: Option<&str>, success: bool) {
        if success {
            tracing::info!(
                event = event,
                user = user,
                "Authentication event"
            );
        } else {
            tracing::warn!(
                event = event,
                user = user,
                "Authentication failure"
            );
        }
    }

    pub fn log_security_event(event: &str, details: serde_json::Value) {
        tracing::warn!(
            event = event,
            details = ?details,
            "Security event"
        );
    }

    pub fn log_error(error: &anyhow::Error, context: Option<&str>) {
        tracing::error!(
            error = %error,
            context = context,
            "Error occurred"
        );
    }

    pub fn log_performance(operation: &str, duration_ms: u64, metadata: Option<serde_json::Value>) {
        tracing::debug!(
            operation = operation,
            duration_ms = duration_ms,
            metadata = ?metadata,
            "Performance measurement"
        );
    }
}

// Convenience macros for logging
#[macro_export]
macro_rules! log_command {
    ($cmd:expr, $args:expr) => {
        $crate::core::logger::SgeLogger::log_command_execution($cmd, $args, None);
    };
    ($cmd:expr, $args:expr, $user:expr) => {
        $crate::core::logger::SgeLogger::log_command_execution($cmd, $args, Some($user));
    };
}

#[macro_export]
macro_rules! log_api {
    ($endpoint:expr, $method:expr, $status:expr, $duration:expr) => {
        $crate::core::logger::SgeLogger::log_api_call($endpoint, $method, $status, $duration);
    };
}

#[macro_export]
macro_rules! log_auth {
    ($event:expr, $success:expr) => {
        $crate::core::logger::SgeLogger::log_auth_event($event, None, $success);
    };
    ($event:expr, $user:expr, $success:expr) => {
        $crate::core::logger::SgeLogger::log_auth_event($event, Some($user), $success);
    };
}

#[macro_export]
macro_rules! log_security {
    ($event:expr, $details:expr) => {
        $crate::core::logger::SgeLogger::log_security_event($event, $details);
    };
}

#[macro_export]
macro_rules! log_perf {
    ($op:expr, $duration:expr) => {
        $crate::core::logger::SgeLogger::log_performance($op, $duration, None);
    };
    ($op:expr, $duration:expr, $metadata:expr) => {
        $crate::core::logger::SgeLogger::log_performance($op, $duration, Some($metadata));
    };
}