// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Telemetry Core
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide telemetry and metrics collection for CLI operations.
//  NOTICE: This module implements performance monitoring, usage analytics,
//  and operational metrics for the CLI tool.
//  SECURITY: Telemetry data anonymized and opt-in
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandMetrics {
    pub command: String,
    pub execution_count: u64,
    pub total_duration_ms: u64,
    pub average_duration_ms: f64,
    pub min_duration_ms: u64,
    pub max_duration_ms: u64,
    pub last_executed: Option<DateTime<Utc>>,
    pub success_count: u64,
    pub error_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiMetrics {
    pub endpoint: String,
    pub method: String,
    pub call_count: u64,
    pub total_duration_ms: u64,
    pub average_duration_ms: f64,
    pub status_codes: HashMap<u16, u64>,
    pub last_called: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMetrics {
    pub user_id: Option<String>,
    pub session_start: DateTime<Utc>,
    pub commands_executed: u64,
    pub api_calls_made: u64,
    pub total_duration: Duration,
    pub errors_encountered: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub uptime_seconds: u64,
    pub cli_version: String,
    pub rust_version: String,
    pub os_info: String,
}

#[derive(Debug)]
pub struct TelemetryCollector {
    command_metrics: Arc<RwLock<HashMap<String, CommandMetrics>>>,
    api_metrics: Arc<RwLock<HashMap<String, ApiMetrics>>>,
    user_metrics: Arc<RwLock<Option<UserMetrics>>>,
    system_metrics: Arc<RwLock<SystemMetrics>>,
    start_time: Instant,
}

impl TelemetryCollector {
    pub fn new() -> Self {
        let system_metrics = SystemMetrics {
            memory_usage_mb: 0.0,
            cpu_usage_percent: 0.0,
            uptime_seconds: 0,
            cli_version: env!("CARGO_PKG_VERSION").to_string(),
            rust_version: get_rust_version(),
            os_info: get_os_info(),
        };

        Self {
            command_metrics: Arc::new(RwLock::new(HashMap::new())),
            api_metrics: Arc::new(RwLock::new(HashMap::new())),
            user_metrics: Arc::new(RwLock::new(None)),
            system_metrics: Arc::new(RwLock::new(system_metrics)),
            start_time: Instant::now(),
        }
    }

    pub async fn record_command_execution(&self, command: &str, duration: Duration, success: bool) {
        let mut metrics = self.command_metrics.write().await;
        let entry = metrics.entry(command.to_string()).or_insert_with(|| CommandMetrics {
            command: command.to_string(),
            execution_count: 0,
            total_duration_ms: 0,
            average_duration_ms: 0.0,
            min_duration_ms: u64::MAX,
            max_duration_ms: 0,
            last_executed: None,
            success_count: 0,
            error_count: 0,
        });

        entry.execution_count += 1;
        let duration_ms = duration.as_millis() as u64;
        entry.total_duration_ms += duration_ms;
        entry.average_duration_ms = entry.total_duration_ms as f64 / entry.execution_count as f64;
        entry.min_duration_ms = entry.min_duration_ms.min(duration_ms);
        entry.max_duration_ms = entry.max_duration_ms.max(duration_ms);
        entry.last_executed = Some(Utc::now());

        if success {
            entry.success_count += 1;
        } else {
            entry.error_count += 1;
        }

        // Update user metrics
        if let Some(user_metrics) = self.user_metrics.write().await.as_mut() {
            user_metrics.commands_executed += 1;
            user_metrics.total_duration += duration;
            if !success {
                user_metrics.errors_encountered += 1;
            }
        }
    }

    pub async fn record_api_call(&self, endpoint: &str, method: &str, status_code: Option<u16>, duration: Duration) {
        let key = format!("{} {}", method, endpoint);
        let mut metrics = self.api_metrics.write().await;
        let entry = metrics.entry(key.clone()).or_insert_with(|| ApiMetrics {
            endpoint: endpoint.to_string(),
            method: method.to_string(),
            call_count: 0,
            total_duration_ms: 0,
            average_duration_ms: 0.0,
            status_codes: HashMap::new(),
            last_called: None,
        });

        entry.call_count += 1;
        let duration_ms = duration.as_millis() as u64;
        entry.total_duration_ms += duration_ms;
        entry.average_duration_ms = entry.total_duration_ms as f64 / entry.call_count as f64;
        entry.last_called = Some(Utc::now());

        if let Some(code) = status_code {
            *entry.status_codes.entry(code).or_insert(0) += 1;
        }

        // Update user metrics
        if let Some(user_metrics) = self.user_metrics.write().await.as_mut() {
            user_metrics.api_calls_made += 1;
        }
    }

    pub async fn start_user_session(&self, user_id: Option<String>) {
        let mut user_metrics = self.user_metrics.write().await;
        *user_metrics = Some(UserMetrics {
            user_id,
            session_start: Utc::now(),
            commands_executed: 0,
            api_calls_made: 0,
            total_duration: Duration::default(),
            errors_encountered: 0,
        });
    }

    pub async fn end_user_session(&self) {
        let mut user_metrics = self.user_metrics.write().await;
        if let Some(metrics) = user_metrics.as_mut() {
            metrics.total_duration = Utc::now().signed_duration_since(metrics.session_start).to_std()
                .unwrap_or(Duration::default());
        }
        *user_metrics = None;
    }

    pub async fn update_system_metrics(&self) {
        let mut sys_metrics = self.system_metrics.write().await;
        sys_metrics.uptime_seconds = self.start_time.elapsed().as_secs();

        // Update memory and CPU usage (simplified)
        sys_metrics.memory_usage_mb = get_memory_usage_mb();
        sys_metrics.cpu_usage_percent = get_cpu_usage_percent();
    }

    pub async fn get_command_metrics(&self) -> HashMap<String, CommandMetrics> {
        self.command_metrics.read().await.clone()
    }

    pub async fn get_api_metrics(&self) -> HashMap<String, ApiMetrics> {
        self.api_metrics.read().await.clone()
    }

    pub async fn get_user_metrics(&self) -> Option<UserMetrics> {
        self.user_metrics.read().await.clone()
    }

    pub async fn get_system_metrics(&self) -> SystemMetrics {
        self.system_metrics.read().await.clone()
    }

    pub async fn get_summary_report(&self) -> TelemetryReport {
        let command_metrics = self.get_command_metrics().await;
        let api_metrics = self.get_api_metrics().await;
        let user_metrics = self.get_user_metrics().await;
        let system_metrics = self.get_system_metrics().await;

        let total_commands = command_metrics.values().map(|m| m.execution_count).sum();
        let total_api_calls = api_metrics.values().map(|m| m.call_count).sum();
        let total_errors = command_metrics.values().map(|m| m.error_count).sum();

        TelemetryReport {
            session_duration: self.start_time.elapsed(),
            total_commands,
            total_api_calls,
            total_errors,
            command_metrics,
            api_metrics,
            user_metrics,
            system_metrics,
        }
    }

    pub async fn export_metrics(&self, format: ExportFormat) -> Result<String, serde_json::Error> {
        let report = self.get_summary_report().await;

        match format {
            ExportFormat::Json => serde_json::to_string_pretty(&report),
            ExportFormat::JsonCompact => serde_json::to_string(&report),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryReport {
    pub session_duration: Duration,
    pub total_commands: u64,
    pub total_api_calls: u64,
    pub total_errors: u64,
    pub command_metrics: HashMap<String, CommandMetrics>,
    pub api_metrics: HashMap<String, ApiMetrics>,
    pub user_metrics: Option<UserMetrics>,
    pub system_metrics: SystemMetrics,
}

#[derive(Debug, Clone)]
pub enum ExportFormat {
    Json,
    JsonCompact,
}

// Helper functions for system metrics
fn get_rust_version() -> String {
    env!("CARGO_PKG_RUST_VERSION").to_string()
}

fn get_os_info() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

fn get_memory_usage_mb() -> f64 {
    // Simplified memory usage - in a real implementation,
    // you would use system APIs to get actual memory usage
    50.0 // Placeholder
}

fn get_cpu_usage_percent() -> f64 {
    // Simplified CPU usage - in a real implementation,
    // you would use system APIs to get actual CPU usage
    15.0 // Placeholder
}

// Global telemetry instance
lazy_static::lazy_static! {
    pub static ref TELEMETRY: TelemetryCollector = TelemetryCollector::new();
}

// Convenience functions
pub async fn record_command(command: &str, duration: Duration, success: bool) {
    TELEMETRY.record_command_execution(command, duration, success).await;
}

pub async fn record_api_call(endpoint: &str, method: &str, status: Option<u16>, duration: Duration) {
    TELEMETRY.record_api_call(endpoint, method, status, duration).await;
}

pub async fn start_session(user_id: Option<String>) {
    TELEMETRY.start_user_session(user_id).await;
}

pub async fn end_session() {
    TELEMETRY.end_user_session().await;
}

pub async fn update_system_metrics() {
    TELEMETRY.update_system_metrics().await;
}

pub async fn get_report() -> TelemetryReport {
    TELEMETRY.get_summary_report().await
}