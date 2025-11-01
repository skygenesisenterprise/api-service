// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Rate Limiting Middleware
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide rate limiting functionality for CLI operations.
//  NOTICE: This module implements rate limiting to prevent abuse and
//  ensure fair usage of CLI commands and API calls.
//  SECURITY: Distributed rate limiting with configurable limits
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub burst_limit: u32,
    pub window_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            requests_per_hour: 1000,
            burst_limit: 10,
            window_duration: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone)]
struct RateLimitEntry {
    requests: Vec<Instant>,
    last_reset: Instant,
}

impl RateLimitEntry {
    fn new() -> Self {
        Self {
            requests: Vec::new(),
            last_reset: Instant::now(),
        }
    }

    fn add_request(&mut self, now: Instant) {
        // Clean old requests outside the window
        let window_start = now - Duration::from_secs(60); // 1 minute window
        self.requests.retain(|&time| time > window_start);

        self.requests.push(now);
    }

    fn request_count(&self, window: Duration) -> usize {
        let now = Instant::now();
        let window_start = now - window;
        self.requests.iter().filter(|&&time| time > window_start).count()
    }

    fn is_allowed(&self, config: &RateLimitConfig) -> bool {
        let now = Instant::now();
        let minute_count = self.request_count(Duration::from_secs(60));
        let hour_count = self.request_count(Duration::from_secs(3600));

        minute_count < config.requests_per_minute as usize &&
        hour_count < config.requests_per_hour as usize
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    entries: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    pub async fn check_rate_limit(&self, key: &str) -> Result<(), RateLimitError> {
        let mut entries = self.entries.write().await;
        let entry = entries.entry(key.to_string()).or_insert_with(RateLimitEntry::new);

        if !entry.is_allowed(&self.config) {
            return Err(RateLimitError::RateLimitExceeded {
                key: key.to_string(),
                retry_after: Duration::from_secs(60),
            });
        }

        entry.add_request(Instant::now());
        Ok(())
    }

    pub async fn get_remaining_requests(&self, key: &str) -> (u32, u32) {
        let entries = self.entries.read().await;
        if let Some(entry) = entries.get(key) {
            let minute_count = entry.request_count(Duration::from_secs(60)) as u32;
            let hour_count = entry.request_count(Duration::from_secs(3600)) as u32;

            (
                self.config.requests_per_minute.saturating_sub(minute_count),
                self.config.requests_per_hour.saturating_sub(hour_count),
            )
        } else {
            (self.config.requests_per_minute, self.config.requests_per_hour)
        }
    }

    pub async fn reset_limits(&self, key: &str) {
        let mut entries = self.entries.write().await;
        entries.remove(key);
    }

    pub async fn cleanup_expired_entries(&self) {
        let mut entries = self.entries.write().await;
        let now = Instant::now();
        let expiry_duration = Duration::from_secs(3600); // 1 hour

        entries.retain(|_, entry| {
            now.duration_since(entry.last_reset) < expiry_duration
        });
    }

    pub fn get_config(&self) -> &RateLimitConfig {
        &self.config
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded for key '{key}'. Retry after {retry_after:?}")]
    RateLimitExceeded {
        key: String,
        retry_after: Duration,
    },
}

impl From<RateLimitError> for anyhow::Error {
    fn from(error: RateLimitError) -> Self {
        anyhow::anyhow!("{}", error)
    }
}

// Global rate limiter instance
lazy_static::lazy_static! {
    pub static ref GLOBAL_RATE_LIMITER: RateLimiter = RateLimiter::new(RateLimitConfig::default());
}

// Command-specific rate limiters
pub struct CommandRateLimiter {
    limiter: RateLimiter,
    command_configs: HashMap<String, RateLimitConfig>,
}

impl CommandRateLimiter {
    pub fn new() -> Self {
        let mut command_configs = HashMap::new();

        // Define different rate limits for different types of commands
        command_configs.insert(
            "auth".to_string(),
            RateLimitConfig {
                requests_per_minute: 5,
                requests_per_hour: 20,
                burst_limit: 2,
                window_duration: Duration::from_secs(60),
            },
        );

        command_configs.insert(
            "security".to_string(),
            RateLimitConfig {
                requests_per_minute: 30,
                requests_per_hour: 500,
                burst_limit: 5,
                window_duration: Duration::from_secs(60),
            },
        );

        // Default config for other commands
        let default_config = RateLimitConfig::default();

        Self {
            limiter: RateLimiter::new(default_config),
            command_configs,
        }
    }

    pub async fn check_command_rate_limit(&self, command: &str, user_id: Option<&str>) -> Result<(), RateLimitError> {
        let key = if let Some(user_id) = user_id {
            format!("user:{}:command:{}", user_id, command)
        } else {
            format!("anonymous:command:{}", command)
        };

        // Use command-specific config if available
        let config = self.command_configs.get(command)
            .unwrap_or_else(|| self.limiter.get_config());

        let mut entries = self.limiter.entries.write().await;
        let entry = entries.entry(key.clone()).or_insert_with(RateLimitEntry::new);

        if !entry.is_allowed(config) {
            return Err(RateLimitError::RateLimitExceeded {
                key,
                retry_after: config.window_duration,
            });
        }

        entry.add_request(Instant::now());
        Ok(())
    }

    pub async fn get_command_remaining(&self, command: &str, user_id: Option<&str>) -> (u32, u32) {
        let key = if let Some(user_id) = user_id {
            format!("user:{}:command:{}", user_id, command)
        } else {
            format!("anonymous:command:{}", command)
        };

        let config = self.command_configs.get(command)
            .unwrap_or_else(|| self.limiter.get_config());

        let entries = self.limiter.entries.read().await;
        if let Some(entry) = entries.get(&key) {
            let minute_count = entry.request_count(Duration::from_secs(60)) as u32;
            let hour_count = entry.request_count(Duration::from_secs(3600)) as u32;

            (
                config.requests_per_minute.saturating_sub(minute_count),
                config.requests_per_hour.saturating_sub(hour_count),
            )
        } else {
            (config.requests_per_minute, config.requests_per_hour)
        }
    }
}

// Global command rate limiter
lazy_static::lazy_static! {
    pub static ref COMMAND_RATE_LIMITER: CommandRateLimiter = CommandRateLimiter::new();
}

// Convenience functions
pub async fn check_global_rate_limit(key: &str) -> Result<(), RateLimitError> {
    GLOBAL_RATE_LIMITER.check_rate_limit(key).await
}

pub async fn check_command_rate_limit(command: &str, user_id: Option<&str>) -> Result<(), RateLimitError> {
    COMMAND_RATE_LIMITER.check_command_rate_limit(command, user_id).await
}

pub async fn get_remaining_requests(key: &str) -> (u32, u32) {
    GLOBAL_RATE_LIMITER.get_remaining_requests(key).await
}

pub async fn get_command_remaining(command: &str, user_id: Option<&str>) -> (u32, u32) {
    COMMAND_RATE_LIMITER.get_command_remaining(command, user_id).await
}