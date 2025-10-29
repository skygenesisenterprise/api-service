// ===============================================================
// SKY GENESIS ENTERPRISE :: AETHER SEARCH MODULE - UTILS
// CLASSIFIED LEVEL: INTERNAL USE ONLY
// MISSION: Provide security utilities for search operations
// PROTOCOLS: OAuth2 | FIDO2 | PGP | TLS 1.3 | VPN Tunnel
// AUDIT TRAIL: Vault + OpenTelemetry | Internal Node ID Signed
// ===============================================================

use std::collections::HashMap;
use crate::core::vault::VaultClient;
use crate::core::encryption_manager::EncryptionManager;

/// Security utilities for search operations
pub struct SearchSecurityUtils {
    vault: VaultClient,
    encryption_manager: EncryptionManager,
}

impl SearchSecurityUtils {
    /// Initialize security utilities
    pub fn new(vault: VaultClient, encryption_manager: EncryptionManager) -> Self {
        Self {
            vault,
            encryption_manager,
        }
    }

    /// Validate VPN tunnel access
    pub async fn validate_vpn_access(&self, client_ip: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Check if client IP is in allowed VPN range
        // In a real implementation, this would check Tailscale/WireGuard peer status
        let allowed_ranges = self.vault.get_secret("vpn/allowed_ranges").await
            .unwrap_or_else(|_| "10.0.0.0/8,192.168.0.0/16".to_string());

        // Simple IP range check (simplified)
        Ok(client_ip.starts_with("10.") || client_ip.starts_with("192.168."))
    }

    /// Sign search results with PGP
    pub async fn sign_results(&self, results_json: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Get PGP private key from Vault
        let pgp_key = self.vault.get_secret("pgp/search_private_key").await?;

        // Sign the results (simplified - would use actual PGP library)
        let signature = format!("PGP_SIGNATURE:{}", self.calculate_signature(results_json, &pgp_key));

        Ok(format!("{}\n{}", results_json, signature))
    }

    /// Encrypt sensitive search metadata
    pub async fn encrypt_metadata(&self, metadata: &HashMap<String, serde_json::Value>) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let json = serde_json::to_string(metadata)?;
        self.encryption_manager.encrypt_data(json.as_bytes()).await
    }

    /// Decrypt search metadata
    pub async fn decrypt_metadata(&self, encrypted: &str) -> Result<HashMap<String, serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
        let decrypted = self.encryption_manager.decrypt_data(encrypted).await?;
        let json: HashMap<String, serde_json::Value> = serde_json::from_slice(&decrypted)?;
        Ok(json)
    }

    /// Validate search query against security policies
    pub fn validate_query(&self, query: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check for malicious patterns
        let forbidden_patterns = [
            r"DROP\s+TABLE",
            r"DELETE\s+FROM",
            r"UNION\s+SELECT",
            r"SCRIPT\s+SRC",
            r"JAVASCRIPT:",
        ];

        for pattern in &forbidden_patterns {
            if regex::Regex::new(&format!("(?i){}", pattern))?.is_match(query) {
                return Err("Query contains forbidden patterns".into());
            }
        }

        // Check query length
        if query.len() > 1000 {
            return Err("Query too long".into());
        }

        Ok(())
    }

    /// Rate limiting check
    pub async fn check_rate_limit(&self, user_id: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Simple in-memory rate limiting (would use Redis in production)
        // Allow 100 searches per minute per user
        Ok(true) // Simplified
    }

    /// Audit log search operation
    pub async fn audit_search(&self, user_id: &str, query: &str, results_count: u64, duration_ms: u64) {
        // Log to audit system
        println!("AUDIT: User {} searched '{}' -> {} results in {}ms", user_id, query, results_count, duration_ms);
    }

    /// Calculate simple signature (would use proper crypto in production)
    fn calculate_signature(&self, data: &str, key: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(key);
        format!("{:x}", hasher.finalize())
    }
}

/// Input sanitization utilities
pub struct SearchSanitizer;

impl SearchSanitizer {
    /// Sanitize search query
    pub fn sanitize_query(query: &str) -> String {
        // Remove potentially dangerous characters
        query.chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '-' || *c == '_' || *c == '.')
            .collect::<String>()
            .trim()
            .to_string()
    }

    /// Sanitize filter values
    pub fn sanitize_filters(filters: &mut crate::search::models::SearchFilters) {
        if let Some(ref mut custom) = filters.custom {
            for (key, value) in custom.iter_mut() {
                *key = Self::sanitize_query(key);
                *value = Self::sanitize_query(value);
            }
        }
    }
}

/// Performance monitoring utilities
pub struct SearchPerformanceMonitor;

impl SearchPerformanceMonitor {
    /// Record search performance metrics
    pub async fn record_metrics(query_time_ms: u64, result_count: u64, cache_hit: bool) {
        // Record to metrics system
        println!("PERF: Query took {}ms, returned {} results, cache_hit={}", query_time_ms, result_count, cache_hit);
    }

    /// Check if query should be cached
    pub fn should_cache(query: &str, result_count: usize) -> bool {
        // Cache queries that are not too specific and have reasonable result counts
        query.len() > 3 && result_count > 0 && result_count < 1000
    }
}