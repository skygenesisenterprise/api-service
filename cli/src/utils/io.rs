// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: IO Utilities
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide I/O utilities for CLI operations.
//  NOTICE: This module contains file and input/output helper functions.
//  SECURITY: Safe file operations and input validation
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use anyhow::{Result, anyhow};
use std::fs;
use std::path::Path;

/// I/O utilities for CLI operations
#[allow(dead_code)]
pub struct IoUtils;

#[allow(dead_code)]
impl IoUtils {
    /// Read file content safely
    pub fn read_file(path: &str) -> Result<String> {
        fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read file '{}': {}", path, e))
    }

    /// Write content to file safely
    pub fn write_file(path: &str, content: &str) -> Result<()> {
        fs::write(path, content)
            .map_err(|e| anyhow!("Failed to write file '{}': {}", path, e))
    }

    /// Check if file exists
    pub fn file_exists(path: &str) -> bool {
        Path::new(path).exists()
    }

    /// Create directory if it doesn't exist
    pub fn create_dir(path: &str) -> Result<()> {
        fs::create_dir_all(path)
            .map_err(|e| anyhow!("Failed to create directory '{}': {}", path, e))
    }

    /// Read JSON file and parse it
    pub fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
        let content = Self::read_file(path)?;
        serde_json::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse JSON from '{}': {}", path, e))
    }

    /// Write data as JSON to file
    pub fn write_json<T: serde::Serialize>(path: &str, data: &T) -> Result<()> {
        let content = serde_json::to_string_pretty(data)
            .map_err(|e| anyhow!("Failed to serialize data: {}", e))?;
        Self::write_file(path, &content)
    }

    /// Read environment variable with default
    pub fn read_env_var(key: &str, default: &str) -> String {
        std::env::var(key).unwrap_or_else(|_| default.to_string())
    }

    /// Read environment variable or error
    pub fn read_env_var_required(key: &str) -> Result<String> {
        std::env::var(key)
            .map_err(|_| anyhow!("Environment variable '{}' is required but not set", key))
    }

    /// Get current working directory
    pub fn current_dir() -> Result<String> {
        std::env::current_dir()
            .map_err(|e| anyhow!("Failed to get current directory: {}", e))?
            .to_string_lossy()
            .to_string()
            .pipe(Ok)
    }

    /// Expand tilde in path
    pub fn expand_tilde(path: &str) -> String {
        if path.starts_with('~') {
            if let Some(home) = std::env::var_os("HOME") {
                return path.replacen('~', &home.to_string_lossy(), 1);
            }
        }
        path.to_string()
    }

    /// Validate file path (basic security check)
    pub fn validate_path(path: &str) -> Result<()> {
        let path = Path::new(path);

        // Check for directory traversal attempts
        if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err(anyhow!("Path contains '..' which is not allowed"));
        }

        // Check for absolute paths if not allowed
        if path.is_absolute() {
            return Err(anyhow!("Absolute paths are not allowed"));
        }

        Ok(())
    }

    /// Get file metadata
    pub fn file_metadata(path: &str) -> Result<fs::Metadata> {
        fs::metadata(path)
            .map_err(|e| anyhow!("Failed to get metadata for '{}': {}", path, e))
    }
}

// Extension trait for Result
#[allow(dead_code)]
trait Pipe<T> {
    fn pipe<F, U>(self, f: F) -> U
    where
        F: FnOnce(T) -> U;
}

#[allow(dead_code)]
impl<T> Pipe<T> for T {
    fn pipe<F, U>(self, f: F) -> U
    where
        F: FnOnce(T) -> U,
    {
        f(self)
    }
}