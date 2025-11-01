// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Format Utilities
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide formatting utilities for CLI output.
//  NOTICE: This module contains functions for formatting data display.
//  SECURITY: Safe data formatting for user display
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use chrono::{DateTime, Utc};
use serde_json::Value;

/// Formatting utilities for CLI output
pub struct FormatUtils;

impl FormatUtils {
    /// Format timestamp to human readable string
    pub fn format_timestamp(timestamp: &str) -> String {
        if let Ok(dt) = DateTime::parse_from_rfc3339(timestamp) {
            dt.with_timezone(&Utc).format("%Y-%m-%d %H:%M:%S UTC").to_string()
        } else {
            timestamp.to_string()
        }
    }

    /// Format file size in human readable format
    pub fn format_file_size(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];

        if bytes == 0 {
            return "0 B".to_string();
        }

        let base = 1024_f64;
        let log = (bytes as f64).log(base);
        let unit_index = log.floor() as usize;

        if unit_index >= UNITS.len() {
            return format!("{} {}", bytes, UNITS[0]);
        }

        let size = bytes as f64 / base.powi(unit_index as i32);
        format!("{:.2} {}", size, UNITS[unit_index])
    }

    /// Format duration in human readable format
    pub fn format_duration(seconds: u64) -> String {
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        let minutes = (seconds % 3600) / 60;
        let secs = seconds % 60;

        let mut parts = Vec::new();

        if days > 0 {
            parts.push(format!("{}d", days));
        }
        if hours > 0 {
            parts.push(format!("{}h", hours));
        }
        if minutes > 0 {
            parts.push(format!("{}m", minutes));
        }
        if secs > 0 || parts.is_empty() {
            parts.push(format!("{}s", secs));
        }

        parts.join(" ")
    }

    /// Format JSON value for display
    pub fn format_json(value: &Value) -> String {
        serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
    }

    /// Format percentage
    pub fn format_percentage(value: f64) -> String {
        format!("{:.1}%", value * 100.0)
    }

    /// Format network speed
    pub fn format_speed(bps: f64) -> String {
        const UNITS: &[&str] = &["bps", "Kbps", "Mbps", "Gbps", "Tbps"];

        if bps == 0.0 {
            return "0 bps".to_string();
        }

        let base = 1000_f64;
        let log = bps.log10() / base.log10();
        let unit_index = log.floor() as usize;

        if unit_index >= UNITS.len() {
            return format!("{:.2} {}", bps, UNITS[0]);
        }

        let speed = bps / base.powi(unit_index as i32);
        format!("{:.2} {}", speed, UNITS[unit_index])
    }

    /// Format table data
    pub fn format_table(headers: &[&str], rows: &[Vec<String>]) -> String {
        if headers.is_empty() || rows.is_empty() {
            return String::new();
        }

        let mut col_widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();

        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                if i < col_widths.len() {
                    col_widths[i] = col_widths[i].max(cell.len());
                }
            }
        }

        let mut result = String::new();

        // Header
        for (i, header) in headers.iter().enumerate() {
            if i > 0 {
                result.push_str(" | ");
            }
            result.push_str(&format!("{:<width$}", header, width = col_widths[i]));
        }
        result.push('\n');

        // Separator
        for (i, &width) in col_widths.iter().enumerate() {
            if i > 0 {
                result.push_str("-+-");
            }
            result.push_str(&"-".repeat(width));
        }
        result.push('\n');

        // Rows
        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                if i > 0 {
                    result.push_str(" | ");
                }
                result.push_str(&format!("{:<width$}", cell, width = col_widths[i]));
            }
            result.push('\n');
        }

        result
    }

    /// Truncate string with ellipsis
    pub fn truncate(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len.saturating_sub(3)])
        }
    }
}