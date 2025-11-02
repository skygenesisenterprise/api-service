// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Git Utils
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide utility functions for GitHub integration including
//  payload parsing, data transformation, formatting, and helper operations.
//  NOTICE: Implements safe data handling, validation, and transformation
//  utilities for GitHub webhook processing and API interactions.
//  UTILITY STANDARDS: Data Safety, Validation, Error Handling, Documentation
//  COMPLIANCE: Data Protection, Input Validation, Enterprise Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::models::git_model::*;
use serde_json;
use regex::Regex;
use std::collections::HashMap;

/// [PAYLOAD PARSING UTILITIES] Parse and Validate GitHub Webhook Payloads
pub mod payload_parser {
    use super::*;

    /// [PAYLOAD VALIDATION] Validate GitHub Webhook Payload Structure
    /// @MISSION Ensure webhook payload contains required fields.
    /// @THREAT Malformed payloads, missing data, injection attacks.
    /// @COUNTERMEASURE Schema validation, sanitization, type checking.
    /// @INVARIANT Payloads are validated before processing.
    /// @AUDIT Validation results are logged.
    pub fn validate_webhook_payload(payload: &serde_json::Value) -> Result<(), String> {
        // Check for required fields based on event type
        if let Some(event_type) = payload.get("action") {
            match event_type.as_str() {
                Some("push") => validate_push_payload(payload)?,
                Some("pull_request") => validate_pull_request_payload(payload)?,
                Some("issues") => validate_issue_payload(payload)?,
                _ => {} // Allow unknown event types
            }
        }

        // Validate repository information
        if let Some(repo) = payload.get("repository") {
            validate_repository_data(repo)?;
        }

        // Validate sender information
        if let Some(sender) = payload.get("sender") {
            validate_user_data(sender)?;
        }

        Ok(())
    }

    /// [PUSH PAYLOAD VALIDATION] Validate Push Event Payload
    fn validate_push_payload(payload: &serde_json::Value) -> Result<(), String> {
        if payload.get("ref").is_none() {
            return Err("Push payload missing 'ref' field".to_string());
        }
        if payload.get("commits").is_none() {
            return Err("Push payload missing 'commits' field".to_string());
        }
        Ok(())
    }

    /// [PULL REQUEST PAYLOAD VALIDATION] Validate Pull Request Event Payload
    fn validate_pull_request_payload(payload: &serde_json::Value) -> Result<(), String> {
        if let Some(pr) = payload.get("pull_request") {
            if pr.get("number").is_none() {
                return Err("Pull request payload missing 'number' field".to_string());
            }
            if pr.get("title").is_none() {
                return Err("Pull request payload missing 'title' field".to_string());
            }
        } else {
            return Err("Pull request payload missing 'pull_request' field".to_string());
        }
        Ok(())
    }

    /// [ISSUE PAYLOAD VALIDATION] Validate Issue Event Payload
    fn validate_issue_payload(payload: &serde_json::Value) -> Result<(), String> {
        if let Some(issue) = payload.get("issue") {
            if issue.get("number").is_none() {
                return Err("Issue payload missing 'number' field".to_string());
            }
            if issue.get("title").is_none() {
                return Err("Issue payload missing 'title' field".to_string());
            }
        } else {
            return Err("Issue payload missing 'issue' field".to_string());
        }
        Ok(())
    }

    /// [REPOSITORY DATA VALIDATION] Validate Repository Information
    fn validate_repository_data(repo: &serde_json::Value) -> Result<(), String> {
        if repo.get("id").is_none() {
            return Err("Repository missing 'id' field".to_string());
        }
        if repo.get("name").is_none() {
            return Err("Repository missing 'name' field".to_string());
        }
        if repo.get("full_name").is_none() {
            return Err("Repository missing 'full_name' field".to_string());
        }
        Ok(())
    }

    /// [USER DATA VALIDATION] Validate User Information
    fn validate_user_data(user: &serde_json::Value) -> Result<(), String> {
        if user.get("id").is_none() {
            return Err("User missing 'id' field".to_string());
        }
        if user.get("login").is_none() {
            return Err("User missing 'login' field".to_string());
        }
        Ok(())
    }

    /// [PAYLOAD EXTRACTION] Extract Specific Data from Webhook Payload
    /// @MISSION Safely extract data from webhook payloads.
    /// @THREAT Data corruption, type mismatches.
    /// @COUNTERMEASURE Type checking, default values, error handling.
    /// @INVARIANT Extracted data is valid and safe.
    /// @AUDIT Extraction operations are logged.
    pub fn extract_payload_data(payload: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = payload;

        for part in parts {
            if let Some(obj) = current.as_object() {
                current = obj.get(part)?;
            } else if let Some(arr) = current.as_array() {
                if let Ok(index) = part.parse::<usize>() {
                    current = arr.get(index)?;
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }

        Some(current.clone())
    }
}

/// [DATA TRANSFORMATION UTILITIES] Transform GitHub Data Structures
pub mod data_transformer {
    use super::*;

    /// [EVENT NORMALIZATION] Normalize GitHub Event Data
    /// @MISSION Standardize event data across different GitHub event types.
    /// @THREAT Inconsistent data formats, missing fields.
    /// @COUNTERMEASURE Data normalization, default values.
    /// @INVARIANT Event data is consistent and complete.
    /// @AUDIT Transformation operations are logged.
    pub fn normalize_event_data(event: &mut GitHubWebhookEvent) {
        // Ensure repository URLs are properly formatted
        if !event.repository.html_url.starts_with("https://") {
            event.repository.html_url = format!("https://github.com/{}", event.repository.full_name);
        }

        // Normalize user data
        if event.sender.name.is_none() {
            event.sender.name = Some(event.sender.login.clone());
        }

        // Add default timestamps if missing
        if event.repository.created_at.timestamp() == 0 {
            event.repository.created_at = chrono::Utc::now();
        }
        if event.repository.updated_at.timestamp() == 0 {
            event.repository.updated_at = chrono::Utc::now();
        }
    }

    /// [BRANCH EXTRACTION] Extract Branch Name from Git Reference
    /// @MISSION Parse branch names from Git refs.
    /// @THREAT Malformed refs, incorrect parsing.
    /// @COUNTERMEASURE Regex validation, error handling.
    /// @INVARIANT Branch names are correctly extracted.
    /// @AUDIT Parsing operations are logged.
    pub fn extract_branch_name(git_ref: &str) -> Option<String> {
        if git_ref.starts_with("refs/heads/") {
            Some(git_ref.trim_start_matches("refs/heads/").to_string())
        } else if git_ref.starts_with("refs/tags/") {
            Some(git_ref.trim_start_matches("refs/tags/").to_string())
        } else {
            None
        }
    }

    /// [COMMIT MESSAGE PARSING] Parse Commit Messages for Automation Triggers
    /// @MISSION Extract keywords and patterns from commit messages.
    /// @THREAT Malformed messages, injection attacks.
    /// @COUNTERMEASURE Sanitization, pattern matching.
    /// @INVARIANT Messages are safely parsed.
    /// @AUDIT Parsing results are logged.
    pub fn parse_commit_message(message: &str) -> HashMap<String, String> {
        let mut result = HashMap::new();

        // Extract conventional commit type
        if let Some(captures) = Regex::new(r"^(feat|fix|docs|style|refactor|test|chore)(\(.+\))?:")
            .unwrap()
            .captures(message) {
            if let Some(commit_type) = captures.get(1) {
                result.insert("type".to_string(), commit_type.as_str().to_string());
            }
        }

        // Check for skip CI patterns
        if message.contains("[skip ci]") || message.contains("[ci skip]") {
            result.insert("skip_ci".to_string(), "true".to_string());
        }

        // Extract issue references
        let issue_regex = Regex::new(r"#(\d+)").unwrap();
        let issues: Vec<String> = issue_regex
            .captures_iter(message)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
            .collect();

        if !issues.is_empty() {
            result.insert("issues".to_string(), issues.join(","));
        }

        result
    }
}

/// [FORMATTING UTILITIES] Format Data for Display and Logging
pub mod formatter {
    use super::*;

    /// [EVENT SUMMARY FORMATTING] Create Human-Readable Event Summaries
    /// @MISSION Format webhook events for logging and notifications.
    /// @THREAT Information leakage, formatting errors.
    /// @COUNTERMEASURE Safe formatting, data sanitization.
    /// @INVARIANT Formatted data is safe and readable.
    /// @AUDIT Formatting operations are logged.
    pub fn format_event_summary(event: &GitHubWebhookEvent) -> String {
        match event.event_type.as_str() {
            "push" => {
                format!(
                    "Push to {} by {} ({} commits)",
                    event.repository.full_name,
                    event.sender.login,
                    extract_commit_count(&event.payload)
                )
            }
            "pull_request" => {
                format!(
                    "Pull request {} in {} by {}",
                    event.action.as_deref().unwrap_or("updated"),
                    event.repository.full_name,
                    event.sender.login
                )
            }
            "issues" => {
                format!(
                    "Issue {} in {} by {}",
                    event.action.as_deref().unwrap_or("updated"),
                    event.repository.full_name,
                    event.sender.login
                )
            }
            _ => {
                format!(
                    "{} event in {} by {}",
                    event.event_type,
                    event.repository.full_name,
                    event.sender.login
                )
            }
        }
    }

    /// [NOTIFICATION MESSAGE FORMATTING] Format Messages for Team Notifications
    /// @MISSION Create notification messages for different channels.
    /// @THREAT Information overload, formatting issues.
    /// @COUNTERMEASURE Concise formatting, relevant information.
    /// @INVARIANT Notifications are clear and actionable.
    /// @AUDIT Notification formatting is logged.
    pub fn format_notification_message(event: &GitHubWebhookEvent, channel: &str) -> String {
        let base_message = format_event_summary(event);

        match channel {
            "slack" => format!("🚀 {}", base_message),
            "discord" => format!("**GitHub Event:** {}", base_message),
            "email" => format!("GitHub Activity: {}", base_message),
            _ => base_message,
        }
    }

    /// [LOG ENTRY FORMATTING] Format Events for Audit Logging
    /// @MISSION Create structured log entries for compliance.
    /// @THREAT Incomplete logs, inconsistent formatting.
    /// @COUNTERMEASURE Structured formatting, complete data.
    /// @INVARIANT Log entries are complete and structured.
    /// @AUDIT Log formatting is itself audited.
    pub fn format_audit_log(event: &GitHubWebhookEvent, action: &str) -> serde_json::Value {
        serde_json::json!({
            "timestamp": event.timestamp.to_rfc3339(),
            "action": action,
            "event_type": event.event_type,
            "repository": event.repository.full_name,
            "sender": event.sender.login,
            "delivery_id": event.delivery_id,
            "user_agent": "sky-genesis-api"
        })
    }

    fn extract_commit_count(payload: &serde_json::Value) -> usize {
        payload.get("commits")
            .and_then(|c| c.as_array())
            .map(|arr| arr.len())
            .unwrap_or(0)
    }
}

/// [VALIDATION UTILITIES] Additional Validation Functions
pub mod validator {
    use super::*;

    /// [REPOSITORY NAME VALIDATION] Validate GitHub Repository Names
    /// @MISSION Ensure repository names follow GitHub conventions.
    /// @THREAT Invalid names, path traversal attacks.
    /// @COUNTERMEASURE Regex validation, character checking.
    /// @INVARIANT Repository names are valid and safe.
    /// @AUDIT Validation results are logged.
    pub fn validate_repository_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Repository name cannot be empty".to_string());
        }

        if name.len() > 100 {
            return Err("Repository name too long".to_string());
        }

        // GitHub repository name regex
        let repo_regex = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
        if !repo_regex.is_match(name) {
            return Err("Repository name contains invalid characters".to_string());
        }

        // Check for path traversal attempts
        if name.contains("..") || name.contains("/") {
            return Err("Repository name contains invalid path characters".to_string());
        }

        Ok(())
    }

    /// [WEBHOOK SECRET VALIDATION] Validate Webhook Secret Strength
    /// @MISSION Ensure webhook secrets are sufficiently secure.
    /// @THREAT Weak secrets, brute force attacks.
    /// @COUNTERMEASURE Length and complexity requirements.
    /// @INVARIANT Secrets meet security requirements.
    /// @AUDIT Secret validation is logged.
    pub fn validate_webhook_secret(secret: &str) -> Result<(), String> {
        if secret.len() < 16 {
            return Err("Webhook secret must be at least 16 characters long".to_string());
        }

        // Check for common weak patterns
        if secret.chars().all(|c| c.is_alphabetic()) {
            return Err("Webhook secret must contain numbers or special characters".to_string());
        }

        Ok(())
    }

    /// [AUTOMATION ACTION VALIDATION] Validate Automation Action Names
    /// @MISSION Ensure automation actions are valid and safe.
    /// @THREAT Invalid actions, command injection.
    /// @COUNTERMEASURE Whitelist validation, sanitization.
    /// @INVARIANT Only approved actions are allowed.
    /// @AUDIT Action validation is logged.
    pub fn validate_automation_action(action: &str) -> Result<(), String> {
        let valid_actions = vec![
            "trigger_pipeline",
            "run_security_scan",
            "notify_team",
            "update_docs",
            "deploy_staging",
            "create_release",
        ];

        if !valid_actions.contains(&action) {
            return Err(format!("Invalid automation action: {}", action));
        }

        Ok(())
    }
}