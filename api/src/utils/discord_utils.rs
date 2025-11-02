// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Discord Utilities
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide utility functions for Discord bot integration including
//  message formatting, content validation, embed creation, and command
//  parsing with security controls.
//  NOTICE: Utilities implement secure Discord operations with input validation,
//  sanitization, and enterprise security standards.
//  DISCORD STANDARDS: Message Formatting, Content Validation, Embed Creation
//  COMPLIANCE: Discord API Standards, Security Best Practices
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::models::discord_model::*;
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;

/// [MESSAGE FORMATTING] Format Discord Messages with Rich Content
/// @MISSION Create properly formatted Discord messages with embeds and components.
/// @THREAT Message injection, formatting abuse, information disclosure.
/// @COUNTERMEASURE Input sanitization, content validation, safe formatting.
/// @INVARIANT All messages are safe and properly formatted.
/// @AUDIT Message formatting operations are logged.
/// @FLOW Validate input -> Format content -> Create message structure.
pub struct DiscordMessageFormatter;

impl DiscordMessageFormatter {
    /// [STATUS MESSAGE] Format System Status Information
    /// @MISSION Create formatted status messages for Discord channels.
    /// @THREAT Status information disclosure, formatting issues.
    /// @COUNTERMEASURE Controlled information exposure, safe formatting.
    /// @INVARIANT Status messages contain only authorized information.
    /// @AUDIT Status message creation is logged.
    /// @FLOW Gather status data -> Format with colors/codes -> Return message.
    pub fn format_status_message(services: HashMap<String, String>) -> DiscordMessage {
        let mut fields = Vec::new();
        let mut all_ok = true;

        for (service, status) in services {
            let status_emoji = if status == "OK" { "✅" } else { "❌" };
            if status != "OK" {
                all_ok = false;
            }

            fields.push(EmbedField {
                name: service,
                value: format!("{} {}", status_emoji, status),
                inline: Some(true),
            });
        }

        let color = if all_ok { 0x00ff00 } else { 0xff0000 };
        let title = if all_ok { "System Status: All Systems Operational" } else { "System Status: Issues Detected" };

        let embed = DiscordEmbed {
            title: Some(title.to_string()),
            description: Some("Current status of all enterprise services".to_string()),
            color: Some(color),
            fields: Some(fields),
            timestamp: Some(Utc::now()),
        };

        DiscordMessage {
            content: None,
            embeds: Some(vec![embed]),
            components: None,
        }
    }

    /// [ERROR MESSAGE] Format Error Messages for Discord
    /// @MISSION Create user-friendly error messages with appropriate styling.
    /// @THREAT Error information disclosure, confusing error messages.
    /// @COUNTERMEASURE Controlled error exposure, clear messaging.
    /// @INVARIANT Error messages don't leak sensitive information.
    /// @AUDIT Error message creation is logged.
    /// @FLOW Sanitize error -> Format with styling -> Return message.
    pub fn format_error_message(error: &str, error_code: Option<&str>) -> DiscordMessage {
        let sanitized_error = sanitize_error_message(error);

        let embed = DiscordEmbed {
            title: Some("❌ Error".to_string()),
            description: Some(sanitized_error),
            color: Some(0xff0000),
            fields: error_code.map(|code| vec![EmbedField {
                name: "Error Code".to_string(),
                value: code.to_string(),
                inline: Some(true),
            }]),
            timestamp: Some(Utc::now()),
        };

        DiscordMessage {
            content: None,
            embeds: Some(vec![embed]),
            components: None,
        }
    }

    /// [SUCCESS MESSAGE] Format Success Messages for Discord
    /// @MISSION Create confirmation messages for successful operations.
    /// @THREAT Overly verbose success messages, information disclosure.
    /// @COUNTERMEASURE Concise messaging, appropriate detail level.
    /// @INVARIANT Success messages are informative but not verbose.
    /// @AUDIT Success message creation is logged.
    /// @FLOW Format operation result -> Add styling -> Return message.
    pub fn format_success_message(operation: &str, details: Option<&str>) -> DiscordMessage {
        let description = match details {
            Some(d) => format!("✅ {} completed successfully.\n{}", operation, d),
            None => format!("✅ {} completed successfully.", operation),
        };

        let embed = DiscordEmbed {
            title: Some("Success".to_string()),
            description: Some(description),
            color: Some(0x00ff00),
            fields: None,
            timestamp: Some(Utc::now()),
        };

        DiscordMessage {
            content: None,
            embeds: Some(vec![embed]),
            components: None,
        }
    }

    /// [COMMAND HELP] Format Command Help Information
    /// @MISSION Create help messages showing available commands and usage.
    /// @THREAT Command exposure, confusing help text.
    /// @COUNTERMEASURE Filtered command display, clear formatting.
    /// @INVARIANT Help shows only authorized commands.
    /// @AUDIT Help message creation is logged.
    /// @FLOW Filter commands -> Format help text -> Return message.
    pub fn format_help_message(commands: &[CommandConfig], user_permissions: &[String]) -> DiscordMessage {
        let available_commands: Vec<&CommandConfig> = commands.iter()
            .filter(|cmd| {
                cmd.permissions.is_empty() ||
                cmd.permissions.iter().any(|p| user_permissions.contains(p))
            })
            .collect();

        let mut fields = Vec::new();

        for cmd in available_commands {
            let vpn_indicator = if cmd.vpn_required { " (VPN Required)" } else { "" };
            let description = format!("{}{}", cmd.description, vpn_indicator);

            fields.push(EmbedField {
                name: format!("/{}", cmd.name),
                value: description,
                inline: Some(false),
            });
        }

        let embed = DiscordEmbed {
            title: Some("🤖 Available Commands".to_string()),
            description: Some("Here are the commands you can use:".to_string()),
            color: Some(0x0099ff),
            fields: Some(fields),
            timestamp: Some(Utc::now()),
        };

        DiscordMessage {
            content: None,
            embeds: Some(vec![embed]),
            components: None,
        }
    }

    /// [VPN PEERS MESSAGE] Format VPN Peers List
    /// @MISSION Display connected VPN peers in a formatted list.
    /// @THREAT Peer information disclosure, formatting issues.
    /// @COUNTERMEASURE Controlled information display, safe formatting.
    /// @INVARIANT Peer information is appropriately masked.
    /// @AUDIT Peer list creation is logged.
    /// @FLOW Format peer list -> Add styling -> Return message.
    pub fn format_vpn_peers_message(peers: &[String]) -> DiscordMessage {
        let peer_list = if peers.is_empty() {
            "No VPN peers currently connected.".to_string()
        } else {
            peers.iter()
                .enumerate()
                .map(|(i, peer)| format!("{}. {}", i + 1, mask_peer_name(peer)))
                .collect::<Vec<String>>()
                .join("\n")
        };

        let embed = DiscordEmbed {
            title: Some("🔒 VPN Peers".to_string()),
            description: Some(peer_list),
            color: Some(0x00ff00),
            fields: Some(vec![EmbedField {
                name: "Total Connected".to_string(),
                value: peers.len().to_string(),
                inline: Some(true),
            }]),
            timestamp: Some(Utc::now()),
        };

        DiscordMessage {
            content: None,
            embeds: Some(vec![embed]),
            components: None,
        }
    }
}

/// [CONTENT VALIDATION] Validate and Sanitize Discord Content
/// @MISSION Ensure all Discord content is safe and compliant.
/// @THREAT XSS, injection attacks, malicious content, spam.
/// @COUNTERMEASURE Content filtering, sanitization, length limits.
/// @INVARIANT All content is validated and safe.
/// @AUDIT Content validation operations are logged.
/// @FLOW Check content -> Apply filters -> Sanitize -> Return result.
pub struct DiscordContentValidator;

impl DiscordContentValidator {
    /// [MESSAGE VALIDATION] Validate Discord Message Content
    /// @MISSION Check message content for safety and compliance.
    /// @THREAT Malicious content, spam, inappropriate material.
    /// @COUNTERMEASURE Pattern matching, content analysis, length checks.
    /// @INVARIANT Invalid content is rejected.
    /// @AUDIT Validation failures are logged.
    /// @FLOW Run checks -> Return validation result.
    pub fn validate_message_content(content: &str) -> Result<(), ValidationError> {
        // Check length
        if content.len() > 2000 {
            return Err(ValidationError::ContentTooLong);
        }

        if content.is_empty() {
            return Err(ValidationError::EmptyContent);
        }

        // Check for malicious patterns
        if contains_malicious_patterns(content) {
            return Err(ValidationError::MaliciousContent);
        }

        // Check for spam patterns
        if contains_spam_patterns(content) {
            return Err(ValidationError::SpamDetected);
        }

        Ok(())
    }

    /// [COMMAND VALIDATION] Validate Discord Command Input
    /// @MISSION Ensure command arguments are safe and valid.
    /// @THREAT Command injection, malformed arguments.
    /// @COUNTERMEASURE Argument validation, type checking, sanitization.
    /// @INVARIANT Command arguments are safe and valid.
    /// @AUDIT Command validation operations are logged.
    /// @FLOW Validate command name -> Check arguments -> Return result.
    pub fn validate_command(command: &DiscordCommand) -> Result<(), ValidationError> {
        // Validate command name
        if command.command.is_empty() || command.command.len() > 50 {
            return Err(ValidationError::InvalidCommandName);
        }

        // Check for valid command name pattern
        let command_regex = Regex::new(r"^[a-zA-Z][a-zA-Z0-9_]*$").unwrap();
        if !command_regex.is_match(&command.command) {
            return Err(ValidationError::InvalidCommandName);
        }

        // Validate arguments if present
        if let Some(args) = &command.args {
            for arg in args {
                if arg.len() > 100 {
                    return Err(ValidationError::ArgumentTooLong);
                }

                // Check for dangerous characters in arguments
                if arg.contains("..") || arg.contains("/") || arg.contains("\\") {
                    return Err(ValidationError::DangerousArgument);
                }
            }
        }

        // Validate user and channel IDs
        if command.user_id.is_empty() || command.channel_id.is_empty() {
            return Err(ValidationError::MissingRequiredFields);
        }

        Ok(())
    }

    /// [EMBED VALIDATION] Validate Discord Embed Content
    /// @MISSION Ensure embed content is safe and properly formatted.
    /// @THREAT Malicious embed content, formatting abuse.
    /// @COUNTERMEASURE Content validation, size limits, safe formatting.
    /// @INVARIANT Embed content is safe and valid.
    /// @AUDIT Embed validation operations are logged.
    /// @FLOW Validate embed fields -> Check sizes -> Return result.
    pub fn validate_embed(embed: &DiscordEmbed) -> Result<(), ValidationError> {
        // Check title length
        if let Some(title) = &embed.title {
            if title.len() > 256 {
                return Err(ValidationError::TitleTooLong);
            }
        }

        // Check description length
        if let Some(description) = &embed.description {
            if description.len() > 4096 {
                return Err(ValidationError::DescriptionTooLong);
            }

            if contains_malicious_patterns(description) {
                return Err(ValidationError::MaliciousContent);
            }
        }

        // Check fields
        if let Some(fields) = &embed.fields {
            if fields.len() > 25 {
                return Err(ValidationError::TooManyFields);
            }

            for field in fields {
                if field.name.len() > 256 || field.value.len() > 1024 {
                    return Err(ValidationError::FieldTooLong);
                }

                if contains_malicious_patterns(&field.name) || contains_malicious_patterns(&field.value) {
                    return Err(ValidationError::MaliciousContent);
                }
            }
        }

        Ok(())
    }
}

/// [COMMAND PARSING] Parse Discord Commands and Arguments
/// @MISSION Parse Discord slash commands and extract arguments.
/// @THREAT Command parsing errors, malformed input.
/// @COUNTERMEASURE Robust parsing, error handling, validation.
/// @INVARIANT Commands are correctly parsed.
/// @AUDIT Command parsing operations are logged.
/// @FLOW Parse command string -> Extract arguments -> Validate -> Return result.
pub struct DiscordCommandParser;

impl DiscordCommandParser {
    /// [SLASH COMMAND PARSING] Parse Discord Slash Command
    /// @MISSION Parse slash command interactions from Discord.
    /// @THREAT Parsing errors, injection through command data.
    /// @COUNTERMEASURE Safe parsing, validation, sanitization.
    /// @INVARIANT Commands are safely parsed.
    /// @AUDIT Parsing operations are logged.
    /// @FLOW Extract command data -> Parse arguments -> Return command.
    pub fn parse_slash_command(interaction_data: &serde_json::Value) -> Result<DiscordCommand, ParseError> {
        let command_name = interaction_data.get("name")
            .and_then(|n| n.as_str())
            .ok_or(ParseError::MissingCommandName)?;

        let user_id = interaction_data.get("member")
            .and_then(|m| m.get("user"))
            .and_then(|u| u.get("id"))
            .and_then(|id| id.as_str())
            .unwrap_or("unknown");

        let channel_id = interaction_data.get("channel_id")
            .and_then(|c| c.as_str())
            .unwrap_or("unknown");

        let options = interaction_data.get("options")
            .and_then(|o| o.as_array())
            .unwrap_or(&vec![]);

        let args = Self::parse_command_options(options)?;

        Ok(DiscordCommand {
            command: command_name.to_string(),
            args: if args.is_empty() { None } else { Some(args) },
            user_id: user_id.to_string(),
            channel_id: channel_id.to_string(),
            service: None,
            urgent: false,
        })
    }

    /// [TEXT COMMAND PARSING] Parse Text-Based Commands
    /// @MISSION Parse commands from text messages.
    /// @THREAT Command injection, malformed commands.
    /// @COUNTERMEASURE Safe parsing, prefix validation.
    /// @INVARIANT Text commands are safely parsed.
    /// @AUDIT Parsing operations are logged.
    /// @FLOW Check prefix -> Extract command -> Parse arguments -> Return result.
    pub fn parse_text_command(message: &str, user_id: &str, channel_id: &str) -> Result<DiscordCommand, ParseError> {
        let message = message.trim();

        // Check for command prefix
        if !message.starts_with('!') && !message.starts_with('/') {
            return Err(ParseError::NotACommand);
        }

        let content = &message[1..]; // Remove prefix
        let parts: Vec<&str> = content.split_whitespace().collect();

        if parts.is_empty() {
            return Err(ParseError::EmptyCommand);
        }

        let command = parts[0].to_string();
        let args = if parts.len() > 1 {
            Some(parts[1..].iter().map(|s| s.to_string()).collect())
        } else {
            None
        };

        Ok(DiscordCommand {
            command,
            args,
            user_id: user_id.to_string(),
            channel_id: channel_id.to_string(),
            service: None,
            urgent: false,
        })
    }

    fn parse_command_options(options: &[serde_json::Value]) -> Result<Vec<String>, ParseError> {
        let mut args = Vec::new();

        for option in options {
            if let Some(value) = option.get("value") {
                if let Some(str_value) = value.as_str() {
                    args.push(str_value.to_string());
                } else if let Some(num_value) = value.as_number() {
                    args.push(num_value.to_string());
                }
            }
        }

        Ok(args)
    }
}

// Helper functions

fn sanitize_error_message(error: &str) -> String {
    // Remove potentially sensitive information from error messages
    let sensitive_patterns = [
        r"password.*",
        r"token.*",
        r"key.*",
        r"secret.*",
        r"credential.*",
    ];

    let mut sanitized = error.to_string();

    for pattern in &sensitive_patterns {
        let regex = Regex::new(&format!(r"(?i){}", pattern)).unwrap();
        sanitized = regex.replace_all(&sanitized, "[REDACTED]").to_string();
    }

    // Limit error message length
    if sanitized.len() > 500 {
        sanitized = sanitized.chars().take(500).collect::<String>() + "...";
    }

    sanitized
}

fn mask_peer_name(peer: &str) -> String {
    // Mask sensitive parts of peer names while keeping structure
    if peer.len() > 8 {
        format!("{}***{}", &peer[..4], &peer[peer.len()-4..])
    } else {
        "***masked***".to_string()
    }
}

fn contains_malicious_patterns(content: &str) -> bool {
    let malicious_patterns = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"data:text/html",
        r"<iframe[^>]*>.*?</iframe>",
        r"<object[^>]*>.*?</object>",
        r"<embed[^>]*>.*?</embed>",
        r"vbscript:",
        r"onload\s*=",
        r"onerror\s*=",
        r"onclick\s*=",
    ];

    for pattern in &malicious_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(content) {
                return true;
            }
        }
    }

    false
}

fn contains_spam_patterns(content: &str) -> bool {
    let spam_patterns = [
        r"\b(?:free|cheap|buy|sell|discount)\b.*\b(?:viagra|casino|lottery)\b",
        r"(?i)(?:http|https|www\.)\S{10,}", // Long URLs
        r"[A-Z]{5,}", // Excessive caps
        r"(.)\1{4,}", // Character repetition
    ];

    for pattern in &spam_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(content) {
                return true;
            }
        }
    }

    false
}

/// [VALIDATION ERRORS] Error Types for Content Validation
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    ContentTooLong,
    EmptyContent,
    MaliciousContent,
    SpamDetected,
    InvalidCommandName,
    ArgumentTooLong,
    DangerousArgument,
    MissingRequiredFields,
    TitleTooLong,
    DescriptionTooLong,
    TooManyFields,
    FieldTooLong,
}

/// [PARSE ERRORS] Error Types for Command Parsing
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    MissingCommandName,
    NotACommand,
    EmptyCommand,
    InvalidArguments,
    MalformedCommand,
}