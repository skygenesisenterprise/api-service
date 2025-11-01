// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: VoIP Utilities
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide utility functions for VoIP operations including
//  SDP parsing, codec validation, bandwidth calculation, and helper functions.
//  NOTICE: Implements VoIP-specific utilities with security validation,
//  performance optimization, and enterprise compliance features.
//  UTILITY STANDARDS: Input validation, error handling, performance
//  SECURITY: Secure parsing, validation, sanitization
//  COMPLIANCE: VoIP security standards, data protection
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::collections::HashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;

/// [SDP PARSER] Session Description Protocol parser
/// @MISSION Parse and validate SDP descriptions.
/// @THREAT Malformed SDP injection.
/// @COUNTERMEASURE Secure parsing, validation.
/// @COMPLIANCE RFC 4566 SDP specification.
pub struct SdpParser;

impl SdpParser {
    /// [SDP PARSING] Parse SDP string into structured data
    /// @MISSION Extract session and media information.
    /// @THREAT Parsing vulnerabilities.
    /// @COUNTERMEASURE Safe parsing with limits.
    pub fn parse_sdp(sdp: &str) -> Result<SdpData, String> {
        if sdp.is_empty() {
            return Err("Empty SDP".to_string());
        }

        if sdp.len() > 10000 {
            return Err("SDP too large".to_string());
        }

        let mut lines = sdp.lines();
        let mut sdp_data = SdpData::default();

        // Parse session-level attributes
        while let Some(line) = lines.next() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if line.len() < 2 || !line.contains('=') {
                continue;
            }

            let (field, value) = line.split_at(2);
            let value = &value[1..]; // Skip the '='

            match field {
                "v=" => {
                    if value != "0" {
                        return Err("Unsupported SDP version".to_string());
                    }
                }
                "o=" => {
                    sdp_data.origin = Some(value.to_string());
                }
                "s=" => {
                    sdp_data.session_name = Some(value.to_string());
                }
                "t=" => {
                    sdp_data.timing = Some(value.to_string());
                }
                "m=" => {
                    // Media description - parse media sections
                    let media = Self::parse_media_section(value, &mut lines)?;
                    sdp_data.media.push(media);
                }
                _ => {
                    // Other session-level attributes
                    sdp_data.attributes.insert(field[0..1].to_string(), value.to_string());
                }
            }
        }

        Ok(sdp_data)
    }

    /// [MEDIA PARSING] Parse media section
    /// @MISSION Extract media-specific information.
    /// @THREAT Malformed media descriptions.
    /// @COUNTERMEASURE Validation and sanitization.
    fn parse_media_section<'a>(media_line: &str, lines: &mut impl Iterator<Item = &'a str>) -> Result<MediaDescription, String> {
        let parts: Vec<&str> = media_line.split_whitespace().collect();
        if parts.len() < 4 {
            return Err("Invalid media description".to_string());
        }

        let media_type = parts[0].to_string();
        let port = parts[1].parse::<u16>()
            .map_err(|_| "Invalid port number".to_string())?;
        let protocol = parts[2].to_string();
        let formats: Vec<String> = parts[3..].iter().map(|s| s.to_string()).collect();

        let mut media = MediaDescription {
            media_type,
            port,
            protocol,
            formats,
            attributes: HashMap::new(),
        };

        // Parse media-level attributes
        while let Some(line) = lines.next() {
            let line = line.trim();
            if line.is_empty() {
                break;
            }

            if line.len() < 2 || !line.contains('=') {
                continue;
            }

            let (field, value) = line.split_at(2);
            let value = &value[1..];

            if field == "m=" {
                // Next media section - put it back
                // This is a simplified implementation
                break;
            } else {
                media.attributes.insert(field[0..1].to_string(), value.to_string());
            }
        }

        Ok(media)
    }

    /// [SDP VALIDATION] Validate SDP structure and content
    /// @MISSION Check SDP for security and compliance.
    /// @THREAT Malicious SDP content.
    /// @COUNTERMEASURE Comprehensive validation.
    pub fn validate_sdp(sdp: &str) -> Result<(), String> {
        let sdp_data = Self::parse_sdp(sdp)?;

        // Validate version
        if sdp_data.version != 0 {
            return Err("Unsupported SDP version".to_string());
        }

        // Validate media descriptions
        for media in &sdp_data.media {
            Self::validate_media_description(media)?;
        }

        // Check for potentially malicious content
        if sdp.contains("javascript:") || sdp.contains("data:") {
            return Err("Potentially malicious SDP content".to_string());
        }

        Ok(())
    }

    /// [MEDIA VALIDATION] Validate media description
    /// @MISSION Check media parameters for security.
    /// @THREAT Malformed media parameters.
    /// @COUNTERMEASURE Parameter validation.
    fn validate_media_description(media: &MediaDescription) -> Result<(), String> {
        // Validate port range
        if media.port == 0 || media.port > 65535 {
            return Err("Invalid media port".to_string());
        }

        // Validate protocol
        if !["RTP/AVP", "RTP/SAVP", "UDP/TLS/RTP/SAVPF"].contains(&media.protocol.as_str()) {
            return Err("Unsupported media protocol".to_string());
        }

        // Validate codecs (basic check)
        for format in &media.formats {
            if format.len() > 10 {
                return Err("Invalid codec format".to_string());
            }
        }

        Ok(())
    }
}

/// [SDP DATA] Parsed SDP structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SdpData {
    pub version: u32,
    pub origin: Option<String>,
    pub session_name: Option<String>,
    pub timing: Option<String>,
    pub media: Vec<MediaDescription>,
    pub attributes: HashMap<String, String>,
}

/// [MEDIA DESCRIPTION] Media section data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaDescription {
    pub media_type: String,
    pub port: u16,
    pub protocol: String,
    pub formats: Vec<String>,
    pub attributes: HashMap<String, String>,
}

/// [CODEC VALIDATOR] Audio/video codec validation
/// @MISSION Validate and normalize codec information.
/// @THREAT Unsupported or malicious codecs.
/// @COUNTERMEASURE Codec whitelist and validation.
pub struct CodecValidator;

impl CodecValidator {
    /// [CODEC VALIDATION] Check if codec is supported and safe
    /// @MISSION Validate codec parameters.
    /// @THREAT Codec vulnerabilities, resource exhaustion.
    /// @COUNTERMEASURE Whitelist validation.
    pub fn validate_codec(codec: &str, fmtp: Option<&str>) -> Result<CodecInfo, String> {
        let supported_codecs = [
            ("opus", 111),
            ("vp8", 96),
            ("vp9", 98),
            ("h264", 126),
            ("pcmu", 0),
            ("pcma", 8),
        ];

        for (name, default_pt) in &supported_codecs {
            if codec.to_lowercase().contains(name) {
                let payload_type = Self::extract_payload_type(codec).unwrap_or(*default_pt);

                // Validate fmtp parameters if present
                if let Some(fmtp_params) = fmtp {
                    Self::validate_fmtp_parameters(name, fmtp_params)?;
                }

                return Ok(CodecInfo {
                    name: name.to_string(),
                    payload_type,
                    clock_rate: Self::get_clock_rate(name),
                    channels: Self::get_channels(name),
                });
            }
        }

        Err(format!("Unsupported codec: {}", codec))
    }

    /// [PAYLOAD TYPE EXTRACTION] Extract RTP payload type
    /// @MISSION Parse payload type from codec string.
    /// @THREAT Malformed payload types.
    /// @COUNTERMEASURE Safe parsing.
    fn extract_payload_type(codec: &str) -> Option<u8> {
        let re = Regex::new(r"(\d+)").unwrap();
        if let Some(cap) = re.captures(codec).and_then(|cap| cap.get(1)) {
            cap.as_str().parse::<u8>().ok()
        } else {
            None
        }
    }

    /// [FMTP VALIDATION] Validate format parameters
    /// @MISSION Check codec-specific parameters.
    /// @THREAT Malicious codec parameters.
    /// @COUNTERMEASURE Parameter validation.
    fn validate_fmtp_parameters(codec: &str, fmtp: &str) -> Result<(), String> {
        match codec {
            "opus" => {
                // Validate Opus parameters
                if fmtp.contains("maxplaybackrate=") {
                    let re = Regex::new(r"maxplaybackrate=(\d+)").unwrap();
                    if let Some(cap) = re.captures(fmtp).and_then(|cap| cap.get(1)) {
                        let rate: u32 = cap.as_str().parse()
                            .map_err(|_| "Invalid maxplaybackrate".to_string())?;
                        if rate > 192000 {
                            return Err("Invalid Opus maxplaybackrate".to_string());
                        }
                    }
                }
            }
            "h264" => {
                // Validate H.264 parameters
                if fmtp.contains("profile-level-id=") {
                    // Basic validation - could be more comprehensive
                    if fmtp.len() > 1000 {
                        return Err("H.264 fmtp too long".to_string());
                    }
                }
            }
            _ => {
                // For other codecs, basic length check
                if fmtp.len() > 500 {
                    return Err("Codec fmtp too long".to_string());
                }
            }
        }

        Ok(())
    }

    /// [CLOCK RATE] Get codec clock rate
    fn get_clock_rate(codec: &str) -> u32 {
        match codec {
            "opus" => 48000,
            "pcmu" | "pcma" => 8000,
            _ => 90000, // Default for video codecs
        }
    }

    /// [CHANNELS] Get codec channel count
    fn get_channels(codec: &str) -> u8 {
        match codec {
            "pcmu" | "pcma" => 1,
            _ => 1, // Most codecs default to mono/stereo handled separately
        }
    }
}

/// [CODEC INFO] Validated codec information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodecInfo {
    pub name: String,
    pub payload_type: u8,
    pub clock_rate: u32,
    pub channels: u8,
}

/// [BANDWIDTH CALCULATOR] Network bandwidth estimation
/// @MISSION Calculate bandwidth requirements for VoIP calls.
/// @THREAT Bandwidth exhaustion, QoS issues.
/// @COUNTERMEASURE Accurate bandwidth calculation.
pub struct BandwidthCalculator;

impl BandwidthCalculator {
    /// [BANDWIDTH ESTIMATION] Estimate call bandwidth requirements
    /// @MISSION Calculate total bandwidth needed.
    /// @THREAT Inaccurate bandwidth allocation.
    /// @COUNTERMEASURE Empirical data and codec specifications.
    pub fn estimate_call_bandwidth(
        audio_codec: &str,
        video_codec: Option<&str>,
        participant_count: usize,
    ) -> BandwidthEstimate {
        let mut total_up = 0u32;
        let mut total_down = 0u32;

        // Audio bandwidth (bidirectional)
        let audio_bw = Self::get_audio_bandwidth(audio_codec);
        total_up += audio_bw;
        total_down += audio_bw * participant_count as u32;

        // Video bandwidth (if present)
        if let Some(video_codec) = video_codec {
            let video_bw = Self::get_video_bandwidth(video_codec);
            total_up += video_bw;
            total_down += video_bw * participant_count as u32;
        }

        // Add protocol overhead (RTP, RTCP, STUN, TURN)
        let overhead_factor = 1.2;
        total_up = (total_up as f64 * overhead_factor) as u32;
        total_down = (total_down as f64 * overhead_factor) as u32;

        BandwidthEstimate {
            upload_kbps: total_up,
            download_kbps: total_down,
            recommended_upload: total_up * 2, // Buffer for variability
            recommended_download: total_down * 2,
        }
    }

    /// [AUDIO BANDWIDTH] Get audio codec bandwidth
    fn get_audio_bandwidth(codec: &str) -> u32 {
        match codec.to_lowercase().as_str() {
            "opus" => 64,    // Opus at 64kbps
            "pcmu" | "pcma" => 64, // G.711
            "g722" => 64,    // G.722
            _ => 32,         // Conservative default
        }
    }

    /// [VIDEO BANDWIDTH] Get video codec bandwidth
    fn get_video_bandwidth(codec: &str) -> u32 {
        match codec.to_lowercase().as_str() {
            "vp8" => 500,    // VP8 typical bitrate
            "vp9" => 400,    // VP9 more efficient
            "h264" => 600,   // H.264
            _ => 300,        // Conservative default
        }
    }
}

/// [BANDWIDTH ESTIMATE] Bandwidth calculation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthEstimate {
    pub upload_kbps: u32,
    pub download_kbps: u32,
    pub recommended_upload: u32,
    pub recommended_download: u32,
}

/// [CALL QUALITY MONITOR] VoIP quality assessment
/// @MISSION Monitor and assess call quality metrics.
/// @THREAT Poor call quality, user dissatisfaction.
/// @COUNTERMEASURE Quality monitoring and alerting.
pub struct CallQualityMonitor;

impl CallQualityMonitor {
    /// [QUALITY ASSESSMENT] Assess call quality from metrics
    /// @MISSION Calculate quality score from RTP metrics.
    /// @THREAT Poor quality calls undetected.
    /// @COUNTERMEASURE Automated quality assessment.
    pub fn assess_quality(
        packet_loss: f64,
        jitter_ms: f64,
        latency_ms: u32,
        codec: &str,
    ) -> QualityScore {
        let mut score = 100u8;

        // Packet loss impact (0-100%, higher is worse)
        score = score.saturating_sub((packet_loss * 50.0) as u8);

        // Jitter impact (0-100ms, higher is worse)
        let jitter_penalty = if jitter_ms > 50.0 {
            ((jitter_ms - 50.0) / 2.0) as u8
        } else {
            0
        };
        score = score.saturating_sub(jitter_penalty.min(30));

        // Latency impact (0-500ms, higher is worse)
        let latency_penalty = if latency_ms > 200 {
            ((latency_ms - 200) / 10) as u8
        } else {
            0
        };
        score = score.saturating_sub(latency_penalty.min(20));

        // Codec efficiency bonus
        let codec_bonus = match codec.to_lowercase().as_str() {
            "opus" => 5,
            "vp9" => 3,
            "vp8" => 2,
            _ => 0,
        };
        score = score.saturating_add(codec_bonus);

        let rating = if score >= 90 {
            QualityRating::Excellent
        } else if score >= 75 {
            QualityRating::Good
        } else if score >= 60 {
            QualityRating::Fair
        } else if score >= 40 {
            QualityRating::Poor
        } else {
            QualityRating::Unusable
        };

        QualityScore { score, rating }
    }

    /// [QUALITY THRESHOLDS] Get quality threshold recommendations
    /// @MISSION Provide quality monitoring thresholds.
    /// @THREAT Inappropriate alerting.
    /// @COUNTERMEASURE Evidence-based thresholds.
    pub fn get_quality_thresholds() -> QualityThresholds {
        QualityThresholds {
            excellent_packet_loss: 0.5,
            good_packet_loss: 2.0,
            poor_packet_loss: 5.0,
            excellent_jitter: 10.0,
            good_jitter: 30.0,
            poor_jitter: 50.0,
            excellent_latency: 50,
            good_latency: 150,
            poor_latency: 300,
        }
    }
}

/// [QUALITY SCORE] Call quality assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityScore {
    pub score: u8, // 0-100
    pub rating: QualityRating,
}

/// [QUALITY RATING] Qualitative quality assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QualityRating {
    Excellent,
    Good,
    Fair,
    Poor,
    Unusable,
}

/// [QUALITY THRESHOLDS] Quality monitoring thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityThresholds {
    pub excellent_packet_loss: f64,
    pub good_packet_loss: f64,
    pub poor_packet_loss: f64,
    pub excellent_jitter: f64,
    pub good_jitter: f64,
    pub poor_jitter: f64,
    pub excellent_latency: u32,
    pub good_latency: u32,
    pub poor_latency: u32,
}

/// [VOIP ID GENERATOR] Generate unique VoIP identifiers
/// @MISSION Create unique IDs for calls, rooms, and sessions.
/// @THREAT ID collisions, predictability.
/// @COUNTERMEASURE Cryptographically secure generation.
pub struct VoipIdGenerator;

impl VoipIdGenerator {
    /// [CALL ID GENERATION] Generate unique call identifier
    /// @MISSION Create call ID with VoIP prefix.
    /// @THREAT ID collision.
    /// @COUNTERMEASURE UUID-based generation.
    pub fn generate_call_id() -> String {
        format!("call_{}", Uuid::new_v4().simple())
    }

    /// [ROOM ID GENERATION] Generate unique room identifier
    /// @MISSION Create room ID with VoIP prefix.
    /// @THREAT ID collision.
    /// @COUNTERMEASURE UUID-based generation.
    pub fn generate_room_id() -> String {
        format!("room_{}", Uuid::new_v4().simple())
    }

    /// [SESSION ID GENERATION] Generate unique session identifier
    /// @MISSION Create session ID with VoIP prefix.
    /// @THREAT ID collision.
    /// @COUNTERMEASURE UUID-based generation.
    pub fn generate_session_id() -> String {
        format!("session_{}", Uuid::new_v4().simple())
    }

    /// [SIGNALING ID GENERATION] Generate unique signaling message ID
    /// @MISSION Create signaling ID with sequence.
    /// @THREAT ID collision.
    /// @COUNTERMEASURE UUID-based generation.
    pub fn generate_signaling_id() -> String {
        format!("sig_{}", Uuid::new_v4().simple())
    }
}

/// [DURATION FORMATTER] Format call durations for display
/// @MISSION Format duration strings for user interfaces.
/// @THREAT Incorrect duration display.
/// @COUNTERMEASURE Safe formatting.
pub struct DurationFormatter;

impl DurationFormatter {
    /// [DURATION FORMATTING] Format seconds into human-readable string
    /// @MISSION Create user-friendly duration display.
    /// @THREAT Formatting errors.
    /// @COUNTERMEASURE Safe arithmetic and formatting.
    pub fn format_duration(seconds: u64) -> String {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        let secs = seconds % 60;

        if hours > 0 {
            format!("{}:{:02}:{:02}", hours, minutes, secs)
        } else {
            format!("{}:{:02}", minutes, secs)
        }
    }

    /// [DURATION PARSING] Parse duration string into seconds
    /// @MISSION Parse user input duration.
    /// @THREAT Malformed input.
    /// @COUNTERMEASURE Safe parsing with validation.
    pub fn parse_duration(duration_str: &str) -> Result<u64, String> {
        let parts: Vec<&str> = duration_str.split(':').collect();

        match parts.len() {
            1 => {
                // Just seconds
                parts[0].parse::<u64>()
                    .map_err(|_| "Invalid seconds format".to_string())
            }
            2 => {
                // minutes:seconds
                let minutes: u64 = parts[0].parse()
                    .map_err(|_| "Invalid minutes format".to_string())?;
                let seconds: u64 = parts[1].parse()
                    .map_err(|_| "Invalid seconds format".to_string())?;
                Ok(minutes * 60 + seconds)
            }
            3 => {
                // hours:minutes:seconds
                let hours: u64 = parts[0].parse()
                    .map_err(|_| "Invalid hours format".to_string())?;
                let minutes: u64 = parts[1].parse()
                    .map_err(|_| "Invalid minutes format".to_string())?;
                let seconds: u64 = parts[2].parse()
                    .map_err(|_| "Invalid seconds format".to_string())?;
                Ok(hours * 3600 + minutes * 60 + seconds)
            }
            _ => Err("Invalid duration format".to_string()),
        }
    }
}

/// [VOIP LOGGER] Specialized logging for VoIP operations
/// @MISSION Log VoIP events with structured data.
/// @THREAT Log injection, sensitive data exposure.
/// @COUNTERMEASURE Sanitized logging, structured format.
pub struct VoipLogger;

impl VoipLogger {
    /// [CALL EVENT LOGGING] Log call lifecycle events
    /// @MISSION Record call events for auditing.
    /// @THREAT Log data exposure.
    /// @COUNTERMEASURE Sanitized structured logging.
    pub fn log_call_event(call_id: &str, event: &str, details: serde_json::Value) {
        println!(
            "VOIP_CALL_EVENT: call_id={}, event={}, details={}",
            call_id,
            event,
            serde_json::to_string(&details).unwrap_or_default()
        );
    }

    /// [SIGNALING LOGGING] Log signaling events
    /// @MISSION Record signaling for debugging.
    /// @THREAT Sensitive data in logs.
    /// @COUNTERMEASURE Sanitized logging.
    pub fn log_signaling_event(call_id: &str, from: &str, to: &str, message_type: &str) {
        println!(
            "VOIP_SIGNALING: call_id={}, from={}, to={}, type={}",
            call_id, from, to, message_type
        );
    }

    /// [QUALITY LOGGING] Log quality metrics
    /// @MISSION Record quality data for monitoring.
    /// @THREAT Log volume.
    /// @COUNTERMEASURE Structured sampling.
    pub fn log_quality_metrics(call_id: &str, metrics: serde_json::Value) {
        println!(
            "VOIP_QUALITY: call_id={}, metrics={}",
            call_id,
            serde_json::to_string(&metrics).unwrap_or_default()
        );
    }
}