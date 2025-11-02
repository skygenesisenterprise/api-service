// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Asterisk ARI Client
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide native Asterisk PBX integration through ARI (Asterisk
//  REST Interface) for enterprise VoIP management and call control.
//  NOTICE: Implements secure communication with Asterisk server for call
//  management, channel control, and PBX administration.
//  ASTERISK INTEGRATION: ARI (Asterisk REST Interface) v1.8+
//  SECURITY: TLS encryption, authentication, audit logging
//  COMPLIANCE: Enterprise VoIP security standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// [ASTERISK CONFIG] Configuration for Asterisk ARI connection
#[derive(Debug, Clone)]
pub struct AsteriskConfig {
    pub base_url: String,
    pub username: String,
    pub password: String,
    pub app_name: String,
    pub tls_enabled: bool,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub ca_cert_path: Option<String>,
}

/// [ARI CHANNEL] Asterisk channel information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AriChannel {
    pub id: String,
    pub name: String,
    pub state: String,
    pub caller: AriCallerId,
    pub connected: AriCallerId,
    pub accountcode: String,
    pub dialplan: AriDialplan,
    pub creationtime: DateTime<Utc>,
    pub language: String,
}

/// [ARI CALLER ID] Caller identification information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AriCallerId {
    pub name: String,
    pub number: String,
}

/// [ARI DIALPLAN] Dialplan context and extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AriDialplan {
    pub context: String,
    pub exten: String,
    pub priority: u32,
}

/// [ARI BRIDGE] Conference bridge information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AriBridge {
    pub id: String,
    pub name: String,
    pub bridge_type: String,
    pub bridge_class: String,
    pub channels: Vec<String>,
    pub creator: String,
    pub creationtime: DateTime<Utc>,
}

/// [ARI ENDPOINT] SIP endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AriEndpoint {
    pub technology: String,
    pub resource: String,
    pub state: String,
    pub channel_ids: Vec<String>,
}

/// [ARI PLAYBACK] Audio playback information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AriPlayback {
    pub id: String,
    pub media_uri: String,
    pub target_uri: String,
    pub state: String,
}

/// [ARI RECORDING] Call recording information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AriRecording {
    pub id: String,
    pub name: String,
    pub format: String,
    pub target_uri: String,
    pub state: String,
}

/// [ASTERISK CLIENT] Main client for Asterisk ARI integration
pub struct AsteriskClient {
    client: Client,
    config: AsteriskConfig,
}

impl AsteriskClient {
    /// [CLIENT INITIALIZATION] Create new Asterisk ARI client with TLS support
    /// @MISSION Create secure HTTP client with optional mTLS authentication.
    /// @THREAT Man-in-the-middle attacks, unauthorized ARI access.
    /// @COUNTERMEASURE TLS encryption, mutual certificate authentication.
    pub fn new(config: AsteriskConfig) -> Self {
        let mut client_builder = Client::builder()
            .timeout(std::time::Duration::from_secs(30));

        // Configure TLS if enabled
        if config.tls_enabled {
            client_builder = client_builder.use_rustls_tls();

            // Add client certificate for mutual TLS if provided
            if let (Some(cert_path), Some(key_path)) = (&config.client_cert_path, &config.client_key_path) {
                // Load client certificate and private key
                let cert = std::fs::read(cert_path)
                    .expect("Failed to read client certificate");
                let key = std::fs::read(key_path)
                    .expect("Failed to read client private key");

                let identity = reqwest::Identity::from_pkcs12_der(&cert, "")
                    .expect("Failed to create identity from certificate");

                client_builder = client_builder.identity(identity);
            }

            // Add CA certificate for server verification if provided
            if let Some(ca_path) = &config.ca_cert_path {
                let ca_cert = std::fs::read(ca_path)
                    .expect("Failed to read CA certificate");

                // Note: reqwest doesn't directly support custom CA certs in builder
                // This would require using rustls directly or a custom connector
                // For now, we'll rely on system CA certificates
            }
        }

        let client = client_builder
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    /// [AUTHENTICATION] Get authentication header for ARI requests
    fn auth_header(&self) -> String {
        use base64::encode;
        let credentials = format!("{}:{}", self.config.username, self.config.password);
        format!("Basic {}", encode(credentials))
    }

    /// [ARI REQUEST] Make authenticated request to ARI
    async fn ari_request(&self, method: reqwest::Method, endpoint: &str, body: Option<serde_json::Value>) -> Result<Response, String> {
        let url = format!("{}/ari/{}", self.config.base_url.trim_end_matches('/'), endpoint.trim_start_matches('/'));

        let mut request = self.client
            .request(method, &url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json");

        if let Some(body) = body {
            request = request.json(&body);
        }

        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(response)
                } else {
                    let status = response.status();
                    let error_text = response.text().await.unwrap_or_default();
                    Err(format!("ARI request failed: {} - {}", status, error_text))
                }
            }
            Err(e) => Err(format!("Request error: {}", e)),
        }
    }

    // ===== CHANNEL MANAGEMENT =====

    /// [GET CHANNELS] List all active channels
    pub async fn get_channels(&self) -> Result<Vec<AriChannel>, String> {
        let response = self.ari_request(reqwest::Method::GET, "channels", None).await?;
        let channels: Vec<AriChannel> = response.json().await
            .map_err(|e| format!("Failed to parse channels: {}", e))?;
        Ok(channels)
    }

    /// [GET CHANNEL] Get specific channel information
    pub async fn get_channel(&self, channel_id: &str) -> Result<AriChannel, String> {
        let endpoint = format!("channels/{}", channel_id);
        let response = self.ari_request(reqwest::Method::GET, &endpoint, None).await?;
        let channel: AriChannel = response.json().await
            .map_err(|e| format!("Failed to parse channel: {}", e))?;
        Ok(channel)
    }

    /// [CREATE CHANNEL] Originate new channel
    pub async fn create_channel(&self, endpoint: &str, app: &str, caller_id: Option<&str>) -> Result<AriChannel, String> {
        let mut body = serde_json::json!({
            "endpoint": endpoint,
            "app": app
        });

        if let Some(caller_id) = caller_id {
            body["callerId"] = serde_json::Value::String(caller_id.to_string());
        }

        let response = self.ari_request(reqwest::Method::POST, "channels", Some(body)).await?;
        let channel: AriChannel = response.json().await
            .map_err(|e| format!("Failed to parse created channel: {}", e))?;
        Ok(channel)
    }

    /// [DELETE CHANNEL] Hang up channel
    pub async fn delete_channel(&self, channel_id: &str) -> Result<(), String> {
        let endpoint = format!("channels/{}", channel_id);
        self.ari_request(reqwest::Method::DELETE, &endpoint, None).await?;
        Ok(())
    }

    /// [ANSWER CHANNEL] Answer incoming channel
    pub async fn answer_channel(&self, channel_id: &str) -> Result<(), String> {
        let endpoint = format!("channels/{}/answer", channel_id);
        self.ari_request(reqwest::Method::POST, &endpoint, None).await?;
        Ok(())
    }

    /// [RING CHANNEL] Start ringing on channel
    pub async fn ring_channel(&self, channel_id: &str) -> Result<(), String> {
        let endpoint = format!("channels/{}/ring", channel_id);
        self.ari_request(reqwest::Method::POST, &endpoint, None).await?;
        Ok(())
    }

    /// [HOLD CHANNEL] Put channel on hold
    pub async fn hold_channel(&self, channel_id: &str) -> Result<(), String> {
        let endpoint = format!("channels/{}/hold", channel_id);
        self.ari_request(reqwest::Method::POST, &endpoint, None).await?;
        Ok(())
    }

    /// [UNHOLD CHANNEL] Take channel off hold
    pub async fn unhold_channel(&self, channel_id: &str) -> Result<(), String> {
        let endpoint = format!("channels/{}/unhold", channel_id);
        self.ari_request(reqwest::Method::POST, &endpoint, None).await?;
        Ok(())
    }

    // ===== BRIDGE MANAGEMENT =====

    /// [GET BRIDGES] List all bridges
    pub async fn get_bridges(&self) -> Result<Vec<AriBridge>, String> {
        let response = self.ari_request(reqwest::Method::GET, "bridges", None).await?;
        let bridges: Vec<AriBridge> = response.json().await
            .map_err(|e| format!("Failed to parse bridges: {}", e))?;
        Ok(bridges)
    }

    /// [CREATE BRIDGE] Create new conference bridge
    pub async fn create_bridge(&self, bridge_type: &str, name: Option<&str>) -> Result<AriBridge, String> {
        let mut body = serde_json::json!({
            "type": bridge_type
        });

        if let Some(name) = name {
            body["name"] = serde_json::Value::String(name.to_string());
        }

        let response = self.ari_request(reqwest::Method::POST, "bridges", Some(body)).await?;
        let bridge: AriBridge = response.json().await
            .map_err(|e| format!("Failed to parse created bridge: {}", e))?;
        Ok(bridge)
    }

    /// [DELETE BRIDGE] Destroy bridge
    pub async fn delete_bridge(&self, bridge_id: &str) -> Result<(), String> {
        let endpoint = format!("bridges/{}", bridge_id);
        self.ari_request(reqwest::Method::DELETE, &endpoint, None).await?;
        Ok(())
    }

    /// [ADD CHANNEL TO BRIDGE] Add channel to bridge
    pub async fn add_channel_to_bridge(&self, bridge_id: &str, channel_id: &str) -> Result<(), String> {
        let endpoint = format!("bridges/{}/addChannel", bridge_id);
        let body = serde_json::json!({
            "channel": channel_id
        });
        self.ari_request(reqwest::Method::POST, &endpoint, Some(body)).await?;
        Ok(())
    }

    /// [REMOVE CHANNEL FROM BRIDGE] Remove channel from bridge
    pub async fn remove_channel_from_bridge(&self, bridge_id: &str, channel_id: &str) -> Result<(), String> {
        let endpoint = format!("bridges/{}/removeChannel", bridge_id);
        let body = serde_json::json!({
            "channel": channel_id
        });
        self.ari_request(reqwest::Method::POST, &endpoint, Some(body)).await?;
        Ok(())
    }

    // ===== ENDPOINT MANAGEMENT =====

    /// [GET ENDPOINTS] List all endpoints
    pub async fn get_endpoints(&self) -> Result<Vec<AriEndpoint>, String> {
        let response = self.ari_request(reqwest::Method::GET, "endpoints", None).await?;
        let endpoints: Vec<AriEndpoint> = response.json().await
            .map_err(|e| format!("Failed to parse endpoints: {}", e))?;
        Ok(endpoints)
    }

    /// [GET ENDPOINT] Get specific endpoint information
    pub async fn get_endpoint(&self, tech: &str, resource: &str) -> Result<AriEndpoint, String> {
        let endpoint = format!("endpoints/{}/{}", tech, resource);
        let response = self.ari_request(reqwest::Method::GET, &endpoint, None).await?;
        let endpoint_info: AriEndpoint = response.json().await
            .map_err(|e| format!("Failed to parse endpoint: {}", e))?;
        Ok(endpoint_info)
    }

    // ===== PLAYBACK MANAGEMENT =====

    /// [PLAY AUDIO] Play audio file on channel
    pub async fn play_audio(&self, channel_id: &str, media: &str) -> Result<AriPlayback, String> {
        let endpoint = format!("channels/{}/play", channel_id);
        let body = serde_json::json!({
            "media": media
        });
        let response = self.ari_request(reqwest::Method::POST, &endpoint, Some(body)).await?;
        let playback: AriPlayback = response.json().await
            .map_err(|e| format!("Failed to parse playback: {}", e))?;
        Ok(playback)
    }

    /// [STOP PLAYBACK] Stop audio playback
    pub async fn stop_playback(&self, playback_id: &str) -> Result<(), String> {
        let endpoint = format!("playbacks/{}", playback_id);
        self.ari_request(reqwest::Method::DELETE, &endpoint, None).await?;
        Ok(())
    }

    // ===== RECORDING MANAGEMENT =====

    /// [RECORD CHANNEL] Start recording channel
    pub async fn record_channel(&self, channel_id: &str, name: &str, format: &str) -> Result<AriRecording, String> {
        let endpoint = format!("channels/{}/record", channel_id);
        let body = serde_json::json!({
            "name": name,
            "format": format
        });
        let response = self.ari_request(reqwest::Method::POST, &endpoint, Some(body)).await?;
        let recording: AriRecording = response.json().await
            .map_err(|e| format!("Failed to parse recording: {}", e))?;
        Ok(recording)
    }

    /// [STOP RECORDING] Stop channel recording
    pub async fn stop_recording(&self, recording_name: &str) -> Result<(), String> {
        let endpoint = format!("recordings/live/{}/stop", recording_name);
        self.ari_request(reqwest::Method::POST, &endpoint, None).await?;
        Ok(())
    }

    // ===== UTILITY METHODS =====

    /// [HEALTH CHECK] Test Asterisk ARI connectivity
    pub async fn health_check(&self) -> Result<bool, String> {
        match self.ari_request(reqwest::Method::GET, "asterisk/info", None).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// [GET ASTERISK INFO] Get Asterisk system information
    pub async fn get_asterisk_info(&self) -> Result<serde_json::Value, String> {
        let response = self.ari_request(reqwest::Method::GET, "asterisk/info", None).await?;
        let info: serde_json::Value = response.json().await
            .map_err(|e| format!("Failed to parse Asterisk info: {}", e))?;
        Ok(info)
    }

    /// [RELOAD MODULE] Reload Asterisk module
    pub async fn reload_module(&self, module: &str) -> Result<(), String> {
        let endpoint = format!("asterisk/modules/{}", module);
        let body = serde_json::json!({
            "action": "reload"
        });
        self.ari_request(reqwest::Method::PUT, &endpoint, Some(body)).await?;
        Ok(())
    }
}