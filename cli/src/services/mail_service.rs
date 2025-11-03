// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Mail Service
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide mail business logic for CLI operations.
//  NOTICE: This module encapsulates mail operations using the API client.
//  SECURITY: Secure mail handling and validation
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::core::api_client::SshApiClient;
use crate::queries::mail_query::MailQuery;
use anyhow::Result;
use serde_json::Value;

/// Mail service for CLI operations
#[allow(dead_code)]
pub struct MailService<'a> {
    client: &'a SshApiClient,
}

#[allow(dead_code)]
impl<'a> MailService<'a> {
    /// Create new mail service
    pub fn new(client: &'a SshApiClient) -> Self {
        Self { client }
    }

    /// Get mail service status
    pub async fn get_status(&self) -> Result<Value> {
        let params = MailQuery::status();
        let result = self.client.call_method("mail.status", params)?;
        Ok(result)
    }

    /// Send test email
    pub async fn send_test(&self, to: &str) -> Result<Value> {
        let params = MailQuery::send_test(to);
        let result = self.client.call_method("mail.send_test", params)?;
        Ok(result)
    }

    /// Send email
    pub async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<Value> {
        let params = MailQuery::send_email(to, subject, body);
        let result = self.client.call_method("mail.send", params)?;
        Ok(result)
    }

    /// Get mail configuration
    pub async fn get_config(&self) -> Result<Value> {
        let params = MailQuery::get_config();
        let result = self.client.call_method("mail.get_config", params)?;
        Ok(result)
    }

    /// Update mail configuration
    pub async fn update_config(&self, smtp_host: &str, smtp_port: u16, username: &str) -> Result<Value> {
        let params = MailQuery::update_config(smtp_host, smtp_port, username);
        let result = self.client.call_method("mail.update_config", params)?;
        Ok(result)
    }

    /// Get mail queue status
    pub async fn get_queue_status(&self) -> Result<Value> {
        let params = serde_json::json!({
            "action": "queue_status"
        });
        let result = self.client.call_method("mail.queue_status", params)?;
        Ok(result)
    }

    /// Clear mail queue
    pub async fn clear_queue(&self) -> Result<Value> {
        let params = serde_json::json!({
            "action": "clear_queue"
        });
        let result = self.client.call_method("mail.clear_queue", params)?;
        Ok(result)
    }
}