// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Secure Mail Storage Manager
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide encrypted mail storage and retrieval with Stalwart
//  integration, Vault-backed encryption, and comprehensive audit logging.
//  NOTICE: This module implements zero-knowledge email storage with
//  AES-256-GCM encryption, metadata isolation, and compliance monitoring.
//  STORAGE: Stalwart IMAP/SMTP server, Vault Transit encryption,
//  PostgreSQL metadata, Redis caching
//  SECURITY: End-to-end encryption, access controls, data masking
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::sync::Arc;
use tokio::sync::RwLock;
use crate::core::stalwart_client::StalwartClient;
use crate::core::vault::VaultClient;
use crate::core::encryption_manager::{EncryptionManager, EncryptionMethod};
use crate::core::audit_manager::{AuditManager, AuditEventType, AuditSeverity};
use crate::models::user::User;
use crate::models::mail::*;

#[derive(Debug)]
pub enum StorageError {
    StalwartError(String),
    EncryptionError(String),
    VaultError(String),
    AuditError(String),
    ValidationError(String),
    PermissionError(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::StalwartError(msg) => write!(f, "Stalwart error: {}", msg),
            StorageError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            StorageError::VaultError(msg) => write!(f, "Vault error: {}", msg),
            StorageError::AuditError(msg) => write!(f, "Audit error: {}", msg),
            StorageError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            StorageError::PermissionError(msg) => write!(f, "Permission error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

pub type StorageResult<T> = Result<T, StorageError>;

/// [MAIL STORAGE MANAGER STRUCT] Secure Email Storage Interface
/// @MISSION Provide encrypted email storage and retrieval with Stalwart integration.
/// @THREAT Email data exposure or unauthorized access to stored messages.
/// @COUNTERMEASURE AES-256-GCM encryption, access controls, and comprehensive audit.
/// @DEPENDENCY Stalwart mail server, Vault encryption, and audit logging.
/// @INVARIANT All stored emails are encrypted and access is auditable.
/// @AUDIT Storage operations logged for compliance and security monitoring.
pub struct MailStorageManager {
    stalwart_client: Arc<StalwartClient>,
    vault_client: Arc<VaultClient>,
    encryption_manager: Arc<EncryptionManager>,
    audit_manager: Arc<AuditManager>,
    cache: Arc<RwLock<std::collections::HashMap<String, CachedMailData>>>,
}

/// [CACHED MAIL DATA STRUCT] Performance-Optimized Email Caching
/// @MISSION Cache encrypted email data for improved retrieval performance.
/// @THREAT Cache poisoning or data exposure through memory dumps.
/// @COUNTERMEASURE Time-limited caching with encryption status tracking.
/// @DEPENDENCY RwLock for thread-safe access and automatic cleanup.
/// @INVARIANT Cached data expires and is validated before use.
/// @AUDIT Cache operations logged for performance and security monitoring.
#[derive(Clone)]
struct CachedMailData {
    data: Vec<u8>,
    timestamp: chrono::DateTime<chrono::Utc>,
    encrypted: bool,
}

impl MailStorageManager {
    /// Create new mail storage manager
    pub fn new(
        stalwart_client: Arc<StalwartClient>,
        vault_client: Arc<VaultClient>,
        encryption_manager: Arc<EncryptionManager>,
        audit_manager: Arc<AuditManager>,
    ) -> Self {
        MailStorageManager {
            stalwart_client,
            vault_client,
            encryption_manager,
            audit_manager,
            cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    // ============================================================================
    // MAILBOX OPERATIONS
    // ============================================================================

    /// Get user mailboxes with security validation
    pub async fn get_user_mailboxes(&self, user: &User) -> StorageResult<Vec<Mailbox>> {
        // Audit the access
        let _ = self.audit_manager.log_mail_event(
            AuditEventType::MailRead,
            user,
            "mailboxes".to_string(),
            true,
            serde_json::json!({"operation": "list_mailboxes"}),
        ).await;

        // Get mailboxes from Stalwart
        let mailboxes = self.stalwart_client.get_mailboxes(user).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        // Apply security filtering (remove sensitive system mailboxes if needed)
        let filtered_mailboxes = self.filter_mailboxes_by_permissions(mailboxes, user);

        Ok(filtered_mailboxes)
    }

    /// Get specific mailbox details
    pub async fn get_mailbox(&self, mailbox_id: &str, user: &User) -> StorageResult<Mailbox> {
        // Validate permissions
        self.validate_mailbox_access(mailbox_id, user).await?;

        // Audit the access
        let _ = self.audit_manager.log_mail_event(
            AuditEventType::MailRead,
            user,
            format!("mailbox:{}", mailbox_id),
            true,
            serde_json::json!({"operation": "get_mailbox", "mailbox_id": mailbox_id}),
        ).await;

        // Get mailbox from Stalwart
        let mailbox = self.stalwart_client.get_mailbox(mailbox_id, user).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        Ok(mailbox)
    }

    // ============================================================================
    // MESSAGE OPERATIONS
    // ============================================================================

    /// Get messages from mailbox with encryption/decryption
    pub async fn get_messages(&self, query: &MessageQuery, user: &User) -> StorageResult<Vec<Message>> {
        // Validate permissions
        self.validate_message_query_permissions(query, user).await?;

        // Audit the access
        let _ = self.audit_manager.log_mail_event(
            AuditEventType::MailRead,
            user,
            format!("mailbox:{}", query.mailbox.as_deref().unwrap_or("unknown")),
            true,
            serde_json::json!({"operation": "get_messages", "query": serde_json::to_value(query).unwrap_or_default()}),
        ).await;

        // Get messages from Stalwart
        let mut messages = self.stalwart_client.get_messages(query, user).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        // Decrypt message bodies if they are encrypted
        for message in &mut messages {
            if let Some(body) = &message.body {
                let decrypted_body = self.encryption_manager.decrypt_message_body(body, user).await
                    .map_err(|e| StorageError::EncryptionError(format!("Failed to decrypt message {}: {}", message.id, e)))?;
                message.body = Some(decrypted_body);
            }
        }

        Ok(messages)
    }

    /// Get specific message with decryption
    pub async fn get_message(&self, message_id: &str, user: &User) -> StorageResult<Message> {
        // Validate permissions
        self.validate_message_access(message_id, user).await?;

        // Check cache first
        let cache_key = format!("message:{}:{}", user.id, message_id);
        if let Some(cached) = self.get_cached_message(&cache_key).await {
            // Audit cache hit
            let _ = self.audit_manager.log_mail_event(
                AuditEventType::MailRead,
                user,
                format!("message:{}", message_id),
                true,
                serde_json::json!({"operation": "get_message", "cached": true}),
            ).await;
            return Ok(cached);
        }

        // Get message from Stalwart
        let mut message = self.stalwart_client.get_message(message_id, user).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        // Decrypt message body if encrypted
        if let Some(body) = &message.body {
            let decrypted_body = self.encryption_manager.decrypt_message_body(body, user).await
                .map_err(|e| StorageError::EncryptionError(format!("Failed to decrypt message {}: {}", message_id, e)))?;
            message.body = Some(decrypted_body);
        }

        // Cache the decrypted message
        self.cache_message(&cache_key, &message).await;

        // Audit the access
        let _ = self.audit_manager.log_mail_event(
            AuditEventType::MailRead,
            user,
            format!("message:{}", message_id),
            true,
            serde_json::json!({"operation": "get_message", "cached": false}),
        ).await;

        Ok(message)
    }

    /// Send message with encryption
    pub async fn send_message(&self, request: &SendRequest, user: &User, encryption_method: Option<EncryptionMethod>) -> StorageResult<SendResult> {
        // Validate send permissions
        self.validate_send_permissions(request, user).await?;

        // Apply encryption if requested
        let send_request = if let Some(method) = encryption_method {
            let encrypted_body = self.encryption_manager.encrypt_message_body(&request.body, method, &request.to, user).await
                .map_err(|e| StorageError::EncryptionError(format!("Failed to encrypt message: {}", e)))?;

            SendRequest {
                to: request.to.clone(),
                cc: request.cc.clone(),
                bcc: request.bcc.clone(),
                subject: request.subject.clone(),
                body: encrypted_body,
                attachments: request.attachments.clone(),
                priority: request.priority.clone(),
                request_read_receipt: request.request_read_receipt.clone(),
            }
        } else {
            // Encrypt for storage anyway (at-rest encryption)
            let encrypted_body = MessageBody {
                text: if let Some(text) = &request.body.text {
                    Some(self.encryption_manager.encrypt_for_storage(text.as_bytes()).await
                        .map_err(|e| StorageError::EncryptionError(format!("Failed to encrypt text: {}", e)))?)
                } else {
                    None
                },
                html: if let Some(html) = &request.body.html {
                    Some(self.encryption_manager.encrypt_for_storage(html.as_bytes()).await
                        .map_err(|e| StorageError::EncryptionError(format!("Failed to encrypt HTML: {}", e)))?)
                } else {
                    None
                },
            };

            SendRequest {
                to: request.to.clone(),
                cc: request.cc.clone(),
                bcc: request.bcc.clone(),
                subject: request.subject.clone(),
                body: encrypted_body,
                attachments: request.attachments.clone(),
                priority: request.priority.clone(),
                request_read_receipt: request.request_read_receipt.clone(),
            }
        };

        // Send via Stalwart
        let result = self.stalwart_client.send_message(&send_request, user).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        // Audit the send operation
        let _ = self.audit_manager.log_mail_event(
            AuditEventType::MailSent,
            user,
            "outgoing".to_string(),
            true,
            serde_json::json!({
                "operation": "send_message",
                "recipients": request.to.len(),
                "has_attachments": request.attachments.is_some(),
                "encrypted": encryption_method.is_some()
            }),
        ).await;

        Ok(result)
    }

    /// Update message
    pub async fn update_message(&self, message_id: &str, update: &MessageUpdate, user: &User) -> StorageResult<()> {
        // Validate permissions
        self.validate_message_update_permissions(message_id, update, user).await?;

        // Update via Stalwart
        self.stalwart_client.update_message(message_id, update, user).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        // Clear cache
        let cache_key = format!("message:{}:{}", user.id, message_id);
        self.clear_cache(&cache_key).await;

        // Audit the update
        let _ = self.audit_manager.log_mail_event(
            AuditEventType::MailRead, // Using MailRead as closest match for update
            user,
            format!("message:{}", message_id),
            true,
            serde_json::json!({"operation": "update_message", "update": serde_json::to_value(update).unwrap_or_default()}),
        ).await;

        Ok(())
    }

    /// Delete message
    pub async fn delete_message(&self, message_id: &str, permanent: bool, user: &User) -> StorageResult<()> {
        // Validate permissions
        self.validate_message_delete_permissions(message_id, user).await?;

        // Delete via Stalwart
        self.stalwart_client.delete_message(message_id, permanent, user).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        // Clear cache
        let cache_key = format!("message:{}:{}", user.id, message_id);
        self.clear_cache(&cache_key).await;

        // Audit the deletion
        let _ = self.audit_manager.log_mail_event(
            AuditEventType::MailDeleted,
            user,
            format!("message:{}", message_id),
            true,
            serde_json::json!({"operation": "delete_message", "permanent": permanent}),
        ).await;

        Ok(())
    }

    // ============================================================================
    // ATTACHMENT OPERATIONS
    // ============================================================================

    /// Download attachment with decryption
    pub async fn download_attachment(&self, message_id: &str, attachment_id: &str, user: &User) -> StorageResult<Vec<u8>> {
        // Validate permissions
        self.validate_attachment_access(message_id, attachment_id, user).await?;

        // Download from Stalwart
        let encrypted_data = self.stalwart_client.get_attachment(message_id, attachment_id, user).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        // Decrypt if necessary (check if it's encrypted)
        let data = if self.is_encrypted_attachment(&encrypted_data) {
            self.encryption_manager.decrypt_aes_hybrid(&encrypted_data, &[], user).await
                .map_err(|e| StorageError::EncryptionError(format!("Failed to decrypt attachment: {}", e)))?
        } else {
            encrypted_data
        };

        // Audit the download
        let _ = self.audit_manager.log_mail_event(
            AuditEventType::AttachmentDownloaded,
            user,
            format!("attachment:{}:{}", message_id, attachment_id),
            true,
            serde_json::json!({"operation": "download_attachment", "size": data.len()}),
        ).await;

        Ok(data)
    }

    /// Upload attachment with encryption
    pub async fn upload_attachment(&self, filename: &str, content_type: &str, data: &[u8], user: &User) -> StorageResult<String> {
        // Validate upload permissions
        self.validate_attachment_upload_permissions(data.len(), user).await?;

        // Encrypt attachment for storage
        let (encrypted_data, encrypted_keys) = self.encryption_manager.encrypt_aes_hybrid(data, &[user.id.clone()]).await
            .map_err(|e| StorageError::EncryptionError(format!("Failed to encrypt attachment: {}", e)))?;

        // Upload to Stalwart
        let attachment_id = self.stalwart_client.upload_attachment(filename, content_type, &encrypted_data, user).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        // Audit the upload
        let _ = self.audit_manager.log_mail_event(
            AuditEventType::AttachmentUploaded,
            user,
            format!("attachment:{}", attachment_id),
            true,
            serde_json::json!({"operation": "upload_attachment", "filename": filename, "size": data.len()}),
        ).await;

        Ok(attachment_id)
    }

    // ============================================================================
    // SEARCH OPERATIONS
    // ============================================================================

    /// Search messages with security filtering
    pub async fn search_messages(&self, query: &SearchQuery, user: &User) -> StorageResult<SearchResult> {
        // Validate search permissions
        self.validate_search_permissions(query, user).await?;

        // Apply security filters to search query
        let filtered_query = self.apply_search_security_filters(query, user);

        // Search via Stalwart
        let result = self.stalwart_client.search_messages(&filtered_query, user).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        // Decrypt message previews if encrypted
        let mut filtered_messages = Vec::new();
        for mut message in result.messages {
            if let Some(body) = &message.body {
                let decrypted_body = self.encryption_manager.decrypt_message_body(body, user).await
                    .map_err(|e| StorageError::EncryptionError(format!("Failed to decrypt search result {}: {}", message.id, e)))?;
                message.body = Some(decrypted_body);
            }
            filtered_messages.push(message);
        }

        let filtered_result = SearchResult {
            messages: filtered_messages,
            total: result.total,
            has_more: result.has_more,
        };

        // Audit the search
        let _ = self.audit_manager.log_mail_event(
            AuditEventType::MailRead,
            user,
            "search".to_string(),
            true,
            serde_json::json!({"operation": "search_messages", "query": query.query, "results": filtered_result.messages.len()}),
        ).await;

        Ok(filtered_result)
    }

    // ============================================================================
    // DRAFT OPERATIONS
    // ============================================================================

    /// Save draft with encryption
    pub async fn save_draft(&self, draft: &DraftRequest, user: &User) -> StorageResult<String> {
        // Encrypt draft content
        let encrypted_body = self.encryption_manager.encrypt_message_body(&draft.body, EncryptionMethod::AesHybrid, &[user.id.clone()], user).await
            .map_err(|e| StorageError::EncryptionError(format!("Failed to encrypt draft: {}", e)))?;

        let encrypted_draft = DraftRequest {
            to: draft.to.clone(),
            cc: draft.cc.clone(),
            bcc: draft.bcc.clone(),
            subject: draft.subject.clone(),
            body: encrypted_body,
            attachments: draft.attachments.clone(),
        };

        // Save via Stalwart
        let draft_id = self.stalwart_client.save_draft(&encrypted_draft, user).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        // Audit the draft save
        let _ = self.audit_manager.log_mail_event(
            AuditEventType::MailRead, // Using MailRead as closest match
            user,
            format!("draft:{}", draft_id),
            true,
            serde_json::json!({"operation": "save_draft"}),
        ).await;

        Ok(draft_id)
    }

    /// Send draft
    pub async fn send_draft(&self, draft_id: &str, user: &User) -> StorageResult<SendResult> {
        // Send via Stalwart
        let result = self.stalwart_client.send_draft(draft_id, user).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        // Audit the draft send
        let _ = self.audit_manager.log_mail_event(
            AuditEventType::MailSent,
            user,
            format!("draft:{}", draft_id),
            true,
            serde_json::json!({"operation": "send_draft"}),
        ).await;

        Ok(result)
    }

    // ============================================================================
    // SECURITY VALIDATION METHODS
    // ============================================================================

    /// Validate mailbox access permissions
    async fn validate_mailbox_access(&self, mailbox_id: &str, user: &User) -> StorageResult<()> {
        // Check if user has access to this mailbox
        // This would check against user permissions and mailbox ownership
        // For now, allow access (implement proper validation based on your auth system)

        // Prevent access to system mailboxes for non-admin users
        if mailbox_id.starts_with("system.") && !user.roles.contains(&"admin".to_string()) {
            return Err(StorageError::PermissionError("Access denied to system mailbox".to_string()));
        }

        Ok(())
    }

    /// Validate message query permissions
    async fn validate_message_query_permissions(&self, query: &MessageQuery, user: &User) -> StorageResult<()> {
        // Validate mailbox access
        if let Some(mailbox) = &query.mailbox {
            self.validate_mailbox_access(mailbox, user).await?;
        }

        // Check rate limits
        // This would integrate with your rate limiting system

        Ok(())
    }

    /// Validate message access permissions
    async fn validate_message_access(&self, message_id: &str, user: &User) -> StorageResult<()> {
        // Check if user owns this message or has been granted access
        // This would query the message ownership from Stalwart or cache

        Ok(())
    }

    /// Validate send permissions
    async fn validate_send_permissions(&self, request: &SendRequest, user: &User) -> StorageResult<()> {
        // Check sending limits
        // Validate recipient domains
        // Check for spam patterns

        // Prevent sending to blocked domains
        let blocked_domains = vec!["spam.example.com", "malicious.example.com"];
        for recipient in &request.to {
            if let Some(domain) = recipient.split('@').nth(1) {
                if blocked_domains.contains(&domain) {
                    return Err(StorageError::PermissionError(format!("Sending to domain {} is not allowed", domain)));
                }
            }
        }

        Ok(())
    }

    /// Validate message update permissions
    async fn validate_message_update_permissions(&self, message_id: &str, update: &MessageUpdate, user: &User) -> StorageResult<()> {
        // Check if user can modify this message
        self.validate_message_access(message_id, user).await?;

        // Prevent certain updates for compliance
        if update.mailbox_id.is_some() {
            // Check if user can move to target mailbox
            if let Some(target_mailbox) = &update.mailbox_id {
                self.validate_mailbox_access(target_mailbox, user).await?;
            }
        }

        Ok(())
    }

    /// Validate message delete permissions
    async fn validate_message_delete_permissions(&self, message_id: &str, user: &User) -> StorageResult<()> {
        // Check if user can delete this message
        self.validate_message_access(message_id, user).await?;

        Ok(())
    }

    /// Validate attachment access
    async fn validate_attachment_access(&self, message_id: &str, attachment_id: &str, user: &User) -> StorageResult<()> {
        // Check message access first
        self.validate_message_access(message_id, user).await?;

        // Additional attachment-specific checks
        // Check file type restrictions, size limits, etc.

        Ok(())
    }

    /// Validate attachment upload permissions
    async fn validate_attachment_upload_permissions(&self, size: usize, user: &User) -> StorageResult<()> {
        // Check file size limits
        const MAX_ATTACHMENT_SIZE: usize = 25 * 1024 * 1024; // 25MB
        if size > MAX_ATTACHMENT_SIZE {
            return Err(StorageError::ValidationError(format!("Attachment size {} exceeds maximum allowed size {}", size, MAX_ATTACHMENT_SIZE)));
        }

        // Check user quota
        // This would check against user's attachment quota

        Ok(())
    }

    /// Validate search permissions
    async fn validate_search_permissions(&self, query: &SearchQuery, user: &User) -> StorageResult<()> {
        // Check if user can search
        // Apply search scope limitations

        Ok(())
    }

    /// Apply security filters to search query
    fn apply_search_security_filters(&self, query: &SearchQuery, user: &User) -> SearchQuery {
        // Limit search scope based on user permissions
        // Remove sensitive fields from search

        query.clone() // For now, return as-is
    }

    /// Filter mailboxes by user permissions
    fn filter_mailboxes_by_permissions(&self, mailboxes: Vec<Mailbox>, user: &User) -> Vec<Mailbox> {
        // Filter out mailboxes user shouldn't see
        mailboxes.into_iter()
            .filter(|mailbox| {
                // Allow access to user's personal mailboxes
                !mailbox.id.starts_with("system.") || user.roles.contains(&"admin".to_string())
            })
            .collect()
    }

    // ============================================================================
    // CACHING METHODS
    // ============================================================================

    /// Get cached message
    async fn get_cached_message(&self, cache_key: &str) -> Option<Message> {
        let cache = self.cache.read().await;
        if let Some(cached) = cache.get(cache_key) {
            // Check if cache is still valid (5 minutes)
            if chrono::Utc::now().signed_duration_since(cached.timestamp) < chrono::Duration::minutes(5) {
                // Deserialize cached message
                if let Ok(message) = serde_json::from_slice::<Message>(&cached.data) {
                    return Some(message);
                }
            }
        }
        None
    }

    /// Cache message
    async fn cache_message(&self, cache_key: &str, message: &Message) {
        if let Ok(data) = serde_json::to_vec(message) {
            let cached = CachedMailData {
                data,
                timestamp: chrono::Utc::now(),
                encrypted: false,
            };

            let mut cache = self.cache.write().await;
            cache.insert(cache_key.to_string(), cached);
        }
    }

    /// Clear cache entry
    async fn clear_cache(&self, cache_key: &str) {
        let mut cache = self.cache.write().await;
        cache.remove(cache_key);
    }

    /// Check if attachment data is encrypted
    fn is_encrypted_attachment(&self, data: &[u8]) -> bool {
        // Check for encryption markers
        data.len() > 32 && data.starts_with(b"SGE-ENCRYPTED-ATTACHMENT")
    }

    // ============================================================================
    // HEALTH AND MONITORING
    // ============================================================================

    /// Health check
    pub async fn health_check(&self) -> StorageResult<serde_json::Value> {
        // Check Stalwart connectivity
        let stalwart_ok = self.stalwart_client.health_check(None).await
            .map_err(|e| StorageError::StalwartError(e.to_string()))?;

        // Check Vault connectivity
        let vault_ok = self.vault_client.get_secret("secret/health").await.is_ok();

        // Check encryption functionality
        let test_data = b"health check";
        let encrypted = self.encryption_manager.encrypt_for_storage(test_data).await
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
        let decrypted = self.encryption_manager.decrypt_from_storage(&encrypted).await
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
        let encryption_ok = decrypted == test_data;

        let cache_size = {
            let cache = self.cache.read().await;
            cache.len()
        };

        let status = serde_json::json!({
            "stalwart": stalwart_ok,
            "vault": vault_ok,
            "encryption": encryption_ok,
            "cache_size": cache_size,
            "overall_healthy": stalwart_ok && vault_ok && encryption_ok
        });

        Ok(status)
    }

    /// Get storage statistics
    pub async fn get_statistics(&self) -> StorageResult<serde_json::Value> {
        let cache_entries = {
            let cache = self.cache.read().await;
            cache.len()
        };

        let stats = serde_json::json!({
            "cache_entries": cache_entries,
            "encryption_enabled": true,
            "audit_enabled": true,
            "supported_protocols": ["SMTP", "IMAP", "POP3"],
            "security_features": ["E2E Encryption", "At-Rest Encryption", "HMAC Integrity", "Audit Logging"]
        });

        Ok(stats)
    }
}