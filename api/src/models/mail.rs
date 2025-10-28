// Mail Models - Data structures for mail operations
// This is a design specification file

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// Core mail entities

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mailbox {
    pub id: String,
    pub name: String,
    pub special_use: Option<SpecialUse>,
    pub total_emails: u32,
    pub unread_emails: u32,
    pub size: u64,
    pub permissions: Vec<MailboxPermission>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpecialUse {
    #[serde(rename = "inbox")]
    Inbox,
    #[serde(rename = "sent")]
    Sent,
    #[serde(rename = "drafts")]
    Drafts,
    #[serde(rename = "trash")]
    Trash,
    #[serde(rename = "archive")]
    Archive,
    #[serde(rename = "junk")]
    Junk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MailboxPermission {
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "write")]
    Write,
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "admin")]
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub thread_id: Option<String>,
    pub mailbox_id: String,
    pub subject: String,
    pub from: Vec<EmailAddress>,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
    pub date: DateTime<Utc>,
    pub size: u64,
    pub is_read: bool,
    pub is_flagged: bool,
    pub has_attachments: bool,
    pub preview: Option<String>,
    pub body: Option<MessageBody>,
    pub attachments: Vec<Attachment>,
    pub headers: std::collections::HashMap<String, String>,
    pub priority: MessagePriority,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAddress {
    pub name: Option<String>,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageBody {
    pub text: Option<String>,
    pub html: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePriority {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "normal")]
    Normal,
    #[serde(rename = "high")]
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub disposition: AttachmentDisposition,
    pub cid: Option<String>, // Content-ID for inline attachments
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttachmentDisposition {
    #[serde(rename = "attachment")]
    Attachment,
    #[serde(rename = "inline")]
    Inline,
}

// Request/Response types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub to: Vec<String>,
    pub cc: Option<Vec<String>>,
    pub bcc: Option<Vec<String>>,
    pub subject: String,
    pub body: MessageBody,
    pub attachments: Option<Vec<String>>, // Attachment IDs
    pub priority: Option<String>,
    pub request_read_receipt: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageResponse {
    pub message_id: String,
    pub status: SendStatus,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SendStatus {
    #[serde(rename = "sent")]
    Sent,
    #[serde(rename = "queued")]
    Queued,
    #[serde(rename = "failed")]
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageUpdateRequest {
    pub is_read: Option<bool>,
    pub is_flagged: Option<bool>,
    pub mailbox_id: Option<String>,
    pub labels: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRequest {
    pub query: String,
    pub mailbox: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub has_attachment: Option<bool>,
    pub is_read: Option<bool>,
    pub is_flagged: Option<bool>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub messages: Vec<Message>,
    pub total: usize,
    pub has_more: bool,
    pub query_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thread {
    pub id: String,
    pub subject: String,
    pub participants: Vec<EmailAddress>,
    pub messages: Vec<ThreadMessage>,
    pub total_messages: u32,
    pub unread_count: u32,
    pub last_activity: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadMessage {
    pub id: String,
    pub subject: String,
    pub from: EmailAddress,
    pub date: DateTime<Utc>,
    pub is_read: bool,
    pub has_attachments: bool,
    pub size: u64,
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftRequest {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: MessageBody,
    pub attachments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftResponse {
    pub draft_id: String,
    pub message_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentUploadRequest {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentUploadResponse {
    pub attachment_id: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

// Query types

#[derive(Debug, Clone)]
pub struct MailboxQuery {
    pub filter: Option<MailboxFilter>,
    pub sort: Option<MailboxSort>,
}

#[derive(Debug, Clone)]
pub enum MailboxFilter {
    SpecialUse(SpecialUse),
    Name(String),
    HasUnread(bool),
}

#[derive(Debug, Clone)]
pub enum MailboxSort {
    NameAsc,
    NameDesc,
    TotalEmailsDesc,
    UnreadEmailsDesc,
}

#[derive(Debug, Clone)]
pub struct MessageQuery {
    pub mailbox: Option<String>,
    pub limit: usize,
    pub offset: usize,
    pub sort: MessageSort,
    pub filter: Option<MessageFilter>,
}

#[derive(Debug, Clone)]
pub enum MessageSort {
    DateDesc,
    DateAsc,
    SubjectAsc,
    SubjectDesc,
    SizeDesc,
    SizeAsc,
}

#[derive(Debug, Clone)]
pub enum MessageFilter {
    Unread,
    Flagged,
    HasAttachment,
    From(String),
    To(String),
    Subject(String),
    DateRange(DateRange),
}

#[derive(Debug, Clone)]
pub struct DateRange {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SearchQuery {
    pub query: String,
    pub mailbox: Option<String>,
    pub date_range: Option<DateRange>,
    pub has_attachment: Option<bool>,
    pub is_read: Option<bool>,
    pub is_flagged: Option<bool>,
    pub limit: usize,
    pub offset: usize,
}

// Update types

#[derive(Debug, Clone)]
pub struct MessageUpdate {
    pub is_read: Option<bool>,
    pub is_flagged: Option<bool>,
    pub mailbox_id: Option<String>,
    pub labels: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct MailboxUpdate {
    pub name: Option<String>,
    pub permissions: Option<Vec<MailboxPermission>>,
}

// Statistics and metadata

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailStats {
    pub total_mailboxes: u32,
    pub total_messages: u64,
    pub total_size: u64,
    pub unread_messages: u32,
    pub todays_messages: u32,
    pub attachments_count: u64,
    pub attachments_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxStats {
    pub mailbox_id: String,
    pub total_messages: u32,
    pub unread_messages: u32,
    pub total_size: u64,
    pub oldest_message: Option<DateTime<Utc>>,
    pub newest_message: Option<DateTime<Utc>>,
}

// Error types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl MailError {
    pub fn new(code: &str, message: &str) -> Self {
        MailError {
            code: code.to_string(),
            message: message.to_string(),
            details: None,
        }
    }

    pub fn with_details(code: &str, message: &str, details: serde_json::Value) -> Self {
        MailError {
            code: code.to_string(),
            message: message.to_string(),
            details: Some(details),
        }
    }
}

// Common error codes
impl MailError {
    pub fn mailbox_not_found() -> Self {
        MailError::new("MAILBOX_NOT_FOUND", "Mailbox not found")
    }

    pub fn message_not_found() -> Self {
        MailError::new("MESSAGE_NOT_FOUND", "Message not found")
    }

    pub fn permission_denied() -> Self {
        MailError::new("PERMISSION_DENIED", "Insufficient permissions")
    }

    pub fn quota_exceeded() -> Self {
        MailError::new("QUOTA_EXCEEDED", "Mailbox quota exceeded")
    }

    pub fn invalid_request() -> Self {
        MailError::new("INVALID_REQUEST", "Invalid request parameters")
    }

    pub fn rate_limit_exceeded() -> Self {
        MailError::new("RATE_LIMIT_EXCEEDED", "Rate limit exceeded")
    }
}

// Pagination metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMeta {
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    pub has_more: bool,
}

// Sorting options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortDirection {
    #[serde(rename = "asc")]
    Ascending,
    #[serde(rename = "desc")]
    Descending,
}

// Validation helpers
pub trait Validate {
    fn validate(&self) -> Result<(), MailError>;
}

impl Validate for SendMessageRequest {
    fn validate(&self) -> Result<(), MailError> {
        if self.to.is_empty() {
            return Err(MailError::invalid_request());
        }

        if self.subject.trim().is_empty() {
            return Err(MailError::new("INVALID_SUBJECT", "Subject cannot be empty"));
        }

        // Validate email addresses
        for email in &self.to {
            if !is_valid_email(email) {
                return Err(MailError::new("INVALID_EMAIL", &format!("Invalid email: {}", email)));
            }
        }

        Ok(())
    }
}

impl Validate for SearchRequest {
    fn validate(&self) -> Result<(), MailError> {
        if self.query.trim().is_empty() {
            return Err(MailError::new("EMPTY_QUERY", "Search query cannot be empty"));
        }

        if let (Some(from), Some(to)) = (self.date_from, self.date_to) {
            if from > to {
                return Err(MailError::new("INVALID_DATE_RANGE", "Date from cannot be after date to"));
            }
        }

        Ok(())
    }
}

// Utility functions
fn is_valid_email(email: &str) -> bool {
    // Basic email validation
    email.contains('@') && email.split('@').count() == 2
}

// Contextual email types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmailContext {
    #[serde(rename = "no-reply")]
    NoReply,
    #[serde(rename = "security")]
    Security,
    #[serde(rename = "support")]
    Support,
    #[serde(rename = "marketing")]
    Marketing,
    #[serde(rename = "billing")]
    Billing,
    #[serde(rename = "legal")]
    Legal,
}

impl EmailContext {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "no-reply" => Some(EmailContext::NoReply),
            "security" => Some(EmailContext::Security),
            "support" => Some(EmailContext::Support),
            "marketing" => Some(EmailContext::Marketing),
            "billing" => Some(EmailContext::Billing),
            "legal" => Some(EmailContext::Legal),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            EmailContext::NoReply => "no-reply",
            EmailContext::Security => "security",
            EmailContext::Support => "support",
            EmailContext::Marketing => "marketing",
            EmailContext::Billing => "billing",
            EmailContext::Legal => "legal",
        }
    }

    pub fn get_from_address(&self) -> &'static str {
        match self {
            EmailContext::NoReply => "no-reply@skygenesisenterprise.com",
            EmailContext::Security => "security@skygenesisenterprise.com",
            EmailContext::Support => "support@skygenesisenterprise.com",
            EmailContext::Marketing => "news@skygenesisenterprise.com",
            EmailContext::Billing => "billing@skygenesisenterprise.com",
            EmailContext::Legal => "legal@skygenesisenterprise.com",
        }
    }

    pub fn get_rate_limit(&self) -> u32 {
        match self {
            EmailContext::NoReply => 100, // emails per minute
            EmailContext::Security => 50,
            EmailContext::Support => 20,
            EmailContext::Marketing => 1000, // per hour
            EmailContext::Billing => 100,
            EmailContext::Legal => 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextualSendRequest {
    pub to: Vec<String>,
    pub template: Option<String>,
    pub template_data: Option<serde_json::Value>,
    pub subject: Option<String>,
    pub body: Option<MessageBody>,
    pub priority: Option<String>,
    pub attachments: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextualSendResponse {
    pub message_id: String,
    pub context: String,
    pub status: SendStatus,
    pub timestamp: DateTime<Utc>,
    pub from: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkContextualSendRequest {
    pub recipients: Vec<BulkRecipient>,
    pub template: String,
    pub batch_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRecipient {
    pub to: Vec<String>,
    pub template_data: serde_json::Value,
    pub locale: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkSendResponse {
    pub batch_id: String,
    pub total_recipients: usize,
    pub messages: Vec<BulkMessageResult>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkMessageResult {
    pub message_id: String,
    pub status: SendStatus,
    pub recipient: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailTemplate {
    pub id: String,
    pub context: EmailContext,
    pub name: String,
    pub description: String,
    pub subject: String,
    pub body: TemplateBody,
    pub variables: Vec<String>,
    pub locales: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateBody {
    pub text: String,
    pub html: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateListResponse {
    pub context: String,
    pub templates: Vec<EmailTemplate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextStats {
    pub context: String,
    pub period: String,
    pub stats: EmailStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailStats {
    pub sent: u64,
    pub delivered: u64,
    pub opened: u64,
    pub clicked: u64,
    pub bounced: u64,
    pub complained: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchStatus {
    pub batch_id: String,
    pub status: BatchStatusType,
    pub total: usize,
    pub sent: usize,
    pub failed: usize,
    pub progress: f64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BatchStatusType {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "processing")]
    Processing,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
}

// Type aliases for convenience
pub type SendRequest = SendMessageRequest;
pub type SendResult = SendMessageResponse;
pub type SearchResult = SearchResponse;