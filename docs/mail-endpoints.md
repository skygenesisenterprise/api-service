# Mail API Endpoints

## Base URL
All mail endpoints are served under `/api/v1/mail/`.

## Authentication
All endpoints require authentication via JWT tokens or API keys:
```
Authorization: Bearer <jwt_token>
X-API-Key: <api_key>
```

## Core Endpoints

### Mailbox Management

#### Get Mailbox List
- **GET** `/api/v1/mail/mailboxes`
- **Description**: Retrieve list of user mailboxes
- **Response**:
  ```json
  {
    "mailboxes": [
      {
        "id": "INBOX",
        "name": "INBOX",
        "specialUse": "inbox",
        "totalEmails": 150,
        "unreadEmails": 5
      },
      {
        "id": "Sent",
        "name": "Sent",
        "specialUse": "sent",
        "totalEmails": 89,
        "unreadEmails": 0
      }
    ]
  }
  ```

#### Get Mailbox Details
- **GET** `/api/v1/mail/mailboxes/{mailboxId}`
- **Description**: Get detailed information about a specific mailbox
- **Parameters**:
  - `mailboxId`: Mailbox identifier (URL-encoded)
- **Response**:
  ```json
  {
    "id": "INBOX",
    "name": "INBOX",
    "specialUse": "inbox",
    "totalEmails": 150,
    "unreadEmails": 5,
    "size": 1048576,
    "permissions": ["read", "write", "delete"]
  }
  ```

### Message Operations

#### List Messages
- **GET** `/api/v1/mail/messages`
- **Description**: Retrieve messages from a mailbox
- **Query Parameters**:
  - `mailbox`: Mailbox ID (required)
  - `limit`: Maximum messages to return (default: 50, max: 100)
  - `offset`: Pagination offset (default: 0)
  - `sort`: Sort order (`date_desc`, `date_asc`, `subject`)
  - `filter`: Filter criteria (`unread`, `flagged`, `has_attachment`)
- **Response**:
  ```json
  {
    "messages": [
      {
        "id": "msg_12345",
        "threadId": "thread_678",
        "mailboxId": "INBOX",
        "subject": "Meeting Tomorrow",
        "from": {"name": "John Doe", "email": "john@example.com"},
        "to": [{"name": "Jane Smith", "email": "jane@example.com"}],
        "date": "2024-01-15T10:30:00Z",
        "size": 24576,
        "isRead": false,
        "isFlagged": true,
        "hasAttachments": false,
        "preview": "Hi Jane, Just a reminder about..."
      }
    ],
    "total": 150,
    "hasMore": true
  }
  ```

#### Get Message
- **GET** `/api/v1/mail/messages/{messageId}`
- **Description**: Retrieve full message content
- **Parameters**:
  - `messageId`: Message identifier
- **Query Parameters**:
  - `include`: Include options (`body`, `attachments`, `headers`)
- **Response**:
  ```json
  {
    "id": "msg_12345",
    "subject": "Meeting Tomorrow",
    "from": {"name": "John Doe", "email": "john@example.com"},
    "to": [{"name": "Jane Smith", "email": "jane@example.com"}],
    "cc": [],
    "bcc": [],
    "date": "2024-01-15T10:30:00Z",
    "headers": {
      "Message-ID": "<msg_12345@example.com>",
      "Content-Type": "text/plain; charset=UTF-8"
    },
    "body": {
      "text": "Hi Jane,\n\nJust a reminder about our meeting tomorrow at 2 PM.\n\nBest,\nJohn",
      "html": "<p>Hi Jane,</p><p>Just a reminder about our meeting tomorrow at 2 PM.</p><p>Best,<br>John</p>"
    },
    "attachments": [],
    "isRead": false,
    "isFlagged": true
  }
  ```

#### Send Message
- **POST** `/api/v1/mail/messages`
- **Description**: Send a new email message
- **Body**:
  ```json
  {
    "to": [
      {"name": "Jane Smith", "email": "jane@example.com"}
    ],
    "cc": [],
    "bcc": [],
    "subject": "Meeting Tomorrow",
    "body": {
      "text": "Hi Jane,\n\nJust a reminder about our meeting tomorrow at 2 PM.\n\nBest,\nJohn",
      "html": "<p>Hi Jane,</p><p>Just a reminder about our meeting tomorrow at 2 PM.</p><p>Best,<br>John</p>"
    },
    "attachments": [
      {
        "filename": "agenda.pdf",
        "contentType": "application/pdf",
        "size": 245760,
        "data": "base64-encoded-content"
      }
    ],
    "priority": "normal",
    "requestReadReceipt": false
  }
  ```
- **Response**:
  ```json
  {
    "messageId": "msg_12346",
    "status": "sent",
    "timestamp": "2024-01-15T10:30:15Z"
  }
  ```

## Contextual Email Sending

### Overview

The API provides specialized routes for sending contextual emails with predefined configurations, templates, and security policies. This enables applications to send emails through dedicated channels for different purposes.

### Supported Contexts

- **`no-reply`**: Automated system emails (password resets, notifications)
- **`security`**: Security-related communications (2FA codes, alerts)
- **`support`**: Customer support communications
- **`marketing`**: Marketing and promotional emails
- **`billing`**: Billing and payment-related emails
- **`legal`**: Legal and compliance communications

### Send Contextual Email

#### Basic Contextual Send
- **POST** `/api/v1/mail/send/{context}`
- **Description**: Send an email through a specific contextual route
- **Parameters**:
  - `context`: Email context (`no-reply`, `security`, `support`, `marketing`, `billing`, `legal`)
- **Body**:
  ```json
  {
    "to": [
      {"name": "John Doe", "email": "john@example.com"}
    ],
    "template": "welcome",
    "templateData": {
      "userName": "John Doe",
      "activationLink": "https://app.example.com/activate/12345",
      "companyName": "Sky Genesis"
    },
    "priority": "normal",
    "attachments": []
  }
  ```
- **Response**:
  ```json
  {
    "messageId": "msg_ctx_12346",
    "context": "no-reply",
    "status": "sent",
    "timestamp": "2024-01-15T10:30:15Z",
    "from": "no-reply@skygenesisenterprise.com"
  }
  ```

#### Template-Based Send
- **POST** `/api/v1/mail/send/{context}/template/{templateId}`
- **Description**: Send an email using a predefined template
- **Parameters**:
  - `context`: Email context
  - `templateId`: Template identifier
- **Body**:
  ```json
  {
    "to": ["user@example.com"],
    "data": {
      "userName": "John",
      "resetToken": "abc123",
      "expiryHours": 24
    },
    "locale": "en-US"
  }
  ```

#### Bulk Contextual Send
- **POST** `/api/v1/mail/send/{context}/bulk`
- **Description**: Send emails to multiple recipients through contextual route
- **Body**:
  ```json
  {
    "recipients": [
      {
        "to": ["user1@example.com"],
        "templateData": {"name": "User 1"},
        "locale": "en-US"
      },
      {
        "to": ["user2@example.com"],
        "templateData": {"name": "User 2"},
        "locale": "fr-FR"
      }
    ],
    "template": "newsletter",
    "batchId": "campaign_2024_001"
  }
  ```
- **Response**:
  ```json
  {
    "batchId": "campaign_2024_001",
    "totalRecipients": 2,
    "messages": [
      {"messageId": "msg_001", "status": "sent", "recipient": "user1@example.com"},
      {"messageId": "msg_002", "status": "sent", "recipient": "user2@example.com"}
    ],
    "timestamp": "2024-01-15T10:30:15Z"
  }
  ```

### Context-Specific Features

#### No-Reply Context
- **From Address**: `no-reply@skygenesisenterprise.com`
- **Purpose**: System notifications, password resets, account activations
- **Templates**: `password-reset`, `email-verification`, `welcome`, `notification`
- **Rate Limits**: 100 emails/minute per application
- **Security**: No replies accepted, DKIM/SPF configured

#### Security Context
- **From Address**: `security@skygenesisenterprise.com`
- **Purpose**: Security alerts, 2FA codes, login notifications
- **Templates**: `login-alert`, `2fa-code`, `password-changed`, `suspicious-activity`
- **Rate Limits**: 50 emails/minute per user
- **Security**: Encrypted delivery, audit logging, high priority

#### Support Context
- **From Address**: `support@skygenesisenterprise.com`
- **Purpose**: Customer support communications
- **Templates**: `ticket-created`, `ticket-updated`, `support-response`
- **Rate Limits**: 20 emails/minute per application
- **Features**: Reply-to handling, ticket integration

#### Marketing Context
- **From Address**: `news@skygenesisenterprise.com`
- **Purpose**: Marketing campaigns, newsletters, promotions
- **Templates**: `newsletter`, `promotion`, `product-update`
- **Rate Limits**: 1000 emails/hour per application
- **Features**: Unsubscribe handling, analytics tracking

#### Billing Context
- **From Address**: `billing@skygenesisenterprise.com`
- **Purpose**: Invoices, payment confirmations, billing alerts
- **Templates**: `invoice`, `payment-receipt`, `billing-alert`
- **Rate Limits**: 100 emails/minute per application
- **Security**: PCI compliance, encrypted attachments

#### Legal Context
- **From Address**: `legal@skygenesisenterprise.com`
- **Purpose**: Legal notices, terms updates, compliance communications
- **Templates**: `terms-update`, `privacy-notice`, `legal-alert`
- **Rate Limits**: 10 emails/minute per application
- **Security**: Legal hold capabilities, audit trails

### Template Management

#### List Available Templates
- **GET** `/api/v1/mail/templates/{context}`
- **Description**: Get available templates for a context
- **Response**:
  ```json
  {
    "context": "no-reply",
    "templates": [
      {
        "id": "welcome",
        "name": "Welcome Email",
        "description": "New user welcome message",
        "variables": ["userName", "activationLink", "companyName"],
        "locales": ["en-US", "fr-FR", "es-ES"]
      }
    ]
  }
  ```

#### Get Template Details
- **GET** `/api/v1/mail/templates/{context}/{templateId}`
- **Description**: Get template details and preview
- **Response**:
  ```json
  {
    "id": "welcome",
    "subject": "Welcome to {{companyName}}!",
    "body": {
      "text": "Hi {{userName}},\n\nWelcome to {{companyName}}! Please activate your account: {{activationLink}}",
      "html": "<p>Hi {{userName}},</p><p>Welcome to {{companyName}}! Please <a href=\"{{activationLink}}\">activate your account</a>.</p>"
    },
    "variables": ["userName", "activationLink", "companyName"]
  }
  ```

### Email Analytics

#### Get Context Statistics
- **GET** `/api/v1/mail/stats/{context}`
- **Description**: Get sending statistics for a context
- **Query Parameters**:
  - `period`: Time period (`hour`, `day`, `week`, `month`)
- **Response**:
  ```json
  {
    "context": "no-reply",
    "period": "day",
    "stats": {
      "sent": 1250,
      "delivered": 1220,
      "opened": 340,
      "clicked": 85,
      "bounced": 15,
      "complained": 2
    }
  }
  ```

#### Get Batch Status
- **GET** `/api/v1/mail/batch/{batchId}`
- **Description**: Get status of a bulk email batch
- **Response**:
  ```json
  {
    "batchId": "campaign_2024_001",
    "status": "completed",
    "total": 1000,
    "sent": 980,
    "failed": 20,
    "progress": 100.0
  }
  ```

#### Update Message
- **PATCH** `/api/v1/mail/messages/{messageId}`
- **Description**: Update message flags or move between mailboxes
- **Body**:
  ```json
  {
    "isRead": true,
    "isFlagged": false,
    "mailboxId": "Archive"
  }
  ```
- **Response**: `200 OK`

#### Delete Message
- **DELETE** `/api/v1/mail/messages/{messageId}`
- **Description**: Delete a message (move to trash or permanent delete)
- **Query Parameters**:
  - `permanent`: If true, permanently delete (default: false)
- **Response**: `204 No Content`

### Attachment Operations

#### Get Attachment
- **GET** `/api/v1/mail/messages/{messageId}/attachments/{attachmentId}`
- **Description**: Download message attachment
- **Response**: Binary file content with appropriate headers

#### Upload Attachment
- **POST** `/api/v1/mail/attachments`
- **Description**: Upload attachment for future use in messages
- **Content-Type**: `multipart/form-data`
- **Response**:
  ```json
  {
    "attachmentId": "att_789",
    "filename": "document.pdf",
    "contentType": "application/pdf",
    "size": 245760,
    "url": "/api/v1/mail/attachments/att_789"
  }
  ```

### Search Operations

#### Search Messages
- **GET** `/api/v1/mail/search`
- **Description**: Full-text search across messages
- **Query Parameters**:
  - `query`: Search query (required)
  - `mailbox`: Limit to specific mailbox
  - `from`: Sender email
  - `to`: Recipient email
  - `subject`: Subject contains
  - `dateFrom`: Start date (ISO 8601)
  - `dateTo`: End date (ISO 8601)
  - `hasAttachment`: Filter by attachment presence
- **Response**: Same as List Messages

### Thread Operations

#### Get Thread
- **GET** `/api/v1/mail/threads/{threadId}`
- **Description**: Get all messages in a conversation thread
- **Response**:
  ```json
  {
    "threadId": "thread_678",
    "subject": "Meeting Tomorrow",
    "participants": [
      {"name": "John Doe", "email": "john@example.com"},
      {"name": "Jane Smith", "email": "jane@example.com"}
    ],
    "messages": [
      {
        "id": "msg_12345",
        "subject": "Meeting Tomorrow",
        "from": {"name": "John Doe", "email": "john@example.com"},
        "date": "2024-01-15T10:30:00Z",
        "isRead": true
      },
      {
        "id": "msg_12347",
        "subject": "Re: Meeting Tomorrow",
        "from": {"name": "Jane Smith", "email": "jane@example.com"},
        "date": "2024-01-15T11:00:00Z",
        "isRead": false
      }
    ]
  }
  ```

### Draft Operations

#### Save Draft
- **POST** `/api/v1/mail/drafts`
- **Description**: Save a draft message
- **Body**: Same as Send Message
- **Response**:
  ```json
  {
    "draftId": "draft_101",
    "messageId": "msg_draft_101"
  }
  ```

#### Update Draft
- **PUT** `/api/v1/mail/drafts/{draftId}`
- **Description**: Update an existing draft
- **Body**: Same as Send Message

#### Send Draft
- **POST** `/api/v1/mail/drafts/{draftId}/send`
- **Description**: Send a draft message
- **Response**: Same as Send Message

## Error Responses

All endpoints may return standard HTTP error codes:

- **400 Bad Request**: Invalid request parameters
- **401 Unauthorized**: Missing or invalid authentication
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error

Error response format:
```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "The request parameters are invalid",
    "details": {
      "field": "mailbox",
      "issue": "Mailbox ID is required"
    }
  }
}
```

## Rate Limiting

Mail endpoints implement rate limiting:
- **Read operations**: 100 requests/minute per user
- **Send operations**: 50 messages/hour per user
- **Search operations**: 30 searches/minute per user

## Content Limits

- **Message size**: 25MB maximum
- **Attachment size**: 10MB per attachment
- **Attachments per message**: 20 maximum
- **Recipients per message**: 100 maximum

## Pagination

List operations support pagination:
- `limit`: Items per page (1-100, default 50)
- `offset`: Starting position (default 0)
- Response includes `total` and `hasMore` fields

## Real-time Updates

The API supports real-time updates via WebSocket:
- **WebSocket URL**: `ws://api.skygenesisenterprise.com/api/v1/mail/events`
- **Events**: `message:new`, `message:updated`, `mailbox:updated`

## Versioning

All endpoints are versioned under `/api/v1/mail/`. Future versions will use `/api/v2/mail/`.