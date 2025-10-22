# API Reference

Complete reference for all Sky Genesis Enterprise API endpoints.

## Base URL

```
https://api.skygenesisenterprise.com/api/v1
```

## Authentication

All endpoints require authentication via API key. See [Authentication Guide](AUTHENTICATION.md) for details.

## Response Format

All responses follow this structure:

```json
{
  "data": { ... },
  "message": "Optional success message",
  "error": "Optional error message"
}
```

## Error Responses

Standard HTTP status codes are used:

- `200 OK`: Success
- `201 Created`: Resource created
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource conflict
- `500 Internal Server Error`: Server error

---

## Conversations

### List Organization Conversations

Get all conversations for an organization.

**Endpoint:** `GET /organizations/{organization_id}/conversations`

**Parameters:**
- `organization_id` (path): Organization UUID

**Response:**
```json
{
  "data": [
    {
      "conversation": {
        "id": "uuid",
        "organization_id": "uuid",
        "title": "Team Discussion",
        "type": "group",
        "created_by": "uuid",
        "is_archived": false,
        "last_message_at": "2024-01-01T00:00:00Z",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
      },
      "participants": [...],
      "last_message": {
        "id": "uuid",
        "content": "Hello everyone!",
        "sender_id": "uuid",
        "created_at": "2024-01-01T00:00:00Z",
        "sender_name": "John Doe"
      },
      "unread_count": 5
    }
  ]
}
```

### Create Conversation

Create a new conversation.

**Endpoint:** `POST /organizations/{organization_id}/conversations`

**Parameters:**
- `organization_id` (path): Organization UUID

**Request Body:**
```json
{
  "title": "Project Discussion",
  "type": "group",
  "participant_ids": ["uuid1", "uuid2"]
}
```

**Response:**
```json
{
  "message": "Conversation created successfully",
  "data": {
    "id": "uuid",
    "organization_id": "uuid",
    "title": "Project Discussion",
    "type": "group",
    "created_by": "uuid",
    "is_archived": false,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

### Get Conversation

Get a specific conversation by ID.

**Endpoint:** `GET /organizations/{organization_id}/conversations/{conversation_id}`

**Parameters:**
- `organization_id` (path): Organization UUID
- `conversation_id` (path): Conversation UUID

**Response:** Same as create conversation response.

### Delete Conversation

Archive a conversation (soft delete).

**Endpoint:** `DELETE /organizations/{organization_id}/conversations/{conversation_id}`

**Parameters:**
- `organization_id` (path): Organization UUID
- `conversation_id` (path): Conversation UUID

**Response:**
```json
{
  "message": "Conversation deleted successfully"
}
```

### Archive Conversation

Archive a conversation.

**Endpoint:** `POST /organizations/{organization_id}/conversations/{conversation_id}/archive`

**Parameters:**
- `organization_id` (path): Organization UUID
- `conversation_id` (path): Conversation UUID

**Response:**
```json
{
  "message": "Conversation archived successfully"
}
```

### Unarchive Conversation

Unarchive a conversation.

**Endpoint:** `POST /organizations/{organization_id}/conversations/{conversation_id}/unarchive`

**Parameters:**
- `organization_id` (path): Organization UUID
- `conversation_id` (path): Conversation UUID

**Response:**
```json
{
  "message": "Conversation unarchived successfully"
}
```

### Get Conversation Unread Count

Get the number of unread messages in a conversation.

**Endpoint:** `GET /organizations/{organization_id}/conversations/{conversation_id}/unread`

**Parameters:**
- `organization_id` (path): Organization UUID
- `conversation_id` (path): Conversation UUID

**Response:**
```json
{
  "data": {
    "unread_count": 3
  }
}
```

### Mark Conversation as Read

Mark all messages in a conversation as read.

**Endpoint:** `POST /organizations/{organization_id}/conversations/{conversation_id}/read`

**Parameters:**
- `organization_id` (path): Organization UUID
- `conversation_id` (path): Conversation UUID

**Response:**
```json
{
  "message": "Conversation marked as read"
}
```

---

## Messages

### List Conversation Messages

Get messages in a conversation with pagination.

**Endpoint:** `GET /organizations/{organization_id}/conversations/{conversation_id}/messages`

**Parameters:**
- `organization_id` (path): Organization UUID
- `conversation_id` (path): Conversation UUID
- `limit` (query, optional): Number of messages to return (default: 50, max: 100)
- `offset` (query, optional): Number of messages to skip (default: 0)

**Response:**
```json
{
  "data": [
    {
      "message": {
        "id": "uuid",
        "conversation_id": "uuid",
        "sender_id": "uuid",
        "content": "Hello world!",
        "message_type": "text",
        "reply_to_id": null,
        "is_edited": false,
        "edited_at": null,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
      },
      "sender_name": "John Doe",
      "attachments": [...],
      "reactions": [...],
      "read_by": [...],
      "reply_to": null
    }
  ]
}
```

### Send Message

Send a new message to a conversation.

**Endpoint:** `POST /organizations/{organization_id}/conversations/{conversation_id}/messages`

**Parameters:**
- `organization_id` (path): Organization UUID
- `conversation_id` (path): Conversation UUID

**Request Body:**
```json
{
  "content": "Hello everyone!",
  "message_type": "text",
  "reply_to_id": "uuid"
}
```

**Response:**
```json
{
  "message": "Message sent successfully",
  "data": {
    "id": "uuid",
    "conversation_id": "uuid",
    "sender_id": "uuid",
    "content": "Hello everyone!",
    "message_type": "text",
    "reply_to_id": "uuid",
    "is_edited": false,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

### Update Message

Edit an existing message.

**Endpoint:** `PUT /organizations/{organization_id}/messages/{message_id}`

**Parameters:**
- `organization_id` (path): Organization UUID
- `message_id` (path): Message UUID

**Request Body:**
```json
{
  "content": "Updated message content"
}
```

**Response:**
```json
{
  "message": "Message updated successfully",
  "data": { ... }
}
```

### Delete Message

Delete a message.

**Endpoint:** `DELETE /organizations/{organization_id}/messages/{message_id}`

**Parameters:**
- `organization_id` (path): Organization UUID
- `message_id` (path): Message UUID

**Response:**
```json
{
  "message": "Message deleted successfully"
}
```

### Mark Message as Read

Mark a specific message as read.

**Endpoint:** `POST /organizations/{organization_id}/messages/{message_id}/read`

**Parameters:**
- `organization_id` (path): Organization UUID
- `message_id` (path): Message UUID

**Response:**
```json
{
  "message": "Message marked as read",
  "data": { ... }
}
```

---

## Attachments

### List Message Attachments

Get all attachments for a message.

**Endpoint:** `GET /organizations/{organization_id}/messages/{message_id}/attachments`

**Parameters:**
- `organization_id` (path): Organization UUID
- `message_id` (path): Message UUID

**Response:**
```json
{
  "data": [
    {
      "id": "uuid",
      "message_id": "uuid",
      "filename": "document.pdf",
      "original_filename": "My Document.pdf",
      "mime_type": "application/pdf",
      "file_size": 1024000,
      "file_url": "https://files.sky-genesis.com/...",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### Add Attachment

Add a file attachment to a message.

**Endpoint:** `POST /organizations/{organization_id}/messages/{message_id}/attachments`

**Parameters:**
- `organization_id` (path): Organization UUID
- `message_id` (path): Message UUID

**Request Body:**
```json
{
  "filename": "document.pdf",
  "original_filename": "My Document.pdf",
  "mime_type": "application/pdf",
  "file_size": 1024000,
  "file_url": "https://files.sky-genesis.com/..."
}
```

**Response:**
```json
{
  "message": "Attachment added successfully",
  "data": { ... }
}
```

### Delete Attachment

Remove an attachment from a message.

**Endpoint:** `DELETE /organizations/{organization_id}/messages/{message_id}/attachments/{attachment_id}`

**Parameters:**
- `organization_id` (path): Organization UUID
- `message_id` (path): Message UUID
- `attachment_id` (path): Attachment UUID

**Response:**
```json
{
  "message": "Attachment deleted successfully"
}
```

---

## Participants

### List Conversation Participants

Get all participants in a conversation.

**Endpoint:** `GET /organizations/{organization_id}/conversations/{conversation_id}/participants`

**Parameters:**
- `organization_id` (path): Organization UUID
- `conversation_id` (path): Conversation UUID

**Response:**
```json
{
  "data": [
    {
      "id": "uuid",
      "conversation_id": "uuid",
      "user_id": "uuid",
      "role": "member",
      "joined_at": "2024-01-01T00:00:00Z",
      "last_read_at": "2024-01-01T00:00:00Z",
      "is_muted": false
    }
  ]
}
```

### Add Participant

Add a user to a conversation.

**Endpoint:** `POST /organizations/{organization_id}/conversations/{conversation_id}/participants`

**Parameters:**
- `organization_id` (path): Organization UUID
- `conversation_id` (path): Conversation UUID

**Request Body:**
```json
{
  "user_id": "uuid"
}
```

**Response:**
```json
{
  "message": "Participant added successfully",
  "data": { ... }
}
```

### Remove Participant

Remove a user from a conversation.

**Endpoint:** `DELETE /organizations/{organization_id}/conversations/{conversation_id}/participants/{user_id}`

**Parameters:**
- `organization_id` (path): Organization UUID
- `conversation_id` (path): Conversation UUID
- `user_id` (path): User UUID

**Response:**
```json
{
  "message": "Participant removed successfully"
}
```

---

## Reactions

### Add Reaction

Add a reaction to a message.

**Endpoint:** `POST /organizations/{organization_id}/messages/{message_id}/reactions`

**Parameters:**
- `organization_id` (path): Organization UUID
- `message_id` (path): Message UUID

**Request Body:**
```json
{
  "reaction": "👍"
}
```

**Response:**
```json
{
  "message": "Reaction added successfully",
  "data": {
    "id": "uuid",
    "message_id": "uuid",
    "user_id": "uuid",
    "reaction": "👍",
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

### Remove Reaction

Remove a reaction from a message.

**Endpoint:** `DELETE /organizations/{organization_id}/messages/{message_id}/reactions/{reaction}`

**Parameters:**
- `organization_id` (path): Organization UUID
- `message_id` (path): Message UUID
- `reaction` (path): Reaction emoji (URL encoded)

**Response:**
```json
{
  "message": "Reaction removed successfully"
}
```

---

## Search

### Search Messages

Search for messages containing specific text.

**Endpoint:** `GET /organizations/{organization_id}/search/messages`

**Parameters:**
- `organization_id` (path): Organization UUID
- `q` (query, required): Search query
- `limit` (query, optional): Number of results (default: 50)
- `offset` (query, optional): Number of results to skip (default: 0)

**Response:**
```json
{
  "data": [
    {
      "message": { ... },
      "sender_name": "John Doe",
      "attachments": [...],
      "reactions": [...],
      "read_by": [...],
      "reply_to": null
    }
  ]
}
```

---

## Statistics

### Get Unread Statistics

Get total unread message count for the organization.

**Endpoint:** `GET /organizations/{organization_id}/stats/unread`

**Parameters:**
- `organization_id` (path): Organization UUID

**Response:**
```json
{
  "data": {
    "unread_count": 15
  }
}
```

---

## Data Types

### Conversation Types
- `direct`: One-on-one conversation
- `group`: Multi-user conversation
- `channel`: Public channel conversation

### Message Types
- `text`: Plain text message
- `system`: System-generated message
- `file`: Message with file attachment

### User Roles
- `owner`: Conversation owner
- `admin`: Conversation administrator
- `member`: Regular member
- `guest`: Limited access member

### Pagination Parameters
- `limit`: Maximum number of items (1-100, default: 50)
- `offset`: Number of items to skip (default: 0)

### Date Format
All dates use ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ`