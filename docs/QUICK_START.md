# Quick Start Guide

This guide will get you up and running with the Sky Genesis Enterprise API Service in minutes.

## Prerequisites

- An API key from your organization administrator
- HTTP client (curl, Postman, or any programming language)
- Basic understanding of REST APIs

## 1. Authentication Setup

All API requests require authentication. You'll need an API key from your organization.

```bash
# Set your API key as an environment variable
export SKY_GENESIS_API_KEY="your-api-key-here"
```

## 2. Make Your First API Call

Let's test your API key by listing conversations in your organization.

```bash
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/your-org-id/conversations" \
  -H "X-API-Key: $SKY_GENESIS_API_KEY" \
  -H "Content-Type: application/json"
```

**Expected Response:**
```json
{
  "data": []
}
```

If you get an empty array, your API key is working! If you get an authentication error, contact your administrator.

## 3. Create Your First Conversation

Let's create a conversation to start messaging.

```bash
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/your-org-id/conversations" \
  -H "X-API-Key: $SKY_GENESIS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My First Conversation",
    "type": "group",
    "participant_ids": ["user-id-1", "user-id-2"]
  }'
```

**Response:**
```json
{
  "message": "Conversation created successfully",
  "data": {
    "id": "conversation-uuid",
    "title": "My First Conversation",
    "type": "group",
    "created_by": "your-api-key-id",
    "is_archived": false,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

## 4. Send Your First Message

Now let's send a message in the conversation we just created.

```bash
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/your-org-id/conversations/conversation-uuid/messages" \
  -H "X-API-Key: $SKY_GENESIS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Hello, World! This is my first message.",
    "message_type": "text"
  }'
```

**Response:**
```json
{
  "message": "Message sent successfully",
  "data": {
    "id": "message-uuid",
    "conversation_id": "conversation-uuid",
    "sender_id": "your-api-key-id",
    "content": "Hello, World! This is my first message.",
    "message_type": "text",
    "is_edited": false,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

## 5. Retrieve Messages

Let's retrieve the messages from our conversation.

```bash
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/your-org-id/conversations/conversation-uuid/messages" \
  -H "X-API-Key: $SKY_GENESIS_API_KEY"
```

**Response:**
```json
{
  "data": [
    {
      "message": {
        "id": "message-uuid",
        "conversation_id": "conversation-uuid",
        "sender_id": "your-api-key-id",
        "content": "Hello, World! This is my first message.",
        "message_type": "text",
        "is_edited": false,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
      },
      "sender_name": null,
      "attachments": null,
      "reactions": null,
      "read_by": null,
      "reply_to": null
    }
  ]
}
```

## 6. Add a Reaction

Let's add a reaction to our message.

```bash
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/your-org-id/messages/message-uuid/reactions" \
  -H "X-API-Key: $SKY_GENESIS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "reaction": "👍"
  }'
```

## 7. Search Messages

Let's search for messages containing specific text.

```bash
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/your-org-id/search/messages?q=Hello" \
  -H "X-API-Key: $SKY_GENESIS_API_KEY"
```

## Next Steps

Now that you have the basics working, explore more advanced features:

- **File Attachments**: Learn how to upload and manage file attachments
- **Participant Management**: Add and remove participants from conversations
- **Read Status**: Mark messages and conversations as read
- **Advanced Search**: Use filters and pagination for better results
- **Statistics**: Get unread message counts and conversation statistics

Check out the [API Reference](API_REFERENCE.md) for complete endpoint documentation and the [Examples](EXAMPLES.md) for code samples in your preferred language.