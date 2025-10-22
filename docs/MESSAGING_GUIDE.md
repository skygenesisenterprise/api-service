# Messaging API Guide

Complete guide to using the Sky Genesis Enterprise messaging features.

## Overview

The messaging API provides a comprehensive set of features for building modern chat applications, including real-time messaging, file sharing, reactions, and advanced search capabilities.

## Core Concepts

### Conversations
Conversations are the primary containers for messages. They can be:
- **Direct**: One-on-one conversations
- **Group**: Multi-user conversations
- **Channel**: Public channels for team communication

### Messages
Messages are the core communication units containing:
- Text content
- File attachments
- Reactions and interactions
- Read status tracking
- Threaded replies

### Participants
Users who are members of conversations with different roles:
- **Owner**: Full control over the conversation
- **Admin**: Administrative privileges
- **Member**: Standard participant
- **Guest**: Limited access

## Working with Conversations

### Creating Conversations

```bash
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Project Alpha",
    "type": "group",
    "participant_ids": ["user-1", "user-2", "user-3"]
  }'
```

**Important Notes:**
- The API key used to create the conversation becomes the creator
- All participant IDs must be valid users in the organization
- At least one participant is required (creator is automatically added)

### Managing Conversation Lifecycle

```bash
# Archive a conversation
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations/{conv_id}/archive" \
  -H "X-API-Key: $API_KEY"

# Unarchive a conversation
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations/{conv_id}/unarchive" \
  -H "X-API-Key: $API_KEY"

# Delete a conversation (archive)
curl -X DELETE "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations/{conv_id}" \
  -H "X-API-Key: $API_KEY"
```

### Listing Conversations

```bash
# Get all conversations
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations" \
  -H "X-API-Key: $API_KEY"
```

The response includes:
- Conversation metadata
- Last message preview
- Unread message count
- Participant information

## Sending and Managing Messages

### Basic Message Sending

```bash
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations/{conv_id}/messages" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Hello team! How is the project progressing?",
    "message_type": "text"
  }'
```

### Message Types

- **text**: Regular text messages
- **system**: System-generated notifications
- **file**: Messages with file attachments

### Replying to Messages

```bash
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations/{conv_id}/messages" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "I agree with this approach",
    "message_type": "text",
    "reply_to_id": "original-message-id"
  }'
```

### Editing Messages

```bash
curl -X PUT "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/messages/{message_id}" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Updated: Hello team! How is the project progressing? Any blockers?"
  }'
```

**Note:** Only the original sender can edit messages.

### Deleting Messages

```bash
curl -X DELETE "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/messages/{message_id}" \
  -H "X-API-Key: $API_KEY"
```

**Note:** Only the original sender can delete messages.

## File Attachments

### Adding Attachments

```bash
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/messages/{message_id}/attachments" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "design-spec.pdf",
    "original_filename": "Project Design Specification.pdf",
    "mime_type": "application/pdf",
    "file_size": 2048000,
    "file_url": "https://files.example.com/uploads/design-spec.pdf"
  }'
```

### Listing Attachments

```bash
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/messages/{message_id}/attachments" \
  -H "X-API-Key: $API_KEY"
```

### Managing Attachments

```bash
# Remove an attachment
curl -X DELETE "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/messages/{message_id}/attachments/{attachment_id}" \
  -H "X-API-Key: $API_KEY"
```

## Reactions and Interactions

### Adding Reactions

```bash
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/messages/{message_id}/reactions" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "reaction": "👍"
  }'
```

### Removing Reactions

```bash
# URL encode the emoji if needed
curl -X DELETE "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/messages/{message_id}/reactions/%F0%9F%91%8D" \
  -H "X-API-Key: $API_KEY"
```

## Read Status Management

### Marking Messages as Read

```bash
# Mark a specific message as read
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/messages/{message_id}/read" \
  -H "X-API-Key: $API_KEY"

# Mark entire conversation as read
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations/{conv_id}/read" \
  -H "X-API-Key: $API_KEY"
```

### Checking Read Status

```bash
# Get unread count for a conversation
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations/{conv_id}/unread" \
  -H "X-API-Key: $API_KEY"

# Get total unread count for organization
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/stats/unread" \
  -H "X-API-Key: $API_KEY"
```

## Participant Management

### Adding Participants

```bash
curl -X POST "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations/{conv_id}/participants" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "new-user-id"
  }'
```

### Listing Participants

```bash
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations/{conv_id}/participants" \
  -H "X-API-Key: $API_KEY"
```

### Removing Participants

```bash
curl -X DELETE "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations/{conv_id}/participants/{user_id}" \
  -H "X-API-Key: $API_KEY"
```

## Search and Discovery

### Searching Messages

```bash
# Basic search
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/search/messages?q=project&limit=20" \
  -H "X-API-Key: $API_KEY"

# Search with pagination
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/search/messages?q=meeting&limit=10&offset=20" \
  -H "X-API-Key: $API_KEY"
```

**Search Features:**
- Full-text search across message content
- Case-insensitive matching
- Pagination support
- Results ordered by relevance and date

## Pagination

Most list endpoints support pagination:

```bash
# Get messages with pagination
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations/{conv_id}/messages?limit=25&offset=50" \
  -H "X-API-Key: $API_KEY"
```

**Pagination Parameters:**
- `limit`: Number of items per page (1-100, default: 50)
- `offset`: Number of items to skip (default: 0)

## Real-time Considerations

While the API itself is REST-based, here are best practices for real-time messaging:

### Polling Strategy

```javascript
async function pollMessages(conversationId, lastMessageId) {
  const response = await fetch(`/api/v1/organizations/${orgId}/conversations/${conversationId}/messages?limit=50`);

  if (response.ok) {
    const data = await response.json();
    const newMessages = data.data.filter(msg => msg.id > lastMessageId);

    if (newMessages.length > 0) {
      // Handle new messages
      updateUI(newMessages);
    }
  }
}

// Poll every 5 seconds
setInterval(() => pollMessages(currentConversationId, lastMessageId), 5000);
```

### WebSocket Integration (Future)

The API is designed to work with WebSocket connections for real-time updates:

```javascript
// Future WebSocket integration
const ws = new WebSocket('wss://api.skygenesisenterprise.com/ws');

ws.onmessage = (event) => {
  const update = JSON.parse(event.data);

  if (update.type === 'new_message') {
    addMessageToUI(update.message);
  }
};
```

## Error Handling

### Common Error Scenarios

```javascript
async function sendMessage(content) {
  try {
    const response = await fetch('/api/v1/organizations/{org_id}/conversations/{conv_id}/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': apiKey
      },
      body: JSON.stringify({ content, message_type: 'text' })
    });

    if (!response.ok) {
      const error = await response.json();

      switch (response.status) {
        case 401:
          throw new Error('Authentication required');
        case 403:
          throw new Error('Access denied to this conversation');
        case 404:
          throw new Error('Conversation not found');
        default:
          throw new Error(error.error || 'Unknown error');
      }
    }

    return await response.json();
  } catch (error) {
    console.error('Failed to send message:', error);
    // Handle error in UI
  }
}
```

## Best Practices

### 1. Efficient Polling

```javascript
// Use exponential backoff for polling
let pollInterval = 5000; // Start with 5 seconds

function pollWithBackoff() {
  pollMessages().then(success => {
    if (success) {
      pollInterval = Math.max(1000, pollInterval / 2); // Speed up on success
    } else {
      pollInterval = Math.min(30000, pollInterval * 1.5); // Slow down on failure
    }
  });

  setTimeout(pollWithBackoff, pollInterval);
}
```

### 2. Message Caching

```javascript
// Cache messages locally
const messageCache = new Map();

function getCachedMessages(conversationId) {
  if (messageCache.has(conversationId)) {
    return messageCache.get(conversationId);
  }

  return fetchMessages(conversationId).then(messages => {
    messageCache.set(conversationId, messages);
    return messages;
  });
}
```

### 3. Optimistic Updates

```javascript
function sendMessageOptimistically(content) {
  // Add message to UI immediately
  const tempMessage = {
    id: 'temp-' + Date.now(),
    content,
    sending: true
  };
  addMessageToUI(tempMessage);

  // Send to server
  sendMessage(content).then(response => {
    // Replace temp message with real one
    updateMessageInUI(tempMessage.id, response.data);
  }).catch(error => {
    // Remove temp message and show error
    removeMessageFromUI(tempMessage.id);
    showError('Failed to send message');
  });
}
```

### 4. Connection Handling

```javascript
function handleNetworkErrors() {
  window.addEventListener('online', () => {
    // Retry failed requests
    retryFailedRequests();
  });

  window.addEventListener('offline', () => {
    // Show offline indicator
    showOfflineIndicator();
  });
}
```

## Rate Limiting

Be aware of API rate limits:

- **Requests per minute**: Varies by plan
- **Concurrent connections**: Limited per API key
- **File uploads**: Size and frequency limits

Monitor response headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## Migration from Other Platforms

### From Slack

```javascript
// Slack-like message sending
async function sendSlackStyleMessage(channel, text, threadTs = null) {
  const payload = {
    content: text,
    message_type: 'text'
  };

  if (threadTs) {
    // Find message by timestamp and set reply_to_id
    const threadMessage = await findMessageByTimestamp(channel, threadTs);
    payload.reply_to_id = threadMessage.id;
  }

  return await sendMessage(channel, payload);
}
```

### From Discord

```javascript
// Discord-like reactions
async function addReaction(messageId, emoji) {
  return await fetch(`/api/v1/messages/${messageId}/reactions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reaction: emoji })
  });
}
```

This comprehensive messaging API provides all the building blocks needed for modern chat applications while maintaining simplicity and reliability.