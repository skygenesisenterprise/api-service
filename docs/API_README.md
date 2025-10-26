# Sky Genesis Enterprise API - Messaging Service

This API provides a comprehensive messaging service for organizations, secured with API key authentication.

## Authentication

All API requests must include a valid API key. API keys can be provided in one of the following ways:

1. **X-API-Key header**: `X-API-Key: your-api-key-here`
2. **Authorization header**: `Authorization: Bearer your-api-key-here`
3. **Query parameter**: `?api_key=your-api-key-here`

### API Key Permissions

API keys can have the following permissions:
- `read`: Read access to conversations and messages
- `write`: Write access to create/modify conversations and messages
- `admin`: Administrative access including API key management
- `*`: Full access to all permissions

## API Endpoints

### API Key Management

#### Create API Key
```http
POST /api/v1/organizations/{organization_id}/api-keys
Authorization: Bearer your-api-key
Content-Type: application/json

{
  "label": "My API Key",
  "permissions": ["read", "write"]
}
```

#### List API Keys
```http
GET /api/v1/organizations/{organization_id}/api-keys
Authorization: Bearer your-api-key
```

#### Revoke API Key
```http
DELETE /api/v1/organizations/{organization_id}/api-keys/{key_id}
Authorization: Bearer your-api-key
```

#### Validate API Key
```http
GET /api/v1/validate
Authorization: Bearer your-api-key
```

### Messaging

#### Create Conversation
```http
POST /api/v1/messaging/organizations/{organization_id}/conversations
Authorization: Bearer your-api-key
Content-Type: application/json

{
  "title": "Project Discussion",
  "type": "group",
  "participant_ids": ["user1", "user2"]
}
```

#### Get Organization Conversations
```http
GET /api/v1/messaging/organizations/{organization_id}/conversations
Authorization: Bearer your-api-key
```

#### Get Conversation
```http
GET /api/v1/messaging/organizations/{organization_id}/conversations/{conversation_id}
Authorization: Bearer your-api-key
```

#### Delete Conversation
```http
DELETE /api/v1/messaging/organizations/{organization_id}/conversations/{conversation_id}
Authorization: Bearer your-api-key
```

#### Send Message
```http
POST /api/v1/messaging/organizations/{organization_id}/conversations/{conversation_id}/messages
Authorization: Bearer your-api-key
Content-Type: application/json

{
  "content": "Hello, world!",
  "message_type": "text",
  "reply_to_id": "optional-reply-message-id"
}
```

#### Get Messages
```http
GET /api/v1/messaging/organizations/{organization_id}/conversations/{conversation_id}/messages?limit=50&offset=0
Authorization: Bearer your-api-key
```

#### Update Message
```http
PUT /api/v1/messaging/organizations/{organization_id}/messages/{message_id}
Authorization: Bearer your-api-key
Content-Type: application/json

{
  "content": "Updated message content"
}
```

#### Delete Message
```http
DELETE /api/v1/messaging/organizations/{organization_id}/messages/{message_id}
Authorization: Bearer your-api-key
```

#### Add Participant
```http
POST /api/v1/messaging/organizations/{organization_id}/conversations/{conversation_id}/participants
Authorization: Bearer your-api-key
Content-Type: application/json

{
  "user_id": "new-participant-id"
}
```

#### Remove Participant
```http
DELETE /api/v1/messaging/organizations/{organization_id}/conversations/{conversation_id}/participants/{user_id}
Authorization: Bearer your-api-key
```

#### Add Reaction
```http
POST /api/v1/messaging/organizations/{organization_id}/messages/{message_id}/reactions
Authorization: Bearer your-api-key
Content-Type: application/json

{
  "reaction": "👍"
}
```

#### Remove Reaction
```http
DELETE /api/v1/messaging/organizations/{organization_id}/messages/{message_id}/reactions/{reaction}
Authorization: Bearer your-api-key
```

#### Mark Message as Read
```http
POST /api/v1/messaging/organizations/{organization_id}/messages/{message_id}/read
Authorization: Bearer your-api-key
```

#### Mark Conversation as Read
```http
POST /api/v1/messaging/organizations/{organization_id}/conversations/{conversation_id}/read
Authorization: Bearer your-api-key
```

## Error Responses

### Authentication Errors
```json
{
  "error": "API key required",
  "message": "Please provide an API key in X-API-Key header, Authorization header, or api_key query parameter"
}
```

```json
{
  "error": "Invalid API key",
  "message": "The provided API key is invalid or inactive"
}
```

### Permission Errors
```json
{
  "error": "Insufficient permissions",
  "message": "Required permission: write"
}
```

### Quota Errors
```json
{
  "error": "Quota exceeded",
  "message": "API quota limit has been reached"
}
```

## Rate Limiting

API keys have usage quotas. Monitor the `usage_count` and `quota_limit` fields when validating your API key.

## Data Types

### Conversation Types
- `direct`: One-on-one conversation
- `group`: Group conversation
- `channel`: Public channel conversation

### Message Types
- `text`: Text message
- `image`: Image message
- `file`: File attachment
- `system`: System message

### Participant Roles
- `admin`: Can manage conversation and participants
- `member`: Standard participant
- `guest`: Limited access participant

## Getting Started

1. Create an organization in the database
2. Generate an API key for your organization
3. Use the API key in your requests
4. Start creating conversations and sending messages

## Examples

### JavaScript/Node.js
```javascript
const axios = require('axios');

const apiKey = 'your-api-key-here';
const organizationId = 'your-organization-id';

const client = axios.create({
  baseURL: 'http://localhost:3001/api/v1',
  headers: {
    'X-API-Key': apiKey,
    'Content-Type': 'application/json'
  }
});

// Create a conversation
const conversation = await client.post(`/messaging/organizations/${organizationId}/conversations`, {
  title: 'My Conversation',
  type: 'group',
  participant_ids: ['user1', 'user2']
});

// Send a message
const message = await client.post(`/messaging/organizations/${organizationId}/conversations/${conversation.data.data.id}/messages`, {
  content: 'Hello, world!',
  message_type: 'text'
});
```

### cURL
```bash
# Create conversation
curl -X POST http://localhost:3001/api/v1/messaging/organizations/your-org-id/conversations \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Conversation",
    "type": "group",
    "participant_ids": ["user1"]
  }'

# Send message
curl -X POST http://localhost:3001/api/v1/messaging/organizations/your-org-id/conversations/conversation-id/messages \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Hello!",
    "message_type": "text"
  }'
```