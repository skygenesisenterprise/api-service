# Code Examples

Practical examples of using the Sky Genesis Enterprise API in various programming languages.

## JavaScript/Node.js

### Setup

```javascript
const fetch = require('node-fetch');

class SkyGenesisClient {
  constructor(options) {
    this.baseUrl = options.baseUrl || 'https://api.skygenesisenterprise.com/api/v1';
    this.apiKey = options.apiKey;
    this.organizationId = options.organizationId;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const config = {
      headers: {
        'X-API-Key': this.apiKey,
        'Content-Type': 'application/json',
        ...options.headers
      },
      ...options
    };

    const response = await fetch(url, config);

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `HTTP ${response.status}`);
    }

    return response.json();
  }
}

// Initialize client
const client = new SkyGenesisClient({
  apiKey: process.env.SKY_GENESIS_API_KEY,
  organizationId: 'your-org-id'
});
```

### Basic Messaging

```javascript
// Send a message
async function sendMessage(conversationId, content) {
  try {
    const response = await client.request(
      `/organizations/${client.organizationId}/conversations/${conversationId}/messages`,
      {
        method: 'POST',
        body: JSON.stringify({
          content,
          message_type: 'text'
        })
      }
    );

    console.log('Message sent:', response.data);
    return response.data;
  } catch (error) {
    console.error('Failed to send message:', error.message);
  }
}

// Get conversation messages
async function getMessages(conversationId, limit = 50) {
  try {
    const response = await client.request(
      `/organizations/${client.organizationId}/conversations/${conversationId}/messages?limit=${limit}`
    );

    return response.data;
  } catch (error) {
    console.error('Failed to get messages:', error.message);
    return [];
  }
}

// Create a conversation
async function createConversation(title, participantIds) {
  try {
    const response = await client.request(
      `/organizations/${client.organizationId}/conversations`,
      {
        method: 'POST',
        body: JSON.stringify({
          title,
          type: 'group',
          participant_ids: participantIds
        })
      }
    );

    console.log('Conversation created:', response.data);
    return response.data;
  } catch (error) {
    console.error('Failed to create conversation:', error.message);
  }
}
```

### Advanced Features

```javascript
// Search messages
async function searchMessages(query, limit = 20) {
  try {
    const response = await client.request(
      `/organizations/${client.organizationId}/search/messages?q=${encodeURIComponent(query)}&limit=${limit}`
    );

    return response.data;
  } catch (error) {
    console.error('Search failed:', error.message);
    return [];
  }
}

// Add reaction to message
async function addReaction(messageId, emoji) {
  try {
    const response = await client.request(
      `/organizations/${client.organizationId}/messages/${messageId}/reactions`,
      {
        method: 'POST',
        body: JSON.stringify({ reaction: emoji })
      }
    );

    console.log('Reaction added:', response.data);
    return response.data;
  } catch (error) {
    console.error('Failed to add reaction:', error.message);
  }
}

// Upload file attachment
async function uploadAttachment(messageId, file) {
  try {
    // First, upload file to your storage service
    const fileUrl = await uploadToStorage(file);

    // Then add attachment metadata
    const response = await client.request(
      `/organizations/${client.organizationId}/messages/${messageId}/attachments`,
      {
        method: 'POST',
        body: JSON.stringify({
          filename: file.name,
          original_filename: file.originalName,
          mime_type: file.mimetype,
          file_size: file.size,
          file_url: fileUrl
        })
      }
    );

    console.log('Attachment added:', response.data);
    return response.data;
  } catch (error) {
    console.error('Failed to upload attachment:', error.message);
  }
}

// Get unread statistics
async function getUnreadStats() {
  try {
    const response = await client.request(
      `/organizations/${client.organizationId}/stats/unread`
    );

    return response.data.unread_count;
  } catch (error) {
    console.error('Failed to get unread stats:', error.message);
    return 0;
  }
}
```

### Real-time Message Polling

```javascript
class MessagePoller {
  constructor(client, conversationId, onNewMessages) {
    this.client = client;
    this.conversationId = conversationId;
    this.onNewMessages = onNewMessages;
    this.lastMessageId = null;
    this.intervalId = null;
    this.pollInterval = 5000; // 5 seconds
  }

  start() {
    this.intervalId = setInterval(() => this.poll(), this.pollInterval);
  }

  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  async poll() {
    try {
      const messages = await this.client.request(
        `/organizations/${this.client.organizationId}/conversations/${this.conversationId}/messages?limit=10`
      );

      const newMessages = messages.data.filter(msg => {
        return !this.lastMessageId || msg.message.id > this.lastMessageId;
      });

      if (newMessages.length > 0) {
        this.lastMessageId = newMessages[0].message.id;
        this.onNewMessages(newMessages);

        // Speed up polling when there are new messages
        this.adjustPollInterval(true);
      } else {
        // Slow down polling when no new messages
        this.adjustPollInterval(false);
      }
    } catch (error) {
      console.error('Polling failed:', error.message);
      // Slow down on errors
      this.adjustPollInterval(false);
    }
  }

  adjustPollInterval(hasNewMessages) {
    if (hasNewMessages) {
      this.pollInterval = Math.max(1000, this.pollInterval / 2);
    } else {
      this.pollInterval = Math.min(30000, this.pollInterval * 1.2);
    }

    // Restart with new interval
    this.stop();
    this.start();
  }
}

// Usage
const poller = new MessagePoller(client, 'conversation-id', (newMessages) => {
  console.log('New messages:', newMessages);
  // Update UI with new messages
});

poller.start();

// Stop polling when done
// poller.stop();
```

## Python

### Setup

```python
import os
import requests
from typing import List, Dict, Any, Optional

class SkyGenesisClient:
    def __init__(self, api_key: str, organization_id: str, base_url: str = "https://api.skygenesisenterprise.com/api/v1"):
        self.base_url = base_url
        self.api_key = api_key
        self.organization_id = organization_id
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': self.api_key,
            'Content-Type': 'application/json'
        })

    def request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        response = self.session.request(method, url, **kwargs)

        if not response.ok:
            error_data = response.json()
            raise Exception(error_data.get('error', f'HTTP {response.status_code}'))

        return response.json()

# Initialize client
client = SkyGenesisClient(
    api_key=os.environ['SKY_GENESIS_API_KEY'],
    organization_id='your-org-id'
)
```

### Basic Operations

```python
def send_message(conversation_id: str, content: str) -> Dict[str, Any]:
    """Send a message to a conversation."""
    try:
        response = client.request(
            'POST',
            f'/organizations/{client.organization_id}/conversations/{conversation_id}/messages',
            json={
                'content': content,
                'message_type': 'text'
            }
        )
        print(f"Message sent: {response['data']['id']}")
        return response['data']
    except Exception as e:
        print(f"Failed to send message: {e}")
        return {}

def get_messages(conversation_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Get messages from a conversation."""
    try:
        response = client.request(
            'GET',
            f'/organizations/{client.organization_id}/conversations/{conversation_id}/messages',
            params={'limit': limit}
        )
        return response['data']
    except Exception as e:
        print(f"Failed to get messages: {e}")
        return []

def create_conversation(title: str, participant_ids: List[str]) -> Dict[str, Any]:
    """Create a new conversation."""
    try:
        response = client.request(
            'POST',
            f'/organizations/{client.organization_id}/conversations',
            json={
                'title': title,
                'type': 'group',
                'participant_ids': participant_ids
            }
        )
        print(f"Conversation created: {response['data']['id']}")
        return response['data']
    except Exception as e:
        print(f"Failed to create conversation: {e}")
        return {}
```

### Advanced Features

```python
def search_messages(query: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Search for messages containing the query."""
    try:
        response = client.request(
            'GET',
            f'/organizations/{client.organization_id}/search/messages',
            params={
                'q': query,
                'limit': limit
            }
        )
        return response['data']
    except Exception as e:
        print(f"Search failed: {e}")
        return []

def add_reaction(message_id: str, emoji: str) -> Dict[str, Any]:
    """Add a reaction to a message."""
    try:
        response = client.request(
            'POST',
            f'/organizations/{client.organization_id}/messages/{message_id}/reactions',
            json={'reaction': emoji}
        )
        print(f"Reaction added: {emoji}")
        return response['data']
    except Exception as e:
        print(f"Failed to add reaction: {e}")
        return {}

def get_unread_count() -> int:
    """Get total unread message count."""
    try:
        response = client.request(
            'GET',
            f'/organizations/{client.organization_id}/stats/unread'
        )
        return response['data']['unread_count']
    except Exception as e:
        print(f"Failed to get unread count: {e}")
        return 0

def mark_conversation_read(conversation_id: str) -> bool:
    """Mark all messages in a conversation as read."""
    try:
        client.request(
            'POST',
            f'/organizations/{client.organization_id}/conversations/{conversation_id}/read'
        )
        print("Conversation marked as read")
        return True
    except Exception as e:
        print(f"Failed to mark conversation as read: {e}")
        return False
```

## Java

### Setup

```java
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

public class SkyGenesisClient {
    private final String baseUrl;
    private final String apiKey;
    private final String organizationId;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public SkyGenesisClient(String apiKey, String organizationId) {
        this(apiKey, organizationId, "https://api.skygenesisenterprise.com/api/v1");
    }

    public SkyGenesisClient(String apiKey, String organizationId, String baseUrl) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.organizationId = organizationId;
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    private HttpRequest.Builder baseRequest(String endpoint) {
        return HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + endpoint))
                .header("X-API-Key", apiKey)
                .header("Content-Type", "application/json");
    }

    private <T> T makeRequest(HttpRequest request, Class<T> responseType) throws IOException, InterruptedException {
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            return objectMapper.readValue(response.body(), responseType);
        } else {
            throw new RuntimeException("API request failed: " + response.body());
        }
    }
}
```

### Message Operations

```java
// Message data classes
public static class MessageRequest {
    public String content;
    public String message_type = "text";
    public String reply_to_id;

    public MessageRequest(String content) {
        this.content = content;
    }
}

public static class MessageResponse {
    public String message;
    public MessageData data;

    public static class MessageData {
        public String id;
        public String conversation_id;
        public String sender_id;
        public String content;
        public String message_type;
        public String created_at;
    }
}

public static class ConversationRequest {
    public String title;
    public String type = "group";
    public List<String> participant_ids;

    public ConversationRequest(String title, List<String> participantIds) {
        this.title = title;
        this.participant_ids = participantIds;
    }
}

// Usage
public MessageResponse sendMessage(String conversationId, String content) throws IOException, InterruptedException {
    MessageRequest request = new MessageRequest(content);

    HttpRequest httpRequest = baseRequest(
            "/organizations/" + organizationId + "/conversations/" + conversationId + "/messages"
    )
    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(request)))
    .build();

    return makeRequest(httpRequest, MessageResponse.class);
}

public ConversationResponse createConversation(String title, List<String> participantIds) throws IOException, InterruptedException {
    ConversationRequest request = new ConversationRequest(title, participantIds);

    HttpRequest httpRequest = baseRequest("/organizations/" + organizationId + "/conversations")
            .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(request)))
            .build();

    return makeRequest(httpRequest, ConversationResponse.class);
}
```

## Go

### Setup

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
)

type SkyGenesisClient struct {
    BaseURL        string
    APIKey         string
    OrganizationID string
    HTTPClient     *http.Client
}

func NewSkyGenesisClient(apiKey, organizationID string) *SkyGenesisClient {
    return &SkyGenesisClient{
        BaseURL:        "https://api.skygenesisenterprise.com/api/v1",
        APIKey:         apiKey,
        OrganizationID: organizationID,
        HTTPClient:     &http.Client{},
    }
}

func (c *SkyGenesisClient) doRequest(method, endpoint string, body interface{}) (*http.Response, error) {
    var bodyReader io.Reader
    if body != nil {
        jsonBody, err := json.Marshal(body)
        if err != nil {
            return nil, err
        }
        bodyReader = bytes.NewReader(jsonBody)
    }

    req, err := http.NewRequest(method, c.BaseURL+endpoint, bodyReader)
    if err != nil {
        return nil, err
    }

    req.Header.Set("X-API-Key", c.APIKey)
    req.Header.Set("Content-Type", "application/json")

    return c.HTTPClient.Do(req)
}

func (c *SkyGenesisClient) makeRequest(method, endpoint string, body interface{}, result interface{}) error {
    resp, err := c.doRequest(method, endpoint, body)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        var errorResp map[string]interface{}
        json.NewDecoder(resp.Body).Decode(&errorResp)
        return fmt.Errorf("API error: %v", errorResp["error"])
    }

    return json.NewDecoder(resp.Body).Decode(result)
}
```

### Usage

```go
// Data structures
type MessageRequest struct {
    Content     string `json:"content"`
    MessageType string `json:"message_type,omitempty"`
    ReplyToID   string `json:"reply_to_id,omitempty"`
}

type MessageResponse struct {
    Message string `json:"message"`
    Data    struct {
        ID             string `json:"id"`
        ConversationID string `json:"conversation_id"`
        SenderID       string `json:"sender_id"`
        Content        string `json:"content"`
        MessageType    string `json:"message_type"`
        CreatedAt      string `json:"created_at"`
    } `json:"data"`
}

type ConversationRequest struct {
    Title          string   `json:"title"`
    Type           string   `json:"type"`
    ParticipantIDs []string `json:"participant_ids"`
}

// Client methods
func (c *SkyGenesisClient) SendMessage(conversationID, content string) (*MessageResponse, error) {
    req := MessageRequest{
        Content:     content,
        MessageType: "text",
    }

    var resp MessageResponse
    err := c.makeRequest(
        "POST",
        fmt.Sprintf("/organizations/%s/conversations/%s/messages", c.OrganizationID, conversationID),
        req,
        &resp,
    )

    if err != nil {
        return nil, err
    }

    return &resp, nil
}

func (c *SkyGenesisClient) CreateConversation(title string, participantIDs []string) (*ConversationResponse, error) {
    req := ConversationRequest{
        Title:          title,
        Type:           "group",
        ParticipantIDs: participantIDs,
    }

    var resp ConversationResponse
    err := c.makeRequest(
        "POST",
        fmt.Sprintf("/organizations/%s/conversations", c.OrganizationID),
        req,
        &resp,
    )

    if err != nil {
        return nil, err
    }

    return &resp, nil
}

func (c *SkyGenesisClient) GetMessages(conversationID string, limit int) ([]MessageData, error) {
    endpoint := fmt.Sprintf(
        "/organizations/%s/conversations/%s/messages?limit=%d",
        c.OrganizationID,
        conversationID,
        limit,
    )

    var resp struct {
        Data []MessageData `json:"data"`
    }

    err := c.makeRequest("GET", endpoint, nil, &resp)
    if err != nil {
        return nil, err
    }

    return resp.Data, nil
}

// Main usage
func main() {
    client := NewSkyGenesisClient(
        os.Getenv("SKY_GENESIS_API_KEY"),
        "your-org-id",
    )

    // Send a message
    msgResp, err := client.SendMessage("conversation-id", "Hello, World!")
    if err != nil {
        fmt.Printf("Error sending message: %v\n", err)
        return
    }

    fmt.Printf("Message sent with ID: %s\n", msgResp.Data.ID)

    // Get messages
    messages, err := client.GetMessages("conversation-id", 10)
    if err != nil {
        fmt.Printf("Error getting messages: %v\n", err)
        return
    }

    fmt.Printf("Retrieved %d messages\n", len(messages))
}
```

## cURL Examples

### Authentication

```bash
# Set API key
API_KEY="your-api-key-here"
ORG_ID="your-org-id"

# All requests need the API key header
curl -H "X-API-Key: $API_KEY" \
     "https://api.skygenesisenterprise.com/api/v1/organizations/$ORG_ID/conversations"
```

### Conversations

```bash
# List conversations
curl -H "X-API-Key: $API_KEY" \
     "https://api.skygenesisenterprise.com/api/v1/organizations/$ORG_ID/conversations"

# Create conversation
curl -X POST \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "title": "Project Team",
       "type": "group",
       "participant_ids": ["user-1", "user-2"]
     }' \
     "https://api.skygenesisenterprise.com/api/v1/organizations/$ORG_ID/conversations"
```

### Messages

```bash
# Send message
curl -X POST \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "content": "Hello everyone!",
       "message_type": "text"
     }' \
     "https://api.skygenesisenterprise.com/api/v1/organizations/$ORG_ID/conversations/$CONV_ID/messages"

# Get messages with pagination
curl -H "X-API-Key: $API_KEY" \
     "https://api.skygenesisenterprise.com/api/v1/organizations/$ORG_ID/conversations/$CONV_ID/messages?limit=25&offset=0"
```

### Search and Statistics

```bash
# Search messages
curl -H "X-API-Key: $API_KEY" \
     "https://api.skygenesisenterprise.com/api/v1/organizations/$ORG_ID/search/messages?q=meeting&limit=10"

# Get unread count
curl -H "X-API-Key: $API_KEY" \
     "https://api.skygenesisenterprise.com/api/v1/organizations/$ORG_ID/stats/unread"
```

### File Attachments

```bash
# Add attachment
curl -X POST \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "filename": "document.pdf",
       "original_filename": "Project Document.pdf",
       "mime_type": "application/pdf",
       "file_size": 2048000,
       "file_url": "https://files.example.com/document.pdf"
     }' \
     "https://api.skygenesisenterprise.com/api/v1/organizations/$ORG_ID/messages/$MESSAGE_ID/attachments"
```

### Reactions

```bash
# Add reaction
curl -X POST \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"reaction": "👍"}' \
     "https://api.skygenesisenterprise.com/api/v1/organizations/$ORG_ID/messages/$MESSAGE_ID/reactions"

# Remove reaction (URL encode emoji)
curl -X DELETE \
     -H "X-API-Key: $API_KEY" \
     "https://api.skygenesisenterprise.com/api/v1/organizations/$ORG_ID/messages/$MESSAGE_ID/reactions/%F0%9F%91%8D"
```

These examples should help you get started with integrating the Sky Genesis Enterprise API into your applications. Each language implementation follows similar patterns but adapts to the specific idioms and best practices of that language.