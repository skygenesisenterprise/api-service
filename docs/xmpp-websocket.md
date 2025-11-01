# XMPP / WebSocket Integration

## Overview

The Sky Genesis Enterprise API implements real-time communication using WebSocket as the transport layer with XMPP-inspired presence and messaging features, enabling instant communication between users and services.

## Architecture

### WebSocket Transport
- **Protocol**: RFC 6455 WebSocket
- **Security**: TLS 1.3 encryption
- **Authentication**: JWT or API key based
- **Connection Limits**: Configurable per user/service

### XMPP Features
- **Presence**: Online, away, busy, offline status
- **Roster**: Contact list management
- **Messaging**: Direct and group chat
- **Typing Indicators**: Real-time typing notifications

## WebSocket Connection

### Establishing Connection
```javascript
const ws = new WebSocket('wss://api.skygenesisenterprise.com/ws/connect?token=jwt_token');

// Connection established
ws.onopen = () => {
  console.log('Connected to SGE WebSocket');
};

// Handle messages
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  handleMessage(message);
};

// Handle errors
ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};
```

### Message Format
All messages use JSON-RPC 2.0 inspired format:

```json
{
  "type": "MessageType",
  "id": "optional_message_id",
  "payload": {
    // Message-specific data
  }
}
```

## Presence Management

### Presence Status Types
- **online**: User is actively available
- **away**: User is away from device
- **busy**: User is busy, do not disturb
- **offline**: User is disconnected

### Update Presence
```javascript
ws.send(JSON.stringify({
  type: "PresenceUpdate",
  user_id: "user123",
  status: "online",
  status_message: "Available for chat"
}));
```

### Subscribe to Presence
```javascript
ws.send(JSON.stringify({
  type: "Subscribe",
  channel: "presence:user123"
}));
```

### Presence Endpoints

#### Get All Presence
```http
GET /xmpp/presence
Authorization: Bearer <token>
```

**Response:**
```json
{
  "user123": {
    "status": "online",
    "message": "Available",
    "timestamp": 1640995200
  },
  "user456": {
    "status": "away",
    "message": null,
    "timestamp": 1640995100
  }
}
```

#### Get User Presence
```http
GET /xmpp/presence/user123
```

#### Update Presence
```http
POST /xmpp/presence
Authorization: Bearer <token>
Content-Type: application/json

{
  "user_id": "user123",
  "status": "busy",
  "message": "In meeting"
}
```

## Real-time Messaging

### Message Types
- **chat**: Direct one-to-one messages
- **groupchat**: Multi-user group messages
- **muc**: Multi-user chat room messages

### Send Message
```javascript
ws.send(JSON.stringify({
  type: "ChatMessage",
  message: {
    from: "user123",
    to: "user456",
    message: "Hello, how are you?",
    timestamp: Date.now(),
    message_type: "chat"
  }
}));
```

### Typing Indicators
```javascript
// Start typing
ws.send(JSON.stringify({
  type: "Typing",
  from: "user123",
  to: "user456",
  typing: true
}));

// Stop typing
ws.send(JSON.stringify({
  type: "Typing",
  from: "user123",
  to: "user456",
  typing: false
}));
```

## Channel System

### Channel Types
- **user:{user_id}**: User-specific messages
- **presence:{user_id}**: Presence updates for user
- **chat:{user_id}**: Direct messages to/from user
- **group:{group_id}**: Group chat messages
- **system**: System-wide broadcasts

### Subscribe to Channels
```javascript
// Subscribe to multiple channels
ws.send(JSON.stringify({
  type: "Subscribe",
  channel: "chat:user123"
}));

ws.send(JSON.stringify({
  type: "Subscribe",
  channel: "presence:user456"
}));
```

### Unsubscribe from Channels
```javascript
ws.send(JSON.stringify({
  type: "Unsubscribe",
  channel: "chat:user123"
}));
```

## WebSocket Status Endpoints

### Connection Status
```http
GET /ws/status
```

**Response:**
```json
{
  "status": "active",
  "clients_connected": 42,
  "channels_active": 15,
  "timestamp": 1640995200
}
```

### Broadcast to Channel
```http
POST /ws/broadcast/notifications
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "System Maintenance",
  "message": "Scheduled maintenance in 30 minutes",
  "level": "warning"
}
```

### Send to User
```http
POST /ws/notify/user123
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "New Message",
  "message": "You have a new message from John",
  "level": "info"
}
```

## Message Handling Examples

### Complete Chat Application
```javascript
class ChatClient {
  constructor(userId) {
    this.userId = userId;
    this.ws = null;
    this.connect();
  }

  connect() {
    this.ws = new WebSocket(`wss://api.skygenesisenterprise.com/ws/auth?token=${getToken()}`);

    this.ws.onopen = () => {
      // Subscribe to personal channels
      this.subscribe(`chat:${this.userId}`);
      this.subscribe(`presence:${this.userId}`);

      // Set presence to online
      this.updatePresence('online', 'Available');
    };

    this.ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      this.handleMessage(message);
    };
  }

  subscribe(channel) {
    this.ws.send(JSON.stringify({
      type: "Subscribe",
      channel
    }));
  }

  updatePresence(status, message) {
    this.ws.send(JSON.stringify({
      type: "PresenceUpdate",
      user_id: this.userId,
      status,
      status_message: message
    }));
  }

  sendMessage(to, text, type = 'chat') {
    this.ws.send(JSON.stringify({
      type: "ChatMessage",
      message: {
        from: this.userId,
        to,
        message: text,
        timestamp: Date.now(),
        message_type: type
      }
    }));
  }

  handleMessage(message) {
    switch (message.type) {
      case 'ChatMessage':
        this.displayMessage(message.message);
        break;
      case 'PresenceStatus':
        this.updateUserPresence(message.user_id, message);
        break;
      case 'Notification':
        this.showNotification(message);
        break;
      case 'Typing':
        this.showTypingIndicator(message);
        break;
    }
  }
}
```

## Scalability Features

### Connection Management
- **Connection Pooling**: Efficient connection handling
- **Load Balancing**: Distribute connections across instances
- **Heartbeat**: Automatic ping/pong for connection health

### Message Routing
- **Channel-based**: Efficient message routing
- **Broadcast Optimization**: Minimize duplicate sends
- **Backpressure**: Prevent message flooding

### Persistence
- **Message History**: Optional message persistence
- **Offline Delivery**: Queue messages for offline users
- **Presence History**: Track presence changes

## Security Considerations

### Authentication
- **JWT Validation**: Token-based authentication
- **API Key Support**: Alternative authentication
- **Connection Limits**: Prevent abuse

### Authorization
- **Channel Permissions**: User-specific channel access
- **Message Filtering**: Content validation
- **Rate Limiting**: Prevent spam

### Encryption
- **TLS 1.3**: End-to-end encryption
- **Message Encryption**: Optional E2E encryption
- **Secure WebSocket**: wss:// protocol

## Monitoring & Observability

### Metrics
- `websocket_connections_total`: Total active connections
- `websocket_messages_total`: Messages sent/received
- `websocket_channels_total`: Active channels
- `presence_updates_total`: Presence status changes

### Traces
- Connection establishment spans
- Message routing spans
- Channel subscription spans

### Logs
- Connection events
- Message delivery status
- Error conditions

## Configuration

### Environment Variables
```bash
WS_MAX_CONNECTIONS=10000
WS_MESSAGE_TIMEOUT=30
WS_HEARTBEAT_INTERVAL=30
WS_MAX_MESSAGE_SIZE=65536
```

### Client Configuration
```javascript
const wsConfig = {
  url: 'wss://api.skygenesisenterprise.com/ws/auth',
  reconnectInterval: 5000,
  maxReconnectAttempts: 5,
  heartbeatInterval: 30000
};
```

## Troubleshooting

### Connection Issues
- **CORS Errors**: Configure CORS for WebSocket
- **Firewall Blocking**: Ensure port 443 is open
- **SSL Certificate**: Valid certificate required

### Message Delivery
- **Offline Users**: Implement offline queuing
- **Network Issues**: Automatic reconnection
- **Message Loss**: Sequence numbering

### Performance Issues
- **High Latency**: Check network conditions
- **Memory Usage**: Monitor connection count
- **CPU Usage**: Optimize message processing

## Integration Examples

### React Chat Component
```jsx
import { useEffect, useState } from 'react';

function ChatComponent({ userId }) {
  const [messages, setMessages] = useState([]);
  const [ws, setWs] = useState(null);

  useEffect(() => {
    const websocket = new WebSocket('wss://api.skygenesisenterprise.com/ws/auth');

    websocket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'ChatMessage') {
        setMessages(prev => [...prev, message.message]);
      }
    };

    setWs(websocket);
    return () => websocket.close();
  }, []);

  const sendMessage = (text) => {
    ws.send(JSON.stringify({
      type: "ChatMessage",
      message: {
        from: userId,
        to: "recipient",
        message: text,
        timestamp: Date.now(),
        message_type: "chat"
      }
    }));
  };

  return (
    <div>
      {messages.map(msg => (
        <div key={msg.timestamp}>{msg.message}</div>
      ))}
      <input onKeyPress={(e) => e.key === 'Enter' && sendMessage(e.target.value)} />
    </div>
  );
}
```

This WebSocket/XMPP implementation provides a robust foundation for real-time communication in the SGE ecosystem.