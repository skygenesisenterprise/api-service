# Discord API Integration Guide

## Overview

The Sky Genesis Enterprise API provides comprehensive Discord bot integration capabilities, allowing secure communication between Discord and internal enterprise services. This integration enables administrators and authorized users to interact with enterprise systems directly through Discord commands and receive notifications.

## Authentication

All Discord API endpoints require proper authentication. The system supports multiple authentication methods:

### API Key Authentication
```http
X-API-Key: your-api-key
Authorization: Bearer your-api-key
```

### Discord-Specific Headers
For webhook endpoints, additional Discord-specific headers are required:
```http
X-Signature-Ed25519: discord-signature
X-Signature-Timestamp: timestamp
X-User-Id: discord-user-id
X-Channel-Id: discord-channel-id
```

## Endpoints

### 1. Event Processing

**Endpoint:** `POST /api/v1/discord/event`

Processes incoming Discord events such as slash commands, messages, and reactions.

**Request Body:**
```json
{
  "event_type": "slash_command",
  "user_id": "123456789012345678",
  "channel_id": "987654321098765432",
  "guild_id": "111111111111111111",
  "content": "/status",
  "command": "status",
  "args": ["service1", "service2"],
  "timestamp": "2024-01-01T12:00:00Z",
  "signature": "discord-webhook-signature"
}
```

**Response:**
```json
{
  "status": "processed"
}
```

### 2. Send Notifications

**Endpoint:** `POST /api/v1/discord/notify`

Sends notifications from internal services to Discord channels.

**Request Body:**
```json
{
  "channel_id": "987654321098765432",
  "message": "System maintenance completed successfully",
  "embed": {
    "title": "Maintenance Complete",
    "description": "All systems are now operational",
    "color": 65280,
    "fields": [
      {
        "name": "Duration",
        "value": "2 hours 30 minutes",
        "inline": true
      }
    ],
    "timestamp": "2024-01-01T12:00:00Z"
  },
  "urgent": false,
  "service": "maintenance"
}
```

**Response:**
```json
{
  "status": "sent"
}
```

### 3. Get Configuration

**Endpoint:** `GET /api/v1/discord/config`

Retrieves the current Discord bot configuration.

**Response:**
```json
{
  "channels": [
    {
      "id": "987654321098765432",
      "name": "admin-commands",
      "purpose": "commands",
      "permissions": ["admin", "read", "write"]
    }
  ],
  "roles": [
    {
      "id": "123456789012345678",
      "name": "Administrator",
      "permissions": ["admin"],
      "vpn_access": true
    }
  ],
  "commands": [
    {
      "name": "status",
      "description": "Get system status",
      "permissions": ["read"],
      "vpn_required": false,
      "audit_level": "basic"
    }
  ],
  "webhooks": [
    {
      "id": "987654321098765432",
      "url": "https://discord.com/api/webhooks/123/abc",
      "events": ["command", "notification"],
      "secret": "webhook-secret"
    }
  ],
  "vpn_required": true,
  "audit_enabled": true
}
```

### 4. Update Configuration

**Endpoint:** `PATCH /api/v1/discord/config`

Updates the Discord bot configuration. Requires admin privileges.

**Request Body:**
```json
{
  "channels": [
    {
      "id": "987654321098765432",
      "name": "admin-commands",
      "purpose": "commands",
      "permissions": ["admin", "read", "write"]
    }
  ],
  "vpn_required": true,
  "audit_enabled": true
}
```

**Response:**
```json
{
  "status": "updated"
}
```

### 5. Execute Commands

**Endpoint:** `POST /api/v1/discord/command`

Executes administrative commands via Discord.

**Request Body:**
```json
{
  "command": "status",
  "args": ["api", "database"],
  "user_id": "123456789012345678",
  "channel_id": "987654321098765432",
  "service": "api",
  "urgent": false
}
```

**Response:**
```json
{
  "success": true,
  "output": "API: OK\nDatabase: OK\nVPN: 5 peers connected",
  "error": null,
  "execution_time": 150,
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## Available Commands

### System Status
```
/status [service1] [service2] ...
```
Gets the current status of enterprise services.

**Examples:**
```
/status
/status api database
```

### Deployment
```
/deploy <service>
```
Triggers deployment of the specified service.

**Examples:**
```
/deploy api
/deploy web-frontend
```

### Logs
```
/logs <service>
```
Retrieves recent logs for the specified service.

**Examples:**
```
/logs api
/logs database
```

### Restart Service
```
/restart <service>
```
Restarts the specified service.

**Examples:**
```
/restart api
/restart monitoring
```

### VPN Peers
```
/vpn_peers
```
Lists all connected VPN peers.

### Announcements
```
/announce <message>
```
Sends an announcement to configured channels.

**Examples:**
```
/announce System maintenance will begin in 30 minutes
/announce Emergency: Database overload detected
```

## Discord Bot Setup

### 1. Create Discord Application

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new application
3. Note the Application ID and Public Key
4. Create a bot user and note the Bot Token

### 2. Configure Webhooks

1. In your Discord server, create webhook URLs for notification channels
2. Configure webhook endpoints in the API configuration
3. Set up proper permissions for each webhook

### 3. Environment Variables

Set the following environment variables:

```bash
DISCORD_BOT_TOKEN=your-bot-token
DISCORD_PUBLIC_KEY=your-public-key
DISCORD_GUILD_ID=your-guild-id
```

### 4. Slash Commands Registration

The bot automatically registers slash commands when it starts. Available commands will appear in Discord as `/command-name`.

## Security Considerations

### Authentication & Authorization
- All endpoints require valid API keys
- Discord-specific operations validate webhook signatures
- Role-based access control for commands
- Guild membership verification

### Rate Limiting
- Commands are rate-limited per user
- Webhook events are validated for authenticity
- Suspicious activity is logged and flagged

### Content Filtering
- All messages are scanned for malicious content
- HTML/script injection is prevented
- Content length limits are enforced

### Audit Logging
- All Discord operations are logged
- Command executions include full context
- Failed authentication attempts are tracked
- Audit logs are retained for compliance

## Error Handling

### Common Error Responses

**Invalid Signature:**
```json
{
  "error": "Invalid signature"
}
```

**Insufficient Permissions:**
```json
{
  "error": "Insufficient permissions"
}
```

**Rate Limit Exceeded:**
```json
{
  "error": "Rate limit exceeded"
}
```

**Unknown Command:**
```json
{
  "error": "Unknown command",
  "success": false
}
```

**VPN Required:**
```json
{
  "error": "VPN access required for this command"
}
```

## Webhook Integration

### Discord Webhook Events

The API accepts the following Discord webhook events:

- `slash_command`: Slash command interactions
- `message`: Regular text messages
- `reaction`: Message reactions

### Webhook Signature Validation

Discord webhooks include cryptographic signatures that must be validated:

```rust
// The API automatically validates signatures using the public key
// Invalid signatures result in 400 Bad Request responses
```

## Monitoring & Maintenance

### Health Checks
- Monitor webhook delivery success rates
- Track command execution times
- Check API response times

### Log Analysis
- Review audit logs for suspicious activity
- Monitor command usage patterns
- Track error rates and types

### Configuration Updates
- Update channel configurations as needed
- Modify command permissions
- Refresh webhook URLs periodically

## Troubleshooting

### Common Issues

1. **Webhook signatures failing**
   - Verify Discord Public Key is correct
   - Check timestamp is within acceptable range
   - Ensure raw request body is used for signature calculation

2. **Commands not executing**
   - Verify user has required permissions
   - Check if VPN access is required
   - Confirm command name is spelled correctly

3. **Notifications not appearing**
   - Verify webhook URLs are valid
   - Check channel permissions
   - Ensure service is configured for the channel

4. **Rate limiting issues**
   - Wait for rate limit to reset
   - Reduce command frequency
   - Contact administrator for increased limits

## Best Practices

### Security
- Rotate API keys regularly
- Use VPN for sensitive operations
- Monitor audit logs for anomalies
- Keep Discord bot token secure

### Performance
- Use slash commands instead of text commands
- Batch notifications when possible
- Implement proper error handling
- Monitor API usage patterns

### User Experience
- Provide clear command descriptions
- Use embeds for rich formatting
- Include helpful error messages
- Document available commands

## API Limits & Quotas

- **Rate Limits:** 10 commands per minute per user
- **Content Length:** 2000 characters maximum
- **Embed Fields:** 25 fields maximum per embed
- **Audit Retention:** 90 days for command history
- **Webhook Timeout:** 15 seconds for delivery

## Support

For technical support or questions about the Discord API integration:

- Check the audit logs for detailed error information
- Review the system status using `/status` command
- Contact your system administrator
- Refer to the main API documentation for additional endpoints

---

*This documentation is for the Sky Genesis Enterprise API Discord integration. All operations are logged and monitored for security and compliance purposes.*