# Sky Genesis Enterprise API Service

A comprehensive REST API service for enterprise messaging and communication, built with Rust and Actix-Web.

## Overview

The Sky Genesis Enterprise API Service provides a complete messaging platform that enables developers to integrate advanced communication features into their applications. Built for enterprise use, it offers robust messaging capabilities with API key authentication, conversation management, file attachments, real-time features, and comprehensive search functionality.

## Features

- **Complete Messaging API**: Full-featured messaging with conversations, messages, attachments, and reactions
- **API Key Authentication**: Secure authentication with organization-based access control
- **File Attachments**: Upload and manage file attachments for messages
- **Real-time Capabilities**: Support for read status, reactions, and conversation updates
- **Search Functionality**: Full-text search across messages and conversations
- **Pagination Support**: Efficient pagination for large datasets
- **Organization Management**: Multi-tenant architecture with organization isolation
- **Comprehensive Statistics**: Unread message counts and conversation statistics

## Quick Start

1. **Get an API Key**: Contact your organization administrator to obtain an API key
2. **Set Authentication**: Include your API key in requests using `X-API-Key` header or `Authorization: Bearer` header
3. **Start Messaging**: Create conversations, send messages, and manage participants

See [Quick Start Guide](QUICK_START.md) for detailed setup instructions.

## API Reference

The API is organized around REST principles with resource-based URLs and standard HTTP methods.

### Base URL
```
https://api.skygenesisenterprise.com/api/v1
```

### Authentication
All API requests require authentication via API keys. See [Authentication Guide](AUTHENTICATION.md) for details.

### Core Resources

- **Organizations**: Multi-tenant containers for users and conversations
- **Conversations**: Chat rooms or direct message threads
- **Messages**: Individual messages within conversations
- **Participants**: Users participating in conversations
- **Attachments**: File attachments for messages
- **Reactions**: User reactions to messages

### Example Request

```bash
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations" \
  -H "X-API-Key: your-api-key-here"
```

## Documentation Structure

- **[Quick Start Guide](QUICK_START.md)**: Get up and running quickly
- **[Authentication Guide](AUTHENTICATION.md)**: Learn about API key authentication
- **[API Reference](API_REFERENCE.md)**: Complete API endpoint documentation
- **[Messaging Guide](MESSAGING_GUIDE.md)**: Detailed messaging API usage
- **[Examples](EXAMPLES.md)**: Code examples in multiple languages
- **[Error Handling](ERROR_HANDLING.md)**: Error codes and troubleshooting

## SDKs and Libraries

While the API is REST-based and can be used with any HTTP client, we provide official SDKs for popular languages:

- **JavaScript/TypeScript**: `npm install @sky-genesis/api-client`
- **Python**: `pip install sky-genesis-api`
- **Java**: Maven dependency available
- **Go**: `go get github.com/sky-genesis/api-client-go`

## Support

- **Documentation**: This documentation site
- **Issues**: Report bugs at [GitHub Issues](https://github.com/sky-genesis/api-service/issues)
- **Discussions**: Join community discussions on [GitHub Discussions](https://github.com/sky-genesis/api-service/discussions)

## License

This API service is proprietary software. See LICENSE file for details.

## Version

Current API version: v1.0.0

For changelog and version history, see [CHANGELOG.md](../CHANGELOG.md).