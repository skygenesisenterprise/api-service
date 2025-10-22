# Authentication Guide

The Sky Genesis Enterprise API uses API key-based authentication to ensure secure access to messaging resources.

## Overview

All API requests must include authentication credentials. The API uses API keys that are tied to specific organizations, ensuring proper access control and resource isolation.

## API Key Types

### Organization API Keys
- **Scope**: Organization-wide access
- **Permissions**: Configurable permissions for different operations
- **Usage**: Primary authentication method for most operations

### User API Keys (Future)
- **Scope**: Individual user access
- **Permissions**: User-specific permissions
- **Usage**: For user-specific operations (planned feature)

## Authentication Methods

### Method 1: X-API-Key Header (Recommended)

Include the API key in the `X-API-Key` header:

```bash
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations" \
  -H "X-API-Key: your-api-key-here"
```

### Method 2: Authorization Bearer Header

Include the API key in the `Authorization` header with Bearer scheme:

```bash
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations" \
  -H "Authorization: Bearer your-api-key-here"
```

### Method 3: Query Parameter

Include the API key as a query parameter (less secure, use only for testing):

```bash
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations?api_key=your-api-key-here"
```

## Getting an API Key

1. **Contact Administrator**: Request an API key from your organization administrator
2. **Specify Permissions**: Indicate what permissions you need (read, write, admin)
3. **Environment Setup**: Store the key securely in your environment

## API Key Permissions

API keys can have different permission levels:

- **read**: Read-only access to conversations and messages
- **write**: Create and modify conversations, messages, and attachments
- **admin**: Full administrative access including user management

## Security Best Practices

### 1. Secure Storage
```bash
# Environment variables (recommended)
export SKY_GENESIS_API_KEY="your-secure-api-key"

# Never hardcode in source code
# ❌ BAD
const apiKey = "your-api-key-here";

# ✅ GOOD
const apiKey = process.env.SKY_GENESIS_API_KEY;
```

### 2. Key Rotation
- Rotate API keys regularly (recommended: every 90 days)
- Use different keys for different environments (dev, staging, prod)
- Immediately revoke compromised keys

### 3. Access Control
- Use the principle of least privilege
- Grant only necessary permissions
- Monitor API key usage

### 4. Network Security
- Use HTTPS for all API calls
- Avoid sending API keys over insecure connections
- Implement proper TLS certificate validation

## Authentication Errors

### 401 Unauthorized
```json
{
  "error": "Invalid API key"
}
```

**Causes:**
- Invalid or expired API key
- Missing authentication headers
- Incorrect header format

### 403 Forbidden
```json
{
  "error": "API key does not belong to this organization"
}
```

**Causes:**
- API key belongs to a different organization
- Insufficient permissions for the operation
- Key has been revoked

## Organization Context

All authenticated requests operate within the context of the organization associated with the API key. This ensures:

- **Data Isolation**: Users can only access data from their organization
- **Resource Limits**: Quotas are enforced per organization
- **Audit Trails**: All actions are logged with organization context

## Rate Limiting

API keys are subject to rate limiting based on:

- **Requests per minute**: Configurable per organization
- **Concurrent connections**: Limits on simultaneous requests
- **Data transfer**: Bandwidth limits for attachments

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## Troubleshooting

### Common Issues

1. **"Invalid API key" error**
   - Verify the API key is correct
   - Check for extra spaces or characters
   - Ensure the key hasn't expired

2. **"Organization access denied" error**
   - Confirm you're using the correct organization ID
   - Verify your API key belongs to that organization
   - Contact admin if you need access to multiple organizations

3. **Rate limiting errors**
   - Implement exponential backoff
   - Check rate limit headers
   - Consider upgrading your plan for higher limits

### Testing Authentication

Use this endpoint to test your authentication setup:

```bash
curl -X GET "https://api.skygenesisenterprise.com/api/v1/organizations/{org_id}/conversations" \
  -H "X-API-Key: your-api-key-here" \
  -v
```

Look for:
- HTTP 200 status code
- Valid JSON response
- No authentication errors

## SDK Authentication

When using official SDKs, authentication is handled automatically:

### JavaScript/TypeScript
```javascript
import { SkyGenesisClient } from '@sky-genesis/api-client';

const client = new SkyGenesisClient({
  apiKey: process.env.SKY_GENESIS_API_KEY,
  organizationId: 'your-org-id'
});
```

### Python
```python
from sky_genesis_api import SkyGenesisClient

client = SkyGenesisClient(
    api_key=os.environ['SKY_GENESIS_API_KEY'],
    organization_id='your-org-id'
)
```

### Java
```java
SkyGenesisClient client = new SkyGenesisClient.Builder()
    .apiKey(System.getenv("SKY_GENESIS_API_KEY"))
    .organizationId("your-org-id")
    .build();
```

## Support

If you encounter authentication issues:

1. Check this documentation
2. Verify your API key and permissions
3. Contact your organization administrator
4. Open an issue on [GitHub](https://github.com/skygenesisenterprise/api-service/issues)