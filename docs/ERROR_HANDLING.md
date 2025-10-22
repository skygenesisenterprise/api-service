# Error Handling Guide

Comprehensive guide to handling errors and troubleshooting issues with the Sky Genesis Enterprise API.

## HTTP Status Codes

The API uses standard HTTP status codes to indicate the outcome of requests:

### Success Codes

- **200 OK**: Request successful
- **201 Created**: Resource created successfully
- **204 No Content**: Request successful, no content returned

### Client Error Codes

- **400 Bad Request**: Invalid request data or parameters
- **401 Unauthorized**: Authentication required or invalid credentials
- **403 Forbidden**: Insufficient permissions or access denied
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource conflict (e.g., duplicate creation)
- **413 Payload Too Large**: Request body too large
- **415 Unsupported Media Type**: Invalid content type
- **422 Unprocessable Entity**: Validation failed
- **429 Too Many Requests**: Rate limit exceeded

### Server Error Codes

- **500 Internal Server Error**: Unexpected server error
- **502 Bad Gateway**: Invalid response from upstream server
- **503 Service Unavailable**: Service temporarily unavailable
- **504 Gateway Timeout**: Request timeout

## Error Response Format

All error responses follow a consistent JSON structure:

```json
{
  "error": "Human-readable error message",
  "code": "ERROR_CODE",
  "details": {
    "field": "specific_field_name",
    "reason": "Detailed explanation"
  }
}
```

### Example Error Responses

#### Authentication Error
```json
{
  "error": "Invalid API key",
  "code": "AUTH_INVALID_KEY"
}
```

#### Validation Error
```json
{
  "error": "Validation failed",
  "code": "VALIDATION_ERROR",
  "details": {
    "field": "participant_ids",
    "reason": "At least one participant is required"
  }
}
```

#### Permission Error
```json
{
  "error": "API key does not belong to this organization",
  "code": "AUTH_ORGANIZATION_MISMATCH"
}
```

## Common Error Scenarios

### Authentication Errors

#### Invalid API Key
```
HTTP 401
{
  "error": "Invalid API key",
  "code": "AUTH_INVALID_KEY"
}
```

**Causes:**
- API key is incorrect or malformed
- API key has been revoked
- API key has expired
- Missing API key header

**Solutions:**
- Verify the API key is correct
- Check for extra spaces or characters
- Regenerate the API key if compromised
- Ensure the `X-API-Key` header is present

#### Organization Mismatch
```
HTTP 403
{
  "error": "API key does not belong to this organization",
  "code": "AUTH_ORGANIZATION_MISMATCH"
}
```

**Causes:**
- Using an API key from a different organization
- Incorrect organization ID in the URL

**Solutions:**
- Verify you're using the correct API key for the organization
- Check the organization ID in the request URL
- Contact administrator for organization access

### Validation Errors

#### Missing Required Fields
```
HTTP 400
{
  "error": "Validation failed",
  "code": "VALIDATION_ERROR",
  "details": {
    "field": "content",
    "reason": "Message content is required for non-system messages"
  }
}
```

**Common validation errors:**
- Missing required fields (`content`, `participant_ids`)
- Invalid field types
- Field values outside allowed ranges
- Invalid UUID formats

#### Invalid Conversation Type
```
HTTP 400
{
  "error": "Invalid conversation type",
  "code": "VALIDATION_INVALID_TYPE",
  "details": {
    "field": "type",
    "reason": "Type must be one of: direct, group, channel"
  }
}
```

### Permission Errors

#### Insufficient Permissions
```
HTTP 403
{
  "error": "Insufficient permissions",
  "code": "PERMISSION_DENIED"
}
```

**Causes:**
- API key lacks required permissions
- Attempting to modify resources you don't own
- Accessing restricted organization data

### Resource Errors

#### Conversation Not Found
```
HTTP 404
{
  "error": "Conversation not found or access denied",
  "code": "RESOURCE_NOT_FOUND"
}
```

**Causes:**
- Invalid conversation ID
- Conversation belongs to different organization
- Conversation has been deleted/archived

#### Message Not Found
```
HTTP 404
{
  "error": "Message not found",
  "code": "MESSAGE_NOT_FOUND"
}
```

#### Participant Not Found
```
HTTP 404
{
  "error": "Participant not found",
  "code": "PARTICIPANT_NOT_FOUND"
}
```

### Rate Limiting

#### Rate Limit Exceeded
```
HTTP 429
{
  "error": "Rate limit exceeded",
  "code": "RATE_LIMIT_EXCEEDED"
}
```

**Headers included:**
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1640995200
X-RateLimit-Retry-After: 60
```

**Solutions:**
- Implement exponential backoff
- Reduce request frequency
- Cache responses when possible
- Consider upgrading your plan

## Error Handling Best Practices

### 1. Implement Retry Logic

```javascript
async function makeRequestWithRetry(url, options, maxRetries = 3) {
  let lastError;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url, options);

      if (response.ok) {
        return response.json();
      }

      // Don't retry client errors (4xx)
      if (response.status >= 400 && response.status < 500) {
        throw new Error(`Client error: ${response.status}`);
      }

      // Retry server errors (5xx) and network errors
      lastError = new Error(`Server error: ${response.status}`);
    } catch (error) {
      lastError = error;

      // Don't retry client errors
      if (error.message.includes('Client error')) {
        throw error;
      }
    }

    // Wait before retrying (exponential backoff)
    if (attempt < maxRetries) {
      const delay = Math.pow(2, attempt) * 1000; // 2s, 4s, 8s...
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw lastError;
}
```

### 2. Handle Rate Limits

```javascript
class RateLimitHandler {
  constructor() {
    this.resetTime = null;
    this.remaining = null;
  }

  updateLimits(headers) {
    this.resetTime = headers.get('x-ratelimit-reset');
    this.remaining = headers.get('x-ratelimit-remaining');
  }

  shouldWait() {
    return this.remaining !== null && parseInt(this.remaining) <= 0;
  }

  getWaitTime() {
    if (!this.resetTime) return 0;
    const resetTime = parseInt(this.resetTime) * 1000; // Convert to milliseconds
    return Math.max(0, resetTime - Date.now());
  }
}

const rateLimiter = new RateLimitHandler();

async function makeRateLimitedRequest(url, options) {
  if (rateLimiter.shouldWait()) {
    const waitTime = rateLimiter.getWaitTime();
    console.log(`Rate limited. Waiting ${waitTime}ms...`);
    await new Promise(resolve => setTimeout(resolve, waitTime));
  }

  const response = await fetch(url, options);
  rateLimiter.updateLimits(response.headers);

  return response;
}
```

### 3. Comprehensive Error Handling

```javascript
async function robustApiCall(endpoint, options) {
  try {
    const response = await fetch(endpoint, options);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));

      switch (response.status) {
        case 401:
          // Handle authentication errors
          throw new AuthenticationError(errorData.error);
        case 403:
          // Handle permission errors
          throw new PermissionError(errorData.error);
        case 404:
          // Handle not found errors
          throw new NotFoundError(errorData.error);
        case 429:
          // Handle rate limiting
          const retryAfter = response.headers.get('retry-after');
          throw new RateLimitError(errorData.error, retryAfter);
        case 422:
          // Handle validation errors
          throw new ValidationError(errorData.error, errorData.details);
        default:
          // Handle other errors
          throw new ApiError(errorData.error || `HTTP ${response.status}`, response.status);
      }
    }

    return await response.json();
  } catch (error) {
    if (error instanceof ApiError) {
      throw error; // Re-throw API errors
    }

    // Handle network errors
    throw new NetworkError('Network request failed', error);
  }
}

// Custom error classes
class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

class AuthenticationError extends ApiError {
  constructor(message) {
    super(message, 401);
    this.name = 'AuthenticationError';
  }
}

class RateLimitError extends ApiError {
  constructor(message, retryAfter) {
    super(message, 429);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}
```

### 4. Error Logging and Monitoring

```javascript
class ErrorLogger {
  logError(error, context) {
    const errorInfo = {
      message: error.message,
      stack: error.stack,
      context,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href
    };

    // Send to error reporting service
    this.reportError(errorInfo);

    // Log locally for debugging
    console.error('API Error:', errorInfo);
  }

  reportError(errorInfo) {
    // Send to your error reporting service
    // Example: Sentry, LogRocket, etc.
    fetch('/api/errors', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(errorInfo)
    }).catch(() => {
      // Ignore errors in error reporting
    });
  }
}

const errorLogger = new ErrorLogger();

// Usage in API calls
async function apiCallWithLogging(endpoint, options) {
  try {
    return await robustApiCall(endpoint, options);
  } catch (error) {
    errorLogger.logError(error, {
      endpoint,
      method: options.method || 'GET',
      headers: options.headers
    });
    throw error;
  }
}
```

### 5. User-Friendly Error Messages

```javascript
function getUserFriendlyErrorMessage(error) {
  if (error instanceof AuthenticationError) {
    return {
      title: 'Authentication Required',
      message: 'Please check your API key and try again.',
      action: 'Check API Key'
    };
  }

  if (error instanceof RateLimitError) {
    return {
      title: 'Too Many Requests',
      message: `Please wait ${error.retryAfter} seconds before trying again.`,
      action: 'Wait and Retry'
    };
  }

  if (error instanceof NetworkError) {
    return {
      title: 'Connection Problem',
      message: 'Please check your internet connection and try again.',
      action: 'Retry'
    };
  }

  // Generic error
  return {
    title: 'Something went wrong',
    message: 'An unexpected error occurred. Please try again.',
    action: 'Retry'
  };
}

// Usage in UI
function showErrorDialog(error) {
  const friendlyError = getUserFriendlyErrorMessage(error);

  // Show dialog with friendly error message
  showDialog({
    type: 'error',
    title: friendlyError.title,
    message: friendlyError.message,
    actions: [{
      label: friendlyError.action,
      onClick: () => retryLastAction()
    }]
  });
}
```

## Troubleshooting Checklist

### When Requests Fail

1. **Check API Key**
   - Verify the API key is correct and active
   - Ensure proper header format: `X-API-Key: your-key`
   - Check for extra spaces or special characters

2. **Verify Organization Access**
   - Confirm the API key belongs to the correct organization
   - Check the organization ID in URLs
   - Ensure you have permission for the operation

3. **Validate Request Data**
   - Check required fields are present
   - Verify data types and formats
   - Ensure IDs are valid UUIDs

4. **Check Network Connectivity**
   - Verify internet connection
   - Check for firewall/proxy issues
   - Confirm API endpoint URLs are correct

5. **Review Rate Limits**
   - Check rate limit headers in responses
   - Implement appropriate delays between requests
   - Consider request batching

6. **Examine Server Status**
   - Check service status page
   - Look for maintenance windows
   - Monitor for service outages

### Debug Mode

Enable debug logging for detailed error information:

```javascript
// Enable debug mode
localStorage.setItem('sky-genesis-debug', 'true');

// All API calls will now log detailed information
// Check browser console for debug output
```

### Getting Help

If you continue to experience issues:

1. **Check Documentation**: Review this error handling guide
2. **Search Issues**: Look for similar issues in the [GitHub Issues](https://github.com/sky-genesis/api-service/issues)
3. **Contact Support**: Reach out to your organization administrator
4. **Provide Details**: Include error messages, request IDs, and steps to reproduce

## Error Codes Reference

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `AUTH_INVALID_KEY` | 401 | Invalid or missing API key |
| `AUTH_ORGANIZATION_MISMATCH` | 403 | API key doesn't belong to organization |
| `PERMISSION_DENIED` | 403 | Insufficient permissions |
| `RESOURCE_NOT_FOUND` | 404 | Requested resource doesn't exist |
| `VALIDATION_ERROR` | 422 | Request validation failed |
| `RATE_LIMIT_EXCEEDED` | 429 | Rate limit exceeded |
| `DUPLICATE_RESOURCE` | 409 | Resource already exists |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

This comprehensive error handling approach will help you build robust applications that gracefully handle various error conditions and provide a better user experience.