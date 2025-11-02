# GitHub App Integration Guide

This guide explains how to create and configure a GitHub App to integrate with the Sky Genesis Enterprise API Service for automated workflows and webhook processing.

## Overview

The Sky Genesis API provides a `/api/v1/git/webhook` endpoint that can receive and process GitHub webhooks. By creating a GitHub App, you can automate various tasks such as:

- Processing push events
- Handling pull request workflows
- Managing issue tracking
- Triggering CI/CD pipelines
- Automating repository management

## Prerequisites

- A GitHub account with repository admin permissions
- Access to the Sky Genesis Enterprise API
- A webhook endpoint accessible from GitHub (publicly accessible URL)

## Step 1: Create a GitHub App

### 1.1 Access GitHub App Settings

1. Go to your GitHub account settings
2. Navigate to **Developer settings** → **GitHub Apps**
3. Click **New GitHub App**

### 1.2 Configure Basic Information

Fill in the following fields:

- **GitHub App name**: Choose a descriptive name (e.g., "Sky Genesis Automation")
- **Description**: Brief description of the app's purpose
- **Homepage URL**: Your organization's website or repository URL

### 1.3 Configure Webhook

- **Webhook URL**: `https://api.skygenesisenterprise.com/api/v1/git/webhook`
- **Webhook secret**: Generate a strong secret key (store this securely)

### 1.4 Set Permissions

Configure the following repository permissions based on your needs:

| Permission | Access | Purpose |
|------------|--------|---------|
| Contents | Read | Access repository contents |
| Issues | Read & Write | Create/manage issues |
| Pull requests | Read & Write | Handle PR events |
| Repository administration | Read | Access repository settings |
| Webhooks | Read & Write | Manage repository webhooks |
| Metadata | Read | Access repository metadata |

### 1.5 Subscribe to Events

Select the webhook events you want to receive:

- **Push** - Code pushes to repository
- **Pull request** - PR creation, updates, merges
- **Issues** - Issue creation, updates, comments
- **Repository** - Repository creation, deletion, etc.
- **Release** - Release creation and publishing

### 1.6 Generate Private Key

1. Scroll to the bottom of the app settings
2. Click **Generate a private key**
3. Download the `.pem` file and store it securely

### 1.7 Install the App

1. From the app settings, click **Install App**
2. Choose the repositories to install on
3. Complete the installation

## Step 2: Configure API Integration

### 2.1 Store Credentials Securely

Store the following credentials in your environment or secure vault:

```bash
GITHUB_APP_ID=your_app_id
GITHUB_PRIVATE_KEY_PATH=/path/to/private-key.pem
GITHUB_WEBHOOK_SECRET=your_webhook_secret
```

### 2.2 API Configuration

Update your GitHub integration configuration via the API:

```bash
curl -X PATCH https://api.skygenesisenterprise.com/api/v1/git/config \
  -H "Authorization: Bearer your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "webhooks": [
      {
        "id": "github-app-webhook",
        "repository": "owner/repo",
        "events": ["push", "pull_request", "issues"],
        "secret": "your_webhook_secret",
        "active": true
      }
    ],
    "repositories": [
      {
        "name": "owner/repo",
        "permissions": ["read", "write"],
        "automations": ["ci-trigger", "issue-sync"]
      }
    ],
    "automations": [
      {
        "id": "ci-trigger",
        "name": "CI Pipeline Trigger",
        "description": "Trigger CI pipeline on push events",
        "event_types": ["push"],
        "actions": ["trigger_pipeline"],
        "enabled": true
      }
    ],
    "audit_enabled": true
  }'
```

## Step 3: Webhook Processing

### 3.1 Webhook Payload Structure

GitHub sends webhook payloads as JSON. The API automatically parses these into structured data:

```json
{
  "event_type": "push",
  "repository": {
    "id": 123456789,
    "name": "my-repo",
    "full_name": "owner/my-repo",
    "owner": {
      "login": "owner",
      "id": 987654321
    }
  },
  "sender": {
    "login": "user",
    "id": 123456789
  },
  "payload": {
    // Full GitHub webhook payload
  }
}
```

### 3.2 Event Processing

The API processes different event types:

- **Push Events**: Trigger CI/CD, code analysis, notifications
- **Pull Request Events**: Code review automation, testing, deployment
- **Issue Events**: Issue tracking, assignment, labeling
- **Release Events**: Deployment automation, changelog generation

### 3.3 Response Handling

The API responds with a success status for all processed webhooks:

```json
{
  "status": "ok",
  "message": "Webhook processed successfully",
  "event_type": "push",
  "repository": "owner/repo"
}
```

## Step 4: Security Considerations

### 4.1 Webhook Signature Verification

The API automatically verifies webhook signatures using the configured secret:

- Validates `X-Hub-Signature-256` header
- Ensures payload integrity
- Rejects unsigned or tampered requests

### 4.2 Access Control

- API key authentication required for configuration endpoints
- Repository-specific permissions
- Audit logging for all operations

### 4.3 Rate Limiting

GitHub imposes rate limits on webhook deliveries. The API includes:

- Request throttling
- Error handling for rate limit exceeded
- Retry mechanisms for failed deliveries

## Step 5: Testing and Monitoring

### 5.1 Test Webhook Delivery

1. Go to your GitHub App settings
2. Navigate to **Advanced** → **Recent deliveries**
3. Click on a delivery to view payload and response
4. Check API logs for processing details

### 5.2 Monitor Integration

Use the monitoring endpoints to track webhook processing:

```bash
# Check webhook processing status
curl https://api.skygenesisenterprise.com/api/v1/monitoring/webhooks \
  -H "Authorization: Bearer your_api_key"
```

### 5.3 Debug Issues

Common issues and solutions:

- **Webhook not received**: Check webhook URL accessibility
- **Signature verification failed**: Verify webhook secret configuration
- **Permission denied**: Ensure proper repository permissions
- **Rate limit exceeded**: Implement exponential backoff

## Step 6: Advanced Configuration

### 6.1 Custom Automations

Create custom automation rules based on webhook events:

```json
{
  "automations": [
    {
      "id": "security-scan",
      "name": "Security Vulnerability Scan",
      "event_types": ["push", "pull_request"],
      "conditions": {
        "branches": ["main", "develop"],
        "file_patterns": ["*.js", "*.ts", "*.rs"]
      },
      "actions": ["run_security_scan", "notify_team"],
      "enabled": true
    }
  ]
}
```

### 6.2 Repository-Specific Rules

Configure different behaviors per repository:

```json
{
  "repositories": [
    {
      "name": "myorg/frontend",
      "permissions": ["read", "write"],
      "automations": ["lint-check", "unit-tests"],
      "webhook_secret": "unique-secret-per-repo"
    },
    {
      "name": "myorg/backend",
      "permissions": ["read", "write"],
      "automations": ["security-scan", "integration-tests"]
    }
  ]
}
```

## Troubleshooting

### Common Error Messages

- **"Invalid webhook signature"**: Check webhook secret configuration
- **"Repository not found"**: Verify repository permissions and app installation
- **"Rate limit exceeded"**: Implement retry logic with exponential backoff
- **"Permission denied"**: Review GitHub App permissions

### Logs and Debugging

Check the API logs for detailed webhook processing information:

```bash
# View recent webhook activity
curl https://api.skygenesisenterprise.com/api/v1/logs/webhooks \
  -H "Authorization: Bearer your_api_key"
```

## Support

For additional support:

- Check the API documentation at `/docs/swagger-ui`
- Review GitHub App documentation: https://docs.github.com/en/developers/apps
- Contact the development team for integration assistance

## Security Best Practices

- Rotate webhook secrets regularly
- Use HTTPS for all webhook URLs
- Implement proper access controls
- Monitor webhook activity for anomalies
- Keep GitHub App permissions minimal
- Regularly audit integration logs