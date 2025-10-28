# Secrets Management Runbook

## Overview
This runbook covers the management of secrets and sensitive configuration for the Sky Genesis Enterprise API Service.

## Secret Storage

### Tools Used
- HashiCorp Vault for secret storage
- Kubernetes Secrets for runtime secrets
- GitHub Secrets for CI/CD

### Vault Setup
```bash
# Enable KV secrets engine
vault secrets enable -path=secret kv-v2

# Store database credentials
vault kv put secret/database host=localhost port=5432 username=api password=secret

# Read secrets
vault kv get secret/database
```

## Application Secrets

### Environment Variables
- Database connection strings
- API keys
- JWT secrets
- External service credentials

### Runtime Injection
```yaml
# Kubernetes secret
apiVersion: v1
kind: Secret
metadata:
  name: api-secrets
type: Opaque
data:
  db-password: <base64-encoded>
```

## CI/CD Secrets

### GitHub Secrets
- Docker registry credentials
- Deployment keys
- Cloud provider credentials

### Secure Usage
```yaml
# GitHub Actions workflow
- name: Deploy
  env:
    DOCKER_PASSWORD: ${{ secrets.DOCKER_PASSWORD }}
  run: |
    echo $DOCKER_PASSWORD | docker login -u $DOCKER_USER --password-stdin
```

## Key Rotation

### Process
1. Generate new secret/key
2. Update in Vault
3. Deploy application with new secret
4. Verify functionality
5. Remove old secret
6. Update dependent systems

### Schedule
- API keys: quarterly
- Database passwords: monthly
- TLS certificates: annually

## Access Control

### Vault Policies
```hcl
path "secret/data/database" {
  capabilities = ["read"]
}
```

### Principle of Least Privilege
- Secrets accessed only by required services
- Time-bound access for temporary needs
- Audit logging enabled

## Monitoring and Auditing

### Audit Logs
- All secret access logged
- Regular audit log review
- Alert on suspicious access patterns

### Compliance
- Secrets inventory maintained
- Encryption at rest verified
- Access reviews conducted quarterly