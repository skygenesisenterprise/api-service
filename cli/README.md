# Sky Genesis Enterprise CLI

A professional command-line interface for enterprise-grade management of Sky Genesis Enterprise API infrastructure. This tool provides secure, scalable administration capabilities for network operations, user management, security operations, and system monitoring.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [Command Reference](#command-reference)
- [Advanced Usage](#advanced-usage)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Overview

The Sky Genesis Enterprise CLI (`sge`) is a comprehensive management tool designed for enterprise environments. It provides secure remote administration capabilities through SSH tunnels, ensuring encrypted communication with your API infrastructure.

### Key Benefits

- **🔒 Enterprise Security**: Certificate-based authentication, encrypted communications
- **🏢 Multi-Tenant Support**: Manage multiple organizations and tenants
- **📊 Real-time Monitoring**: Live telemetry and health monitoring
- **🔧 Comprehensive Management**: Users, API keys, devices, networks, and more
- **⚡ High Performance**: Optimized for large-scale enterprise deployments

## Features

### Authentication & Authorization
- JWT-based authentication with secure token storage
- Certificate-coupled API key management
- Multi-tenant organization support
- Role-based access control (RBAC)

### User Management
- Complete user lifecycle management (CRUD operations)
- Role assignment and permission management
- Bulk user operations and status control

### API Key Management
- Standard and certificate-coupled API keys
- Automated key rotation and revocation
- Tenant-specific key isolation
- Certificate fingerprint verification

### Security Operations
- Cryptographic key generation (AES, RSA, Ed25519)
- Data encryption/decryption operations
- Digital signatures and verification
- Password hashing and secure random generation

### Organization Management
- Multi-tenant organization hierarchy
- Member management with role assignments
- Organization settings and quota management

### Network Administration
- Network interface monitoring and configuration
- Routing table management
- Connection tracking and bandwidth monitoring
- VPN integration (WireGuard, Tailscale)

### Device Management
- Network device inventory and discovery
- Device configuration management
- SNMP monitoring integration
- Real-time device health monitoring

### Monitoring & Telemetry
- Comprehensive log searching and analysis
- System metrics collection and alerting
- Health checks and readiness probes
- WebSocket-based real-time monitoring

## Installation

### Prerequisites

- **Rust 1.70+** with Cargo package manager
- **SSH access** to Enterprise API server
- **SSH key pair** configured for authentication
- **PostgreSQL client** libraries (for database operations)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/skygenesisenterprise/api-service.git
cd api-service/cli

# Build in release mode for optimal performance
cargo build --release

# Install globally (optional)
cargo install --path .
```

### Binary Installation

```bash
# Download the latest release
curl -L https://github.com/skygenesisenterprise/api-service/releases/latest/download/sge-cli-linux-x64 -o sge

# Make executable
chmod +x sge

# Move to system path
sudo mv sge /usr/local/bin/
```

## Configuration

### Environment Configuration

Create a configuration file at `~/.sge/config.toml`:

```toml
[ssh]
host = "your-api-server.com"
port = 22
username = "admin"
key_path = "~/.ssh/id_rsa"

[api]
host = "localhost"
port = 8080
timeout = 30
retry_attempts = 3

[logging]
level = "info"
format = "json"
file = "~/.sge/logs/sge.log"

[security]
token_storage = "~/.sge/auth.json"
certificate_validation = true
```

### Environment Variables

```bash
export SGE_SSH_HOST="your-api-server.com"
export SGE_SSH_PORT="22"
export SGE_SSH_USERNAME="admin"
export SGE_API_HOST="localhost"
export SGE_API_PORT="8080"
export SGE_LOG_LEVEL="info"
```

## Authentication

### Initial Setup

```bash
# Interactive authentication (recommended)
sge auth login

# Non-interactive with credentials
sge auth login admin@example.com --password your-password

# Certificate-based authentication
sge auth login --certificate-path ~/.ssh/cert.pem
```

### Session Management

```bash
# Check authentication status
sge auth status

# Display current user information
sge auth me

# Refresh authentication token
sge auth refresh

# Logout and clear stored credentials
sge auth logout
```

## Command Reference

### User Management

#### List Users
```bash
# List all users
sge user list

# Filter by organization
sge user list --org org-uuid

# Include inactive users
sge user list --include-inactive

# Output in JSON format
sge user list --format json
```

#### Create User
```bash
# Interactive user creation
sge user create

# With all parameters
sge user create john.doe@example.com \
  --first-name "John" \
  --last-name "Doe" \
  --roles "employee,developer" \
  --org org-uuid \
  --password \
  --send-invitation
```

#### Update User
```bash
# Update user information
sge user update user-uuid-123 \
  --email "new.email@example.com" \
  --roles "admin,developer" \
  --status active

# Reset user password
sge user update user-uuid-123 --reset-password
```

#### Delete User
```bash
# Soft delete (recommended)
sge user delete user-uuid-123

# Hard delete with confirmation
sge user delete user-uuid-123 --hard --confirm
```

### API Key Management

#### Create API Keys
```bash
# Standard API key
sge keys create client mytenant --ttl 3600 --permissions "read,write"

# Certificate-coupled API key
sge keys create client mytenant \
  --with-certificate \
  --cert-type rsa \
  --key-size 2048 \
  --ttl 7200

# Service account key
sge keys create service monitoring-service \
  --permissions "metrics:read,health:read" \
  --no-expiration
```

#### Manage API Keys
```bash
# List keys with details
sge keys list --tenant mytenant --include-expired

# Get key information
sge keys info key-uuid-123 --show-usage

# Export public key
sge keys public-key key-uuid-123 --format pem

# Revoke key
sge keys revoke key-uuid-123 --reason "Security policy"
```

### Security Operations

#### Cryptographic Operations
```bash
# Generate encryption key
sge security key-gen my-encryption-key --algorithm aes256

# Generate signing keypair
sge security sign-key-gen my-signing-key \
  --algorithm ed25519 \
  --output-format pem

# Encrypt data
echo "Sensitive data" | base64 | \
sge security encrypt my-encryption-key

# Decrypt data
sge security decrypt my-encryption-key <encrypted-base64>

# Sign data
sge security sign my-signing-key <data-base64> \
  --format base64

# Verify signature
sge security verify my-signing-key <data-base64> <signature-base64>
```

#### Password Operations
```bash
# Hash password with Argon2
sge security hash-password "secure_password" --algorithm argon2

# Generate secure random password
sge security generate-password --length 32 --include-symbols

# Generate random data
sge security random 32 --format hex
```

### Organization Management

#### Organization Operations
```bash
# List organizations
sge org list --include-stats

# Create organization
sge org create "Acme Corporation" \
  --description "Enterprise customer" \
  --domain "acme.com" \
  --max-users 500 \
  --plan enterprise

# Organization details
sge org info org-uuid-123 --include-members

# Member management
sge org members org-uuid-123 --role admin
sge org add-member org-uuid-123 user-uuid-456 --role developer
sge org remove-member org-uuid-123 user-uuid-456
```

### Network Management

#### Network Operations
```bash
# Network status overview
sge network status --detailed

# Interface information
sge network interfaces --include-stats

# Routing table
sge network routes --table main

# Connection monitoring
sge network connections --state established
```

### VPN Management

#### VPN Operations
```bash
# VPN status
sge vpn status --include-peers

# Peer management
sge vpn peers --status active
sge vpn connect peer-name --timeout 30
sge vpn disconnect peer-name

# Configuration
sge vpn config --export-file vpn.conf
```

### Device Management

#### Device Operations
```bash
# Device inventory
sge device list --status online --type router

# Add device
sge device add "Core Router" \
  --hostname "192.168.1.1" \
  --device-type "router" \
  --vendor "Cisco" \
  --model "ISR4331" \
  --tags "production,core"

# Device information
sge device info device-uuid-123 --include-metrics

# Device commands
sge device command device-uuid-123 "show running-config"
sge device metrics device-uuid-123 --last-hour
```

### Monitoring & Telemetry

#### Health and Status
```bash
# System health check
sge telemetry health --detailed

# System status
sge telemetry status --include-services

# Real-time metrics
sge telemetry metrics --stream --interval 5

# Log searching
sge telemetry logs "ERROR" \
  --since "2024-01-01" \
  --limit 100 \
  --format json

# Security alerts
sge telemetry alerts --severity critical --unresolved
```

## Advanced Usage

### Certificate-Based Authentication Flow

1. **Generate certificate-enabled API key:**
```bash
sge keys create client production \
  --with-certificate \
  --cert-type rsa \
  --key-size 4096 \
  --ttl 86400
```

2. **Extract certificate components:**
```bash
# Get public key
sge keys public-key key-uuid-123 --format pem > public.pem

# Get certificate chain
sge keys certificate key-uuid-123 --chain > chain.pem

# Get fingerprint
sge keys fingerprint key-uuid-123 --format sha256
```

3. **Use in applications:**
```bash
# Example curl with certificate
curl -X GET https://api.example.com/endpoint \
  --cert public.pem \
  --key private.pem \
  --cacert chain.pem \
  -H "Authorization: Bearer <api-key>"
```

### Bulk Operations

#### User Bulk Operations
```bash
# Bulk user creation from CSV
cat users.csv | while IFS=, read email first last role org; do
  sge user create "$email" \
    --first-name "$first" \
    --last-name "$last" \
    --roles "$role" \
    --org "$org"
done

# Bulk role assignment
sge user bulk-update --role developer --org org-uuid-123
```

#### API Key Bulk Operations
```bash
# Rotate all keys for tenant
sge keys rotate-all --tenant mytenant --confirm

# Revoke expired keys
sge keys cleanup --expired --older-than 30d
```

### Monitoring Integration

#### Prometheus Integration
```bash
# Export metrics for Prometheus
sge telemetry prometheus --port 9090

# Custom metrics endpoint
sge telemetry metrics --endpoint /metrics --format prometheus
```

#### Health Check Integration
```bash
# Kubernetes readiness probe
sge telemetry ready --timeout 5

# Load balancer health check
sge telemetry health --endpoint /healthz --format json
```

### Automation Scripts

#### Backup Script
```bash
#!/bin/bash
# backup-sge.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/sge/$DATE"

mkdir -p "$BACKUP_DIR"

# Backup users
sge user list --format json > "$BACKUP_DIR/users.json"

# Backup API keys
sge keys list --format json > "$BACKUP_DIR/api-keys.json"

# Backup organizations
sge org list --format json > "$BACKUP_DIR/organizations.json"

# Backup device configurations
sge device list --format json > "$BACKUP_DIR/devices.json"

echo "Backup completed: $BACKUP_DIR"
```

## Security Best Practices

### Authentication Security
1. **SSH Key Management**: Use Ed25519 keys with strong passphrases
2. **Token Storage**: Tokens are encrypted at rest in `~/.sge/auth.json`
3. **Certificate Validation**: Always verify certificate fingerprints
4. **Regular Rotation**: Rotate API keys and certificates every 90 days
5. **Multi-Factor Authentication**: Enable MFA for all admin accounts

### Network Security
1. **Encrypted Communication**: All CLI communications use SSH tunnels
2. **Certificate Pinning**: Verify server certificates against known fingerprints
3. **Network Isolation**: Use VPN for remote management when possible
4. **Audit Logging**: All operations are logged with timestamps and user context

### Data Protection
1. **Sensitive Data**: Never log passwords, tokens, or private keys
2. **Secure Storage**: Use hardware security modules (HSM) for production keys
3. **Access Control**: Implement principle of least privilege
4. **Regular Audits**: Review access logs and permission assignments

## Troubleshooting

### Connection Issues

#### SSH Connection Problems
```bash
# Test SSH connectivity
ssh -v -T admin@your-api-server.com

# Check SSH configuration
cat ~/.ssh/config

# Verify key permissions
ls -la ~/.ssh/id_rsa*
```

#### API Connection Issues
```bash
# Test API connectivity
curl -k https://localhost:8080/health

# Check configuration
sge config show

# Test with verbose output
sge telemetry health --verbose
```

### Authentication Problems

#### Token Issues
```bash
# Check authentication status
sge auth status --verbose

# Clear cached credentials
sge auth logout --clear-cache

# Re-authenticate
sge auth login --force
```

#### Certificate Issues
```bash
# Verify certificate
openssl x509 -in cert.pem -text -noout

# Check certificate chain
openssl verify -CAfile ca.pem cert.pem

# Test certificate authentication
sge auth test-certificate --cert cert.pem --key key.pem
```

### Performance Issues

#### Slow Operations
```bash
# Enable performance logging
export SGE_LOG_LEVEL=debug
export RUST_LOG=debug

# Profile operations
sge telemetry profile --operation user-list

# Check system resources
sge telemetry system-stats
```

### Common Error Messages

| Error | Cause | Solution |
|--------|-------|----------|
| `Authentication failed` | Invalid credentials | Check username/password or SSH key |
| `Connection timeout` | Network issues | Verify connectivity and firewall settings |
| `Permission denied` | Insufficient privileges | Check user roles and API key permissions |
| `Certificate expired` | Expired certificate | Rotate certificate or API key |
| `Rate limit exceeded` | Too many requests | Wait and retry, or increase rate limits |

## Contributing

We welcome contributions to the Sky Genesis Enterprise CLI. Please follow these guidelines:

### Development Setup
```bash
# Clone repository
git clone https://github.com/skygenesisenterprise/api-service.git
cd api-service/cli

# Install development dependencies
cargo install cargo-watch cargo-tarpaulin

# Run tests
cargo test

# Run with hot reload
cargo watch -x run
```

### Code Standards
- Follow Rust coding standards and conventions
- Use `cargo fmt` for code formatting
- Use `cargo clippy` for linting
- Include comprehensive unit tests
- Add integration tests for new features
- Update documentation for API changes

### Submitting Changes
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make your changes and add tests
4. Ensure all tests pass: `cargo test`
5. Commit with conventional commit format
6. Push to your fork and create a pull request

### Testing
```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration

# Generate coverage report
cargo tarpaulin --out Html

# Run benchmarks
cargo bench
```

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Support

- **Documentation**: [Sky Genesis Enterprise Docs](https://docs.skygenesisenterprise.com)
- **Issues**: [GitHub Issues](https://github.com/skygenesisenterprise/api-service/issues)
- **Discussions**: [GitHub Discussions](https://github.com/skygenesisenterprise/api-service/discussions)
- **Email**: support@skygenesisenterprise.com

---

**Sky Genesis Enterprise CLI** - Professional infrastructure management for modern enterprises.