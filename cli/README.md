# Sky Genesis Enterprise CLI

A comprehensive command-line interface for managing the Sky Genesis Enterprise API infrastructure via SSH. This tool provides enterprise-grade administration capabilities for network management, user access control, security operations, and system monitoring.

## Features

### 🔐 Authentication & Authorization
- JWT-based authentication with secure token storage
- Certificate-coupled API key management
- Multi-tenant organization support
- Role-based access control

### 👥 User Management
- Create, list, update, and delete users
- Role assignment and permission management
- User status control (enable/disable)

### 🔑 API Key Management
- Standard and certificate-coupled API keys
- Key rotation and revocation
- Tenant-specific key management
- Certificate fingerprint verification

### 🔒 Security Operations
- Cryptographic key generation (encryption/signing)
- Data encryption/decryption
- Digital signatures and verification
- Password hashing and verification
- Key exchange protocols
- Random data generation

### 🏢 Organization Management
- Multi-tenant organization support
- Member management and role assignment
- Organization settings and limits

### 🌐 Network Administration
- Network interface monitoring
- Routing table management
- Connection tracking
- Bandwidth monitoring

### 🔗 VPN Management
- WireGuard and Tailscale integration
- Peer management and connection handling
- VPN status monitoring

### 📧 Mail Services
- Mail service status monitoring
- Test email sending
- SMTP configuration management

### 🔍 Search & Monitoring
- Log searching and analysis
- System metrics collection
- Security alerts monitoring
- Health checks and readiness probes

### 📱 Device Management
- Network device inventory
- Device configuration management
- SNMP monitoring integration

## Installation

### Prerequisites
- Rust 1.70+ with Cargo
- SSH access to the Enterprise API server
- SSH key pair configured for authentication

### Build from Source
```bash
git clone <repository-url>
cd cli
cargo build --release
```

### Configuration
Create a configuration file at `cli/.env`:
```toml
ssh_host = "your-api-server.com"
ssh_port = 22
ssh_username = "admin"
api_host = "localhost"
api_port = 8080
```

## Authentication

### Login
```bash
# Interactive login (prompts for password)
sge auth login admin@example.com

# Login with password as argument
sge auth login admin@example.com --password mypassword
```

### Check Authentication Status
```bash
sge auth status
```

### Get Current User Info
```bash
sge auth me
```

### Logout
```bash
sge auth logout
```

## User Management

### List Users
```bash
sge user list
```

### Create User
```bash
sge user create john.doe@example.com \
  --first-name "John" \
  --last-name "Doe" \
  --roles "employee,developer" \
  --password
```

### Update User
```bash
sge user update user-uuid-123 \
  --email "new.email@example.com" \
  --roles "admin,developer"
```

### Delete User
```bash
sge user delete user-uuid-123 --confirm
```

## API Key Management

### Create Standard API Key
```bash
sge keys create client mytenant --ttl 3600
```

### Create Certificate-Coupled API Key
```bash
sge keys create client mytenant \
  --with-certificate \
  --cert-type rsa \
  --ttl 3600
```

### List API Keys
```bash
sge keys list --tenant mytenant
```

### Get API Key Info
```bash
sge keys info key-uuid-123
```

### Get Public Key
```bash
sge keys public-key key-uuid-123
```

### Revoke API Key
```bash
sge keys revoke key-uuid-123 --confirm
```

## Security Operations

### Generate Encryption Key
```bash
sge security key-gen my-encryption-key
```

### Generate Signing Keypair
```bash
sge security sign-key-gen my-signing-key --key-type ed25519
```

### Encrypt Data
```bash
echo -n "Hello, World!" | base64
# Output: SGVsbG8sIFdvcmxkIQ==

sge security encrypt my-encryption-key SGVsbG8sIFdvcmxkIQ==
```

### Decrypt Data
```bash
sge security decrypt my-encryption-key <encrypted-data>
```

### Sign Data
```bash
sge security sign my-signing-key SGVsbG8sIFdvcmxkIQ==
```

### Verify Signature
```bash
sge security verify my-signing-key SGVsbG8sIFdvcmxkIQ== <signature>
```

### Hash Password
```bash
sge security hash-password "my_secure_password"
```

### Generate Random Data
```bash
sge security random 32
```

## Organization Management

### List Organizations
```bash
sge org list
```

### Create Organization
```bash
sge org create "My Company" \
  --description "Enterprise organization" \
  --domain "mycompany.com" \
  --max-users 100
```

### List Organization Members
```bash
sge org members org-uuid-123
```

### Add Member to Organization
```bash
sge org add-member org-uuid-123 user-uuid-456 --role admin
```

## Network Management

### Show Network Status
```bash
sge network status
```

### List Network Interfaces
```bash
sge network interfaces
```

### Show Routing Table
```bash
sge network routes
```

## VPN Management

### Show VPN Status
```bash
sge vpn status
```

### List VPN Peers
```bash
sge vpn peers
```

### Connect to VPN Peer
```bash
sge vpn connect peer-name
```

## Monitoring & Health Checks

### System Health Check
```bash
sge telemetry health
```

### Detailed System Status
```bash
sge telemetry status
```

### System Metrics
```bash
sge telemetry metrics
```

### Search Logs
```bash
sge telemetry logs "ERROR" --limit 50
```

### Security Alerts
```bash
sge telemetry alerts
```

### WebSocket Status
```bash
sge telemetry ws-status
```

## Device Management

### List Devices
```bash
sge device list
```

### Add Device
```bash
sge device add "Router-01" \
  --hostname "192.168.1.1" \
  --device-type "router" \
  --tags "production,core"
```

### Get Device Info
```bash
sge device info device-uuid-123
```

## Advanced Usage

### Certificate-Coupled Authentication Flow

1. **Create certificate-enabled API key:**
```bash
sge keys create client mytenant --with-certificate --cert-type rsa
```

2. **Retrieve certificate information:**
```bash
sge keys public-key <key-id>
```

3. **Use in applications with certificate signing**

### Bulk Operations

Use shell scripting for bulk operations:
```bash
# Bulk user creation
cat users.csv | while IFS=, read email first last role; do
  sge user create "$email" --first-name "$first" --last-name "$last" --roles "$role"
done
```

### Monitoring Integration

Integrate with monitoring systems:
```bash
# Health check for load balancers
sge telemetry ready

# Prometheus metrics export
sge telemetry prometheus
```

## Security Best Practices

1. **SSH Key Management**: Use strong SSH keys with appropriate permissions
2. **Token Storage**: Tokens are stored securely in `~/.sge/auth.json`
3. **Certificate Validation**: Always verify certificate fingerprints
4. **Regular Rotation**: Rotate API keys and certificates regularly
5. **Audit Logging**: All operations are logged for compliance

## Troubleshooting

### Connection Issues
```bash
# Check SSH connectivity
ssh -T admin@your-api-server.com

# Verify configuration
cat cli/.env
```

### Authentication Problems
```bash
# Check token status
sge auth status

# Re-authenticate
sge auth logout
sge auth login your-email@example.com
```

### Permission Errors
```bash
# Check user roles
sge auth me

# Verify API key permissions
sge keys info <key-id>
```

## Contributing

1. Follow Rust coding standards
2. Add comprehensive error handling
3. Include unit tests for new features
4. Update documentation for API changes

## License

This project is licensed under the MIT License - see the LICENSE file for details.