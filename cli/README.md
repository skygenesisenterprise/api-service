# Sky Genesis Enterprise CLI

Command-line interface for Sky Genesis Enterprise network administration using SSH-based JSON RPC API.

## Installation

```bash
cargo build --release
```

## Usage

### Authentication

The CLI uses SSH key authentication to connect to the Enterprise API server:

```bash
# Ensure your SSH key is available
ssh-keygen -t ed25519 -C "your-email@skygenesisenterprise.com"

# Copy public key to authorized_keys on the API server
ssh-copy-id jean.dupont@skygenesisenterprise.com
```

### Connecting to the API

```bash
# Set environment variables
export SGE_API_HOST=skygenesisenterprise.com
export SGE_API_PORT=2222
export SGE_USERNAME=jean.dupont

# Or use command-line flags
sge --host skygenesisenterprise.com --port 2222 --user jean.dupont network status
```

### Commands

#### Network Management

```bash
# Show network status
sge network status

# List network interfaces
sge network interfaces

# Show routing table
sge network routes

# Show active connections
sge network connections
```

#### VPN Management

```bash
# Show VPN status
sge vpn status

# List VPN peers
sge vpn peers

# Connect to VPN peer
sge vpn connect dc-east-01

# Disconnect from VPN peer
sge vpn disconnect dc-east-01
```

#### SNMP Management

```bash
# Show SNMP status
sge snmp status

# List SNMP agents
sge snmp agents

# Show recent traps
sge snmp traps
```

#### User Management

```bash
# List all users
sge users list

# Show user information
sge users info jean.dupont

# Create new user
sge users create marie.martin

# Delete user
sge users delete old.user
```

#### Service Management

```bash
# List all services
sge services list

# Show service status
sge services status api-server

# Restart service
sge services restart vpn-service
```

#### Monitoring

```bash
# Show system metrics
sge monitoring metrics

# Show monitoring alerts
sge monitoring alerts

# Search logs
sge logs search "error" --limit 20
```

#### Security

```bash
# Show security alerts
sge security alerts

# Show security policies
sge security policies

# Show security audit
sge security audit
```

## Configuration

Create a configuration file `~/.sge/config.toml`:

```toml
[api]
host = "skygenesisenterprise.com"
port = 2222
username = "jean.dupont"

[ssh]
key_path = "~/.ssh/id_rsa"
timeout = 30

[output]
format = "table"  # table, json, yaml
colors = true
```

## Examples

### Daily Network Check

```bash
# Check overall network status
sge network status

# Verify VPN connections
sge vpn status

# Check for security alerts
sge security alerts

# Review recent logs
sge logs tail
```

### Troubleshooting

```bash
# Check service health
sge services list

# Monitor system metrics
sge monitoring metrics

# Search for errors
sge logs search "error" --limit 50

# Check SNMP traps
sge snmp traps --limit 20
```

### User Management

```bash
# Add new network operator
sge users create paul.bernard

# Check user permissions
sge users info paul.bernard

# Audit user activity
sge logs search "paul.bernard"
```

## API Reference

The CLI communicates with the Enterprise API using JSON RPC over SSH. All commands are audited and require appropriate permissions.

### Authentication

- SSH key-based authentication
- User permissions validated against Keycloak
- All operations logged with cryptographic integrity

### Error Handling

The CLI provides clear error messages and exit codes:

- `0`: Success
- `1`: General error
- `2`: Authentication failed
- `3`: Permission denied
- `4`: Network error

## Security

- All communication encrypted with SSH
- Commands audited in real-time
- Role-based access control
- Secure credential storage in Vault

## Development

```bash
# Run tests
cargo test

# Run linter
cargo clippy

# Format code
cargo fmt
```