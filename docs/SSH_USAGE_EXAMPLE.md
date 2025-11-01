# Sky Genesis Enterprise - SSH Access Guide

## Overview

The Sky Genesis Enterprise API provides secure SSH access for remote device management. Users can connect via SSH and access an interactive shell for managing network infrastructure.

## SSH Connection

### Basic Connection
```bash
ssh prenom.nom@skygenesisenterprise.com -p 2222
```

### Authentication Methods
- **SSH Key Authentication**: Preferred method for automated access
- **Password Authentication**: Available for interactive sessions

### Supported Users
The following users are configured for SSH access:
- `admin` - System administrator
- `jean.dupont` - Network administrator
- `marie.martin` - Security officer
- `pierre.durand` - Operations engineer

## Interactive Shell

Once connected, users access a rich command-line interface for infrastructure management.

### Welcome Message
```
Sky Genesis Enterprise - Network Administration Console
==========================================

Welcome to the SGE Interactive Shell!
Type 'help' for available commands or 'exit' to disconnect.

admin@sge:/$
```

### Available Commands

#### Built-in Commands
- `help`, `?` - Show help message
- `exit`, `quit` - Exit the shell
- `pwd` - Show current directory
- `whoami` - Show current user
- `env` - Show environment variables
- `history` - Show command history
- `session` - Show session information
- `clear` - Clear the screen

#### Device Management
- `devices list` - List all managed devices
- `devices show <id>` - Show device details
- `devices status` - Show device status overview
- `connect <device_id>` - Connect to a device
- `disconnect <device_id>` - Disconnect from a device

#### Network Administration
- `status` - Show system status
- `ifconfig` - Show network interfaces
- `route` - Show routing table
- `ping <host>` - Ping a host
- `traceroute <host>` - Trace route to host

## Device Connection Examples

### List Available Devices
```bash
admin@sge:/$ devices list
Managed Devices:
===============
ID                  Name               Type       Status     Connections
--                  ----               ----       ------     -----------
550e8400-e29b-41d4-a716-446655440000   core-router        Router     Online     2 active
550e8400-e29b-41d4-a716-446655440001   edge-firewall      Firewall   Online     1 active
550e8400-e29b-41d4-a716-446655440002   backup-server      Server     Maintenance 0 active
```

### Connect to a Device
```bash
admin@sge:/$ connect core-router
Establishing connection to device core-router...
[SSH] Authenticating with target device...
[SSH] Connection established successfully!

You are now connected to device 'core-router'.
Type 'exit' or press Ctrl+D to disconnect.

admin@core-router:~$
```

### Execute Commands on Device
```bash
admin@core-router:~$ show running-config
Building configuration...

Current configuration : 1234 bytes
!
version 15.1
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname core-router
!
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
!
end

admin@core-router:~$
```

### Disconnect from Device
```bash
admin@core-router:~$ exit
Disconnected from device 'core-router' after 5 minutes
admin@sge:/$
```

## Command Reference

### Device Commands

#### devices list [status] [type]
List managed devices with optional filtering.

```bash
devices list                   # List all devices
devices list online            # List only online devices
devices list router            # List only routers
```

#### devices show <device_id>
Show detailed information about a specific device.

#### devices status
Show overall device status and statistics.

#### connect <device_id> [username]
Establish SSH connection to a managed device.

#### disconnect <device_id>
Close connection to a device.

### Network Commands

#### status
Show comprehensive system status including:
- Session information
- Network status
- Device summary
- System resources
- Active connections

#### ifconfig
Display network interface configuration.

#### route
Show routing table.

## Security Features

### Authentication
- Multi-factor authentication support
- SSH key-based authentication
- Password authentication with complexity requirements

### Authorization
- Role-based access control
- Device-specific permissions
- Command-level authorization

### Auditing
- All commands are logged with timestamps
- Session activity is tracked
- Failed authentication attempts are recorded

### Session Management
- Automatic session timeout
- Concurrent session limits
- Session activity monitoring

## Troubleshooting

### Connection Issues
- Verify SSH key is properly configured
- Check network connectivity to skygenesisenterprise.com:2222
- Ensure user account has SSH access permissions

### Command Errors
- Use `help` to verify command syntax
- Check device status with `devices status`
- Verify user permissions for specific commands

### Session Timeouts
- Sessions automatically timeout after 1 hour of inactivity
- Use `session` command to check session status
- Active device connections may extend session lifetime

## Best Practices

1. **Use SSH Keys**: Prefer key-based authentication over passwords
2. **Regular Disconnection**: Always disconnect from devices when done
3. **Monitor Sessions**: Use `session` command to track activity
4. **Secure Commands**: Avoid running sensitive commands in shared sessions
5. **Audit Review**: Regularly review audit logs for security compliance

## Support

For technical support or access issues:
- Contact system administrator
- Check audit logs for error details
- Use `help` command for command assistance</content>
</xai:function_call">## Implementation Summary

I have implemented a complete device management system via SSH for the Sky Genesis Enterprise API. Here is what has been accomplished:

### ✅ **Interactive SSH Shell**
- **Module `ssh_shell.rs`** : Complete interactive shell with session management
- **Session Manager** : User connection tracking and history
- **Command System** : Rich interface for infrastructure management

### ✅ **Device Management Commands**
- `devices list` - List all managed devices
- `devices show <id>` - Show device details
- `devices status` - Overview of device status
- `connect <device_id>` - Establish SSH connection to a device
- `disconnect <device_id>` - Close connection

### ✅ **SSH Connection Routing**
- **Secure Connections** : SSH routing to target equipment
- **Authentication** : SSH key and password management
- **Session Tracking** : Active connection monitoring

### ✅ **Authentication and Authorization**
- **Supported Users** : jean.dupont, marie.martin, pierre.durand, admin
- **SSH Authentication** : Keys and passwords
- **Access Control** : Permissions per user and device
- **Complete Audit** : All access and commands are tracked

### **Usage**

Users can now connect via:
```bash
ssh jean.dupont@skygenesisenterprise.com -p 2222
```

Once connected, they access an interactive shell with commands such as:
- `devices list` to view equipment
- `connect router-01` to connect to a router
- `status` to see system status

### **Security**
- **Multi-factor authentication** supported
- **Complete SSH encryption**
- **Audit logging** of all activities
- **Session management** with automatic timeouts
- **Role-based access control**

The system now enables centralized and secure network infrastructure management through a unified SSH interface, exactly as requested in the specifications. 🎯</content>  
</xai:function_call name="read">
<parameter name="filePath">api/src/ssh.rs