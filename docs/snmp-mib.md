# SGE-MIB: Sky Genesis Enterprise MIB

## Overview

The SGE-MIB (Sky Genesis Enterprise Management Information Base) defines a set of SNMP objects for monitoring and managing the Sky Genesis Enterprise API and its associated services.

## MIB Structure

```
SGE-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, enterprises, Counter32, Gauge32, Integer32
        FROM SNMPv2-SMI
    TEXTUAL-CONVENTION, DisplayString
        FROM SNMPv2-TC;

sge MODULE-IDENTITY
    LAST-UPDATED "202412290000Z"
    ORGANIZATION "Sky Genesis Enterprise"
    CONTACT-INFO
        "Sky Genesis Enterprise
         https://skygenesisenterprise.com"
    DESCRIPTION
        "Management Information Base for Sky Genesis Enterprise API"
    ::= { enterprises 8072 1 3 2 3 }

-- SGE API Objects
sgeApi OBJECT IDENTIFIER ::= { sge 1 }

sgeApiStatus OBJECT-TYPE
    SYNTAX      DisplayString
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Current operational status of the SGE API.
         Values: 'operational', 'degraded', 'maintenance'"
    ::= { sgeApi 1 }

sgeApiUptime OBJECT-TYPE
    SYNTAX      Counter32
    UNITS       "seconds"
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Time since the SGE API was last restarted"
    ::= { sgeApi 2 }

sgeApiVersion OBJECT-TYPE
    SYNTAX      DisplayString
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Version string of the SGE API"
    ::= { sgeApi 3 }

sgeActiveConnections OBJECT-TYPE
    SYNTAX      Gauge32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Number of currently active connections to the API"
    ::= { sgeApi 4 }

sgeMemoryUsage OBJECT-TYPE
    SYNTAX      Gauge32
    UNITS       "MB"
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Current memory usage of the API process in MB"
    ::= { sgeApi 5 }

sgeCpuUsage OBJECT-TYPE
    SYNTAX      Gauge32
    UNITS       "percent"
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Current CPU usage percentage"
    ::= { sgeApi 6 }

-- SGE Services Objects
sgeServices OBJECT IDENTIFIER ::= { sge 2 }

sgeServiceTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF SgeServiceEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION
        "Table of SGE services"
    ::= { sgeServices 1 }

sgeServiceEntry OBJECT-TYPE
    SYNTAX      SgeServiceEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION
        "An entry in the SGE services table"
    INDEX       { sgeServiceIndex }
    ::= { sgeServiceTable 1 }

SgeServiceEntry ::= SEQUENCE {
    sgeServiceIndex         Integer32,
    sgeServiceName          DisplayString,
    sgeServiceStatus        INTEGER,
    sgeServiceUptime        Counter32,
    sgeServiceVersion       DisplayString,
    sgeServiceHealthScore   Gauge32
}

sgeServiceIndex OBJECT-TYPE
    SYNTAX      Integer32 (1..2147483647)
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION
        "Unique index for this service entry"
    ::= { sgeServiceEntry 1 }

sgeServiceName OBJECT-TYPE
    SYNTAX      DisplayString
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Name of the service"
    ::= { sgeServiceEntry 2 }

sgeServiceStatus OBJECT-TYPE
    SYNTAX      INTEGER {
                    up(1),
                    down(2),
                    degraded(3),
                    maintenance(4)
                }
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Current status of the service"
    ::= { sgeServiceEntry 3 }

sgeServiceUptime OBJECT-TYPE
    SYNTAX      Counter32
    UNITS       "seconds"
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Time since this service was last restarted"
    ::= { sgeServiceEntry 4 }

sgeServiceVersion OBJECT-TYPE
    SYNTAX      DisplayString
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Version of the service"
    ::= { sgeServiceEntry 5 }

sgeServiceHealthScore OBJECT-TYPE
    SYNTAX      Gauge32 (0..100)
    UNITS       "percent"
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Health score of the service (0-100)"
    ::= { sgeServiceEntry 6 }

-- SGE Security Objects
sgeSecurity OBJECT IDENTIFIER ::= { sge 3 }

sgeActiveSessions OBJECT-TYPE
    SYNTAX      Gauge32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Number of currently active user sessions"
    ::= { sgeSecurity 1 }

sgeFailedAuthAttempts OBJECT-TYPE
    SYNTAX      Counter32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Number of failed authentication attempts since startup"
    ::= { sgeSecurity 2 }

sgeActiveApiKeys OBJECT-TYPE
    SYNTAX      Gauge32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Number of currently active API keys"
    ::= { sgeSecurity 3 }

sgeEncryptionOperations OBJECT-TYPE
    SYNTAX      Counter32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Number of encryption operations performed since startup"
    ::= { sgeSecurity 4 }

-- SGE Performance Objects
sgePerformance OBJECT IDENTIFIER ::= { sge 4 }

sgeRequestsPerSecond OBJECT-TYPE
    SYNTAX      Gauge32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Current requests per second rate"
    ::= { sgePerformance 1 }

sgeAverageResponseTime OBJECT-TYPE
    SYNTAX      Gauge32
    UNITS       "milliseconds"
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Average response time for API requests"
    ::= { sgePerformance 2 }

-- SGE Network Objects
sgeNetwork OBJECT IDENTIFIER ::= { sge 5 }

sgeBytesReceived OBJECT-TYPE
    SYNTAX      Counter32
    UNITS       "bytes"
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Total bytes received since startup"
    ::= { sgeNetwork 1 }

sgeBytesSent OBJECT-TYPE
    SYNTAX      Counter32
    UNITS       "bytes"
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Total bytes sent since startup"
    ::= { sgeNetwork 2 }

sgePacketsReceived OBJECT-TYPE
    SYNTAX      Counter32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Total packets received since startup"
    ::= { sgeNetwork 3 }

sgePacketsSent OBJECT-TYPE
    SYNTAX      Counter32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Total packets sent since startup"
    ::= { sgeNetwork 4 }

sgeNetworkActiveConnections OBJECT-TYPE
    SYNTAX      Gauge32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Number of active network connections"
    ::= { sgeNetwork 5 }

sgeNetworkErrorCount OBJECT-TYPE
    SYNTAX      Counter32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
        "Number of network errors since startup"
    ::= { sgeNetwork 6 }

-- Trap Definitions
sgeTraps OBJECT IDENTIFIER ::= { sge 6 }

sgeServiceDown NOTIFICATION-TYPE
    OBJECTS     { sgeServiceName, sgeServiceStatus }
    STATUS      current
    DESCRIPTION
        "A service has gone down"
    ::= { sgeTraps 1 }

sgeHighCpuUsage NOTIFICATION-TYPE
    OBJECTS     { sgeCpuUsage }
    STATUS      current
    DESCRIPTION
        "CPU usage has exceeded threshold"
    ::= { sgeTraps 2 }

sgeLowMemory NOTIFICATION-TYPE
    OBJECTS     { sgeMemoryUsage }
    STATUS      current
    DESCRIPTION
        "Memory usage is critically low"
    ::= { sgeTraps 3 }

sgeAuthFailure NOTIFICATION-TYPE
    OBJECTS     { sgeFailedAuthAttempts }
    STATUS      current
    DESCRIPTION
        "Authentication failure detected"
    ::= { sgeTraps 4 }

sgeNetworkIssue NOTIFICATION-TYPE
    OBJECTS     { sgeNetworkErrorCount }
    STATUS      current
    DESCRIPTION
        "Network connectivity issue detected"
    ::= { sgeTraps 5 }

END
```

## OID Reference

### Base OIDs

- **SGE Enterprise OID**: `1.3.6.1.4.1.8072.1.3.2.3`
- **API Objects**: `1.3.6.1.4.1.8072.1.3.2.3.1`
- **Services Objects**: `1.3.6.1.4.1.8072.1.3.2.3.2`
- **Security Objects**: `1.3.6.1.4.1.8072.1.3.2.3.3`
- **Performance Objects**: `1.3.6.1.4.1.8072.1.3.2.3.4`
- **Network Objects**: `1.3.6.1.4.1.8072.1.3.2.3.5`
- **Traps**: `1.3.6.1.4.1.8072.1.3.2.3.6`

### Specific OIDs

| OID | Name | Description | Type |
|-----|------|-------------|------|
| 1.3.6.1.4.1.8072.1.3.2.3.1.1 | sgeApiStatus | API operational status | DisplayString |
| 1.3.6.1.4.1.8072.1.3.2.3.1.2 | sgeApiUptime | API uptime in seconds | Counter32 |
| 1.3.6.1.4.1.8072.1.3.2.3.1.3 | sgeApiVersion | API version string | DisplayString |
| 1.3.6.1.4.1.8072.1.3.2.3.1.4 | sgeActiveConnections | Active connections count | Gauge32 |
| 1.3.6.1.4.1.8072.1.3.2.3.1.5 | sgeMemoryUsage | Memory usage in MB | Gauge32 |
| 1.3.6.1.4.1.8072.1.3.2.3.1.6 | sgeCpuUsage | CPU usage percentage | Gauge32 |
| 1.3.6.1.4.1.8072.1.3.2.3.3.1 | sgeActiveSessions | Active sessions count | Gauge32 |
| 1.3.6.1.4.1.8072.1.3.2.3.3.2 | sgeFailedAuthAttempts | Failed auth attempts | Counter32 |
| 1.3.6.1.4.1.8072.1.3.2.3.3.3 | sgeActiveApiKeys | Active API keys count | Gauge32 |
| 1.3.6.1.4.1.8072.1.3.2.3.3.4 | sgeEncryptionOperations | Encryption ops count | Counter32 |
| 1.3.6.1.4.1.8072.1.3.2.3.4.1 | sgeRequestsPerSecond | RPS rate | Gauge32 |
| 1.3.6.1.4.1.8072.1.3.2.3.4.2 | sgeAverageResponseTime | Avg response time (ms) | Gauge32 |

## SNMP Configuration

### SNMPv3 Security

For secure SNMPv3 access, configure the following in Vault:

```json
{
  "snmp/v3/contexts/sge": {
    "engine_id": "hex-encoded-engine-id",
    "context_name": "sge",
    "credentials": {
      "username": "snmp-user",
      "auth_protocol": "SHA256",
      "priv_protocol": "AES256"
    }
  },
  "snmp/v3/contexts/sge/auth_key": {
    "key": "hex-encoded-auth-key"
  },
  "snmp/v3/contexts/sge/priv_key": {
    "key": "hex-encoded-priv-key"
  }
}
```

### Community Strings (v1/v2c)

For backward compatibility, community strings are stored in Vault:

```json
{
  "snmp/config/community": {
    "community": "sge-readonly"
  }
}
```

## Usage Examples

### Query API Status

```bash
snmpget -v 3 -u snmp-user -a SHA256 -A auth-password -x AES256 -X priv-password \
  -l authPriv localhost:161 1.3.6.1.4.1.8072.1.3.2.3.1.1
```

### Walk All SGE Objects

```bash
snmpwalk -v 3 -u snmp-user -a SHA256 -A auth-password -x AES256 -X priv-password \
  -l authPriv localhost:161 1.3.6.1.4.1.8072.1.3.2.3
```

### Monitor with Nagios/Icinga

```bash
# Check API status
check_snmp -H localhost -P 3 -U snmp-user -a SHA256 -A auth-password \
  -x AES256 -X priv-password -o 1.3.6.1.4.1.8072.1.3.2.3.1.1 \
  -s "operational"
```

## Trap Handling

The SGE API can send SNMP traps for important events. Configure your trap receiver to listen on UDP port 162.

### Example Trap Receiver Configuration

```bash
# snmptrapd.conf
authCommunity log,execute,net public
traphandle SGE-MIB::sgeServiceDown /usr/local/bin/handle_service_down
traphandle SGE-MIB::sgeHighCpuUsage /usr/local/bin/handle_high_cpu
```

## Security Considerations

- **SNMPv3 Only**: Use SNMPv3 with authentication and encryption for production
- **Network Isolation**: SNMP access is restricted to Tailscale VPN networks
- **Access Control**: All SNMP operations are audited and require proper authentication
- **Key Rotation**: SNMPv3 keys are automatically rotated through Vault
- **Rate Limiting**: SNMP queries are rate-limited to prevent abuse

## Implementation Notes

- The MIB is implemented as a subagent to the main SNMP daemon
- All sensitive data is retrieved from Vault at runtime
- Traps are sent asynchronously to avoid blocking operations
- The agent supports both IPv4 and IPv6
- All OIDs are read-only for security reasons