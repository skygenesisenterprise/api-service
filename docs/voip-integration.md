# VoIP Integration with Sky Genesis Enterprise API

## Overview

The Sky Genesis Enterprise API provides comprehensive VoIP (Voice over IP) and real-time communication features, enabling seamless integration with PBX (Private Branch Exchange) environments. This documentation explains how to use and integrate the API for voice, video, and instant messaging communications within PBX infrastructures.

## Architecture

The API implements a hybrid architecture combining Asterisk PBX as the official VoIP management server with WebRTC for client-side signaling and media transport:

### Main Components
- **Asterisk PBX**: Official VoIP and PBX management server
- **ARI (Asterisk REST Interface)**: Programmatic control interface
- **WebRTC Signaling**: Real-time signaling via REST API
- **WebSocket/XMPP**: Presence and instant messaging
- **SRTP/DTLS**: End-to-end media encryption

### Architecture Flow
```
[WebRTC Client] <─── Signaling ───> [SGE API] <─── ARI ───> [Asterisk PBX]
       │                                        │
       └────────────── RTP/SRTP ────────────────┘
```

## VoIP Security and Certificates

### TLS Encryption and Mutual Authentication

The Sky Genesis VoIP integration implements multiple layers of cryptographic security:

#### ARI Interface Security (mTLS)
- **Mutual TLS Authentication**: Both client and server authenticate using X.509 certificates
- **Certificate Validation**: Full certificate chain validation with revocation checking
- **Perfect Forward Secrecy**: TLS 1.3 with ephemeral key exchange

#### Media Encryption
- **SRTP**: Secure RTP for audio/video streams
- **DTLS**: Datagram TLS for WebRTC media encryption
- **End-to-End Encryption**: Media encrypted from client to Asterisk PBX

#### Client Certificate Authentication
- **SIP Clients**: Certificate-based authentication for SIP endpoints
- **WebRTC Clients**: Certificate validation for browser-based VoIP
- **Federation Peers**: Mutual authentication between federated offices

### Certificate Management

#### Certificate Types
- **ARI Client Certificates**: For SGE API to Asterisk ARI communication
- **VoIP Client Certificates**: For SIP/WebRTC endpoint authentication
- **Federation Certificates**: For inter-office secure communication

#### Certificate Lifecycle
- **Issuance**: Automated certificate generation via Vault PKI
- **Rotation**: Automatic renewal before expiration
- **Revocation**: Immediate revocation of compromised certificates
- **Validation**: Real-time certificate validation and CRL checking

### Security Configuration

#### Asterisk TLS Configuration
```ini
; /etc/asterisk/sip.conf or pjsip.conf
[transport-tls]
type = transport
protocol = tls
bind = 0.0.0.0:5061
cert_file = /etc/asterisk/keys/asterisk.crt
priv_key_file = /etc/asterisk/keys/asterisk.key
cafile = /etc/asterisk/keys/ca.crt
verify_client = yes
require_client_cert = yes
method = tlsv1_2,tlsv1_3
```

#### Client Certificate Generation
```bash
# Generate client certificate for VoIP endpoint
openssl req -new -newkey rsa:2048 -days 365 -nodes \
  -subj "/C=BE/O=Sky Genesis/CN=voip-client" \
  -keyout voip-client.key -out voip-client.csr

# Sign with CA
openssl x509 -req -in voip-client.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out voip-client.crt -days 365 -sha256
```

### Supported Features
- **Native SIP Calls**: Full management via Asterisk
- **Conferences**: Asterisk bridges for multi-participant rooms
- **SIP Trunks**: Connection to operators and external PBXs
- **Extensions**: User and device management
- **Dialplan**: Intelligent call routing
- **Recording**: Audio capture of communications
- **Monitoring**: Real-time metrics and supervision

## Prerequisites

### Authentication
All VoIP requests require authentication via JWT or API key:

```bash
Authorization: Bearer <jwt_token>
# or
X-API-Key: <api_key>
```

### Asterisk PBX Environment
- **Asterisk 18+** with ARI module enabled
- **ARI Configuration** in `/etc/asterisk/ari.conf`
- **TLS Certificates** for secure communications (mTLS supported)
- **Network Ports**: 5060 (SIP), 8088 (ARI), UDP range 10000-20000 (RTP)
- **chan_sip or chan_pjsip module** configured
- **Stasis Application** defined for SGE integration
- **Client Certificates** for VoIP endpoints (SIP/WebRTC)

### Asterisk Dependencies
- **Asterisk**: Official PBX server
- **ARI (Asterisk REST Interface)**: Control API
- **WebRTC**: Client-side media transport
- **WebSocket**: Real-time signaling
- **SRTP/DTLS**: Media encryption
- **SIP/PJSIP**: Signaling protocols

## Asterisk Configuration

### ARI Configuration (`/etc/asterisk/ari.conf`)
```ini
[general]
enabled = yes
bindaddr = 0.0.0.0
bindport = 8088
tlsenable = yes
tlscertfile = /etc/asterisk/keys/asterisk.crt
tlsprivatekey = /etc/asterisk/keys/asterisk.key
# Mutual TLS configuration
tlsclientcert = /etc/asterisk/keys/client.crt
tlsclientkey = /etc/asterisk/keys/client.key
tlscafile = /etc/asterisk/keys/ca.crt
tlsverifyclient = yes

[skygenesisenterprise]
type = user
read_only = no
password = your_secure_password
```

### SIP Configuration (`/etc/asterisk/sip.conf` or `pjsip.conf`)
```ini
[skygenesisenterprise-trunk]
type = peer
host = dynamic
context = skygenesisenterprise-voip
disallow = all
allow = ulaw,alaw,g729
dtmfmode = rfc4733
qualify = yes

[1001]
type = friend
host = dynamic
context = sky-genesis-voip
secret = user_password
disallow = all
allow = ulaw,alaw,opus
```

### Stasis Application (`/etc/asterisk/extensions.conf`)
```ini
[skygenesisenterprise-voip]
exten => _X.,1,NoOp(SGE Call: ${EXTEN})
exten => _X.,n,Stasis(skygenesisenterprise-voip)
exten => _X.,n,Hangup()
```

### API Environment Variables
```bash
ASTERISK_ARI_URL=https://localhost:8088/ari
ASTERISK_ARI_USERNAME=skygenesisenterprise
ASTERISK_ARI_PASSWORD=your_secure_password
ASTERISK_ARI_APP=skygenesisenterprise-voip
# TLS Configuration for mTLS
ASTERISK_TLS_ENABLED=true
ASTERISK_CLIENT_CERT=/etc/ssl/sge/voip-client.crt
ASTERISK_CLIENT_KEY=/etc/ssl/sge/voip-client.key
ASTERISK_CA_CERT=/etc/ssl/sge/ca.crt
```

## VoIP API Endpoints

### Asterisk Call Management

#### Initiate a call via Asterisk
```http
POST /api/v1/voip/calls
Authorization: Bearer <token>
Content-Type: application/json

{
  "participants": ["SIP/1001", "SIP/1002"],
  "call_type": "audio"
}
```

**Supported call types:**
- `audio`: Voice call via SIP/RTP
- `video`: Call with video (WebRTC)
- `screen`: Screen sharing (WebRTC)

**Participant formats:**
- `SIP/{extension}`: Local SIP extension
- `PJSIP/{endpoint}`: PJSIP endpoint
- `{tech}/{resource}`: Generic Asterisk format

#### Accept a call
```http
POST /api/v1/voip/calls/{call_id}/accept
Authorization: Bearer <token>
```

#### End a call
```http
POST /api/v1/voip/calls/{call_id}/end
Authorization: Bearer <token>
```

#### Get call information
```http
GET /api/v1/voip/calls/{call_id}
Authorization: Bearer <token>
```

#### List active calls
```http
GET /api/v1/voip/calls
Authorization: Bearer <token>
```

### Asterisk Conference Room Management

#### Create a room (Asterisk Bridge)
```http
POST /api/v1/voip/rooms
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Team Meeting",
  "max_participants": 10,
  "settings": {
    "allow_recording": true,
    "allow_screen_share": true,
    "require_moderator": false,
    "bridge_type": "mixing"
  }
}
```

**Asterisk bridge types:**
- `mixing`: Standard audio conference
- `holding`: Holding queue
- `dtmf_events`: DTMF detection
- `proxy_media`: Advanced media proxy

#### Join a room
```http
POST /api/v1/voip/rooms/{room_id}/join
Authorization: Bearer <token>
```

#### Get room information
```http
GET /api/v1/voip/rooms/{room_id}
Authorization: Bearer <token>
```

#### List active rooms
```http
GET /api/v1/voip/rooms
Authorization: Bearer <token>
```

### WebRTC Signaling

#### Send a signaling message
```http
POST /api/v1/voip/calls/{call_id}/signaling
Authorization: Bearer <token>
Content-Type: application/json

{
  "to_user": "user456",
  "message_type": "offer",
  "payload": {
    "sdp": "v=0\r\no=- 12345 67890 IN IP4 192.168.1.1\r\n...",
    "type": "offer"
  }
}
```

**Supported message types:**
- `offer`: WebRTC SDP offer
- `answer`: WebRTC SDP answer
- `ice_candidate`: ICE candidate
- `hangup`: Hang up
- `mute` / `unmute`: Audio control

#### Retrieve signaling messages
```http
GET /api/v1/voip/calls/{call_id}/signaling
Authorization: Bearer <token>
```

## Integration with Asterisk PBX

### Integration Architecture

```
[Asterisk PBX] <─── ARI ───> [SGE API] <─── WebRTC ───> [Web/Mobile Clients]
       │                           │
       ├─ SIP Trunks ──────────────┘
       ├─ Extensions ──────────────┘
       ├─ Conferences ─────────────┘
       └─ Call Recordings ─────────┘
```

### Typical Call Flow
1. **Client** → **SGE API**: Call request
2. **SGE API** → **Asterisk ARI**: Channel creation
3. **Asterisk** → **Client**: SIP/WebRTC connection
4. **Media**: Direct RTP/SRTP stream or via Asterisk

### Advanced Asterisk Configuration

#### Extensions with Stasis (`/etc/asterisk/extensions.conf`)
```ini
[sky-genesis-voip]
; Incoming call to extension
exten => _X.,1,NoOp(SGE Call to ${EXTEN})
exten => _X.,n,Set(SGE_USER_ID=${EXTEN})
exten => _X.,n,Stasis(sky-genesis-voip)
exten => _X.,n,Hangup()

; Conference
exten => _9XXX,1,NoOp(Conference ${EXTEN})
exten => _9XXX,1,Set(CONF_ID=${EXTEN:1})
exten => _9XXX,n,Stasis(sky-genesis-conference,${CONF_ID})
exten => _9XXX,n,Hangup()

; Outgoing call
exten => _0X.,1,NoOp(Outgoing call to ${EXTEN:1})
exten => _0X.,n,Set(DEST_NUM=${EXTEN:1})
exten => _0X.,n,Stasis(sky-genesis-outbound,${DEST_NUM})
exten => _0X.,n,Hangup()
```

#### PJSIP Configuration (`/etc/asterisk/pjsip.conf`)
```ini
[transport-udp]
type = transport
protocol = udp
bind = 0.0.0.0:5060

[skygenesisenterprise-endpoint]
type = endpoint
context = skygenesisenterprise-voip
disallow = all
allow = ulaw,alaw,opus,g729
auth = skygenesisenterprise-auth
aors = skygenesisenterprise-aor
direct_media = no
rtp_timeout = 30
send_pai = yes

[skygenesisenterprise-auth]
type = auth
auth_type = userpass
password = secure_password
username = skygenesisenterprise

[skygenesisenterprise-aor]
type = aor
max_contacts = 1
remove_existing = yes
```

### AGI Integration Script (dialplan)

#### AGI Python Script (`/var/lib/asterisk/agi-bin/sge-voip-integration.py`)
```python
#!/usr/bin/env python3
import sys
import requests
import json
import os

# Configuration
SGE_API_URL = os.getenv('SGE_API_URL', 'http://localhost:8080/api/v1/voip')
SGE_JWT_TOKEN = os.getenv('SGE_JWT_TOKEN')

def main():
    # Retrieve AGI arguments
    agi_env = {}
    for line in sys.stdin:
        line = line.strip()
        if line == '':
            break
        key, value = line.split(': ', 1)
        agi_env[key] = value

    call_id = agi_env.get('agi_uniqueid')
    extension = agi_env.get('agi_extension')
    caller_id = agi_env.get('agi_callerid')

    # Create call via SGE API
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {SGE_JWT_TOKEN}'
    }

    call_data = {
        'participants': [f'SIP/{extension}'],
        'call_type': 'audio',
        'metadata': {
            'asterisk_call_id': call_id,
            'caller_id': caller_id
        }
    }

    try:
        response = requests.post(
            f'{SGE_API_URL}/calls',
            headers=headers,
            json=call_data,
            timeout=5
        )

        if response.status_code == 201:
            call_info = response.json()
            # Return call ID to Asterisk
            print(f"SET VARIABLE SGE_CALL_ID {call_info['id']}")
            print(f"SET VARIABLE SGE_CHANNEL_ID {call_info['metadata']['asterisk_channel_id']}")
        else:
            print("SET VARIABLE SGE_ERROR \"API call failed\"")

    except Exception as e:
        print(f"SET VARIABLE SGE_ERROR \"Integration error: {str(e)}\"")

if __name__ == '__main__':
    main()
```

#### AGI Configuration in dialplan
```ini
[skygenesisenterprise-voip]
exten => _X.,1,NoOp(SGE Call: ${EXTEN})
exten => _X.,n,AGI(sge-voip-integration.py)
exten => _X.,n,GotoIf($["${SGE_ERROR}" != ""]?error)
exten => _X.,n,Dial(SIP/${EXTEN},30)
exten => _X.,n,Hangup()

exten => error,1,Playback(invalid)
exten => error,n,Hangup()
```

### Client-side WebRTC Integration

#### WebRTC Configuration
```javascript
// STUN/TURN configuration for NAT traversal
const rtcConfiguration = {
    iceServers: [
        { urls: 'stun:stun.skygenesisenterprise.com:19302' },
        {
            urls: 'turn:turn.skygenesisenterprise.com:3478',
            username: 'user',
            credential: 'password'
        }
    ]
};

// Create peer connection
const peerConnection = new RTCPeerConnection(rtcConfiguration);

// ICE candidate handling
peerConnection.onicecandidate = (event) => {
    if (event.candidate) {
        // Send candidate via signaling
        sendSignalingMessage(callId, 'ice_candidate', {
            candidate: event.candidate
        });
    }
};

// Media track handling
peerConnection.ontrack = (event) => {
    // Add audio/video stream to interface
    const remoteVideo = document.getElementById('remote-video');
    remoteVideo.srcObject = event.streams[0];
};
```

#### Typical Call Flow
```javascript
async function initiateCall(participants, callType) {
    // 1. Create call via API
    const callResponse = await fetch('/api/v1/voip/calls', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${jwtToken}`
        },
        body: JSON.stringify({
            participants,
            call_type: callType
        })
    });

    const callData = await callResponse.json();
    const callId = callData.id;

    // 2. Create WebRTC connection
    const peerConnection = new RTCPeerConnection(rtcConfiguration);

    // 3. Add local tracks
    const localStream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: callType === 'video'
    });

    localStream.getTracks().forEach(track => {
        peerConnection.addTrack(track, localStream);
    });

    // 4. Create and send offer
    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);

    await sendSignalingMessage(callId, 'offer', offer);

    return { callId, peerConnection };
}
```

### Presence Management

#### WebSocket Connection for Presence
```javascript
const ws = new WebSocket('wss://api.skygenesisenterprise.com/ws/auth?token=' + jwtToken);

ws.onopen = () => {
    // Subscribe to presence
    ws.send(JSON.stringify({
        type: 'Subscribe',
        channel: 'presence:user123'
    }));

    // Update status
    updatePresence('online', 'Available for calls');
};

function updatePresence(status, message) {
    ws.send(JSON.stringify({
        type: 'PresenceUpdate',
        user_id: 'user123',
        status,
        status_message: message
    }));
}
```

## Metrics and Asterisk Monitoring

### Extended VoIP SNMP Metrics
The API exposes detailed VoIP metrics via SNMP:

```bash
# Active Asterisk calls
snmpget -v2c -c public localhost 1.3.6.1.4.1.8072.1.3.2.3.2.1.1.1

# Active channels
snmpget -v2c -c public localhost 1.3.6.1.4.1.8072.1.3.2.3.2.1.2.1

# Active bridges (rooms)
snmpget -v2c -c public localhost 1.3.6.1.4.1.8072.1.3.2.3.2.1.3.1

# Registered SIP endpoints
snmpget -v2c -c public localhost 1.3.6.1.4.1.8072.1.3.2.3.2.1.4.1

# Call quality (MOS Score)
snmpget -v2c -c public localhost 1.3.6.1.4.1.8072.1.3.2.3.2.1.9.1
```

### Asterisk ARI Metrics
```bash
# Asterisk system information
curl -u sky-genesis:password http://localhost:8088/ari/asterisk/info

# List active channels
curl -u sky-genesis:password http://localhost:8088/ari/channels

# List bridges
curl -u sky-genesis:password http://localhost:8088/ari/bridges

# System health
curl -u sky-genesis:password http://localhost:8080/api/v1/voip/asterisk/health
```

### Prometheus Metrics
```bash
# Call metrics
curl http://localhost:8080/api/v1/metrics/prometheus | grep voip
```

## SSO Integration and Roaming Extensions

### Single Sign-On (SSO)

The VoIP API seamlessly integrates with Sky Genesis Enterprise's single sign-on system, allowing users to access VoIP features with their enterprise credentials from any workstation.

#### SSO Integration Benefits
- **Transparent Authentication**: Use the same credentials for all services
- **Centralized Management**: VoIP rights administration via enterprise identity system
- **Unified Audit**: VoIP access traceability in enterprise logs
- **Enhanced Security**: Application of enterprise security policies

#### SSO Authentication Flow
```
[User] → [Enterprise Portal] → [Keycloak SSO] → [SGE VoIP API]
      │                      │                      │
      └─ Credentials ────────┼─ JWT Token ──────────┼─ VoIP Access
                             │                      │
                             └─ Policies ──────────┼─ User Rights
                                                    │
                                                    └─ Persistent Session
```

### Roaming Extensions

The roaming extensions system allows users to use their internal enterprise number from any registered device.

#### Roaming Extensions Features
- **Fixed Personal Number**: Each user keeps their internal number
- **Multi-Device**: Registration of multiple devices per user
- **Intelligent Routing**: Calls directed to the appropriate active device
- **Unified Presence**: Availability status synchronized across devices
- **International Extensions**: Support for country code prefixes (e.g., 32-1001 for Belgium)

#### User Extension Management

##### Assign an Extension
```http
POST /api/v1/voip/extensions
Authorization: Bearer <token>
Content-Type: application/json

{
  "extension": "1001",
  "display_name": "John Doe"
}
```

**International Extension Format:**
Extensions can include country code prefixes with flexible local extension formats:
- `"32-1001"` - Belgium extension 1001
- `"1-555"` - US extension 555
- `"33-2001"` - France extension 2001
- `"32-001-00-00-00"` - Complex Belgian VoIP number (country-enterprise-local)
- `"1-800-123-4567"` - US toll-free with area code

##### Get Supported Country Codes
```http
GET /api/v1/voip/country-codes
Authorization: Bearer <token>
```

Returns a list of supported country codes with their names.

##### Get Extensions by Country
```http
GET /api/v1/voip/extensions/country/{country_code}
Authorization: Bearer <token>
```

Example: `GET /api/v1/voip/extensions/country/32` returns all Belgian extensions.

##### Get All Extensions with Country Info
```http
GET /api/v1/voip/extensions/with-country-info
Authorization: Bearer <token>
```

Returns all extensions with their country code and country name information.

##### Parse Extension Structure
```http
GET /api/v1/voip/extensions/parse/{extension}
Authorization: Bearer <token>
```

Analyzes and breaks down an extension into its components. Example for `32-001-00-00-00`:

```json
{
  "country_code": "32",
  "country_name": "Belgium",
  "local_extension": "001-00-00-00",
  "full_extension": "32-001-00-00-00",
  "parts": ["32", "001", "00", "00", "00"]
}
```

##### Retrieve Extension
```http
GET /api/v1/voip/extensions
Authorization: Bearer <token>
```

#### Device Registration

##### Register a New Device
```http
POST /api/v1/voip/devices
Authorization: Bearer <token>
Content-Type: application/json

{
  "device_name": "Main Office",
  "endpoint_type": "desktop",
  "endpoint_uri": "SIP/1001@desktop-office"
}
```

**Supported Device Types:**
- `sip`: Traditional SIP phone
- `webrtc`: WebRTC client (browser, web app)
- `mobile`: Mobile application
- `desktop`: Desktop application

##### List Registered Devices
```http
GET /api/v1/voip/devices
Authorization: Bearer <token>
```

##### Update Device Presence
```http
PUT /api/v1/voip/devices/{device_id}/presence
Authorization: Bearer <token>
Content-Type: application/json

true  # or false to mark offline
```

#### Presence Management

##### Update Presence Status
```http
PUT /api/v1/voip/presence
Authorization: Bearer <token>
Content-Type: application/json

{
  "status": "online",
  "status_message": "Available for calls",
  "current_device": "desktop-office"
}
```

**Supported Presence Statuses:**
- `online`: Online and available
- `away`: Away
- `busy`: Busy
- `offline`: Offline
- `do_not_disturb`: Do not disturb

##### Check Presence Status
```http
GET /api/v1/voip/presence
Authorization: Bearer <token>
```

#### Intelligent Call Routing

The system automatically determines the appropriate device to route incoming calls to:

1. **Extension Verification**: User must have an assigned extension
2. **Active Device Evaluation**: Search for online devices
3. **Device Selection**: Choice based on presence and preferences
4. **Fallback Routing**: Fallback to SIP/{extension} if no active device

```rust
// Endpoint resolution logic
async fn resolve_user_endpoint(user_id: &str) -> Result<String, String> {
    // 1. Check user extension
    if let Some(extension) = get_user_extension(user_id).await {
        if !extension.enabled {
            return Err("Extension disabled".to_string());
        }

        // 2. Find active devices
        let devices = get_user_devices(user_id).await;
        let online_devices: Vec<&DeviceRegistration> = devices.iter()
            .filter(|d| d.is_online)
            .collect();

        if online_devices.is_empty() {
            // 3. Fallback to default SIP endpoint
            return Ok(format!("SIP/{}", extension.extension));
        }

        // 4. Select first active device
        Ok(online_devices[0].endpoint_uri.clone())
    } else {
        Err("No extension assigned".to_string())
    }
}
```

### Asterisk Configuration for Roaming Extensions

#### Dynamic Peer Configuration
```ini
; /etc/asterisk/sip.conf
[sky-genesis-dynamic]
type = peer
host = dynamic
context = sky-genesis-voip
disallow = all
allow = ulaw,alaw,opus,g729
dtmfmode = rfc4733
qualify = yes
```

#### Stasis Application for Dynamic Routing
```ini
; /etc/asterisk/extensions.conf
[sky-genesis-voip]
exten => _X.,1,NoOp(Incoming call to ${EXTEN})
exten => _X.,n,Set(USER_ID=${EXTEN})
exten => _X.,n,AGI(resolve_endpoint.py,${USER_ID})
exten => _X.,n,GotoIf($["${ENDPOINT}" = ""]?no_endpoint)
exten => _X.,n,Dial(${ENDPOINT},30)
exten => _X.,n,Hangup()

exten => no_endpoint,1,Playback(user-not-registered)
exten => no_endpoint,n,Hangup()
```

#### AGI Endpoint Resolution Script
```python
#!/usr/bin/env python3
import sys
import requests
import os

SGE_API_URL = os.getenv('SGE_API_URL', 'http://localhost:8080/api/v1')
SGE_JWT_TOKEN = os.getenv('SGE_JWT_TOKEN')

def resolve_endpoint(user_id):
    headers = {'Authorization': f'Bearer {SGE_JWT_TOKEN}'}

    # Get user extension
    response = requests.get(f'{SGE_API_URL}/voip/extensions',
                          headers=headers)
    if response.status_code != 200:
        return ""

    extension_data = response.json()
    if not extension_data.get('enabled', False):
        return ""

    # Get active devices
    response = requests.get(f'{SGE_API_URL}/voip/devices',
                          headers=headers)
    if response.status_code != 200:
        return f"SIP/{extension_data['extension']}"

    devices = response.json()
    online_devices = [d for d in devices if d['is_online']]

    if not online_devices:
        return f"SIP/{extension_data['extension']}"

    # Return first active device
    return online_devices[0]['endpoint_uri']

# Main AGI logic
user_id = sys.argv[1] if len(sys.argv) > 1 else ""
endpoint = resolve_endpoint(user_id)
print(f"SET VARIABLE ENDPOINT {endpoint}")
```

## Security and Best Practices

### Encryption
- **Signaling**: All API communications use HTTPS/TLS 1.3 with mTLS
- **ARI Interface**: Mutual TLS authentication between SGE API and Asterisk
- **Media**: SRTP with DTLS encryption for VoIP streams
- **Storage**: Encryption keys and certificates in Vault PKI

### Authentication
- **JWT Tokens**: For user authentication
- **API Keys**: For service access
- **Client Certificates**: Mutual TLS authentication for VoIP endpoints
- **SSO Integration**: Single sign-on via Keycloak

### Certificate Management
- **VoIP Client Certificates**: X.509 certificates for SIP/WebRTC clients
- **ARI mTLS**: Mutual authentication for Asterisk REST Interface
- **Federation Certificates**: Secure inter-office VoIP communication
- **Certificate Lifecycle**: Automated issuance, renewal, and revocation via Vault PKI

### Resource Management
- **Call Limits**: User-specific limit configuration
- **Timeout**: Automatic cleanup of inactive calls
- **Rate Limiting**: Protection against abuse
- **Roaming Extensions**: Device and presence management

### Compliance
- **GDPR**: Personal data management
- **HIPAA**: Security for medical data
- **Audit**: Complete call logging

## Troubleshooting

### Common Asterisk Issues

#### ARI Connection Failure
- Check `/etc/asterisk/ari.conf` configuration
- Verify ARI credentials
- Validate network connectivity on port 8088

#### Channels Not Created
- Check ARI user permissions
- Verify SIP/PJSIP configuration
- Examine Asterisk logs (`asterisk -rvvv`)

#### Signaling Issues
- Verify JWT authentication
- Check ARI timeouts
- Examine API and Asterisk logs

#### Degraded Audio Quality
- Check codec configuration in Asterisk
- Monitor network bandwidth and latency
- Monitor RTP metrics (`rtp set debug on`)

### Asterisk Logs and Debugging
```bash
# SGE API logs
tail -f /var/log/sge/api.log | grep voip

# Complete Asterisk logs
tail -f /var/log/asterisk/full

# Specific ARI logs
tail -f /var/log/asterisk/full | grep ARI

# Real-time ARI debug
asterisk -rvvv
ari show apps
ari show channels

# Detailed metrics
curl http://localhost:8080/api/v1/voip/asterisk/info
curl http://localhost:8080/api/v1/voip/asterisk/channels
```

## Asterisk Implementation Examples

### WebRTC Client with Asterisk
```javascript
class AsteriskVoIPClient {
    constructor(apiUrl, asteriskConfig) {
        this.apiUrl = apiUrl;
        this.asteriskConfig = asteriskConfig;
        this.peerConnection = null;
    }

    async initiateCall(extension, callType = 'audio') {
        try {
            // Create call via SGE API
            const response = await fetch(`${this.apiUrl}/api/v1/voip/calls`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getToken()}`
                },
                body: JSON.stringify({
                    participants: [`SIP/${extension}`],
                    call_type: callType
                })
            });

            const callData = await response.json();

            // Initialize WebRTC with Asterisk information
            await this.setupWebRTC(callData);

            return callData;
        } catch (error) {
            console.error('Error initiating call:', error);
            throw error;
        }
    }

    async setupWebRTC(callData) {
        const configuration = {
            iceServers: [
                { urls: 'stun:stun.skygenesisenterprise.com:19302' }
            ]
        };

        this.peerConnection = new RTCPeerConnection(configuration);

        // ICE candidate handling
        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.sendSignaling(callData.id, 'ice_candidate', event.candidate);
            }
        };

        // Media track handling
        this.peerConnection.ontrack = (event) => {
            const remoteAudio = document.getElementById('remote-audio');
            remoteAudio.srcObject = event.streams[0];
        };

        // Add local tracks
        const localStream = await navigator.mediaDevices.getUserMedia({
            audio: true,
            video: false
        });

        localStream.getTracks().forEach(track => {
            this.peerConnection.addTrack(track, localStream);
        });
    }

    async sendSignaling(callId, messageType, payload) {
        await fetch(`${this.apiUrl}/api/v1/voip/calls/${callId}/signaling`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.getToken()}`
            },
            body: JSON.stringify({
                to_user: 'asterisk',
                message_type: messageType,
                payload: payload
            })
        });
    }

    getToken() {
        return localStorage.getItem('sge_jwt_token');
    }
}

// Usage
const voipClient = new AsteriskVoIPClient('https://api.skygenesisenterprise.com');
await voipClient.initiateCall('1001', 'audio');
```

### React Native Mobile Application
See the example in the previous section, adapted for Asterisk using ARI endpoints instead of in-memory storage.

### Asterisk Integration
Complete configuration available in `infrastructure/stalwart/`.

### React Native Mobile Application
```javascript
import { RTCPeerConnection, RTCView } from 'react-native-webrtc';

class VoIPCall extends Component {
    constructor(props) {
        super(props);
        this.peerConnection = null;
    }

    async startCall = async () => {
        // Create call via API
        const callResponse = await this.createCall();
        const callId = callResponse.id;

        // Initialize WebRTC
        this.peerConnection = new RTCPeerConnection(rtcConfiguration);

        // Configure events
        this.setupPeerConnection();

        // Get media permissions
        const stream = await mediaDevices.getUserMedia({
            audio: true,
            video: true
        });

        // Add tracks
        stream.getTracks().forEach(track => {
            this.peerConnection.addTrack(track, stream);
        });

        // Create and send offer
        const offer = await this.peerConnection.createOffer();
        await this.peerConnection.setLocalDescription(offer);

        await this.sendSignaling(callId, 'offer', offer);
    }

    setupPeerConnection = () => {
        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.sendSignaling(this.callId, 'ice_candidate', event.candidate);
            }
        };

        this.peerConnection.onaddstream = (event) => {
            this.setState({ remoteStream: event.stream });
        };
    }

    render() {
        return (
            <View>
                <RTCView streamURL={this.state.remoteStream} />
                <TouchableOpacity onPress={this.startCall}>
                    <Text>Call</Text>
                </TouchableOpacity>
            </View>
        );
    }
}
```

## VoIP Federation

### Federation Overview

The Sky Genesis Enterprise API supports a federated VoIP architecture where each office can maintain its own Asterisk server while connecting to the central enterprise network. This enables distributed VoIP infrastructure with centralized management and security.

### Federation Components

- **Federated Offices**: Individual offices with their own Asterisk PBX
- **Federation Links**: Secure connections between offices (SIP trunks, IAX, API gateway)
- **Federation Routes**: Intelligent routing rules for inter-office calls
- **Federation Tokens**: Secure authentication for inter-office communication

### Registering a Federated Office

```http
POST /api/v1/voip/federation/offices
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "name": "Brussels Office",
  "location": "Brussels, Belgium",
  "office_prefix": "BRU",
  "asterisk_config": {
    "host": "asterisk-bru.company.com",
    "port": 5038,
    "ari_url": "http://asterisk-bru.company.com:8088/ari",
    "ari_username": "federation",
    "ari_password": "secure_password",
    "sip_trunk_host": "sip.company.com",
    "sip_trunk_port": 5060,
    "federation_context": "federation-bru"
  }
}
```

### Creating Federation Links

```http
POST /api/v1/voip/federation/links
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "source_office_id": "office-bru-id",
  "target_office_id": "office-par-id",
  "link_type": "SipTrunk",
  "priority": 1
}
```

**Link Types:**
- `SipTrunk`: Direct SIP trunk between Asterisk servers
- `IaxTrunk`: IAX2 trunk (more efficient for VoIP)
- `ApiGateway`: Route via central API gateway
- `PstnGateway`: PSTN connectivity

### Defining Federation Routes

```http
POST /api/v1/voip/federation/routes
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "source_office_prefix": "BRU",
  "destination_pattern": "PAR-*",
  "target_office_id": "office-par-id",
  "cost_priority": 1
}
```

### Federation Authentication

Federated offices authenticate using federation tokens:

```http
Authorization: Bearer <federation_token>
X-Federation-Office: <office_prefix>
```

### Asterisk Federation Configuration

#### Federation Context Example (`/etc/asterisk/extensions.conf`)

```ini
[federation-bru]
; Outgoing calls to other offices
exten => _PAR-.,1,NoOp(Federation call from BRU to PAR)
exten => _PAR-.,n,Dial(SIP/federation-par/${EXTEN:4})

; Incoming calls from federation
exten => _BRU-.,1,NoOp(Incoming federation call)
exten => _BRU-.,n,Dial(SIP/${EXTEN:4})

; Emergency routing
exten => _911,1,NoOp(Emergency call)
exten => _911,n,Dial(SIP/trunk-pstn/911)
```

#### SIP Trunk Configuration (`/etc/asterisk/sip.conf`)

```ini
[federation-par]
type=peer
host=dynamic
context=federation-bru
disallow=all
allow=ulaw,alaw,g729
qualify=yes
secret=federation_secret_par
```

### Federation Security

- **Encrypted Links**: All federation links use SRTP/TLS encryption
- **Token Authentication**: Federation tokens with expiration
- **Access Control**: Office-specific permissions and routing rules
- **Audit Logging**: All federation activities are logged
- **Failover**: Automatic failover to backup links

### Monitoring Federation

```http
GET /api/v1/voip/federation/offices
GET /api/v1/voip/federation/links
```

## Useful Asterisk Commands

### Call Management
```bash
# List all channels
asterisk -rx "core show channels"

# Details of specific channel
asterisk -rx "core show channel SIP/1001-00000001"

# Hang up a channel
asterisk -rx "channel request hangup SIP/1001-00000001"
```

### Bridge Management
```bash
# List bridges
asterisk -rx "bridge show all"

# Details of a bridge
asterisk -rx "bridge show 12345678-1234-1234-1234-123456789012"
```

### Network Diagnostics
```bash
# SIP latency test
asterisk -rx "sip show peers"

# RTP statistics
asterisk -rx "rtp set stats on"
asterisk -rx "rtp show stats"
```

### Configuration Reload
```bash
# Reload ARI
asterisk -rx "module reload res_ari.so"

# Reload SIP
asterisk -rx "sip reload"

# Reload dialplan
asterisk -rx "dialplan reload"
```