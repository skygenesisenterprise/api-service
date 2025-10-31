# OAuth2 / OIDC + FIDO2 Integration

## Overview

The SGE Enterprise API implements comprehensive identity management using OAuth2/OpenID Connect (OIDC) with Keycloak as the identity provider, enhanced with FIDO2/WebAuthn for strong hardware-based authentication.

## OIDC Implementation

### Discovery & Configuration
- **Well-Known Endpoint**: `/.well-known/openid-connect-configuration`
- **JWKS**: Automatic key rotation and validation
- **Supported Flows**: Authorization Code, Implicit, Client Credentials

### Endpoints

#### Initiate Login
```http
POST /api/v1/auth/oidc/login
Content-Type: application/json

{
  "redirect_uri": "https://app.skygenesisenterprise.com/callback",
  "state": "random_state_string"
}
```

**Response:**
```json
{
  "authorization_url": "https://keycloak.skygenesisenterprise.com/realms/sge/protocol/openid-connect/auth?client_id=api-client&redirect_uri=https%3A%2F%2Fapp.skygenesisenterprise.com%2Fcallback&scope=openid&response_type=code&state=random_state_string"
}
```

#### Handle Callback
```http
GET /api/v1/auth/oidc/callback?code=auth_code&state=random_state_string
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "refresh_token_here",
  "expires_in": 3600,
  "state": "random_state_string"
}
```

### Token Validation
- **Algorithm**: RS256 (RSA signatures)
- **Validation**: JWKS-based public key validation
- **Claims**: Standard OIDC claims + custom enterprise claims

## FIDO2/WebAuthn Implementation

### Registration Flow

#### Start Registration
```http
POST /api/v1/auth/fido2/register/start
Content-Type: application/json

{
  "username": "john.doe",
  "display_name": "John Doe"
}
```

**Response:**
```json
{
  "challenge": "base64_encoded_challenge",
  "user_id": "uuid_generated"
}
```

#### Complete Registration
```http
POST /api/v1/auth/fido2/register/finish
Content-Type: application/json

{
  "user_id": "uuid_generated",
  "challenge": "base64_encoded_challenge",
  "response": "base64_encoded_attestation"
}
```

### Authentication Flow

#### Start Authentication
```http
POST /api/v1/auth/fido2/auth/start
Content-Type: application/json

{
  "username": "john.doe"
}
```

**Response:**
```json
{
  "challenge": "base64_encoded_challenge"
}
```

#### Complete Authentication
```http
POST /api/v1/auth/fido2/auth/finish
Content-Type: application/json

{
  "username": "john.doe",
  "challenge": "base64_encoded_challenge",
  "response": "base64_encoded_assertion"
}
```

**Response:**
```json
{
  "status": "authenticated"
}
```

## Security Features

### OIDC Security
- **PKCE**: Proof Key for Code Exchange
- **State Parameter**: CSRF protection
- **Nonce**: Replay attack prevention
- **Token Introspection**: Real-time token validation

### FIDO2 Security
- **Attestation**: Hardware authenticity verification
- **User Verification**: Biometric/PIN verification
- **Resident Keys**: Device-bound credentials
- **HmacSecret**: Encrypted credential storage

## Integration Examples

### Frontend OIDC Login
```javascript
async function login() {
  const response = await fetch('/api/v1/auth/oidc/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      redirect_uri: window.location.origin + '/callback'
    })
  });

  const { authorization_url } = await response.json();
  window.location.href = authorization_url;
}
```

### Frontend FIDO2 Registration
```javascript
async function registerFido2() {
  // Start registration
  const startResponse = await fetch('/api/v1/auth/fido2/register/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'john.doe',
      display_name: 'John Doe'
    })
  });

  const { challenge, user_id } = await startResponse.json();

  // Create credential
  const credential = await navigator.credentials.create({
    publicKey: JSON.parse(atob(challenge))
  });

  // Finish registration
  await fetch('/api/v1/auth/fido2/register/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user_id,
      challenge,
      response: btoa(JSON.stringify(credential))
    })
  });
}
```

## Configuration

### Keycloak Configuration
```json
{
  "realm": "skygenesisenterprise",
  "clients": [{
    "clientId": "api-client",
    "protocol": "openid-connect",
    "publicClient": false,
    "redirectUris": ["https://api.skygenesisenterprise.com/*"]
  }]
}
```

### Environment Variables
```bash
KEYCLOAK_URL=https://keycloak.skygenesisenterprise.com
KEYCLOAK_REALM=skygenesisenterprise
FIDO2_RP_ID=api.skygenesisenterprise.com
FIDO2_RP_ORIGIN=https://api.skygenesisenterprise.com
```

## Monitoring

### Metrics
- `oidc_login_attempts_total`: Total OIDC login attempts
- `fido2_registration_total`: Total FIDO2 registrations
- `fido2_authentication_total`: Total FIDO2 authentications

### Traces
- OIDC authorization flow spans
- FIDO2 credential creation spans
- Token validation spans

## Troubleshooting

### Common OIDC Issues
- **Invalid redirect URI**: Ensure redirect URI is registered in Keycloak
- **Token expired**: Implement refresh token flow
- **CORS errors**: Configure CORS policies for frontend

### Common FIDO2 Issues
- **NotSupportedError**: Browser doesn't support WebAuthn
- **AbortError**: User cancelled operation
- **SecurityError**: Insecure context (requires HTTPS)

## SSO Service Integration

For a complete SSO implementation that serves login pages under the API domain, see the [SSO Service Documentation](sso.md). The SSO service provides:

- Unified login experience under `sso.skygenesisenterprise.com`
- Application-controlled redirection logic
- Token proxying and validation
- State management for CSRF protection

## Compliance

- **OIDC Certified**: Compliant with OIDC Core specifications
- **FIDO2 Certified**: Compatible with FIDO2 Level 2 certification
- **GDPR Compliant**: Minimal data collection, user consent required
- **eIDAS Ready**: Supports qualified electronic signatures