# Certificate-Coupled API Key Authentication

This document provides a complete guide for using certificate-coupled API keys with the Sky Genesis API.

## Overview

Certificate-coupled API keys implement a two-factor authentication system where each request must provide:

1. **JWT Token** - Proves user identity and authorization
2. **Certificate Signature** - Proves ownership of the specific API key

This creates a robust security model where compromising one authentication factor alone is insufficient for unauthorized access.

## Prerequisites

- API server running on `http://localhost:8080`
- Valid JWT token for API access
- OpenSSL or similar cryptographic tools

## Step 1: Create an API Key with Certificate

First, create an API key that includes a certificate:

```bash
curl -X POST "http://localhost:8080/api/keys/with-certificate?type=client&tenant=myorg&ttl=3600&cert_type=rsa" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "key_type": "Client",
  "tenant": "myorg",
  "ttl": 3600,
  "created_at": "2023-01-01T00:00:00Z",
  "permissions": ["read"],
  "vault_path": "secret/client",
  "certificate": {
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
    "private_key_path": "secret/certificates/550e8400-e29b-41d4-a716-446655440000/private",
    "certificate_type": "RSA",
    "fingerprint": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
  }
}
```

## Step 2: Retrieve Certificate Information

You can retrieve the public key information at any time:

```bash
curl -X GET "http://localhost:8080/api/keys/550e8400-e29b-41d4-a716-446655440000/public-key" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

**Response:**
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
  "certificate_type": "RSA",
  "fingerprint": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
}
```

## Step 3: Generate Private Key for Client Use

**Important:** In a real application, you would securely store and manage the private key. For this example, we'll extract it from the server (this is not recommended for production).

```bash
# This is for demonstration only - in production, private keys should never leave the server
# The private key is stored in Vault at the path specified in private_key_path
```

## Step 4: Make Authenticated Requests

Certificate-coupled authentication requires **both** JWT token and certificate signature. Here's how to make authenticated requests:

### Prerequisites
- Valid JWT token (obtained via `/auth/login`)
- API key ID with associated certificate
- Private key for signing (securely stored)

### Authentication Flow

1. **Obtain JWT Token** (if not already available)
2. **Create Request Signature** using the certificate private key
3. **Send Request** with both authentication methods

### Using OpenSSL (RSA Example)

```bash
#!/bin/bash

# Configuration
API_KEY_ID="550e8400-e29b-41d4-a716-446655440000"
JWT_TOKEN="your_jwt_token_here"
PRIVATE_KEY_FILE="client_private_key.pem"

# Create timestamp
TIMESTAMP=$(date +%s)

# Create message to sign (API key ID + timestamp)
MESSAGE="${API_KEY_ID}${TIMESTAMP}"

# Sign the message with private key
SIGNATURE=$(echo -n "$MESSAGE" | openssl dgst -sha256 -sign "$PRIVATE_KEY_FILE" | base64 -w 0)

# Make the request with BOTH JWT and certificate authentication
curl -X GET "http://localhost:8080/api/secure/data" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "X-API-Key: $API_KEY_ID" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "X-Signature: $SIGNATURE"
```

### Using Node.js

```javascript
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');

const apiKeyId = '550e8400-e29b-12d3-a456-426614174000';
const jwtToken = 'your_jwt_token_here';
const privateKey = fs.readFileSync('client_private_key.pem');

function signMessage(message) {
  const sign = crypto.createSign('SHA256');
  sign.update(message);
  return sign.sign(privateKey);
}

async function makeAuthenticatedRequest() {
  const timestamp = Math.floor(Date.now() / 1000);
  const message = apiKeyId + timestamp;
  const signature = signMessage(message);
  const signatureB64 = signature.toString('base64');

  try {
    const response = await axios.get('http://localhost:8080/api/secure/data', {
      headers: {
        'Authorization': `Bearer ${jwtToken}`,  // JWT authentication
        'X-API-Key': apiKeyId,                   // Certificate-coupled key
        'X-Timestamp': timestamp.toString(),
        'X-Signature': signatureB64
      }
    });

    console.log('Success:', response.data);
  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

makeAuthenticatedRequest();
```

### Using Python

```python
import requests
import base64
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

api_key_id = '550e8400-e29b-41d4-a716-446655440000'
jwt_token = 'your_jwt_token_here'

# Load private key (you need to obtain this securely)
with open('client_private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

def sign_message(message):
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def make_authenticated_request():
    timestamp = int(time.time())
    message = f"{api_key_id}{timestamp}"
    signature = sign_message(message)

    headers = {
        'Authorization': f'Bearer {jwt_token}',  # JWT authentication
        'X-API-Key': api_key_id,                  # Certificate-coupled key
        'X-Timestamp': str(timestamp),
        'X-Signature': signature
    }

    response = requests.get('http://localhost:8080/api/secure/data', headers=headers)

    if response.status_code == 200:
        print('Success:', response.json())
    else:
        print('Error:', response.status_code, response.text)

make_authenticated_request()
```

## Step 5: Verify Authentication

If both JWT and certificate authentication succeed, the server will respond with:

```json
{
  "message": "Authenticated with JWT + certificate",
  "user_id": "user_id_from_jwt",
  "api_key_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Authentication Failure Scenarios

- **Invalid JWT**: `401 Unauthorized` - JWT token missing, expired, or invalid
- **Invalid API Key**: `401 Unauthorized` - API key doesn't exist or has no certificate
- **Invalid Signature**: `401 Unauthorized` - Signature verification failed
- **Expired Timestamp**: `401 Unauthorized` - Timestamp outside 5-minute window
- **Missing Headers**: `400 Bad Request` - Required certificate headers missing

## Security Considerations

### Two-Factor Authentication Benefits

1. **Defense in Depth**: JWT compromise alone is insufficient for access
2. **Non-Repudiation**: Cryptographic proof of request origin
3. **Key Theft Protection**: Stolen credentials require both JWT and private key

### Certificate Security

1. **Private Key Security**: Never expose private keys. Store them securely (HSM, secure enclaves)
2. **Key Rotation**: Regularly rotate certificate-coupled keys
3. **Certificate Revocation**: Immediately revoke compromised certificates:
   ```bash
   DELETE /api/keys/{api_key_id}/certificate
   ```

### Request Security

1. **Timestamp Validation**: Requests must be made within 5 minutes to prevent replay attacks
2. **Signature Algorithm**: Supports RSA (PKCS#1 v1.5) and ECDSA with SHA256
3. **Message Integrity**: Signature covers API key ID + timestamp to prevent tampering

### Implementation Security

1. **Secure Key Storage**: Private keys stored encrypted in Vault
2. **Audit Logging**: All authentication attempts logged
3. **Rate Limiting**: Protection against brute force attacks
4. **TLS Required**: All communications must use HTTPS

## Troubleshooting

### Common Issues

1. **"Invalid signature"**: Check that you're using the correct private key and signing algorithm.

2. **"Expired timestamp"**: Ensure your timestamp is current (within 5 minutes).

3. **"Certificate not found"**: Verify that the API key has a certificate associated with it.

4. **"Key not found"**: Check that the API key ID is correct.

### Debug Tips

- Verify your timestamp is a valid Unix timestamp
- Ensure the message format is exactly: `api_key_id + timestamp` (no separators)
- Check that your base64 encoding is correct
- Verify the private key format (PEM)