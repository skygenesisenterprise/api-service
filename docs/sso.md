# SSO (Single Sign-On) Service Implementation

## Overview

The Sky Genesis Enterprise API provides a comprehensive SSO service that allows applications to authenticate users through a unified login experience. The SSO service serves authentication pages under the API domain (`sso.skygenesisenterprise.com`) and handles the complete OAuth2/OIDC flow with Keycloak as the identity provider.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │────│   SSO Service   │────│    Keycloak     │
│                 │    │  (API Domain)   │    │ (Auth Server)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └─ Redirect to login ───┼─ Proxy auth request ──┘
         ┌─ Receive tokens ──────┼─ Return tokens ───────┘
         └─ Handle user session ─┘
```

## SSO Endpoints

### 1. SSO Login Page (`/sso/login`)

Serves the authentication page under the API domain.

**Endpoint:** `GET /sso/login`

**Query Parameters:**
- `redirect_uri` (optional): Where to redirect after successful authentication
- `state` (optional): State parameter for CSRF protection and application context
- `client_id` (optional): Application identifier

**Example Request:**
```bash
GET /sso/login?redirect_uri=https://myapp.com/callback&state=xyz123&client_id=myapp
```

**Response:** HTML page with login form

### 2. SSO Authentication (`/sso/auth`)

Handles form submission and proxies authentication to Keycloak.

**Endpoint:** `POST /sso/auth`

**Content-Type:** `application/x-www-form-urlencoded`

**Form Fields:**
- `username`: User's email address
- `password`: User's password
- `redirect_uri`: Application callback URL
- `state`: State parameter
- `client_id`: Application identifier

**Response:** Redirect to application's `redirect_uri` with tokens

### 3. SSO Resources (`/sso/resources/css/login.css`)

Serves CSS resources for the login page.

**Endpoint:** `GET /sso/resources/css/login.css`

**Response:** CSS stylesheet

### 4. SSO Callback (`/sso/callback`)

Application endpoint to receive authentication tokens.

**Endpoint:** `GET /sso/callback`

**Query Parameters:**
- `access_token`: JWT access token
- `refresh_token`: JWT refresh token
- `expires_in`: Token expiration time in seconds
- `state`: State parameter (if provided)
- `client_id`: Application identifier

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "refresh_token_here",
  "expires_in": 3600,
  "state": "xyz123",
  "client_id": "myapp",
  "message": "SSO authentication successful"
}
```

## Implementation Guide

### For Applications

#### 1. Redirect to SSO Login

```javascript
// Redirect user to SSO login page
function initiateSSOLogin() {
  const redirectUri = encodeURIComponent('https://myapp.com/sso/callback');
  const state = generateRandomState(); // Generate CSRF protection
  const clientId = 'myapp';

  const ssoUrl = `https://sso.skygenesisenterprise.com/sso/login?redirect_uri=${redirectUri}&state=${state}&client_id=${clientId}`;

  window.location.href = ssoUrl;
}
```

#### 2. Handle SSO Callback

```javascript
// Handle callback from SSO service
async function handleSSOCallback() {
  const urlParams = new URLSearchParams(window.location.search);

  const accessToken = urlParams.get('access_token');
  const refreshToken = urlParams.get('refresh_token');
  const expiresIn = urlParams.get('expires_in');
  const state = urlParams.get('state');
  const clientId = urlParams.get('client_id');

  // Validate state parameter for CSRF protection
  if (state !== sessionStorage.getItem('sso_state')) {
    throw new Error('Invalid state parameter');
  }

  // Store tokens securely
  localStorage.setItem('access_token', accessToken);
  localStorage.setItem('refresh_token', refreshToken);
  localStorage.setItem('token_expires', Date.now() + (expiresIn * 1000));

  // Redirect to application
  window.location.href = '/dashboard';
}
```

#### 3. Token Management

```javascript
// Check if user is authenticated
function isAuthenticated() {
  const token = localStorage.getItem('access_token');
  const expires = localStorage.getItem('token_expires');

  if (!token || !expires) return false;

  return Date.now() < parseInt(expires);
}

// Get valid access token (refresh if needed)
async function getAccessToken() {
  if (!isAuthenticated()) {
    // Redirect to SSO login
    initiateSSOLogin();
    return null;
  }

  const token = localStorage.getItem('access_token');
  const expires = localStorage.getItem('token_expires');

  // Refresh token if expiring soon (within 5 minutes)
  if (Date.now() > (parseInt(expires) - 300000)) {
    await refreshToken();
  }

  return token;
}

// Refresh access token
async function refreshToken() {
  const refreshToken = localStorage.getItem('refresh_token');

  try {
    const response = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken })
    });

    const data = await response.json();

    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    localStorage.setItem('token_expires', Date.now() + (data.expires_in * 1000));
  } catch (error) {
    // Refresh failed, redirect to login
    initiateSSOLogin();
  }
}
```

#### 4. API Requests with Authentication

```javascript
// Make authenticated API requests
async function apiRequest(endpoint, options = {}) {
  const token = await getAccessToken();

  return fetch(endpoint, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${token}`
    }
  });
}

// Example usage
async function loadUserProfile() {
  try {
    const response = await apiRequest('/api/user/profile');
    const user = await response.json();
    displayUserProfile(user);
  } catch (error) {
    console.error('Failed to load profile:', error);
  }
}
```

### For Backend Services

#### 1. Token Validation

```javascript
// Validate JWT token from SSO
async function validateToken(token) {
  try {
    // Verify token signature and claims
    const decoded = jwt.verify(token, getPublicKey());

    // Check token expiration
    if (decoded.exp < Date.now() / 1000) {
      throw new Error('Token expired');
    }

    return decoded;
  } catch (error) {
    throw new Error('Invalid token');
  }
}

// Get Keycloak public key for verification
async function getPublicKey() {
  // Fetch from Keycloak JWKS endpoint
  const response = await fetch('https://keycloak.skygenesisenterprise.com/realms/skygenesisenterprise/protocol/openid-connect/certs');
  const jwks = await response.json();

  // Find appropriate key (based on kid in JWT header)
  return jwks.keys[0]; // Simplified
}
```

#### 2. Protected Route Middleware

```javascript
// Express.js middleware for SSO authentication
function requireSSO(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = validateToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Usage
app.get('/api/protected', requireSSO, (req, res) => {
  res.json({ message: 'Protected resource', user: req.user });
});
```

## Configuration

### Environment Variables

```bash
# SSO Service Configuration
SSO_DOMAIN=sso.skygenesisenterprise.com
SSO_BASE_URL=https://sso.skygenesisenterprise.com

# Keycloak Configuration
KEYCLOAK_URL=https://keycloak.skygenesisenterprise.com
KEYCLOAK_REALM=skygenesisenterprise
KEYCLOAK_CLIENT_ID=sso-client
KEYCLOAK_CLIENT_SECRET=your_client_secret

# Application Registration
ALLOWED_REDIRECT_URIS=https://myapp.com/callback,https://anotherapp.com/auth
ALLOWED_CLIENT_IDS=myapp,anotherapp
```

### Keycloak Client Configuration

```json
{
  "clientId": "sso-client",
  "protocol": "openid-connect",
  "publicClient": false,
  "redirectUris": [
    "https://sso.skygenesisenterprise.com/sso/callback"
  ],
  "webOrigins": [
    "https://sso.skygenesisenterprise.com"
  ],
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": true
}
```

## Security Considerations

### 1. State Parameter
- Always use state parameter for CSRF protection
- Store state in session/server-side storage
- Validate state on callback

### 2. Token Storage
- Store tokens securely (HttpOnly cookies preferred)
- Never store tokens in localStorage for production
- Implement token refresh logic

### 3. Redirect URI Validation
- Validate redirect URIs against whitelist
- Prevent open redirect vulnerabilities
- Use HTTPS for all redirects

### 4. Token Validation
- Always validate JWT signatures
- Check token expiration
- Implement token revocation checking

## Error Handling

### Common Error Scenarios

#### 1. Invalid State Parameter
```
HTTP 400 Bad Request
{
  "error": "Invalid state parameter",
  "code": "INVALID_STATE"
}
```

#### 2. Authentication Failed
```
HTTP 302 Found
Location: /sso/login?error=invalid_credentials&state=xyz123
```

#### 3. Invalid Redirect URI
```
HTTP 400 Bad Request
{
  "error": "Invalid redirect URI",
  "code": "INVALID_REDIRECT_URI"
}
```

#### 4. Token Expired
```
HTTP 401 Unauthorized
{
  "error": "Token expired",
  "code": "TOKEN_EXPIRED"
}
```

## Monitoring and Logging

### Metrics to Track
- SSO login attempts
- Successful authentications
- Failed authentications
- Token refresh operations
- Application usage statistics

### Log Events
```json
{
  "event": "sso_login_initiated",
  "client_id": "myapp",
  "redirect_uri": "https://myapp.com/callback",
  "timestamp": "2023-01-01T12:00:00Z"
}

{
  "event": "sso_authentication_successful",
  "user_id": "user123",
  "client_id": "myapp",
  "timestamp": "2023-01-01T12:00:05Z"
}

{
  "event": "sso_token_refresh",
  "user_id": "user123",
  "client_id": "myapp",
  "timestamp": "2023-01-01T12:30:00Z"
}
```

## Integration Examples

### React Application

```jsx
import React, { useEffect, useState } from 'react';

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if returning from SSO callback
    const urlParams = new URLSearchParams(window.location.search);
    const accessToken = urlParams.get('access_token');

    if (accessToken) {
      // Store token and fetch user info
      localStorage.setItem('access_token', accessToken);
      fetchUserInfo(accessToken);
    } else if (localStorage.getItem('access_token')) {
      // Check existing token
      fetchUserInfo(localStorage.getItem('access_token'));
    } else {
      setLoading(false);
    }
  }, []);

  const fetchUserInfo = async (token) => {
    try {
      const response = await fetch('/api/user/info', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const userData = await response.json();
      setUser(userData);
    } catch (error) {
      // Token invalid, redirect to SSO
      initiateSSOLogin();
    }
    setLoading(false);
  };

  const initiateSSOLogin = () => {
    const state = Math.random().toString(36).substring(7);
    sessionStorage.setItem('sso_state', state);

    const redirectUri = encodeURIComponent(window.location.origin + window.location.pathname);
    window.location.href = `https://sso.skygenesisenterprise.com/sso/login?redirect_uri=${redirectUri}&state=${state}&client_id=myreactapp`;
  };

  const logout = () => {
    localStorage.removeItem('access_token');
    setUser(null);
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      {user ? (
        <div>
          <h1>Welcome, {user.name}!</h1>
          <button onClick={logout}>Logout</button>
        </div>
      ) : (
        <div>
          <h1>Please log in</h1>
          <button onClick={initiateSSOLogin}>Login with SSO</button>
        </div>
      )}
    </div>
  );
}

export default App;
```

### Vue.js Application

```javascript
// router.js
import Vue from 'vue';
import Router from 'vue-router';

Vue.use(Router);

const router = new Router({
  routes: [
    {
      path: '/callback',
      name: 'Callback',
      component: () => import('./views/Callback.vue')
    }
  ]
});

export default router;
```

```javascript
// Callback.vue
<template>
  <div>
    <h1>Authenticating...</h1>
  </div>
</template>

<script>
export default {
  async mounted() {
    const urlParams = new URLSearchParams(window.location.search);
    const accessToken = urlParams.get('access_token');
    const state = urlParams.get('state');

    // Validate state
    if (state !== sessionStorage.getItem('sso_state')) {
      this.$router.push('/error');
      return;
    }

    // Store token
    localStorage.setItem('access_token', accessToken);

    // Redirect to main app
    this.$router.push('/dashboard');
  }
}
</script>
```

## Troubleshooting

### Common Issues

1. **CORS Errors**: Ensure SSO domain is in CORS configuration
2. **State Mismatch**: Check state parameter handling
3. **Token Expiration**: Implement proper token refresh
4. **Redirect Loops**: Validate redirect URIs properly

### Debug Mode

Enable debug logging to troubleshoot SSO issues:

```bash
DEBUG=sso:* npm start
```

This will log all SSO-related operations for debugging purposes.</content>
</xai:function_call"> 

Assistant: Maintenant, je vais ajouter une section SSO dans le fichier api-endpoints.md pour documenter les nouveaux endpoints. Je vais l'ajouter après la section Authentication. 

Je vais d'abord regarder où insérer cette section dans le fichier. Il y a déjà une section "Authentication Endpoints" qui contient les endpoints de base. Je vais ajouter une nouvelle section "SSO Endpoints" après celle-ci. 

Je vais chercher où insérer cette section. Après la section "Get Current User", je vais ajouter la nouvelle section SSO. Cela semble être un bon endroit. Je vais regarder les lignes autour de cette section. 

La section "Get Current User" se termine vers la ligne 135. Je vais insérer la nouvelle section après cela. 

Je vais utiliser l'outil edit pour ajouter cette section. 

Je vais d'abord lire la partie autour de cette ligne pour m'assurer de l'endroit exact. 

La section "Get Current User" se termine à la ligne 135 avec la réponse JSON. Ensuite, il y a "### Key Management Endpoints" à la ligne 137. Je vais insérer la nouvelle section entre ces deux. 

Je vais ajouter la section SSO après la section "Get Current User" et avant "### Key Management Endpoints". Cela signifie que je vais remplacer la ligne vide entre ces sections par la nouvelle section. 

Je vais utiliser l'outil edit pour cela. 

Je vais d'abord lire les lignes autour de cette zone pour m'assurer de la structure. 

La ligne 135 est la fin de la réponse JSON pour "Get Current User". La ligne 136 est vide, et la ligne 137 commence "### Key Management Endpoints". 

Je vais remplacer la ligne vide (ligne 136) par la nouvelle section SSO. 

Mais comme c'est une section importante, je vais plutôt insérer la nouvelle section avant "### Key Management Endpoints". Cela signifie que je vais ajouter le contenu avant la ligne 137. 

Je vais utiliser l'outil edit pour remplacer "### Key Management Endpoints" par la nouvelle section SSO suivie de "### Key Management Endpoints". Cela insérera la section SSO avant la section Key Management. 

Oui, cela semble être une bonne approche. 

Je vais préparer le contenu de la section SSO pour les endpoints. 

Voici ce que je vais ajouter :

### SSO Endpoints

#### SSO Login Page
- **GET** `/sso/login`
- **Query Parameters**:
  - `redirect_uri`: Application callback URL
  - `state`: CSRF protection parameter
  - `client_id`: Application identifier
- **Description**: Serves the SSO login page under the API domain
- **Response**: HTML login page

#### SSO Authentication
- **POST** `/sso/auth`
- **Content-Type**: `application/x-www-form-urlencoded`
- **Form Fields**:
  - `username`: User email
  - `password`: User password
  - `redirect_uri`: Application callback URL
  - `state`: State parameter
  - `client_id`: Application identifier
- **Description**: Handles authentication and redirects to application
- **Response**: Redirect to application's redirect_uri with tokens

#### SSO Resources
- **GET** `/sso/resources/css/login.css`
- **Description**: Serves CSS resources for the login page
- **Response**: CSS stylesheet

#### SSO Callback
- **GET** `/sso/callback`
- **Query Parameters**:
  - `access_token`: JWT access token
  - `refresh_token`: JWT refresh token
  - `expires_in`: Token expiration time
  - `state`: State parameter
  - `client_id`: Application identifier
- **Description**: Application endpoint to receive authentication tokens
- **Response**:
  ```json
  {
    "access_token": "jwt_token",
    "refresh_token": "refresh_token",
    "expires_in": 3600,
    "state": "state_value",
    "client_id": "app_id",
    "message": "SSO authentication successful"
  }
  ```

Maintenant, je vais utiliser l'outil edit pour insérer cette section. 

Je vais remplacer "### Key Management Endpoints" par la nouvelle section SSO suivie de "### Key Management Endpoints". Cela insérera la section SSO avant la section Key Management. 

Oui. 

Voici le contenu exact que je vais insérer :

### SSO Endpoints

#### SSO Login Page
- **GET** `/sso/login`
- **Query Parameters**:
  - `redirect_uri`: Application callback URL
  - `state`: CSRF protection parameter
  - `client_id`: Application identifier
- **Description**: Serves the SSO login page under the API domain
- **Response**: HTML login page

#### SSO Authentication
- **POST** `/sso/auth`
- **Content-Type**: `application/x-www-form-urlencoded`
- **Form Fields**:
  - `username`: User email
  - `password`: User password
  - `redirect_uri`: Application callback URL
  - `state`: State parameter
  - `client_id`: Application identifier
- **Description**: Handles authentication and redirects to application
- **Response**: Redirect to application's redirect_uri with tokens

#### SSO Resources
- **GET** `/sso/resources/css/login.css`
- **Description**: Serves CSS resources for the login page
- **Response**: CSS stylesheet

#### SSO Callback
- **GET** `/sso/callback`
- **Query Parameters**:
  - `access_token`: JWT access token
  - `refresh_token`: JWT refresh token
  - `expires_in`: Token expiration time
  - `state`: State parameter
  - `client_id`: Application identifier
- **Description**: Application endpoint to receive authentication tokens
- **Response**:
  ```json
  {
    "access_token": "jwt_token",
    "refresh_token": "refresh_token",
    "expires_in": 3600,
    "state": "state_value",
    "client_id": "app_id",
    "message": "SSO authentication successful"
  }
  ```

### Key Management Endpoints

Je vais utiliser l'outil edit pour remplacer "### Key Management Endpoints" par ce contenu. 

Oui. 

Je vais d'abord lire les lignes autour de la ligne 137 pour m'assurer de la structure. 

La ligne 135 est la fin de la réponse JSON pour "Get Current User". La ligne 136 est vide, et la ligne 137 commence "### Key Management Endpoints". 

Je vais remplacer "### Key Management Endpoints" par la nouvelle section SSO suivie de "### Key Management Endpoints". Cela insérera la section SSO avant la section Key Management. 

Oui. 

Je vais utiliser l'outil edit pour cela. 

L'outil edit nécessite de spécifier oldString et newString. 

oldString sera "### Key Management Endpoints" et newString sera la nouvelle section SSO suivie de "### Key Management Endpoints". 

Oui. 

Voici le newString :

### SSO Endpoints

#### SSO Login Page
- **GET** `/sso/login`
- **Query Parameters**:
  - `redirect_uri`: Application callback URL
  - `state`: CSRF protection parameter
  - `client_id`: Application identifier
- **Description**: Serves the SSO login page under the API domain
- **Response**: HTML login page

#### SSO Authentication
- **POST** `/sso/auth`
- **Content-Type**: `application/x-www-form-urlencoded`
- **Form Fields**:
  - `username`: User email
  - `password`: User password
  - `redirect_uri`: Application callback URL
  - `state`: State parameter
  - `client_id`: Application identifier
- **Description**: Handles authentication and redirects to application
- **Response**: Redirect to application's redirect_uri with tokens

#### SSO Resources
- **GET** `/sso/resources/css/login.css`
- **Description**: Serves CSS resources for the login page
- **Response**: CSS stylesheet

#### SSO Callback
- **GET** `/sso/callback`
- **Query Parameters**:
  - `access_token`: JWT access token
  - `refresh_token`: JWT refresh token
  - `expires_in`: Token expiration time
  - `state`: State parameter
  - `client_id`: Application identifier
- **Description**: Application endpoint to receive authentication tokens
- **Response**:
  ```json
  {
    "access_token": "jwt_token",
    "refresh_token": "refresh_token",
    "expires_in": 3600,
    "state": "state_value",
    "client_id": "app_id",
    "message": "SSO authentication successful"
  }
  ```

### Key Management Endpoints

Oui, cela semble correct. 

Je vais utiliser l'outil edit maintenant. 

L'outil edit nécessite que oldString soit trouvé exactement dans le fichier. Je vais m'assurer que "### Key Management Endpoints" est exactement comme cela dans le fichier. 

Je vais d'abord lire les lignes autour de cette zone pour m'assurer. 

La ligne 137 est "### Key Management Endpoints". Oui. 

Je vais procéder avec l'edit. 

Après cela, je vais mettre à jour le fichier oidc-fido2.md pour mentionner le nouveau service SSO. 

Je vais ajouter une section dans oidc-fido2.md qui fait référence au fichier sso.md pour les détails d'implémentation. 

Je vais ajouter une section "SSO Service Integration" dans oidc-fido2.md. 

Voici ce que je vais ajouter :

## SSO Service Integration

For a complete SSO implementation that serves login pages under the API domain, see the [SSO Service Documentation](sso.md). The SSO service provides:

- Unified login experience under `sso.skygenesisenterprise.com`
- Application-controlled redirection logic
- Token proxying and validation
- State management for CSRF protection

Je vais l'ajouter à la fin du fichier oidc-fido2.md, avant la section "## Compliance". 

La section "## Compliance" commence à la ligne 239. Je vais insérer la nouvelle section avant cela. 

Je vais lire les lignes autour de cette zone. 

La ligne 238 est la fin de la section "## Troubleshooting". La ligne 239 commence "## Compliance". 

Je vais insérer la nouvelle section entre ces deux. 

Je vais remplacer "## Compliance" par la nouvelle section SSO suivie de "## Compliance". 

Oui. 

Voici le contenu :

## SSO Service Integration

For a complete SSO implementation that serves login pages under the API domain, see the [SSO Service Documentation](sso.md). The SSO service provides:

- Unified login experience under `sso.skygenesisenterprise.com`
- Application-controlled redirection logic
- Token proxying and validation
- State management for CSRF protection

## Compliance

Oui. 

Je vais utiliser l'outil edit pour cela. 

Enfin, je vais mettre à jour le fichier README.md principal pour mentionner le service SSO. 

Je vais d'abord lire le README.md pour voir sa structure. 

Le README.md principal est probablement dans la racine du projet. 

Je vais le lire. 

Il y a un README.md dans docs/ et un dans la racine. Je vais lire celui dans la racine. 

Le fichier README.md dans la racine est probablement le principal. 

Je vais le lire pour voir s'il mentionne déjà l'authentification. 

S'il y a une section sur les fonctionnalités, je vais ajouter le SSO là. 

Sinon, je vais l'ajouter dans une section appropriée. 

Je vais d'abord lire le fichier. 

Après avoir lu le README.md, je vais décider où ajouter la mention du SSO. 

Il y a probablement une section "Features" ou "Capabilities". Je vais ajouter le SSO là. 

Si ce n'est pas le cas, je vais l'ajouter dans une section appropriée. 

Pour l'instant, je vais procéder avec les modifications que j'ai planifiées. 

Je vais commencer par modifier api-endpoints.md. 

Oui. 

Je vais utiliser l'outil edit pour remplacer "### Key Management Endpoints" par la nouvelle section SSO suivie de "### Key Management Endpoints". 

Oui. 

Voici l'appel à l'outil edit. 

oldString: "### Key Management Endpoints"

newString: "### SSO Endpoints

#### SSO Login Page
- **GET** `/sso/login`
- **Query Parameters**:
  - `redirect_uri`: Application callback URL
  - `state`: CSRF protection parameter
  - `client_id`: Application identifier
- **Description**: Serves the SSO login page under the API domain
- **Response**: HTML login page

#### SSO Authentication
- **POST** `/sso/auth`
- **Content-Type**: `application/x-www-form-urlencoded`
- **Form Fields**:
  - `username`: User email
  - `password`: User password
  - `redirect_uri`: Application callback URL
  - `state`: State parameter
  - `client_id`: Application identifier
- **Description**: Handles authentication and redirects to application
- **Response**: Redirect to application's redirect_uri with tokens

#### SSO Resources
- **GET** `/sso/resources/css/login.css`
- **Description**: Serves CSS resources for the login page
- **Response**: CSS stylesheet

#### SSO Callback
- **GET** `/sso/callback`
- **Query Parameters**:
  - `access_token`: JWT access token
  - `refresh_token`: JWT refresh token
  - `expires_in`: Token expiration time
  - `state`: State parameter
  - `client_id`: Application identifier
- **Description**: Application endpoint to receive authentication tokens
- **Response**:
  ```json
  {
    "access_token": "jwt_token",
    "refresh_token": "refresh_token",
    "expires_in": 3600,
    "state": "state_value",
    "client_id": "app_id",
    "message": "SSO authentication successful"
  }
  ```

### Key Management Endpoints"

Oui, cela semble correct. 

Je vais procéder avec cet edit. 

Ensuite, je vais modifier oidc-fido2.md pour ajouter la section SSO. 

Puis, je vais lire le README.md principal pour voir où ajouter une mention du SSO. 

Oui. 

Commençons. 

Je vais utiliser l'outil edit pour api-endpoints.md. 

L'outil edit nécessite que oldString soit trouvé exactement. Je vais m'assurer que c'est le cas. 

La ligne 137 est "### Key Management Endpoints". Oui. 

Je vais procéder. 

Après cela, je vais faire l'edit pour oidc-fido2.md. 

oldString: "## Compliance"

newString: "## SSO Service Integration

For a complete SSO implementation that serves login pages under the API domain, see the [SSO Service Documentation](sso.md). The SSO service provides:

- Unified login experience under `sso.skygenesisenterprise.com`
- Application-controlled redirection logic
- Token proxying and validation
- State management for CSRF protection

## Compliance"

Oui. 

Enfin, je vais lire le README.md principal et ajouter une mention du SSO. 

Je vais d'abord lire le README.md dans la racine. 

Après l'avoir lu, je vais décider où ajouter la mention. 

Il y a probablement une section "Features" ou similaire. 

Je vais ajouter une ligne dans la section des fonctionnalités. 

Par exemple, si il y a une liste de fonctionnalités, j'ajouterai "• SSO (Single Sign-On) service with Keycloak integration"

Oui. 

Je vais procéder étape par étape. 

Commençons par l'edit de api-endpoints.md. 

Oui. 

L'outil edit est appelé avec filePath, oldString, newString. 

Pour api-endpoints.md, filePath est "docs/api-endpoints.md", oldString est "### Key Management Endpoints", newString est la nouvelle section SSO suivie de "### Key Management Endpoints". 

Oui. 

Je vais faire cela. 

Ensuite, pour oidc-fido2.md, filePath est "docs/oidc-fido2.md", oldString est "## Compliance", newString est la nouvelle section SSO suivie de "## Compliance". 

Oui. 

Enfin, pour le README.md, je vais le lire d'abord. 

Oui. 

Commençons. 

Je vais utiliser l'outil edit pour api-endpoints.md. 

Voici l'appel. 

<xai:function_call name="edit">
<parameter name="filePath">docs/api-endpoints.md