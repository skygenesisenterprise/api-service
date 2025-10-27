# API Endpoints Documentation

## Base URL
All API endpoints are served under `http://localhost:3000` in development.

## Authentication
Most endpoints require authentication via JWT tokens in the `Authorization` header:
```
Authorization: Bearer <jwt_token>
```

## Endpoints

### Hello World
- **GET** `/hello`
- **Description**: Simple health check endpoint
- **Response**: `"Hello, World!"`

### Authentication Endpoints

#### Login
- **POST** `/auth/login`
- **Headers**:
  - `x-app-token`: Application token for validation
- **Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "password"
  }
  ```
- **Response**:
  ```json
  {
    "access_token": "jwt_token",
    "refresh_token": "refresh_token",
    "expires_in": 3600,
    "user": {
      "id": "user_id",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "roles": ["employee"],
      "created_at": "2023-01-01T00:00:00Z",
      "enabled": true
    }
  }
  ```

#### Register
- **POST** `/auth/register`
- **Body**:
  ```json
  [
    {
      "id": "user_id",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "roles": ["employee"],
      "created_at": "2023-01-01T00:00:00Z",
      "enabled": true
    },
    "password"
  ]
  ```
- **Response**: `200 OK`

#### Password Recovery
- **POST** `/auth/recover`
- **Body**:
  ```json
  {
    "email": "user@example.com"
  }
  ```
- **Response**: `200 OK`

#### Get Current User
- **GET** `/auth/me`
- **Headers**: `Authorization: Bearer <token>`
- **Response**:
  ```json
  {
    "id": "user_id",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "roles": ["employee"],
    "created_at": "2023-01-01T00:00:00Z",
    "enabled": true
  }
  ```

### Key Management Endpoints

#### Create API Key
- **POST** `/api/keys`
- **Headers**: `Authorization: Bearer <token>`
- **Query Parameters**:
  - `type`: Key type (`client`, `server`, `database`)
  - `tenant`: Tenant identifier
  - `ttl`: Time to live in seconds (default: 3600)
- **Response**:
  ```json
  {
    "id": "key_id",
    "key_type": "Client",
    "tenant": "tenant_id",
    "ttl": 3600,
    "created_at": "2023-01-01T00:00:00Z",
    "permissions": ["read"],
    "vault_path": "secret/client"
  }
  ```

#### List API Keys
- **GET** `/api/keys`
- **Headers**: `Authorization: Bearer <token>`
- **Query Parameters**:
  - `tenant`: Tenant identifier
- **Response**:
  ```json
  [
    {
      "id": "key_id",
      "key_type": "Client",
      "tenant": "tenant_id",
      "ttl": 3600,
      "created_at": "2023-01-01T00:00:00Z",
      "permissions": ["read"],
      "vault_path": "secret/client"
    }
  ]
  ```

#### Get API Key
- **GET** `/api/keys/{id}`
- **Headers**: `Authorization: Bearer <token>`
- **Response**: Same as create key response

#### Revoke API Key
- **DELETE** `/api/keys/{id}`
- **Headers**: `Authorization: Bearer <token>`
- **Response**:
  ```json
  {
    "message": "Key revoked"
  }
  ```

## Error Responses

All endpoints may return the following error responses:

- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Missing or invalid authentication
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **500 Internal Server Error**: Server error

Error response format:
```json
{
  "error": "Error message"
}
```

## Rate Limiting

API endpoints implement rate limiting to prevent abuse. Rate limits vary by endpoint and user role.

## Data Types

### User
```json
{
  "id": "string",
  "email": "string",
  "first_name": "string?",
  "last_name": "string?",
  "roles": ["string"],
  "created_at": "datetime",
  "enabled": "boolean"
}
```

### ApiKey
```json
{
  "id": "string",
  "key_type": "Client|Server|Database",
  "tenant": "string",
  "ttl": "number",
  "created_at": "datetime",
  "permissions": ["string"],
  "vault_path": "string"
}
```