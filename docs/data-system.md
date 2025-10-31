# Data System - API `/api/v1/data`

## Overview

The data system provides a secure REST API for managing database connections and executing queries under a Zero Trust Network Access (ZTNA) model. This documentation explains how to integrate and use the `/api/v1/data` route in your applications and services.

## Authentication

All requests require valid JWT authentication. Obtain a token via the API authentication system and include it in all requests:

```javascript
const headers = {
  'Authorization': `Bearer ${jwtToken}`,
  'Content-Type': 'application/json'
};
```

## ZTNA Architecture

The system implements Zero Trust Network Access with:

- **Authentication**: JWT verification on every request
- **Authorization**: Access policy evaluation per request
- **Audit**: Complete logging of all operations
- **Isolation**: Access control by tenant and resource

## Main Endpoints

### 1. Connection Management

#### Create a Connection

```javascript
async function createDatabaseConnection(name, type, host, port, database, username, passwordRef, tenant) {
  const response = await fetch('/api/v1/data/connections', {
    method: 'POST',
    headers: headers,
    body: new URLSearchParams({
      name,
      type, // 'postgresql', 'mysql', etc.
      host,
      port,
      database,
      username,
      password_ref: passwordRef,
      tenant
    })
  });

  if (!response.ok) {
    throw new Error(`Connection creation error: ${response.status}`);
  }

  return await response.json();
}
```

#### List Connections

```javascript
async function listConnections(tenant) {
  const response = await fetch(`/api/v1/data/connections?tenant=${tenant}`, {
    method: 'GET',
    headers: headers
  });

  if (!response.ok) {
    throw new Error(`List connections error: ${response.status}`);
  }

  return await response.json();
}
```

### 2. Query Execution

#### Basic Data Query

```javascript
async function executeQuery(connectionId, sqlQuery, parameters = [], readOnly = true, timeout = 30) {
  const response = await fetch('/api/v1/data/query', {
    method: 'POST',
    headers: headers,
    body: JSON.stringify({
      connection_id: connectionId,
      query: sqlQuery,
      parameters,
      read_only: readOnly,
      timeout
    })
  });

  if (!response.ok) {
    throw new Error(`Query execution error: ${response.status}`);
  }

  const result = await response.json();

  if (!result.success) {
    throw new Error(`Query error: ${result.error.message}`);
  }

  return result.data;
}
```

#### Complete Usage Example

```javascript
// Retrieve user data
async function getActiveUsers() {
  try {
    const users = await executeQuery(
      'conn-123',
      'SELECT id, name, email FROM users WHERE status = ? AND created_at > ?',
      ['active', '2024-01-01'],
      true, // read-only
      60   // timeout 60s
    );

    console.log('Active users:', users.rows);
    return users.rows;
  } catch (error) {
    console.error('Error retrieving users:', error);
    throw error;
  }
}

// Update data (with caution)
async function updateUserStatus(userId, newStatus) {
  try {
    const result = await executeQuery(
      'conn-123',
      'UPDATE users SET status = ?, updated_at = NOW() WHERE id = ?',
      [newStatus, userId],
      false, // write operation
      30
    );

    console.log('Update completed, affected rows:', result.row_count);
    return result;
  } catch (error) {
    console.error('Update error:', error);
    throw error;
  }
}
```

### 3. Health Check

```javascript
async function checkConnectionHealth(connectionId) {
  const response = await fetch(`/api/v1/data/health/${connectionId}`, {
    method: 'GET',
    headers: headers
  });

  if (!response.ok) {
    throw new Error(`Health check error: ${response.status}`);
  }

  return await response.json();
}
```

## Error Handling

### Centralized Error Handling

```javascript
class DataApiError extends Error {
  constructor(message, statusCode, details) {
    super(message);
    this.statusCode = statusCode;
    this.details = details;
  }
}

async function handleApiCall(apiCall) {
  try {
    return await apiCall();
  } catch (error) {
    if (error instanceof DataApiError) {
      throw error;
    }

    // Network or parsing error
    if (error.name === 'TypeError' || error.name === 'SyntaxError') {
      throw new DataApiError('API communication error', 0, error.message);
    }

    // HTTP error
    if (error.statusCode) {
      throw new DataApiError(error.message, error.statusCode, error.details);
    }

    throw new DataApiError('Unknown error', 500, error.message);
  }
}
```

### Common Error Codes

| Code | Description | Action |
|------|-------------|--------|
| 400 | Invalid parameters | Check query parameters |
| 401 | Not authenticated | Refresh JWT token |
| 403 | Access denied | Check ZTNA permissions |
| 404 | Resource not found | Check connection ID |
| 429 | Rate limit exceeded | Implement exponential backoff |
| 500 | Server error | Contact administrator |

## Integration Best Practices

### 1. Connection Management

```javascript
class DatabaseManager {
  constructor() {
    this.connections = new Map();
  }

  async getConnection(tenant, connectionName) {
    const key = `${tenant}:${connectionName}`;

    if (!this.connections.has(key)) {
      const connections = await listConnections(tenant);
      const connection = connections.find(c => c.name === connectionName);

      if (!connection) {
        throw new Error(`Connection ${connectionName} not found for tenant ${tenant}`);
      }

      this.connections.set(key, connection);
    }

    return this.connections.get(key);
  }
}
```

### 2. Caching and Optimization

```javascript
class QueryCache {
  constructor(ttl = 300000) { // 5 minutes
    this.cache = new Map();
    this.ttl = ttl;
  }

  get(key) {
    const item = this.cache.get(key);
    if (item && Date.now() - item.timestamp < this.ttl) {
      return item.data;
    }
    this.cache.delete(key);
    return null;
  }

  set(key, data) {
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }
}

const queryCache = new QueryCache();

// Usage
async function cachedQuery(connectionId, query, params) {
  const key = `${connectionId}:${query}:${JSON.stringify(params)}`;
  let result = queryCache.get(key);

  if (!result) {
    result = await executeQuery(connectionId, query, params);
    queryCache.set(key, result);
  }

  return result;
}
```

### 3. Retry and Circuit Breaker

```javascript
async function executeWithRetry(apiCall, maxRetries = 3, delay = 1000) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await apiCall();
    } catch (error) {
      if (attempt === maxRetries || error.statusCode < 500) {
        throw error;
      }

      console.warn(`Attempt ${attempt} failed, retry in ${delay}ms`);
      await new Promise(resolve => setTimeout(resolve, delay));
      delay *= 2; // Exponential backoff
    }
  }
}
```

### 4. Logging and Monitoring

```javascript
async function executeQueryWithLogging(connectionId, query, params, context = {}) {
  const startTime = Date.now();

  try {
    console.log('Executing query:', {
      connectionId,
      query,
      params,
      context,
      timestamp: new Date().toISOString()
    });

    const result = await executeQuery(connectionId, query, params);

    console.log('Query successful:', {
      connectionId,
      executionTime: Date.now() - startTime,
      rowCount: result.row_count
    });

    return result;
  } catch (error) {
    console.error('Query error:', {
      connectionId,
      query,
      params,
      context,
      error: error.message,
      executionTime: Date.now() - startTime
    });

    throw error;
  }
}
```

## Security

### Secret Management

- Never store passwords in plain text
- Use secret references (`password_ref`)
- Rotate credentials regularly

### Input Validation

```javascript
function validateQueryInput(query, params) {
  if (!query || typeof query !== 'string') {
    throw new Error('SQL query required');
  }

  if (query.toLowerCase().includes('drop') ||
      query.toLowerCase().includes('delete') && !query.toLowerCase().includes('where')) {
    throw new Error('Dangerous operations forbidden without conditions');
  }

  if (params && !Array.isArray(params)) {
    throw new Error('Parameters must be an array');
  }
}
```

### Audit and Compliance

- All requests are automatically audited
- Keep audit logs for compliance
- Monitor unusual access

## Integration Examples by Use Case

### Web Application - Data Dashboard

```javascript
// React component to display metrics
import { useState, useEffect } from 'react';

function DataDashboard({ connectionId }) {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadMetrics() {
      try {
        const result = await executeQuery(
          connectionId,
          `SELECT
            COUNT(*) as total_users,
            COUNT(CASE WHEN status = 'active' THEN 1 END) as active_users,
            AVG(created_at) as avg_registration_date
           FROM users`
        );

        setMetrics(result.rows[0]);
      } catch (error) {
        console.error('Error loading metrics:', error);
      } finally {
        setLoading(false);
      }
    }

    loadMetrics();
  }, [connectionId]);

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>Dashboard</h2>
      <p>Total users: {metrics.total_users}</p>
      <p>Active users: {metrics.active_users}</p>
    </div>
  );
}
```

### Backend Service - Data Synchronization

```javascript
// Node.js service for periodic synchronization
class DataSyncService {
  constructor(connectionId, syncInterval = 3600000) { // 1 hour
    this.connectionId = connectionId;
    this.interval = setInterval(() => this.sync(), syncInterval);
  }

  async sync() {
    try {
      console.log('Starting data synchronization');

      // Retrieve new data
      const newData = await executeQuery(
        this.connectionId,
        'SELECT * FROM events WHERE synced = false'
      );

      // Process data
      for (const row of newData.rows) {
        await this.processEvent(row);
      }

      // Mark as synced
      await executeQuery(
        this.connectionId,
        'UPDATE events SET synced = true WHERE id = ?',
        [newData.rows.map(r => r.id)]
      );

      console.log(`${newData.rows.length} events synchronized`);
    } catch (error) {
      console.error('Synchronization error:', error);
      // Implement error notification
    }
  }

  async processEvent(event) {
    // Business logic processing
    console.log('Processing event:', event);
  }

  stop() {
    clearInterval(this.interval);
  }
}
```

## Troubleshooting

### Common Issues

1. **Expired token**: Refresh JWT token
2. **Unavailable connection**: Check health with `/health/{id}`
3. **Timeout**: Increase timeout or optimize query
4. **Rate limit**: Implement queuing system
5. **Insufficient permissions**: Check ZTNA policies

### Debugging

```javascript
// Debug mode for development
const DEBUG = process.env.NODE_ENV === 'development';

async function debugExecuteQuery(connectionId, query, params) {
  if (DEBUG) {
    console.log('Debug - Query:', { connectionId, query, params });
  }

  const result = await executeQuery(connectionId, query, params);

  if (DEBUG) {
    console.log('Debug - Result:', result);
  }

  return result;
}
```

For more information on other endpoints or advanced configuration, consult the complete API documentation.