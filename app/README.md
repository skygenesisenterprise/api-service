# Sky Genesis Enterprise API Client

[![Next.js](https://img.shields.io/badge/Next.js-14.0+-black)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.0+-38B2AC)](https://tailwindcss.com/)

The official Next.js client for the Sky Genesis Enterprise (SGE) API. This application provides a secure and sovereign web interface to interact with the Aether ecosystem backend services.

## 🚀 Features

### 🔍 **Aether Sovereign Search**
- **Multi-source search** : Aether Mail, Aether Office, and other federated services
- **Advanced filtering** : by source, language, dates, and custom criteria
- **Intelligent auto-completion** : real-time suggestions
- **Pagination & sorting** : optimized results with relevance scoring
- **Zero-trust security** : OAuth2 + FIDO2 authentication

### 🔐 **Authentication & Security**
- **OAuth2 / OIDC** : Authentication via Keycloak
- **FIDO2 / WebAuthn** : Hardware-backed authentication
- **Mandatory VPN** : Access via encrypted tunnel (Tailscale/WireGuard)
- **PGP Encryption** : Cryptographic signing of results

### 📊 **Observability**
- **Real-time metrics** : Performance and usage monitoring
- **Audit logs** : Complete traceability of operations
- **OpenTelemetry** : Distributed monitoring

## 📦 Installation

### Prerequisites

- **Node.js** 18.0+
- **npm** or **yarn** or **pnpm**
- **VPN Access** : Connection to SGE private network
- **API Backend** : Operational SGE API instance

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/skygenesisenterprise/api-client.git
cd api-client

# Install dependencies
pnpm install

# Configure environment variables
cp .env.example .env.local

# Start in development mode
pnpm run dev
```

### Environment Variables

Create a `.env.local` file:

```env
# API Configuration
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080
NEXT_PUBLIC_API_VERSION=v1

# Authentication
NEXT_PUBLIC_KEYCLOAK_URL=https://auth.skygenesisenterprise.com
NEXT_PUBLIC_KEYCLOAK_REALM=sky-genesis
NEXT_PUBLIC_KEYCLOAK_CLIENT_ID=aether-client

# FIDO2 Configuration
NEXT_PUBLIC_FIDO2_RP_ID=skygenesisenterprise.com
NEXT_PUBLIC_FIDO2_RP_NAME="Sky Genesis Enterprise"

# VPN Configuration
NEXT_PUBLIC_VPN_REQUIRED=true
NEXT_PUBLIC_VPN_CHECK_ENDPOINT=/api/v1/vpn/status

# Feature Flags
NEXT_PUBLIC_ENABLE_SEARCH=true
NEXT_PUBLIC_ENABLE_METRICS=true
NEXT_PUBLIC_ENABLE_AUDIT_LOGS=true
```

## 🏗️ Architecture

### Project Structure

```
app/
├── components/          # Reusable React components
│   ├── Navigation.tsx   # Main navigation
│   └── ...
├── context/            # React contexts (Auth, etc.)
│   └── AuthContext.tsx
├── pages/              # Next.js pages (App Router)
│   ├── auth/           # Authentication pages
│   ├── dashboard/      # Dashboard
│   ├── docs/           # Documentation
│   └── ...
├── styles/             # Global styles
├── utils/              # Utilities
│   └── apiClient.ts    # Main API client
└── ...
```

### API Client

The API client (`utils/apiClient.ts`) provides a unified interface for all backend API interactions:

```typescript
import { apiRequest } from '@/utils/apiClient';

// Usage example
const data = await apiRequest('/api/v1/search', {
  method: 'POST',
  body: { query: 'renewable energy' },
  token: userToken
});
```

## 🔍 Using Search

### Basic Search

```typescript
import { apiRequest } from '@/utils/apiClient';

interface SearchQuery {
  query: string;
  filters?: {
    source?: string[];
    lang?: string;
    date_from?: string;
    date_to?: string;
  };
  limit?: number;
  sort?: 'relevance' | 'date' | 'score';
}

const searchDocuments = async (query: SearchQuery) => {
  try {
    const response = await apiRequest('/api/v1/search', {
      method: 'POST',
      body: query,
      token: authToken
    });

    return response;
  } catch (error) {
    console.error('Search error:', error);
    throw error;
  }
};

// Usage
const results = await searchDocuments({
  query: 'renewable energy',
  filters: {
    source: ['aether_mail', 'aether_office'],
    lang: 'en'
  },
  limit: 20
});
```

### Auto-completion

```typescript
const getSuggestions = async (prefix: string) => {
  const response = await apiRequest('/api/v1/search/suggest', {
    method: 'GET',
    token: authToken,
    headers: {
      // Query parameters as headers for GET requests
      'X-Prefix': prefix,
      'X-Limit': '10'
    }
  });

  return response.suggestions;
};
```

### Search with React Hook

```typescript
import { useState, useEffect } from 'react';
import { apiRequest } from '@/utils/apiClient';

export const useSearch = () => {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const search = async (query) => {
    setLoading(true);
    setError(null);

    try {
      const data = await apiRequest('/api/v1/search', {
        method: 'POST',
        body: query,
        token: localStorage.getItem('authToken')
      });

      setResults(data.results);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return { results, loading, error, search };
};
```

### Search Component

```tsx
import React, { useState } from 'react';
import { useSearch } from '@/hooks/useSearch';

export const SearchComponent = () => {
  const [query, setQuery] = useState('');
  const { results, loading, error, search } = useSearch();

  const handleSearch = async () => {
    if (query.trim()) {
      await search({
        query: query.trim(),
        filters: {
          source: ['aether_mail', 'aether_office']
        },
        limit: 20
      });
    }
  };

  return (
    <div className="search-container">
      <div className="search-input-group">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search in Aether..."
          onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
        />
        <button onClick={handleSearch} disabled={loading}>
          {loading ? 'Searching...' : 'Search'}
        </button>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="search-results">
        {results.map((result) => (
          <div key={result.id} className="result-item">
            <h3>{result.title}</h3>
            <p className="snippet">{result.snippet}</p>
            <div className="metadata">
              <span>Source: {result.source}</span>
              <span>Score: {result.score.toFixed(2)}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
```

## 🔐 Authentication

### OAuth2 Configuration

```typescript
// context/AuthContext.tsx
import { createContext, useContext, useState, useEffect } from 'react';

interface AuthContextType {
  user: any;
  token: string | null;
  login: () => void;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState<string | null>(null);

  const login = async () => {
    // Redirect to Keycloak
    window.location.href = `${process.env.NEXT_PUBLIC_KEYCLOAK_URL}/auth`;
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('authToken');
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout, isAuthenticated: !!token }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};
```

### FIDO2 Authentication

```typescript
// utils/fido2.ts
export const authenticateWithFIDO2 = async () => {
  try {
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: new Uint8Array(32), // Generated by server
        rpId: process.env.NEXT_PUBLIC_FIDO2_RP_ID,
        userVerification: 'required',
        timeout: 60000,
      },
    });

    // Send credential to server for validation
    const response = await apiRequest('/api/v1/auth/fido2/verify', {
      method: 'POST',
      body: {
        credential: credential.toJSON(),
      },
      token: authToken,
    });

    return response;
  } catch (error) {
    console.error('FIDO2 authentication failed:', error);
    throw error;
  }
};
```

## 📊 Metrics and Monitoring

### Search Metrics

```typescript
const getSearchMetrics = async () => {
  const metrics = await apiRequest('/api/v1/search/metrics', {
    method: 'GET',
    token: adminToken,
    headers: {
      'X-Time-Range': '24h'
    }
  });

  return metrics;
};

// Metrics display
const SearchMetrics = () => {
  const [metrics, setMetrics] = useState([]);

  useEffect(() => {
    getSearchMetrics().then(setMetrics);
  }, []);

  return (
    <div className="metrics-dashboard">
      {metrics.map((metric) => (
        <div key={metric.name} className="metric-card">
          <h4>{metric.name}</h4>
          <span className="value">{metric.value}</span>
          <span className="timestamp">{metric.timestamp}</span>
        </div>
      ))}
    </div>
  );
};
```

## 🛠️ Development

### Available Scripts

```bash
# Development
pnpm run dev          # Start development server
pnpm run build        # Production build
pnpm run start        # Start in production
pnpm run lint         # Code linting
pnpm run type-check   # TypeScript checking

# Testing
pnpm run test         # Unit tests
pnpm run test:e2e     # End-to-end tests
pnpm run test:coverage # Tests with coverage

# Storybook
pnpm run storybook    # Start Storybook
```

### Component Structure

#### Search Components

```
components/search/
├── SearchBar.tsx          # Main search bar
├── SearchResults.tsx      # Results display
├── SearchFilters.tsx      # Advanced filters
├── SearchSuggestions.tsx  # Auto-completion
├── SearchMetrics.tsx      # Performance metrics
└── index.ts
```

#### Custom Hooks

```typescript
// hooks/useSearch.ts
import { useState, useCallback } from 'react';
import { apiRequest } from '@/utils/apiClient';

export const useSearch = () => {
  const [state, setState] = useState({
    results: [],
    loading: false,
    error: null,
    total: 0,
  });

  const search = useCallback(async (query) => {
    setState(prev => ({ ...prev, loading: true, error: null }));

    try {
      const response = await apiRequest('/api/v1/search', {
        method: 'POST',
        body: query,
      });

      setState({
        results: response.results,
        loading: false,
        error: null,
        total: response.metadata.total_results,
      });
    } catch (error) {
      setState(prev => ({
        ...prev,
        loading: false,
        error: error.message,
      }));
    }
  }, []);

  return { ...state, search };
};
```

## 🔒 Security

### Best Practices

1. **Never store tokens in localStorage** (except for session)
2. **Use HTTPS in production**
3. **Validate all user inputs**
4. **Implement session timeouts**
5. **Check permissions on client AND server side**

### Error Handling

```typescript
// utils/errorHandler.ts
export const handleApiError = (error: any) => {
  if (error.message.includes('401')) {
    // Token expired - redirect to login
    window.location.href = '/auth/login';
  } else if (error.message.includes('403')) {
    // Insufficient permissions
    alert('Access denied');
  } else if (error.message.includes('VPN')) {
    // VPN required
    alert('VPN connection required');
  } else {
    // Generic error
    console.error('API error:', error);
  }
};
```

## 📚 API Documentation

### Main Endpoints

| Endpoint | Method | Description | Authentication |
|----------|--------|-------------|----------------|
| `/api/v1/search` | POST | Main search | OAuth2 + VPN |
| `/api/v1/search/suggest` | GET | Auto-completion | OAuth2 |
| `/api/v1/search/metrics` | GET | Metrics | Admin |
| `/api/v1/auth/login` | POST | Authentication | - |
| `/api/v1/auth/fido2` | POST | FIDO2 challenge | OAuth2 |

### Error Codes

- `400` : Bad request
- `401` : Unauthorized
- `403` : Forbidden / VPN required
- `429` : Rate limiting
- `500` : Server error

## 🤝 Contributing

### Contribution Process

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Create** a Pull Request

### Code Standards

- **Strict TypeScript** enabled
- **ESLint** and **Prettier** configured
- **Unit tests** required (Jest + React Testing Library)
- **Storybook** for components
- **Conventional commits**

## 📄 License

**Classified - Internal Use Only**

This project is part of the Sky Genesis Enterprise ecosystem and is subject to the following classification rules:

- **Classification Level** : INTERNAL
- **Distribution** : Restricted to authorized personnel
- **Audit** : All operations are tracked
- **License** : MIT (Open Source for Strategic Transparency)

## 🆘 Support

### Resources

- **API Documentation** : `/docs/api`
- **Developer Guide** : `/docs/developer`
- **Technical Support** : `support@skygenesisenterprise.com`
- **Issues** : [GitHub Issues](https://github.com/sky-genesis-enterprise/api-client/issues)

### Emergency Contacts

- **Security** : `security@skygenesisenterprise.com`
- **Infrastructure** : `infra@skygenesisenterprise.com`
- **Development** : `dev@skygenesisenterprise.com`

---

**Sky Genesis Enterprise** - *Sovereign Infrastructure for the Digital Age* 🛡️</content>
</xai:function_call">## README Translated to English

I've successfully translated the README from French to English. The translation maintains:

### ✅ **Key Features Preserved**

- **Complete documentation** of the search functionality
- **Code examples** in TypeScript/React
- **Security emphasis** (VPN, FIDO2, OAuth2)
- **Architecture explanations**
- **Development guidelines**
- **API documentation**

### 🔄 **Translation Quality**

- **Technical terms** kept in English (OAuth2, FIDO2, API, etc.)
- **Product names** maintained (Sky Genesis Enterprise, Aether)
- **Code comments** and examples properly translated
- **Cultural context** preserved for enterprise/security focus

### 📋 **Structure Maintained**

1. **Introduction** - Overview and features
2. **Installation** - Setup and configuration
3. **Architecture** - Project structure
4. **Search Usage** - Detailed search API examples
5. **Authentication** - OAuth2 and FIDO2 setup
6. **Metrics** - Monitoring and observability
7. **Development** - Scripts and best practices
8. **Security** - Guidelines and error handling
9. **API Docs** - Endpoints and error codes
10. **Contributing** - Development process
11. **License & Support** - Legal and contact info

The README is now fully in English and ready for international development teams working on the Sky Genesis Enterprise API client. 🚀