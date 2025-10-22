// API Client for frontend communication with backend

export interface ApiResponse<T = any> {
  message?: string;
  data?: T;
  error?: string;
}

export interface ApiKey {
  id: string;
  label: string;
  permissions: string[];
  quota_limit: number;
  usage_count: number;
  status: string;
  created_at: string;
}

export interface CreateApiKeyRequest {
  label: string;
  permissions: string[];
  quota_limit?: number;
}

class ApiClient {
  private apiKey: string | null = null;
  private orgId: string | null = null;
  private baseUrl: string;

  constructor(baseUrl: string = '') {
    this.baseUrl = baseUrl || (typeof window !== 'undefined' ? '' : 'http://localhost:8080');
  }

  setAuth(apiKey: string, orgId: string) {
    this.apiKey = apiKey;
    this.orgId = orgId;
  }

  private getHeaders(): HeadersInit {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    return headers;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.baseUrl}/api/v1${endpoint}`;

    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...this.getHeaders(),
          ...options.headers,
        },
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || data.message || `HTTP ${response.status}`);
      }

      return data;
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  // API Key Management
  async createApiKey(data: CreateApiKeyRequest): Promise<ApiResponse<{ id: string; key_value: string; label: string; permissions: string[]; created_at: string }>> {
    if (!this.orgId) throw new Error('Organization ID not set');
    return this.request(`/organizations/${this.orgId}/api-keys`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getApiKeys(): Promise<ApiResponse<ApiKey[]>> {
    if (!this.orgId) throw new Error('Organization ID not set');
    return this.request(`/organizations/${this.orgId}/api-keys`);
  }

  async revokeApiKey(keyId: string): Promise<ApiResponse> {
    if (!this.orgId) throw new Error('Organization ID not set');
    return this.request(`/organizations/${this.orgId}/api-keys/${keyId}`, {
      method: 'DELETE',
    });
  }

  async validateApiKey(): Promise<ApiResponse<{ organization_id: string; permissions: string[]; quota_limit: number; usage_count: number }>> {
    return this.request('/validate');
  }

  // Messaging
  async getConversations(): Promise<ApiResponse<any[]>> {
    if (!this.orgId) throw new Error('Organization ID not set');
    return this.request(`/messaging/organizations/${this.orgId}/conversations`);
  }

  async getConversation(conversationId: string): Promise<ApiResponse<any>> {
    if (!this.orgId) throw new Error('Organization ID not set');
    return this.request(`/messaging/organizations/${this.orgId}/conversations/${conversationId}`);
  }

  async createConversation(data: { title?: string; type: string; participant_ids: string[] }): Promise<ApiResponse<any>> {
    if (!this.orgId) throw new Error('Organization ID not set');
    return this.request(`/messaging/organizations/${this.orgId}/conversations`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async sendMessage(conversationId: string, data: { content?: string; message_type?: string; reply_to_id?: string }): Promise<ApiResponse<any>> {
    if (!this.orgId) throw new Error('Organization ID not set');
    return this.request(`/messaging/organizations/${this.orgId}/conversations/${conversationId}/messages`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getMessages(conversationId: string, limit = 50, offset = 0): Promise<ApiResponse<any[]>> {
    if (!this.orgId) throw new Error('Organization ID not set');
    return this.request(`/messaging/organizations/${this.orgId}/conversations/${conversationId}/messages?limit=${limit}&offset=${offset}`);
  }

  // Utility methods
  isAuthenticated(): boolean {
    return !!(this.apiKey && this.orgId);
  }

  clearAuth() {
    this.apiKey = null;
    this.orgId = null;
  }
}

// Export singleton instance
export const apiClient = new ApiClient();

// Helper hook for React components
export function useApiClient() {
  // Load from localStorage on client side
  if (typeof window !== 'undefined') {
    const apiKey = localStorage.getItem('admin_api_key');
    const orgId = localStorage.getItem('admin_org_id');

    if (apiKey && orgId) {
      apiClient.setAuth(apiKey, orgId);
    }
  }

  return apiClient;
}