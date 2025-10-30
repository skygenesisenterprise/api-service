"use client";

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8080";

export async function apiRequest<T>(path: string, options: {
  method?: HttpMethod;
  body?: unknown;
  token?: string | null;
  headers?: Record<string, string>;
  cache?: RequestCache;
} = {}): Promise<T> {
  const { method = "GET", body, token, headers = {}, cache } = options;

  const requestHeaders: HeadersInit = {
    "Content-Type": "application/json",
    ...headers,
  };

  if (token) {
    requestHeaders["Authorization"] = `Bearer ${token}`;
    requestHeaders["X-API-Key"] = token;
  }

  const res = await fetch(`${API_BASE_URL}${path}`, {
    method,
    headers: requestHeaders,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: "include",
    cache,
  });

  const contentType = res.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const data = isJson ? await res.json() : (await res.text());

  if (!res.ok) {
    const message = isJson && (data as any)?.message ? (data as any).message : res.statusText;
    throw new Error(message || "Request failed");
  }

  return data as T;
}

// Types for API keys
export interface ApiKey {
  id: string;
  key: string;
  key_type: string;
  tenant: string;
  status: string;
  ttl: number;
  created_at: string;
  permissions: string[];
  vault_path: string;
  certificate?: CertificateInfo;
}

export interface CertificateInfo {
  public_key: string;
  private_key_path: string;
  certificate_type: string;
  fingerprint: string;
}

export interface CreateApiKeyRequest {
  type: string;
  tenant: string;
  ttl: number;
  cert_type?: string;
  status?: string;
}

// API Key service functions
export const apiKeyService = {
  async createKeyWithCertificate(params: CreateApiKeyRequest, token: string): Promise<ApiKey> {
    const queryParams = new URLSearchParams({
      type: params.type,
      tenant: params.tenant,
      ttl: params.ttl.toString(),
      ...(params.cert_type && { cert_type: params.cert_type }),
      ...(params.status && { status: params.status }),
    });

    return apiRequest<ApiKey>(`/api/keys/with-certificate?${queryParams}`, {
      method: "POST",
      token,
    });
  },

  async createSandboxKeyWithCertificate(params: CreateApiKeyRequest, token: string): Promise<ApiKey> {
    const queryParams = new URLSearchParams({
      type: params.type,
      tenant: params.tenant,
      ttl: params.ttl.toString(),
      ...(params.cert_type && { cert_type: params.cert_type }),
    });

    return apiRequest<ApiKey>(`/api/keys/sandbox/with-certificate?${queryParams}`, {
      method: "POST",
      token,
    });
  },

  async createProductionKeyWithCertificate(params: CreateApiKeyRequest, token: string): Promise<ApiKey> {
    const queryParams = new URLSearchParams({
      type: params.type,
      tenant: params.tenant,
      ttl: params.ttl.toString(),
      ...(params.cert_type && { cert_type: params.cert_type }),
    });

    return apiRequest<ApiKey>(`/api/keys/production/with-certificate?${queryParams}`, {
      method: "POST",
      token,
    });
  },

  async getKey(keyId: string, token: string): Promise<ApiKey> {
    return apiRequest<ApiKey>(`/api/keys/${keyId}`, {
      method: "GET",
      token,
    });
  },

  async listKeys(tenant: string, token: string): Promise<ApiKey[]> {
    return apiRequest<ApiKey[]>(`/api/keys?tenant=${tenant}`, {
      method: "GET",
      token,
    });
  },

  async revokeKey(keyId: string, token: string): Promise<void> {
    return apiRequest<void>(`/api/keys/${keyId}`, {
      method: "DELETE",
      token,
    });
  },
};