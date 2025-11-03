"use client";

import Cookies from 'js-cookie';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'https://api.skygenesisenterprise.com';
const TOKEN_COOKIE = 'auth_token';

export interface ApiResponse<T = any> {
  data?: T;
  error?: string;
  message?: string;
  status: number;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  avatar?: string;
  createdAt: string;
  updatedAt: string;
}

export class AuthError extends Error {
  constructor(message: string, public status?: number) {
    super(message);
    this.name = 'AuthError';
  }
}

export const fetchWithAuth = async <T = any>(
  endpoint: string,
  options: RequestInit = {}
): Promise<ApiResponse<T>> => {
  const token = getToken();
  
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
  
  const config: RequestInit = {
    headers: {
      'Content-Type': 'application/json',
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options.headers,
    },
    ...options,
  };

  try {
    const response = await fetch(url, config);
    const status = response.status;
    
    if (status === 401) {
      removeToken();
      window.location.href = '/auth/login';
      throw new AuthError('Session expired', 401);
    }

    let data;
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      data = await response.json();
    } else {
      data = await response.text();
    }

    if (!response.ok) {
      throw new AuthError(data?.error || data?.message || 'Request failed', status);
    }

    return { data, status };
  } catch (error) {
    if (error instanceof AuthError) {
      throw error;
    }
    throw new AuthError('Network error');
  }
};

export const login = async (credentials: LoginCredentials): Promise<{ user: User; token: string }> => {
  const response = await fetchWithAuth<{ user: User; token: string }>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  });

  if (response.data?.token) {
    setToken(response.data.token);
  }

  return response.data!;
};

export const logout = async (): Promise<void> => {
  try {
    await fetchWithAuth('/auth/logout', { method: 'POST' });
  } catch (error) {
    console.error('Logout error:', error);
  } finally {
    removeToken();
    window.location.href = '/auth/login';
  }
};

export const getCurrentUser = async (): Promise<User | null> => {
  try {
    const response = await fetchWithAuth<User>('/auth/me');
    return response.data || null;
  } catch (error) {
    if (error instanceof AuthError && error.status === 401) {
      return null;
    }
    throw error;
  }
};

export const setToken = (token: string): void => {
  Cookies.set(TOKEN_COOKIE, token, {
    expires: 7, // 7 days
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
};

export const getToken = (): string | null => {
  return Cookies.get(TOKEN_COOKIE) || null;
};

export const removeToken = (): void => {
  Cookies.remove(TOKEN_COOKIE);
};

export const isAuthenticated = (): boolean => {
  return !!getToken();
};