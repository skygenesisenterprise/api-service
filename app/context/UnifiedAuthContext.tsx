"use client";

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';

interface User {
  id: string;
  globalId: string;
  primaryEmail: string;
  username?: string;
  profile?: any;
}

interface UserPermissions {
  applications: string[];
  services: string[];
  roles: string[];
  permissions: string[];
  organizations: string[];
}

interface AuthContextType {
  user: User | null;
  permissions: UserPermissions | null;
  loading: boolean;
  error: string | null;
  login: (identifier: string, password: string) => Promise<boolean>;
  logout: () => void;
  refreshToken: () => Promise<boolean>;
  checkPermission: (permission: string) => boolean;
  hasAccess: (resource: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [permissions, setPermissions] = useState<UserPermissions | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Vérifier l'authentification au chargement
  useEffect(() => {
    const checkAuth = async () => {
      try {
        setLoading(true);
        setError(null);
        
        const token = localStorage.getItem('token');
        if (!token) {
          console.log('🔍 No token found, user not authenticated');
          return;
        }

        console.log('🔍 Validating token...');
        
        // Valider le token et obtenir les informations utilisateur
        const validateResponse = await fetch('/api/v1/auth/validate', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!validateResponse.ok) {
          throw new Error(`Token validation failed: ${validateResponse.status}`);
        }

        const validateResult = await validateResponse.json();
        console.log('✅ Token validation result:', validateResult);
        
        if (!validateResult.success) {
          throw new Error('Invalid token response');
        }
        
        setUser(validateResult.data.user);
        
        // Obtenir les permissions détaillées
        console.log('🔍 Fetching permissions...');
        const permsResponse = await fetch('/api/v1/auth/permissions', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!permsResponse.ok) {
          throw new Error(`Permissions fetch failed: ${permsResponse.status}`);
        }
        
        const permsResult = await permsResponse.json();
        console.log('✅ Permissions result:', permsResult);
        
        if (permsResult.success) {
          setPermissions(permsResult.data);
          console.log('🎉 User authenticated:', validateResult.data.user.primaryEmail);
          console.log('🔑 User permissions:', {
            services: permsResult.data.services,
            roles: permsResult.data.roles,
            permissions: permsResult.data.permissions
          });
        } else {
          throw new Error('Invalid permissions response');
        }
        
      } catch (error) {
        console.error('❌ Auth check failed:', error);
        setError(error instanceof Error ? error.message : 'Authentication failed');
        
        // Nettoyer le stockage en cas d'erreur
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, []);

  // Fonction de connexion
  const login = async (identifier: string, password: string): Promise<boolean> => {
    try {
      setLoading(true);
      setError(null);
      
      console.log('🔐 Attempting login...');
      
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier, password })
      });
      
      const result = await response.json();
      
      if (result.success) {
        console.log('✅ Login successful');
        
        // Stocker les tokens
        localStorage.setItem('token', result.data.token);
        localStorage.setItem('refreshToken', result.data.refreshToken);
        
        // Mettre à jour l'état
        setUser(result.data.user);
        
        // Obtenir les permissions
        const token = result.data.token;
        const permsResponse = await fetch('/api/v1/auth/permissions', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (permsResponse.ok) {
          const permsResult = await permsResponse.json();
          if (permsResult.success) {
            setPermissions(permsResult.data);
            console.log('🎉 User logged in:', result.data.user.primaryEmail);
            return true;
          }
        }
      } else {
        console.error('❌ Login failed:', result.error);
        setError(result.error || 'Login failed');
      }
      
      return false;
    } catch (error) {
      console.error('❌ Login error:', error);
      setError(error instanceof Error ? error.message : 'Login failed');
      return false;
    } finally {
      setLoading(false);
    }
  };

  // Fonction de déconnexion
  const logout = async () => {
    try {
      const token = localStorage.getItem('token');
      if (token) {
        await fetch('/api/v1/auth/logout', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` }
        });
      }
      
      // Nettoyer l'état et le stockage
      setUser(null);
      setPermissions(null);
      setError(null);
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
      
      console.log('👋 User logged out');
    } catch (error) {
      console.error('❌ Logout error:', error);
    }
  };

  // Rafraîchir le token
  const refreshToken = async (): Promise<boolean> => {
    try {
      const refresh_token = localStorage.getItem('refreshToken');
      if (!refresh_token) {
        return false;
      }
      
      const response = await fetch('/api/v1/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken })
      });
      
      const result = await response.json();
      
      if (result.success) {
        localStorage.setItem('token', result.data.token);
        localStorage.setItem('refreshToken', result.data.refreshToken);
        
        // Mettre à jour l'utilisateur
        setUser(result.data.user);
        
        return true;
      }
      
      return false;
    } catch (error) {
      console.error('❌ Token refresh error:', error);
      return false;
    }
  };

  // Vérifier une permission spécifique
  const checkPermission = (permission: string): boolean => {
    if (!permissions) return false;
    
    return permissions.permissions.includes(permission) ||
           permissions.permissions.includes('*') ||
           permissions.roles.includes('owner') ||
           permissions.roles.includes('admin');
  };

  // Vérifier l'accès à une ressource
  const hasAccess = (resource: string): boolean => {
    if (!permissions) return false;
    
    return permissions.services.includes(resource) ||
           permissions.services.includes('*') ||
           permissions.permissions.includes(`${resource}:access`) ||
           permissions.permissions.includes(`${resource}:read`) ||
           permissions.roles.includes('owner') ||
           permissions.roles.includes('admin');
  };

  const value: AuthContextType = {
    user,
    permissions,
    loading,
    error,
    login,
    logout,
    refreshToken,
    checkPermission,
    hasAccess
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}