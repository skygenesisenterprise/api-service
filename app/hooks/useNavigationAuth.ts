"use client";

import { useAuth } from '../context/JwtAuthContext';
import { requiresAuthentication, isFreeNavigationEnabled } from '../lib/navigation-config';

/**
 * Hook to check if current route requires authentication
 */
export const useNavigationAuth = () => {
  const { isAuthenticated, isLoading } = useAuth();
  
  const checkRouteRequiresAuth = (pathname: string): boolean => {
    return requiresAuthentication(pathname);
  };

  const canAccessRoute = (pathname: string): boolean => {
    // In development mode, always allow access
    if (isFreeNavigationEnabled()) {
      return true;
    }
    
    // In production mode, check authentication for protected routes
    if (requiresAuthentication(pathname)) {
      return isAuthenticated;
    }
    
    // Public routes are always accessible
    return true;
  };

  return {
    isAuthenticated,
    isLoading,
    isDevelopmentMode: isFreeNavigationEnabled(),
    checkRouteRequiresAuth,
    canAccessRoute,
  };
};