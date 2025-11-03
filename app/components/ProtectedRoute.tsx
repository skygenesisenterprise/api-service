"use client";

import { useAuth } from '../context/JwtAuthContext';
import { useEffect, ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import { requiresAuthentication } from '../lib/navigation-config';

interface ProtectedRouteProps {
  children: ReactNode;
  fallback?: ReactNode;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  fallback = <div className="min-h-screen flex items-center justify-center">
    <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-gray-900"></div>
  </div> 
}) => {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    // Only check authentication if not in development mode and route requires protection
    if (typeof window !== 'undefined' && requiresAuthentication(window.location.pathname)) {
      if (!isLoading && !isAuthenticated) {
        router.push('/login');
      }
    }
  }, [isAuthenticated, isLoading, router]);

  // In development mode or if authenticated, show children
  if (typeof window !== 'undefined' && requiresAuthentication(window.location.pathname)) {
    if (isLoading) {
      return <>{fallback}</>;
    }
    
    if (!isAuthenticated) {
      return null;
    }
  }

  return <>{children}</>;
};