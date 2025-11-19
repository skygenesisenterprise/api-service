"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import ModernSidebar from "./ModernSidebar";
import { Header } from "./header";
import { Toaster } from "./toaster";

interface ProtectedLayoutProps {
  children: React.ReactNode;
}

export function ProtectedLayout({ children }: ProtectedLayoutProps) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const pathname = usePathname();

  // Pages publiques qui n'ont pas besoin de sidebar/header
  const publicPaths = ['/login', '/register', '/forgot-password'];
  const isPublicPath = publicPaths.some(path => pathname.startsWith(path));

  useEffect(() => {
    const checkAuth = () => {
      const token = localStorage.getItem('authToken');
      setIsAuthenticated(!!token);
      setIsLoading(false);
    };

    checkAuth();

    // Écouter les changements de localStorage
    const handleStorageChange = () => {
      checkAuth();
    };

    window.addEventListener('storage', handleStorageChange);
    window.addEventListener('auth-changed', handleStorageChange);

    return () => {
      window.removeEventListener('storage', handleStorageChange);
      window.removeEventListener('auth-changed', handleStorageChange);
    };
  }, [pathname]);

  // Si c'est une page publique, afficher sans sidebar/header
  if (isPublicPath) {
    return (
      <div className="min-h-screen">
        {children}
        <Toaster />
      </div>
    );
  }

  // Si en chargement, afficher un loader
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-black"></div>
      </div>
    );
  }

  // Si non authentifié sur page protégée, le middleware gérera la redirection
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-black mx-auto mb-4"></div>
          <p className="text-gray-600">Vérification de l'authentification...</p>
        </div>
      </div>
    );
  }

  // Si authentifié, afficher layout complet avec sidebar/header
  return (
    <div className="flex h-screen bg-gray-50">
      <ModernSidebar />
      <div className="flex-1 flex flex-col">
        <Header />
        <div className="flex-1 flex flex-col overflow-hidden">
          <main className="flex-1 overflow-auto p-6">
            {children}
          </main>
          <Toaster />
        </div>
      </div>
    </div>
  );
}