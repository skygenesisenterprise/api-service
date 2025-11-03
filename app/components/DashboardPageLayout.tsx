"use client";

import { ReactNode } from 'react';
import { usePathname } from 'next/navigation';

import { useSidebar } from '../context/SidebarContext';
import DashboardLayout from './DashboardLayout';
import DashboardHeader from './DashboardHeader';
import { ProtectedRoute } from './ProtectedRoute';

interface DashboardPageLayoutProps {
  children: ReactNode;
  title?: string;
  subtitle?: string;
}

export default function DashboardPageLayout({ 
  children, 
  title, 
  subtitle 
}: DashboardPageLayoutProps) {
  const { isCollapsed } = useSidebar();
  const pathname = usePathname();
  
  // Don't use dashboard layout on auth pages
  const isAuthPage = pathname.startsWith('/auth') || pathname === '/login';

  if (isAuthPage) {
    return <ProtectedRoute>{children}</ProtectedRoute>;
  }

  return (
    <ProtectedRoute>
      <DashboardLayout />
      <div className={`transition-all duration-300 ${
        isCollapsed ? 'lg:ml-20' : 'lg:ml-72'
      }`}>
        <DashboardHeader title={title} subtitle={subtitle} />
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </main>
      </div>
    </ProtectedRoute>
  );
}