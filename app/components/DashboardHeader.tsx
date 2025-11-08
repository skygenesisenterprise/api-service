"use client";

import { useAuth } from '../context/JwtAuthContext';
import { usePathname } from 'next/navigation';

interface DashboardHeaderProps {
  title?: string;
  subtitle?: string;
}

export default function DashboardHeader({ title, subtitle }: DashboardHeaderProps) {
  const { user } = useAuth();
  const pathname = usePathname();

  // Generate title based on pathname if not provided
  const getPageTitle = () => {
    if (title) return title;
    
    const pathSegments = pathname.split('/').filter(Boolean);
    if (pathSegments.length === 0) return 'Dashboard';
    
    const pageName = pathSegments[pathSegments.length - 1];
    return pageName.charAt(0).toUpperCase() + pageName.slice(1);
  };

  return (
    <header className="bg-white shadow-sm border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center py-6">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">
              {getPageTitle()}
            </h1>
            {subtitle && (
              <p className="mt-1 text-sm text-gray-500">{subtitle}</p>
            )}
          </div>
          
          {user && (
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <p className="text-sm font-medium text-gray-900">{user.fullName || user.email}</p>
                <p className="text-xs text-gray-500">{user.position || 'User'}</p>
              </div>
              <div className="w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
                <span className="text-sm font-medium text-gray-700">
                  {(user.fullName || user.email)?.charAt(0).toUpperCase() || 'U'}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}