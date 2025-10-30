"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';

interface BreadcrumbItem {
  name: string;
  href: string;
  icon?: string;
}

const routeMap: Record<string, BreadcrumbItem[]> = {
  '/dashboard': [{ name: 'Dashboard', href: '/dashboard', icon: '📊' }],
  '/users': [{ name: 'Users', href: '/users', icon: '👥' }],
  '/settings': [{ name: 'Settings', href: '/settings', icon: '⚙️' }],
  '/settings/general': [
    { name: 'Settings', href: '/settings', icon: '⚙️' },
    { name: 'General', href: '/settings/general', icon: '🔧' }
  ],
  '/settings/api': [
    { name: 'Settings', href: '/settings', icon: '⚙️' },
    { name: 'API Keys', href: '/settings/api', icon: '🔑' }
  ],
  '/settings/security': [
    { name: 'Settings', href: '/settings', icon: '⚙️' },
    { name: 'Security', href: '/settings/security', icon: '🔒' }
  ],
  '/logs': [{ name: 'Logs', href: '/logs', icon: '📋' }],
  '/logs/audit': [
    { name: 'Logs', href: '/logs', icon: '📋' },
    { name: 'Audit Logs', href: '/logs/audit', icon: '📝' }
  ],
  '/logs/errors': [
    { name: 'Logs', href: '/logs', icon: '📋' },
    { name: 'Error Logs', href: '/logs/errors', icon: '⚠️' }
  ],
  '/profile': [{ name: 'Profile', href: '/profile', icon: '👤' }],
  '/inbox': [{ name: 'Inbox', href: '/inbox', icon: '📬' }],
  '/docs/swagger': [{ name: 'API Documentation', href: '/docs/swagger', icon: '🔗' }],
};

export default function Breadcrumb() {
  const pathname = usePathname();

  // Get breadcrumb items for current path
  const getBreadcrumbItems = (): BreadcrumbItem[] => {
    // Check for exact matches first
    if (routeMap[pathname]) {
      return routeMap[pathname];
    }

    // Check for partial matches (for dynamic routes or sub-routes)
    for (const [route, items] of Object.entries(routeMap)) {
      if (pathname.startsWith(route) && route !== '/') {
        return items;
      }
    }

    // Default fallback
    return [{ name: 'Dashboard', href: '/dashboard', icon: '📊' }];
  };

  const breadcrumbItems = getBreadcrumbItems();

  if (breadcrumbItems.length <= 1) {
    return null; // Don't show breadcrumb if only one item
  }

  return (
    <nav className="bg-white px-4 py-3 border-b border-gray-200">
      <div className="max-w-7xl mx-auto">
        <ol className="flex items-center space-x-2 text-sm">
          {breadcrumbItems.map((item, index) => (
            <li key={item.href} className="flex items-center">
              {index > 0 && (
                <span className="text-gray-400 mx-2">/</span>
              )}
              {index === breadcrumbItems.length - 1 ? (
                // Last item (current page) - not clickable
                <span className="flex items-center text-gray-900 font-medium">
                  {item.icon && <span className="mr-1">{item.icon}</span>}
                  {item.name}
                </span>
              ) : (
                // Previous items - clickable
                <Link
                  href={item.href}
                  className="flex items-center text-gray-600 hover:text-gray-900 transition-colors"
                >
                  {item.icon && <span className="mr-1">{item.icon}</span>}
                  {item.name}
                </Link>
              )}
            </li>
          ))}
        </ol>
      </div>
    </nav>
  );
}