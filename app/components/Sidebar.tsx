"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';

interface SidebarItem {
  name: string;
  href: string;
  icon: string;
  description?: string;
}

interface SidebarProps {
  title: string;
  items: SidebarItem[];
  className?: string;
}

export default function Sidebar({ title, items, className = '' }: SidebarProps) {
  const pathname = usePathname();

  return (
    <div className={`bg-white rounded-lg shadow-sm border border-gray-200 p-6 ${className}`}>
      <h2 className="text-lg font-semibold text-gray-900 mb-4">{title}</h2>
      <nav className="space-y-2">
        {items.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={`flex items-center space-x-3 px-3 py-2 rounded-md text-sm transition-colors ${
              pathname === item.href
                ? 'bg-blue-50 text-blue-700 border border-blue-200'
                : 'text-gray-700 hover:bg-gray-50 hover:text-gray-900'
            }`}
          >
            <span className="text-lg">{item.icon}</span>
            <div className="flex-1">
              <div className="font-medium">{item.name}</div>
              {item.description && (
                <div className="text-xs text-gray-500 mt-0.5">{item.description}</div>
              )}
            </div>
          </Link>
        ))}
      </nav>
    </div>
  );
}

// Predefined sidebar configurations for different sections
export const SettingsSidebar = () => (
  <Sidebar
    title="Settings"
    items={[
      {
        name: 'General',
        href: '/settings/general',
        icon: '🔧',
        description: 'General application settings'
      },
      {
        name: 'API Keys',
        href: '/settings/api',
        icon: '🔑',
        description: 'Manage API keys and certificates'
      },
      {
        name: 'Security',
        href: '/settings/security',
        icon: '🔒',
        description: 'Security and access controls'
      },
    ]}
  />
);

export const LogsSidebar = () => (
  <Sidebar
    title="Logs"
    items={[
      {
        name: 'Audit Logs',
        href: '/logs/audit',
        icon: '📝',
        description: 'Security and access audit logs'
      },
      {
        name: 'Error Logs',
        href: '/logs/errors',
        icon: '⚠️',
        description: 'Application error logs'
      },
    ]}
  />
);