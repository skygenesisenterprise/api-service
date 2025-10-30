"use client";

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter, usePathname } from 'next/navigation';
import { useAuthContext } from '../context/AuthContext';
import { useSidebar } from '../context/SidebarContext';

// Navigation icons (using emoji for simplicity, can be replaced with proper icons)
const Icons = {
  dashboard: '📊',
  users: '👥',
  settings: '⚙️',
  logs: '📋',
  profile: '👤',
  inbox: '📬',
  api: '🔗',
  logout: '🚪',
  menu: '☰',
  close: '✕',
  chevron: '▶',
  chevronDown: '▼',
  chevronUp: '▲',
};

interface NavItem {
  name: string;
  href: string;
  icon: string;
  children?: NavItem[];
}

const navigationItems: NavItem[] = [
  {
    name: 'Dashboard',
    href: '/dashboard',
    icon: Icons.dashboard,
  },
  {
    name: 'Users',
    href: '/users',
    icon: Icons.users,
  },
  {
    name: 'Settings',
    href: '/settings',
    icon: Icons.settings,
    children: [
      {
        name: 'General',
        href: '/settings/general',
        icon: '🔧',
      },
      {
        name: 'API Keys',
        href: '/settings/api',
        icon: '🔑',
      },
      {
        name: 'Security',
        href: '/settings/security',
        icon: '🔒',
      },
    ],
  },
  {
    name: 'Logs',
    href: '/logs',
    icon: Icons.logs,
    children: [
      {
        name: 'Audit Logs',
        href: '/logs/audit',
        icon: '📝',
      },
      {
        name: 'Error Logs',
        href: '/logs/errors',
        icon: '⚠️',
      },
    ],
  },
  {
    name: 'Profile',
    href: '/profile',
    icon: Icons.profile,
  },
  {
    name: 'Inbox',
    href: '/inbox',
    icon: Icons.inbox,
  },
  {
    name: 'API Docs',
    href: '/docs/swagger',
    icon: Icons.api,
  },
];

export default function Navbar() {
  const { logout, isAuthenticated } = useAuthContext();
  const { isCollapsed, setIsCollapsed } = useSidebar();
  const router = useRouter();
  const pathname = usePathname();
  const [openDropdowns, setOpenDropdowns] = useState<Set<string>>(new Set());
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  // Debug logs
  console.log('Navbar component mounted');
  console.log('Navbar render - isAuthenticated:', isAuthenticated);
  console.log('Navbar render - token exists:', !!localStorage.getItem('sge_token'));

  const handleLogout = () => {
    logout();
    router.push('/auth/login');
  };

  const toggleDropdown = (name: string) => {
    const newOpenDropdowns = new Set(openDropdowns);
    if (newOpenDropdowns.has(name)) {
      newOpenDropdowns.delete(name);
    } else {
      newOpenDropdowns.add(name);
    }
    setOpenDropdowns(newOpenDropdowns);
  };

  const isActive = (href: string) => {
    if (href === '/dashboard' && pathname === '/') return true;
    return pathname === href || pathname.startsWith(href + '/');
  };

  const isDropdownActive = (item: NavItem) => {
    if (item.children) {
      return item.children.some(child => isActive(child.href));
    }
    return isActive(item.href);
  };

  // Auto-expand dropdowns for active sections
  useEffect(() => {
    const activeDropdowns = new Set<string>();
    navigationItems.forEach(item => {
      if (item.children && isDropdownActive(item)) {
        activeDropdowns.add(item.name);
      }
    });
    setOpenDropdowns(activeDropdowns);
  }, [pathname]);

  if (!isAuthenticated || pathname !== '/dashboard') {
    console.log('Navbar not rendering - user not authenticated or not on dashboard');
    return null;
  }

  return (
    <>
      {/* Mobile menu button */}
      <div className="md:hidden fixed top-4 left-4 z-50">
        <button
          onClick={() => setIsMobileOpen(!isMobileOpen)}
          className="p-2 bg-white rounded-md shadow-lg border border-gray-200 text-gray-700 hover:text-gray-900 transition-colors"
        >
          <span className="text-xl">
            {isMobileOpen ? Icons.close : Icons.menu}
          </span>
        </button>
      </div>

      {/* Mobile overlay */}
      {isMobileOpen && (
        <div
          className="md:hidden fixed inset-0 bg-black bg-opacity-50 z-30"
          onClick={() => setIsMobileOpen(false)}
        />
      )}

      {/* Mobile sidebar */}
      <div className={`md:hidden fixed left-0 top-0 h-full bg-white border-r border-gray-200 shadow-lg z-40 transition-all duration-300 w-64 ${
        isMobileOpen ? 'translate-x-0' : '-translate-x-full'
      }`}>
        {/* Mobile header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200">
          <Link
            href="/dashboard"
            className="flex items-center space-x-2 text-lg font-bold text-gray-900 hover:text-blue-600 transition-colors"
            onClick={() => setIsMobileOpen(false)}
          >
            <span className="text-2xl">☁️</span>
            <span>Sky Genesis</span>
          </Link>
          <button
            onClick={() => setIsMobileOpen(false)}
            className="p-1 rounded-md text-gray-500 hover:text-gray-700 hover:bg-gray-100 transition-colors"
          >
            <span className="text-lg">{Icons.close}</span>
          </button>
        </div>

        {/* Mobile Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navigationItems.map((item) => (
            <div key={item.name}>
              {item.children ? (
                // Mobile dropdown section
                <div>
                  <button
                    onClick={() => toggleDropdown(item.name)}
                    className={`flex items-center justify-between w-full px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                      isDropdownActive(item)
                        ? 'text-blue-600 bg-blue-50'
                        : 'text-gray-700 hover:text-gray-900 hover:bg-gray-50'
                    }`}
                  >
                    <div className="flex items-center space-x-2">
                      <span className="text-lg">{item.icon}</span>
                      <span>{item.name}</span>
                    </div>
                    <span className={`text-xs transition-transform ${
                      openDropdowns.has(item.name) ? 'rotate-90' : ''
                    }`}>
                      {Icons.chevron}
                    </span>
                  </button>

                  {/* Mobile dropdown content */}
                  {openDropdowns.has(item.name) && (
                    <div className="ml-6 mt-1 space-y-1">
                      {item.children.map((child) => (
                        <Link
                          key={child.href}
                          href={child.href}
                          onClick={() => setIsMobileOpen(false)}
                          className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm hover:bg-gray-50 transition-colors ${
                            isActive(child.href)
                              ? 'text-blue-600 bg-blue-50 border-l-2 border-blue-600'
                              : 'text-gray-700'
                          }`}
                        >
                          <span>{child.icon}</span>
                          <span>{child.name}</span>
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                // Mobile regular link
                <Link
                  href={item.href}
                  onClick={() => setIsMobileOpen(false)}
                  className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    isActive(item.href)
                      ? 'text-blue-600 bg-blue-50 border-l-2 border-blue-600'
                      : 'text-gray-700 hover:text-gray-900 hover:bg-gray-50'
                  }`}
                >
                  <span className="text-lg">{item.icon}</span>
                  <span>{item.name}</span>
                </Link>
              )}
            </div>
          ))}
        </nav>

        {/* Mobile footer with logout */}
        <div className="border-t border-gray-200 p-3">
          <button
            onClick={handleLogout}
            className="flex items-center space-x-2 w-full px-3 py-2 rounded-md text-sm font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-50 transition-colors"
          >
            <span className="text-lg">{Icons.logout}</span>
            <span>Logout</span>
          </button>
        </div>
      </div>

      {/* Desktop Sidebar */}
      <div className={`hidden md:block fixed left-0 top-0 h-full bg-white border-r border-gray-200 shadow-lg z-40 transition-all duration-300 ${
        isCollapsed ? 'w-16' : 'w-64'
      }`}>
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200">
          {!isCollapsed && (
            <Link
              href="/dashboard"
              className="flex items-center space-x-2 text-lg font-bold text-gray-900 hover:text-blue-600 transition-colors"
            >
              <span className="text-2xl">☁️</span>
              <span className="truncate">Sky Genesis</span>
            </Link>
          )}
          {isCollapsed && (
            <Link
              href="/dashboard"
              className="flex justify-center w-full text-2xl text-gray-900 hover:text-blue-600 transition-colors"
            >
              ☁️
            </Link>
          )}

          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="p-1 rounded-md text-gray-500 hover:text-gray-700 hover:bg-gray-100 transition-colors"
          >
            <span className="text-sm">
              {isCollapsed ? Icons.chevron : Icons.chevronUp}
            </span>
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navigationItems.map((item) => (
            <div key={item.name}>
              {item.children ? (
                // Dropdown section
                <div>
                  <button
                    onClick={() => toggleDropdown(item.name)}
                    className={`flex items-center w-full px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                      isDropdownActive(item)
                        ? 'text-blue-600 bg-blue-50'
                        : 'text-gray-700 hover:text-gray-900 hover:bg-gray-50'
                    } ${isCollapsed ? 'justify-center' : 'justify-between'}`}
                  >
                    <div className="flex items-center space-x-2">
                      <span className="text-lg">{item.icon}</span>
                      {!isCollapsed && <span className="truncate">{item.name}</span>}
                    </div>
                    {!isCollapsed && (
                      <span className={`text-xs transition-transform ${
                        openDropdowns.has(item.name) ? 'rotate-90' : ''
                      }`}>
                        {Icons.chevron}
                      </span>
                    )}
                  </button>

                  {/* Dropdown content */}
                  {openDropdowns.has(item.name) && !isCollapsed && (
                    <div className="ml-6 mt-1 space-y-1">
                      {item.children.map((child) => (
                        <Link
                          key={child.href}
                          href={child.href}
                          className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm hover:bg-gray-50 transition-colors ${
                            isActive(child.href)
                              ? 'text-blue-600 bg-blue-50 border-l-2 border-blue-600'
                              : 'text-gray-700'
                          }`}
                        >
                          <span>{child.icon}</span>
                          <span className="truncate">{child.name}</span>
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                // Regular link
                <Link
                  href={item.href}
                  className={`flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    isActive(item.href)
                      ? 'text-blue-600 bg-blue-50 border-l-2 border-blue-600'
                      : 'text-gray-700 hover:text-gray-900 hover:bg-gray-50'
                  } ${isCollapsed ? 'justify-center' : 'space-x-2'}`}
                >
                  <span className="text-lg">{item.icon}</span>
                  {!isCollapsed && <span className="truncate">{item.name}</span>}
                </Link>
              )}
            </div>
          ))}
        </nav>

        {/* Footer with logout */}
        <div className="border-t border-gray-200 p-3">
          <button
            onClick={handleLogout}
            className={`flex items-center w-full px-3 py-2 rounded-md text-sm font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-50 transition-colors ${
              isCollapsed ? 'justify-center' : 'space-x-2'
            }`}
          >
            <span className="text-lg">{Icons.logout}</span>
            {!isCollapsed && <span>Logout</span>}
          </button>
        </div>
      </div>

    </>
  );
}