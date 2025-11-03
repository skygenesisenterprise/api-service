"use client";

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuth } from '../context/JwtAuthContext';
import { useSidebar } from '../context/SidebarContext';
import { 
  LayoutDashboard, 
  Users, 
  Settings, 
  FileText, 
  User, 
  Inbox, 
  BookOpen, 
  LogOut,
  Menu,
  X,
  ChevronRight,
  Shield,
  Key,
  AlertTriangle,
  FileCheck
} from 'lucide-react';

interface NavItem {
  name: string;
  href: string;
  icon: React.ReactNode;
  children?: NavItem[];
}

const navigationItems: NavItem[] = [
  {
    name: 'Dashboard',
    href: '/dashboard',
    icon: <LayoutDashboard className="w-5 h-5" />,
  },
  {
    name: 'Users',
    href: '/users',
    icon: <Users className="w-5 h-5" />,
  },
  {
    name: 'Projects',
    href: '/projects',
    icon: <BookOpen className="w-5 h-5" />,
  },
  {
    name: 'Settings',
    href: '/settings',
    icon: <Settings className="w-5 h-5" />,
    children: [
      {
        name: 'General',
        href: '/settings/general',
        icon: <Settings className="w-4 h-4" />,
      },
      {
        name: 'API Keys',
        href: '/settings/api',
        icon: <Key className="w-4 h-4" />,
      },
      {
        name: 'Security',
        href: '/settings/security',
        icon: <Shield className="w-4 h-4" />,
      },
    ],
  },
  {
    name: 'Logs',
    href: '/logs',
    icon: <FileText className="w-5 h-5" />,
    children: [
      {
        name: 'Activity',
        href: '/logs',
        icon: <FileCheck className="w-4 h-4" />,
      },
      {
        name: 'Errors',
        href: '/logs/errors',
        icon: <AlertTriangle className="w-4 h-4" />,
      },
    ],
  },
  {
    name: 'Profile',
    href: '/profile',
    icon: <User className="w-5 h-5" />,
  },
  {
    name: 'Inbox',
    href: '/inbox',
    icon: <Inbox className="w-5 h-5" />,
  },
];

export default function DashboardLayout() {
  const { user, logout } = useAuth();
  const { isCollapsed, setIsCollapsed } = useSidebar();
  const pathname = usePathname();
  const [openDropdowns, setOpenDropdowns] = useState<Set<string>>(new Set());
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  const handleLogout = async () => {
    await logout();
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
  React.useEffect(() => {
    const activeDropdowns = new Set<string>();
    navigationItems.forEach(item => {
      if (item.children && isDropdownActive(item)) {
        activeDropdowns.add(item.name);
      }
    });
    setOpenDropdowns(activeDropdowns);
  }, [pathname]);

  if (pathname.startsWith('/auth') || pathname === '/login') {
    return null;
  }

  return (
    <>
      {/* Mobile menu button */}
      <div className="lg:hidden fixed top-4 left-4 z-50">
        <button
          onClick={() => setIsMobileOpen(!isMobileOpen)}
          className="p-2 bg-white rounded-md shadow-lg border border-gray-200 text-gray-700 hover:text-gray-900 transition-colors"
        >
          {isMobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
      </div>

      {/* Mobile overlay */}
      {isMobileOpen && (
        <div
          className="lg:hidden fixed inset-0 bg-black bg-opacity-50 z-30"
          onClick={() => setIsMobileOpen(false)}
        />
      )}

      {/* Mobile sidebar */}
      <div className={`lg:hidden fixed left-0 top-0 h-full bg-white border-r border-gray-200 shadow-lg z-40 transition-all duration-300 w-72 ${
        isMobileOpen ? 'translate-x-0' : '-translate-x-full'
      }`}>
        {/* Mobile header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200">
          <Link
            href="/dashboard"
            className="flex items-center space-x-3 text-lg font-bold text-gray-900 hover:text-blue-600 transition-colors"
            onClick={() => setIsMobileOpen(false)}
          >
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold">S</span>
            </div>
            <span>Sky Genesis</span>
          </Link>
          <button
            onClick={() => setIsMobileOpen(false)}
            className="p-1 rounded-md text-gray-500 hover:text-gray-700 hover:bg-gray-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Mobile Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navigationItems.map((item) => (
            <div key={item.name}>
              {item.children ? (
                <div>
                  <button
                    onClick={() => toggleDropdown(item.name)}
                    className={`flex items-center justify-between w-full px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                      isDropdownActive(item)
                        ? 'text-blue-600 bg-blue-50'
                        : 'text-gray-700 hover:text-gray-900 hover:bg-gray-50'
                    }`}
                  >
                    <div className="flex items-center space-x-3">
                      {item.icon}
                      <span>{item.name}</span>
                    </div>
                    <ChevronRight className={`w-4 h-4 transition-transform ${
                      openDropdowns.has(item.name) ? 'rotate-90' : ''
                    }`} />
                  </button>

                  {openDropdowns.has(item.name) && (
                    <div className="ml-6 mt-1 space-y-1">
                      {item.children.map((child) => (
                        <Link
                          key={child.href}
                          href={child.href}
                          onClick={() => setIsMobileOpen(false)}
                          className={`flex items-center space-x-3 px-3 py-2 rounded-md text-sm hover:bg-gray-50 transition-colors ${
                            isActive(child.href)
                              ? 'text-blue-600 bg-blue-50 border-l-2 border-blue-600'
                              : 'text-gray-700'
                          }`}
                        >
                          {child.icon}
                          <span>{child.name}</span>
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <Link
                  href={item.href}
                  onClick={() => setIsMobileOpen(false)}
                  className={`flex items-center space-x-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    isActive(item.href)
                      ? 'text-blue-600 bg-blue-50 border-l-2 border-blue-600'
                      : 'text-gray-700 hover:text-gray-900 hover:bg-gray-50'
                  }`}
                >
                  {item.icon}
                  <span>{item.name}</span>
                </Link>
              )}
            </div>
          ))}
        </nav>

        {/* Mobile footer with user info and logout */}
        <div className="border-t border-gray-200 p-4">
          {user && (
            <div className="flex items-center space-x-3 mb-3">
              <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center">
                <span className="text-sm font-medium text-gray-700">
                  {user.name?.charAt(0).toUpperCase() || 'U'}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900 truncate">
                  {user.name}
                </p>
                <p className="text-xs text-gray-500 truncate">
                  {user.email}
                </p>
              </div>
            </div>
          )}
          <button
            onClick={handleLogout}
            className="flex items-center space-x-3 w-full px-3 py-2 rounded-md text-sm font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-50 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            <span>Logout</span>
          </button>
        </div>
      </div>

      {/* Desktop Sidebar */}
      <div className={`hidden lg:block fixed left-0 top-0 h-full bg-white border-r border-gray-200 shadow-lg z-40 transition-all duration-300 ${
        isCollapsed ? 'w-20' : 'w-72'
      }`}>
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200">
          {!isCollapsed && (
            <Link
              href="/dashboard"
              className="flex items-center space-x-3 text-lg font-bold text-gray-900 hover:text-blue-600 transition-colors"
            >
              <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                <span className="text-white font-bold">S</span>
              </div>
              <span className="truncate">Sky Genesis</span>
            </Link>
          )}
          {isCollapsed && (
            <Link
              href="/dashboard"
              className="flex justify-center w-full"
            >
              <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                <span className="text-white font-bold">S</span>
              </div>
            </Link>
          )}

          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="p-1 rounded-md text-gray-500 hover:text-gray-700 hover:bg-gray-100 transition-colors"
          >
            <ChevronRight className={`w-4 h-4 transition-transform ${
              isCollapsed ? '' : 'rotate-180'
            }`} />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navigationItems.map((item) => (
            <div key={item.name}>
              {item.children ? (
                <div>
                  <button
                    onClick={() => toggleDropdown(item.name)}
                    className={`flex items-center w-full px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                      isDropdownActive(item)
                        ? 'text-blue-600 bg-blue-50'
                        : 'text-gray-700 hover:text-gray-900 hover:bg-gray-50'
                    } ${isCollapsed ? 'justify-center' : 'justify-between'}`}
                  >
                    <div className="flex items-center space-x-3">
                      {item.icon}
                      {!isCollapsed && <span className="truncate">{item.name}</span>}
                    </div>
                    {!isCollapsed && (
                      <ChevronRight className={`w-4 h-4 transition-transform ${
                        openDropdowns.has(item.name) ? 'rotate-90' : ''
                      }`} />
                    )}
                  </button>

                  {openDropdowns.has(item.name) && !isCollapsed && (
                    <div className="ml-6 mt-1 space-y-1">
                      {item.children.map((child) => (
                        <Link
                          key={child.href}
                          href={child.href}
                          className={`flex items-center space-x-3 px-3 py-2 rounded-md text-sm hover:bg-gray-50 transition-colors ${
                            isActive(child.href)
                              ? 'text-blue-600 bg-blue-50 border-l-2 border-blue-600'
                              : 'text-gray-700'
                          }`}
                        >
                          {child.icon}
                          <span className="truncate">{child.name}</span>
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <Link
                  href={item.href}
                  className={`flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    isActive(item.href)
                      ? 'text-blue-600 bg-blue-50 border-l-2 border-blue-600'
                      : 'text-gray-700 hover:text-gray-900 hover:bg-gray-50'
                  } ${isCollapsed ? 'justify-center' : 'space-x-3'}`}
                  title={isCollapsed ? item.name : undefined}
                >
                  {item.icon}
                  {!isCollapsed && <span className="truncate">{item.name}</span>}
                </Link>
              )}
            </div>
          ))}
        </nav>

        {/* Footer with user info and logout */}
        <div className="border-t border-gray-200 p-4">
          {!isCollapsed && user && (
            <div className="flex items-center space-x-3 mb-3">
              <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center">
                <span className="text-sm font-medium text-gray-700">
                  {user.name?.charAt(0).toUpperCase() || 'U'}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900 truncate">
                  {user.name}
                </p>
                <p className="text-xs text-gray-500 truncate">
                  {user.email}
                </p>
              </div>
            </div>
          )}
          <button
            onClick={handleLogout}
            className={`flex items-center w-full px-3 py-2 rounded-md text-sm font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-50 transition-colors ${
              isCollapsed ? 'justify-center' : 'space-x-3'
            }`}
            title={isCollapsed ? 'Logout' : undefined}
          >
            <LogOut className="w-4 h-4" />
            {!isCollapsed && <span>Logout</span>}
          </button>
        </div>
      </div>
    </>
  );
}