"use client";

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { 
  FileText, 
  Activity, 
  AlertTriangle, 
  Shield, 
  Settings, 
  Clock, 
  Bookmark,
  Filter,
  ChevronDown,
  ChevronRight,
  Search,
  Zap,
  Database,
  Globe,
  Users,
  Server
} from 'lucide-react';

interface LogSidebarProps {
  className?: string;
}

interface SidebarSection {
  title: string;
  items: SidebarItem[];
  defaultExpanded?: boolean;
}

interface SidebarItem {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string | number;
  description?: string;
  isActive?: boolean;
}

export function LogSidebar({ className = '' }: LogSidebarProps) {
  const pathname = usePathname();
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['navigation', 'quick-filters']));

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const newSet = new Set(prev);
      if (newSet.has(section)) {
        newSet.delete(section);
      } else {
        newSet.add(section);
      }
      return newSet;
    });
  };

  const navigationItems: SidebarItem[] = [
    {
      name: 'Overview',
      href: '/logs',
      icon: Activity,
      description: 'Dashboard and statistics',
      isActive: pathname === '/logs'
    },
    {
      name: 'Live Stream',
      href: '/logs/live',
      icon: Zap,
      description: 'Real-time log streaming',
      badge: 'LIVE',
      isActive: pathname === '/logs/live'
    },
    {
      name: 'Audit Logs',
      href: '/logs/audit',
      icon: Shield,
      description: 'Security and compliance',
      isActive: pathname === '/logs/audit'
    },
    {
      name: 'Error Logs',
      href: '/logs/errors',
      icon: AlertTriangle,
      description: 'Errors and exceptions',
      isActive: pathname === '/logs/errors'
    },
    {
      name: 'System Logs',
      href: '/logs/system',
      icon: Server,
      description: 'System and infrastructure',
      isActive: pathname === '/logs/system'
    },
    {
      name: 'Access Logs',
      href: '/logs/access',
      icon: Globe,
      description: 'HTTP requests and API calls',
      isActive: pathname === '/logs/access'
    },
  ];

  const quickFilterItems: SidebarItem[] = [
    {
      name: 'Errors Only',
      href: '/logs?level=error',
      icon: AlertTriangle,
      badge: '12'
    },
    {
      name: 'Last Hour',
      href: '/logs?time=1h',
      icon: Clock
    },
    {
      name: 'My Actions',
      href: '/logs?user=current',
      icon: Users
    },
    {
      name: 'Production',
      href: '/logs?env=prod',
      icon: Server
    },
  ];

  const toolsItems: SidebarItem[] = [
    {
      name: 'Saved Searches',
      href: '/logs/saved',
      icon: Bookmark,
      badge: '5'
    },
    {
      name: 'Export Manager',
      href: '/logs/export',
      icon: Database
    },
    {
      name: 'Alert Rules',
      href: '/logs/alerts',
      icon: Settings
    },
  ];

  const sections: SidebarSection[] = [
    {
      title: 'Navigation',
      items: navigationItems,
      defaultExpanded: true
    },
    {
      title: 'Quick Filters',
      items: quickFilterItems,
      defaultExpanded: true
    },
    {
      title: 'Tools',
      items: toolsItems,
      defaultExpanded: false
    }
  ];

  return (
    <div className={`bg-white border border-gray-200 rounded-lg ${className}`}>
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center gap-2">
          <FileText className="h-5 w-5 text-blue-600" />
          <h2 className="text-lg font-semibold text-gray-900">Logs</h2>
        </div>
      </div>

      <div className="p-4 space-y-6">
        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search logs..."
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>

        {/* Sections */}
        {sections.map((section) => {
          const isExpanded = expandedSections.has(section.title);
          
          return (
            <div key={section.title}>
              <button
                onClick={() => toggleSection(section.title)}
                className="flex items-center justify-between w-full text-left"
              >
                <h3 className="text-sm font-medium text-gray-900 uppercase tracking-wide">
                  {section.title}
                </h3>
                {isExpanded ? (
                  <ChevronDown className="h-4 w-4 text-gray-400" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-gray-400" />
                )}
              </button>

              {isExpanded && (
                <div className="mt-3 space-y-1">
                  {section.items.map((item) => {
                    const Icon = item.icon;
                    const isActive = item.isActive || pathname === item.href;
                    
                    return (
                      <Link
                        key={item.href}
                        href={item.href}
                        className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                          isActive
                            ? 'bg-blue-50 text-blue-700 border border-blue-200'
                            : 'text-gray-700 hover:bg-gray-50 hover:text-gray-900'
                        }`}
                      >
                        <Icon className="h-4 w-4 flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="font-medium truncate">{item.name}</div>
                          {item.description && (
                            <div className="text-xs text-gray-500 truncate">{item.description}</div>
                          )}
                        </div>
                        {item.badge && (
                          <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${
                            typeof item.badge === 'string' && item.badge === 'LIVE'
                              ? 'bg-red-100 text-red-700 animate-pulse'
                              : 'bg-gray-100 text-gray-700'
                          }`}>
                            {item.badge}
                          </span>
                        )}
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}

        {/* Quick Stats */}
        <div className="border-t border-gray-200 pt-4">
          <h3 className="text-sm font-medium text-gray-900 uppercase tracking-wide mb-3">
            Quick Stats
          </h3>
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Logs (last 24h)</span>
              <span className="font-medium text-gray-900">1.2M</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Error Rate</span>
              <span className="font-medium text-red-600">2.3%</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Active Services</span>
              <span className="font-medium text-gray-900">24</span>
            </div>
          </div>
        </div>

        {/* Recent Searches */}
        <div className="border-t border-gray-200 pt-4">
          <h3 className="text-sm font-medium text-gray-900 uppercase tracking-wide mb-3">
            Recent Searches
          </h3>
          <div className="space-y-1">
            {[
              'level:error AND service:api-gateway',
              'user:admin AND timestamp:>2025-01-15',
              'message:"database connection"'
            ].map((search, index) => (
              <button
                key={index}
                className="block w-full text-left px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 rounded-lg truncate"
                title={search}
              >
                {search}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}