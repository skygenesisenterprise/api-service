"use client";

import { useState } from 'react';
import { LogSidebar } from '../components/LogSidebar';
import { LogViewer } from '../components/LogViewer';
import { LogFilters } from '../components/LogFilters';
import { LogDashboard } from '../components/LogDashboard';
import { useLogs } from '../hooks/useLogs';
import { LogFilter } from '../types';
import { Shield, AlertTriangle, UserCheck, Key, FileText, Eye } from 'lucide-react';

const AUDIT_FILTER: LogFilter = {
  levels: ['info', 'warn', 'error', 'fatal'],
  search: 'audit OR authentication OR authorization OR security OR compliance',
  dateRange: {
    start: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
    end: new Date().toISOString()
  }
};

const AUDIT_CATEGORIES = [
  {
    name: 'Authentication Events',
    description: 'User logins, logouts, and authentication attempts',
    icon: UserCheck,
    filter: { search: 'login OR logout OR authentication OR sign' },
    color: 'bg-blue-100 text-blue-700 border-blue-200'
  },
  {
    name: 'Authorization Changes',
    description: 'Permission changes, role assignments, access grants',
    icon: Key,
    filter: { search: 'permission OR role OR access OR grant OR revoke' },
    color: 'bg-purple-100 text-purple-700 border-purple-200'
  },
  {
    name: 'Security Events',
    description: 'Security violations, suspicious activities, threats',
    icon: Shield,
    filter: { search: 'security OR threat OR violation OR suspicious OR breach' },
    color: 'bg-red-100 text-red-700 border-red-200'
  },
  {
    name: 'Compliance Events',
    description: 'Regulatory compliance, audit trails, policy violations',
    icon: FileText,
    filter: { search: 'compliance OR audit OR policy OR regulation OR GDPR' },
    color: 'bg-green-100 text-green-700 border-green-200'
  },
  {
    name: 'Data Access',
    description: 'Data access, modifications, exports, deletions',
    icon: Eye,
    filter: { search: 'data OR export OR delete OR modify OR access' },
    color: 'bg-yellow-100 text-yellow-700 border-yellow-200'
  },
  {
    name: 'System Changes',
    description: 'Configuration changes, system updates, deployments',
    icon: AlertTriangle,
    filter: { search: 'config OR deployment OR update OR system OR change' },
    color: 'bg-orange-100 text-orange-700 border-orange-200'
  }
];

export default function AuditLogsPage() {
  const [selectedCategory, setSelectedCategory] = useState<typeof AUDIT_CATEGORIES[0] | null>(null);
  const [activeView, setActiveView] = useState<'dashboard' | 'logs'>('logs');
  
  const {
    logs,
    loading,
    hasMore,
    filter,
    setFilter,
    config,
    setConfig,
    stats,
    savedFilters,
    loadMore,
    refresh,
    exportLogs,
    saveFilter,
    loadSavedFilter,
  } = useLogs(AUDIT_FILTER);

  const handleCategorySelect = (category: typeof AUDIT_CATEGORIES[0]) => {
    setSelectedCategory(category);
    setFilter({
      ...AUDIT_FILTER,
      ...category.filter
    });
  };

  const handleSaveFilter = (name: string, description: string) => {
    saveFilter(name, description);
  };

  const handleLoadFilter = (savedFilter: any) => {
    loadSavedFilter(savedFilter);
  };

  const complianceScore = stats ? Math.max(0, 100 - ((stats.byLevel.error || 0) + (stats.byLevel.fatal || 0)) / stats.total * 100) : 0;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-full px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Shield className="h-8 w-8 text-blue-600" />
              <div>
                <h1 className="text-3xl font-bold text-gray-900">Audit Logs</h1>
                <p className="text-gray-600 mt-1">
                  Security, compliance, and audit trail monitoring
                </p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {/* Compliance Score */}
              <div className="text-right">
                <div className="text-sm text-gray-600">Compliance Score</div>
                <div className={`text-2xl font-bold ${
                  complianceScore >= 90 ? 'text-green-600' :
                  complianceScore >= 70 ? 'text-yellow-600' : 'text-red-600'
                }`}>
                  {complianceScore.toFixed(1)}%
                </div>
              </div>

              {/* View Toggle */}
              <div className="flex items-center bg-gray-100 rounded-lg p-1">
                <button
                  onClick={() => setActiveView('dashboard')}
                  className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeView === 'dashboard'
                      ? 'bg-white text-blue-600 shadow-sm'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  Dashboard
                </button>
                <button
                  onClick={() => setActiveView('logs')}
                  className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeView === 'logs'
                      ? 'bg-white text-blue-600 shadow-sm'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  Logs
                </button>
              </div>

              <button
                onClick={refresh}
                disabled={loading}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                Refresh
              </button>
            </div>
          </div>

          {/* Quick Stats */}
          <div className="flex items-center gap-8 mt-4 text-sm">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-blue-500 rounded-full" />
              <span className="text-gray-600">
                {logs.filter((log: any) => log.message.includes('login') || log.message.includes('authentication')).length} Auth Events
              </span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-red-500 rounded-full" />
              <span className="text-gray-600">
                {logs.filter((log: any) => log.level === 'error' || log.level === 'fatal').length} Security Issues
              </span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-green-500 rounded-full" />
              <span className="text-gray-600">
                {logs.filter((log: any) => log.message.includes('compliance') || log.message.includes('audit')).length} Compliance Events
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="flex">
        {/* Sidebar */}
        <div className="w-80 bg-white border-r border-gray-200 min-h-screen">
          <LogSidebar />
        </div>

        {/* Main Content */}
        <div className="flex-1 p-6">
          {/* Audit Categories */}
          <div className="mb-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Audit Categories</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {AUDIT_CATEGORIES.map((category) => {
                const Icon = category.icon;
                const isSelected = selectedCategory?.name === category.name;
                
                return (
                  <button
                    key={category.name}
                    onClick={() => handleCategorySelect(category)}
                    className={`p-4 border rounded-lg text-left transition-all ${
                      isSelected
                        ? 'border-blue-500 bg-blue-50'
                        : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div className={`p-2 rounded-lg ${category.color}`}>
                        <Icon className="h-5 w-5" />
                      </div>
                      <div className="flex-1">
                        <h4 className="font-medium text-gray-900">{category.name}</h4>
                        <p className="text-sm text-gray-600 mt-1">{category.description}</p>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
            
            {selectedCategory && (
              <div className="mt-4 flex items-center gap-2">
                <span className="text-sm text-gray-600">Filtered by:</span>
                <span className="px-2 py-1 bg-blue-100 text-blue-700 text-sm rounded-full">
                  {selectedCategory.name}
                </span>
                <button
                  onClick={() => {
                    setSelectedCategory(null);
                    setFilter(AUDIT_FILTER);
                  }}
                  className="text-sm text-blue-600 hover:text-blue-700"
                >
                  Clear filter
                </button>
              </div>
            )}
          </div>

          {/* Filters */}
          <div className="mb-6">
            <LogFilters
              filter={filter}
              onFilterChange={setFilter}
              savedFilters={savedFilters}
              onSaveFilter={handleSaveFilter}
              onLoadFilter={handleLoadFilter}
            />
          </div>

          {/* Content Area */}
          {activeView === 'dashboard' && stats && (
            <LogDashboard
              logs={logs}
              stats={stats}
              loading={loading}
              onRefresh={refresh}
            />
          )}

          {activeView === 'logs' && (
            <LogViewer
              logs={logs}
              loading={loading}
              config={config}
              onConfigChange={setConfig}
              onExport={exportLogs}
              onRefresh={refresh}
              onLoadMore={loadMore}
              hasMore={hasMore}
            />
          )}
        </div>
      </div>
    </div>
  );
}