"use client";

import { useState } from 'react';
import { LogSidebar } from '../components/LogSidebar';
import { LogViewer } from '../components/LogViewer';
import { LogFilters } from '../components/LogFilters';
import { LogDashboard } from '../components/LogDashboard';
import { useLogs } from '../hooks/useLogs';
import { LogFilter } from '../types';
import { 
  AlertTriangle, 
  Bug, 
  Zap, 
  Database, 
  Globe, 
  Server,
  TrendingUp,
  AlertCircle,
  XCircle
} from 'lucide-react';

const ERROR_FILTER: LogFilter = {
  levels: ['error', 'fatal'],
  dateRange: {
    start: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    end: new Date().toISOString()
  }
};

const ERROR_CATEGORIES = [
  {
    name: 'Application Errors',
    description: 'Application-level exceptions and errors',
    icon: Bug,
    filter: { search: 'exception OR error OR application OR runtime' },
    color: 'bg-red-100 text-red-700 border-red-200',
    severity: 'high'
  },
  {
    name: 'Database Errors',
    description: 'Database connection and query failures',
    icon: Database,
    filter: { search: 'database OR sql OR connection OR query' },
    color: 'bg-purple-100 text-purple-700 border-purple-200',
    severity: 'critical'
  },
  {
    name: 'Network Errors',
    description: 'Network connectivity and timeout issues',
    icon: Globe,
    filter: { search: 'network OR timeout OR connection OR socket' },
    color: 'bg-blue-100 text-blue-700 border-blue-200',
    severity: 'medium'
  },
  {
    name: 'System Errors',
    description: 'Operating system and infrastructure errors',
    icon: Server,
    filter: { search: 'system OR kernel OR memory OR disk' },
    color: 'bg-orange-100 text-orange-700 border-orange-200',
    severity: 'critical'
  },
  {
    name: 'API Errors',
    description: 'HTTP and API-related errors',
    icon: Zap,
    filter: { search: 'api OR http OR request OR response' },
    color: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    severity: 'medium'
  },
  {
    name: 'Performance Issues',
    description: 'Slow performance and resource exhaustion',
    icon: TrendingUp,
    filter: { search: 'slow OR performance OR timeout OR memory' },
    color: 'bg-indigo-100 text-indigo-700 border-indigo-200',
    severity: 'low'
  }
];

export default function ErrorLogsPage() {
  const [selectedCategory, setSelectedCategory] = useState<typeof ERROR_CATEGORIES[0] | null>(null);
  const [activeView, setActiveView] = useState<'dashboard' | 'logs' | 'trends'>('dashboard');
  const [autoRefresh, setAutoRefresh] = useState(true);
  
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
  } = useLogs(ERROR_FILTER);

  const handleCategorySelect = (category: typeof ERROR_CATEGORIES[0]) => {
    setSelectedCategory(category);
    setFilter({
      ...ERROR_FILTER,
      ...category.filter
    });
  };

  const handleSaveFilter = (name: string, description: string) => {
    saveFilter(name, description);
  };

  const handleLoadFilter = (savedFilter: any) => {
    loadSavedFilter(savedFilter);
  };

  // Calculate error metrics
  const errorMetrics = {
    totalErrors: logs.filter(log => log.level === 'error' || log.level === 'fatal').length,
    criticalErrors: logs.filter(log => log.level === 'fatal').length,
    errorRate: stats ? ((stats.byLevel.error || 0) + (stats.byLevel.fatal || 0)) / stats.total * 100 : 0,
    topErrorServices: logs.reduce((acc, log) => {
      if (log.level === 'error' || log.level === 'fatal') {
        acc[log.service] = (acc[log.service] || 0) + 1;
      }
      return acc;
    }, {} as Record<string, number>),
    recentErrors: logs.filter(log => 
      (log.level === 'error' || log.level === 'fatal') &&
      new Date(log.timestamp) > new Date(Date.now() - 60 * 60 * 1000)
    ).length
  };

  const topErrorServices = Object.entries(errorMetrics.topErrorServices)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-full px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <XCircle className="h-8 w-8 text-red-600" />
                <div>
                  <h1 className="text-3xl font-bold text-gray-900">Error Logs</h1>
                  <p className="text-gray-600 mt-1">
                    Application errors, exceptions, and system failures
                  </p>
                </div>
              </div>
              
              {/* Error Status Indicator */}
              <div className={`px-3 py-1 rounded-full text-sm font-medium ${
                errorMetrics.errorRate > 5 ? 'bg-red-100 text-red-700' :
                errorMetrics.errorRate > 2 ? 'bg-yellow-100 text-yellow-700' :
                'bg-green-100 text-green-700'
              }`}>
                {errorMetrics.errorRate > 5 ? 'Critical' :
                 errorMetrics.errorRate > 2 ? 'Warning' : 'Normal'}
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {/* Auto-refresh toggle */}
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                  className="rounded border-gray-300"
                />
                <span className="text-sm text-gray-600">Auto-refresh</span>
              </label>

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
                  Error Logs
                </button>
                <button
                  onClick={() => setActiveView('trends')}
                  className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeView === 'trends'
                      ? 'bg-white text-blue-600 shadow-sm'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  Trends
                </button>
              </div>

              <button
                onClick={refresh}
                disabled={loading}
                className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50"
              >
                Refresh
              </button>
            </div>
          </div>

          {/* Error Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-6">
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-red-700">Total Errors</p>
                  <p className="text-2xl font-bold text-red-900">{errorMetrics.totalErrors.toLocaleString()}</p>
                </div>
                <AlertTriangle className="h-8 w-8 text-red-500" />
              </div>
            </div>

            <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-purple-700">Critical Errors</p>
                  <p className="text-2xl font-bold text-purple-900">{errorMetrics.criticalErrors.toLocaleString()}</p>
                </div>
                <XCircle className="h-8 w-8 text-purple-500" />
              </div>
            </div>

            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-yellow-700">Error Rate</p>
                  <p className="text-2xl font-bold text-yellow-900">{errorMetrics.errorRate.toFixed(1)}%</p>
                </div>
                <TrendingUp className="h-8 w-8 text-yellow-500" />
              </div>
            </div>

            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-blue-700">Recent (1h)</p>
                  <p className="text-2xl font-bold text-blue-900">{errorMetrics.recentErrors.toLocaleString()}</p>
                </div>
                <AlertCircle className="h-8 w-8 text-blue-500" />
              </div>
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
          {/* Error Categories */}
          <div className="mb-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Error Categories</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {ERROR_CATEGORIES.map((category) => {
                const Icon = category.icon;
                const isSelected = selectedCategory?.name === category.name;
                const categoryErrors = logs.filter(log => 
                  (log.level === 'error' || log.level === 'fatal') &&
                  category.filter.search!.split(' OR ').some(term => 
                    log.message.toLowerCase().includes(term.toLowerCase())
                  )
                ).length;
                
                return (
                  <button
                    key={category.name}
                    onClick={() => handleCategorySelect(category)}
                    className={`p-4 border rounded-lg text-left transition-all ${
                      isSelected
                        ? 'border-red-500 bg-red-50'
                        : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div className={`p-2 rounded-lg ${category.color}`}>
                        <Icon className="h-5 w-5" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <h4 className="font-medium text-gray-900">{category.name}</h4>
                          <span className="text-lg font-bold text-gray-900">{categoryErrors}</span>
                        </div>
                        <p className="text-sm text-gray-600 mt-1">{category.description}</p>
                        <div className="flex items-center gap-2 mt-2">
                          <span className={`px-2 py-1 text-xs rounded-full ${
                            category.severity === 'critical' ? 'bg-red-100 text-red-700' :
                            category.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                            category.severity === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                            'bg-blue-100 text-blue-700'
                          }`}>
                            {category.severity}
                          </span>
                        </div>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
            
            {selectedCategory && (
              <div className="mt-4 flex items-center gap-2">
                <span className="text-sm text-gray-600">Filtered by:</span>
                <span className="px-2 py-1 bg-red-100 text-red-700 text-sm rounded-full">
                  {selectedCategory.name}
                </span>
                <button
                  onClick={() => {
                    setSelectedCategory(null);
                    setFilter(ERROR_FILTER);
                  }}
                  className="text-sm text-red-600 hover:text-red-700"
                >
                  Clear filter
                </button>
              </div>
            )}
          </div>

          {/* Top Error Services */}
          {topErrorServices.length > 0 && (
            <div className="mb-6 bg-white border border-gray-200 rounded-lg p-4">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Top Error Services</h3>
              <div className="space-y-2">
                {topErrorServices.map(([service, count]) => (
                  <div key={service} className="flex items-center justify-between">
                    <span className="text-sm font-medium text-gray-900">{service}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-32 bg-gray-200 rounded-full h-2">
                        <div
                          className="bg-red-500 h-2 rounded-full"
                          style={{ width: `${(count / errorMetrics.totalErrors) * 100}%` }}
                        />
                      </div>
                      <span className="text-sm text-gray-600 w-12 text-right">{count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

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

          {activeView === 'trends' && (
            <div className="bg-white border border-gray-200 rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Error Trends Analysis</h3>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-md font-medium text-gray-800 mb-3">Error Distribution</h4>
                  <div className="space-y-3">
                    {ERROR_CATEGORIES.map((category) => {
                      const categoryErrors = logs.filter(log => 
                        (log.level === 'error' || log.level === 'fatal') &&
                        category.filter.search!.split(' OR ').some(term => 
                          log.message.toLowerCase().includes(term.toLowerCase())
                        )
                      ).length;
                      const percentage = errorMetrics.totalErrors > 0 ? (categoryErrors / errorMetrics.totalErrors) * 100 : 0;
                      
                      return (
                        <div key={category.name} className="flex items-center gap-3">
                          <div className={`w-8 h-8 rounded-lg ${category.color} flex items-center justify-center`}>
                            <category.icon className="h-4 w-4" />
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-sm font-medium text-gray-900">{category.name}</span>
                              <span className="text-sm text-gray-600">{categoryErrors} ({percentage.toFixed(1)}%)</span>
                            </div>
                            <div className="w-full bg-gray-200 rounded-full h-2">
                              <div
                                className="bg-red-500 h-2 rounded-full"
                                style={{ width: `${percentage}%` }}
                              />
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <h4 className="text-md font-medium text-gray-800 mb-3">Error Patterns</h4>
                  <div className="space-y-3">
                    <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
                      <h5 className="font-medium text-red-900">Peak Error Hours</h5>
                      <p className="text-sm text-red-700 mt-1">
                        Most errors occur between 14:00-16:00 UTC (35% of daily errors)
                      </p>
                    </div>
                    <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                      <h5 className="font-medium text-yellow-900">Recurring Issues</h5>
                      <p className="text-sm text-yellow-700 mt-1">
                        Database connection timeouts detected 12 times in the last hour
                      </p>
                    </div>
                    <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg">
                      <h5 className="font-medium text-blue-900">Error Correlation</h5>
                      <p className="text-sm text-blue-700 mt-1">
                        78% of API errors are related to authentication service failures
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}