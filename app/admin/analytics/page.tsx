'use client';

import { useState, useEffect } from 'react';

interface AnalyticsData {
  totalRequests: number;
  requestsByEndpoint: { endpoint: string; count: number }[];
  requestsByStatus: { status: number; count: number }[];
  requestsOverTime: { date: string; count: number }[];
  topApiKeys: { key_label: string; usage: number }[];
}

export default function AnalyticsPage() {
  const [analytics, setAnalytics] = useState<AnalyticsData>({
    totalRequests: 0,
    requestsByEndpoint: [],
    requestsByStatus: [],
    requestsOverTime: [],
    topApiKeys: []
  });
  const [loading, setLoading] = useState(true);
  const [apiKey, setApiKey] = useState('');
  const [orgId, setOrgId] = useState('');
  const [timeRange, setTimeRange] = useState('7d');

  useEffect(() => {
    const savedApiKey = localStorage.getItem('admin_api_key');
    const savedOrgId = localStorage.getItem('admin_org_id');

    if (savedApiKey && savedOrgId) {
      setApiKey(savedApiKey);
      setOrgId(savedOrgId);
      loadAnalytics(savedApiKey, savedOrgId);
    } else {
      setLoading(false);
    }
  }, [timeRange]);

  const loadAnalytics = async (key: string, organizationId: string) => {
    try {
      // In a real implementation, you'd have analytics endpoints
      // For now, we'll generate mock data
      setAnalytics({
        totalRequests: 15420,
        requestsByEndpoint: [
          { endpoint: '/api/v1/validate', count: 8920 },
          { endpoint: '/api/v1/messaging/conversations', count: 3450 },
          { endpoint: '/api/v1/messaging/messages', count: 2230 },
          { endpoint: '/api/v1/api-keys', count: 820 }
        ],
        requestsByStatus: [
          { status: 200, count: 14200 },
          { status: 201, count: 890 },
          { status: 400, count: 220 },
          { status: 401, count: 110 }
        ],
        requestsOverTime: [
          { date: '2024-01-01', count: 2100 },
          { date: '2024-01-02', count: 2350 },
          { date: '2024-01-03', count: 1980 },
          { date: '2024-01-04', count: 2450 },
          { date: '2024-01-05', count: 2200 },
          { date: '2024-01-06', count: 2380 },
          { date: '2024-01-07', count: 1960 }
        ],
        topApiKeys: [
          { key_label: 'Production API', usage: 8920 },
          { key_label: 'Mobile App', usage: 3450 },
          { key_label: 'Web Client', usage: 2230 },
          { key_label: 'Testing', usage: 820 }
        ]
      });
    } catch (error) {
      console.error('Failed to load analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'text-green-600 dark:text-green-400';
    if (status >= 400 && status < 500) return 'text-yellow-600 dark:text-yellow-400';
    if (status >= 500) return 'text-red-600 dark:text-red-400';
    return 'text-gray-600 dark:text-gray-400';
  };

  if (!apiKey || !orgId) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-600 dark:text-gray-400 mb-4">
          Please authenticate first to access analytics.
        </p>
        <a
          href="/admin"
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition-colors duration-200"
        >
          Go to Dashboard
        </a>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Analytics</h1>
          <p className="text-gray-600 dark:text-gray-400">Monitor API usage and performance</p>
        </div>
        <select
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value)}
          className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
        >
          <option value="1d">Last 24 hours</option>
          <option value="7d">Last 7 days</option>
          <option value="30d">Last 30 days</option>
          <option value="90d">Last 90 days</option>
        </select>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 dark:bg-blue-900 rounded-lg">
              <span className="text-2xl">📊</span>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Requests</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {analytics.totalRequests.toLocaleString()}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 dark:bg-green-900 rounded-lg">
              <span className="text-2xl">✅</span>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Success Rate</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {((analytics.requestsByStatus.find(s => s.status === 200)?.count || 0) / analytics.totalRequests * 100).toFixed(1)}%
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-yellow-100 dark:bg-yellow-900 rounded-lg">
              <span className="text-2xl">⚠️</span>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Error Rate</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {((analytics.requestsByStatus.filter(s => s.status >= 400).reduce((sum, s) => sum + s.count, 0)) / analytics.totalRequests * 100).toFixed(1)}%
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-purple-100 dark:bg-purple-900 rounded-lg">
              <span className="text-2xl">🔑</span>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Active Keys</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {analytics.topApiKeys.length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Requests by Endpoint */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Requests by Endpoint</h2>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {analytics.requestsByEndpoint.map((endpoint, index) => (
                <div key={index} className="flex items-center justify-between">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                      {endpoint.endpoint}
                    </p>
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mt-1">
                      <div
                        className="bg-blue-600 h-2 rounded-full"
                        style={{ width: `${(endpoint.count / analytics.totalRequests) * 100}%` }}
                      ></div>
                    </div>
                  </div>
                  <div className="ml-4 text-right">
                    <p className="text-sm font-semibold text-gray-900 dark:text-white">
                      {endpoint.count.toLocaleString()}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {((endpoint.count / analytics.totalRequests) * 100).toFixed(1)}%
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Response Status Codes */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Response Status Codes</h2>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {analytics.requestsByStatus.map((status, index) => (
                <div key={index} className="flex items-center justify-between">
                  <div className="flex items-center">
                    <span className={`font-mono text-sm font-bold ${getStatusColor(status.status)}`}>
                      {status.status}
                    </span>
                    <span className="ml-2 text-sm text-gray-600 dark:text-gray-400">
                      {status.status === 200 ? 'OK' :
                       status.status === 201 ? 'Created' :
                       status.status === 400 ? 'Bad Request' :
                       status.status === 401 ? 'Unauthorized' :
                       status.status === 403 ? 'Forbidden' :
                       status.status === 404 ? 'Not Found' :
                       status.status === 500 ? 'Server Error' : 'Unknown'}
                    </span>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-semibold text-gray-900 dark:text-white">
                      {status.count.toLocaleString()}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {((status.count / analytics.totalRequests) * 100).toFixed(1)}%
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Top API Keys */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Top API Keys by Usage</h2>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {analytics.topApiKeys.map((key, index) => (
                <div key={index} className="flex items-center justify-between">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      {key.key_label}
                    </p>
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mt-1">
                      <div
                        className="bg-green-600 h-2 rounded-full"
                        style={{ width: `${(key.usage / Math.max(...analytics.topApiKeys.map(k => k.usage))) * 100}%` }}
                      ></div>
                    </div>
                  </div>
                  <div className="ml-4 text-right">
                    <p className="text-sm font-semibold text-gray-900 dark:text-white">
                      {key.usage.toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Requests Over Time */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Requests Over Time</h2>
          </div>
          <div className="p-6">
            <div className="space-y-3">
              {analytics.requestsOverTime.map((day, index) => (
                <div key={index} className="flex items-center justify-between">
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {new Date(day.date).toLocaleDateString()}
                  </p>
                  <div className="flex items-center">
                    <div className="w-24 bg-gray-200 dark:bg-gray-700 rounded-full h-2 mr-3">
                      <div
                        className="bg-purple-600 h-2 rounded-full"
                        style={{ width: `${(day.count / Math.max(...analytics.requestsOverTime.map(d => d.count))) * 100}%` }}
                      ></div>
                    </div>
                    <p className="text-sm font-semibold text-gray-900 dark:text-white w-16 text-right">
                      {day.count.toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Additional Metrics */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Performance Metrics</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center">
            <p className="text-2xl font-bold text-gray-900 dark:text-white">45ms</p>
            <p className="text-sm text-gray-600 dark:text-gray-400">Average Response Time</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-gray-900 dark:text-white">99.8%</p>
            <p className="text-sm text-gray-600 dark:text-gray-400">Uptime</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-gray-900 dark:text-white">2.1GB</p>
            <p className="text-sm text-gray-600 dark:text-gray-400">Data Processed</p>
          </div>
        </div>
      </div>
    </div>
  );
}