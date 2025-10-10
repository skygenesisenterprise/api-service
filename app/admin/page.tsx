'use client';

import { useState, useEffect } from 'react';

interface ApiKey {
  id: string;
  label: string;
  permissions: string[];
  quota_limit: number;
  usage_count: number;
  status: string;
  created_at: string;
}

interface DashboardStats {
  totalApiKeys: number;
  activeApiKeys: number;
  totalUsage: number;
  recentActivity: any[];
}

export default function AdminDashboard() {
  const [stats, setStats] = useState<DashboardStats>({
    totalApiKeys: 0,
    activeApiKeys: 0,
    totalUsage: 0,
    recentActivity: []
  });
  const [loading, setLoading] = useState(true);
  const [apiKey, setApiKey] = useState('');
  const [orgId, setOrgId] = useState('');

  useEffect(() => {
    // Load from localStorage on mount
    const savedApiKey = localStorage.getItem('admin_api_key');
    const savedOrgId = localStorage.getItem('admin_org_id');

    if (savedApiKey) setApiKey(savedApiKey);
    if (savedOrgId) setOrgId(savedOrgId);

    if (savedApiKey && savedOrgId) {
      loadDashboardData(savedApiKey, savedOrgId);
    } else {
      setLoading(false);
    }
  }, []);

  const loadDashboardData = async (key: string, organizationId: string) => {
    try {
      const response = await fetch(`/api/v1/organizations/${organizationId}/api-keys`, {
        headers: {
          'X-API-Key': key
        }
      });

      if (response.ok) {
        const data = await response.json();
        const apiKeys = data.data || [];

        setStats({
          totalApiKeys: apiKeys.length,
          activeApiKeys: apiKeys.filter((k: ApiKey) => k.status === 'active').length,
          totalUsage: apiKeys.reduce((sum: number, k: ApiKey) => sum + k.usage_count, 0),
          recentActivity: apiKeys.slice(0, 5)
        });
      }
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!apiKey || !orgId) return;

    localStorage.setItem('admin_api_key', apiKey);
    localStorage.setItem('admin_org_id', orgId);

    setLoading(true);
    await loadDashboardData(apiKey, orgId);
  };

  const handleLogout = () => {
    localStorage.removeItem('admin_api_key');
    localStorage.removeItem('admin_org_id');
    setApiKey('');
    setOrgId('');
    setStats({
      totalApiKeys: 0,
      activeApiKeys: 0,
      totalUsage: 0,
      recentActivity: []
    });
  };

  if (!apiKey || !orgId) {
    return (
      <div className="max-w-md mx-auto bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6 text-center">
          Admin Authentication
        </h2>

        <form onSubmit={handleAuthSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Organization ID
            </label>
            <input
              type="text"
              value={orgId}
              onChange={(e) => setOrgId(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
              placeholder="Enter organization ID"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              API Key
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
              placeholder="Enter admin API key"
              required
            />
          </div>

          <button
            type="submit"
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-md transition-colors duration-200"
          >
            Access Admin Portal
          </button>
        </form>

        <div className="mt-6 text-sm text-gray-600 dark:text-gray-400">
          <p className="mb-2">
            <strong>Note:</strong> You need an API key with admin permissions to access this portal.
          </p>
          <p>
            Don't have an API key? Create one through the API or contact your administrator.
          </p>
        </div>
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
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
          <p className="text-gray-600 dark:text-gray-400">Welcome to your API management portal</p>
        </div>
        <button
          onClick={handleLogout}
          className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md transition-colors duration-200"
        >
          Logout
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 dark:bg-blue-900 rounded-lg">
              <span className="text-2xl">🔑</span>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Total API Keys</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.totalApiKeys}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 dark:bg-green-900 rounded-lg">
              <span className="text-2xl">✅</span>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Active Keys</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.activeApiKeys}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-purple-100 dark:bg-purple-900 rounded-lg">
              <span className="text-2xl">📊</span>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Usage</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.totalUsage.toLocaleString()}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Recent API Keys</h2>
        </div>
        <div className="p-6">
          {stats.recentActivity.length > 0 ? (
            <div className="space-y-4">
              {stats.recentActivity.map((key: ApiKey) => (
                <div key={key.id} className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">{key.label}</p>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      Usage: {key.usage_count.toLocaleString()} / {key.quota_limit.toLocaleString()}
                    </p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      key.status === 'active'
                        ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
                        : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
                    }`}>
                      {key.status}
                    </span>
                    <span className="text-sm text-gray-500 dark:text-gray-400">
                      {new Date(key.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 dark:text-gray-400 text-center py-8">
              No API keys found. Create your first API key to get started.
            </p>
          )}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <a
            href="/admin/api-keys"
            className="flex items-center p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/30 transition-colors duration-200"
          >
            <span className="text-2xl mr-3">🔑</span>
            <div>
              <p className="font-medium text-gray-900 dark:text-white">Manage API Keys</p>
              <p className="text-sm text-gray-600 dark:text-gray-400">Create, edit, and revoke API keys</p>
            </div>
          </a>

          <a
            href="/admin/analytics"
            className="flex items-center p-4 bg-green-50 dark:bg-green-900/20 rounded-lg hover:bg-green-100 dark:hover:bg-green-900/30 transition-colors duration-200"
          >
            <span className="text-2xl mr-3">📈</span>
            <div>
              <p className="font-medium text-gray-900 dark:text-white">View Analytics</p>
              <p className="text-sm text-gray-600 dark:text-gray-400">Monitor API usage and performance</p>
            </div>
          </a>
        </div>
      </div>
    </div>
  );
}