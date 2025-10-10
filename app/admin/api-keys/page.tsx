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

export default function ApiKeysPage() {
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [apiKey, setApiKey] = useState('');
  const [orgId, setOrgId] = useState('');

  // Form state
  const [formData, setFormData] = useState({
    label: '',
    permissions: [] as string[],
    quota_limit: 100000
  });

  useEffect(() => {
    const savedApiKey = localStorage.getItem('admin_api_key');
    const savedOrgId = localStorage.getItem('admin_org_id');

    if (savedApiKey && savedOrgId) {
      setApiKey(savedApiKey);
      setOrgId(savedOrgId);
      loadApiKeys(savedApiKey, savedOrgId);
    } else {
      setLoading(false);
    }
  }, []);

  const loadApiKeys = async (key: string, organizationId: string) => {
    try {
      const response = await fetch(`/api/v1/organizations/${organizationId}/api-keys`, {
        headers: {
          'X-API-Key': key
        }
      });

      if (response.ok) {
        const data = await response.json();
        setApiKeys(data.data || []);
      }
    } catch (error) {
      console.error('Failed to load API keys:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const response = await fetch(`/api/v1/organizations/${orgId}/api-keys`, {
        method: 'POST',
        headers: {
          'X-API-Key': apiKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
      });

      if (response.ok) {
        const result = await response.json();
        alert(`API Key created successfully!\n\nKey: ${result.data.key_value}\n\nPlease save this key securely. It will not be shown again.`);
        setFormData({ label: '', permissions: [], quota_limit: 100000 });
        setShowCreateForm(false);
        loadApiKeys(apiKey, orgId);
      } else {
        const error = await response.json();
        alert(`Error: ${error.message || 'Failed to create API key'}`);
      }
    } catch (error) {
      console.error('Failed to create API key:', error);
      alert('Failed to create API key');
    }
  };

  const handleRevokeApiKey = async (keyId: string) => {
    if (!confirm('Are you sure you want to revoke this API key? This action cannot be undone.')) {
      return;
    }

    try {
      const response = await fetch(`/api/v1/organizations/${orgId}/api-keys/${keyId}`, {
        method: 'DELETE',
        headers: {
          'X-API-Key': apiKey
        }
      });

      if (response.ok) {
        alert('API key revoked successfully');
        loadApiKeys(apiKey, orgId);
      } else {
        const error = await response.json();
        alert(`Error: ${error.message || 'Failed to revoke API key'}`);
      }
    } catch (error) {
      console.error('Failed to revoke API key:', error);
      alert('Failed to revoke API key');
    }
  };

  const handlePermissionChange = (permission: string, checked: boolean) => {
    setFormData(prev => ({
      ...prev,
      permissions: checked
        ? [...prev.permissions, permission]
        : prev.permissions.filter(p => p !== permission)
    }));
  };

  const getUsagePercentage = (usage: number, limit: number) => {
    return Math.min((usage / limit) * 100, 100);
  };

  const getUsageColor = (percentage: number) => {
    if (percentage >= 90) return 'bg-red-500';
    if (percentage >= 70) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  if (!apiKey || !orgId) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-600 dark:text-gray-400 mb-4">
          Please authenticate first to access API key management.
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
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">API Keys</h1>
          <p className="text-gray-600 dark:text-gray-400">Manage your organization's API keys</p>
        </div>
        <button
          onClick={() => setShowCreateForm(true)}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition-colors duration-200 flex items-center"
        >
          <span className="mr-2">+</span>
          Create API Key
        </button>
      </div>

      {/* Create API Key Modal */}
      {showCreateForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full mx-4">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Create API Key</h2>
            </div>

            <form onSubmit={handleCreateApiKey} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Label
                </label>
                <input
                  type="text"
                  value={formData.label}
                  onChange={(e) => setFormData(prev => ({ ...prev, label: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
                  placeholder="e.g., Production API Key"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Permissions
                </label>
                <div className="space-y-2">
                  {[
                    { value: 'read', label: 'Read - Access to view data' },
                    { value: 'write', label: 'Write - Create and modify data' },
                    { value: 'admin', label: 'Admin - Full access including API key management' }
                  ].map(({ value, label }) => (
                    <label key={value} className="flex items-center">
                      <input
                        type="checkbox"
                        checked={formData.permissions.includes(value)}
                        onChange={(e) => handlePermissionChange(value, e.target.checked)}
                        className="mr-2"
                      />
                      <span className="text-sm text-gray-700 dark:text-gray-300">{label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Quota Limit
                </label>
                <input
                  type="number"
                  value={formData.quota_limit}
                  onChange={(e) => setFormData(prev => ({ ...prev, quota_limit: parseInt(e.target.value) || 100000 }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
                  min="1"
                  max="10000000"
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Maximum API calls allowed per key
                </p>
              </div>

              <div className="flex space-x-3 pt-4">
                <button
                  type="submit"
                  className="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-md transition-colors duration-200"
                >
                  Create Key
                </button>
                <button
                  type="button"
                  onClick={() => setShowCreateForm(false)}
                  className="flex-1 bg-gray-300 hover:bg-gray-400 dark:bg-gray-600 dark:hover:bg-gray-500 text-gray-700 dark:text-gray-300 py-2 px-4 rounded-md transition-colors duration-200"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* API Keys List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            API Keys ({apiKeys.length})
          </h2>
        </div>

        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {apiKeys.length > 0 ? (
            apiKeys.map((key) => {
              const usagePercentage = getUsagePercentage(key.usage_count, key.quota_limit);
              const usageColor = getUsageColor(usagePercentage);

              return (
                <div key={key.id} className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                        {key.label}
                      </h3>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        Created {new Date(key.created_at).toLocaleDateString()}
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
                      {key.status === 'active' && (
                        <button
                          onClick={() => handleRevokeApiKey(key.id)}
                          className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 text-sm"
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="space-y-3">
                    <div>
                      <div className="flex justify-between text-sm text-gray-600 dark:text-gray-400 mb-1">
                        <span>Permissions</span>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {key.permissions.map((permission) => (
                          <span
                            key={permission}
                            className="px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-300 text-xs rounded"
                          >
                            {permission}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-sm text-gray-600 dark:text-gray-400 mb-1">
                        <span>Usage</span>
                        <span>{key.usage_count.toLocaleString()} / {key.quota_limit.toLocaleString()}</span>
                      </div>
                      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${usageColor}`}
                          style={{ width: `${usagePercentage}%` }}
                        ></div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="p-12 text-center">
              <div className="w-16 h-16 bg-gray-100 dark:bg-gray-700 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">🔑</span>
              </div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                No API keys found
              </h3>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Get started by creating your first API key.
              </p>
              <button
                onClick={() => setShowCreateForm(true)}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition-colors duration-200"
              >
                Create API Key
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}