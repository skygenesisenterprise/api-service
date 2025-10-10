'use client';

import { useState, useEffect } from 'react';

interface Organization {
  id: string;
  name: string;
  country_code: string;
  created_at: string;
  updated_at: string;
}

export default function OrganizationsPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [apiKey, setApiKey] = useState('');
  const [orgId, setOrgId] = useState('');

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    country_code: 'US'
  });

  useEffect(() => {
    const savedApiKey = localStorage.getItem('admin_api_key');
    const savedOrgId = localStorage.getItem('admin_org_id');

    if (savedApiKey && savedOrgId) {
      setApiKey(savedApiKey);
      setOrgId(savedOrgId);
      // For now, we'll just show the current organization
      // In a real implementation, you'd have an endpoint to list all organizations
      setOrganizations([{
        id: savedOrgId,
        name: 'Current Organization',
        country_code: 'US',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }]);
      setLoading(false);
    } else {
      setLoading(false);
    }
  }, []);

  const handleCreateOrganization = async (e: React.FormEvent) => {
    e.preventDefault();

    // Note: In a real implementation, you'd call an API endpoint to create organizations
    // For now, this is just a placeholder
    alert('Organization creation would be implemented with proper admin permissions');

    setFormData({ name: '', country_code: 'US' });
    setShowCreateForm(false);
  };

  if (!apiKey || !orgId) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-600 dark:text-gray-400 mb-4">
          Please authenticate first to access organization management.
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Organizations</h1>
          <p className="text-gray-600 dark:text-gray-400">Manage organizations and their settings</p>
        </div>
        <button
          onClick={() => setShowCreateForm(true)}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition-colors duration-200 flex items-center"
        >
          <span className="mr-2">+</span>
          Create Organization
        </button>
      </div>

      {/* Create Organization Modal */}
      {showCreateForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full mx-4">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Create Organization</h2>
            </div>

            <form onSubmit={handleCreateOrganization} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Organization Name
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
                  placeholder="e.g., Acme Corporation"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Country Code
                </label>
                <select
                  value={formData.country_code}
                  onChange={(e) => setFormData(prev => ({ ...prev, country_code: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
                >
                  <option value="US">United States</option>
                  <option value="CA">Canada</option>
                  <option value="GB">United Kingdom</option>
                  <option value="DE">Germany</option>
                  <option value="FR">France</option>
                  <option value="JP">Japan</option>
                  <option value="AU">Australia</option>
                </select>
              </div>

              <div className="flex space-x-3 pt-4">
                <button
                  type="submit"
                  className="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-md transition-colors duration-200"
                >
                  Create Organization
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

      {/* Organizations List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Organizations ({organizations.length})
          </h2>
        </div>

        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {organizations.length > 0 ? (
            organizations.map((org) => (
              <div key={org.id} className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                      {org.name}
                    </h3>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      ID: {org.id}
                    </p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-1 bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300 text-xs rounded-full">
                      Active
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      <span className="font-medium">Country:</span> {org.country_code}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      <span className="font-medium">Created:</span> {new Date(org.created_at).toLocaleDateString()}
                    </p>
                  </div>
                </div>

                <div className="mt-4 flex space-x-2">
                  <button className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 text-sm">
                    View Details
                  </button>
                  <button className="text-gray-600 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-300 text-sm">
                    Edit Settings
                  </button>
                </div>
              </div>
            ))
          ) : (
            <div className="p-12 text-center">
              <div className="w-16 h-16 bg-gray-100 dark:bg-gray-700 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">🏢</span>
              </div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                No organizations found
              </h3>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Create your first organization to get started.
              </p>
              <button
                onClick={() => setShowCreateForm(true)}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition-colors duration-200"
              >
                Create Organization
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Organization Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 dark:bg-blue-900 rounded-lg">
              <span className="text-2xl">🏢</span>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Organizations</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{organizations.length}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 dark:bg-green-900 rounded-lg">
              <span className="text-2xl">✅</span>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Active Organizations</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{organizations.length}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-purple-100 dark:bg-purple-900 rounded-lg">
              <span className="text-2xl">🔑</span>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">API Keys</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">-</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}