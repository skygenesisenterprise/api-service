"use client";

import { useState, useEffect } from "react";
import { apiKeyService, ApiKey, CreateApiKeyRequest } from "../../utils/apiClient";
import { useAuthContext } from "../../context/AuthContext";

export default function ApiSettingsPage() {
  const { token, isAuthenticated } = useAuthContext();
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [selectedKey, setSelectedKey] = useState<ApiKey | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);

  // Form state for creating new key
  const [formData, setFormData] = useState<CreateApiKeyRequest>({
    type: "client",
    tenant: "default-tenant",
    ttl: 3600,
    cert_type: "rsa",
    status: "sandbox",
  });

  // Load existing keys
  const loadKeys = async () => {
    if (!token) {
      setError("Authentication required");
      return;
    }

    try {
      setLoading(true);
      const keyList = await apiKeyService.listKeys(formData.tenant, token);
      setKeys(keyList);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load keys");
    } finally {
      setLoading(false);
    }
  };

  // Create new key with certificate
  const createKey = async () => {
    if (!token) {
      setError("Authentication required");
      return;
    }

    try {
      setLoading(true);
      setError(null);

      let newKey: ApiKey;
      if (formData.status === "sandbox") {
        newKey = await apiKeyService.createSandboxKeyWithCertificate(formData, token);
      } else {
        newKey = await apiKeyService.createProductionKeyWithCertificate(formData, token);
      }

      setKeys(prev => [newKey, ...prev]);
      setSelectedKey(newKey);
      setSuccess("API key with certificate created successfully!");
      setShowCreateForm(false);

      // Reset form
      setFormData({
        type: "client",
        tenant: "default-tenant",
        ttl: 3600,
        cert_type: "rsa",
        status: "sandbox",
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create key");
    } finally {
      setLoading(false);
    }
  };

  // Revoke key
  const revokeKey = async (keyId: string) => {
    if (!confirm("Are you sure you want to revoke this API key?")) return;

    if (!token) {
      setError("Authentication required");
      return;
    }

    try {
      setLoading(true);
      await apiKeyService.revokeKey(keyId, token);
      setKeys(prev => prev.filter(k => k.id !== keyId));
      setSuccess("API key revoked successfully");
      if (selectedKey?.id === keyId) {
        setSelectedKey(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke key");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isAuthenticated && token) {
      loadKeys();
    }
  }, [isAuthenticated, token]);

  return (
    <div className="max-w-6xl mx-auto p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">API Keys & Certificates</h1>
        <p className="text-gray-600">
          Manage your API keys and their associated certificates for secure authentication.
        </p>
        {!isAuthenticated && (
          <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-md">
            <p className="text-yellow-800">Please log in to manage your API keys.</p>
          </div>
        )}
      </div>

      {/* Error/Success Messages */}
      {error && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
          <p className="text-red-800">{error}</p>
        </div>
      )}

      {success && (
        <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-md">
          <p className="text-green-800">{success}</p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Left Column - Key Management */}
        <div>
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-xl font-semibold text-gray-900">API Keys</h2>
              <button
                onClick={() => setShowCreateForm(!showCreateForm)}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
              >
                {showCreateForm ? "Cancel" : "Create Key"}
              </button>
            </div>

            {/* Create Key Form */}
            {showCreateForm && (
              <div className="mb-6 p-4 bg-gray-50 rounded-md">
                <h3 className="text-lg font-medium mb-4">Create New API Key with Certificate</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Key Type
                    </label>
                    <select
                      value={formData.type}
                      onChange={(e) => setFormData(prev => ({ ...prev, type: e.target.value }))}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="client">Client</option>
                      <option value="server">Server</option>
                      <option value="database">Database</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Tenant
                    </label>
                    <input
                      type="text"
                      value={formData.tenant}
                      onChange={(e) => setFormData(prev => ({ ...prev, tenant: e.target.value }))}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="default-tenant"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      TTL (seconds)
                    </label>
                    <input
                      type="number"
                      value={formData.ttl}
                      onChange={(e) => setFormData(prev => ({ ...prev, ttl: parseInt(e.target.value) }))}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      min="60"
                      max="31536000"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Certificate Type
                    </label>
                    <select
                      value={formData.cert_type}
                      onChange={(e) => setFormData(prev => ({ ...prev, cert_type: e.target.value }))}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="rsa">RSA</option>
                      <option value="ecdsa">ECDSA</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Environment
                    </label>
                    <select
                      value={formData.status}
                      onChange={(e) => setFormData(prev => ({ ...prev, status: e.target.value }))}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="sandbox">Sandbox</option>
                      <option value="production">Production</option>
                    </select>
                  </div>

                  <button
                    onClick={createKey}
                    disabled={loading}
                    className="w-full px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors disabled:opacity-50"
                  >
                    {loading ? "Creating..." : "Create Key with Certificate"}
                  </button>
                </div>
              </div>
            )}

            {/* Keys List */}
            <div className="space-y-3">
              {keys.map((key) => (
                <div
                  key={key.id}
                  className={`p-4 border rounded-md cursor-pointer transition-colors ${
                    selectedKey?.id === key.id
                      ? "border-blue-500 bg-blue-50"
                      : "border-gray-200 hover:border-gray-300"
                  }`}
                  onClick={() => setSelectedKey(key)}
                >
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-medium text-gray-900">{key.key_type}</span>
                        <span className={`px-2 py-1 text-xs rounded-full ${
                          key.status === "production"
                            ? "bg-red-100 text-red-800"
                            : "bg-yellow-100 text-yellow-800"
                        }`}>
                          {key.status}
                        </span>
                        {key.certificate && (
                          <span className="px-2 py-1 text-xs bg-green-100 text-green-800 rounded-full">
                            Certificate
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-gray-600 font-mono">
                        {key.key.substring(0, 20)}...
                      </p>
                      <p className="text-xs text-gray-500">
                        Created: {new Date(key.created_at).toLocaleDateString()}
                      </p>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        revokeKey(key.id);
                      }}
                      className="text-red-600 hover:text-red-800 text-sm"
                    >
                      Revoke
                    </button>
                  </div>
                </div>
              ))}

              {keys.length === 0 && !loading && (
                <p className="text-gray-500 text-center py-8">No API keys found</p>
              )}
            </div>
          </div>
        </div>

        {/* Right Column - Key Details */}
        <div>
          {selectedKey ? (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-6">Key Details</h2>

              <div className="space-y-6">
                {/* Basic Info */}
                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-3">Basic Information</h3>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-gray-600">ID:</span>
                      <span className="font-mono text-sm">{selectedKey.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Type:</span>
                      <span>{selectedKey.key_type}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Status:</span>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        selectedKey.status === "production"
                          ? "bg-red-100 text-red-800"
                          : "bg-yellow-100 text-yellow-800"
                      }`}>
                        {selectedKey.status}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Tenant:</span>
                      <span>{selectedKey.tenant}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">TTL:</span>
                      <span>{selectedKey.ttl} seconds</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Created:</span>
                      <span>{new Date(selectedKey.created_at).toLocaleString()}</span>
                    </div>
                  </div>
                </div>

                {/* API Key */}
                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-3">API Key</h3>
                  <div className="bg-gray-50 p-4 rounded-md">
                    <p className="font-mono text-sm break-all text-gray-800">
                      {selectedKey.key}
                    </p>
                  </div>
                  <button
                    onClick={() => navigator.clipboard.writeText(selectedKey.key)}
                    className="mt-2 text-sm text-blue-600 hover:text-blue-800"
                  >
                    Copy to clipboard
                  </button>
                </div>

                {/* Certificate */}
                {selectedKey.certificate && (
                  <div>
                    <h3 className="text-lg font-medium text-gray-900 mb-3">Certificate Information</h3>

                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Certificate Type
                        </label>
                        <p className="text-sm text-gray-900">{selectedKey.certificate.certificate_type}</p>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Fingerprint
                        </label>
                        <p className="font-mono text-sm text-gray-900 break-all">
                          {selectedKey.certificate.fingerprint}
                        </p>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Public Key
                        </label>
                        <div className="bg-gray-50 p-4 rounded-md max-h-48 overflow-y-auto">
                          <pre className="font-mono text-xs text-gray-800 whitespace-pre-wrap">
                            {selectedKey.certificate.public_key}
                          </pre>
                        </div>
                        <button
                          onClick={() => navigator.clipboard.writeText(selectedKey.certificate!.public_key)}
                          className="mt-2 text-sm text-blue-600 hover:text-blue-800"
                        >
                          Copy public key
                        </button>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Private Key Path
                        </label>
                        <p className="font-mono text-sm text-gray-900">
                          {selectedKey.certificate.private_key_path}
                        </p>
                        <p className="text-xs text-gray-500 mt-1">
                          Private key is securely stored in Vault
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {!selectedKey.certificate && (
                  <div className="text-center py-8 text-gray-500">
                    <p>No certificate associated with this key</p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <div className="text-center py-12 text-gray-500">
                <p>Select an API key to view details</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}