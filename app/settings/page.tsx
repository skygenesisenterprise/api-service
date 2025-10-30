"use client";

import { useAuthContext } from "../context/AuthContext";
import { SettingsSidebar } from "../components/Sidebar";

export default function SettingsPage() {
  const { isAuthenticated } = useAuthContext();

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-900 mb-4">Access Denied</h1>
          <p className="text-gray-600">Please log in to access settings.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Settings</h1>
        <p className="text-gray-600">
          Manage your account settings and preferences.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Sidebar */}
        <div className="lg:col-span-1">
          <SettingsSidebar />
        </div>

        {/* Main content */}
        <div className="lg:col-span-3">
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-8">
            <div className="text-center py-12">
              <div className="text-6xl mb-4">⚙️</div>
              <h2 className="text-2xl font-semibold text-gray-900 mb-2">Settings Overview</h2>
              <p className="text-gray-600 mb-6">
                Choose a settings category from the sidebar to configure your preferences.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-2xl mx-auto">
                <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
                  <div className="text-2xl mb-2">🔑</div>
                  <h3 className="font-semibold text-blue-900">API Keys</h3>
                  <p className="text-sm text-blue-700">Manage authentication keys</p>
                </div>
                <div className="p-4 bg-green-50 rounded-lg border border-green-200">
                  <div className="text-2xl mb-2">🔧</div>
                  <h3 className="font-semibold text-green-900">General</h3>
                  <p className="text-sm text-green-700">Application preferences</p>
                </div>
                <div className="p-4 bg-red-50 rounded-lg border border-red-200">
                  <div className="text-2xl mb-2">🔒</div>
                  <h3 className="font-semibold text-red-900">Security</h3>
                  <p className="text-sm text-red-700">Access and security controls</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}