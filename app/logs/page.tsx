import { LogsSidebar } from "../components/Sidebar";

export default function LogsPage() {

  return (
    <div className="max-w-7xl mx-auto p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Logs</h1>
        <p className="text-gray-600">
          Monitor and analyze system logs and activities.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Sidebar */}
        <div className="lg:col-span-1">
          <LogsSidebar />
        </div>

        {/* Main content */}
        <div className="lg:col-span-3">
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-8">
            <div className="text-center py-12">
              <div className="text-6xl mb-4">📋</div>
              <h2 className="text-2xl font-semibold text-gray-900 mb-2">Logs Overview</h2>
              <p className="text-gray-600 mb-6">
                Select a log category from the sidebar to view detailed information.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-xl mx-auto">
                <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
                  <div className="text-2xl mb-2">📝</div>
                  <h3 className="font-semibold text-blue-900">Audit Logs</h3>
                  <p className="text-sm text-blue-700">Security and access events</p>
                </div>
                <div className="p-4 bg-orange-50 rounded-lg border border-orange-200">
                  <div className="text-2xl mb-2">⚠️</div>
                  <h3 className="font-semibold text-orange-900">Error Logs</h3>
                  <p className="text-sm text-orange-700">Application errors and issues</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}