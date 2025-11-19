"use client";

import { WidgetCard } from "./WidgetCard";

interface Endpoint {
  path: string;
  method: string;
  requests: number;
  percentage: number;
  avgLatency: number;
}

interface TopEndpointsProps {
  endpoints: Endpoint[];
}

export function TopEndpoints({ endpoints }: TopEndpointsProps) {
  return (
    <WidgetCard title="Top Endpoints">
      <div className="space-y-3">
        {endpoints.map((endpoint, index) => (
          <div key={endpoint.path} className="flex items-center justify-between p-3 rounded-lg bg-gray-50 hover:bg-gray-100 transition-colors">
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center w-8 h-8 rounded-full bg-gray-200 text-gray-700 text-sm font-medium">
                {index + 1}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-1 text-xs rounded font-medium ${
                    endpoint.method === 'GET' ? 'bg-gray-200 text-gray-700' :
                    endpoint.method === 'POST' ? 'bg-gray-200 text-gray-700' :
                    endpoint.method === 'PUT' ? 'bg-gray-200 text-gray-700' :
                    'bg-gray-200 text-gray-700'
                  }`}>
                    {endpoint.method}
                  </span>
                  <span className="text-sm font-medium text-gray-900">
                    {endpoint.path}
                  </span>
                </div>
                <div className="text-xs text-gray-500 mt-1">
                  {endpoint.avgLatency}ms avg latency
                </div>
              </div>
            </div>
            <div className="text-right">
              <div className="text-sm font-medium text-gray-900">
                {endpoint.requests.toLocaleString()}
              </div>
              <div className="text-xs text-gray-500">
                {endpoint.percentage}%
              </div>
            </div>
          </div>
        ))}
      </div>
    </WidgetCard>
  );
}