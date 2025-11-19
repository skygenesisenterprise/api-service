"use client";

import { useState, useEffect } from "react";
import { 
  Activity, 
  Database, 
  Server, 
  Wifi, 
  MessageSquare, 
  Shield,
  Zap,
  Clock,
  TrendingUp,
  Cpu,
  HardDrive,
  Settings,
  Maximize2,
  Grid3X3,
  AlertTriangle,
  Layers,
  Eye,
  EyeOff,
  BarChart3,
  Download,
  RefreshCw
} from "lucide-react";

import { GrafanaMetricCard } from "../components/dashboard/GrafanaMetricCard";
import { GrafanaWidget } from "../components/dashboard/GrafanaWidget";
import { GrafanaChart } from "../components/dashboard/GrafanaChart";
import { ServiceStatus } from "../components/dashboard/ServiceStatus";
import { TopEndpoints } from "../components/dashboard/TopEndpoints";
import { RecentLogs } from "../components/dashboard/RecentLogs";
import { SecurityAlerts } from "../components/dashboard/SecurityAlerts";
import { ProjectUsage } from "../components/dashboard/ProjectUsage";
import { realTimeDataService } from "../lib/realTimeDataService";

export default function DashboardPage() {
  const [timeRange, setTimeRange] = useState<"24h" | "7d" | "30d">("24h");
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(5000);
  
  const [metrics, setMetrics] = useState(realTimeDataService.getMetrics());
  const [endpoints, setEndpoints] = useState(realTimeDataService.getEndpoints());
  const [logs, setLogs] = useState(realTimeDataService.getLogs());
  const [securityAlerts, setSecurityAlerts] = useState(realTimeDataService.getSecurityAlerts());

  useEffect(() => {
    const unsubscribe = realTimeDataService.subscribe(() => {
      setMetrics(realTimeDataService.getMetrics());
      setEndpoints(realTimeDataService.getEndpoints());
      setLogs(realTimeDataService.getLogs());
      setSecurityAlerts(realTimeDataService.getSecurityAlerts());
    });

    return () => {
      if (typeof unsubscribe === 'function') {
        unsubscribe();
      }
    };
  }, []);

  // Enhanced chart data with more realistic patterns
  const chartData = [
    { name: "00:00", requests: metrics.requests?.value || 0, latency: metrics.latency?.value || 0, errors: metrics.errorRate?.value || 0, throughput: (metrics.requests?.value || 0) * 0.8 },
    { name: "04:00", requests: (metrics.requests?.value || 0) * 0.6, latency: (metrics.latency?.value || 0) * 1.2, errors: (metrics.errorRate?.value || 0) * 0.5, throughput: (metrics.requests?.value || 0) * 0.5 },
    { name: "08:00", requests: (metrics.requests?.value || 0) * 1.4, latency: (metrics.latency?.value || 0) * 0.8, errors: (metrics.errorRate?.value || 0) * 1.3, throughput: (metrics.requests?.value || 0) * 1.6 },
    { name: "12:00", requests: (metrics.requests?.value || 0) * 1.8, latency: (metrics.latency?.value || 0) * 0.7, errors: (metrics.errorRate?.value || 0) * 1.6, throughput: (metrics.requests?.value || 0) * 2.0 },
    { name: "16:00", requests: (metrics.requests?.value || 0) * 1.3, latency: (metrics.latency?.value || 0) * 0.9, errors: (metrics.errorRate?.value || 0) * 1.2, throughput: (metrics.requests?.value || 0) * 1.4 },
    { name: "20:00", requests: (metrics.requests?.value || 0) * 0.8, latency: (metrics.latency?.value || 0) * 1.1, errors: (metrics.errorRate?.value || 0) * 0.7, throughput: (metrics.requests?.value || 0) * 0.9 },
    { name: "23:59", requests: metrics.requests?.value || 0, latency: metrics.latency?.value || 0, errors: metrics.errorRate?.value || 0, throughput: metrics.requests?.value || 0 },
  ];

  const exportReport = () => {
    const reportData = {
      timestamp: new Date().toISOString(),
      metrics: metrics,
      endpoints: endpoints,
      logs: logs,
      securityAlerts: securityAlerts,
      timeRange: timeRange,
      dashboardConfig: {
        darkMode: isDarkMode,
        autoRefresh: autoRefresh,
        refreshInterval: refreshInterval
      }
    };
    
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `grafana-dashboard-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const refreshData = () => {
    realTimeDataService.destroy();
    setTimeout(() => window.location.reload(), 100);
  };

  return (
    <div className={`min-h-screen bg-white transition-colors duration-300`}>
      {/* Header - Fixed Inverted Monochrome Style */}
      <div className="fixed top-16 left-18 right-0 z-40 bg-white border-b border-gray-200 backdrop-blur-lg transition-all duration-200 group-hover:left-72">
        <div className="flex items-center justify-between px-6 py-3">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-6 h-6 text-gray-700" />
              <div>
                <h1 className="text-xl font-bold text-black">Enterprise Dashboard</h1>
                <p className="text-xs text-gray-600">Real-time monitoring & analytics</p>
              </div>
            </div>
            
            <div className="flex items-center gap-2 ml-8">
              <div className="flex items-center gap-1 px-3 py-1 bg-gray-50 rounded-md border border-gray-200">
                <div className="w-2 h-2 bg-gray-700 rounded-full animate-pulse" />
                <span className="text-xs text-gray-700 font-mono">LIVE</span>
              </div>
              <span className="text-xs text-gray-500">
                Last updated: {new Date().toLocaleTimeString()}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Time Range Selector */}
            <div className="flex items-center gap-1 bg-gray-50 rounded-md border border-gray-200 p-1">
              {(["24h", "7d", "30d"] as const).map((range) => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={`px-3 py-1 text-xs rounded transition-all font-mono ${
                    timeRange === range
                      ? "bg-gray-200 text-gray-700 border border-gray-300"
                      : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"
                  }`}
                >
                  {range}
                </button>
              ))}
            </div>

            {/* Action Buttons */}
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`p-2 rounded transition-colors ${
                autoRefresh ? "bg-gray-200 text-gray-700" : "bg-gray-50 text-gray-500 hover:text-gray-700"
              }`}
              title="Auto Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${autoRefresh ? 'animate-spin' : ''}`} />
            </button>

            <button
              onClick={() => setIsFullscreen(!isFullscreen)}
              className="p-2 bg-gray-50 text-gray-500 rounded hover:text-gray-700 transition-colors"
              title="Fullscreen"
            >
              <Maximize2 className="w-4 h-4" />
            </button>

            <button
              onClick={exportReport}
              className="p-2 bg-gray-50 text-gray-500 rounded hover:text-gray-700 transition-colors"
              title="Export Report"
            >
              <Download className="w-4 h-4" />
            </button>

            <button
              onClick={refreshData}
              className="p-2 bg-gray-50 text-gray-500 rounded hover:text-gray-700 transition-colors"
              title="Refresh Data"
            >
              <RefreshCw className="w-4 h-4" />
            </button>

            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              className="p-2 bg-gray-50 text-gray-500 rounded hover:text-gray-700 transition-colors"
              title="Toggle Theme"
            >
              <Eye className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Dashboard Grid */}
      <div className="pt-32 pl-24 pr-6 pb-20 group-hover:pl-80 transition-all duration-200">
        <div className="grid grid-cols-12 gap-4 auto-rows-min">
          
          {/* Top Metrics Row */}
          <div className="col-span-12 grid grid-cols-12 gap-4">
            <div className="col-span-3">
              <GrafanaMetricCard
                title="REQUESTS/MIN"
                value={metrics.requests?.value || 0}
                change={metrics.requests?.change}
                changeType={metrics.requests?.changeType}
                icon={Zap}
                description="Real-time requests"
                status="success"
                isRealTime={true}
                minValue={800}
                maxValue={2000}
                unit=""
                variant="default"
              />
            </div>
            
            <div className="col-span-3">
              <GrafanaMetricCard
                title="AVG LATENCY"
                value={metrics.latency?.value || 0}
                change={metrics.latency?.change}
                changeType={metrics.latency?.changeType}
                icon={Clock}
                description="Response time"
                status="success"
                isRealTime={true}
                minValue={20}
                maxValue={100}
                unit="ms"
                variant="default"
              />
            </div>
            
            <div className="col-span-3">
              <GrafanaMetricCard
                title="ERROR RATE"
                value={metrics.errorRate?.value || 0}
                change={metrics.errorRate?.change}
                changeType={metrics.errorRate?.changeType}
                icon={AlertTriangle}
                description="Last 24 hours"
                status="warning"
                isRealTime={true}
                minValue={0}
                maxValue={5}
                unit="%"
                variant="default"
              />
            </div>
            
            <div className="col-span-3">
              <GrafanaMetricCard
                title="CPU USAGE"
                value={metrics.cpuUsage?.value || 0}
                change={metrics.cpuUsage?.change}
                changeType={metrics.cpuUsage?.changeType}
                icon={Cpu}
                description="System load"
                status="info"
                isRealTime={true}
                minValue={0}
                maxValue={100}
                unit="%"
                variant="default"
              />
            </div>
          </div>

          {/* Main Performance Chart */}
          <div className="col-span-8">
            <GrafanaWidget 
              title="Performance Overview" 
              size="large"
              actions={
                <div className="flex gap-1">
                  <button className="p-1 hover:bg-[#2a2a2a] rounded text-xs text-gray-400">
                    Area
                  </button>
                  <button className="p-1 hover:bg-[#2a2a2a] rounded text-xs text-gray-400">
                    Line
                  </button>
                  <button className="p-1 hover:bg-[#2a2a2a] rounded text-xs text-gray-400">
                    Bar
                  </button>
                </div>
              }
            >
              <GrafanaChart
                data={chartData}
                type="area"
                height={350}
                colors={["#374151", "#4b5563", "#6b7280", "#9ca3af"]}
                grid={true}
                timeRange={timeRange}
                onTimeRangeChange={setTimeRange}
                yAxisLabel="Count"
                xAxisLabel="Time"
                animated={true}
              />
            </GrafanaWidget>
          </div>

          {/* Service Health Panel */}
          <div className="col-span-4">
            <GrafanaWidget title="Service Health" size="medium">
              <div className="space-y-3">
                {endpoints.slice(0, 6).map((endpoint, index) => {
                  const status = endpoint.status === 'critical' ? 'error' : endpoint.status;
                  return (
                    <div key={`${endpoint.method}-${endpoint.path}`} className="flex items-center justify-between p-2 bg-gray-50 rounded border border-gray-200">
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${
                          status === 'healthy' ? 'bg-gray-600' : 
                          status === 'warning' ? 'bg-gray-500' : 'bg-gray-400'
                        }`} />
                        <span className="text-xs text-gray-700 font-mono">
                          {endpoint.path.replace('/api/v1/', '').toUpperCase()}
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-xs text-gray-600">
                          {endpoint.avgLatency}ms
                        </span>
                        <span className="text-xs text-gray-600">
                          {endpoint.requests}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </GrafanaWidget>
          </div>

          {/* System Resources */}
          <div className="col-span-4">
            <GrafanaWidget title="System Resources" size="medium">
              <div className="space-y-4">
                <GrafanaMetricCard
                  title="MEMORY"
                  value={65}
                  change={2.3}
                  changeType="increase"
                  icon={HardDrive}
                  description="RAM consumption"
                  status="warning"
                  isRealTime={true}
                  minValue={0}
                  maxValue={100}
                  unit="%"
                  variant="compact"
                  sparkline={true}
                />
                
                <GrafanaMetricCard
                  title="DISK"
                  value={78}
                  change={-1.2}
                  changeType="decrease"
                  icon={HardDrive}
                  description="Storage space"
                  status="warning"
                  isRealTime={true}
                  minValue={0}
                  maxValue={100}
                  unit="%"
                  variant="compact"
                  sparkline={true}
                />
                
                <GrafanaMetricCard
                  title="UPTIME"
                  value={99.9}
                  change={0.1}
                  changeType="increase"
                  icon={Activity}
                  description="Last 30 days"
                  status="success"
                  isRealTime={false}
                  variant="compact"
                  sparkline={false}
                />
              </div>
            </GrafanaWidget>
          </div>

          {/* Top Endpoints */}
          <div className="col-span-4">
            <GrafanaWidget title="Top Endpoints" size="medium">
              <TopEndpoints endpoints={endpoints.map(ep => ({
                ...ep,
                percentage: Math.round((ep.requests / endpoints.reduce((sum, e) => sum + e.requests, 0)) * 100) || 0
              }))} />
            </GrafanaWidget>
          </div>

          {/* Project Usage */}
          <div className="col-span-4">
            <GrafanaWidget title="Project Usage" size="medium">
              <ProjectUsage 
                data={endpoints.map(ep => ({
                  name: ep.path.replace('/api/v1/', '').replace('/', ' ').toUpperCase(),
                  requests: ep.requests,
                  percentage: Math.round((ep.requests / endpoints.reduce((sum, e) => sum + e.requests, 0)) * 100) || 0,
                  color: ep.status === 'healthy' ? '#10b981' : ep.status === 'warning' ? '#f59e0b' : '#ef4444'
                }))} 
              />
            </GrafanaWidget>
          </div>

          {/* Recent Logs */}
          <div className="col-span-6">
            <GrafanaWidget title="Recent Logs" size="medium">
              <RecentLogs logs={logs.map(log => ({
                ...log,
                timestamp: log.timestamp instanceof Date ? log.timestamp.toLocaleTimeString() : log.timestamp
              }))} />
            </GrafanaWidget>
          </div>

          {/* Security Alerts */}
          <div className="col-span-6">
            <GrafanaWidget title="Security Alerts" size="medium">
              <SecurityAlerts alerts={securityAlerts.map(alert => ({
                ...alert,
                timestamp: alert.timestamp instanceof Date ? alert.timestamp.toLocaleTimeString() : alert.timestamp
              }))} />
            </GrafanaWidget>
          </div>

        </div>
      </div>

      {/* Status Bar */}
      <div className="fixed bottom-0 left-0 right-0 bg-gray-50 border-t border-gray-200 px-6 py-2">
        <div className="flex items-center justify-between text-xs text-gray-600">
          <div className="flex items-center gap-4">
            <span>Dashboard v2.0</span>
            <span>•</span>
            <span>Auto-refresh: {autoRefresh ? 'ON' : 'OFF'}</span>
            <span>•</span>
            <span>Theme: Light</span>
          </div>
          <div className="flex items-center gap-4">
            <span>Endpoints: {endpoints.length}</span>
            <span>•</span>
            <span>Alerts: {securityAlerts.length}</span>
            <span>•</span>
            <span>CPU: {metrics.cpuUsage?.value || 0}%</span>
          </div>
        </div>
      </div>
    </div>
  );
}