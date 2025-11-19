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
  Users,
  Cpu,
  HardDrive,
  Download,
  RefreshCw
} from "lucide-react";

import { MetricCard } from "../components/dashboard/MetricCard";
import { ServiceStatus } from "../components/dashboard/ServiceStatus";
import { DashboardChart } from "../components/dashboard/DashboardChart";
import { TopEndpoints } from "../components/dashboard/TopEndpoints";
import { RecentLogs } from "../components/dashboard/RecentLogs";
import { SecurityAlerts } from "../components/dashboard/SecurityAlerts";
import { ProjectUsage } from "../components/dashboard/ProjectUsage";
import { realTimeDataService } from "../lib/realTimeDataService";

export default function DashboardPage() {
  const [timeRange, setTimeRange] = useState<"24h" | "7d" | "30d">("24h");
  const [metrics, setMetrics] = useState(realTimeDataService.getMetrics());
  const [endpoints, setEndpoints] = useState(realTimeDataService.getEndpoints());
  const [logs, setLogs] = useState(realTimeDataService.getLogs());
  const [securityAlerts, setSecurityAlerts] = useState(realTimeDataService.getSecurityAlerts());

  useEffect(() => {
    // S'abonner aux mises à jour en temps réel
    const unsubscribe = realTimeDataService.subscribe(() => {
      setMetrics(realTimeDataService.getMetrics());
      setEndpoints(realTimeDataService.getEndpoints());
      setLogs(realTimeDataService.getLogs());
      setSecurityAlerts(realTimeDataService.getSecurityAlerts());
    });

    return () => {
      unsubscribe();
    };
  }, []);

  // Données pour le graphique
  const chartData = [
    { name: "00:00", requests: metrics.requests?.value || 0, latency: metrics.latency?.value || 0, errors: metrics.errorRate?.value || 0 },
    { name: "04:00", requests: (metrics.requests?.value || 0) * 0.8, latency: (metrics.latency?.value || 0) * 1.1, errors: (metrics.errorRate?.value || 0) * 0.8 },
    { name: "08:00", requests: (metrics.requests?.value || 0) * 1.2, latency: (metrics.latency?.value || 0) * 0.9, errors: (metrics.errorRate?.value || 0) * 1.2 },
    { name: "12:00", requests: (metrics.requests?.value || 0) * 1.5, latency: (metrics.latency?.value || 0) * 0.95, errors: (metrics.errorRate?.value || 0) * 1.5 },
    { name: "16:00", requests: (metrics.requests?.value || 0) * 1.1, latency: (metrics.latency?.value || 0) * 1.05, errors: (metrics.errorRate?.value || 0) * 1.1 },
    { name: "20:00", requests: (metrics.requests?.value || 0) * 0.9, latency: (metrics.latency?.value || 0) * 1.1, errors: (metrics.errorRate?.value || 0) * 0.9 },
    { name: "23:59", requests: metrics.requests?.value || 0, latency: metrics.latency?.value || 0, errors: metrics.errorRate?.value || 0 },
  ];

  return (
    <div className="space-y-6 bg-gray-50 min-h-full w-full">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-gray-600 mt-1">Monitor your system performance and security</p>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={() => {
              // Fonctionnalité d'export de rapport
              const reportData = {
                timestamp: new Date().toISOString(),
                metrics: metrics,
                endpoints: endpoints,
                logs: logs,
                securityAlerts: securityAlerts,
                timeRange: timeRange
              };
              
              // Créer un blob JSON et le télécharger
              const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const link = document.createElement('a');
              link.href = url;
              link.download = `dashboard-report-${new Date().toISOString().split('T')[0]}.json`;
              document.body.appendChild(link);
              link.click();
              document.body.removeChild(link);
              URL.revokeObjectURL(url);
            }}
            className="px-4 py-2 text-sm bg-white border border-gray-200 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3v6m0 0l-3-3m3 3v6m0 0l-3-3m3 3v6m0 0l-3-3m3 3v6m0 0l-3-3m3 3v6m0 0l-3-3m3 3v6m0 0l-3-3m3 3v6m0 0l-3-3m3 3v6m0 0l-3-3m3 3v6m0 0l-3-3m3 3v6" />
            </svg>
            Export Report
          </button>
          
          <button 
            onClick={() => {
              // Forcer le rafraîchissement des données
              realTimeDataService.destroy();
              
              // Recréer le service pour forcer une nouvelle initialisation
              setTimeout(() => {
                window.location.reload();
              }, 100);
            }}
            className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 018.582 0m15.356 2A8.001 8.001 0 018.582 0M4 12a8.001 8.001 0 018.582 0m15.356 8A8.001 8.001 0 018.582 0" />
            </svg>
            Refresh Data
          </button>
        </div>
      </div>

      {/* KPI Metrics - Temps Réel */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 w-full">
        <MetricCard
          title="Requests/min"
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
        />
        <MetricCard
          title="Avg Latency"
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
        />
        <MetricCard
          title="Error Rate"
          value={metrics.errorRate?.value || 0}
          change={metrics.errorRate?.change}
          changeType={metrics.errorRate?.changeType}
          icon={TrendingUp}
          description="Last 24 hours"
          status="warning"
          isRealTime={true}
          minValue={0}
          maxValue={5}
          unit="%"
        />
        <MetricCard
          title="CPU Usage"
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
        />
      </div>

      {/* Service Health Status */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        <div className="lg:col-span-1">
          <h3 className="text-sm font-medium text-gray-900 mb-3">Service Health</h3>
          <div className="space-y-2">
            {endpoints.slice(0, 5).map((endpoint, index) => {
              const status = endpoint.status === 'critical' ? 'error' : endpoint.status;
              return (
                <ServiceStatus
                  key={`${endpoint.method}-${endpoint.path}`}
                  name={endpoint.path.replace('/api/v1/', '').toUpperCase()}
                  status={status}
                  latency={endpoint.avgLatency}
                  load={Math.round((endpoint.requests / 1000) * 100)}
                  icon={index === 0 ? Server : index === 1 ? Shield : index === 2 ? Database : index === 3 ? Wifi : MessageSquare}
                />
              );
            })}
          </div>
        </div>

        {/* Performance Chart */}
        <div className="lg:col-span-4">
          <DashboardChart 
            data={chartData}
            timeRange={timeRange}
            onTimeRangeChange={setTimeRange}
          />
        </div>
      </div>

      {/* Second Row - Top Endpoints and Project Usage */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TopEndpoints endpoints={endpoints} />
        <ProjectUsage data={endpoints.map(ep => ({
          name: ep.path.replace('/api/v1/', '').replace('/', ' ').toUpperCase(),
          requests: ep.requests,
          percentage: Math.round((ep.requests / endpoints.reduce((sum, e) => sum + e.requests, 0)) * 100),
          color: ep.status === 'healthy' ? '#10b981' : ep.status === 'warning' ? '#f59e0b' : '#ef4444'
        }))} />
      </div>

      {/* Third Row - Logs and Security Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RecentLogs logs={logs.map(log => ({
          ...log,
          timestamp: log.timestamp instanceof Date ? log.timestamp.toLocaleTimeString() : log.timestamp
        }))} />
        <SecurityAlerts alerts={securityAlerts.map(alert => ({
          ...alert,
          timestamp: alert.timestamp instanceof Date ? alert.timestamp.toLocaleTimeString() : alert.timestamp
        }))} />
      </div>

      {/* System Resources */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <MetricCard
          title="Memory Usage"
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
        />
        <MetricCard
          title="Disk Usage"
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
        />
        <MetricCard
          title="Uptime"
          value={99.9}
          change={0.1}
          changeType="increase"
          icon={Activity}
          description="Last 30 days"
          status="success"
          isRealTime={false}
        />
      </div>
    </div>
  );
}