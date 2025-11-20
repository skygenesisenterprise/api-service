"use client";

import { useState, useEffect } from "react";
import { 
  Zap,
  Clock,
  AlertTriangle,
  Cpu,
  Activity,
  HardDrive,
  Monitor,
  Search,
  LayoutGrid,
  List,
  Filter,
  Bell,
  ChevronDown,
  MoreHorizontal,
  Pause,
  Play,
  Download,
  Maximize2,
  TrendingUp,
  TrendingDown,
  BarChart3,
  Users,
  Shield,
  Globe,
  Server,
  Wifi,
  MessageSquare,
  Database,
  Settings,
  RefreshCw,
  Eye,
  Sparkles,
  ArrowUpRight,
  ArrowDownRight,
  Grid3X3,
  Layers,
  EyeOff
} from "lucide-react";

import { ModernMetricCard } from "../components/dashboard/ModernMetricCard";
import { ModernWidget } from "../components/dashboard/ModernWidget";
import { ModernChart } from "../components/dashboard/ModernChart";
import { realTimeDataService } from "../lib/realTimeDataService";

export default function DashboardPage() {
  const [timeRange, setTimeRange] = useState<"24h" | "7d" | "30d">("24h");
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");
  const [searchQuery, setSearchQuery] = useState("");
  const [isPaused, setIsPaused] = useState(false);
  
  const [metrics, setMetrics] = useState(realTimeDataService.getMetrics());
  const [endpoints, setEndpoints] = useState(realTimeDataService.getEndpoints());

  useEffect(() => {
    const unsubscribe = realTimeDataService.subscribe(() => {
      setMetrics(realTimeDataService.getMetrics());
      setEndpoints(realTimeDataService.getEndpoints());
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
      timeRange: timeRange,
      dashboardConfig: {
        autoRefresh: autoRefresh,
        viewMode: viewMode
      }
    };
    
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `enterprise-dashboard-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50/30 to-indigo-50/50">
      {/* Modern Minimalist Header */}
      <div className="relative mt-6 mb-6 mx-auto max-w-7xl bg-white/60 backdrop-blur-md border-b border-white/10 rounded-t-2xl transition-all duration-300">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            {/* Left Section - Title and Status */}
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-3">
                <div className="relative">
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg blur-md opacity-25 animate-pulse" />
                  <div className="relative bg-gradient-to-r from-blue-500 to-purple-600 p-2 rounded-lg shadow-md">
                    <Monitor className="w-5 h-5 text-white" />
                  </div>
                </div>
                <div>
                  <h1 className="text-2xl font-bold text-slate-900">
                    Enterprise Dashboard
                  </h1>
                  <p className="text-sm text-slate-600">Real-time monitoring platform</p>
                </div>
              </div>
              
              <div className="flex items-center gap-3">
                <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-all ${
                  isPaused 
                    ? "bg-orange-50 border-orange-200" 
                    : "bg-emerald-50 border-emerald-200"
                }`}>
                  <div className={`w-2 h-2 rounded-full ${
                    isPaused ? "bg-orange-500" : "bg-emerald-500 animate-pulse"
                  }`} />
                  <span className={`text-xs font-semibold font-mono ${
                    isPaused ? "text-orange-700" : "text-emerald-700"
                  }`}>
                    {isPaused ? "PAUSED" : "LIVE"}
                  </span>
                </div>
                <span className="text-xs text-slate-600 font-mono bg-white/60 px-2 py-1 rounded border border-slate-200">
                  {new Date().toLocaleTimeString()}
                </span>
              </div>
            </div>

            {/* Center Section - Time Range */}
            <div className="flex items-center gap-2">
              <div className="flex items-center bg-white/60 rounded-lg p-1 border border-slate-200">
                {(["24h", "7d", "30d"] as const).map((range) => (
                  <button
                    key={range}
                    onClick={() => setTimeRange(range)}
                    className={`px-3 py-1.5 text-sm font-medium rounded-md transition-all ${
                      timeRange === range
                        ? "bg-white text-slate-900 shadow-sm"
                        : "text-slate-600 hover:text-slate-900"
                    }`}
                  >
                    {range}
                  </button>
                ))}
              </div>
            </div>

            {/* Right Section - Actions */}
            <div className="flex items-center gap-2">
              {/* Search Bar */}
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 pr-3 py-2 bg-white/60 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all w-48"
                />
              </div>

              {/* View Mode Toggle */}
              <div className="flex items-center bg-white/60 rounded-lg p-1 border border-slate-200">
                <button
                  onClick={() => setViewMode("grid")}
                  className={`p-1.5 rounded-md transition-all ${
                    viewMode === "grid" 
                      ? "bg-white shadow-sm text-slate-900" 
                      : "text-slate-500 hover:text-slate-700"
                  }`}
                >
                  <LayoutGrid className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setViewMode("list")}
                  className={`p-1.5 rounded-md transition-all ${
                    viewMode === "list" 
                      ? "bg-white shadow-sm text-slate-900" 
                      : "text-slate-500 hover:text-slate-700"
                  }`}
                >
                  <List className="w-4 h-4" />
                </button>
              </div>

              {/* Action Buttons */}
              <button
                onClick={() => setIsPaused(!isPaused)}
                className={`p-2 rounded-lg transition-all ${
                  isPaused 
                    ? "bg-orange-100 text-orange-600 hover:bg-orange-200" 
                    : "bg-emerald-100 text-emerald-600 hover:bg-emerald-200"
                }`}
                title={isPaused ? "Resume" : "Pause"}
              >
                {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
              </button>

              <button
                onClick={exportReport}
                className="p-2 bg-white/60 text-slate-600 rounded-lg hover:bg-slate-100 transition-all border border-slate-200"
                title="Export Report"
              >
                <Download className="w-4 h-4" />
              </button>

              <button
                onClick={() => setIsFullscreen(!isFullscreen)}
                className="p-2 bg-white/60 text-slate-600 rounded-lg hover:bg-slate-100 transition-all border border-slate-200"
                title="Fullscreen"
              >
                <Maximize2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Dashboard Grid */}
      <div className="mx-auto max-w-7xl pb-8 transition-all duration-300">
        <div className="grid grid-cols-12 gap-6 auto-rows-min">
          
          {/* Top Metrics Row - Modern Cards */}
          <div className="col-span-12 grid grid-cols-12 gap-6 mb-6">
            <div className="col-span-3">
              <ModernMetricCard
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
                trend="up"
              />
            </div>
            
            <div className="col-span-3">
              <ModernMetricCard
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
                trend="down"
              />
            </div>
            
            <div className="col-span-3">
              <ModernMetricCard
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
                trend="stable"
              />
            </div>
            
            <div className="col-span-3">
              <ModernMetricCard
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
                trend="up"
              />
            </div>
          </div>

          {/* Main Performance Chart - Modern */}
          <div className="col-span-8">
            <ModernWidget 
              title="Performance Analytics" 
              variant="gradient"
              onExport={exportReport}
            >
              <ModernChart
                data={chartData}
                type="area"
                height={400}
                colors={["#3b82f6", "#8b5cf6", "#10b981", "#f59e0b"]}
                grid={true}
                timeRange={timeRange}
                onTimeRangeChange={setTimeRange}
                yAxisLabel="Count"
                xAxisLabel="Time"
                animated={true}
                variant="gradient"
                gradient={true}
                curved={true}
              />
            </ModernWidget>
          </div>

          {/* Service Health Panel - Modern */}
          <div className="col-span-4">
            <ModernWidget title="Service Health" variant="default">
              <div className="space-y-4">
                {endpoints.slice(0, 6).map((endpoint) => {
                  const status = endpoint.status === 'critical' ? 'error' : endpoint.status;
                  return (
                    <div key={`${endpoint.method}-${endpoint.path}`} className="flex items-center justify-between p-4 bg-slate-50 rounded-xl border border-slate-200 hover:border-slate-300 transition-all">
                      <div className="flex items-center gap-3">
                        <div className={`w-3 h-3 rounded-full ${
                          status === 'healthy' ? 'bg-emerald-500 shadow-sm shadow-emerald-500/50' : 
                          status === 'warning' ? 'bg-amber-500 shadow-sm shadow-amber-500/50' : 'bg-red-500 shadow-sm shadow-red-500/50'
                        }`} />
                        <span className="text-sm font-semibold text-slate-700 font-mono">
                          {endpoint.path.replace('/api/v1/', '').toUpperCase()}
                        </span>
                      </div>
                      <div className="flex items-center gap-4">
                        <span className="text-sm text-slate-600 font-mono">
                          {endpoint.avgLatency}ms
                        </span>
                        <span className="text-sm font-semibold text-slate-700">
                          {endpoint.requests}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </ModernWidget>
          </div>

          {/* System Resources - Modern Cards */}
          <div className="col-span-4">
            <ModernWidget title="System Resources" variant="default">
              <div className="space-y-5">
                <ModernMetricCard
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
                  trend="up"
                />
                
                <ModernMetricCard
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
                  trend="down"
                />
                
                <ModernMetricCard
                  title="UPTIME"
                  value={99.9}
                  change={0.1}
                  changeType="increase"
                  icon={Activity}
                  description="Last 30 days"
                  status="success"
                  isRealTime={false}
                  variant="compact"
                  trend="up"
                />
              </div>
            </ModernWidget>
          </div>

          {/* Additional Analytics Section */}
          <div className="col-span-8">
            <ModernWidget title="Network Traffic Analysis" variant="gradient">
              <ModernChart
                data={chartData}
                type="line"
                height={300}
                colors={["#3b82f6", "#8b5cf6"]}
                grid={true}
                yAxisLabel="MB/s"
                xAxisLabel="Time"
                animated={true}
                variant="gradient"
                curved={true}
                showDots={true}
                strokeWidth={3}
              />
            </ModernWidget>
          </div>

        </div>
      </div>


    </div>
  );
}