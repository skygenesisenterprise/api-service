"use client";

import { useState, useEffect } from 'react';
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
  RefreshCw,
  Bell,
  ChevronDown,
  Search,
  Plus,
  Bookmark,
  Share2,
  CheckCircle,
  XCircle,
  AlertCircle,
  Loader2,
  LineChart
} from 'lucide-react';

// Types
interface LogEntry {
  id: string;
  timestamp: string;
  level: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';
  service: string;
  message: string;
  userId?: string;
  requestId?: string;
  ip?: string;
  userAgent?: string;
  projectId?: string;
  tenantId?: string;
  environment?: string;
  tags?: string[];
  raw?: string;
}

interface LogStats {
  total: number;
  byLevel: Record<string, number>;
  byService: Record<string, number>;
  timeRange: {
    start: string;
    end: string;
  };
}

interface LogFilter {
  dateRange?: {
    start: string;
    end: string;
  };
  levels?: string[];
  services?: string[];
  projects?: string[];
  tenants?: string[];
  environments?: string[];
  search?: string;
  userId?: string;
  requestId?: string;
  ip?: string;
  tags?: string[];
  regex?: string;
}

// Mock data service
const realTimeDataService = {
  getMetrics: () => ({
    requests: { value: 1250, change: 5.2, changeType: 'increase' as const },
    latency: { value: 45, change: -2.1, changeType: 'decrease' as const },
    errorRate: { value: 0.8, change: 0.1, changeType: 'increase' as const },
    cpuUsage: { value: 65, change: 1.2, changeType: 'increase' as const },
    memoryUsage: { value: 78, change: -0.5, changeType: 'decrease' as const },
    diskUsage: { value: 45, change: 0.3, changeType: 'increase' as const }
  }),
  getEndpoints: () => [
    { id: '1', path: '/api/v1/auth', method: 'GET', status: 'healthy', requests: 450, avgLatency: 23, errorRate: 0.2 },
    { id: '2', path: '/api/v1/users', method: 'GET', status: 'healthy', requests: 320, avgLatency: 18, errorRate: 0.1 },
    { id: '3', path: '/api/v1/payments', method: 'POST', status: 'warning', requests: 180, avgLatency: 45, errorRate: 2.3 },
    { id: '4', path: '/api/v1/logs', method: 'GET', status: 'critical', requests: 890, avgLatency: 67, errorRate: 5.6 },
    { id: '5', path: '/api/v1/analytics', method: 'GET', status: 'healthy', requests: 120, avgLatency: 12, errorRate: 0.05 }
  ],
  getLogs: () => [
    {
      id: '1',
      timestamp: new Date(Date.now() - 120000).toISOString(),
      level: 'error',
      service: 'api-gateway',
      message: 'Authentication failed for user: invalid credentials',
      userId: 'user-456',
      requestId: 'req-def456',
      ip: '192.168.1.101',
      environment: 'production'
    },
    {
      id: '2',
      timestamp: new Date(Date.now() - 60000).toISOString(),
      level: 'warn',
      service: 'payment-service',
      message: 'Payment retry attempted for order #12345',
      userId: 'user-789',
      requestId: 'req-ghi789',
      ip: '192.168.1.102',
      environment: 'production'
    },
    {
      id: '3',
      timestamp: new Date(Date.now() - 30000).toISOString(),
      level: 'info',
      service: 'notification-service',
      message: 'Email notification sent successfully',
      userId: 'user-123',
      requestId: 'req-jkl012',
      ip: '192.168.1.104',
      environment: 'production'
    },
    {
      id: '4',
      timestamp: new Date(Date.now() - 180000).toISOString(),
      level: 'fatal',
      service: 'database',
      message: 'Database connection lost',
      ip: '192.168.1.103',
      environment: 'production'
    },
    {
      id: '5',
      timestamp: new Date(Date.now() - 240000).toISOString(),
      level: 'debug',
      service: 'storage-service',
      message: 'File cleanup completed successfully',
      userId: 'user-123',
      requestId: 'req-mno345',
      ip: '192.168.1.105',
      environment: 'production'
    }
  ],
  getSecurityAlerts: () => [
    {
      id: '1',
      timestamp: new Date(Date.now() - 300000).toISOString(),
      type: 'critical',
      title: 'Security Breach Detected',
      message: 'Multiple failed login attempts from IP 192.168.1.50',
      severity: 'high',
      acknowledged: false
    },
    {
      id: '2',
      timestamp: new Date(Date.now() - 600000).toISOString(),
      type: 'warning',
      title: 'Unusual Activity Pattern',
      message: 'Spike in API requests from unknown source',
      severity: 'medium',
      acknowledged: false
    },
    {
      id: '3',
      timestamp: new Date(Date.now() - 900000).toISOString(),
      type: 'info',
      title: 'System Update Completed',
      message: 'Security patches applied successfully',
      severity: 'low',
      acknowledged: true
    }
  ],
  subscribe: (callback: () => void) => {
    const interval = setInterval(callback, 5000);
    return () => clearInterval(interval);
  },
  destroy: () => {
    // Cleanup method
  }
};

// Mock Metric Card Component
interface MetricCardProps {
  title: string;
  value: string | number;
  change?: number;
  changeType?: 'increase' | 'decrease';
  icon: React.ComponentType<{ className?: string }>;
  description?: string;
  status?: 'success' | 'warning' | 'error';
  isRealTime?: boolean;
  minValue?: number;
  maxValue?: number;
  unit?: string;
  variant?: 'default' | 'compact';
  sparkline?: boolean;
}

function MetricCard({ 
  title, 
  value, 
  change, 
  changeType, 
  icon: Icon, 
  description, 
  status = 'success', 
  isRealTime = false,
  minValue,
  maxValue,
  unit = '',
  variant = 'default',
  sparkline = false 
}: MetricCardProps) {
  const changeColor = changeType === 'increase' ? 'text-green-600' : changeType === 'decrease' ? 'text-red-600' : 'text-gray-600';
  const statusColor = status === 'success' ? 'text-green-600' : status === 'warning' ? 'text-yellow-600' : status === 'error' ? 'text-red-600' : 'text-gray-600';
  
  return (
    <div className={`bg-white border border-gray-200 rounded-lg p-6 transition-all duration-200 hover:shadow-lg ${variant === 'compact' ? 'p-4' : ''}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-xs text-gray-500">{description}</p>
        </div>
        <div className="flex items-center gap-2">
          {isRealTime && (
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
          )}
          <Icon className="h-4 w-4 text-gray-600" />
        </div>
      </div>
      <div className="mt-2">
        <div className="text-2xl font-bold text-gray-900">{value}</div>
        {change !== undefined && (
          <div className={`flex items-center text-sm ${changeColor}`}>
            {changeType === 'increase' ? <TrendingUp className="h-3 w-3" /> : <TrendingUp className="h-3 w-3 rotate-180" />}
            <span className="ml-1">{Math.abs(change)}%</span>
          </div>
        )}
        {(minValue !== undefined && maxValue !== undefined && typeof value === 'number') && (
          <div className="mt-2">
            <div className="flex justify-between text-xs text-gray-500 mb-1">
              <span>{minValue}</span>
              <div className="flex-1 bg-gray-200 rounded-full h-1 mx-2">
                <div 
                  className="bg-blue-500 h-1 rounded-full transition-all duration-300"
                  style={{ width: `${Math.max(0, Math.min(100, ((value - minValue) / (maxValue - minValue)) * 100))}%` }}
                />
              </div>
              <span>{maxValue}</span>
            </div>
          </div>
        )}
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <span className={statusColor}>{status}</span>
          {unit && <span className="ml-2">{unit}</span>}
        </div>
      </div>
    </div>
  );
}

// Mock Grafana Widget Component
interface GrafanaWidgetProps {
  title: string;
  size?: 'small' | 'medium' | 'large';
  actions?: React.ReactNode;
  children: React.ReactNode;
}

function GrafanaWidget({ title, size = 'medium', actions, children }: GrafanaWidgetProps) {
  return (
    <div className={`bg-white border border-gray-200 rounded-lg p-4 ${size === 'small' ? 'p-3' : size === 'large' ? 'p-6' : 'p-4'}`}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">{title}</h3>
        {actions && (
          <div className="flex gap-2">
            {actions}
          </div>
        )}
      </div>
      <div className="bg-gray-50 rounded p-4">
        {children}
      </div>
    </div>
  );
}

// Mock Grafana Chart Component
interface GrafanaChartProps {
  title: string;
  type?: 'line' | 'area' | 'bar';
  height?: number;
  data?: any[];
  timeRange?: string;
  onTimeRangeChange?: (range: string) => void;
}

function GrafanaChart({ title, type = 'line', height = 200, data = [], timeRange, onTimeRangeChange }: GrafanaChartProps) {
  return (
    <GrafanaWidget title={title} size="large">
      <div className="h-64 flex items-center justify-center border-2 border-dashed border-gray-300 rounded">
        <LineChart className="h-6 w-6 text-gray-400" />
        <p className="text-sm text-gray-500">Chart visualization</p>
      </div>
    </GrafanaWidget>
  );
}

// Mock Service Status Component
interface ServiceStatusProps {
  services: Array<{
    name: string;
    status: 'healthy' | 'warning' | 'critical' | 'unknown';
    requests: number;
    avgLatency: number;
    errorRate: number;
  }>;
}

function ServiceStatus({ services }: ServiceStatusProps) {
  const healthyCount = services.filter(s => s.status === 'healthy').length;
  const warningCount = services.filter(s => s.status === 'warning').length;
  const criticalCount = services.filter(s => s.status === 'critical').length;
  
  return (
    <GrafanaWidget title="Service Status" size="medium">
      <div className="space-y-4">
        <div className="grid grid-cols-3 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600">{healthyCount}</div>
            <div className="text-sm text-gray-600">Healthy</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-600">{warningCount}</div>
            <div className="text-sm text-gray-600">Warning</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-600">{criticalCount}</div>
            <div className="text-sm text-gray-600">Critical</div>
          </div>
        </div>
        <div className="mt-4 space-y-2">
          {services.map((service, index) => (
            <div key={index} className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
              <div className="flex items-center gap-3">
                <div className={`w-3 h-3 rounded-full ${
                  service.status === 'healthy' ? 'bg-green-500' : 
                  service.status === 'warning' ? 'bg-yellow-500' : 
                  service.status === 'critical' ? 'bg-red-500' : 'bg-gray-400'
                }`} />
                <div>
                  <div className="text-sm font-medium">{service.name}</div>
                  <div className="text-xs text-gray-500">{service.requests} requests</div>
                </div>
              </div>
              <div className="text-right text-sm">
                <div className="text-gray-600">{service.avgLatency}ms</div>
                <div className={`text-xs ${service.errorRate > 1 ? 'text-red-600' : 'text-green-600'}`}>
                  {service.errorRate}% error rate
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </GrafanaWidget>
  );
}

// Mock Top Endpoints Component
interface TopEndpointsProps {
  endpoints: Array<{
    path: string;
    method: string;
    status: 'healthy' | 'warning' | 'critical' | 'unknown';
    requests: number;
    avgLatency: number;
    errorRate: number;
  }>;
}

function TopEndpoints({ endpoints }: TopEndpointsProps) {
  return (
    <GrafanaWidget title="Top Endpoints" size="medium">
      <div className="space-y-4">
        {endpoints.slice(0, 5).map((endpoint, index) => (
          <div key={index} className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-3">
              <div className={`w-3 h-3 rounded-full ${
                endpoint.status === 'healthy' ? 'bg-green-500' : 
                endpoint.status === 'warning' ? 'bg-yellow-500' : 
                endpoint.status === 'critical' ? 'bg-red-500' : 'bg-gray-400'
              }`} />
              <div>
                <div className="text-sm font-medium">{endpoint.path}</div>
                <div className="text-xs text-gray-500">{endpoint.method}</div>
              </div>
            </div>
            <div className="text-right text-sm">
              <div className="text-gray-600">{endpoint.requests}</div>
              <div className={`text-xs ${endpoint.errorRate > 1 ? 'text-red-600' : 'text-green-600'}`}>
                {endpoint.errorRate}% errors
              </div>
            </div>
          </div>
        ))}
      </div>
    </GrafanaWidget>
  );
}

// Mock Recent Logs Component
interface RecentLogsProps {
  logs: Array<{
    id: string;
    timestamp: string;
    level: string;
    service: string;
    message: string;
    userId?: string;
    requestId?: string;
    ip?: string;
  }>;
}

function RecentLogs({ logs }: RecentLogsProps) {
  return (
    <GrafanaWidget title="Recent Logs" size="medium">
      <div className="space-y-3">
        {logs.slice(0, 10).map((log, index) => (
          <div key={log.id} className="flex items-start gap-3 p-3 border border-gray-200 rounded-lg hover:bg-gray-50">
            <div className={`w-2 h-2 rounded-full mt-1 ${
              log.level === 'error' ? 'bg-red-500' : 
              log.level === 'warn' ? 'bg-yellow-500' : 
              log.level === 'fatal' ? 'bg-red-600' : 
              log.level === 'info' ? 'bg-blue-500' : 
              'bg-gray-500'
            }`} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className={`px-2 py-1 text-xs font-medium rounded ${
                  log.level === 'error' ? 'bg-red-100 text-red-700' : 
                  log.level === 'warn' ? 'bg-yellow-100 text-yellow-700' : 
                  log.level === 'fatal' ? 'bg-red-100 text-red-700' : 
                  log.level === 'info' ? 'bg-blue-100 text-blue-700' : 
                  'bg-gray-100 text-gray-700'
                }`}>
                  {log.level.toUpperCase()}
                </span>
                <span className="text-xs text-gray-500">{log.service}</span>
                <span className="text-xs text-gray-400">
                  {new Date(log.timestamp).toLocaleString()}
                </span>
              </div>
              <p className="text-sm text-gray-900 truncate">{log.message}</p>
              {(log.userId || log.ip) && (
                <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                  {log.userId && <span>User: {log.userId}</span>}
                  {log.ip && <span>IP: {log.ip}</span>}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </GrafanaWidget>
  );
}

// Mock Security Alerts Component
interface SecurityAlertsProps {
  alerts: Array<{
    id: string;
    timestamp: string;
    type: 'critical' | 'warning' | 'info';
    title: string;
    message: string;
    severity: 'high' | 'medium' | 'low';
    acknowledged: boolean;
  }>;
}

function SecurityAlerts({ alerts }: SecurityAlertsProps) {
  return (
    <GrafanaWidget title="Security Alerts" size="medium">
      <div className="space-y-3">
        {alerts.map((alert, index) => (
          <div key={alert.id} className={`flex items-start gap-3 p-3 border border-gray-200 rounded-lg ${
            !alert.acknowledged ? 'border-l-4 border-red-300' : ''
          }`}>
            <div className={`w-2 h-2 rounded-full mt-1 ${
              alert.type === 'critical' ? 'bg-red-500' : 
              alert.type === 'warning' ? 'bg-yellow-500' : 
              alert.type === 'info' ? 'bg-blue-500' : 
              'bg-gray-500'
            }`} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between mb-1">
                <div>
                  <div className="text-sm font-medium text-gray-900">{alert.title}</div>
                  <div className="text-xs text-gray-500">
                    {new Date(alert.timestamp).toLocaleString()}
                  </div>
                </div>
                <p className="text-sm text-gray-900 mt-1">{alert.message}</p>
                <div className="flex items-center justify-between mt-2">
                  <span className={`px-2 py-1 text-xs font-medium rounded ${
                    alert.severity === 'high' ? 'bg-red-100 text-red-700' : 
                    alert.severity === 'medium' ? 'bg-yellow-100 text-yellow-700' : 
                    alert.severity === 'low' ? 'bg-blue-100 text-blue-700' : 
                    'bg-gray-100 text-gray-700'
                  }`}>
                    {alert.acknowledged ? 'Acknowledged' : 'Acknowledge'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </GrafanaWidget>
  );
}

// Mock Project Usage Component
interface ProjectUsageProps {
  projects: Array<{
    id: string;
    name: string;
    requests: number;
    storage: number;
    bandwidth: number;
    users: number;
  }>;
}

function ProjectUsage({ projects }: ProjectUsageProps) {
  return (
    <GrafanaWidget title="Project Usage" size="medium">
      <div className="space-y-4">
        {projects.map((project, index) => (
          <div key={project.id} className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-500 rounded-lg flex items-center justify-center text-white font-bold">
                {project.name.charAt(0).toUpperCase()}
              </div>
              <div>
                <div className="text-sm font-medium text-gray-900">{project.name}</div>
                <div className="text-xs text-gray-500">{project.requests} requests</div>
              </div>
            </div>
            <div className="text-right">
              <div className="text-sm text-gray-600">{project.storage}GB</div>
              <div className="text-sm text-gray-600">{project.bandwidth}GB</div>
              <div className="text-sm text-gray-600">{project.users} users</div>
            </div>
          </div>
        ))}
      </div>
    </GrafanaWidget>
  );
}

export default function LogsPage() {
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
    link.download = `dashboard-report-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const refreshData = () => {
    realTimeDataService.destroy();
    setTimeout(() => {
      window.location.reload();
    }, 100);
  };

  return (
    <div className={`min-h-screen bg-white transition-colors duration-300 ${isDarkMode ? 'dark' : ''}`}>
      {/* Header - Fixed Inverted Monochrome Style */}
      <div className="fixed top-16 left-18 right-0 z-40 bg-white border-b border-gray-200 backdrop-blur-lg transition-all duration-200 group-hover:left-72">
        <div className="flex items-center justify-between px-6 py-3">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-6 h-6 text-gray-700" />
              <div>
                <h1 className="text-xl font-bold text-black">Enterprise Logs</h1>
                <p className="text-xs text-gray-600">Real-time log monitoring and analysis</p>
              </div>
            </div>
            
            {/* Status Indicators */}
            <div className="flex items-center gap-2 ml-8">
              <div className="flex items-center gap-1 px-3 py-1 bg-gray-50 rounded-md border border-gray-200">
                <div className="w-2 h-2 bg-gray-700 rounded-full animate-pulse" />
                <span className="text-xs text-gray-700 font-mono">LIVE</span>
              </div>
              <div className="flex items-center gap-1 px-3 py-1 bg-green-100 rounded-md border border-gray-200">
                <CheckCircle className="w-4 h-4 text-green-600" />
                <span className="text-xs text-gray-700">SYSTEM OK</span>
              </div>
            </div>
          </div>
          
          {/* Action Buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`p-2 rounded-md border border-gray-200 transition-colors ${
                autoRefresh ? 'bg-gray-100 text-gray-700' : 'bg-gray-50 text-gray-500 hover:bg-gray-100'
              }`}
              title="Auto Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${autoRefresh ? 'animate-spin' : ''}`} />
            </button>
            
            <button
              onClick={() => setIsFullscreen(!isFullscreen)}
              className="p-2 rounded-md border border-gray-200 transition-colors bg-gray-50 text-gray-500 hover:bg-gray-100"
              title="Toggle Fullscreen"
            >
              <Maximize2 className="w-4 h-4" />
            </button>
            
            <button
              onClick={exportReport}
              className="p-2 rounded-md border border-gray-200 transition-colors bg-gray-50 text-gray-500 hover:bg-gray-100"
              title="Export Report"
            >
              <Download className="w-4 h-4" />
            </button>
            
            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              className="p-2 rounded-md border border-gray-200 transition-colors bg-gray-50 text-gray-500 hover:bg-gray-100"
              title="Toggle Theme"
            >
              {isDarkMode ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>
      </div>

      {/* Time Range Selector */}
      <div className="px-6 py-3 border-b border-gray-200">
        <div className="flex items-center gap-4">
          <span className="text-sm text-gray-600">Time Range:</span>
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value as any)}
            className="px-3 py-2 border border-gray-200 rounded-md bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="1h">Last Hour</option>
            <option value="6h">Last 6 Hours</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
        </div>
      </div>

      {/* Main Dashboard Grid */}
      <div className="p-6">
        <div className="grid grid-cols-12 gap-4 auto-rows-min">
          {/* Request Metrics */}
          <MetricCard
            title="REQUESTS/MIN"
            value={metrics.requests?.value || 0}
            change={metrics.requests?.change}
            changeType={metrics.requests?.changeType}
            icon={Zap}
            description="Real-time requests"
            isRealTime={true}
            status="success"
          />
          
          {/* Latency Metrics */}
          <MetricCard
            title="AVG LATENCY"
            value={`${metrics.latency?.value || 0}ms`}
            change={metrics.latency?.change}
            changeType={metrics.latency?.changeType}
            icon={Clock}
            description="Response time"
            isRealTime={true}
            status={metrics.latency?.value && metrics.latency?.value < 50 ? 'success' : metrics.latency?.value < 100 ? 'warning' : 'error'}
          />
          
          {/* Error Rate */}
          <MetricCard
            title="ERROR RATE"
            value={`${metrics.errorRate?.value || 0}%`}
            change={metrics.errorRate?.change}
            changeType={metrics.errorRate?.changeType}
            icon={AlertTriangle}
            description="Error percentage"
            isRealTime={true}
            status={metrics.errorRate?.value && metrics.errorRate?.value < 1 ? 'success' : metrics.errorRate?.value > 5 ? 'error' : 'warning'}
          />
          
          {/* CPU Usage */}
          <MetricCard
            title="CPU USAGE"
            value={`${metrics.cpuUsage?.value || 0}%`}
            change={metrics.cpuUsage?.change}
            changeType={metrics.cpuUsage?.changeType}
            icon={Cpu}
            description="System load"
            isRealTime={true}
            status={metrics.cpuUsage?.value && metrics.cpuUsage?.value < 80 ? 'success' : metrics.cpuUsage?.value > 90 ? 'error' : 'warning'}
            sparkline={true}
            minValue={0}
            maxValue={100}
            unit="%"
          />
          
          {/* Memory Usage */}
          <MetricCard
            title="MEMORY USAGE"
            value={`${metrics.memoryUsage?.value || 0}%`}
            change={metrics.memoryUsage?.change}
            changeType={metrics.memoryUsage?.changeType}
            icon={Database}
            description="RAM consumption"
            isRealTime={true}
            status={metrics.memoryUsage?.value && metrics.memoryUsage?.value < 85 ? 'success' : metrics.memoryUsage?.value > 95 ? 'error' : 'warning'}
            sparkline={true}
            minValue={0}
            maxValue={100}
            unit="%"
          />
          
          {/* Disk Usage */}
          <MetricCard
            title="DISK USAGE"
            value={`${metrics.diskUsage?.value || 0}%`}
            change={metrics.diskUsage?.change}
            changeType={metrics.diskUsage?.changeType}
            icon={HardDrive}
            description="Storage consumption"
            isRealTime={true}
            status={metrics.diskUsage?.value && metrics.diskUsage?.value < 90 ? 'success' : 'warning'}
            sparkline={true}
            minValue={0}
            maxValue={100}
            unit="%"
          />
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-12 gap-4 auto-rows-min">
          {/* Performance Chart */}
          <GrafanaChart
            title="Performance Overview"
            type="area"
            height={300}
            data={[]}
            timeRange={timeRange}
          />
          
          {/* Error Trends */}
          <GrafanaChart
            title="Error Trends"
            type="line"
            height={300}
            data={[]}
            timeRange={timeRange}
          />
          
          {/* System Resources */}
          <GrafanaChart
            title="System Resources"
            type="bar"
            height={300}
            data={[]}
            timeRange={timeRange}
          />
        </div>

        {/* Service Status */}
        <ServiceStatus services={endpoints.map(endpoint => ({
          name: endpoint.path.replace('/api/v1/', '').replace('/', ' ').toUpperCase(),
          status: endpoint.status as 'healthy' | 'warning' | 'critical' | 'unknown',
          requests: endpoint.requests,
          avgLatency: endpoint.avgLatency,
          errorRate: endpoint.errorRate
        }))} />

        {/* Top Endpoints */}
        <TopEndpoints endpoints={endpoints.map(endpoint => ({
          path: endpoint.path,
          method: endpoint.method,
          status: endpoint.status as 'healthy' | 'warning' | 'critical' | 'unknown',
          requests: endpoint.requests,
          avgLatency: endpoint.avgLatency,
          errorRate: endpoint.errorRate
        }))} />

        {/* Recent Logs */}
        <RecentLogs logs={logs} />

        {/* Security Alerts */}
        <SecurityAlerts alerts={securityAlerts.map(alert => ({
          ...alert,
          type: alert.type as 'info' | 'warning' | 'critical',
          severity: alert.severity as 'high' | 'medium' | 'low'
        }))} />
      </div>

      {/* Project Usage */}
      <ProjectUsage projects={endpoints.map(endpoint => ({
        id: endpoint.id,
        name: endpoint.path.replace('/api/v1/', '').replace('/', ' ').toUpperCase(),
        requests: endpoint.requests,
        storage: Math.random() * 100,
        bandwidth: Math.random() * 1000,
        users: Math.floor(Math.random() * 100)
      }))} />

      {/* Status Bar */}
      <div className="fixed bottom-0 left-0 right-0 bg-white border-t border-gray-200 px-6 py-2">
        <div className="flex items-center justify-between text-xs text-gray-600">
          <span>Dashboard v2.0</span>
          <span>•</span>
          <span>Auto-refresh: {autoRefresh ? 'ON' : 'OFF'}</span>
          <span>•</span>
          <span>Theme: {isDarkMode ? 'Dark' : 'Light'}</span>
          <span>•</span>
          <span>Endpoints: {endpoints.length}</span>
          <span>•</span>
          <span>Alerts: {securityAlerts.filter(a => !a.acknowledged).length}</span>
        </div>
      </div>
    </div>
  );
}