"use client";

import { useState } from "react";
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
  HardDrive
} from "lucide-react";

import { MetricCard } from "../components/dashboard/MetricCard";
import { ServiceStatus } from "../components/dashboard/ServiceStatus";
import { DashboardChart } from "../components/dashboard/DashboardChart";
import { TopEndpoints } from "../components/dashboard/TopEndpoints";
import { RecentLogs } from "../components/dashboard/RecentLogs";
import { SecurityAlerts } from "../components/dashboard/SecurityAlerts";
import { ProjectUsage } from "../components/dashboard/ProjectUsage";

// Mock data
const mockChartData = [
  { name: "00:00", requests: 120, latency: 45, errors: 2 },
  { name: "04:00", requests: 98, latency: 52, errors: 1 },
  { name: "08:00", requests: 280, latency: 38, errors: 3 },
  { name: "12:00", requests: 450, latency: 42, errors: 5 },
  { name: "16:00", requests: 380, latency: 48, errors: 2 },
  { name: "20:00", requests: 220, latency: 55, errors: 1 },
  { name: "23:59", requests: 150, latency: 50, errors: 0 },
];

const mockEndpoints = [
  { path: "/api/v1/users", method: "GET", requests: 15420, percentage: 35, avgLatency: 42 },
  { path: "/api/v1/auth/login", method: "POST", requests: 12380, percentage: 28, avgLatency: 38 },
  { path: "/api/v1/projects", method: "GET", requests: 8760, percentage: 20, avgLatency: 45 },
  { path: "/api/v1/data", method: "POST", requests: 6570, percentage: 15, avgLatency: 52 },
  { path: "/api/v1/monitoring", method: "GET", requests: 870, percentage: 2, avgLatency: 35 },
];

const mockLogs = [
  { id: "1", level: "error" as const, message: "Database connection timeout", timestamp: "2 min ago", source: "api-service" },
  { id: "2", level: "warning" as const, message: "High memory usage detected", timestamp: "5 min ago", source: "monitoring" },
  { id: "3", level: "info" as const, message: "New user registration", timestamp: "12 min ago", source: "auth-service" },
  { id: "4", level: "error" as const, message: "Failed to process webhook", timestamp: "18 min ago", source: "webhook-service" },
  { id: "5", level: "warning" as const, message: "Rate limit exceeded for IP 192.168.1.100", timestamp: "25 min ago", source: "api-gateway" },
];

const mockSecurityAlerts = [
  { id: "1", type: "failed_login" as const, message: "Multiple failed login attempts", severity: "high" as const, timestamp: "1 min ago", user: "admin@example.com", ip: "192.168.1.100" },
  { id: "2", type: "suspicious_activity" as const, message: "Unusual API usage pattern detected", severity: "medium" as const, timestamp: "8 min ago", user: "user123", ip: "10.0.0.50" },
  { id: "3", type: "api_key_abuse" as const, message: "API key rate limit exceeded", severity: "low" as const, timestamp: "15 min ago", ip: "172.16.0.10" },
  { id: "4", type: "permission_change" as const, message: "Admin privileges modified", severity: "critical" as const, timestamp: "32 min ago", user: "superadmin" },
];

const mockProjectUsage = [
  { name: "E-commerce Platform", requests: 15420, percentage: 35, color: "#3b82f6" },
  { name: "Mobile App Backend", requests: 12380, percentage: 28, color: "#10b981" },
  { name: "Analytics Service", requests: 8760, percentage: 20, color: "#f59e0b" },
  { name: "Admin Dashboard", requests: 6570, percentage: 15, color: "#8b5cf6" },
  { name: "API Gateway", requests: 870, percentage: 2, color: "#ef4444" },
];

export default function DashboardPage() {
  const [timeRange, setTimeRange] = useState<"24h" | "7d" | "30d">("24h");

  return (
    <div className="space-y-6 min-h-full w-full">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Dashboard</h1>
          <p className="text-gray-400 mt-1">Monitor your system performance and security</p>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-4 py-2 text-sm bg-gray-800 border border-gray-700 text-gray-300 rounded-lg hover:bg-gray-700 transition-colors">
            Export Report
          </button>
          <button className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
            Refresh Data
          </button>
        </div>
      </div>

      {/* KPI Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 w-full">
        <MetricCard
          title="Requests/min"
          value="1,247"
          change={12.5}
          changeType="increase"
          icon={Zap}
          description="Real-time requests"
          status="success"
        />
        <MetricCard
          title="Avg Latency"
          value="45ms"
          change={-8.2}
          changeType="increase"
          icon={Clock}
          description="Response time"
          status="success"
        />
        <MetricCard
          title="Error Rate"
          value="0.8%"
          change={-15.3}
          changeType="increase"
          icon={TrendingUp}
          description="Last 24 hours"
          status="warning"
        />
        <MetricCard
          title="CPU Usage"
          value="42%"
          change={5.1}
          changeType="decrease"
          icon={Cpu}
          description="System load"
          status="info"
        />
      </div>

      {/* Service Health Status */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        <div className="lg:col-span-1">
          <h3 className="text-sm font-medium text-gray-900 mb-3">Service Health</h3>
          <div className="space-y-2">
            <ServiceStatus
              name="API Gateway"
              status="healthy"
              latency={42}
              load={35}
              icon={Server}
            />
            <ServiceStatus
              name="Auth Service"
              status="healthy"
              latency={28}
              load={22}
              icon={Shield}
            />
            <ServiceStatus
              name="Database"
              status="warning"
              latency={85}
              load={78}
              icon={Database}
            />
            <ServiceStatus
              name="Queue"
              status="healthy"
              latency={15}
              load={12}
              icon={MessageSquare}
            />
            <ServiceStatus
              name="Realtime Gateway"
              status="healthy"
              latency={8}
              load={5}
              icon={Wifi}
            />
          </div>
        </div>

        {/* Main Chart */}
        <div className="lg:col-span-4">
          <DashboardChart 
            data={mockChartData} 
            timeRange={timeRange}
            onTimeRangeChange={setTimeRange}
          />
        </div>
      </div>

      {/* Second Row - Top Endpoints and Project Usage */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TopEndpoints endpoints={mockEndpoints} />
        <ProjectUsage data={mockProjectUsage} />
      </div>

      {/* Third Row - Logs and Security Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RecentLogs logs={mockLogs} />
        <SecurityAlerts alerts={mockSecurityAlerts} />
      </div>

      {/* System Resources */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <MetricCard
          title="Memory Usage"
          value="6.2 GB"
          change={2.1}
          changeType="increase"
          icon={HardDrive}
          description="of 16 GB total"
          status="warning"
        />
        <MetricCard
          title="Active Users"
          value="2,847"
          change={18.7}
          changeType="increase"
          icon={Users}
          description="Currently online"
          status="success"
        />
        <MetricCard
          title="Uptime"
          value="99.9%"
          change={0.1}
          changeType="increase"
          icon={Activity}
          description="Last 30 days"
          status="success"
        />
      </div>
    </div>
  );
}