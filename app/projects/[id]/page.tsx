"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { useParams, useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  ArrowLeft,
  Settings,
  ExternalLink,
  Server,
  Activity,
  Clock,
  Users,
  Key,
  Shield,
  Database,
  Globe,
  CheckCircle,
  AlertTriangle,
  XCircle,
  TrendingUp,
  TrendingDown,
  Copy,
  RefreshCw,
} from "lucide-react";

// Mock project data - in real app, this would come from API
const mockProject = {
  id: "2",
  name: "Mobile App Backend",
  description: "Backend services for iOS and Android mobile applications",
  status: "warning" as const,
  environments: ["dev", "staging"] as const,
  services: [
    { name: "Grafana", status: "connected" as const, endpoint: "grafana.mobile.example.com" },
    { name: "Prometheus", status: "disconnected" as const },
    { name: "Vault", status: "connected" as const, endpoint: "vault.mobile.example.com" },
  ],
  lastActivity: "15 minutes ago",
  createdAt: "2024-02-20",
  tags: ["mobile", "backend", "api"],
  domains: ["api.mobile.example.com", "staging.mobile.example.com"],
  team: [
    { id: "1", name: "John Doe", email: "john@example.com", role: "owner", avatar: "/avatars/john.jpg" },
    { id: "2", name: "Jane Smith", email: "jane@example.com", role: "admin", avatar: "/avatars/jane.jpg" },
    { id: "3", name: "Bob Wilson", email: "bob@example.com", role: "developer", avatar: "/avatars/bob.jpg" },
  ],
  metrics: {
    requests24h: 15420,
    requests7d: 108500,
    avgLatency: 85,
    errorRate: 2.3,
    uptime: 99.7,
  },
  apiKeys: [
    { id: "1", name: "Production Key", prefix: "sk_live", lastUsed: "2 hours ago", permissions: ["read", "write"] },
    { id: "2", name: "Development Key", prefix: "sk_dev", lastUsed: "5 minutes ago", permissions: ["read", "write"] },
  ],
};

const statusConfig = {
  healthy: {
    icon: CheckCircle,
    color: "text-green-600",
    bgColor: "bg-green-100",
    borderColor: "border-green-200",
  },
  warning: {
    icon: AlertTriangle,
    color: "text-yellow-600",
    bgColor: "bg-yellow-100",
    borderColor: "border-yellow-200",
  },
  critical: {
    icon: XCircle,
    color: "text-red-600",
    bgColor: "bg-red-100",
    borderColor: "border-red-200",
  },
};

const environmentConfig = {
  dev: { color: "bg-blue-100 text-blue-700", label: "Development" },
  staging: { color: "bg-yellow-100 text-yellow-700", label: "Staging" },
  prod: { color: "bg-green-100 text-green-700", label: "Production" },
};

export default function ProjectOverviewPage() {
  const router = useRouter();
  const params = useParams();
  const [activeTab, setActiveTab] = useState("overview");
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 2000));
    setIsRefreshing(false);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    // Here you would show a toast notification
  };

  const containerVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.5,
        ease: "easeOut",
      },
    },
  };

  const tabVariants = {
    hidden: { opacity: 0, x: -10 },
    visible: {
      opacity: 1,
      x: 0,
      transition: {
        duration: 0.3,
        ease: "easeOut",
      },
    },
  };

  const tabs = [
    { id: "overview", label: "Overview", icon: Activity },
    { id: "environments", label: "Environments", icon: Server },
    { id: "services", label: "Services", icon: Database },
    { id: "api-keys", label: "API Keys", icon: Key },
    { id: "team", label: "Team", icon: Users },
    { id: "security", label: "Security", icon: Shield },
  ];

  return (
    <div className="min-h-full bg-gray-50 p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="mb-8"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => router.push("/projects")}
              className="hover:bg-gray-100"
            >
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Projects
            </Button>
            <div>
              <h1 className="text-3xl font-bold text-gray-900">{mockProject.name}</h1>
              <p className="text-gray-600">{mockProject.description}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleRefresh}
              disabled={isRefreshing}
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${isRefreshing ? 'animate-spin' : ''}`} />
              {isRefreshing ? 'Refreshing...' : 'Refresh'}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => router.push(`/projects/${params.id}/settings`)}
            >
              <Settings className="h-4 w-4 mr-2" />
              Settings
            </Button>
          </div>
        </div>
      </motion.div>

      {/* Status Bar */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
        className="mb-6"
      >
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2">
                  {React.createElement(statusConfig[mockProject.status].icon, {
                    className: `h-5 w-5 ${statusConfig[mockProject.status].color}`
                  })}
                  <span className={`text-sm font-medium ${statusConfig[mockProject.status].color}`}>
                    {mockProject.status.charAt(0).toUpperCase() + mockProject.status.slice(1)}
                  </span>
                </div>
                <div className="text-sm text-gray-500">
                  Project ID: {mockProject.id}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="secondary" className="text-xs">
                  Created {mockProject.createdAt}
                </Badge>
                <Badge variant="secondary" className="text-xs">
                  Last activity: {mockProject.lastActivity}
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Tabs */}
      <div className="flex space-x-1 border-b border-gray-200 mb-6">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? "border-blue-500 text-blue-600"
                  : "border-transparent text-gray-600 hover:text-gray-900"
              }`}
            >
              <Icon className="h-4 w-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab Content */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="space-y-6"
      >
        {/* Overview Tab */}
        {activeTab === "overview" && (
          <motion.div
            variants={tabVariants}
            className="grid grid-cols-1 lg:grid-cols-3 gap-6"
          >
            {/* Metrics Card */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle>Performance Metrics</CardTitle>
                <CardDescription>Last 24 hours</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-sm text-gray-600">API Requests</div>
                    <div className="text-2xl font-bold">{mockProject.metrics.requests24h.toLocaleString()}</div>
                    <div className="flex items-center gap-1 text-sm">
                      <TrendingUp className="h-4 w-4 text-green-600" />
                      <span className="text-green-600">+12.5%</span>
                    </div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-600">Avg Latency</div>
                    <div className="text-2xl font-bold">{mockProject.metrics.avgLatency}ms</div>
                    <div className="flex items-center gap-1 text-sm">
                      <TrendingDown className="h-4 w-4 text-green-600" />
                      <span className="text-green-600">-8.2%</span>
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-sm text-gray-600">Error Rate</div>
                    <div className="text-2xl font-bold">{mockProject.metrics.errorRate}%</div>
                    <div className="flex items-center gap-1 text-sm">
                      <TrendingDown className="h-4 w-4 text-green-600" />
                      <span className="text-green-600">-15.3%</span>
                    </div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-600">Uptime</div>
                    <div className="text-2xl font-bold">{mockProject.metrics.uptime}%</div>
                    <div className="flex items-center gap-1 text-sm">
                      <CheckCircle className="h-4 w-4 text-green-600" />
                      <span className="text-green-600">Stable</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Quick Actions Card */}
            <Card>
              <CardHeader>
                <CardTitle>Quick Actions</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <Button className="w-full justify-start" variant="outline">
                  <ExternalLink className="h-4 w-4 mr-2" />
                  Open Grafana Dashboard
                </Button>
                <Button className="w-full justify-start" variant="outline">
                  <Server className="h-4 w-4 mr-2" />
                  View Server Logs
                </Button>
                <Button className="w-full justify-start" variant="outline">
                  <Activity className="h-4 w-4 mr-2" />
                  View API Documentation
                </Button>
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* Environments Tab */}
        {activeTab === "environments" && (
          <motion.div
            variants={tabVariants}
            className="grid grid-cols-1 lg:grid-cols-2 gap-6"
          >
            {mockProject.environments.map((env) => (
              <Card key={env}>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <div className={`w-3 h-3 rounded-full ${
                      env === 'dev' ? 'bg-blue-500' :
                      env === 'staging' ? 'bg-yellow-500' : 'bg-green-500'
                    }`} />
                    {environmentConfig[env].label}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div>
                    <div className="text-sm text-gray-600">Endpoint</div>
                    <div className="font-mono text-sm">
                      {env === 'dev' ? 'dev-api.mobile.example.com' :
                       env === 'staging' ? 'staging-api.mobile.example.com' :
                       'api.mobile.example.com'}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-600">Status</div>
                    <Badge className={environmentConfig[env].color}>
                      Active
                    </Badge>
                  </div>
                  <div>
                    <div className="text-sm text-gray-600">Last Deploy</div>
                    <div className="text-sm">
                      {env === 'dev' ? '2 hours ago' :
                       env === 'staging' ? '1 day ago' : '3 days ago'}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </motion.div>
        )}

        {/* API Keys Tab */}
        {activeTab === "api-keys" && (
          <motion.div
            variants={tabVariants}
          >
            <Card>
              <CardHeader>
                <CardTitle>API Keys</CardTitle>
                <CardDescription>Manage your project's API keys</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {mockProject.apiKeys.map((key) => (
                    <div key={key.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                      <div>
                        <div className="font-medium">{key.name}</div>
                        <div className="text-sm text-gray-600">
                          {key.prefix}_••••••••••••••••••••••••
                        </div>
                        <div className="text-xs text-gray-500">
                          Last used: {key.lastUsed}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="secondary" className="text-xs">
                          {key.permissions.join(", ")}
                        </Badge>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(`${key.prefix}_mock_key_${key.id}`)}
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="pt-4 border-t border-gray-200">
                  <Button className="w-full">
                    Generate New API Key
                  </Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* Other tabs would have similar structure */}
        {activeTab !== "overview" && activeTab !== "environments" && activeTab !== "api-keys" && (
          <motion.div
            variants={tabVariants}
            className="text-center py-12"
          >
            <div className="text-gray-500 mb-4">
              {tabs.find(t => t.id === activeTab)?.icon && (
                <div className="flex justify-center mb-4">
                  {React.createElement(tabs.find(t => t.id === activeTab)!.icon, { className: "h-12 w-12 text-gray-400" })}
                </div>
              )}
            </div>
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              {tabs.find(t => t.id === activeTab)?.label}
            </h3>
            <p className="text-gray-600 mb-4">
              Configure {tabs.find(t => t.id === activeTab)?.label.toLowerCase()} for your project.
            </p>
            <p className="text-sm text-gray-500">
              This section is coming soon with more advanced configuration options.
            </p>
          </motion.div>
        )}
      </motion.div>
    </div>
  );
}