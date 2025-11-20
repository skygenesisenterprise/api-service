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
  Plus,
  Zap,
  BarChart3,
  Eye,
  Edit,
  Trash2,
  Star,
  MoreHorizontal,
} from "lucide-react";

// Mock project data
const mockProject = {
  id: "2",
  name: "Mobile App Backend",
  description: "Backend services for iOS and Android mobile applications with real-time synchronization and offline capabilities",
  status: "warning" as const,
  environments: ["dev", "staging"] as const,
  services: [
    { name: "Grafana", status: "connected" as const, endpoint: "grafana.mobile.example.com" },
    { name: "Prometheus", status: "disconnected" as const },
    { name: "Vault", status: "connected" as const, endpoint: "vault.mobile.example.com" },
    { name: "Redis", status: "connected" as const, endpoint: "redis.mobile.example.com" },
  ],
  lastActivity: "15 minutes ago",
  createdAt: "2024-02-20",
  tags: ["mobile", "backend", "api", "real-time"],
  domains: ["api.mobile.example.com", "staging.mobile.example.com"],
  team: [
    { id: "1", name: "John Doe", email: "john@example.com", role: "owner", avatar: "/avatars/john.jpg" },
    { id: "2", name: "Jane Smith", email: "jane@example.com", role: "admin", avatar: "/avatars/jane.jpg" },
    { id: "3", name: "Bob Wilson", email: "bob@example.com", role: "developer", avatar: "/avatars/bob.jpg" },
    { id: "4", name: "Alice Brown", email: "alice@example.com", role: "developer", avatar: "/avatars/alice.jpg" },
    { id: "5", name: "Charlie Davis", email: "charlie@example.com", role: "viewer", avatar: "/avatars/charlie.jpg" },
  ],
  metrics: {
    requests24h: 15420,
    requests7d: 108500,
    avgLatency: 85,
    errorRate: 2.3,
    uptime: 99.7,
    activeUsers: 1247,
    dataTransferred: "2.4 TB",
  },
  apiKeys: [
    { id: "1", name: "Production Key", prefix: "sk_live", lastUsed: "2 hours ago", permissions: ["read", "write"] },
    { id: "2", name: "Development Key", prefix: "sk_dev", lastUsed: "5 minutes ago", permissions: ["read", "write"] },
    { id: "3", name: "Read-only Key", prefix: "sk_read", lastUsed: "1 day ago", permissions: ["read"] },
  ],
  recentDeployments: [
    { id: "1", version: "v2.1.0", environment: "staging", status: "success", timestamp: "2 hours ago", author: "Jane Smith" },
    { id: "2", version: "v2.0.8", environment: "production", status: "success", timestamp: "1 day ago", author: "John Doe" },
    { id: "3", version: "v2.0.7", environment: "staging", status: "failed", timestamp: "2 days ago", author: "Bob Wilson" },
  ],
};

const statusConfig = {
  healthy: {
    icon: CheckCircle,
    color: "text-emerald-600",
    bgColor: "bg-emerald-50",
    borderColor: "border-emerald-200",
    label: "Healthy",
  },
  warning: {
    icon: AlertTriangle,
    color: "text-amber-600",
    bgColor: "bg-amber-50",
    borderColor: "border-amber-200",
    label: "Warning",
  },
  critical: {
    icon: XCircle,
    color: "text-red-600",
    bgColor: "bg-red-50",
    borderColor: "border-red-200",
    label: "Critical",
  },
};

const environmentConfig = {
  dev: { color: "bg-blue-100 text-blue-700", label: "Development", icon: Database },
  staging: { color: "bg-yellow-100 text-yellow-700", label: "Staging", icon: Zap },
  prod: { color: "bg-green-100 text-green-700", label: "Production", icon: Shield },
};

export default function ProjectOverviewPage() {
  const router = useRouter();
  const params = useParams();
  const [activeTab, setActiveTab] = useState("overview");
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [starred, setStarred] = useState(false);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await new Promise(resolve => setTimeout(resolve, 2000));
    setIsRefreshing(false);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    // Would show toast in real app
  };

  const tabs = [
    { id: "overview", label: "Overview", icon: BarChart3 },
    { id: "services", label: "Services", icon: Server },
    { id: "api-keys", label: "API Keys", icon: Key },
    { id: "team", label: "Team", icon: Users },
    { id: "deployments", label: "Deployments", icon: Activity },
  ];

  return (
    <div className="min-h-full bg-gray-50">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="bg-white border-b border-gray-200"
      >
        <div className="px-6 py-4">
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
              <div className="flex items-center gap-3">
                <div className="p-3 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl">
                  <Server className="h-6 w-6 text-white" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h1 className="text-2xl font-bold text-gray-900">{mockProject.name}</h1>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setStarred(!starred)}
                      className="h-8 w-8 p-0"
                    >
                      <Star className={`h-4 w-4 ${starred ? 'fill-yellow-400 text-yellow-400' : 'text-gray-400'}`} />
                    </Button>
                  </div>
                  <p className="text-gray-600 mt-1">{mockProject.description}</p>
                </div>
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
        </div>
      </motion.div>

      {/* Status Bar */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
        className="bg-white border-b border-gray-100"
      >
        <div className="px-6 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                {React.createElement(statusConfig[mockProject.status].icon, {
                  className: `h-5 w-5 ${statusConfig[mockProject.status].color}`
                })}
                <span className={`text-sm font-medium ${statusConfig[mockProject.status].color}`}>
                  {statusConfig[mockProject.status].label}
                </span>
              </div>
              <div className="text-sm text-gray-500">
                Project ID: {mockProject.id}
              </div>
              <div className="flex gap-1">
                {mockProject.environments.map((env) => (
                  <Badge
                    key={env}
                    variant="secondary"
                    className={`text-xs ${environmentConfig[env].color}`}
                  >
                    {environmentConfig[env].label}
                  </Badge>
                ))}
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
        </div>
      </motion.div>

      {/* Tabs */}
      <div className="bg-white border-b border-gray-200">
        <div className="px-6">
          <div className="flex space-x-8">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 py-4 border-b-2 text-sm font-medium transition-colors ${
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
        </div>
      </div>

      {/* Tab Content */}
      <div className="p-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          {/* Overview Tab */}
          {activeTab === "overview" && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Metrics Card */}
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle>Performance Metrics</CardTitle>
                  <CardDescription>Last 24 hours</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div>
                      <div className="text-sm text-gray-600">API Requests</div>
                      <div className="text-2xl font-bold text-gray-900">{mockProject.metrics.requests24h.toLocaleString()}</div>
                      <div className="flex items-center gap-1 text-sm">
                        <TrendingUp className="h-4 w-4 text-emerald-600" />
                        <span className="text-emerald-600">+12.5%</span>
                      </div>
                    </div>
                    <div>
                      <div className="text-sm text-gray-600">Avg Latency</div>
                      <div className="text-2xl font-bold text-gray-900">{mockProject.metrics.avgLatency}ms</div>
                      <div className="flex items-center gap-1 text-sm">
                        <TrendingDown className="h-4 w-4 text-emerald-600" />
                        <span className="text-emerald-600">-8.2%</span>
                      </div>
                    </div>
                    <div>
                      <div className="text-sm text-gray-600">Error Rate</div>
                      <div className="text-2xl font-bold text-gray-900">{mockProject.metrics.errorRate}%</div>
                      <div className="flex items-center gap-1 text-sm">
                        <TrendingDown className="h-4 w-4 text-emerald-600" />
                        <span className="text-emerald-600">-15.3%</span>
                      </div>
                    </div>
                    <div>
                      <div className="text-sm text-gray-600">Uptime</div>
                      <div className="text-2xl font-bold text-gray-900">{mockProject.metrics.uptime}%</div>
                      <div className="flex items-center gap-1 text-sm">
                        <CheckCircle className="h-4 w-4 text-emerald-600" />
                        <span className="text-emerald-600">Stable</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4 pt-4 border-t border-gray-100">
                    <div>
                      <div className="text-sm text-gray-600">Active Users</div>
                      <div className="text-xl font-bold text-gray-900">{mockProject.metrics.activeUsers.toLocaleString()}</div>
                    </div>
                    <div>
                      <div className="text-sm text-gray-600">Data Transferred</div>
                      <div className="text-xl font-bold text-gray-900">{mockProject.metrics.dataTransferred}</div>
                    </div>
                    <div>
                      <div className="text-sm text-gray-600">7-day Requests</div>
                      <div className="text-xl font-bold text-gray-900">{mockProject.metrics.requests7d.toLocaleString()}</div>
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
                  <Button className="w-full justify-start" variant="outline">
                    <Plus className="h-4 w-4 mr-2" />
                    Generate API Key
                  </Button>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Services Tab */}
          {activeTab === "services" && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {mockProject.services.map((service) => (
                <Card key={service.name}>
                  <CardHeader>
                    <CardTitle className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Server className="h-5 w-5 text-gray-600" />
                        {service.name}
                      </div>
                      <Badge className={
                        service.status === "connected" 
                          ? "bg-emerald-100 text-emerald-700" 
                          : "bg-red-100 text-red-700"
                      }>
                        {service.status === "connected" ? "Connected" : "Disconnected"}
                      </Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {service.endpoint && (
                      <div>
                        <div className="text-sm text-gray-600">Endpoint</div>
                        <div className="font-mono text-sm bg-gray-50 p-2 rounded border">
                          {service.endpoint}
                        </div>
                      </div>
                    )}
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" className="flex-1">
                        <Eye className="h-4 w-4 mr-1" />
                        View
                      </Button>
                      <Button variant="outline" size="sm" className="flex-1">
                        <Settings className="h-4 w-4 mr-1" />
                        Configure
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {/* API Keys Tab */}
          {activeTab === "api-keys" && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>API Keys</CardTitle>
                    <CardDescription>Manage your project's API keys</CardDescription>
                  </div>
                  <Button>
                    <Plus className="h-4 w-4 mr-2" />
                    Generate New Key
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {mockProject.apiKeys.map((key) => (
                    <div key={key.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                      <div className="flex-1">
                        <div className="font-medium">{key.name}</div>
                        <div className="font-mono text-sm text-gray-600 bg-gray-50 p-2 rounded border inline-block mt-1">
                          {key.prefix}_••••••••••••••••••••••
                        </div>
                        <div className="text-xs text-gray-500 mt-1">
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
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem>
                              <Edit className="h-4 w-4 mr-2" />
                              Edit
                            </DropdownMenuItem>
                            <DropdownMenuItem className="text-red-600">
                              <Trash2 className="h-4 w-4 mr-2" />
                              Revoke
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Team Tab */}
          {activeTab === "team" && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Team Members</CardTitle>
                    <CardDescription>{mockProject.team.length} members</CardDescription>
                  </div>
                  <Button>
                    <Plus className="h-4 w-4 mr-2" />
                    Invite Member
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {mockProject.team.map((member) => (
                    <div key={member.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center text-white font-semibold">
                          {member.name.split(' ').map(n => n[0]).join('').toUpperCase()}
                        </div>
                        <div>
                          <div className="font-medium">{member.name}</div>
                          <div className="text-sm text-gray-600">{member.email}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="secondary" className="capitalize">
                          {member.role}
                        </Badge>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem>
                              <Edit className="h-4 w-4 mr-2" />
                              Edit Role
                            </DropdownMenuItem>
                            <DropdownMenuItem className="text-red-600">
                              <Trash2 className="h-4 w-4 mr-2" />
                              Remove
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Deployments Tab */}
          {activeTab === "deployments" && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Recent Deployments</CardTitle>
                    <CardDescription>Latest deployment activity</CardDescription>
                  </div>
                  <Button variant="outline">
                    <Activity className="h-4 w-4 mr-2" />
                    View All
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {mockProject.recentDeployments.map((deployment) => (
                    <div key={deployment.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                      <div className="flex items-center gap-3">
                        <div className={`w-2 h-2 rounded-full ${
                          deployment.status === 'success' ? 'bg-emerald-500' : 'bg-red-500'
                        }`} />
                        <div>
                          <div className="font-medium">{deployment.version}</div>
                          <div className="text-sm text-gray-600">
                            {deployment.environment} • {deployment.author} • {deployment.timestamp}
                          </div>
                        </div>
                      </div>
                      <Badge className={
                        deployment.status === 'success' 
                          ? "bg-emerald-100 text-emerald-700" 
                          : "bg-red-100 text-red-700"
                      }>
                        {deployment.status === 'success' ? 'Success' : 'Failed'}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </motion.div>
      </div>
    </div>
  );
}