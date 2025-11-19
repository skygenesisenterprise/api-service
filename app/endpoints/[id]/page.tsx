"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { useParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ArrowLeft,
  Clock,
  Activity,
  Zap,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Server,
  Shield,
  Copy,
  ExternalLink,
  Trash2,
  Settings,
  Play,
  Code,
  FileText,
  BarChart3,
  Users,
  Globe,
  Key,
  TrendingUp,
  TrendingDown,
} from "lucide-react";
import { mockEndpoints, mockEndpointCalls } from "@/data/mockEndpoints";
import { Endpoint, EndpointSchema } from "@/types/endpoint";

const methodConfig = {
  GET: { color: "bg-green-100 text-green-700", label: "GET" },
  POST: { color: "bg-blue-100 text-blue-700", label: "POST" },
  PUT: { color: "bg-yellow-100 text-yellow-700", label: "PUT" },
  DELETE: { color: "bg-red-100 text-red-700", label: "DELETE" },
  PATCH: { color: "bg-purple-100 text-purple-700", label: "PATCH" },
  HEAD: { color: "bg-gray-100 text-gray-700", label: "HEAD" },
  OPTIONS: { color: "bg-indigo-100 text-indigo-700", label: "OPTIONS" },
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

const mockSchema: EndpointSchema = {
  parameters: [
    {
      name: "id",
      type: "string",
      required: true,
      description: "Unique identifier for the project",
    },
  ],
  query: [
    {
      name: "include",
      type: "string",
      required: false,
      description: "Comma-separated list of related resources to include",
    },
    {
      name: "page",
      type: "number",
      required: false,
      description: "Page number for pagination",
    },
    {
      name: "limit",
      type: "number",
      required: false,
      description: "Number of items per page",
    },
  ],
  response: {
    200: {
      type: "object",
      schema: {
        type: "object",
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          description: { type: "string" },
          status: { type: "string" },
          createdAt: { type: "string" },
          updatedAt: { type: "string" },
        },
      },
      example: {
        id: "proj_123",
        name: "E-commerce Platform",
        description: "Production e-commerce platform",
        status: "active",
        createdAt: "2024-01-15T10:00:00Z",
        updatedAt: "2024-11-18T15:30:00Z",
      },
    },
    404: {
      type: "object",
      schema: {
        type: "object",
        properties: {
          error: { type: "string" },
          message: { type: "string" },
        },
      },
      example: {
        error: "Not Found",
        message: "Project with ID 'proj_123' not found",
      },
    },
  },
};

export default function EndpointDetailPage() {
  const params = useParams();
  const endpointId = params.id as string;
  const [endpoint] = useState<Endpoint | undefined>(
    mockEndpoints.find(ep => ep.id === endpointId)
  );
  const [calls] = useState(mockEndpointCalls.filter(call => call.endpointId === endpointId));

  if (!endpoint) {
    return (
      <div className="min-h-full bg-gray-50 p-6">
        <div className="text-center py-12">
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Endpoint not found</h2>
          <p className="text-gray-600">The endpoint you're looking for doesn't exist.</p>
        </div>
      </div>
    );
  }

  const methodStyle = methodConfig[endpoint.method];
  const StatusIcon = statusConfig[endpoint.status].icon;

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
      },
    },
  };

  const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.3,
      },
    },
  };

  return (
    <div className="min-h-full bg-gray-50 p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="mb-8"
      >
        <div className="flex items-center gap-4 mb-4">
          <Button 
            variant="ghost" 
            size="sm"
            onClick={() => window.history.back()}
            className="gap-2"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Endpoints
          </Button>
        </div>

        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-center gap-4">
            <Badge className={methodStyle.color}>
              {methodStyle.label}
            </Badge>
            <div>
              <h1 className="text-3xl font-bold text-gray-900">{endpoint.route}</h1>
              <p className="text-gray-600 mt-1">{endpoint.description}</p>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <Button variant="outline" className="gap-2">
              <Play className="h-4 w-4" />
              Test Endpoint
            </Button>
            <Button variant="outline" className="gap-2">
              <Copy className="h-4 w-4" />
              Copy Route
            </Button>
            <Button variant="outline" className="gap-2">
              <Settings className="h-4 w-4" />
              Settings
            </Button>
            <Button variant="destructive" className="gap-2">
              <Trash2 className="h-4 w-4" />
              Delete
            </Button>
          </div>
        </div>

        {/* Status and Meta Info */}
        <div className="flex flex-wrap items-center gap-4 mt-6">
          <div className="flex items-center gap-2">
            <StatusIcon className={`h-4 w-4 ${statusConfig[endpoint.status].color}`} />
            <span className={`text-sm font-medium ${statusConfig[endpoint.status].color}`}>
              {endpoint.status.charAt(0).toUpperCase() + endpoint.status.slice(1)}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-gray-400" />
            <span className="text-sm text-gray-600">{endpoint.service}</span>
          </div>
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-gray-400" />
            <span className="text-sm text-gray-600">v{endpoint.version}</span>
          </div>
          {endpoint.deprecated && (
            <Badge variant="destructive">Deprecated</Badge>
          )}
        </div>
      </motion.div>

      {/* Metrics Cards */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8"
      >
        <motion.div variants={cardVariants}>
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Avg Latency</p>
                  <p className="text-2xl font-bold text-gray-900">{endpoint.latency.avg}ms</p>
                  <p className="text-xs text-gray-500">P95: {endpoint.latency.p95}ms</p>
                </div>
                <div className="p-3 bg-blue-100 rounded-lg">
                  <Zap className="h-6 w-6 text-blue-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={cardVariants}>
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Error Rate</p>
                  <p className="text-2xl font-bold text-gray-900">{endpoint.errorRate}%</p>
                  <p className="text-xs text-gray-500">Last 24 hours</p>
                </div>
                <div className="p-3 bg-yellow-100 rounded-lg">
                  <AlertTriangle className="h-6 w-6 text-yellow-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={cardVariants}>
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Requests Today</p>
                  <p className="text-2xl font-bold text-gray-900">{endpoint.requestsToday.toLocaleString()}</p>
                  <p className="text-xs text-gray-500">+12% from yesterday</p>
                </div>
                <div className="p-3 bg-green-100 rounded-lg">
                  <TrendingUp className="h-6 w-6 text-green-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={cardVariants}>
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Uptime</p>
                  <p className="text-2xl font-bold text-gray-900">{endpoint.uptime}%</p>
                  <p className="text-xs text-gray-500">Last 30 days</p>
                </div>
                <div className="p-3 bg-purple-100 rounded-lg">
                  <Activity className="h-6 w-6 text-purple-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>

      {/* Tabs */}
      <Tabs defaultValue="schema" className="space-y-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="schema" className="gap-2">
            <Code className="h-4 w-4" />
            Schema
          </TabsTrigger>
          <TabsTrigger value="security" className="gap-2">
            <Shield className="h-4 w-4" />
            Security
          </TabsTrigger>
          <TabsTrigger value="logs" className="gap-2">
            <FileText className="h-4 w-4" />
            Logs
          </TabsTrigger>
          <TabsTrigger value="analytics" className="gap-2">
            <BarChart3 className="h-4 w-4" />
            Analytics
          </TabsTrigger>
        </TabsList>

        {/* Schema Tab */}
        <TabsContent value="schema">
          <Card>
            <CardHeader>
              <CardTitle>API Schema</CardTitle>
              <CardDescription>
                Request and response structure for this endpoint
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Parameters */}
              {mockSchema.parameters && mockSchema.parameters.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-900 mb-3">Path Parameters</h4>
                  <div className="space-y-2">
                    {mockSchema.parameters.map((param) => (
                      <div key={param.name} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div className="flex items-center gap-3">
                          <Badge variant={param.required ? "default" : "secondary"}>
                            {param.name}
                          </Badge>
                          <span className="text-sm text-gray-600">{param.type}</span>
                          <span className="text-sm text-gray-500">{param.description}</span>
                        </div>
                        {param.required && (
                          <Badge variant="destructive" className="text-xs">Required</Badge>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Query Parameters */}
              {mockSchema.query && mockSchema.query.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-900 mb-3">Query Parameters</h4>
                  <div className="space-y-2">
                    {mockSchema.query.map((param) => (
                      <div key={param.name} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div className="flex items-center gap-3">
                          <Badge variant={param.required ? "default" : "secondary"}>
                            {param.name}
                          </Badge>
                          <span className="text-sm text-gray-600">{param.type}</span>
                          <span className="text-sm text-gray-500">{param.description}</span>
                        </div>
                        {param.required && (
                          <Badge variant="destructive" className="text-xs">Required</Badge>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Response Examples */}
              <div>
                <h4 className="text-sm font-semibold text-gray-900 mb-3">Response Examples</h4>
                <div className="space-y-4">
                  {Object.entries(mockSchema.response || {}).map(([statusCode, response]) => (
                    <div key={statusCode} className="border rounded-lg">
                      <div className="flex items-center justify-between p-3 bg-gray-50 border-b">
                        <div className="flex items-center gap-2">
                          <Badge 
                            variant={statusCode.startsWith('2') ? "default" : "destructive"}
                          >
                            {statusCode}
                          </Badge>
                          <span className="text-sm font-medium">{response.type}</span>
                        </div>
                      </div>
                      <div className="p-3">
                        <pre className="text-xs bg-gray-900 text-gray-100 p-3 rounded overflow-x-auto">
                          {JSON.stringify(response.example, null, 2)}
                        </pre>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security">
          <Card>
            <CardHeader>
              <CardTitle>Security & Permissions</CardTitle>
              <CardDescription>
                Authentication requirements and rate limiting
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Required Scopes */}
              <div>
                <h4 className="text-sm font-semibold text-gray-900 mb-3">Required Scopes</h4>
                <div className="flex flex-wrap gap-2">
                  {endpoint.scopes.map((scope) => (
                    <Badge key={scope} variant="outline" className="gap-1">
                      <Key className="h-3 w-3" />
                      {scope}
                    </Badge>
                  ))}
                </div>
              </div>

              {/* Rate Limiting */}
              <div>
                <h4 className="text-sm font-semibold text-gray-900 mb-3">Rate Limiting</h4>
                <div className="p-4 bg-gray-50 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        {endpoint.rateLimit.requests} requests per {endpoint.rateLimit.window}
                      </p>
                      <p className="text-xs text-gray-500">Per API key</p>
                    </div>
                    <Clock className="h-5 w-5 text-gray-400" />
                  </div>
                </div>
              </div>

              {/* Allowed Applications */}
              <div>
                <h4 className="text-sm font-semibold text-gray-900 mb-3">Allowed Applications</h4>
                <div className="space-y-2">
                  <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex items-center gap-3">
                      <Users className="h-4 w-4 text-gray-400" />
                      <span className="text-sm font-medium">Web Dashboard</span>
                    </div>
                    <Badge variant="default">Active</Badge>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex items-center gap-3">
                      <Users className="h-4 w-4 text-gray-400" />
                      <span className="text-sm font-medium">Mobile App</span>
                    </div>
                    <Badge variant="default">Active</Badge>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex items-center gap-3">
                      <Users className="h-4 w-4 text-gray-400" />
                      <span className="text-sm font-medium">CLI Tool</span>
                    </div>
                    <Badge variant="default">Active</Badge>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Logs Tab */}
        <TabsContent value="logs">
          <Card>
            <CardHeader>
              <CardTitle>Recent Calls</CardTitle>
              <CardDescription>
                Latest API calls to this endpoint
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {calls.map((call) => (
                  <div key={call.id} className="border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <Badge 
                          variant={call.statusCode < 400 ? "default" : "destructive"}
                        >
                          {call.statusCode}
                        </Badge>
                        <span className="text-sm font-medium">{call.application}</span>
                        {call.userId && (
                          <span className="text-xs text-gray-500">User: {call.userId}</span>
                        )}
                      </div>
                      <div className="flex items-center gap-4 text-xs text-gray-500">
                        <span>{call.latency}ms</span>
                        <span>{new Date(call.timestamp).toLocaleString()}</span>
                      </div>
                    </div>
                    {call.errorMessage && (
                      <div className="mt-2 p-2 bg-red-50 border border-red-200 rounded text-sm text-red-700">
                        {call.errorMessage}
                      </div>
                    )}
                    {call.userAgent && (
                      <div className="mt-2 text-xs text-gray-500">
                        {call.userAgent} • {call.ip}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Analytics Tab */}
        <TabsContent value="analytics">
          <Card>
            <CardHeader>
              <CardTitle>Performance Analytics</CardTitle>
              <CardDescription>
                Detailed metrics and trends
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12">
                <BarChart3 className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">Analytics Dashboard</h3>
                <p className="text-gray-600">
                  Performance graphs and detailed analytics will be available here.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}