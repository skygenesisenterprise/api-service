"use client";

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { 
  Activity, 
  AlertTriangle, 
  TrendingUp, 
  TrendingDown, 
  Clock, 
  Zap, 
  Server, 
  Globe,
  Filter,
  Download,
  Play,
  Pause,
  Search,
  Calendar,
  BarChart3,
  LineChart,
  Shield,
  Bug,
  Timer,
  Cpu,
  Database,
  Wifi,
  CheckCircle,
  XCircle,
  AlertCircle
} from 'lucide-react';

// Types
interface RequestData {
  id: string;
  timestamp: Date;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  endpoint: string;
  statusCode: number;
  latency: number;
  project: string;
  service: string;
  ip: string;
  userAgent: string;
  correlationId: string;
  tags: string[];
  spans?: SpanData[];
  requestData?: RequestDetails;
  responseData?: ResponseDetails;
}

interface SpanData {
  name: string;
  duration: number;
  startTime: number;
  color: string;
}

interface RequestDetails {
  headers: Record<string, string>;
  queryParams: Record<string, string>;
  body: any;
}

interface ResponseDetails {
  headers: Record<string, string>;
  payload: any;
  size: number;
  duration: number;
}

interface AnalyticsData {
  rps: number;
  errorRate: number;
  avgLatency: number;
  p90Latency: number;
  p95Latency: number;
  p99Latency: number;
  topEndpoint: string;
  failingEndpoint: string;
}

// Mock data generator
const generateMockRequests = (): RequestData[] => {
  const methods: Array<'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH'> = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
  const endpoints = ['/api/v1/users', '/api/v1/auth', '/api/v1/projects', '/api/v1/endpoints', '/api/v1/logs'];
  const projects = ['main', 'staging', 'dev'];
  const services = ['auth-service', 'user-service', 'project-service', 'api-gateway'];
  const statusCodes = [200, 201, 400, 401, 404, 500, 502];
  const tags = ['internal', 'external', 'admin', 'mobile', 'web', 'api'];

  return Array.from({ length: 100 }, (_, i) => {
    const statusCode = statusCodes[Math.floor(Math.random() * statusCodes.length)];
    const latency = Math.floor(Math.random() * 1000) + 50;
    const uniqueId = `req-${Date.now()}-${i}-${Math.random().toString(36).substr(2, 9)}`;
    
    return {
      id: uniqueId,
      timestamp: new Date(Date.now() - Math.floor(Math.random() * 3600000)),
      method: methods[Math.floor(Math.random() * methods.length)],
      endpoint: endpoints[Math.floor(Math.random() * endpoints.length)],
      statusCode,
      latency,
      project: projects[Math.floor(Math.random() * projects.length)],
      service: services[Math.floor(Math.random() * services.length)],
      ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
      userAgent: 'Mozilla/5.0 (compatible; API-Client/1.0)',
      correlationId: `corr-${Math.random().toString(36).substr(2, 9)}`,
      tags: Array.from({ length: Math.floor(Math.random() * 3) + 1 }, () => 
        tags[Math.floor(Math.random() * tags.length)]
      ),
      spans: [
        { name: 'DNS Resolution', duration: Math.floor(Math.random() * 50) + 10, startTime: 0, color: '#3b82f6' },
        { name: 'TCP Connect', duration: Math.floor(Math.random() * 100) + 20, startTime: 50, color: '#10b981' },
        { name: 'TLS Handshake', duration: Math.floor(Math.random() * 150) + 30, startTime: 150, color: '#f59e0b' },
        { name: 'Auth', duration: Math.floor(Math.random() * 80) + 15, startTime: 300, color: '#8b5cf6' },
        { name: 'Database', duration: Math.floor(Math.random() * 200) + 50, startTime: 380, color: '#ef4444' },
        { name: 'Response', duration: Math.floor(Math.random() * 100) + 20, startTime: 580, color: '#06b6d4' },
      ],
      requestData: {
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ***' },
        queryParams: { 'limit': '10', 'offset': '0' },
        body: { test: 'data' }
      },
      responseData: {
        headers: { 'Content-Type': 'application/json' },
        payload: { success: true, data: [] },
        size: Math.floor(Math.random() * 10000) + 1000,
        duration: latency
      }
    };
  });
};

// Metric Card Component
const MetricCard = ({ 
  title, 
  value, 
  trend, 
  trendValue, 
  icon: Icon, 
  color = "blue" 
}: {
  title: string;
  value: string | number;
  trend: 'up' | 'down' | 'neutral';
  trendValue?: string;
  icon: any;
  color?: string;
}) => {
  const colorClasses = {
    blue: 'text-blue-600 bg-blue-50 border-blue-200',
    green: 'text-green-600 bg-green-50 border-green-200',
    red: 'text-red-600 bg-red-50 border-red-200',
    yellow: 'text-yellow-600 bg-yellow-50 border-yellow-200',
    purple: 'text-purple-600 bg-purple-50 border-purple-200',
  };

  return (
    <Card className="hover:shadow-md transition-shadow">
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-lg ${colorClasses[color as keyof typeof colorClasses]}`}>
              <Icon className="h-5 w-5" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">{title}</p>
              <p className="text-2xl font-bold text-gray-900">{value}</p>
            </div>
          </div>
          {trend !== 'neutral' && (
            <div className={`flex items-center space-x-1 text-sm ${
              trend === 'up' ? 'text-green-600' : 'text-red-600'
            }`}>
              {trend === 'up' ? <TrendingUp className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
              <span>{trendValue}</span>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

// Timeline Chart Component
const TimelineChart = ({ data }: { data: RequestData[] }) => {
  const [isLive, setIsLive] = useState(true);
  
  // Group requests by time buckets (every minute)
  const timeBuckets = data.reduce((acc, req) => {
    const minute = new Date(req.timestamp).getMinutes();
    const key = `${minute}`;
    if (!acc[key]) {
      acc[key] = { time: key, requests: 0, errors: 0, success: 0 };
    }
    acc[key].requests++;
    if (req.statusCode >= 400) {
      acc[key].errors++;
    } else {
      acc[key].success++;
    }
    return acc;
  }, {} as Record<string, { time: string; requests: number; errors: number; success: number }>);

  const chartData = Object.values(timeBuckets).slice(-20); // Last 20 minutes

  const maxRequests = Math.max(...chartData.map(d => d.requests), 1);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center space-x-2">
              <Activity className="h-5 w-5" />
              <span>Real-Time Traffic Timeline</span>
            </CardTitle>
            <CardDescription>Live histogram of API requests per minute</CardDescription>
          </div>
          <div className="flex items-center space-x-2">
            <Button
              variant={isLive ? "default" : "outline"}
              size="sm"
              onClick={() => setIsLive(!isLive)}
            >
              {isLive ? <Pause className="h-4 w-4 mr-2" /> : <Play className="h-4 w-4 mr-2" />}
              {isLive ? 'Live' : 'Paused'}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="h-32 flex items-end space-x-1">
          {chartData.map((bucket, index) => (
            <div key={index} className="flex-1 flex flex-col items-center">
              <div className="w-full flex flex-col space-y-0.5">
                <div 
                  className="w-full bg-green-500 transition-all duration-300"
                  style={{ 
                    height: `${(bucket.success / maxRequests) * 100}%`,
                    minHeight: '2px'
                  }}
                  title={`Success: ${bucket.success}`}
                />
                <div 
                  className="w-full bg-red-500 transition-all duration-300"
                  style={{ 
                    height: `${(bucket.errors / maxRequests) * 100}%`,
                    minHeight: bucket.errors > 0 ? '2px' : '0'
                  }}
                  title={`Errors: ${bucket.errors}`}
                />
              </div>
              <span className="text-xs text-gray-500 mt-1">{bucket.time}</span>
            </div>
          ))}
        </div>
        <div className="flex items-center justify-center space-x-6 mt-4">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-green-500 rounded" />
            <span className="text-sm text-gray-600">2xx Success</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-red-500 rounded" />
            <span className="text-sm text-gray-600">4xx/5xx Errors</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

// Request Detail Modal Component
const RequestDetailModal = ({ request }: { request: RequestData }) => {
  const [activeTab, setActiveTab] = useState('overview');

  const getStatusColor = (statusCode: number) => {
    if (statusCode >= 200 && statusCode < 300) return 'text-green-600 bg-green-50';
    if (statusCode >= 400 && statusCode < 500) return 'text-yellow-600 bg-yellow-50';
    if (statusCode >= 500) return 'text-red-600 bg-red-50';
    return 'text-gray-600 bg-gray-50';
  };

  const getMethodColor = (method: string) => {
    const colors = {
      GET: 'text-blue-600 bg-blue-50',
      POST: 'text-green-600 bg-green-50',
      PUT: 'text-yellow-600 bg-yellow-50',
      DELETE: 'text-red-600 bg-red-50',
      PATCH: 'text-purple-600 bg-purple-50',
    };
    return colors[method as keyof typeof colors] || 'text-gray-600 bg-gray-50';
  };

  const totalDuration = request.spans?.reduce((sum, span) => sum + span.duration, 0) || 0;

  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm">View Details</Button>
      </DialogTrigger>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-3">
            <Badge className={getMethodColor(request.method)}>{request.method}</Badge>
            <span className="font-mono">{request.endpoint}</span>
            <Badge className={getStatusColor(request.statusCode)}>{request.statusCode}</Badge>
          </DialogTitle>
        </DialogHeader>
        
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
            <TabsTrigger value="request">Request Data</TabsTrigger>
            <TabsTrigger value="response">Response Data</TabsTrigger>
          </TabsList>
          
          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-gray-600">Timestamp</label>
                <p className="text-sm">{request.timestamp.toLocaleString()}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-600">Duration</label>
                <p className="text-sm">{request.latency}ms</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-600">Project</label>
                <p className="text-sm">{request.project}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-600">Service</label>
                <p className="text-sm">{request.service}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-600">IP Address</label>
                <p className="text-sm">{request.ip}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-600">Correlation ID</label>
                <p className="text-sm font-mono">{request.correlationId}</p>
              </div>
            </div>
            
            <div>
              <label className="text-sm font-medium text-gray-600 mb-2 block">Tags</label>
              <div className="flex flex-wrap gap-2">
                {request.tags.map((tag, index) => (
                  <Badge key={index} variant="secondary">{tag}</Badge>
                ))}
              </div>
            </div>
            
            <div>
              <label className="text-sm font-medium text-gray-600 mb-2 block">Alerts</label>
              <div className="flex flex-wrap gap-2">
                {request.latency > 500 && (
                  <Badge variant="destructive" className="flex items-center space-x-1">
                    <Timer className="h-3 w-3" />
                    <span>Slow Request</span>
                  </Badge>
                )}
                {request.statusCode >= 400 && (
                  <Badge variant="destructive" className="flex items-center space-x-1">
                    <XCircle className="h-3 w-3" />
                    <span>Error</span>
                  </Badge>
                )}
                {request.statusCode === 429 && (
                  <Badge variant="secondary" className="flex items-center space-x-1">
                    <AlertTriangle className="h-3 w-3" />
                    <span>Rate Limited</span>
                  </Badge>
                )}
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="timeline" className="space-y-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between text-sm text-gray-600 mb-2">
                <span>Span Breakdown</span>
                <span>Total: {totalDuration}ms</span>
              </div>
              {request.spans?.map((span, index) => (
                <div key={index} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div 
                        className="w-3 h-3 rounded"
                        style={{ backgroundColor: span.color }}
                      />
                      <span className="text-sm font-medium">{span.name}</span>
                    </div>
                    <span className="text-sm text-gray-600">{span.duration}ms</span>
                  </div>
                  <div className="relative h-8 bg-gray-100 rounded">
                    <div 
                      className="absolute h-full rounded flex items-center justify-center text-xs text-white font-medium"
                      style={{ 
                        backgroundColor: span.color,
                        left: `${(span.startTime / totalDuration) * 100}%`,
                        width: `${(span.duration / totalDuration) * 100}%`
                      }}
                    >
                      {span.duration}ms
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </TabsContent>
          
          <TabsContent value="request" className="space-y-4">
            <div>
              <label className="text-sm font-medium text-gray-600 mb-2 block">Headers</label>
              <div className="bg-gray-50 p-3 rounded-lg">
                <pre className="text-xs overflow-x-auto">
                  {JSON.stringify(request.requestData?.headers, null, 2)}
                </pre>
              </div>
            </div>
            
            <div>
              <label className="text-sm font-medium text-gray-600 mb-2 block">Query Parameters</label>
              <div className="bg-gray-50 p-3 rounded-lg">
                <pre className="text-xs overflow-x-auto">
                  {JSON.stringify(request.requestData?.queryParams, null, 2)}
                </pre>
              </div>
            </div>
            
            <div>
              <label className="text-sm font-medium text-gray-600 mb-2 block">Body</label>
              <div className="bg-gray-50 p-3 rounded-lg">
                <pre className="text-xs overflow-x-auto">
                  {JSON.stringify(request.requestData?.body, null, 2)}
                </pre>
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="response" className="space-y-4">
            <div>
              <label className="text-sm font-medium text-gray-600 mb-2 block">Headers</label>
              <div className="bg-gray-50 p-3 rounded-lg">
                <pre className="text-xs overflow-x-auto">
                  {JSON.stringify(request.responseData?.headers, null, 2)}
                </pre>
              </div>
            </div>
            
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-gray-600">Response Size</label>
                <p className="text-sm">{request.responseData?.size} bytes</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-600">Duration</label>
                <p className="text-sm">{request.responseData?.duration}ms</p>
              </div>
            </div>
            
            <div>
              <label className="text-sm font-medium text-gray-600 mb-2 block">Payload</label>
              <div className="bg-gray-50 p-3 rounded-lg">
                <pre className="text-xs overflow-x-auto max-h-64">
                  {JSON.stringify(request.responseData?.payload, null, 2)}
                </pre>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
};

// Main Component
export default function RequestMonitoringPage() {
  const [requests, setRequests] = useState<RequestData[]>([]);
  const [filteredRequests, setFilteredRequests] = useState<RequestData[]>([]);
  const [isLiveMode, setIsLiveMode] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [methodFilter, setMethodFilter] = useState<string>('all');
  const [timeRange, setTimeRange] = useState('1h');

  // Analytics data
  const analytics: AnalyticsData = {
    rps: 127.5,
    errorRate: 2.3,
    avgLatency: 245,
    p90Latency: 420,
    p95Latency: 580,
    p99Latency: 920,
    topEndpoint: '/api/v1/users',
    failingEndpoint: '/api/v1/auth'
  };

  useEffect(() => {
    const mockData = generateMockRequests();
    setRequests(mockData);
    setFilteredRequests(mockData);
  }, []);

  useEffect(() => {
    if (isLiveMode) {
      const interval = setInterval(() => {
        const newRequests = generateMockRequests();
        const newRequest = newRequests[0];
        setRequests(prev => [newRequest, ...prev.slice(0, 99)]);
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [isLiveMode]);

  useEffect(() => {
    let filtered = requests;

    if (searchTerm) {
      filtered = filtered.filter(req => 
        req.endpoint.toLowerCase().includes(searchTerm.toLowerCase()) ||
        req.correlationId.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (statusFilter !== 'all') {
      if (statusFilter === '2xx') {
        filtered = filtered.filter(req => req.statusCode >= 200 && req.statusCode < 300);
      } else if (statusFilter === '4xx') {
        filtered = filtered.filter(req => req.statusCode >= 400 && req.statusCode < 500);
      } else if (statusFilter === '5xx') {
        filtered = filtered.filter(req => req.statusCode >= 500);
      }
    }

    if (methodFilter !== 'all') {
      filtered = filtered.filter(req => req.method === methodFilter);
    }

    setFilteredRequests(filtered);
  }, [requests, searchTerm, statusFilter, methodFilter]);

  const getStatusBadgeVariant = (statusCode: number) => {
    if (statusCode >= 200 && statusCode < 300) return 'default';
    if (statusCode >= 400 && statusCode < 500) return 'secondary';
    if (statusCode >= 500) return 'destructive';
    return 'outline';
  };

  const getLatencyColor = (latency: number) => {
    if (latency < 200) return 'text-green-600';
    if (latency < 500) return 'text-yellow-600';
    return 'text-red-600';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Request Monitoring</h1>
          <p className="text-gray-600 mt-1">Monitor all incoming and outgoing API requests in real time</p>
        </div>
        <div className="flex items-center space-x-3">
          <Badge variant="secondary" className="text-sm">
            {filteredRequests.length} requests
          </Badge>
          <Badge variant="destructive" className="text-sm">
            {analytics.errorRate}% error rate
          </Badge>
          <Badge variant="outline" className="text-sm">
            P95: {analytics.p95Latency}ms
          </Badge>
        </div>
      </div>

      {/* Analytics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Requests per Second"
          value={analytics.rps}
          trend="up"
          trendValue="+12%"
          icon={Activity}
          color="blue"
        />
        <MetricCard
          title="Error Rate"
          value={`${analytics.errorRate}%`}
          trend="down"
          trendValue="-0.5%"
          icon={AlertTriangle}
          color="red"
        />
        <MetricCard
          title="Average Latency"
          value={`${analytics.avgLatency}ms`}
          trend="down"
          trendValue="-15ms"
          icon={Clock}
          color="green"
        />
        <MetricCard
          title="P95 Latency"
          value={`${analytics.p95Latency}ms`}
          trend="down"
          trendValue="-25ms"
          icon={Timer}
          color="yellow"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <MetricCard
          title="P99 Latency"
          value={`${analytics.p99Latency}ms`}
          trend="neutral"
          icon={Zap}
          color="purple"
        />
        <MetricCard
          title="Most Called Endpoint"
          value={analytics.topEndpoint}
          trend="up"
          trendValue="+23%"
          icon={Globe}
          color="blue"
        />
        <MetricCard
          title="Most Failing Endpoint"
          value={analytics.failingEndpoint}
          trend="up"
          trendValue="+2"
          icon={Bug}
          color="red"
        />
      </div>

      {/* Real-Time Traffic Timeline */}
      <TimelineChart data={filteredRequests} />

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Filter className="h-5 w-5" />
            <span>Filters</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-4">
            <div className="flex items-center space-x-2">
              <Search className="h-4 w-4 text-gray-500" />
              <Input
                placeholder="Search by endpoint or correlation ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-64"
              />
            </div>
            
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-32">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="2xx">2xx Success</SelectItem>
                <SelectItem value="4xx">4xx Client</SelectItem>
                <SelectItem value="5xx">5xx Server</SelectItem>
              </SelectContent>
            </Select>

            <Select value={methodFilter} onValueChange={setMethodFilter}>
              <SelectTrigger className="w-32">
                <SelectValue placeholder="Method" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Methods</SelectItem>
                <SelectItem value="GET">GET</SelectItem>
                <SelectItem value="POST">POST</SelectItem>
                <SelectItem value="PUT">PUT</SelectItem>
                <SelectItem value="DELETE">DELETE</SelectItem>
                <SelectItem value="PATCH">PATCH</SelectItem>
              </SelectContent>
            </Select>

            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger className="w-32">
                <SelectValue placeholder="Time Range" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="15m">Last 15m</SelectItem>
                <SelectItem value="1h">Last 1h</SelectItem>
                <SelectItem value="24h">Last 24h</SelectItem>
              </SelectContent>
            </Select>

            <Button
              variant={isLiveMode ? "default" : "outline"}
              onClick={() => setIsLiveMode(!isLiveMode)}
            >
              {isLiveMode ? <Pause className="h-4 w-4 mr-2" /> : <Play className="h-4 w-4 mr-2" />}
              {isLiveMode ? 'Live Mode' : 'Paused'}
            </Button>

            <Button variant="outline">
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Requests Table */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Requests</CardTitle>
          <CardDescription>
            Click on any row to view detailed request information
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Timestamp</TableHead>
                <TableHead>Method</TableHead>
                <TableHead>Endpoint</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Latency</TableHead>
                <TableHead>Project</TableHead>
                <TableHead>Service</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredRequests.slice(0, 20).map((request) => (
                <TableRow key={request.id} className="hover:bg-gray-50">
                  <TableCell className="text-sm">
                    {request.timestamp.toLocaleTimeString()}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-xs">
                      {request.method}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {request.endpoint}
                  </TableCell>
                  <TableCell>
                    <Badge variant={getStatusBadgeVariant(request.statusCode)}>
                      {request.statusCode}
                    </Badge>
                  </TableCell>
                  <TableCell className={`font-medium ${getLatencyColor(request.latency)}`}>
                    {request.latency}ms
                  </TableCell>
                  <TableCell className="text-sm">{request.project}</TableCell>
                  <TableCell className="text-sm">{request.service}</TableCell>
                  <TableCell className="text-sm font-mono">{request.ip}</TableCell>
                  <TableCell>
                    <RequestDetailModal request={request} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}