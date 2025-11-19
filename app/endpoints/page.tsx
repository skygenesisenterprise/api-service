"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Globe,
  Activity,
  Clock,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Plus,
  Search,
  Filter,
  MoreHorizontal,
  Eye,
  Settings,
  Trash2,
  Zap,
  TrendingUp,
  TrendingDown,
  Server,
  Shield,
  Copy,
  ExternalLink,
} from "lucide-react";
import { mockEndpoints } from "@/data/mockEndpoints";
import { Endpoint } from "@/types/endpoint";

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

export default function EndpointsPage() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>(mockEndpoints);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedMethod, setSelectedMethod] = useState<string>("all");
  const [selectedService, setSelectedService] = useState<string>("all");
  const [selectedStatus, setSelectedStatus] = useState<string>("all");

  const filteredEndpoints = endpoints.filter((endpoint) => {
    const matchesSearch = endpoint.route.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         endpoint.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         endpoint.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
    
    const matchesMethod = selectedMethod === "all" || endpoint.method === selectedMethod;
    const matchesService = selectedService === "all" || endpoint.service === selectedService;
    const matchesStatus = selectedStatus === "all" || endpoint.status === selectedStatus;

    return matchesSearch && matchesMethod && matchesService && matchesStatus;
  });

  const totalRequests = endpoints.reduce((sum, ep) => sum + ep.requestsToday, 0);
  const avgErrorRate = endpoints.reduce((sum, ep) => sum + ep.errorRate, 0) / endpoints.length;
  const avgLatency = endpoints.reduce((sum, ep) => sum + ep.latency.avg, 0) / endpoints.length;
  const healthyEndpoints = endpoints.filter(ep => ep.status === "healthy").length;

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

  const services = Array.from(new Set(endpoints.map(ep => ep.service)));

  return (
    <div className="min-h-full bg-gray-50 p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="mb-8"
      >
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Endpoints</h1>
            <p className="text-gray-600 mt-1">
              Monitor and manage all API endpoints across your services
            </p>
          </div>
          <Button 
            className="bg-blue-600 hover:bg-blue-700"
            onClick={() => console.log("Create endpoint clicked")}
          >
            <Plus className="h-4 w-4 mr-2" />
            Create Endpoint
          </Button>
        </div>
      </motion.div>

      {/* Stats Cards */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8"
      >
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Endpoints</p>
                <p className="text-2xl font-bold text-gray-900">{endpoints.length}</p>
              </div>
              <div className="p-3 bg-blue-100 rounded-lg">
                <Globe className="h-6 w-6 text-blue-600" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Requests Today</p>
                <p className="text-2xl font-bold text-gray-900">{totalRequests.toLocaleString()}</p>
              </div>
              <div className="p-3 bg-green-100 rounded-lg">
                <TrendingUp className="h-6 w-6 text-green-600" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Avg Error Rate</p>
                <p className="text-2xl font-bold text-gray-900">{avgErrorRate.toFixed(1)}%</p>
              </div>
              <div className="p-3 bg-yellow-100 rounded-lg">
                <AlertTriangle className="h-6 w-6 text-yellow-600" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Avg Latency</p>
                <p className="text-2xl font-bold text-gray-900">{Math.round(avgLatency)}ms</p>
              </div>
              <div className="p-3 bg-purple-100 rounded-lg">
                <Zap className="h-6 w-6 text-purple-600" />
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Search and Filters */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.2 }}
        className="mb-6"
      >
        <div className="flex flex-col lg:flex-row gap-4">
          {/* Search Bar */}
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              placeholder="Search endpoints..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>

          {/* Filters */}
          <div className="flex gap-2">
            {/* Method Filter */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="gap-2">
                  <Filter className="h-4 w-4" />
                  Method: {selectedMethod === "all" ? "All" : selectedMethod}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem onClick={() => setSelectedMethod("all")}>
                  All Methods
                </DropdownMenuItem>
                {Object.keys(methodConfig).map((method) => (
                  <DropdownMenuItem key={method} onClick={() => setSelectedMethod(method)}>
                    <Badge className={`mr-2 ${methodConfig[method as keyof typeof methodConfig].color}`}>
                      {method}
                    </Badge>
                    {method}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>

            {/* Service Filter */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="gap-2">
                  <Server className="h-4 w-4" />
                  Service: {selectedService === "all" ? "All" : selectedService}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem onClick={() => setSelectedService("all")}>
                  All Services
                </DropdownMenuItem>
                {services.map((service) => (
                  <DropdownMenuItem key={service} onClick={() => setSelectedService(service)}>
                    {service}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>

            {/* Status Filter */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="gap-2">
                  <Activity className="h-4 w-4" />
                  Status: {selectedStatus === "all" ? "All" : selectedStatus}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem onClick={() => setSelectedStatus("all")}>
                  All Status
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setSelectedStatus("healthy")}>
                  <CheckCircle className="h-4 w-4 mr-2 text-green-600" />
                  Healthy
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setSelectedStatus("warning")}>
                  <AlertTriangle className="h-4 w-4 mr-2 text-yellow-600" />
                  Warning
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setSelectedStatus("critical")}>
                  <XCircle className="h-4 w-4 mr-2 text-red-600" />
                  Critical
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </motion.div>

      {/* Endpoints Grid */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="grid grid-cols-1 lg:grid-cols-2 gap-6"
      >
        {filteredEndpoints.map((endpoint) => {
          const StatusIcon = statusConfig[endpoint.status].icon;
          const methodStyle = methodConfig[endpoint.method];
          
          return (
            <motion.div
              key={endpoint.id}
              variants={cardVariants}
              whileHover={{ 
                scale: 1.02, 
                boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.1)" 
              }}
              className="group"
            >
              <Card className="h-full hover:shadow-lg transition-all duration-300 cursor-pointer">
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <Badge className={methodStyle.color}>
                        {methodStyle.label}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <CardTitle className="text-lg font-semibold text-gray-900 truncate">
                          {endpoint.route}
                        </CardTitle>
                        <CardDescription className="text-sm text-gray-600 line-clamp-2">
                          {endpoint.description}
                        </CardDescription>
                      </div>
                    </div>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button 
                          variant="ghost" 
                          size="sm" 
                          className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-48">
                        <DropdownMenuItem 
                          onClick={() => {
                            console.log("View endpoint details:", endpoint.route);
                            // Navigate to endpoint details
                          }}
                          className="flex items-center gap-2"
                        >
                          <Eye className="h-4 w-4" />
                          <span>View Details</span>
                        </DropdownMenuItem>
                        <DropdownMenuItem 
                          onClick={() => {
                            navigator.clipboard.writeText(endpoint.route);
                            console.log("Route copied to clipboard");
                          }}
                          className="flex items-center gap-2"
                        >
                          <Copy className="h-4 w-4" />
                          <span>Copy Route</span>
                        </DropdownMenuItem>
                        <DropdownMenuItem 
                          onClick={() => {
                            console.log("Test endpoint:", endpoint.route);
                            // Open API explorer
                          }}
                          className="flex items-center gap-2"
                        >
                          <ExternalLink className="h-4 w-4" />
                          <span>Test Endpoint</span>
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem 
                          onClick={() => {
                            if (window.confirm(`Are you sure you want to delete "${endpoint.route}"?`)) {
                              setEndpoints(prev => prev.filter((e: Endpoint) => e.id !== endpoint.id));
                              console.log("Endpoint deleted:", endpoint.route);
                            }
                          }}
                          className="flex items-center gap-2 text-red-600 focus:text-red-600"
                        >
                          <Trash2 className="h-4 w-4" />
                          <span>Delete Endpoint</span>
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </CardHeader>

                <CardContent className="space-y-4">
                  {/* Status and Service */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <StatusIcon className={`h-4 w-4 ${statusConfig[endpoint.status].color}`} />
                      <span className={`text-sm font-medium ${statusConfig[endpoint.status].color}`}>
                        {endpoint.status.charAt(0).toUpperCase() + endpoint.status.slice(1)}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Server className="h-3 w-3 text-gray-400" />
                      <span className="text-sm text-gray-600">{endpoint.service}</span>
                    </div>
                  </div>

                  {/* Metrics */}
                  <div className="grid grid-cols-3 gap-4">
                    <div className="text-center">
                      <p className="text-xs text-gray-500">Latency</p>
                      <p className="text-sm font-semibold text-gray-900">{endpoint.latency.avg}ms</p>
                    </div>
                    <div className="text-center">
                      <p className="text-xs text-gray-500">Error Rate</p>
                      <p className={`text-sm font-semibold ${
                        endpoint.errorRate > 2 ? 'text-red-600' : 
                        endpoint.errorRate > 1 ? 'text-yellow-600' : 'text-green-600'
                      }`}>
                        {endpoint.errorRate}%
                      </p>
                    </div>
                    <div className="text-center">
                      <p className="text-xs text-gray-500">Requests</p>
                      <p className="text-sm font-semibold text-gray-900">{endpoint.requestsToday.toLocaleString()}</p>
                    </div>
                  </div>

                  {/* Tags */}
                  <div className="flex flex-wrap gap-1">
                    {endpoint.tags.slice(0, 3).map((tag) => (
                      <Badge
                        key={tag}
                        variant="secondary"
                        className="text-xs bg-gray-100 text-gray-700"
                      >
                        {tag}
                      </Badge>
                    ))}
                    {endpoint.tags.length > 3 && (
                      <Badge variant="secondary" className="text-xs">
                        +{endpoint.tags.length - 3} more
                      </Badge>
                    )}
                    {endpoint.deprecated && (
                      <Badge variant="destructive" className="text-xs">
                        Deprecated
                      </Badge>
                    )}
                  </div>

                  {/* Last Activity */}
                  <div className="flex items-center justify-between pt-2 border-t border-gray-100">
                    <div className="flex items-center gap-2 text-sm text-gray-500">
                      <Clock className="h-3 w-3" />
                      Last activity: {endpoint.lastActivity}
                    </div>
                    <div className="text-xs text-gray-400">
                      v{endpoint.version}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          );
        })}
      </motion.div>

      {/* Empty State */}
      {filteredEndpoints.length === 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center py-12"
        >
          <Globe className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No endpoints found</h3>
          <p className="text-gray-600 mb-4">
            Try adjusting your search or filters to find what you're looking for.
          </p>
          <Button variant="outline">
            Clear all filters
          </Button>
        </motion.div>
      )}
    </div>
  );
}