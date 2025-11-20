"use client";

import { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Boxes, 
  Plus, 
  Search, 
  Filter,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Clock,
  Activity,
  Shield,
  Key,
  Settings,
  Eye,
  RotateCcw,
  Trash2,
  Zap,
  BarChart3,
  MoreHorizontal,
  Grid3X3,
  List,
  Sparkles,
  ArrowUpRight,
  ArrowDownRight,
  RefreshCw
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { TooltipProvider } from "@/components/ui/tooltip";

// Types
interface Service {
  id: string;
  name: string;
  type: string;
  category: 'observability' | 'messaging' | 'storage' | 'security' | 'internal';
  domain: string;
  status: 'healthy' | 'degraded' | 'offline';
  lastHeartbeat: Date;
  tags: string[];
  logo: string;
  config?: Record<string, any>;
  metrics?: {
    latency: number;
    uptime: number;
    errorRate: number;
    requests: number;
  };
}

interface ServiceCatalog {
  id: string;
  name: string;
  description: string;
  category: string;
  logo: string;
  popular?: boolean;
  features?: string[];
}

interface AuditLog {
  id: string;
  timestamp: Date;
  actor: string;
  action: string;
  service: string;
  details: string;
  type: 'config' | 'connection' | 'security' | 'error';
}

// Enhanced Mock Data
const mockServices: Service[] = [
  {
    id: "1",
    name: "Grafana",
    type: "grafana",
    category: "observability",
    domain: "grafana.enterprise.com",
    status: "healthy",
    lastHeartbeat: new Date(Date.now() - 2 * 60 * 1000),
    tags: ["Observability", "Dashboards", "Metrics"],
    logo: "📊",
    config: {
      apiToken: "glc_•••••••••••••••••",
      datasourceId: "1",
      syncDashboards: true
    },
    metrics: {
      latency: 45,
      uptime: 99.9,
      errorRate: 0.1,
      requests: 15420
    }
  },
  {
    id: "2",
    name: "Prometheus",
    type: "prometheus",
    category: "observability",
    domain: "prometheus.enterprise.com",
    status: "healthy",
    lastHeartbeat: new Date(Date.now() - 1 * 60 * 1000),
    tags: ["Observability", "Metrics", "Monitoring"],
    logo: "🔥",
    config: {
      scrapeInterval: "15s",
      retentionPeriod: "15d",
      alertingEnabled: true
    },
    metrics: {
      latency: 23,
      uptime: 99.8,
      errorRate: 0.2,
      requests: 28340
    }
  },
  {
    id: "3",
    name: "Loki",
    type: "loki",
    category: "observability",
    domain: "loki.enterprise.com",
    status: "degraded",
    lastHeartbeat: new Date(Date.now() - 10 * 60 * 1000),
    tags: ["Observability", "Logs", "Aggregation"],
    logo: "🪵",
    config: {
      ingestionEndpoint: "https://loki.enterprise.com/loki/api/v1/push",
      retentionPeriod: "30d",
      compressionEnabled: true
    },
    metrics: {
      latency: 156,
      uptime: 95.2,
      errorRate: 4.8,
      requests: 8920
    }
  },
  {
    id: "4",
    name: "Vault",
    type: "vault",
    category: "security",
    domain: "vault.enterprise.com",
    status: "healthy",
    lastHeartbeat: new Date(Date.now() - 30 * 1000),
    tags: ["Security", "Secrets", "Encryption"],
    logo: "🔐",
    config: {
      mountPath: "secret/",
      tokenTTL: "24h",
      autoRotate: true
    },
    metrics: {
      latency: 67,
      uptime: 99.99,
      errorRate: 0.01,
      requests: 3420
    }
  },
  {
    id: "5",
    name: "Redis",
    type: "redis",
    category: "storage",
    domain: "redis.enterprise.com",
    status: "healthy",
    lastHeartbeat: new Date(Date.now() - 5 * 1000),
    tags: ["Storage", "Cache", "Database"],
    logo: "💾",
    config: {
      maxMemory: "2gb",
      evictionPolicy: "allkeys-lru",
      persistenceEnabled: true
    },
    metrics: {
      latency: 12,
      uptime: 99.95,
      errorRate: 0.05,
      requests: 45680
    }
  }
];

const mockServiceCatalog: ServiceCatalog[] = [
  { 
    id: "6", 
    name: "Elasticsearch", 
    description: "Distributed search and analytics engine", 
    category: "observability", 
    logo: "🔍", 
    popular: true,
    features: ["Full-text search", "Real-time analytics", "Scalable architecture"]
  },
  { 
    id: "7", 
    name: "Kafka", 
    description: "Distributed streaming platform", 
    category: "messaging", 
    logo: "📨", 
    popular: true,
    features: ["High throughput", "Fault tolerance", "Real-time streaming"]
  },
  { 
    id: "8", 
    name: "MinIO", 
    description: "High-performance object storage", 
    category: "storage", 
    logo: "🗄️", 
    popular: false,
    features: ["S3 compatible", "Distributed", "High performance"]
  },
  { 
    id: "9", 
    name: "Consul", 
    description: "Service mesh and service discovery", 
    category: "internal", 
    logo: "🌐", 
    popular: false,
    features: ["Service discovery", "Health checking", "Key-value store"]
  },
  { 
    id: "10", 
    name: "Jaeger", 
    description: "Distributed tracing system", 
    category: "observability", 
    logo: "🔬", 
    popular: true,
    features: ["Distributed tracing", "Performance monitoring", "Root cause analysis"]
  }
];

const mockAuditLogs: AuditLog[] = [
  { id: "1", timestamp: new Date(Date.now() - 30 * 60 * 1000), actor: "admin@company.com", action: "API Key Rotated", service: "Grafana", details: "Successfully rotated API key for Grafana integration", type: "security" },
  { id: "2", timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000), actor: "system", action: "Connection Lost", service: "Loki", details: "Lost connection to Loki cluster, attempting reconnection", type: "error" },
  { id: "3", timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000), actor: "devops@company.com", action: "Configuration Updated", service: "Prometheus", details: "Updated scrape interval from 30s to 15s", type: "config" },
  { id: "4", timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000), actor: "admin@company.com", action: "Service Connected", service: "Redis", details: "Successfully connected Redis cache service", type: "connection" }
];

// Modern Components
function StatusIndicator({ status, size = "sm" }: { status: Service['status']; size?: "sm" | "md" | "lg" }) {
  const sizeClasses = {
    sm: "w-2 h-2",
    md: "w-3 h-3", 
    lg: "w-4 h-4"
  };

  const statusConfig = {
    healthy: { bg: "bg-emerald-500", shadow: "shadow-emerald-500/50", pulse: true },
    degraded: { bg: "bg-amber-500", shadow: "shadow-amber-500/50", pulse: false },
    offline: { bg: "bg-red-500", shadow: "shadow-red-500/50", pulse: false }
  };

  const config = statusConfig[status];

  return (
    <div className="relative">
      <div 
        className={`${sizeClasses[size]} ${config.bg} rounded-full ${config.pulse ? 'animate-pulse' : ''}`}
        style={{ boxShadow: `0 0 20px ${config.shadow}` }}
      />
    </div>
  );
}

function ModernServiceCard({ service, onManage, onDisconnect, onRegenerate, viewMode }: { 
  service: Service; 
  onManage: (service: Service) => void;
  onDisconnect: (service: Service) => void;
  onRegenerate: (service: Service) => void;
  viewMode: "grid" | "list";
}) {
  const [isHovered, setIsHovered] = useState(false);

  if (viewMode === "list") {
    return (
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        whileHover={{ scale: 1.02 }}
        className="border border-gray-200/60 rounded-xl p-4 hover:shadow-lg transition-all duration-300 bg-white/50 backdrop-blur-sm"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="relative">
              <div className="text-3xl">{service.logo}</div>
              <StatusIndicator status={service.status} size="sm" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900">{service.name}</h3>
              <p className="text-sm text-gray-500">{service.domain}</p>
              <div className="flex gap-1 mt-1">
                {service.tags.slice(0, 2).map((tag) => (
                  <Badge key={tag} variant="secondary" className="text-xs">
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="flex items-center gap-2 text-sm text-gray-600">
                <Activity className="w-4 h-4" />
                <span>{service.metrics?.latency}ms</span>
              </div>
              <div className="text-xs text-gray-500">
                {service.metrics?.uptime}% uptime
              </div>
            </div>
            
            <div className="flex gap-2">
              <Button size="sm" variant="ghost" onClick={() => onManage(service)}>
                <Settings className="w-4 h-4" />
              </Button>
              <Button size="sm" variant="ghost" onClick={() => onRegenerate(service)}>
                <RotateCcw className="w-4 h-4" />
              </Button>
              <Button size="sm" variant="ghost" onClick={() => onDisconnect(service)} className="text-red-600">
                <Trash2 className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </div>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ 
        scale: 1.03, 
        boxShadow: "0 20px 40px -12px rgba(0, 0, 0, 0.15)"
      }}
      onHoverStart={() => setIsHovered(true)}
      onHoverEnd={() => setIsHovered(false)}
      className="relative group cursor-pointer"
    >
      <Card className="h-full border-0 shadow-lg hover:shadow-2xl transition-all duration-500 bg-gradient-to-br from-white to-gray-50/80 backdrop-blur-sm overflow-hidden">
        {/* Background Pattern */}
        <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-purple-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
        
        <CardHeader className="pb-4 relative">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <motion.div 
                  animate={{ rotate: isHovered ? 360 : 0 }}
                  transition={{ duration: 0.6, ease: "easeInOut" }}
                  className="text-3xl"
                >
                  {service.logo}
                </motion.div>
                <div className="absolute -bottom-1 -right-1">
                  <StatusIndicator status={service.status} size="md" />
                </div>
              </div>
              <div>
                <CardTitle className="text-lg font-bold text-gray-900">{service.name}</CardTitle>
                <CardDescription className="text-sm text-gray-600 font-medium">
                  {service.domain}
                </CardDescription>
              </div>
            </div>
            
            <motion.div
              animate={{ opacity: isHovered ? 1 : 0, x: isHovered ? 0 : 10 }}
              transition={{ duration: 0.2 }}
              className="flex gap-1"
            >
              <Button size="sm" variant="ghost" className="h-8 w-8 p-0">
                <MoreHorizontal className="w-4 h-4" />
              </Button>
            </motion.div>
          </div>
        </CardHeader>
        
        <CardContent className="space-y-4 relative">
          {/* Metrics Row */}
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center p-3 bg-gradient-to-br from-blue-50 to-blue-100/50 rounded-lg">
              <div className="flex items-center justify-center gap-1 text-blue-600 mb-1">
                <Activity className="w-3 h-3" />
                <span className="text-xs font-medium">Latency</span>
              </div>
              <div className="text-lg font-bold text-blue-700">
                {service.metrics?.latency}ms
              </div>
            </div>
            
            <div className="text-center p-3 bg-gradient-to-br from-emerald-50 to-emerald-100/50 rounded-lg">
              <div className="flex items-center justify-center gap-1 text-emerald-600 mb-1">
                <CheckCircle className="w-3 h-3" />
                <span className="text-xs font-medium">Uptime</span>
              </div>
              <div className="text-lg font-bold text-emerald-700">
                {service.metrics?.uptime}%
              </div>
            </div>
            
            <div className="text-center p-3 bg-gradient-to-br from-purple-50 to-purple-100/50 rounded-lg">
              <div className="flex items-center justify-center gap-1 text-purple-600 mb-1">
                <BarChart3 className="w-3 h-3" />
                <span className="text-xs font-medium">Requests</span>
              </div>
              <div className="text-lg font-bold text-purple-700">
                {((service.metrics?.requests || 0) / 1000).toFixed(1)}k
              </div>
            </div>
          </div>

          {/* Tags */}
          <div className="flex flex-wrap gap-1">
            {service.tags.map((tag) => (
              <Badge key={tag} variant="secondary" className="text-xs bg-gray-100 text-gray-700 hover:bg-gray-200 transition-colors">
                {tag}
              </Badge>
            ))}
          </div>
          
          {/* Last Update */}
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <Clock className="w-3 h-3" />
            <span>Last check: {service.lastHeartbeat.toLocaleTimeString()}</span>
          </div>

          {/* Action Buttons */}
          <AnimatePresence>
            {isHovered && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                transition={{ duration: 0.2 }}
                className="flex gap-2 pt-2 border-t border-gray-100"
              >
                <Button 
                  size="sm" 
                  variant="outline" 
                  onClick={() => onManage(service)}
                  className="flex-1 bg-white/80 backdrop-blur-sm hover:bg-white"
                >
                  <Settings className="w-4 h-4 mr-1" />
                  Configure
                </Button>
                <Button 
                  size="sm" 
                  variant="outline" 
                  onClick={() => onRegenerate(service)}
                  className="bg-white/80 backdrop-blur-sm hover:bg-white"
                >
                  <RotateCcw className="w-4 h-4" />
                </Button>
                <Button 
                  size="sm" 
                  variant="outline" 
                  onClick={() => onDisconnect(service)}
                  className="bg-red-50/80 backdrop-blur-sm hover:bg-red-100 text-red-600 border-red-200"
                >
                  <Trash2 className="w-4 h-4" />
                </Button>
              </motion.div>
            )}
          </AnimatePresence>
        </CardContent>
      </Card>
    </motion.div>
  );
}

function QuickStats() {
  const stats = [
    { label: "Total Services", value: mockServices.length, icon: Boxes, color: "blue", trend: "+2" },
    { label: "Healthy", value: mockServices.filter(s => s.status === 'healthy').length, icon: CheckCircle, color: "emerald", trend: "+1" },
    { label: "Degraded", value: mockServices.filter(s => s.status === 'degraded').length, icon: AlertTriangle, color: "amber", trend: "-1" },
    { label: "Offline", value: mockServices.filter(s => s.status === 'offline').length, icon: XCircle, color: "red", trend: "0" }
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      {stats.map((stat, index) => (
        <motion.div
          key={stat.label}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: index * 0.1 }}
        >
          <Card className="border-0 shadow-md hover:shadow-lg transition-shadow duration-300 bg-gradient-to-br from-white to-gray-50/50">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">{stat.label}</p>
                  <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
                </div>
                <div className={`p-3 rounded-lg bg-${stat.color}-100 text-${stat.color}-600`}>
                  <stat.icon className="w-6 h-6" />
                </div>
              </div>
              <div className="flex items-center gap-1 mt-2 text-sm">
                {stat.trend.startsWith('+') ? (
                  <ArrowUpRight className="w-4 h-4 text-emerald-600" />
                ) : stat.trend.startsWith('-') ? (
                  <ArrowDownRight className="w-4 h-4 text-red-600" />
                ) : (
                  <div className="w-4 h-4" />
                )}
                <span className={`font-medium ${
                  stat.trend.startsWith('+') ? 'text-emerald-600' : 
                  stat.trend.startsWith('-') ? 'text-red-600' : 'text-gray-600'
                }`}>
                  {stat.trend} from last week
                </span>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      ))}
    </div>
  );
}

export default function ModernServicesPage() {
  const [services, setServices] = useState<Service[]>(mockServices);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [selectedService, setSelectedService] = useState<Service | null>(null);

  const filteredServices = useMemo(() => {
    return services.filter(service => {
      const matchesSearch = service.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           service.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           service.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
      const matchesCategory = selectedCategory === "all" || service.category === selectedCategory;
      return matchesSearch && matchesCategory;
    });
  }, [services, searchTerm, selectedCategory]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await new Promise(resolve => setTimeout(resolve, 2000));
    setIsRefreshing(false);
  };

  const handleManage = (service: Service) => {
    setSelectedService(service);
  };

  const handleDisconnect = (service: Service) => {
    setServices(prev => prev.filter(s => s.id !== service.id));
  };

  const handleRegenerate = (service: Service) => {
    console.log(`Regenerating credentials for ${service.name}`);
  };

  const handleConnectService = (catalogService: ServiceCatalog) => {
    const newService: Service = {
      id: Date.now().toString(),
      name: catalogService.name,
      type: catalogService.name.toLowerCase(),
      category: catalogService.category as Service['category'],
      domain: `${catalogService.name.toLowerCase()}.enterprise.com`,
      status: "healthy",
      lastHeartbeat: new Date(),
      tags: [catalogService.category],
      logo: catalogService.logo,
      metrics: {
        latency: Math.floor(Math.random() * 100) + 20,
        uptime: 99 + Math.random(),
        errorRate: Math.random() * 2,
        requests: Math.floor(Math.random() * 50000) + 1000
      }
    };
    setServices(prev => [...prev, newService]);
  };

  return (
    <TooltipProvider>
      <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-blue-50/30">
        <div className="max-w-7xl mx-auto p-6 space-y-8">
          {/* Modern Header */}
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center space-y-4"
          >
            <div className="flex items-center justify-center gap-3 mb-4">
              <div className="p-3 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl shadow-lg">
                <Boxes className="w-8 h-8 text-white" />
              </div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-900 to-gray-600 bg-clip-text text-transparent">
                Services Hub
              </h1>
            </div>
            <p className="text-lg text-gray-600 max-w-2xl mx-auto">
              Centralisez, gérez et surveillez toutes vos intégrations d'infrastructure en un seul endroit.
            </p>
          </motion.div>

          {/* Quick Stats */}
          <QuickStats />

          {/* Advanced Search and Filters */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-white/60 backdrop-blur-sm rounded-2xl border border-gray-200/60 p-6 shadow-lg"
          >
            <div className="flex flex-col lg:flex-row gap-4">
              {/* Search Bar */}
              <div className="relative flex-1">
                <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
                <Input
                  placeholder="Rechercher des services, domaines ou tags..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-12 h-12 border-0 bg-gray-50/80 focus:bg-white transition-colors text-base"
                />
              </div>

              {/* Category Filter */}
              <Select value={selectedCategory} onValueChange={setSelectedCategory}>
                <SelectTrigger className="h-12 w-48 border-0 bg-gray-50/80 hover:bg-white transition-colors">
                  <Filter className="w-4 h-4 mr-2" />
                  <SelectValue placeholder="Catégorie" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Toutes les catégories</SelectItem>
                  <SelectItem value="observability">Observabilité</SelectItem>
                  <SelectItem value="messaging">Messagerie</SelectItem>
                  <SelectItem value="storage">Stockage</SelectItem>
                  <SelectItem value="security">Sécurité</SelectItem>
                  <SelectItem value="internal">Interne</SelectItem>
                </SelectContent>
              </Select>

              {/* View Mode Toggle */}
              <div className="flex bg-gray-100/80 rounded-lg p-1">
                <Button
                  variant={viewMode === "grid" ? "default" : "ghost"}
                  size="sm"
                  onClick={() => setViewMode("grid")}
                  className="h-10 px-3"
                >
                  <Grid3X3 className="w-4 h-4" />
                </Button>
                <Button
                  variant={viewMode === "list" ? "default" : "ghost"}
                  size="sm"
                  onClick={() => setViewMode("list")}
                  className="h-10 px-3"
                >
                  <List className="w-4 h-4" />
                </Button>
              </div>

              {/* Actions */}
              <div className="flex gap-3">
                <Button 
                  variant="outline" 
                  onClick={handleRefresh}
                  disabled={isRefreshing}
                  className="h-12 px-6 border-0 bg-gray-50/80 hover:bg-white transition-colors"
                >
                  <RefreshCw className={`w-5 h-5 mr-2 ${isRefreshing ? 'animate-spin' : ''}`} />
                  {isRefreshing ? "Actualisation..." : "Actualiser"}
                </Button>
                
                <Dialog>
                  <DialogTrigger asChild>
                    <Button className="h-12 px-6 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 shadow-lg hover:shadow-xl transition-all duration-300">
                      <Plus className="w-5 h-5 mr-2" />
                      Connecter un service
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
                    <DialogHeader>
                      <DialogTitle className="text-2xl font-bold">Catalogue des Services</DialogTitle>
                      <DialogDescription className="text-base">
                        Découvrez et connectez de nouvelles intégrations pour votre infrastructure.
                      </DialogDescription>
                    </DialogHeader>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mt-6">
                      {mockServiceCatalog.map((catalogService) => (
                        <motion.div
                          key={catalogService.id}
                          whileHover={{ scale: 1.02 }}
                          className="group"
                        >
                          <Card className="h-full border-0 shadow-md hover:shadow-xl transition-all duration-300 overflow-hidden">
                            <CardHeader className="pb-4">
                              <div className="flex items-center gap-3">
                                <motion.div
                                  animate={{ rotate: [0, 10, -10, 0] }}
                                  transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
                                  className="text-3xl"
                                >
                                  {catalogService.logo}
                                </motion.div>
                                <div className="flex-1">
                                  <CardTitle className="text-lg font-bold">{catalogService.name}</CardTitle>
                                  {catalogService.popular && (
                                    <Badge className="bg-gradient-to-r from-amber-500 to-orange-500 text-white border-0 mt-1">
                                      <Sparkles className="w-3 h-3 mr-1" />
                                      Populaire
                                    </Badge>
                                  )}
                                </div>
                              </div>
                            </CardHeader>
                            <CardContent className="space-y-4">
                              <p className="text-gray-600 text-sm leading-relaxed">
                                {catalogService.description}
                              </p>
                              
                              {catalogService.features && (
                                <div className="space-y-2">
                                  <p className="text-xs font-semibold text-gray-700">Fonctionnalités:</p>
                                  <div className="flex flex-wrap gap-1">
                                    {catalogService.features.map((feature) => (
                                      <Badge key={feature} variant="secondary" className="text-xs">
                                        {feature}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>
                              )}
                              
                              <Badge variant="outline" className="w-fit">
                                {catalogService.category}
                              </Badge>
                              
                              <Button 
                                className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 shadow-md hover:shadow-lg transition-all duration-300"
                                onClick={() => handleConnectService(catalogService)}
                              >
                                <Zap className="w-4 h-4 mr-2" />
                                Connecter
                              </Button>
                            </CardContent>
                          </Card>
                        </motion.div>
                      ))}
                    </div>
                  </DialogContent>
                </Dialog>
              </div>
            </div>
          </motion.div>

          {/* Results Count */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            className="flex items-center justify-between"
          >
            <p className="text-gray-600">
              <span className="font-semibold text-gray-900">{filteredServices.length}</span> service{filteredServices.length > 1 ? 's' : ''} trouvé{filteredServices.length > 1 ? 's' : ''}
            </p>
          </motion.div>

          {/* Services Grid/List */}
          <div className={viewMode === "grid" ? 
            "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" : 
            "space-y-4"
          }>
            <AnimatePresence mode="popLayout">
              {filteredServices.map((service) => (
                <ModernServiceCard
                  key={service.id}
                  service={service}
                  onManage={handleManage}
                  onDisconnect={handleDisconnect}
                  onRegenerate={handleRegenerate}
                  viewMode={viewMode}
                />
              ))}
            </AnimatePresence>
          </div>

          {/* Empty State */}
          {filteredServices.length === 0 && (
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-center py-20"
            >
              <div className="max-w-md mx-auto space-y-6">
                <div className="w-24 h-24 bg-gray-100 rounded-full flex items-center justify-center mx-auto">
                  <Boxes className="w-12 h-12 text-gray-400" />
                </div>
                <div>
                  <h3 className="text-xl font-semibold text-gray-900 mb-2">
                    Aucun service trouvé
                  </h3>
                  <p className="text-gray-600 mb-6">
                    Essayez d'ajuster vos filtres ou de connecter un nouveau service.
                  </p>
                  <Dialog>
                    <DialogTrigger asChild>
                      <Button className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700">
                        <Plus className="w-4 h-4 mr-2" />
                        Connecter votre premier service
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      {/* Same catalog content as above */}
                    </DialogContent>
                  </Dialog>
                </div>
              </div>
            </motion.div>
          )}

          {/* Service Management Dialog */}
          {selectedService && (
            <Dialog open={!!selectedService} onOpenChange={() => setSelectedService(null)}>
              <DialogContent className="max-w-3xl">
                <DialogHeader>
                  <DialogTitle className="flex items-center gap-3 text-2xl font-bold">
                    <span className="text-3xl">{selectedService.logo}</span>
                    Gérer {selectedService.name}
                  </DialogTitle>
                  <DialogDescription>
                    Configurez les paramètres, gérez les identifiants et contrôlez l'accès pour ce service.
                  </DialogDescription>
                </DialogHeader>
                
                <Tabs defaultValue="overview" className="mt-6">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="overview">Aperçu</TabsTrigger>
                    <TabsTrigger value="config">Configuration</TabsTrigger>
                    <TabsTrigger value="security">Sécurité</TabsTrigger>
                    <TabsTrigger value="logs">Journaux</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="overview" className="space-y-6">
                    <div className="grid grid-cols-2 gap-6">
                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center gap-2">
                            <Activity className="w-5 h-5" />
                            État de santé
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          <div className="flex items-center justify-between">
                            <span>Statut</span>
                            <Badge className={
                              selectedService.status === 'healthy' ? 'bg-emerald-100 text-emerald-800' :
                              selectedService.status === 'degraded' ? 'bg-amber-100 text-amber-800' :
                              'bg-red-100 text-red-800'
                            }>
                              {selectedService.status}
                            </Badge>
                          </div>
                          <div className="flex items-center justify-between">
                            <span>Latence</span>
                            <span className="font-mono">{selectedService.metrics?.latency}ms</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span>Disponibilité</span>
                            <span className="font-mono">{selectedService.metrics?.uptime}%</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span>Taux d'erreur</span>
                            <span className="font-mono">{selectedService.metrics?.errorRate}%</span>
                          </div>
                        </CardContent>
                      </Card>
                      
                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center gap-2">
                            <BarChart3 className="w-5 h-5" />
                            Performance
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          <div className="flex items-center justify-between">
                            <span>Requêtes/jour</span>
                            <span className="font-mono">{(selectedService.metrics?.requests || 0).toLocaleString()}</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span>Dernière vérification</span>
                            <span className="font-mono text-sm">{selectedService.lastHeartbeat.toLocaleString()}</span>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="config" className="space-y-6">
                    <Card>
                      <CardHeader>
                        <CardTitle>Configuration du service</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {selectedService.config ? (
                          <div className="space-y-4">
                            {Object.entries(selectedService.config).map(([key, value]) => (
                              <div key={key} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                                <div>
                                  <p className="font-medium capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</p>
                                  <p className="text-sm text-gray-500">
                                    {typeof value === 'boolean' ? (value ? 'Activé' : 'Désactivé') : `Valeur: ${value}`}
                                  </p>
                                </div>
                                {typeof value === 'boolean' ? (
                                  <Switch checked={value} />
                                ) : (
                                  <Button size="sm" variant="outline">
                                    Modifier
                                  </Button>
                                )}
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-gray-500">Aucune configuration disponible</p>
                        )}
                      </CardContent>
                    </Card>
                  </TabsContent>
                  
                  <TabsContent value="security" className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center gap-2">
                            <Key className="w-5 h-5" />
                            Clés API
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          <div className="p-4 bg-amber-50 border border-amber-200 rounded-lg">
                            <div className="flex items-center justify-between">
                              <div>
                                <p className="font-medium">Clé principale</p>
                                <p className="text-sm text-gray-600 font-mono">•••••••••••••••••</p>
                              </div>
                              <Button size="sm" variant="outline">
                                <Eye className="w-4 h-4" />
                              </Button>
                            </div>
                          </div>
                          <Button className="w-full">
                            <RotateCcw className="w-4 h-4 mr-2" />
                            Régénérer la clé
                          </Button>
                        </CardContent>
                      </Card>
                      
                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center gap-2">
                            <Shield className="w-5 h-5" />
                            Contrôle d'accès
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          <div className="flex items-center justify-between">
                            <span>Authentification à deux facteurs</span>
                            <Switch />
                          </div>
                          <div className="flex items-center justify-between">
                            <span>Rotation automatique des clés</span>
                            <Switch defaultChecked />
                          </div>
                          <div className="flex items-center justify-between">
                            <span>Limites de débit</span>
                            <span className="text-sm text-gray-600">1000 req/min</span>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="logs" className="space-y-6">
                    <Card>
                      <CardHeader>
                        <CardTitle>Journal d'activité</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Timestamp</TableHead>
                              <TableHead>Acteur</TableHead>
                              <TableHead>Action</TableHead>
                              <TableHead>Détails</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {mockAuditLogs
                              .filter(log => log.service === selectedService.name)
                              .map((log) => (
                                <TableRow key={log.id}>
                                  <TableCell className="text-sm">
                                    {log.timestamp.toLocaleString()}
                                  </TableCell>
                                  <TableCell className="text-sm">{log.actor}</TableCell>
                                  <TableCell className="text-sm font-medium">{log.action}</TableCell>
                                  <TableCell className="text-sm text-gray-600 max-w-xs truncate">
                                    {log.details}
                                  </TableCell>
                                </TableRow>
                              ))}
                          </TableBody>
                        </Table>
                      </CardContent>
                    </Card>
                  </TabsContent>
                </Tabs>
              </DialogContent>
            </Dialog>
          )}
        </div>
      </div>
    </TooltipProvider>
  );
}