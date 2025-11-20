"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Folder,
  Layers,
  Server,
  Plus,
  Search,
  Filter,
  MoreHorizontal,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Clock,
  Eye,
  Trash2,
  Grid3X3,
  List,
  Users,
  Zap,
  Shield,
  Database,
  Star,
  Copy,
  Edit,
  BarChart3,
} from "lucide-react";

interface Project {
  id: string;
  name: string;
  description: string;
  status: "healthy" | "warning" | "critical";
  environments: Array<"dev" | "staging" | "prod">;
  services: Array<{
    name: string;
    status: "connected" | "disconnected";
    endpoint?: string;
  }>;
  lastActivity: string;
  createdAt: string;
  tags: string[];
  team: number;
  requests: number;
  uptime: number;
  starred: boolean;
}

const mockProjects: Project[] = [
  {
    id: "1",
    name: "E-commerce Platform",
    description: "Production e-commerce platform with real-time inventory management",
    status: "healthy",
    environments: ["dev", "staging", "prod"],
    services: [
      { name: "Grafana", status: "connected", endpoint: "grafana.example.com" },
      { name: "Prometheus", status: "connected", endpoint: "prometheus.example.com" },
      { name: "MinIO", status: "connected", endpoint: "minio.example.com" },
    ],
    lastActivity: "2 minutes ago",
    createdAt: "2024-01-15",
    tags: ["production", "e-commerce", "high-traffic"],
    team: 8,
    requests: 15420,
    uptime: 99.9,
    starred: true,
  },
  {
    id: "2",
    name: "Mobile App Backend",
    description: "Backend services for iOS and Android mobile applications",
    status: "warning",
    environments: ["dev", "staging"],
    services: [
      { name: "Grafana", status: "connected", endpoint: "grafana.mobile.example.com" },
      { name: "Prometheus", status: "disconnected" },
      { name: "Vault", status: "connected", endpoint: "vault.mobile.example.com" },
    ],
    lastActivity: "15 minutes ago",
    createdAt: "2024-02-20",
    tags: ["mobile", "backend", "api"],
    team: 5,
    requests: 8930,
    uptime: 98.7,
    starred: false,
  },
  {
    id: "3",
    name: "Analytics Service",
    description: "Data processing and analytics pipeline for business intelligence",
    status: "healthy",
    environments: ["dev", "prod"],
    services: [
      { name: "Grafana", status: "connected", endpoint: "grafana.analytics.example.com" },
      { name: "Loki", status: "connected", endpoint: "loki.analytics.example.com" },
    ],
    lastActivity: "1 hour ago",
    createdAt: "2024-03-10",
    tags: ["analytics", "data", "pipeline"],
    team: 6,
    requests: 12450,
    uptime: 99.5,
    starred: true,
  },
  {
    id: "4",
    name: "Admin Dashboard",
    description: "Internal administration dashboard for system management",
    status: "critical",
    environments: ["dev"],
    services: [
      { name: "Grafana", status: "disconnected" },
      { name: "Prometheus", status: "disconnected" },
    ],
    lastActivity: "3 hours ago",
    createdAt: "2024-01-05",
    tags: ["admin", "internal", "dashboard"],
    team: 3,
    requests: 2340,
    uptime: 95.2,
    starred: false,
  },
  {
    id: "5",
    name: "API Gateway",
    description: "Central API gateway for microservices architecture",
    status: "healthy",
    environments: ["dev", "staging", "prod"],
    services: [
      { name: "Grafana", status: "connected", endpoint: "grafana.gateway.example.com" },
      { name: "Prometheus", status: "connected", endpoint: "prometheus.gateway.example.com" },
      { name: "MinIO", status: "connected", endpoint: "minio.gateway.example.com" },
      { name: "Vault", status: "connected", endpoint: "vault.gateway.example.com" },
    ],
    lastActivity: "5 minutes ago",
    createdAt: "2024-02-01",
    tags: ["gateway", "microservices", "api"],
    team: 12,
    requests: 28930,
    uptime: 99.8,
    starred: false,
  },
];

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
  dev: { color: "bg-blue-100 text-blue-700", label: "Dev", icon: Database },
  staging: { color: "bg-yellow-100 text-yellow-700", label: "Staging", icon: Zap },
  prod: { color: "bg-green-100 text-green-700", label: "Prod", icon: Shield },
};

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>(mockProjects);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedStatus, setSelectedStatus] = useState<string>("all");
  const [selectedEnvironment, setSelectedEnvironment] = useState<string>("all");
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");
  const [sortBy, setSortBy] = useState<"name" | "created" | "updated" | "status">("updated");
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);

  const filteredAndSortedProjects = projects
    .filter((project) => {
      const matchesSearch = project.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           project.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           project.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
      
      const matchesStatus = selectedStatus === "all" || project.status === selectedStatus;
      const matchesEnvironment = selectedEnvironment === "all" || 
                                project.environments.includes(selectedEnvironment as any);
      
      return matchesSearch && matchesStatus && matchesEnvironment;
    })
    .sort((a, b) => {
      switch (sortBy) {
        case "name":
          return a.name.localeCompare(b.name);
        case "created":
          return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
        case "updated":
          return 0; // Would sort by lastActivity in real app
        case "status":
          const statusOrder = { critical: 0, warning: 1, healthy: 2 };
          return statusOrder[a.status] - statusOrder[b.status];
        default:
          return 0;
      }
    });

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.05,
      },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.3,
      },
    },
  };

  const toggleStar = (projectId: string) => {
    setProjects(prev => prev.map(p => 
      p.id === projectId ? { ...p, starred: !p.starred } : p
    ));
  };



  return (
    <div className="min-h-full bg-white">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="border-b border-gray-200 bg-white"
      >
        <div className="px-6 py-4">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="p-2 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl">
                <Folder className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Projects</h1>
                <p className="text-sm text-gray-600">
                  {projects.length} active projects • {projects.reduce((sum, p) => sum + p.team, 0)} team members
                </p>
              </div>
            </div>
            
            <div className="flex items-center gap-3">
              <Button 
                onClick={() => setIsCreateDialogOpen(true)}
                className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
              >
                <Plus className="h-4 w-4 mr-2" />
                New Project
              </Button>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Filters and Controls */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
        className="border-b border-gray-100 bg-gray-50/50"
      >
        <div className="px-6 py-4">
          <div className="flex flex-col xl:flex-row gap-4">
            {/* Search Bar */}
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search projects by name, description, or tags..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 bg-white"
              />
            </div>

            <div className="flex items-center gap-2">
              {/* Status Filter */}
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" className="gap-2 bg-white">
                    <Filter className="h-4 w-4" />
                    Status: {selectedStatus === "all" ? "All" : statusConfig[selectedStatus as keyof typeof statusConfig]?.label}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuItem onClick={() => setSelectedStatus("all")}>
                    All Status
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setSelectedStatus("healthy")}>
                    <CheckCircle className="h-4 w-4 mr-2 text-emerald-600" />
                    Healthy
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setSelectedStatus("warning")}>
                    <AlertTriangle className="h-4 w-4 mr-2 text-amber-600" />
                    Warning
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setSelectedStatus("critical")}>
                    <XCircle className="h-4 w-4 mr-2 text-red-600" />
                    Critical
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>

              {/* Environment Filter */}
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" className="gap-2 bg-white">
                    <Layers className="h-4 w-4" />
                    Environment: {selectedEnvironment === "all" ? "All" : environmentConfig[selectedEnvironment as keyof typeof environmentConfig]?.label}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuItem onClick={() => setSelectedEnvironment("all")}>
                    All Environments
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setSelectedEnvironment("dev")}>
                    <Database className="h-4 w-4 mr-2 text-blue-600" />
                    Development
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setSelectedEnvironment("staging")}>
                    <Zap className="h-4 w-4 mr-2 text-amber-600" />
                    Staging
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setSelectedEnvironment("prod")}>
                    <Shield className="h-4 w-4 mr-2 text-green-600" />
                    Production
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>

              {/* Sort */}
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" className="gap-2 bg-white">
                    <BarChart3 className="h-4 w-4" />
                    Sort by {sortBy}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuItem onClick={() => setSortBy("name")}>Name</DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setSortBy("created")}>Created</DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setSortBy("updated")}>Last Updated</DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setSortBy("status")}>Status</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>

              {/* View Mode Toggle */}
              <div className="flex items-center border border-gray-200 rounded-lg bg-white">
                <Button
                  variant={viewMode === "grid" ? "default" : "ghost"}
                  size="sm"
                  onClick={() => setViewMode("grid")}
                  className="rounded-r-none"
                >
                  <Grid3X3 className="h-4 w-4" />
                </Button>
                <Button
                  variant={viewMode === "list" ? "default" : "ghost"}
                  size="sm"
                  onClick={() => setViewMode("list")}
                  className="rounded-l-none"
                >
                  <List className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Projects Display */}
      <div className="p-6">
        <AnimatePresence mode="wait">
          {filteredAndSortedProjects.length === 0 ? (
            <motion.div
              key="empty"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="text-center py-16"
            >
              <div className="mx-auto w-24 h-24 bg-gray-100 rounded-full flex items-center justify-center mb-6">
                <Folder className="h-12 w-12 text-gray-400" />
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-2">No projects found</h3>
              <p className="text-gray-600 mb-6 max-w-md mx-auto">
                Try adjusting your search or filters, or create a new project to get started.
              </p>
              <Button onClick={() => setIsCreateDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />
                Create Your First Project
              </Button>
            </motion.div>
          ) : (
            <motion.div
              key="projects"
              variants={containerVariants}
              initial="hidden"
              animate="visible"
              className={
                viewMode === "grid" 
                  ? "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6"
                  : "space-y-4"
              }
            >
              {filteredAndSortedProjects.map((project) => {
                const StatusIcon = statusConfig[project.status].icon;
                
                return viewMode === "grid" ? (
                  <motion.div
                    key={project.id}
                    variants={itemVariants}
                    layout
                    whileHover={{ 
                      scale: 1.02, 
                      boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1)" 
                    }}
                    className="group"
                  >
                    <Card className="h-full hover:shadow-xl transition-all duration-300 cursor-pointer border-gray-200 overflow-hidden">
                      {/* Header */}
                      <div className="p-6 pb-4">
                        <div className="flex items-start justify-between mb-4">
                          <div className="flex items-center gap-3">
                            <div className="p-2 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg">
                              <Folder className="h-5 w-5 text-white" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <h3 className="font-semibold text-gray-900 truncate group-hover:text-blue-600 transition-colors">
                                {project.name}
                              </h3>
                              <p className="text-sm text-gray-600 line-clamp-2 mt-1">
                                {project.description}
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center gap-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                toggleStar(project.id);
                              }}
                              className="h-8 w-8 p-0"
                            >
                              <Star className={`h-4 w-4 ${project.starred ? 'fill-yellow-400 text-yellow-400' : 'text-gray-400'}`} />
                            </Button>
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button 
                                  variant="ghost" 
                                  size="sm" 
                                  className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
                                  onClick={(e) => e.stopPropagation()}
                                >
                                  <MoreHorizontal className="h-4 w-4" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end" className="w-48">
                                <DropdownMenuItem onClick={(e) => e.stopPropagation()}>
                                  <Eye className="h-4 w-4 mr-2" />
                                  View Details
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={(e) => e.stopPropagation()}>
                                  <Edit className="h-4 w-4 mr-2" />
                                  Edit Project
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={(e) => e.stopPropagation()}>
                                  <Copy className="h-4 w-4 mr-2" />
                                  Copy ID
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem 
                                  onClick={(e) => e.stopPropagation()}
                                  className="text-red-600 focus:text-red-600"
                                >
                                  <Trash2 className="h-4 w-4 mr-2" />
                                  Delete Project
                                </DropdownMenuItem>
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </div>
                        </div>

                        {/* Status and Environments */}
                        <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center gap-2">
                            <StatusIcon className={`h-4 w-4 ${statusConfig[project.status].color}`} />
                            <span className={`text-sm font-medium ${statusConfig[project.status].color}`}>
                              {statusConfig[project.status].label}
                            </span>
                          </div>
                          <div className="flex gap-1">
                            {project.environments.map((env) => (
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

                        {/* Metrics */}
                        <div className="grid grid-cols-3 gap-3 mb-4">
                          <div className="text-center">
                            <div className="text-lg font-bold text-gray-900">{project.requests.toLocaleString()}</div>
                            <div className="text-xs text-gray-500">Requests</div>
                          </div>
                          <div className="text-center">
                            <div className="text-lg font-bold text-gray-900">{project.uptime}%</div>
                            <div className="text-xs text-gray-500">Uptime</div>
                          </div>
                          <div className="text-center">
                            <div className="text-lg font-bold text-gray-900">{project.team}</div>
                            <div className="text-xs text-gray-500">Team</div>
                          </div>
                        </div>

                        {/* Services */}
                        <div className="mb-4">
                          <div className="text-sm font-medium text-gray-700 mb-2">Services</div>
                          <div className="flex flex-wrap gap-1">
                            {project.services.slice(0, 3).map((service) => (
                              <Badge
                                key={service.name}
                                variant="outline"
                                className={`text-xs ${
                                  service.status === "connected" 
                                    ? "border-emerald-200 text-emerald-700 bg-emerald-50" 
                                    : "border-gray-200 text-gray-500 bg-gray-50"
                                }`}
                              >
                                <Server className="h-3 w-3 mr-1" />
                                {service.name}
                              </Badge>
                            ))}
                            {project.services.length > 3 && (
                              <Badge variant="outline" className="text-xs">
                                +{project.services.length - 3}
                              </Badge>
                            )}
                          </div>
                        </div>

                        {/* Tags */}
                        <div className="flex flex-wrap gap-1">
                          {project.tags.slice(0, 2).map((tag) => (
                            <Badge
                              key={tag}
                              variant="secondary"
                              className="text-xs bg-gray-100 text-gray-700"
                            >
                              {tag}
                            </Badge>
                          ))}
                          {project.tags.length > 2 && (
                            <Badge variant="secondary" className="text-xs bg-gray-100 text-gray-700">
                              +{project.tags.length - 2}
                            </Badge>
                          )}
                        </div>
                      </div>

                      {/* Footer */}
                      <div className="px-6 py-3 bg-gray-50 border-t border-gray-100">
                        <div className="flex items-center justify-between text-xs text-gray-500">
                          <div className="flex items-center gap-2">
                            <Clock className="h-3 w-3" />
                            {project.lastActivity}
                          </div>
                          <div>Created {project.createdAt}</div>
                        </div>
                      </div>
                    </Card>
                  </motion.div>
                ) : (
                  // List view implementation would go here
                  <motion.div
                    key={project.id}
                    variants={itemVariants}
                    layout
                    className="group"
                  >
                    <Card className="hover:shadow-lg transition-all duration-300 cursor-pointer">
                      <CardContent className="p-6">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4 flex-1">
                            <div className="p-2 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg">
                              <Folder className="h-5 w-5 text-white" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-3">
                                <h3 className="font-semibold text-gray-900 truncate group-hover:text-blue-600 transition-colors">
                                  {project.name}
                                </h3>
                                <StatusIcon className={`h-4 w-4 ${statusConfig[project.status].color}`} />
                                <div className="flex gap-1">
                                  {project.environments.map((env) => (
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
                              <p className="text-sm text-gray-600 mt-1">{project.description}</p>
                              <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                                <span>{project.requests.toLocaleString()} requests</span>
                                <span>{project.uptime}% uptime</span>
                                <span>{project.team} team members</span>
                                <span>Last activity: {project.lastActivity}</span>
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => toggleStar(project.id)}
                              className="h-8 w-8 p-0"
                            >
                              <Star className={`h-4 w-4 ${project.starred ? 'fill-yellow-400 text-yellow-400' : 'text-gray-400'}`} />
                            </Button>
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                  <MoreHorizontal className="h-4 w-4" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                <DropdownMenuItem>
                                  <Eye className="h-4 w-4 mr-2" />
                                  View Details
                                </DropdownMenuItem>
                                <DropdownMenuItem>
                                  <Edit className="h-4 w-4 mr-2" />
                                  Edit Project
                                </DropdownMenuItem>
                                <DropdownMenuItem>
                                  <Copy className="h-4 w-4 mr-2" />
                                  Copy ID
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem className="text-red-600 focus:text-red-600">
                                  <Trash2 className="h-4 w-4 mr-2" />
                                  Delete Project
                                </DropdownMenuItem>
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </motion.div>
                );
              })}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Create Project Dialog would go here */}
      {/* For now, we'll just show a placeholder */}
      {isCreateDialogOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h2 className="text-xl font-bold mb-4">Create New Project</h2>
            <p className="text-gray-600 mb-6">Project creation dialog would be implemented here.</p>
            <div className="flex justify-end gap-3">
              <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={() => setIsCreateDialogOpen(false)}>
                Create Project
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}