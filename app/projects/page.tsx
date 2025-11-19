"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import CreateProjectDialog from "@/components/ui/CreateProjectDialog";
import ProjectSettingsDialog from "@/components/ui/ProjectSettingsDialog";
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
  Activity,
  Cog,
  Key,
  Plus,
  Search,
  Filter,
  MoreHorizontal,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Clock,
  ExternalLink,
  Eye,
  Settings,
  Trash2,
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
  },
];

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
  dev: { color: "bg-blue-100 text-blue-700", label: "Dev" },
  staging: { color: "bg-yellow-100 text-yellow-700", label: "Staging" },
  prod: { color: "bg-green-100 text-green-700", label: "Prod" },
};

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>(mockProjects);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedStatus, setSelectedStatus] = useState<string>("all");
  const [selectedEnvironment, setSelectedEnvironment] = useState<string>("all");
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  const filteredProjects = projects.filter((project) => {
    const matchesSearch = project.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         project.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         project.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
    
    const matchesStatus = selectedStatus === "all" || project.status === selectedStatus;
    const matchesEnvironment = selectedEnvironment === "all" || 
                              project.environments.includes(selectedEnvironment as any);

    return matchesSearch && matchesStatus && matchesEnvironment;
  });

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
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Projects</h1>
            <p className="text-gray-600 mt-1">
              Manage and monitor all your organization projects
            </p>
          </div>
          <Button 
            className="bg-blue-600 hover:bg-blue-700"
            onClick={() => setIsCreateDialogOpen(true)}
          >
            <Plus className="h-4 w-4 mr-2" />
            Create Project
          </Button>
        </div>
      </motion.div>

      {/* Search and Filters */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
        className="mb-6"
      >
        <div className="flex flex-col lg:flex-row gap-4">
          {/* Search Bar */}
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              placeholder="Search projects..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>

          {/* Filters */}
          <div className="flex gap-2">
            {/* Status Filter */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="gap-2">
                  <Filter className="h-4 w-4" />
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

            {/* Environment Filter */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="gap-2">
                  <Layers className="h-4 w-4" />
                  Environment: {selectedEnvironment === "all" ? "All" : selectedEnvironment}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem onClick={() => setSelectedEnvironment("all")}>
                  All Environments
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setSelectedEnvironment("dev")}>
                  <div className="w-3 h-3 bg-blue-100 rounded-full mr-2" />
                  Development
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setSelectedEnvironment("staging")}>
                  <div className="w-3 h-3 bg-yellow-100 rounded-full mr-2" />
                  Staging
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setSelectedEnvironment("prod")}>
                  <div className="w-3 h-3 bg-green-100 rounded-full mr-2" />
                  Production
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </motion.div>

      {/* Projects Grid */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
      >
        {filteredProjects.map((project) => {
          const StatusIcon = statusConfig[project.status].icon;
          
          return (
            <motion.div
              key={project.id}
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
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-blue-100 rounded-lg">
                        <Folder className="h-5 w-5 text-blue-600" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <CardTitle className="text-lg font-semibold text-gray-900 truncate">
                          {project.name}
                        </CardTitle>
                        <CardDescription className="text-sm text-gray-600 line-clamp-2">
                          {project.description}
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
                            setSelectedProject(project);
                            console.log("Opening project details:", project.name);
                            // Here you would navigate to project details page
                            // router.push(`/projects/${project.id}/overview`);
                          }}
                          className="flex items-center gap-2"
                        >
                          <Eye className="h-4 w-4" />
                          <span>View Details</span>
                        </DropdownMenuItem>
                        <DropdownMenuItem 
                          onClick={() => {
                            setSelectedProject(project);
                            setIsSettingsOpen(true);
                          }}
                          className="flex items-center gap-2"
                        >
                          <Settings className="h-4 w-4" />
                          <span>Settings</span>
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem 
                          onClick={async () => {
                            if (window.confirm(`Are you sure you want to delete "${project.name}"? This action cannot be undone.`)) {
                              console.log("Deleting project:", project.name);
                              // Here you would call the delete API
                              // await deleteProject(project.id);
                              
                              // Remove from projects list
                              setProjects(prev => prev.filter((p: Project) => p.id !== project.id));
                              
                              // Show success message (in real app, you'd use a toast)
                              alert(`Project "${project.name}" has been deleted successfully.`);
                            }
                          }}
                          className="flex items-center gap-2 text-red-600 focus:text-red-600"
                        >
                          <Trash2 className="h-4 w-4" />
                          <span>Delete Project</span>
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </CardHeader>

                <CardContent className="space-y-4">
                  {/* Status and Environments */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <StatusIcon className={`h-4 w-4 ${statusConfig[project.status].color}`} />
                      <span className={`text-sm font-medium ${statusConfig[project.status].color}`}>
                        {project.status.charAt(0).toUpperCase() + project.status.slice(1)}
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

                  {/* Services */}
                  <div>
                    <div className="text-sm font-medium text-gray-700 mb-2">Connected Services</div>
                    <div className="flex flex-wrap gap-1">
                      {project.services.slice(0, 3).map((service) => (
                        <Badge
                          key={service.name}
                          variant="outline"
                          className={`text-xs ${
                            service.status === "connected" 
                              ? "border-green-200 text-green-700" 
                              : "border-gray-200 text-gray-500"
                          }`}
                        >
                          <Server className="h-3 w-3 mr-1" />
                          {service.name}
                        </Badge>
                      ))}
                      {project.services.length > 3 && (
                        <Badge variant="outline" className="text-xs">
                          +{project.services.length - 3} more
                        </Badge>
                      )}
                    </div>
                  </div>

                  {/* Tags */}
                  <div>
                    <div className="flex flex-wrap gap-1">
                      {project.tags.map((tag) => (
                        <Badge
                          key={tag}
                          variant="secondary"
                          className="text-xs bg-gray-100 text-gray-700"
                        >
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Last Activity */}
                  <div className="flex items-center justify-between pt-2 border-t border-gray-100">
                    <div className="flex items-center gap-2 text-sm text-gray-500">
                      <Clock className="h-3 w-3" />
                      Last activity: {project.lastActivity}
                    </div>
                    <div className="text-xs text-gray-400">
                      Created {project.createdAt}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          );
        })}
      </motion.div>

      {/* Empty State */}
      {filteredProjects.length === 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center py-12"
        >
          <Folder className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No projects found</h3>
          <p className="text-gray-600 mb-4">
            Try adjusting your search or filters to find what you're looking for.
          </p>
          <Button variant="outline">
            Clear all filters
          </Button>
        </motion.div>
      )}
      
      {/* Create Project Dialog */}
      <CreateProjectDialog
        open={isCreateDialogOpen}
        onOpenChange={setIsCreateDialogOpen}
        onProjectCreated={(newProject) => {
          console.log("New project created:", newProject);
          // Here you would typically update the projects list
          // or redirect to the new project page
        }}
      />

      {/* Project Settings Dialog */}
      {selectedProject && (
        <ProjectSettingsDialog
          open={isSettingsOpen}
          onOpenChange={setIsSettingsOpen}
          project={selectedProject}
          onProjectUpdated={(updatedProject) => {
            console.log("Project updated:", updatedProject);
            // Here you would typically update the project in the list
            setSelectedProject(null);
          }}
        />
      )}
    </div>
  );
}