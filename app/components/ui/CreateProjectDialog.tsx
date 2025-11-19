"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Plus,
  X,
  Layers,
  Server,
  Check,
} from "lucide-react";

interface CreateProjectDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onProjectCreated?: (project: any) => void;
}

const availableServices = [
  { id: "grafana", name: "Grafana", description: "Monitoring dashboards" },
  { id: "prometheus", name: "Prometheus", description: "Metrics collection" },
  { id: "minio", name: "MinIO", description: "Object storage" },
  { id: "vault", name: "Vault", description: "Secret management" },
  { id: "loki", name: "Loki", description: "Log aggregation" },
  { id: "postgres", name: "PostgreSQL", description: "Database" },
  { id: "redis", name: "Redis", description: "Cache storage" },
];

const commonTags = [
  "production",
  "development",
  "api",
  "web",
  "mobile",
  "analytics",
  "e-commerce",
  "microservices",
  "internal",
  "external",
];

export default function CreateProjectDialog({ 
  open, 
  onOpenChange, 
  onProjectCreated 
}: CreateProjectDialogProps) {
  const [formData, setFormData] = useState({
    name: "",
    description: "",
    environments: ["dev"],
    services: [] as string[],
    tags: [] as string[],
  });
  
  const [currentTag, setCurrentTag] = useState("");
  const [isCreating, setIsCreating] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsCreating(true);

    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1500));

    const newProject = {
      id: Date.now().toString(),
      ...formData,
      status: "healthy",
      createdAt: new Date().toISOString().split('T')[0],
      lastActivity: "Just now",
      services: formData.services.map(serviceId => {
        const service = availableServices.find(s => s.id === serviceId);
        return {
          name: service?.name || serviceId,
          status: "connected" as const,
          endpoint: `${serviceId}.example.com`,
        };
      }),
    };

    onProjectCreated?.(newProject);
    
    // Reset form
    setFormData({
      name: "",
      description: "",
      environments: ["dev"],
      services: [],
      tags: [],
    });
    setCurrentTag("");
    setIsCreating(false);
    onOpenChange(false);
  };

  const addTag = () => {
    if (currentTag.trim() && !formData.tags.includes(currentTag.trim())) {
      setFormData(prev => ({
        ...prev,
        tags: [...prev.tags, currentTag.trim()]
      }));
      setCurrentTag("");
    }
  };

  const removeTag = (tagToRemove: string) => {
    setFormData(prev => ({
      ...prev,
      tags: prev.tags.filter(tag => tag !== tagToRemove)
    }));
  };

  const toggleEnvironment = (env: string) => {
    setFormData(prev => ({
      ...prev,
      environments: prev.environments.includes(env)
        ? prev.environments.filter(e => e !== env)
        : [...prev.environments, env]
    }));
  };

  const toggleService = (serviceId: string) => {
    setFormData(prev => ({
      ...prev,
      services: prev.services.includes(serviceId)
        ? prev.services.filter(s => s !== serviceId)
        : [...prev.services, serviceId]
    }));
  };

  const dialogVariants = {
    hidden: { opacity: 0, scale: 0.95 },
    visible: { 
      opacity: 1, 
      scale: 1,
      transition: {
        duration: 0.2,
        ease: [0.4, 0, 0.2, 1] as const,
      }
    },
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <motion.div
          variants={dialogVariants}
          initial="hidden"
          animate="visible"
          exit="hidden"
        >
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <div className="p-2 bg-blue-100 rounded-lg">
                <Plus className="h-5 w-5 text-blue-600" />
              </div>
              Create New Project
            </DialogTitle>
            <DialogDescription>
              Set up a new project with environments, services, and configurations.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Basic Information */}
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium text-gray-900 mb-2 block">
                  Project Name *
                </label>
                <Input
                  placeholder="e.g., E-commerce Platform"
                  value={formData.name}
                  onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                  required
                  className="w-full"
                />
              </div>

              <div>
                <label className="text-sm font-medium text-gray-900 mb-2 block">
                  Description
                </label>
                <Textarea
                  placeholder="Describe what this project does..."
                  value={formData.description}
                  onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                  rows={3}
                  className="w-full resize-none"
                />
              </div>
            </div>

            {/* Environments */}
            <div>
              <label className="text-sm font-medium text-gray-900 mb-3 block">
                <Layers className="h-4 w-4 inline mr-2" />
                Environments
              </label>
              <div className="flex flex-wrap gap-2">
                {["dev", "staging", "prod"].map((env) => (
                  <Button
                    key={env}
                    type="button"
                    variant={formData.environments.includes(env) ? "default" : "outline"}
                    size="sm"
                    onClick={() => toggleEnvironment(env)}
                    className="capitalize"
                  >
                    {env}
                    {formData.environments.includes(env) && (
                      <Check className="h-3 w-3 ml-1" />
                    )}
                  </Button>
                ))}
              </div>
            </div>

            {/* Services */}
            <div>
              <label className="text-sm font-medium text-gray-900 mb-3 block">
                <Server className="h-4 w-4 inline mr-2" />
                Connected Services
              </label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {availableServices.map((service) => (
                  <Button
                    key={service.id}
                    type="button"
                    variant={formData.services.includes(service.id) ? "default" : "outline"}
                    size="sm"
                    onClick={() => toggleService(service.id)}
                    className="justify-start h-auto p-3"
                  >
                    <div className="flex items-center w-full">
                      <div className="w-2 h-2 rounded-full bg-blue-500 mr-3" />
                      <div className="text-left">
                        <div className="font-medium">{service.name}</div>
                        <div className="text-xs text-gray-500">{service.description}</div>
                      </div>
                      {formData.services.includes(service.id) && (
                        <Check className="h-4 w-4 ml-auto" />
                      )}
                    </div>
                  </Button>
                ))}
              </div>
            </div>

            {/* Tags */}
            <div>
              <label className="text-sm font-medium text-gray-900 mb-3 block">
                Tags
              </label>
              <div className="space-y-3">
                <div className="flex gap-2">
                  <Input
                    placeholder="Add a tag..."
                    value={currentTag}
                    onChange={(e) => setCurrentTag(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        addTag();
                      }
                    }}
                    className="flex-1"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={addTag}
                    disabled={!currentTag.trim()}
                  >
                    Add
                  </Button>
                </div>

                {/* Common Tags */}
                <div className="flex flex-wrap gap-2">
                  {commonTags.slice(0, 6).map((tag) => (
                    <Badge
                      key={tag}
                      variant="secondary"
                      className="cursor-pointer hover:bg-gray-200"
                      onClick={() => {
                        if (!formData.tags.includes(tag)) {
                          setFormData(prev => ({
                            ...prev,
                            tags: [...prev.tags, tag]
                          }));
                        }
                      }}
                    >
                      {tag}
                    </Badge>
                  ))}
                </div>

                {/* Selected Tags */}
                {formData.tags.length > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {formData.tags.map((tag) => (
                      <Badge
                        key={tag}
                        variant="default"
                        className="bg-blue-100 text-blue-700 hover:bg-blue-200"
                      >
                        {tag}
                        <button
                          type="button"
                          onClick={() => removeTag(tag)}
                          className="ml-1 hover:text-blue-900"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <DialogFooter className="flex gap-3 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={isCreating}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={!formData.name.trim() || isCreating}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {isCreating ? (
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Creating...
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <Plus className="h-4 w-4" />
                    Create Project
                  </div>
                )}
              </Button>
            </DialogFooter>
          </form>
        </motion.div>
      </DialogContent>
    </Dialog>
  );
}