"use client";

import { useState } from "react";
import React from "react";
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
  Settings,
  X,
  Save,
  Trash2,
  Copy,
  ExternalLink,
  Key,
  Globe,
  Users,
  Shield,
  Database,
} from "lucide-react";

interface ProjectSettingsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  project: any;
  onProjectUpdated?: (project: any) => void;
}

export default function ProjectSettingsDialog({ 
  open, 
  onOpenChange, 
  project,
  onProjectUpdated 
}: ProjectSettingsDialogProps) {
  const [formData, setFormData] = useState({
    name: project?.name || "",
    description: project?.description || "",
    domains: project?.domains || [],
    tags: project?.tags || [],
  });
  
  const [currentDomain, setCurrentDomain] = useState("");
  const [currentTag, setCurrentTag] = useState("");
  const [isSaving, setIsSaving] = useState(false);
  const [activeTab, setActiveTab] = useState("general");

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);

    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1500));

    const updatedProject = {
      ...project,
      ...formData,
      updatedAt: new Date().toISOString(),
    };

    onProjectUpdated?.(updatedProject);
    setIsSaving(false);
    onOpenChange(false);
  };

  const addDomain = () => {
    if (currentDomain.trim() && !formData.domains.includes(currentDomain.trim())) {
      setFormData(prev => ({
        ...prev,
        domains: [...prev.domains, currentDomain.trim()]
      }));
      setCurrentDomain("");
    }
  };

  const removeDomain = (domainToRemove: string) => {
    setFormData(prev => ({
      ...prev,
      domains: prev.domains.filter((domain: string) => domain !== domainToRemove)
    }));
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
      tags: prev.tags.filter((tag: string) => tag !== tagToRemove)
    }));
  };

  const copyApiKey = () => {
    navigator.clipboard.writeText("sk_live_" + Math.random().toString(36).substring(2, 15));
    // Here you would show a toast notification
  };

  const tabs = [
    { id: "general", label: "General", icon: Settings },
    { id: "domains", label: "Domains", icon: Globe },
    { id: "api", label: "API Keys", icon: Key },
    { id: "team", label: "Team", icon: Users },
    { id: "security", label: "Security", icon: Shield },
    { id: "database", label: "Database", icon: Database },
  ];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            Project Settings: {project?.name}
          </DialogTitle>
          <DialogDescription>
            Configure your project settings, domains, API keys, and team access.
          </DialogDescription>
        </DialogHeader>

        {/* Tabs */}
        <div className="flex space-x-1 border-b border-gray-200">
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

        <form onSubmit={handleSave} className="space-y-6">
          {/* General Tab */}
          {activeTab === "general" && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className="space-y-4"
            >
              <div>
                <label className="text-sm font-medium text-gray-900 mb-2 block">
                  Project Name
                </label>
                <Input
                  value={formData.name}
                  onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="Enter project name"
                  className="w-full"
                />
              </div>

              <div>
                <label className="text-sm font-medium text-gray-900 mb-2 block">
                  Description
                </label>
                <Textarea
                  value={formData.description}
                  onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                  placeholder="Describe your project..."
                  rows={3}
                  className="w-full resize-none"
                />
              </div>

              <div>
                <label className="text-sm font-medium text-gray-900 mb-2 block">
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
                      onClick={addTag}
                      disabled={!currentTag.trim()}
                    >
                      Add
                    </Button>
                  </div>
                  {formData.tags.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                      {formData.tags.map((tag: string) => (
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
            </motion.div>
          )}

          {/* Domains Tab */}
          {activeTab === "domains" && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className="space-y-4"
            >
              <div>
                <label className="text-sm font-medium text-gray-900 mb-2 block">
                  Custom Domains
                </label>
                <div className="space-y-3">
                  <div className="flex gap-2">
                    <Input
                      placeholder="Add domain (e.g., api.example.com)"
                      value={currentDomain}
                      onChange={(e) => setCurrentDomain(e.target.value)}
                      className="flex-1"
                    />
                    <Button
                      type="button"
                      variant="outline"
                      onClick={addDomain}
                      disabled={!currentDomain.trim()}
                    >
                      Add
                    </Button>
                  </div>
                  {formData.domains.length > 0 && (
                    <div className="space-y-2">
                      {formData.domains.map((domain: string) => (
                        <div
                          key={domain}
                          className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                        >
                          <div className="flex items-center gap-2">
                            <Globe className="h-4 w-4 text-gray-600" />
                            <span className="text-sm font-medium">{domain}</span>
                          </div>
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => removeDomain(domain)}
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          )}

          {/* API Keys Tab */}
          {activeTab === "api" && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className="space-y-4"
            >
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div>
                    <div className="font-medium text-gray-900">Production API Key</div>
                    <div className="text-sm text-gray-600">sk_live_•••••••••••••••••••••</div>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={copyApiKey}
                    >
                      <Copy className="h-4 w-4 mr-2" />
                      Copy
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                    >
                      <ExternalLink className="h-4 w-4 mr-2" />
                      Docs
                    </Button>
                  </div>
                </div>

                <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div>
                    <div className="font-medium text-gray-900">Development API Key</div>
                    <div className="text-sm text-gray-600">sk_dev_••••••••••••••••••••••</div>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                    >
                      <Copy className="h-4 w-4 mr-2" />
                      Copy
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                    >
                      <ExternalLink className="h-4 w-4 mr-2" />
                      Docs
                    </Button>
                  </div>
                </div>
              </div>

              <div className="text-center">
                <Button type="button" variant="outline">
                  Generate New API Key
                </Button>
              </div>
            </motion.div>
          )}

          {/* Other tabs would have similar structure */}
          {activeTab !== "general" && activeTab !== "domains" && activeTab !== "api" && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
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
                {tabs.find(t => t.id === activeTab)?.label} Settings
              </h3>
              <p className="text-gray-600 mb-4">
                Configure {tabs.find(t => t.id === activeTab)?.label.toLowerCase()} for your project.
              </p>
              <p className="text-sm text-gray-500">
                This section is coming soon with more advanced configuration options.
              </p>
            </motion.div>
          )}

          <DialogFooter className="flex gap-3 pt-4">
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={isSaving}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={isSaving}
              className="bg-blue-600 hover:bg-blue-700"
            >
              {isSaving ? (
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Saving...
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <Save className="h-4 w-4" />
                  Save Changes
                </div>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}