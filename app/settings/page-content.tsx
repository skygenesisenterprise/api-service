"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Settings, 
  Building2, 
  Users, 
  Shield, 
  Key,
  FileText,
  CreditCard,
  AlertTriangle,
  Globe,
  Server,
  Lock,
  Save,
  Loader2,
  Clock,
  KeyRound,
  Fingerprint,
  ShieldCheck,
  Crown,
  Activity,
  Database,
  Wifi
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { TooltipProvider } from "@/components/ui/tooltip";

// Types
interface Organization {
  id: string;
  name: string;
  workspaceName: string;
  logo?: string;
  accentColor: string;
  timezone: string;
  locale: string;
}

interface Member {
  id: string;
  name: string;
  email: string;
  role: "admin" | "developer" | "auditor";
  status: "active" | "pending" | "inactive";
  lastActivity: Date;
  avatar?: string;
}

interface ApiKey {
  id: string;
  name: string;
  key: string;
  createdAt: Date;
  lastUsed?: Date;
  permissions: string[];
}

interface AuditLog {
  id: string;
  user: string;
  action: string;
  timestamp: Date;
  ip: string;
  category: "auth" | "config" | "billing" | "security" | "api";
}

// Mock Data
const mockOrganization: Organization = {
  id: "org_123",
  name: "Sky Genesis Enterprise",
  workspaceName: "Production Workspace",
  accentColor: "#3b82f6",
  timezone: "UTC",
  locale: "en"
};

const mockMembers: Member[] = [
  {
    id: "1",
    name: "Alexandre Martin",
    email: "alex.martin@skygenesis.com",
    role: "admin",
    status: "active",
    lastActivity: new Date(Date.now() - 2 * 60 * 1000),
    avatar: "AM"
  },
  {
    id: "2",
    name: "Sophie Dubois",
    email: "sophie.dubois@skygenesis.com",
    role: "developer",
    status: "active",
    lastActivity: new Date(Date.now() - 30 * 60 * 1000),
    avatar: "SD"
  },
  {
    id: "3",
    name: "Thomas Bernard",
    email: "thomas.bernard@skygenesis.com",
    role: "auditor",
    status: "pending",
    lastActivity: new Date(Date.now() - 60 * 60 * 1000),
    avatar: "TB"
  }
];

const mockApiKeys: ApiKey[] = [
  {
    id: "1",
    name: "Production API Key",
    key: "sk_live_51H1K2j2eFvB4X9Y8wLmQpN7rT3uV6iK",
    createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
    lastUsed: new Date(Date.now() - 2 * 60 * 60 * 1000),
    permissions: ["read", "write", "admin"]
  },
  {
    id: "2",
    name: "Development API Key",
    key: "sk_test_51H1K2j2eFvB4X9Y8wLmQpN7rT3uV6iK",
    createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
    lastUsed: new Date(Date.now() - 30 * 60 * 1000),
    permissions: ["read", "write"]
  }
];

const mockAuditLogs: AuditLog[] = [
  {
    id: "1",
    user: "Alexandre Martin",
    action: "Updated organization settings",
    timestamp: new Date(Date.now() - 30 * 60 * 1000),
    ip: "192.168.1.100",
    category: "config"
  },
  {
    id: "2",
    user: "Sophie Dubois",
    action: "Generated new API key",
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
    ip: "10.0.0.45",
    category: "security"
  }
];

// Navigation Categories
const navigationCategories = [
  {
    id: "general",
    title: "General",
    icon: Settings,
    items: [
      { id: "organization", label: "Organization", icon: Building2 },
      { id: "workspace", label: "Workspace", icon: Server },
      { id: "branding", label: "Branding", icon: Globe }
    ]
  },
  {
    id: "access",
    title: "Access & Permissions",
    icon: Users,
    items: [
      { id: "members", label: "Members", icon: Users },
      { id: "roles", label: "Roles", icon: Shield },
      { id: "api-policy", label: "API Access Policy", icon: Key }
    ]
  },
  {
    id: "auth",
    title: "Authentication",
    icon: Lock,
    items: [
      { id: "password-policy", label: "Password Policy", icon: KeyRound },
      { id: "mfa", label: "2FA / MFA", icon: Fingerprint },
      { id: "sso", label: "SSO Providers", icon: ShieldCheck },
      { id: "session", label: "Session Lifetime", icon: Clock }
    ]
  },
  {
    id: "api-keys",
    title: "API Keys",
    icon: Key,
    items: [
      { id: "keys-list", label: "API Keys", icon: Key },
      { id: "create-key", label: "Create New Key", icon: Key }
    ]
  },
  {
    id: "audit",
    title: "Audit Logs",
    icon: FileText,
    items: [
      { id: "logs", label: "Activity Logs", icon: FileText },
      { id: "export", label: "Export Logs", icon: FileText }
    ]
  },
  {
    id: "billing",
    title: "Billing",
    icon: CreditCard,
    items: [
      { id: "plan", label: "Plan", icon: Crown },
      { id: "usage", label: "Usage", icon: Activity },
      { id: "invoices", label: "Invoice History", icon: FileText }
    ]
  },
  {
    id: "advanced",
    title: "Advanced",
    icon: AlertTriangle,
    items: [
      { id: "webhooks", label: "Webhooks", icon: Wifi },
      { id: "retention", label: "Data Retention", icon: Database },
      { id: "encryption", label: "Encryption", icon: Shield },
      { id: "danger-zone", label: "Danger Zone", icon: AlertTriangle }
    ]
  }
];

export default function EnterpriseSettingsPage() {
  const [organization, setOrganization] = useState(mockOrganization);
  const [isSaving, setIsSaving] = useState(false);

  const handleSaveOrganization = async () => {
    setIsSaving(true);
    await new Promise(resolve => setTimeout(resolve, 2000));
    setIsSaving(false);
  };

  return (
    <TooltipProvider>
      <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-blue-50/30">
        <div className="max-w-7xl mx-auto p-6">
          {/* Enterprise Header */}
          <motion.div
            initial={{ opacity: 0, y: -30 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mb-12"
          >
            <div className="flex items-center justify-center gap-6 mb-6">
              <motion.div
                animate={{ rotate: [0, 10, -10, 0] }}
                transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                className="p-4 bg-gradient-to-br from-blue-600 via-purple-600 to-blue-700 rounded-3xl shadow-2xl"
              >
                <Settings className="w-12 h-12 text-white" />
              </motion.div>
              <div>
                <h1 className="text-5xl font-bold bg-gradient-to-r from-gray-900 to-gray-600 bg-clip-text text-transparent">
                  Enterprise Settings
                </h1>
                <p className="text-xl text-gray-600 mt-2 max-w-2xl">
                  Configure your organization's infrastructure, security, and billing preferences
                </p>
              </div>
            </div>
          </motion.div>

          {/* Main Settings */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
            {/* Left Sidebar Navigation */}
            <div className="lg:col-span-1">
              <Card className="sticky top-6">
                <CardHeader>
                  <CardTitle className="text-lg">Settings</CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-[600px]">
                    <div className="p-4 space-y-2">
                      {navigationCategories.map((category) => {
                        const Icon = category.icon;
                        return (
                          <div key={category.id} className="mb-4">
                            <div className="flex items-center gap-2 mb-2 text-sm font-medium text-gray-700">
                              <Icon className="w-4 h-4" />
                              {category.title}
                            </div>
                            <div className="ml-6 space-y-1">
                              {category.items.map((item) => {
                                const ItemIcon = item.icon;
                                return (
                                  <Button
                                    key={item.id}
                                    variant="ghost"
                                    size="sm"
                                    className="w-full justify-start h-8 text-sm"
                                  >
                                    <ItemIcon className="w-3 h-3 mr-2" />
                                    {item.label}
                                  </Button>
                                );
                              })}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>

            {/* Right Content Panel */}
            <div className="lg:col-span-3">
              <AnimatePresence mode="wait">
                <motion.div
                  key="organization"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.2 }}
                >
                  <Card>
                    <CardHeader>
                      <CardTitle>Organization Settings</CardTitle>
                      <CardDescription>Manage your organization's basic information</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-6">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="space-y-2">
                          <Label htmlFor="org-name">Organization Name</Label>
                          <Input
                            id="org-name"
                            value={organization.name}
                            onChange={(e) => setOrganization(prev => ({ ...prev, name: e.target.value }))}
                            placeholder="Acme Corporation"
                          />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="workspace-name">Workspace Name</Label>
                          <Input
                            id="workspace-name"
                            value={organization.workspaceName}
                            onChange={(e) => setOrganization(prev => ({ ...prev, workspaceName: e.target.value }))}
                            placeholder="Production Workspace"
                          />
                        </div>
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="space-y-2">
                          <Label htmlFor="timezone">Default Timezone</Label>
                          <Select value={organization.timezone} onValueChange={(value) => setOrganization(prev => ({ ...prev, timezone: value }))}>
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="UTC">UTC</SelectItem>
                              <SelectItem value="America/New_York">America/New_York</SelectItem>
                              <SelectItem value="Europe/London">Europe/London</SelectItem>
                              <SelectItem value="Asia/Tokyo">Asia/Tokyo</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="locale">Default Locale</Label>
                          <Select value={organization.locale} onValueChange={(value) => setOrganization(prev => ({ ...prev, locale: value }))}>
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="en">English</SelectItem>
                              <SelectItem value="fr">Français</SelectItem>
                              <SelectItem value="de">Deutsch</SelectItem>
                              <SelectItem value="es">Español</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>

                      <div className="flex justify-end">
                        <Button 
                          onClick={handleSaveOrganization}
                          disabled={isSaving}
                          className="flex items-center gap-2"
                        >
                          {isSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                          {isSaving ? "Saving..." : "Save Changes"}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              </AnimatePresence>
            </div>
          </div>
        </div>
      </div>
    </TooltipProvider>
  );
}