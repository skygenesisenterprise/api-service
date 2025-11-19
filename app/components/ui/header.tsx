"use client";

import { useState, useEffect } from "react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { ChevronDown, Building2, Layers, User, Settings, LogOut, Bell } from "lucide-react";

export interface Organization {
  id: string;
  name: string;
  logo?: string;
}

export interface Workspace {
  id: string;
  name: string;
  environment: "dev" | "staging" | "prod";
}

export interface User {
  id: string;
  name: string;
  email: string;
  avatar?: string;
}

interface HeaderProps {
  organizations?: Organization[];
  workspaces?: Workspace[];
  user?: User;
  currentOrganization?: Organization;
  currentWorkspace?: Workspace;
  onOrganizationChange?: (org: Organization) => void;
  onWorkspaceChange?: (workspace: Workspace) => void;
  onProfileClick?: () => void;
  onSettingsClick?: () => void;
  onLogout?: () => void;
}

const defaultWorkspaces: Workspace[] = [
  { id: "1", name: "Development", environment: "dev" },
  { id: "2", name: "Test", environment: "staging" },
  { id: "3", name: "Production", environment: "prod" },
];

export function Header({
  organizations,
  workspaces = defaultWorkspaces,
  user,
  currentOrganization,
  currentWorkspace = defaultWorkspaces[0], // Development par défaut
  onOrganizationChange,
  onWorkspaceChange,
  onProfileClick,
  onSettingsClick,
  onLogout,
}: HeaderProps) {
  const [mounted, setMounted] = useState(false);
  
  // Déterminer l'organisation par défaut basée sur le domaine de l'email
  const getDefaultOrganization = () => {
    if (currentOrganization) return currentOrganization;
    if (user?.email) {
      const domain = user.email.split('@')[1];
      if (domain) {
        return { id: "default", name: domain };
      }
    }
    return null;
  };
  
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(getDefaultOrganization());
  const [selectedWorkspace, setSelectedWorkspace] = useState<Workspace | null>(currentWorkspace);
  const [currentUser, setCurrentUser] = useState(user);

  useEffect(() => {
    setMounted(true);
    
    // Récupérer les données utilisateur depuis localStorage
    const storedUser = localStorage.getItem("user");
    if (storedUser) {
      try {
        const userData = JSON.parse(storedUser);
        setCurrentUser(userData);
        
        // Extraire le domaine de l'email pour l'organisation par défaut si aucune organisation n'est définie
        if (userData.email && !currentOrganization) {
          const domain = userData.email.split('@')[1];
          if (domain) {
            const defaultOrgFromDomain = {
              id: "default",
              name: domain,
              logo: undefined
            };
            setSelectedOrg(defaultOrgFromDomain);
          }
        }
      } catch (error) {
        console.error("Erreur lors de la lecture des données utilisateur:", error);
      }
    }
  }, []);

  // Mettre à jour l'organisation lorsque l'utilisateur change
  useEffect(() => {
    if (currentUser?.email && !currentOrganization) {
      const domain = currentUser.email.split('@')[1];
      if (domain) {
        const defaultOrgFromDomain = {
          id: "default",
          name: domain,
          logo: undefined
        };
        setSelectedOrg(defaultOrgFromDomain);
      }
    }
  }, [currentUser, currentOrganization]);

  const handleOrganizationChange = (org: Organization) => {
    setSelectedOrg(org);
    onOrganizationChange?.(org);
  };

  const handleWorkspaceChange = (workspace: Workspace) => {
    setSelectedWorkspace(workspace);
    onWorkspaceChange?.(workspace);
  };

  const getWorkspaceColor = (environment: string) => {
    switch (environment) {
      case "dev":
        return "bg-green-100 text-green-800";
      case "staging":
        return "bg-yellow-100 text-yellow-800";
      case "prod":
        return "bg-red-100 text-red-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  const handleLogout = () => {
    // Clear localStorage
    localStorage.removeItem("authToken");
    localStorage.removeItem("refreshToken");
    localStorage.removeItem("idToken");
    localStorage.removeItem("user");
    localStorage.removeItem("memberships");
    
    // Redirect to login
    window.location.href = "/login";
  };

  if (!mounted) {
    return (
      <header className="h-16 w-full border-b border-gray-200 bg-white">
        <div className="flex h-full items-center justify-between px-6 w-full">
          {/* Placeholder for left side */}
          <div className="flex items-center gap-4">
            <div className="h-9 w-32 bg-gray-100 rounded animate-pulse"></div>
            <div className="h-9 w-32 bg-gray-100 rounded animate-pulse"></div>
          </div>
          {/* Placeholder for right side */}
          <div className="flex items-center gap-4">
            <div className="h-9 w-9 bg-gray-100 rounded-lg animate-pulse"></div>
            <div className="h-10 w-40 bg-gray-100 rounded-lg animate-pulse"></div>
          </div>
        </div>
      </header>
    );
  }

  return (
    <header className="h-16 w-full border-b border-gray-200 bg-white" suppressHydrationWarning>
      <div className="flex h-full items-center justify-between px-6 w-full">
        {/* Left side - Organization and Workspace dropdowns */}
        <div className="flex items-center gap-4">
          {/* Organization Dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="flex items-center gap-2 px-3 py-2 hover:bg-accent"
              >
                {selectedOrg?.logo ? (
                  <img
                    src={selectedOrg.logo}
                    alt={selectedOrg.name}
                    className="h-5 w-5 rounded"
                  />
                ) : (
                  <Building2 className="h-5 w-5" />
                )}
                <span className="hidden sm:inline font-medium">
                  {selectedOrg?.name || "Sélectionner une organisation"}
                </span>
                <ChevronDown className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-56">
              <DropdownMenuLabel>Organisations</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {[...(organizations || []), ...(selectedOrg?.id === "default" && !(organizations || []).find(org => org.id === "default") && selectedOrg ? [selectedOrg] : [])].map((org) => (
                <DropdownMenuItem
                  key={org.id}
                  onClick={() => handleOrganizationChange(org)}
                  className="flex items-center gap-3"
                >
                  {org.logo ? (
                    <img
                      src={org.logo}
                      alt={org.name}
                      className="h-4 w-4 rounded"
                    />
                  ) : (
                    <Building2 className="h-4 w-4" />
                  )}
                  <span>{org.name}</span>
                  {selectedOrg?.id === org.id && (
                    <div className="ml-auto h-2 w-2 rounded-full bg-blue-600" />
                  )}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Workspace Dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="flex items-center gap-2 px-3 py-2 hover:bg-accent"
              >
                <Layers className="h-5 w-5" />
                <span className="hidden sm:inline font-medium">
                  {selectedWorkspace?.name || "Sélectionner un workspace"}
                </span>
                <span className={`hidden sm:inline px-2 py-1 text-xs rounded-full font-medium ${selectedWorkspace ? getWorkspaceColor(selectedWorkspace.environment) : 'bg-gray-100 text-gray-800'}`}>
                  {selectedWorkspace?.environment?.toUpperCase() || "DEV"}
                </span>
                <ChevronDown className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-56">
              <DropdownMenuLabel>Workspaces</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {(workspaces || []).map((workspace) => (
                <DropdownMenuItem
                  key={workspace.id}
                  onClick={() => handleWorkspaceChange(workspace)}
                  className="flex items-center gap-3"
                >
                  <Layers className="h-4 w-4" />
                  <span>{workspace.name}</span>
                  <span className={`ml-auto px-2 py-1 text-xs rounded-full font-medium ${getWorkspaceColor(workspace.environment)}`}>
                    {workspace.environment.toUpperCase()}
                  </span>
                  {selectedWorkspace?.id === workspace.id && (
                    <div className="ml-auto h-2 w-2 rounded-full bg-blue-600" />
                  )}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        {/* Right side - Notifications and Profile */}
        <div className="flex items-center gap-3">
          {/* Notifications */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="relative h-9 w-9 rounded-lg">
                <div className="absolute -top-1 -right-1 h-5 w-5 rounded-full bg-red-500 text-white text-xs flex items-center justify-center font-medium">
                  3
                </div>
                <Bell className="h-5 w-5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80">
              <DropdownMenuLabel>Notifications</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <div className="max-h-96 overflow-y-auto">
                <div className="p-3 hover:bg-gray-50 cursor-pointer border-b border-gray-100">
                  <div className="flex items-start gap-3">
                    <div className="h-2 w-2 rounded-full bg-blue-500 mt-2"></div>
                    <div className="flex-1">
                      <p className="text-sm font-medium text-gray-900">New API key generated</p>
                      <p className="text-xs text-gray-500 mt-1">A new API key was created for your organization</p>
                    </div>
                  </div>
                  <p className="text-xs text-gray-400 mt-2">2 minutes ago</p>
                </div>
                <div className="p-3 hover:bg-gray-50 cursor-pointer border-b border-gray-100">
                  <div className="flex items-start gap-3">
                    <div className="h-2 w-2 rounded-full bg-green-500 mt-2"></div>
                    <div className="flex-1">
                      <p className="text-sm font-medium text-gray-900">Database backup completed</p>
                      <p className="text-xs text-gray-500 mt-1">Your scheduled backup was completed successfully</p>
                    </div>
                  </div>
                  <p className="text-xs text-gray-400 mt-2">1 hour ago</p>
                </div>
                <div className="p-3 hover:bg-gray-50 cursor-pointer">
                  <div className="flex items-start gap-3">
                    <div className="h-2 w-2 rounded-full bg-yellow-500 mt-2"></div>
                    <div className="flex-1">
                      <p className="text-sm font-medium text-gray-900">API documentation updated</p>
                      <p className="text-xs text-gray-500 mt-1">API documentation has been updated with v2.0 changes</p>
                    </div>
                  </div>
                  <p className="text-xs text-gray-400 mt-2">Yesterday</p>
                </div>
              </div>
              <div className="p-3 border-t border-gray-100">
                <Button variant="ghost" className="w-full text-sm text-blue-600 hover:text-blue-700 hover:bg-blue-50">
                  View all notifications
                </Button>
              </div>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Profile Dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="flex items-center gap-3 h-10 px-3 py-2 rounded-lg hover:bg-gray-100 transition-colors"
              >
                <div className="relative">
                  <Avatar className="h-8 w-8 ring-2 ring-white ring-offset-2 ring-offset-gray-50">
                    <AvatarImage
                      src={currentUser?.avatar}
                      alt={currentUser?.name || "User"}
                    />
                    <AvatarFallback className="bg-gradient-to-br from-blue-500 to-purple-600 text-white font-semibold">
                      {currentUser?.name
                        ?.split(" ")
                        ?.map((n) => n[0])
                        ?.join("")
                        ?.toUpperCase()
                        ?.slice(0, 2) || "U"}
                    </AvatarFallback>
                  </Avatar>
                  <div className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-green-500 border-2 border-white" />
                </div>
                <div className="hidden md:block text-left">
                  <div className="text-sm font-semibold text-gray-900">{currentUser?.name || "User"}</div>
                  <div className="text-xs text-gray-500">admin</div>
                </div>
                <ChevronDown className="h-4 w-4 text-gray-400" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="w-80" align="end" sideOffset={8}>
              {/* Profile Header */}
              <div className="p-4 border-b border-gray-100">
                <div className="flex items-center gap-3">
                  <Avatar className="h-12 w-12 ring-2 ring-gray-100">
                    <AvatarImage
                      src={currentUser?.avatar}
                      alt={currentUser?.name || "User"}
                    />
                    <AvatarFallback className="bg-gradient-to-br from-blue-500 to-purple-600 text-white font-semibold text-lg">
                      {currentUser?.name
                        ?.split(" ")
                        ?.map((n) => n[0])
                        ?.join("")
                        ?.toUpperCase()
                        ?.slice(0, 2) || "U"}
                    </AvatarFallback>
                  </Avatar>
                  <div className="flex-1">
                    <div className="font-semibold text-gray-900">{currentUser?.name || "User"}</div>
                    <div className="text-sm text-gray-500">{currentUser?.email || "user@example.com"}</div>
                  </div>
                </div>
              </div>

              {/* Quick Stats */}
              <div className="p-4 border-b border-gray-100">
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <div className="text-lg font-semibold text-gray-900">24</div>
                    <div className="text-xs text-gray-500">Projects</div>
                  </div>
                  <div>
                    <div className="text-lg font-semibold text-gray-900">142</div>
                    <div className="text-xs text-gray-500">API Calls</div>
                  </div>
                  <div>
                    <div className="text-lg font-semibold text-gray-900">99.9%</div>
                    <div className="text-xs text-gray-500">Uptime</div>
                  </div>
                </div>
              </div>

              {/* Menu Items */}
              <div className="p-2">
                <DropdownMenuItem 
                  onClick={() => window.location.href = "/profile"}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-gray-50 cursor-pointer"
                >
                  <div className="h-8 w-8 rounded-lg bg-blue-100 flex items-center justify-center">
                    <User className="h-4 w-4 text-blue-600" />
                  </div>
                  <div className="flex-1">
                    <div className="text-sm font-medium">Profile</div>
                    <div className="text-xs text-gray-500">Manage your account</div>
                  </div>
                </DropdownMenuItem>

                <DropdownMenuItem 
                  onClick={() => window.location.href = "/settings"}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-gray-50 cursor-pointer"
                >
                  <div className="h-8 w-8 rounded-lg bg-gray-100 flex items-center justify-center">
                    <Settings className="h-4 w-4 text-gray-600" />
                  </div>
                  <div className="flex-1">
                    <div className="text-sm font-medium">Settings</div>
                    <div className="text-xs text-gray-500">Preferences & security</div>
                  </div>
                </DropdownMenuItem>

                <DropdownMenuItem 
                  onClick={handleLogout}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-red-50 cursor-pointer text-red-600"
                >
                  <div className="h-8 w-8 rounded-lg bg-red-100 flex items-center justify-center">
                    <LogOut className="h-4 w-4 text-red-600" />
                  </div>
                  <div className="flex-1">
                    <div className="text-sm font-medium">Sign out</div>
                    <div className="text-xs text-red-500">End your session</div>
                  </div>
                </DropdownMenuItem>
              </div>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}