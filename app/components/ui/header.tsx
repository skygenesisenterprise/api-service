"use client";

import { useState } from "react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/app/components/ui/dropdown-menu";
import { Avatar, AvatarFallback, AvatarImage } from "@/app/components/ui/avatar";
import { Button } from "@/app/components/ui/button";
import { ChevronDown, Building2, Layers, User, Settings, LogOut } from "lucide-react";

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

const defaultOrganizations: Organization[] = [
  { id: "1", name: "Acme Corp", logo: "/logo1.png" },
  { id: "2", name: "Tech Startup", logo: "/logo2.png" },
  { id: "3", name: "Digital Agency", logo: "/logo3.png" },
];

const defaultWorkspaces: Workspace[] = [
  { id: "1", name: "Development", environment: "dev" },
  { id: "2", name: "Staging", environment: "staging" },
  { id: "3", name: "Production", environment: "prod" },
];

const defaultUser: User = {
  id: "1",
  name: "John Doe",
  email: "john.doe@example.com",
  avatar: "/user-avatar.png",
};

export function Header({
  organizations = defaultOrganizations,
  workspaces = defaultWorkspaces,
  user = defaultUser,
  currentOrganization = defaultOrganizations[0],
  currentWorkspace = defaultWorkspaces[0],
  onOrganizationChange,
  onWorkspaceChange,
  onProfileClick,
  onSettingsClick,
  onLogout,
}: HeaderProps) {
  const [selectedOrg, setSelectedOrg] = useState(currentOrganization);
  const [selectedWorkspace, setSelectedWorkspace] = useState(currentWorkspace);

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

  return (
    <header className="h-16 w-full border-b border-gray-800 bg-gray-900/95 backdrop-blur-sm relative z-20">
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
                {selectedOrg.logo ? (
                  <img
                    src={selectedOrg.logo}
                    alt={selectedOrg.name}
                    className="h-5 w-5 rounded"
                  />
                ) : (
                  <Building2 className="h-5 w-5" />
                )}
                <span className="hidden sm:inline font-medium">
                  {selectedOrg.name}
                </span>
                <ChevronDown className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-56">
              <DropdownMenuLabel>Organisations</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {organizations.map((org) => (
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
                  {selectedOrg.id === org.id && (
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
                  {selectedWorkspace.name}
                </span>
                <span
                  className={`hidden sm:inline px-2 py-0.5 rounded-full text-xs font-medium ${getWorkspaceColor(
                    selectedWorkspace.environment
                  )}`}
                >
                  {selectedWorkspace.environment.toUpperCase()}
                </span>
                <ChevronDown className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-56">
              <DropdownMenuLabel>Workspaces</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {workspaces.map((workspace) => (
                <DropdownMenuItem
                  key={workspace.id}
                  onClick={() => handleWorkspaceChange(workspace)}
                  className="flex items-center gap-3"
                >
                  <Layers className="h-4 w-4" />
                  <div className="flex-1">
                    <div className="font-medium">{workspace.name}</div>
                    <div
                      className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium ${getWorkspaceColor(
                        workspace.environment
                      )}`}
                    >
                      {workspace.environment.toUpperCase()}
                    </div>
                  </div>
                  {selectedWorkspace.id === workspace.id && (
                    <div className="h-2 w-2 rounded-full bg-blue-600" />
                  )}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        {/* Right side - User Avatar and Menu */}
        <div className="flex items-center gap-4">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="relative h-8 w-8 rounded-full"
              >
                <Avatar className="h-8 w-8">
                  <AvatarImage
                    src={user.avatar}
                    alt={user.name}
                  />
                  <AvatarFallback>
                    {user.name
                      .split(" ")
                      .map((n) => n[0])
                      .join("")
                      .toUpperCase()
                      .slice(0, 2)}
                  </AvatarFallback>
                </Avatar>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="w-56" align="end" forceMount>
              <DropdownMenuLabel className="font-normal">
                <div className="flex flex-col space-y-1">
                  <p className="text-sm font-medium leading-none">
                    {user.name}
                  </p>
                  <p className="text-xs leading-none text-muted-foreground">
                    {user.email}
                  </p>
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={onProfileClick}>
                <User className="mr-2 h-4 w-4" />
                <span>Profile</span>
              </DropdownMenuItem>
              <DropdownMenuItem onClick={onSettingsClick}>
                <Settings className="mr-2 h-4 w-4" />
                <span>Settings</span>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={onLogout}>
                <LogOut className="mr-2 h-4 w-4" />
                <span>Log out</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}