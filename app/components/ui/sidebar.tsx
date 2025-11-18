"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/app/lib/utils";
import {
  LayoutDashboard,
  FolderKanban,
  Activity,
  User,
  Settings,
  Menu,
  X,
} from "lucide-react";

interface SidebarItem {
  title: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
}

const sidebarItems: SidebarItem[] = [
  {
    title: "Dashboard",
    href: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    title: "Projects",
    href: "/projects",
    icon: FolderKanban,
  },
  {
    title: "Monitoring",
    href: "/monitoring",
    icon: Activity,
  },
  {
    title: "User",
    href: "/profile",
    icon: User,
  },
  {
    title: "Settings",
    href: "/settings",
    icon: Settings,
  },
];

export function Sidebar() {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const pathname = usePathname();

  return (
    <div
      className={cn(
        "relative flex flex-col bg-gray-900/95 backdrop-blur-sm border-r border-gray-800 transition-all duration-300 z-20",
        isCollapsed ? "w-16" : "w-64"
      )}
    >
      {/* Header - Now just menu toggle and title */}
      <div className="flex items-center justify-between p-4 border-b border-gray-800">
        {!isCollapsed && (
          <h2 className="text-lg font-semibold text-white">Menu</h2>
        )}
        <button
          onClick={() => setIsCollapsed(!isCollapsed)}
          className="p-2 rounded-md hover:bg-gray-800 transition-colors"
        >
          {isCollapsed ? (
            <Menu className="h-4 w-4 text-gray-400" />
          ) : (
            <X className="h-4 w-4 text-gray-400" />
          )}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-2">
        {sidebarItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-3 rounded-lg transition-all duration-200 group",
                isActive
                  ? "bg-blue-600/20 text-blue-400 border-l-4 border-blue-500 shadow-sm"
                  : "text-gray-400 hover:bg-gray-800 hover:text-white hover:shadow-sm"
              )}
            >
              <Icon 
                className={cn(
                  "h-5 w-5 flex-shrink-0 transition-colors",
                  isActive ? "text-blue-400" : "text-gray-500 group-hover:text-gray-300"
                )} 
              />
              {!isCollapsed && (
                <span className="text-sm font-medium">{item.title}</span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-gray-800">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-600 rounded-full flex items-center justify-center shadow-sm">
            <User className="h-4 w-4 text-white" />
          </div>
          {!isCollapsed && (
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-white truncate">
                User Name
              </p>
              <p className="text-xs text-gray-400 truncate">user@example.com</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}