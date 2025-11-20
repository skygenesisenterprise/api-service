"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

import {
  LayoutDashboard,
  Boxes,
  TerminalSquare,
  Activity,
  FileText,
  Puzzle,
  ShieldCheck,
  Settings,
  ChevronRight,
} from "lucide-react";

interface SidebarSection {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
  subItems?: Array<{
    name: string;
    href: string;
  }>;
}

const sidebarSections: SidebarSection[] = [
  {
    name: "Dashboard",
    href: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    name: "Projects",
    href: "/projects",
    icon: Boxes,
  },
  {
    name: "Endpoints",
    href: "/endpoints",
    icon: TerminalSquare,
  },
  {
    name: "Requests Monitoring",
    href: "/monitoring",
    icon: Activity,
  },
  {
    name: "Logs",
    href: "/logs",
    icon: FileText,
  },
  {
    name: "Services",
    href: "/services",
    icon: Puzzle,
  },
  {
    name: "Security",
    href: "/security",
    icon: ShieldCheck,
    subItems: [
      { name: "IAM", href: "/security/iam" },
      { name: "Roles", href: "/security/roles" },
      { name: "Policies", href: "/security/policies" },
      { name: "API Keys", href: "/security/api-keys" },
      { name: "Audit Trail", href: "/security/audit" },
      { name: "Sessions", href: "/security/sessions" },
    ],
  },
  {
    name: "Settings",
    href: "/settings",
    icon: Settings,
  },
];

interface ModernSidebarProps {
  className?: string;
}

export default function ModernSidebar({ className }: ModernSidebarProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set());
  const pathname = usePathname();

  const handleSectionClick = (sectionName: string) => {
    if (expandedSections.has(sectionName)) {
      setExpandedSections(prev => {
        const newSet = new Set(prev);
        newSet.delete(sectionName);
        return newSet;
      });
    } else {
      setExpandedSections(prev => new Set([...prev, sectionName]));
    }
  };

  const isActive = (href: string) => {
    if (href === "/dashboard") return pathname === href;
    return pathname.startsWith(href);
  };

  const isSubItemActive = (href: string) => {
    return pathname === href;
  };



  return (
    <div
      className={cn(
        "relative flex flex-col bg-white border-r border-gray-200 transition-all duration-200 ease-out z-50",
        isExpanded ? "w-72" : "w-18",
        className
      )}
      onMouseEnter={() => setIsExpanded(true)}
      onMouseLeave={() => setIsExpanded(false)}
    >
      {/* Navigation Sections - Start directly at top */}
      <nav className="flex-1 p-2 space-y-1 overflow-y-auto pt-4">
        {sidebarSections.map((section) => {
          const Icon = section.icon;
          const isSectionActive = isActive(section.href);
          const isSectionExpanded = expandedSections.has(section.name);
          const hasSubItems = section.subItems && section.subItems.length > 0;

          return (
            <div key={section.name}>
              {/* Main section item */}
              <Link
                href={section.href}
                className={cn(
                  "flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-200 group",
                  isSectionActive
                    ? "bg-blue-50 text-blue-700 border-l-4 border-blue-600"
                    : "text-gray-700 hover:bg-gray-100 hover:text-gray-900"
                )}
                onClick={(e) => {
                  if (hasSubItems) {
                    e.preventDefault();
                    handleSectionClick(section.name);
                  }
                }}
              >
                <Icon className="h-5 w-5 flex-shrink-0" />
                {isExpanded && (
                  <>
                    <span className="text-sm font-medium truncate">{section.name}</span>
                    {section.badge && (
                      <span className="ml-auto px-2 py-0.5 text-xs bg-blue-100 text-blue-700 rounded-full">
                        {section.badge}
                      </span>
                    )}
                    {hasSubItems && (
                      <ChevronRight
                        className={cn(
                          "h-4 w-4 ml-auto transition-transform duration-200",
                          isSectionExpanded && "rotate-90"
                        )}
                      />
                    )}
                  </>
                )}
              </Link>

              {/* Sub-items - only visible when expanded and section is expanded */}
              {isExpanded && hasSubItems && isSectionExpanded && (
                <div className="ml-4 mt-1 space-y-1">
                  {section.subItems!.map((subItem) => (
                    <Link
                      key={subItem.href}
                      href={subItem.href}
                      className={cn(
                        "flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-200 text-sm",
                        isSubItemActive(subItem.href)
                          ? "bg-blue-50 text-blue-700 border-l-2 border-blue-400"
                          : "text-gray-600 hover:bg-gray-50 hover:text-gray-900"
                      )}
                    >
                      <div className="w-2 h-2 bg-gray-400 rounded-full" />
                      <span className="truncate">{subItem.name}</span>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </nav>


    </div>
  );
}