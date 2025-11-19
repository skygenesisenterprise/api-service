"use client";

import { ReactNode, useState } from "react";
import { cn } from "@/lib/utils";
import { Maximize2, Settings, MoreVertical } from "lucide-react";

interface GrafanaWidgetProps {
  title: string;
  children: ReactNode;
  className?: string;
  actions?: ReactNode;
  variant?: "default" | "dark" | "transparent";
  size?: "small" | "medium" | "large" | "full";
  loading?: boolean;
  error?: string;
}

export function GrafanaWidget({ 
  title, 
  children, 
  className,
  actions,
  variant = "default",
  size = "medium",
  loading = false,
  error
}: GrafanaWidgetProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const getSizeClasses = () => {
    switch (size) {
      case "small": return "col-span-1 row-span-1";
      case "medium": return "col-span-1 lg:col-span-2 row-span-2";
      case "large": return "col-span-1 lg:col-span-3 row-span-3";
      case "full": return "col-span-1 lg:col-span-4 row-span-2";
      default: return "col-span-1 lg:col-span-2 row-span-2";
    }
  };

  const getVariantClasses = () => {
    switch (variant) {
      case "dark": 
        return "bg-gray-100 border-gray-300 text-black";
      case "transparent":
        return "bg-transparent border-gray-300/30 text-black backdrop-blur-sm";
      default:
        return "bg-white border-gray-200 text-black";
    }
  };

  return (
    <div className={cn(
      "relative group border rounded-lg overflow-hidden transition-all duration-300 hover:border-gray-400 hover:shadow-2xl",
      getSizeClasses(),
      getVariantClasses(),
      loading && "opacity-50",
      error && "border-gray-500/50",
      className
    )}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-gray-200 bg-gradient-to-r from-gray-50 to-gray-100">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-gray-600 animate-pulse" />
          <h3 className="text-sm font-medium text-gray-700">{title}</h3>
        </div>
        
        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          {actions}
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1 hover:bg-gray-100 rounded transition-colors"
          >
            <Maximize2 className="w-3 h-3 text-gray-500" />
          </button>
          <button className="p-1 hover:bg-gray-100 rounded transition-colors">
            <Settings className="w-3 h-3 text-gray-500" />
          </button>
          <button className="p-1 hover:bg-gray-100 rounded transition-colors">
            <MoreVertical className="w-3 h-3 text-gray-500" />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className={cn(
        "p-4 relative",
        isExpanded && "min-h-[400px]"
      )}>
        {loading && (
          <div className="absolute inset-0 flex items-center justify-center bg-white/80 z-10">
            <div className="w-8 h-8 border-2 border-gray-600 border-t-transparent rounded-full animate-spin" />
          </div>
        )}
        
        {error && (
          <div className="absolute inset-0 flex items-center justify-center bg-gray-50/80 z-10">
            <div className="text-center">
              <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-2">
                <span className="text-gray-600 text-xl">⚠</span>
              </div>
              <p className="text-gray-600 text-sm">{error}</p>
            </div>
          </div>
        )}
        
        {children}
      </div>

      {/* Subtle border animation */}
      <div className="absolute inset-0 rounded-lg pointer-events-none">
        <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-transparent via-gray-600/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      </div>
    </div>
  );
}