"use client";

import { ReactNode, useState } from "react";
import { cn } from "@/lib/utils";
import { Maximize2, Settings, MoreVertical, RefreshCw, Download } from "lucide-react";

interface ModernWidgetProps {
  title: string;
  children: ReactNode;
  className?: string;
  actions?: ReactNode;
  variant?: "default" | "glass" | "gradient" | "minimal";
  size?: "small" | "medium" | "large" | "full";
  loading?: boolean;
  error?: string;
  onRefresh?: () => void;
  onExport?: () => void;
  onMaximize?: () => void;
  showHeader?: boolean;
  headerActions?: boolean;
}

export function ModernWidget({ 
  title, 
  children, 
  className,
  actions,
  variant = "default",
  size = "medium",
  loading = false,
  error,
  onRefresh,
  onExport,
  onMaximize,
  showHeader = true,
  headerActions = true
}: ModernWidgetProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const getVariantClasses = () => {
    switch (variant) {
      case "glass": 
        return "bg-white/10 backdrop-blur-md border-white/20 text-white";
      case "gradient":
        return "bg-gradient-to-br from-white via-gray-50 to-white border-gray-200";
      case "minimal":
        return "bg-transparent border-0 text-black";
      default:
        return "bg-white border-gray-200 text-black";
    }
  };

  const getHeaderClasses = () => {
    switch (variant) {
      case "glass":
        return "border-white/10 bg-white/5";
      case "gradient":
        return "border-gray-200 bg-gradient-to-r from-gray-50/50 to-transparent";
      case "minimal":
        return "border-0 bg-transparent";
      default:
        return "border-gray-200 bg-gray-50/50";
    }
  };

  return (
    <div className={cn(
      "relative group rounded-2xl overflow-hidden transition-all duration-500 hover:shadow-2xl",
      getVariantClasses(),
      loading && "opacity-50",
      error && "border-red-200/50",
      className
    )}>
      {/* Background decoration */}
      {variant === "gradient" && (
        <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-transparent to-purple-500/5 pointer-events-none" />
      )}

      {/* Header */}
      {showHeader && (
        <div className={cn(
          "flex items-center justify-between px-6 py-4 border-b transition-all duration-300",
          getHeaderClasses()
        )}>
          <div className="flex items-center gap-3">
            <div className="w-2 h-2 rounded-full bg-gradient-to-r from-blue-500 to-purple-600 animate-pulse" />
            <h3 className={cn(
              "text-base font-semibold",
              variant === "glass" ? "text-white" : "text-gray-900"
            )}>
              {title}
            </h3>
          </div>
          
          {headerActions && (
            <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-all duration-300">
              {actions}
              
              {onRefresh && (
                <button
                  onClick={onRefresh}
                  className={cn(
                    "p-2 rounded-lg transition-all duration-200",
                    variant === "glass" 
                      ? "hover:bg-white/10 text-white/80 hover:text-white" 
                      : "hover:bg-gray-100 text-gray-500 hover:text-gray-700"
                  )}
                  title="Refresh"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
              )}
              
              {onExport && (
                <button
                  onClick={onExport}
                  className={cn(
                    "p-2 rounded-lg transition-all duration-200",
                    variant === "glass" 
                      ? "hover:bg-white/10 text-white/80 hover:text-white" 
                      : "hover:bg-gray-100 text-gray-500 hover:text-gray-700"
                  )}
                  title="Export"
                >
                  <Download className="w-4 h-4" />
                </button>
              )}
              
              <button
                onClick={() => setIsExpanded(!isExpanded)}
                className={cn(
                  "p-2 rounded-lg transition-all duration-200",
                  variant === "glass" 
                    ? "hover:bg-white/10 text-white/80 hover:text-white" 
                    : "hover:bg-gray-100 text-gray-500 hover:text-gray-700"
                )}
                title="Expand"
              >
                <Maximize2 className="w-4 h-4" />
              </button>
              
              <button
                className={cn(
                  "p-2 rounded-lg transition-all duration-200",
                  variant === "glass" 
                    ? "hover:bg-white/10 text-white/80 hover:text-white" 
                    : "hover:bg-gray-100 text-gray-500 hover:text-gray-700"
                )}
                title="Settings"
              >
                <Settings className="w-4 h-4" />
              </button>
              
              <button
                className={cn(
                  "p-2 rounded-lg transition-all duration-200",
                  variant === "glass" 
                    ? "hover:bg-white/10 text-white/80 hover:text-white" 
                    : "hover:bg-gray-100 text-gray-500 hover:text-gray-700"
                )}
                title="More"
              >
                <MoreVertical className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      )}

      {/* Content */}
      <div className={cn(
        "relative",
        showHeader ? "p-6" : "p-6 pt-4",
        isExpanded && "min-h-[500px]"
      )}>
        {loading && (
          <div className="absolute inset-0 flex items-center justify-center bg-white/80 backdrop-blur-sm z-10">
            <div className="flex flex-col items-center gap-3">
              <div className="w-10 h-10 border-3 border-gray-200 border-t-blue-500 rounded-full animate-spin" />
              <p className="text-sm text-gray-600 font-medium">Loading...</p>
            </div>
          </div>
        )}
        
        {error && (
          <div className="absolute inset-0 flex items-center justify-center bg-red-50/80 backdrop-blur-sm z-10">
            <div className="text-center">
              <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-3">
                <span className="text-red-600 text-2xl">⚠</span>
              </div>
              <p className="text-red-800 font-medium mb-1">Error</p>
              <p className="text-red-600 text-sm">{error}</p>
            </div>
          </div>
        )}
        
        {children}
      </div>

      {/* Subtle border animation */}
      <div className="absolute inset-0 rounded-2xl pointer-events-none">
        <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-transparent via-blue-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
      </div>
    </div>
  );
}