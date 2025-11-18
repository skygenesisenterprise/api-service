"use client";

import { LucideIcon, CheckCircle, AlertTriangle, XCircle, Clock } from "lucide-react";
import { cn } from "@/app/lib/utils";

interface ServiceStatusProps {
  name: string;
  status: "healthy" | "warning" | "error" | "unknown";
  latency?: number;
  load?: number;
  icon?: LucideIcon;
  className?: string;
}

export function ServiceStatus({ 
  name, 
  status, 
  latency, 
  load, 
  icon: Icon, 
  className 
}: ServiceStatusProps) {
  const getStatusIcon = () => {
    switch (status) {
      case "healthy": return <CheckCircle className="h-4 w-4 text-green-500" />;
      case "warning": return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case "error": return <XCircle className="h-4 w-4 text-red-500" />;
      default: return <Clock className="h-4 w-4 text-gray-400" />;
    }
  };

  const getStatusColor = () => {
    switch (status) {
      case "healthy": return "border-green-800 bg-green-900/20";
      case "warning": return "border-yellow-800 bg-yellow-900/20";
      case "error": return "border-red-800 bg-red-900/20";
      default: return "border-gray-700 bg-gray-800/50";
    }
  };

  const getLatencyColor = () => {
    if (!latency) return "text-gray-500";
    if (latency < 100) return "text-green-600";
    if (latency < 500) return "text-yellow-600";
    return "text-red-600";
  };

  return (
    <div className={cn(
      "flex items-center justify-between p-3 rounded-lg border transition-all hover:shadow-sm",
      getStatusColor(),
      className
    )}>
      <div className="flex items-center gap-3">
        {Icon && <Icon className="h-5 w-5 text-gray-400" />}
        <div>
          <p className="text-sm font-medium text-white">{name}</p>
          {latency && (
            <p className={cn("text-xs", getLatencyColor())}>
              {latency}ms
            </p>
          )}
        </div>
      </div>
      <div className="flex items-center gap-2">
        {load !== undefined && (
          <div className="text-xs text-gray-400">
            {load}%
          </div>
        )}
        {getStatusIcon()}
      </div>
    </div>
  );
}