"use client";

import { ReactNode } from "react";
import { Card, CardContent } from "@/app/components/ui/card";
import { cn } from "@/app/lib/utils";
import { LucideIcon, TrendingUp, TrendingDown } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  change?: number;
  changeType?: "increase" | "decrease";
  icon?: LucideIcon;
  description?: string;
  status?: "success" | "warning" | "error" | "info";
  className?: string;
}

export function MetricCard({ 
  title, 
  value, 
  change, 
  changeType, 
  icon: Icon, 
  description, 
  status = "info",
  className 
}: MetricCardProps) {
  const getStatusColor = () => {
    switch (status) {
      case "success": return "text-green-600 bg-green-50";
      case "warning": return "text-yellow-600 bg-yellow-50";
      case "error": return "text-red-600 bg-red-50";
      default: return "text-blue-600 bg-blue-50";
    }
  };

  const getChangeColor = () => {
    if (!change) return "text-gray-500";
    return changeType === "increase" ? "text-green-600" : "text-red-600";
  };

  return (
    <Card className={cn("relative overflow-hidden bg-gray-900/95 border-gray-800", className)}>
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <p className="text-sm font-medium text-gray-400">{title}</p>
            <p className="text-2xl font-bold mt-1 text-white">{value}</p>
            {description && (
              <p className="text-xs text-gray-500 mt-1">{description}</p>
            )}
            {change !== undefined && (
              <div className={cn("flex items-center mt-2 text-sm", getChangeColor())}>
                {changeType === "increase" ? (
                  <TrendingUp className="h-4 w-4 mr-1" />
                ) : (
                  <TrendingDown className="h-4 w-4 mr-1" />
                )}
                <span>{Math.abs(change)}%</span>
              </div>
            )}
          </div>
          {Icon && (
            <div className={cn("p-3 rounded-lg", getStatusColor())}>
              <Icon className="h-6 w-6" />
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}