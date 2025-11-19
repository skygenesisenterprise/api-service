"use client";

import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { LucideIcon, TrendingUp, TrendingDown, Activity } from "lucide-react";

interface GrafanaMetricCardProps {
  title: string;
  value: string | number;
  change?: number;
  changeType?: "increase" | "decrease";
  icon?: LucideIcon;
  description?: string;
  status?: "success" | "warning" | "error" | "info";
  className?: string;
  isRealTime?: boolean;
  minValue?: number;
  maxValue?: number;
  unit?: string;
  sparkline?: boolean;
  variant?: "default" | "compact" | "minimal";
}

export function GrafanaMetricCard({ 
  title, 
  value, 
  change, 
  changeType, 
  icon: Icon, 
  description, 
  status = "info",
  className,
  isRealTime = false,
  minValue = 0,
  maxValue = 100,
  unit = "",
  sparkline = true,
  variant = "default"
}: GrafanaMetricCardProps) {
  const [currentValue, setCurrentValue] = useState(value);
  const [isAnimating, setIsAnimating] = useState(false);
  const [sparklineData, setSparklineData] = useState<number[]>([]);

  // Simulation de données en temps réel
  useEffect(() => {
    if (!isRealTime) return;

    const interval = setInterval(() => {
      const variation = (Math.random() - 0.5) * 10;
      const newValue = Math.max(minValue, Math.min(maxValue, Number(currentValue) + variation));
      
      setCurrentValue(newValue);
      setIsAnimating(true);
      setTimeout(() => setIsAnimating(false), 300);

      // Update sparkline data
      setSparklineData(prev => {
        const newData = [...prev, Number(newValue)];
        return newData.slice(-20); // Keep last 20 points
      });
    }, 2000 + Math.random() * 3000);

    // Initialize sparkline data
    setSparklineData(Array.from({ length: 20 }, () => 
      minValue + Math.random() * (maxValue - minValue)
    ));

    return () => clearInterval(interval);
  }, [isRealTime, currentValue, minValue, maxValue]);

  const getStatusColor = () => {
    switch (status) {
      case "success": return "text-gray-700";
      case "warning": return "text-gray-600";
      case "error": return "text-gray-800";
      default: return "text-gray-700";
    }
  };

  const getStatusBg = () => {
    switch (status) {
      case "success": return "bg-gray-100 border-gray-300";
      case "warning": return "bg-gray-100 border-gray-400";
      case "error": return "bg-gray-100 border-gray-500";
      default: return "bg-gray-100 border-gray-300";
    }
  };

  const getChangeColor = () => {
    if (!change) return "text-gray-500";
    return changeType === "increase" ? "text-gray-700" : "text-gray-600";
  };

  const getVariantClasses = () => {
    switch (variant) {
      case "compact":
        return "p-3";
      case "minimal":
        return "p-2";
      default:
        return "p-4";
    }
  };

  const progress = ((Number(currentValue) - minValue) / (maxValue - minValue)) * 100;

  return (
    <div className={cn(
      "relative bg-white border border-gray-200 rounded-lg overflow-hidden transition-all duration-300 hover:border-gray-400 hover:shadow-2xl",
      isAnimating && "scale-[1.02] border-gray-500",
      getVariantClasses(),
      className
    )}>
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-br from-white via-gray-50 to-white opacity-50" />
      
      {/* Progress bar */}
      {isRealTime && (
        <div className="absolute bottom-0 left-0 right-0 h-1 bg-gray-200">
          <div 
            className="h-full transition-all duration-500 ease-out bg-gray-700"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      <div className="relative z-10">
        {/* Header */}
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            {Icon && (
              <div className={cn(
                "p-1.5 rounded border transition-all duration-300",
                getStatusBg(),
                isAnimating && "scale-110 shadow-lg"
              )}>
                <Icon className={cn("w-4 h-4", getStatusColor())} />
              </div>
            )}
            <div>
            <p className="text-xs font-medium text-gray-700 uppercase tracking-wider">{title}</p>
            {description && (
              <p className="text-xs text-gray-500 mt-0.5">{description}</p>
            )}
            </div>
          </div>
          
          {isRealTime && (
            <div className="flex items-center gap-1">
              <div className={cn(
                "w-1.5 h-1.5 rounded-full transition-all duration-300",
                isAnimating ? "bg-gray-700 animate-pulse" : "bg-gray-700/50"
              )} />
              <span className="text-xs text-gray-700 font-mono">LIVE</span>
            </div>
          )}
        </div>

        {/* Value */}
        <div className="flex items-baseline gap-1 mb-2">
          <p className={cn(
            "text-2xl font-bold text-black transition-all duration-300 tabular-nums",
            isAnimating && "text-gray-700 scale-105"
          )}>
            {typeof currentValue === 'number' ? currentValue.toFixed(1) : currentValue}
          </p>
          {unit && (
            <span className="text-sm text-gray-600 font-medium">{unit}</span>
          )}
        </div>

        {/* Change indicator */}
        {change !== undefined && (
          <div className={cn(
            "flex items-center text-sm transition-all duration-300",
            getChangeColor(),
            isAnimating && "scale-105"
          )}>
            {changeType === "increase" ? (
              <TrendingUp className="h-3 w-3 mr-1" />
            ) : (
              <TrendingDown className="h-3 w-3 mr-1" />
            )}
            <span className="font-mono">{Math.abs(change)}%</span>
          </div>
        )}

        {/* Sparkline */}
        {sparkline && isRealTime && sparklineData.length > 0 && (
          <div className="mt-3 h-8 flex items-end gap-0.5">
            {sparklineData.map((value, i) => {
              const height = ((value - minValue) / (maxValue - minValue)) * 100;
              const opacity = 0.3 + (i / sparklineData.length) * 0.7;
              const isLatest = i === sparklineData.length - 1;
              
              return (
                <div
                  key={i}
                  className={cn(
                    "flex-1 transition-all duration-300 rounded-t",
                    isLatest && isAnimating ? "bg-gray-700" : "bg-gray-400/30"
                  )}
                  style={{ 
                    height: `${height}%`,
                    opacity
                  }}
                />
              );
            })}
          </div>
        )}
      </div>

      {/* Subtle glow effect */}
      {isAnimating && (
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute inset-0 bg-gray-700/5 animate-pulse" />
        </div>
      )}
    </div>
  );
}