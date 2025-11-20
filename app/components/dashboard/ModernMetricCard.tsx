"use client";

import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { LucideIcon, TrendingUp, TrendingDown, Activity, Zap } from "lucide-react";

interface ModernMetricCardProps {
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
  variant?: "default" | "compact" | "minimal" | "glass";
  trend?: "up" | "down" | "stable";
  progress?: number;
}

export function ModernMetricCard({ 
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
  variant = "default",
  trend,
  progress
}: ModernMetricCardProps) {
  const [currentValue, setCurrentValue] = useState(value);
  const [isAnimating, setIsAnimating] = useState(false);
  const [sparklineData, setSparklineData] = useState<number[]>([]);

  useEffect(() => {
    if (!isRealTime) return;

    const interval = setInterval(() => {
      const variation = (Math.random() - 0.5) * 10;
      const newValue = Math.max(minValue, Math.min(maxValue, Number(currentValue) + variation));
      
      setCurrentValue(newValue);
      setIsAnimating(true);
      setTimeout(() => setIsAnimating(false), 300);

      setSparklineData(prev => {
        const newData = [...prev, Number(newValue)];
        return newData.slice(-20);
      });
    }, 2000 + Math.random() * 3000);

    setSparklineData(Array.from({ length: 20 }, () => 
      minValue + Math.random() * (maxValue - minValue)
    ));

    return () => clearInterval(interval);
  }, [isRealTime, currentValue, minValue, maxValue]);

  const getStatusColor = () => {
    switch (status) {
      case "success": return "from-emerald-500 to-green-600";
      case "warning": return "from-amber-500 to-orange-600";
      case "error": return "from-red-500 to-rose-600";
      default: return "from-blue-500 to-indigo-600";
    }
  };

  const getStatusBg = () => {
    switch (variant) {
      case "glass":
        return "bg-white/10 backdrop-blur-md border-white/20";
      default:
        return "bg-white border-gray-200";
    }
  };

  const getVariantClasses = () => {
    switch (variant) {
      case "compact":
        return "p-4";
      case "minimal":
        return "p-3";
      case "glass":
        return "p-6";
      default:
        return "p-6";
    }
  };

  const progressValue = progress ?? ((Number(currentValue) - minValue) / (maxValue - minValue)) * 100;

  return (
    <div className={cn(
      "relative group overflow-hidden transition-all duration-500 hover:scale-[1.02] hover:shadow-2xl",
      getVariantClasses(),
      getStatusBg(),
      variant === "glass" ? "rounded-2xl" : "rounded-xl",
      className
    )}>
      {/* Background gradient */}
      {variant === "glass" ? (
        <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-white/5" />
      ) : (
        <div className="absolute inset-0 bg-gradient-to-br from-gray-50/50 to-white/50" />
      )}
      
      {/* Progress indicator */}
      {isRealTime && (
        <div className="absolute bottom-0 left-0 right-0 h-1 bg-gray-200/50">
          <div 
            className={cn("h-full transition-all duration-700 ease-out bg-gradient-to-r", getStatusColor())}
            style={{ width: `${progressValue}%` }}
          />
        </div>
      )}

      <div className="relative z-10">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            {Icon && (
              <div className={cn(
                "relative p-3 rounded-xl transition-all duration-300",
                variant === "glass" 
                  ? "bg-white/20 backdrop-blur-sm" 
                  : "bg-gray-100",
                isAnimating && "scale-110 shadow-lg"
              )}>
                {isAnimating && (
                  <div className="absolute inset-0 bg-gradient-to-r opacity-20 rounded-xl animate-pulse" 
                       style={{ backgroundImage: `linear-gradient(to right, ${getStatusColor().split(' ').join(', ')})` }} />
                )}
                <Icon className={cn("w-5 h-5", 
                  variant === "glass" ? "text-white" : "text-gray-700"
                )} />
              </div>
            )}
            <div>
              <p className={cn(
                "text-sm font-semibold uppercase tracking-wider",
                variant === "glass" ? "text-white/90" : "text-gray-700"
              )}>
                {title}
              </p>
              {description && (
                <p className={cn(
                  "text-xs mt-0.5",
                  variant === "glass" ? "text-white/70" : "text-gray-500"
                )}>
                  {description}
                </p>
              )}
            </div>
          </div>
          
          {isRealTime && (
            <div className="flex items-center gap-2">
              <div className={cn(
                "w-2 h-2 rounded-full transition-all duration-300",
                isAnimating ? "bg-emerald-500 animate-pulse shadow-lg shadow-emerald-500/50" : "bg-gray-400"
              )} />
              <span className={cn(
                "text-xs font-semibold font-mono",
                variant === "glass" ? "text-white/90" : "text-gray-700"
              )}>
                LIVE
              </span>
            </div>
          )}
        </div>

        {/* Value */}
        <div className="flex items-baseline gap-2 mb-3">
          <p className={cn(
            "text-3xl font-bold tabular-nums transition-all duration-300",
            variant === "glass" ? "text-white" : "text-gray-900",
            isAnimating && "scale-105"
          )}>
            {typeof currentValue === 'number' ? currentValue.toFixed(1) : currentValue}
          </p>
          {unit && (
            <span className={cn(
              "text-sm font-medium",
              variant === "glass" ? "text-white/80" : "text-gray-600"
            )}>
              {unit}
            </span>
          )}
        </div>

        {/* Change indicator */}
        {(change !== undefined || trend) && (
          <div className={cn(
            "flex items-center gap-2 text-sm font-medium transition-all duration-300",
            trend === "up" || changeType === "increase" 
              ? "text-emerald-600" 
              : trend === "down" || changeType === "decrease"
              ? "text-red-600"
              : "text-gray-500",
            isAnimating && "scale-105"
          )}>
            {(trend === "up" || changeType === "increase") ? (
              <TrendingUp className="h-4 w-4" />
            ) : (trend === "down" || changeType === "decrease") ? (
              <TrendingDown className="h-4 w-4" />
            ) : (
              <Activity className="h-4 w-4" />
            )}
            <span className="font-mono">
              {change !== undefined ? `${Math.abs(change)}%` : trend === "stable" ? "0%" : ""}
            </span>
          </div>
        )}

        {/* Sparkline */}
        {sparkline && isRealTime && sparklineData.length > 0 && (
          <div className="mt-4 h-10 flex items-end gap-0.5">
            {sparklineData.map((value, i) => {
              const height = ((value - minValue) / (maxValue - minValue)) * 100;
              const opacity = 0.3 + (i / sparklineData.length) * 0.7;
              const isLatest = i === sparklineData.length - 1;
              
              return (
                <div
                  key={i}
                  className={cn(
                    "flex-1 transition-all duration-300 rounded-t-sm",
                    isLatest && isAnimating 
                      ? "bg-gradient-to-t from-emerald-500 to-green-400" 
                      : variant === "glass"
                      ? "bg-white/30"
                      : "bg-gray-300/50"
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
          <div className="absolute inset-0 bg-gradient-to-r opacity-10 animate-pulse" 
               style={{ backgroundImage: `linear-gradient(to right, ${getStatusColor().split(' ').join(', ')})` }} />
        </div>
      )}
    </div>
  );
}