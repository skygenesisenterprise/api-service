"use client";

import { useState, useEffect, ReactNode } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { LucideIcon, TrendingUp, TrendingDown, Activity } from "lucide-react";

interface MetricCardProps {
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
}

export function MetricCard({ 
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
  unit = ""
}: MetricCardProps) {
  const [currentValue, setCurrentValue] = useState(value);
  const [isAnimating, setIsAnimating] = useState(false);
  const [pulseIntensity, setPulseIntensity] = useState(0);

  // Simulation de données en temps réel
  useEffect(() => {
    if (!isRealTime) return;

    const interval = setInterval(() => {
      // Variation aléatoire réaliste
      const variation = (Math.random() - 0.5) * 10; // -5 à +5
      const newValue = Math.max(minValue, Math.min(maxValue, Number(currentValue) + variation));
      
      setCurrentValue(newValue);
      setPulseIntensity(Math.abs(variation) / 10); // Intensité basée sur la variation
      
      // Animation de pulse
      setIsAnimating(true);
      setTimeout(() => setIsAnimating(false), 300);
    }, 2000 + Math.random() * 3000); // Toutes les 2-5 secondes

    return () => clearInterval(interval);
  }, [isRealTime, currentValue, minValue, maxValue]);

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

  // Calcul de la progression pour la barre animée
  const progress = ((Number(currentValue) - minValue) / (maxValue - minValue)) * 100;

  return (
    <Card className={cn(
      "relative overflow-hidden transition-all duration-300 hover:shadow-lg", 
      isAnimating && "scale-[1.02]",
      className
    )}>
      {/* Barre de progression animée en arrière-plan */}
      {isRealTime && (
        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-blue-50/20 to-transparent opacity-30">
          <div 
            className="h-full bg-blue-500/10 transition-all duration-500 ease-out"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}
      
      <CardContent className="p-6 relative">
        {/* Indicateur de temps réel */}
        {isRealTime && (
          <div className="absolute top-2 right-2 flex items-center gap-1">
            <div className={cn(
              "w-2 h-2 rounded-full transition-all duration-300",
              isAnimating ? "bg-green-500 animate-pulse" : "bg-green-400"
            )} />
            <span className="text-xs text-green-600 font-medium">LIVE</span>
          </div>
        )}

        <div className="flex items-center justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <p className="text-sm font-medium text-muted-foreground">{title}</p>
              {isRealTime && (
                <Activity className={cn(
                  "h-3 w-3 text-blue-500 transition-all duration-300",
                  isAnimating && "animate-spin"
                )} />
              )}
            </div>
            
            <div className="flex items-baseline gap-1 mt-1">
              <p className={cn(
                "text-2xl font-bold transition-all duration-300",
                isAnimating && "text-blue-600 scale-105"
              )}>
                {typeof currentValue === 'number' ? currentValue.toFixed(1) : currentValue}
              </p>
              {unit && (
                <span className="text-sm text-gray-500 font-medium">{unit}</span>
              )}
            </div>
            
            {description && (
              <p className="text-xs text-muted-foreground mt-1">{description}</p>
            )}
            
            {change !== undefined && (
              <div className={cn(
                "flex items-center mt-2 text-sm transition-all duration-300",
                getChangeColor(),
                isAnimating && "scale-105"
              )}>
                {changeType === "increase" ? (
                  <TrendingUp className="h-4 w-4 mr-1" />
                ) : (
                  <TrendingDown className="h-4 w-4 mr-1" />
                )}
                <span>{Math.abs(change)}%</span>
              </div>
            )}

            {/* Mini graphique en temps réel */}
            {isRealTime && (
              <div className="mt-3 h-8 flex items-end gap-1">
                {[...Array(20)].map((_, i) => (
                  <div
                    key={i}
                    className={cn(
                      "w-1 bg-blue-400 transition-all duration-300 rounded-t",
                      isAnimating && i === 19 && "bg-blue-600"
                    )}
                    style={{ 
                      height: `${Math.random() * 100}%`,
                      opacity: 0.3 + (i / 20) * 0.7
                    }}
                  />
                ))}
              </div>
            )}
          </div>
          
          {Icon && (
            <div className={cn(
              "p-3 rounded-lg transition-all duration-300",
              getStatusColor(),
              isAnimating && "scale-110 shadow-lg",
              pulseIntensity > 0.5 && "animate-pulse"
            )}>
              <Icon className="h-6 w-6" />
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}