"use client";

import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Area, AreaChart, BarChart, Bar } from "recharts";
import { cn } from "@/lib/utils";

interface ModernChartProps {
  data: any[];
  title?: string;
  type?: "line" | "area" | "bar";
  height?: number;
  colors?: string[];
  grid?: boolean;
  legend?: boolean;
  timeRange?: "24h" | "7d" | "30d";
  onTimeRangeChange?: (range: "24h" | "7d" | "30d") => void;
  className?: string;
  yAxisLabel?: string;
  xAxisLabel?: string;
  showTooltip?: boolean;
  animated?: boolean;
  variant?: "default" | "gradient" | "minimal";
  curved?: boolean;
  strokeWidth?: number;
  showDots?: boolean;
  gradient?: boolean;
}

export function ModernChart({ 
  data, 
  title,
  type = "line",
  height = 300,
  colors = ["#3b82f6", "#8b5cf6", "#10b981", "#f59e0b", "#ef4444"],
  grid = true,
  legend = false,
  timeRange,
  onTimeRangeChange,
  className,
  yAxisLabel,
  xAxisLabel,
  showTooltip = true,
  animated = true,
  variant = "default",
  curved = true,
  strokeWidth = 2,
  showDots = false,
  gradient = true
}: ModernChartProps) {
  const ChartComponent = type === "area" ? AreaChart : type === "bar" ? BarChart : LineChart;

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (!active || !payload || !showTooltip) return null;

    return (
      <div className="bg-white/95 backdrop-blur-sm border border-gray-200 rounded-xl p-4 shadow-xl">
        <p className="text-sm font-semibold text-gray-900 mb-3">{label}</p>
        {payload.map((entry: any, index: number) => (
          <div key={index} className="flex items-center justify-between gap-4 text-sm mb-2">
            <div className="flex items-center gap-2">
              <div 
                className="w-3 h-3 rounded-full" 
                style={{ backgroundColor: entry.color }}
              />
              <span className="text-gray-600 font-medium">{entry.name}:</span>
            </div>
            <span className="text-gray-900 font-mono font-semibold">
              {typeof entry.value === 'number' ? entry.value.toFixed(2) : entry.value}
            </span>
          </div>
        ))}
      </div>
    );
  };

  const getVariantClasses = () => {
    switch (variant) {
      case "gradient":
        return "bg-gradient-to-br from-blue-50/50 via-transparent to-purple-50/50";
      case "minimal":
        return "bg-transparent";
      default:
        return "bg-white";
    }
  };

  return (
    <div className={cn("rounded-xl overflow-hidden", getVariantClasses(), className)}>
      {/* Header */}
      {(title || timeRange) && (
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200/50">
          {title && (
            <h3 className="text-base font-semibold text-gray-900">{title}</h3>
          )}
          
          {timeRange && onTimeRangeChange && (
            <div className="flex gap-1 bg-gray-100 rounded-lg p-1">
              {(["24h", "7d", "30d"] as const).map((range) => (
                <button
                  key={range}
                  onClick={() => onTimeRangeChange(range)}
                  className={cn(
                    "px-3 py-1.5 text-sm font-medium rounded-md transition-all",
                    timeRange === range
                      ? "bg-white text-gray-900 shadow-sm"
                      : "text-gray-600 hover:text-gray-900"
                  )}
                >
                  {range}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Chart */}
      <div className="p-6">
        <ResponsiveContainer width="100%" height={height}>
          <ChartComponent data={data} margin={{ top: 10, right: 10, bottom: 10, left: 10 }}>
            {grid && (
              <CartesianGrid 
                strokeDasharray="3 3" 
                stroke="#e5e7eb" 
                horizontal={true}
                vertical={false}
                opacity={0.5}
              />
            )}
            
            <XAxis 
              dataKey="name" 
              stroke="#9ca3af"
              fontSize={11}
              tickLine={false}
              axisLine={false}
              tick={{ fill: '#6b7280' }}
              label={xAxisLabel ? { 
                value: xAxisLabel, 
                position: 'insideBottom', 
                offset: -8, 
                style: { fill: '#6b7280', fontSize: 11, fontWeight: 500 } 
              } : undefined}
            />
            
            <YAxis 
              stroke="#9ca3af"
              fontSize={11}
              tickLine={false}
              axisLine={false}
              tick={{ fill: '#6b7280' }}
              label={yAxisLabel ? { 
                value: yAxisLabel, 
                angle: -90, 
                position: 'insideLeft', 
                style: { fill: '#6b7280', fontSize: 11, fontWeight: 500 } 
              } : undefined}
            />
            
            {showTooltip && <Tooltip content={<CustomTooltip />} />}
            
            {/* Dynamic lines/areas/bars based on data keys */}
            {data.length > 0 && Object.keys(data[0])
              .filter(key => key !== 'name' && typeof data[0][key] === 'number')
              .map((key, index) => {
                const color = colors[index % colors.length];
                
                if (type === "area") {
                  return (
                    <Area
                      key={key}
                      type={curved ? "monotone" : "linear"}
                      dataKey={key}
                      stroke={color}
                      fill={gradient ? `url(#gradient-${index})` : color}
                      fillOpacity={gradient ? 0.8 : 0.2}
                      strokeWidth={strokeWidth}
                      animationDuration={animated ? 1500 : 0}
                      name={key.charAt(0).toUpperCase() + key.slice(1).replace(/([A-Z])/g, ' $1')}
                      dot={showDots}
                    />
                  );
                } else if (type === "bar") {
                  return (
                    <Bar
                      key={key}
                      dataKey={key}
                      fill={gradient ? `url(#gradient-${index})` : color}
                      animationDuration={animated ? 1500 : 0}
                      name={key.charAt(0).toUpperCase() + key.slice(1).replace(/([A-Z])/g, ' $1')}
                      radius={[4, 4, 0, 0]}
                    />
                  );
                } else {
                  return (
                    <Line
                      key={key}
                      type={curved ? "monotone" : "linear"}
                      dataKey={key}
                      stroke={color}
                      strokeWidth={strokeWidth}
                      dot={showDots ? { r: 3, fill: color } : false}
                      activeDot={{ r: 5, fill: color, stroke: '#fff', strokeWidth: 2 }}
                      animationDuration={animated ? 1500 : 0}
                      name={key.charAt(0).toUpperCase() + key.slice(1).replace(/([A-Z])/g, ' $1')}
                    />
                  );
                }
              })}
            
            {/* Gradient definitions */}
            {gradient && data.length > 0 && Object.keys(data[0])
              .filter(key => key !== 'name' && typeof data[0][key] === 'number')
              .map((key, index) => {
                const color = colors[index % colors.length];
                return (
                  <defs key={`gradient-${index}`}>
                    <linearGradient id={`gradient-${index}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={color} stopOpacity={0.8}/>
                      <stop offset="95%" stopColor={color} stopOpacity={0.1}/>
                    </linearGradient>
                  </defs>
                );
              })}
          </ChartComponent>
        </ResponsiveContainer>
      </div>
    </div>
  );
}