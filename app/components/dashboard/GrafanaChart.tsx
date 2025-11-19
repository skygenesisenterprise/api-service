"use client";

import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Area, AreaChart, ReferenceLine } from "recharts";
import { cn } from "@/lib/utils";

interface GrafanaChartProps {
  data: any[];
  title?: string;
  type?: "line" | "area";
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
}

export function GrafanaChart({ 
  data, 
  title,
  type = "line",
  height = 300,
  colors = ["#374151", "#4b5563", "#6b7280", "#9ca3af", "#d1d5db"],
  grid = true,
  legend = false,
  timeRange,
  onTimeRangeChange,
  className,
  yAxisLabel,
  xAxisLabel,
  showTooltip = true,
  animated = true
}: GrafanaChartProps) {
  const ChartComponent = type === "area" ? AreaChart : LineChart;

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (!active || !payload || !showTooltip) return null;

    return (
      <div className="bg-white border border-gray-200 rounded-lg p-3 shadow-xl">
        <p className="text-xs text-gray-600 mb-2">{label}</p>
        {payload.map((entry: any, index: number) => (
          <div key={index} className="flex items-center gap-2 text-xs">
            <div 
              className="w-2 h-2 rounded-full" 
              style={{ backgroundColor: entry.color }}
            />
            <span className="text-gray-600">{entry.name}:</span>
            <span className="text-black font-mono ml-auto">
              {typeof entry.value === 'number' ? entry.value.toFixed(2) : entry.value}
            </span>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className={cn("bg-white border border-gray-200 rounded-lg overflow-hidden", className)}>
      {/* Header */}
      {(title || timeRange) && (
        <div className="flex items-center justify-between px-4 py-2 border-b border-gray-200 bg-gradient-to-r from-gray-50 to-gray-100">
          {title && (
            <h3 className="text-sm font-medium text-gray-700">{title}</h3>
          )}
          
          {timeRange && onTimeRangeChange && (
            <div className="flex gap-1">
              {(["24h", "7d", "30d"] as const).map((range) => (
                <button
                  key={range}
                  onClick={() => onTimeRangeChange(range)}
                  className={cn(
                    "px-2 py-1 text-xs rounded transition-colors font-mono",
                    timeRange === range
                      ? "bg-gray-200 text-gray-700 border border-gray-300"
                      : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"
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
      <div className="p-4">
        <ResponsiveContainer width="100%" height={height}>
          <ChartComponent data={data} margin={{ top: 5, right: 5, bottom: 5, left: 5 }}>
            {grid && (
              <CartesianGrid 
                strokeDasharray="2 2" 
                stroke="#e5e7eb" 
                horizontal={true}
                vertical={false}
              />
            )}
            
            <XAxis 
              dataKey="name" 
              stroke="#9ca3af"
              fontSize={10}
              tickLine={false}
              axisLine={false}
              label={xAxisLabel ? { value: xAxisLabel, position: 'insideBottom', offset: -5, style: { fill: '#9ca3af', fontSize: 10 } } : undefined}
            />
            
            <YAxis 
              stroke="#9ca3af"
              fontSize={10}
              tickLine={false}
              axisLine={false}
              label={yAxisLabel ? { value: yAxisLabel, angle: -90, position: 'insideLeft', style: { fill: '#9ca3af', fontSize: 10 } } : undefined}
            />
            
            {showTooltip && <Tooltip content={<CustomTooltip />} />}
            
            {/* Dynamic lines/areas based on data keys */}
            {data.length > 0 && Object.keys(data[0])
              .filter(key => key !== 'name' && typeof data[0][key] === 'number')
              .map((key, index) => {
                const color = colors[index % colors.length];
                
                if (type === "area") {
                  return (
                    <Area
                      key={key}
                      type="monotone"
                      dataKey={key}
                      stroke={color}
                      fill={color}
                      fillOpacity={0.2}
                      strokeWidth={1.5}
                      animationDuration={animated ? 1000 : 0}
                      name={key.charAt(0).toUpperCase() + key.slice(1)}
                    />
                  );
                } else {
                  return (
                    <Line
                      key={key}
                      type="monotone"
                      dataKey={key}
                      stroke={color}
                      strokeWidth={1.5}
                      dot={false}
                      activeDot={{ r: 3, fill: color }}
                      animationDuration={animated ? 1000 : 0}
                      name={key.charAt(0).toUpperCase() + key.slice(1)}
                    />
                  );
                }
              })}
            
            {/* Reference lines for thresholds */}
            <ReferenceLine y={0} stroke="#d1d5db" strokeWidth={1} />
          </ChartComponent>
        </ResponsiveContainer>
      </div>
    </div>
  );
}