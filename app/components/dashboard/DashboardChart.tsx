"use client";

import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Area, AreaChart } from "recharts";
import { WidgetCard } from "./WidgetCard";

interface ChartData {
  name: string;
  requests: number;
  latency: number;
  errors: number;
}

interface DashboardChartProps {
  data: ChartData[];
  timeRange: "24h" | "7d" | "30d";
  onTimeRangeChange: (range: "24h" | "7d" | "30d") => void;
}

export function DashboardChart({ data, timeRange, onTimeRangeChange }: DashboardChartProps) {
  return (
    <WidgetCard 
      title="Performance Overview"
      headerAction={
        <div className="flex gap-1">
          {(["24h", "7d", "30d"] as const).map((range) => (
            <button
              key={range}
              onClick={() => onTimeRangeChange(range)}
              className={`px-3 py-1 text-xs rounded-md transition-colors ${
                timeRange === range
                  ? "bg-blue-100 text-blue-700"
                  : "text-gray-600 hover:bg-gray-100"
              }`}
            >
              {range}
            </button>
          ))}
        </div>
      }
    >
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
          <XAxis 
            dataKey="name" 
            stroke="#888"
            fontSize={12}
          />
          <YAxis 
            stroke="#888"
            fontSize={12}
          />
          <Tooltip 
            contentStyle={{ 
              backgroundColor: "rgba(255, 255, 255, 0.95)",
              border: "1px solid #e0e0e0",
              borderRadius: "8px"
            }}
          />
          <Area
            type="monotone"
            dataKey="requests"
            stackId="1"
            stroke="#3b82f6"
            fill="#3b82f6"
            fillOpacity={0.6}
          />
          <Area
            type="monotone"
            dataKey="latency"
            stackId="2"
            stroke="#10b981"
            fill="#10b981"
            fillOpacity={0.4}
          />
          <Area
            type="monotone"
            dataKey="errors"
            stackId="3"
            stroke="#ef4444"
            fill="#ef4444"
            fillOpacity={0.3}
          />
        </AreaChart>
      </ResponsiveContainer>
    </WidgetCard>
  );
}