"use client";

import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts";
import { WidgetCard } from "./WidgetCard";

interface ProjectUsage {
  [key: string]: any;
  name: string;
  requests: number;
  percentage: number;
  color: string;
}

interface ProjectUsageProps {
  data: ProjectUsage[];
  chartType?: "pie" | "bar";
}

export function ProjectUsage({ data, chartType = "pie" }: ProjectUsageProps) {
  if (chartType === "bar") {
    return (
      <WidgetCard title="Project Usage Distribution">
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis 
              dataKey="name" 
              fontSize={12}
              angle={-45}
              textAnchor="end"
              height={60}
            />
            <YAxis fontSize={12} />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: "rgba(255, 255, 255, 0.95)",
                border: "1px solid #e0e0e0",
                borderRadius: "8px"
              }}
            />
            <Bar dataKey="requests" radius={[4, 4, 0, 0]}>
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </WidgetCard>
    );
  }

  return (
    <WidgetCard title="Project Usage Distribution">
      <ResponsiveContainer width="100%" height={250}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            paddingAngle={2}
            dataKey="requests"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip 
            contentStyle={{ 
              backgroundColor: "rgba(255, 255, 255, 0.95)",
              border: "1px solid #e0e0e0",
              borderRadius: "8px"
            }}
            formatter={(value: number, name: string, props: any) => [
              `${value.toLocaleString()} requests (${props.payload.percentage}%)`,
              props.payload.name
            ]}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="mt-4 space-y-2">
        {data.map((project, index) => (
          <div key={project.name} className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <div 
                className="w-3 h-3 rounded-full" 
                style={{ backgroundColor: project.color }}
              />
              <span className="text-gray-300">{project.name}</span>
            </div>
            <span className="text-white font-medium">
              {project.percentage}%
            </span>
          </div>
        ))}
      </div>
    </WidgetCard>
  );
}