"use client";

import { WidgetCard } from "./WidgetCard";
import { AlertTriangle, Shield, XCircle, Info } from "lucide-react";

interface LogEntry {
  id: string;
  level: "error" | "warning" | "info";
  message: string;
  timestamp: string;
  source: string;
}

interface RecentLogsProps {
  logs: LogEntry[];
}

export function RecentLogs({ logs }: RecentLogsProps) {
  const getLevelIcon = (level: string) => {
    switch (level) {
      case "error": return <XCircle className="h-4 w-4 text-red-500" />;
      case "warning": return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default: return <Info className="h-4 w-4 text-blue-500" />;
    }
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case "error": return "border-l-red-500 bg-red-900/20";
      case "warning": return "border-l-yellow-500 bg-yellow-900/20";
      default: return "border-l-blue-500 bg-blue-900/20";
    }
  };

  return (
    <WidgetCard title="Recent Logs & Events">
      <div className="space-y-2 max-h-64 overflow-y-auto">
        {logs.map((log) => (
          <div 
            key={log.id} 
            className={`flex items-start gap-3 p-3 rounded-lg border-l-4 ${getLevelColor(log.level)}`}
          >
            {getLevelIcon(log.level)}
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-white truncate">
                {log.message}
              </p>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-xs text-gray-400">{log.source}</span>
                <span className="text-xs text-gray-500">•</span>
                <span className="text-xs text-gray-400">{log.timestamp}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </WidgetCard>
  );
}