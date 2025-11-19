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
      case "error": return <XCircle className="h-4 w-4 text-gray-700" />;
      case "warning": return <AlertTriangle className="h-4 w-4 text-gray-600" />;
      default: return <Info className="h-4 w-4 text-gray-500" />;
    }
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case "error": return "border-l-gray-700 bg-gray-50";
      case "warning": return "border-l-gray-600 bg-gray-50";
      default: return "border-l-gray-500 bg-gray-50";
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
              <p className="text-sm font-medium text-gray-900 truncate">
                {log.message}
              </p>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-xs text-gray-600">{log.source}</span>
                <span className="text-xs text-gray-400">•</span>
                <span className="text-xs text-gray-500">{log.timestamp}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </WidgetCard>
  );
}