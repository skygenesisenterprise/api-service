"use client";

import { WidgetCard } from "./WidgetCard";
import { Shield, AlertTriangle, UserX, Key } from "lucide-react";

interface SecurityAlert {
  id: string;
  type: "failed_login" | "suspicious_activity" | "api_key_abuse" | "permission_change";
  message: string;
  severity: "low" | "medium" | "high" | "critical";
  timestamp: string;
  user?: string;
  ip?: string;
}

interface SecurityAlertsProps {
  alerts: SecurityAlert[];
}

export function SecurityAlerts({ alerts }: SecurityAlertsProps) {
  const getAlertIcon = (type: string) => {
    switch (type) {
      case "failed_login": return <UserX className="h-4 w-4 text-red-500" />;
      case "suspicious_activity": return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case "api_key_abuse": return <Key className="h-4 w-4 text-orange-500" />;
      case "permission_change": return <Shield className="h-4 w-4 text-blue-500" />;
      default: return <AlertTriangle className="h-4 w-4 text-gray-500" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "border-l-red-600 bg-red-900/20";
      case "high": return "border-l-red-500 bg-red-900/20";
      case "medium": return "border-l-yellow-500 bg-yellow-900/20";
      default: return "border-l-blue-500 bg-blue-900/20";
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-600/20 text-red-400";
      case "high": return "bg-red-600/20 text-red-400";
      case "medium": return "bg-yellow-600/20 text-yellow-400";
      default: return "bg-blue-600/20 text-blue-400";
    }
  };

  return (
    <WidgetCard title="Security Alerts (ZTNA/IAM)">
      <div className="space-y-2 max-h-64 overflow-y-auto">
        {alerts.map((alert) => (
          <div 
            key={alert.id} 
            className={`flex items-start gap-3 p-3 rounded-lg border-l-4 ${getSeverityColor(alert.severity)}`}
          >
            {getAlertIcon(alert.type)}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${getSeverityBadge(alert.severity)}`}>
                  {alert.severity.toUpperCase()}
                </span>
                <span className="text-xs text-gray-500">{alert.timestamp}</span>
              </div>
              <p className="text-sm font-medium text-white">
                {alert.message}
              </p>
              {(alert.user || alert.ip) && (
                <div className="flex items-center gap-2 mt-1">
                  {alert.user && (
                    <span className="text-xs text-gray-400">User: {alert.user}</span>
                  )}
                  {alert.ip && (
                    <>
                      <span className="text-xs text-gray-500">•</span>
                      <span className="text-xs text-gray-400">IP: {alert.ip}</span>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </WidgetCard>
  );
}