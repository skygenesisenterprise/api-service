"use client";

interface RealTimeMetric {
  value: number;
  timestamp: Date;
  change?: number;
  changeType?: "increase" | "decrease";
}

interface EndpointData {
  path: string;
  method: string;
  requests: number;
  avgLatency: number;
  status: "healthy" | "warning" | "critical";
  lastCalled: Date;
  percentage?: number;
  color?: string;
}

interface LogEntry {
  id: string;
  level: "info" | "warning" | "error";
  message: string;
  timestamp: Date;
  source: string;
}

interface SecurityAlert {
  id: string;
  type: "failed_login" | "suspicious_activity" | "api_key_abuse" | "permission_change";
  message: string;
  severity: "low" | "medium" | "high" | "critical";
  timestamp: Date;
  user?: string;
  ip?: string;
}

class RealTimeDataService {
  private metrics: Map<string, RealTimeMetric[]> = new Map();
  private endpoints: Map<string, EndpointData> = new Map();
  private logs: LogEntry[] = [];
  private securityAlerts: SecurityAlert[] = [];
  private callbacks: Set<() => void> = new Set();
  private intervalId: NodeJS.Timeout | null = null;

  constructor() {
    this.initializeData();
    this.startRealTimeUpdates();
  }

  private initializeData() {
    // Initialiser les métrics avec des valeurs réalistes
    this.metrics.set("requests", [
      { value: 1247, timestamp: new Date(), change: 12.5, changeType: "increase" }
    ]);
    
    this.metrics.set("latency", [
      { value: 45, timestamp: new Date(), change: -8.2, changeType: "decrease" }
    ]);
    
    this.metrics.set("errorRate", [
      { value: 0.8, timestamp: new Date(), change: -15.3, changeType: "decrease" }
    ]);
    
    this.metrics.set("cpuUsage", [
      { value: 42, timestamp: new Date(), change: 5.1, changeType: "increase" }
    ]);

    // Initialiser les endpoints
    const endpoints: EndpointData[] = [
      { path: "/api/v1/users", method: "GET", requests: 15420, avgLatency: 42, status: "healthy", lastCalled: new Date() },
      { path: "/api/v1/auth/login", method: "POST", requests: 12380, avgLatency: 38, status: "healthy", lastCalled: new Date() },
      { path: "/api/v1/projects", method: "GET", requests: 8760, avgLatency: 45, status: "healthy", lastCalled: new Date() },
      { path: "/api/v1/data", method: "POST", requests: 6570, avgLatency: 52, status: "warning", lastCalled: new Date() },
      { path: "/api/v1/monitoring", method: "GET", requests: 870, avgLatency: 35, status: "healthy", lastCalled: new Date() },
    ];

    endpoints.forEach(endpoint => {
      this.endpoints.set(`${endpoint.method}-${endpoint.path}`, endpoint);
    });

    // Initialiser les logs
    this.logs = [
      { id: "1", level: "error", message: "Database connection timeout", timestamp: new Date(Date.now() - 2 * 60 * 1000), source: "api-service" },
      { id: "2", level: "warning", message: "High memory usage detected", timestamp: new Date(Date.now() - 5 * 60 * 1000), source: "monitoring" },
      { id: "3", level: "info", message: "New user registration", timestamp: new Date(Date.now() - 12 * 60 * 1000), source: "auth-service" },
      { id: "4", level: "error", message: "Failed to process webhook", timestamp: new Date(Date.now() - 18 * 60 * 1000), source: "webhook-service" },
      { id: "5", level: "warning", message: "Rate limit exceeded for IP 192.168.1.100", timestamp: new Date(Date.now() - 25 * 60 * 1000), source: "api-gateway" },
    ];

    // Initialiser les alertes de sécurité
    this.securityAlerts = [
      { id: "1", type: "failed_login", message: "Multiple failed login attempts", severity: "high", timestamp: new Date(Date.now() - 1 * 60 * 1000), user: "admin@skygenesisenterprise.com", ip: "192.168.1.100" },
      { id: "2", type: "suspicious_activity", message: "Unusual API usage pattern detected", severity: "medium", timestamp: new Date(Date.now() - 8 * 60 * 1000), user: "user123", ip: "10.0.0.50" },
      { id: "3", type: "api_key_abuse", message: "API key rate limit exceeded", severity: "low", timestamp: new Date(Date.now() - 15 * 60 * 1000), ip: "172.16.0.10" },
      { id: "4", type: "permission_change", message: "Admin privileges modified", severity: "critical", timestamp: new Date(Date.now() - 32 * 60 * 1000), user: "superadmin" },
    ];
  }

  private startRealTimeUpdates() {
    this.intervalId = setInterval(() => {
      this.updateMetrics();
      this.updateEndpoints();
      this.generateNewLog();
      this.notifyCallbacks();
    }, 2000 + Math.random() * 3000); // 2-5 secondes
  }

  private updateMetrics() {
    const now = new Date();
    
    // Mettre à jour les requests/min
    const requestsMetric = this.metrics.get("requests")?.[0];
    if (requestsMetric) {
      const variation = (Math.random() - 0.3) * 200; // Tendance à la hausse
      const newValue = Math.max(800, Math.min(2000, requestsMetric.value + variation));
      const change = ((newValue - requestsMetric.value) / requestsMetric.value) * 100;
      
      this.metrics.set("requests", [{
        value: newValue,
        timestamp: now,
        change: parseFloat(change.toFixed(1)),
        changeType: change >= 0 ? "increase" : "decrease"
      }]);
    }

    // Mettre à jour la latence
    const latencyMetric = this.metrics.get("latency")?.[0];
    if (latencyMetric) {
      const variation = (Math.random() - 0.5) * 10;
      const newValue = Math.max(20, Math.min(100, latencyMetric.value + variation));
      const change = ((newValue - latencyMetric.value) / latencyMetric.value) * 100;
      
      this.metrics.set("latency", [{
        value: newValue,
        timestamp: now,
        change: parseFloat(change.toFixed(1)),
        changeType: change >= 0 ? "increase" : "decrease"
      }]);
    }

    // Mettre à jour le taux d'erreur
    const errorRateMetric = this.metrics.get("errorRate")?.[0];
    if (errorRateMetric) {
      const variation = (Math.random() - 0.6) * 0.5; // Tendance à la baisse
      const newValue = Math.max(0, Math.min(5, errorRateMetric.value + variation));
      const change = ((newValue - errorRateMetric.value) / errorRateMetric.value) * 100;
      
      this.metrics.set("errorRate", [{
        value: newValue,
        timestamp: now,
        change: parseFloat(change.toFixed(1)),
        changeType: change >= 0 ? "increase" : "decrease"
      }]);
    }

    // Mettre à jour l'usage CPU
    const cpuMetric = this.metrics.get("cpuUsage")?.[0];
    if (cpuMetric) {
      const variation = (Math.random() - 0.5) * 15;
      const newValue = Math.max(0, Math.min(100, cpuMetric.value + variation));
      const change = ((newValue - cpuMetric.value) / cpuMetric.value) * 100;
      
      this.metrics.set("cpuUsage", [{
        value: newValue,
        timestamp: now,
        change: parseFloat(change.toFixed(1)),
        changeType: change >= 0 ? "increase" : "decrease"
      }]);
    }
  }

  private updateEndpoints() {
    this.endpoints.forEach((endpoint, key) => {
      // Variation aléatoire des requêtes
      const requestVariation = Math.floor((Math.random() - 0.5) * 100);
      endpoint.requests = Math.max(100, endpoint.requests + requestVariation);
      
      // Variation de latence
      const latencyVariation = (Math.random() - 0.5) * 10;
      endpoint.avgLatency = Math.max(10, Math.min(200, endpoint.avgLatency + latencyVariation));
      
      // Mise à jour du statut
      const random = Math.random();
      if (random < 0.7) {
        endpoint.status = "healthy";
      } else if (random < 0.9) {
        endpoint.status = "warning";
      } else {
        endpoint.status = "critical";
      }
      
      // Mise à jour du dernier appel
      if (Math.random() < 0.3) {
        endpoint.lastCalled = new Date();
      }
    });
  }

  private generateNewLog() {
    if (Math.random() < 0.2) { // 20% de chance de générer un nouveau log
      const levels: Array<"info" | "warning" | "error"> = ["info", "warning", "error"];
      const sources = ["api-service", "auth-service", "database", "cache", "monitoring", "webhook-service"];
      
      const messages = {
        info: [
          "User session started",
          "Cache cleared successfully", 
          "API request processed",
          "Backup completed",
          "Service health check passed"
        ],
        warning: [
          "High memory usage detected",
          "Slow database query",
          "Rate limit approaching",
          "Disk space low",
          "Connection pool exhausted"
        ],
        error: [
          "Database connection failed",
          "API timeout occurred",
          "Authentication failed",
          "Service unavailable",
          "Memory allocation error"
        ]
      };

      const level = levels[Math.floor(Math.random() * levels.length)];
      const source = sources[Math.floor(Math.random() * sources.length)];
      const messageList = messages[level];
      const message = messageList[Math.floor(Math.random() * messageList.length)];

      const newLog: LogEntry = {
        id: Date.now().toString(),
        level,
        message,
        timestamp: new Date(),
        source
      };

      this.logs.unshift(newLog);
      if (this.logs.length > 50) {
        this.logs = this.logs.slice(0, 50);
      }
    }
  }

  public subscribe(callback: () => void) {
    this.callbacks.add(callback);
    return () => this.callbacks.delete(callback);
  }

  private notifyCallbacks() {
    this.callbacks.forEach(callback => callback());
  }

  public getMetrics() {
    return {
      requests: this.metrics.get("requests")?.[0],
      latency: this.metrics.get("latency")?.[0],
      errorRate: this.metrics.get("errorRate")?.[0],
      cpuUsage: this.metrics.get("cpuUsage")?.[0]
    };
  }

  public getEndpoints(): EndpointData[] {
    return Array.from(this.endpoints.values()).map(endpoint => ({
      ...endpoint,
      percentage: Math.round((endpoint.requests / Array.from(this.endpoints.values()).reduce((sum, e) => sum + e.requests, 0)) * 100),
      color: endpoint.status === 'healthy' ? '#10b981' : endpoint.status === 'warning' ? '#f59e0b' : '#ef4444'
    }));
  }

  public getLogs(): LogEntry[] {
    return this.logs;
  }

  public getSecurityAlerts(): SecurityAlert[] {
    return this.securityAlerts;
  }

  public destroy() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }
    this.callbacks.clear();
  }
}

// Singleton global
export const realTimeDataService = new RealTimeDataService();