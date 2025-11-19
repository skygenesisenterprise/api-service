import { LogEntry, LogLevel, LogStats, SavedFilter } from '../types';

// Mock data generators
export const generateMockLogEntry = (index: number): LogEntry => {
  const services = [
    'api-gateway', 'auth-service', 'payment-service', 'notification-service',
    'user-service', 'order-service', 'inventory-service', 'analytics-service',
    'search-service', 'email-service', 'file-service', 'cache-service'
  ];
  
  const environments = ['dev', 'staging', 'prod'];
  const levels: LogLevel[] = ['trace', 'debug', 'info', 'warn', 'error', 'fatal'];
  
  const levelWeights = [0.05, 0.15, 0.60, 0.15, 0.04, 0.01]; // Weighted distribution
  const randomLevel = (): LogLevel => {
    const random = Math.random();
    let cumulative = 0;
    for (let i = 0; i < levels.length; i++) {
      cumulative += levelWeights[i];
      if (random <= cumulative) return levels[i];
    }
    return 'info';
  };

  const level = randomLevel();
  const service = services[Math.floor(Math.random() * services.length)];
  const environment = environments[Math.floor(Math.random() * environments.length)];
  
  const timestamp = new Date(Date.now() - index * 1000 - Math.random() * 60000).toISOString();
  
  const messagesByLevel = {
    trace: [
      'Function entry: processPayment',
      'Cache hit for user session',
      'Database query executed',
      'API request validated',
      'Middleware processing complete'
    ],
    debug: [
      'Processing user request with ID: req_123456',
      'Cache miss for key: user_profile_789',
      'Database connection established',
      'API response time: 45ms',
      'Memory usage: 256MB'
    ],
    info: [
      'User login successful for user@example.com',
      'Payment processed successfully: $99.99',
      'Order #12345 shipped to customer',
      'Database backup completed successfully',
      'API health check passed'
    ],
    warn: [
      'Rate limit approaching for user: user_123',
      'Database connection pool at 80% capacity',
      'Memory usage above 75% threshold',
      'API response time exceeded 500ms',
      'Disk space below 20% available'
    ],
    error: [
      'Failed to process payment: Card declined',
      'Database connection timeout after 30s',
      'API request failed: 500 Internal Server Error',
      'User authentication failed: Invalid credentials',
      'File upload failed: Size limit exceeded'
    ],
    fatal: [
      'Database server connection lost',
      'Application out of memory - shutting down',
      'Critical security breach detected',
      'System crash: Kernel panic',
      'Data corruption detected in primary database'
    ]
  };

  const message = messagesByLevel[level][Math.floor(Math.random() * messagesByLevel[level].length)];
  
  const metadata = {
    requestId: `req_${Math.random().toString(36).substring(2, 11)}`,
    userId: Math.random() > 0.3 ? `user_${Math.floor(Math.random() * 10000)}` : undefined,
    ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    responseTime: Math.floor(Math.random() * 1000),
    statusCode: level === 'error' || level === 'fatal' ? 500 : 200,
    environment,
    version: 'v2.1.3',
    pod: `${service}-pod-${Math.floor(Math.random() * 10)}`,
    namespace: environment === 'prod' ? 'production' : 'development'
  };

  const tags = [
    environment,
    service,
    level === 'error' || level === 'fatal' ? 'critical' : 'normal',
    Math.random() > 0.7 ? 'batch-job' : 'user-request'
  ].filter(Boolean);

  return {
    id: `log_${Date.now()}_${index}`,
    timestamp,
    level,
    service,
    message,
    metadata,
    userId: metadata.userId,
    requestId: metadata.requestId,
    ip: metadata.ip,
    userAgent: metadata.userAgent,
    projectId: `project_${Math.floor(Math.random() * 100)}`,
    tenantId: `tenant_${Math.floor(Math.random() * 10)}`,
    environment,
    tags,
    raw: `[${timestamp}] ${level.toUpperCase()} ${service}: ${message} | ${JSON.stringify(metadata)}`
  };
};

export const generateMockLogs = (count: number): LogEntry[] => {
  return Array.from({ length: count }, (_, i) => generateMockLogEntry(i));
};

export const generateMockStats = (): LogStats => {
  const logs = generateMockLogs(10000);
  const byLevel: Record<LogLevel, number> = {
    trace: 0,
    debug: 0,
    info: 0,
    warn: 0,
    error: 0,
    fatal: 0
  };
  
  const byService: Record<string, number> = {};
  
  logs.forEach(log => {
    byLevel[log.level]++;
    byService[log.service] = (byService[log.service] || 0) + 1;
  });

  return {
    total: logs.length,
    byLevel,
    byService,
    timeRange: {
      start: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      end: new Date().toISOString()
    }
  };
};

export const mockSavedFilters: SavedFilter[] = [
  {
    id: 'filter_1',
    name: 'Production Errors',
    description: 'All error and fatal logs from production environment',
    filter: {
      levels: ['error', 'fatal'],
      environments: ['prod'],
      dateRange: {
        start: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        end: new Date().toISOString()
      }
    },
    isPublic: true,
    createdBy: 'admin',
    createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
    usageCount: 156
  },
  {
    id: 'filter_2',
    name: 'Payment Service Issues',
    description: 'Issues related to payment processing',
    filter: {
      services: ['payment-service'],
      levels: ['warn', 'error', 'fatal'],
      search: 'payment OR transaction OR billing'
    },
    isPublic: false,
    createdBy: 'user_123',
    createdAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
    usageCount: 45
  },
  {
    id: 'filter_3',
    name: 'API Performance',
    description: 'Slow API responses and performance issues',
    filter: {
      search: 'response_time:>500 OR timeout OR slow',
      environments: ['prod', 'staging']
    },
    isPublic: true,
    createdBy: 'ops_team',
    createdAt: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString(),
    usageCount: 89
  }
];

// Real-time log stream simulation
export class LogStreamService {
  private listeners: ((log: LogEntry) => void)[] = [];
  private interval: NodeJS.Timeout | null = null;
  private isRunning = false;

  subscribe(listener: (log: LogEntry) => void) {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  start() {
    if (this.isRunning) return;
    
    this.isRunning = true;
    this.interval = setInterval(() => {
      const log = generateMockLogEntry(Math.floor(Math.random() * 1000));
      this.listeners.forEach(listener => listener(log));
    }, Math.random() * 2000 + 500); // Random interval between 500ms and 2500ms
  }

  stop() {
    this.isRunning = false;
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }

  isStreaming() {
    return this.isRunning;
  }
}

export const logStreamService = new LogStreamService();