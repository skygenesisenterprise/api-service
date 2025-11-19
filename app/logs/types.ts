export interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  service: string;
  message: string;
  metadata?: Record<string, any>;
  userId?: string;
  requestId?: string;
  ip?: string;
  userAgent?: string;
  projectId?: string;
  tenantId?: string;
  environment?: string;
  tags?: string[];
  raw?: string;
}

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';

export interface LogFilter {
  dateRange?: {
    start: string;
    end: string;
  };
  levels?: LogLevel[];
  services?: string[];
  projects?: string[];
  tenants?: string[];
  environments?: string[];
  search?: string;
  userId?: string;
  requestId?: string;
  ip?: string;
  tags?: string[];
  regex?: string;
}

export interface LogStats {
  total: number;
  byLevel: Record<LogLevel, number>;
  byService: Record<string, number>;
  timeRange: {
    start: string;
    end: string;
  };
}

export interface SavedFilter {
  id: string;
  name: string;
  description?: string;
  filter: LogFilter;
  isPublic: boolean;
  createdBy: string;
  createdAt: string;
  usageCount: number;
}

export interface LogExportOptions {
  format: 'json' | 'csv' | 'txt';
  includeMetadata: boolean;
  maxEntries?: number;
}

export interface LogViewerConfig {
  autoRefresh: boolean;
  refreshInterval: number;
  maxEntries: number;
  colorCoding: boolean;
  timestamps: 'utc' | 'local' | 'relative';
  lineWrapping: boolean;
  jsonPrettyPrint: boolean;
}