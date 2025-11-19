"use client";

import { useState, useEffect, useCallback, useMemo } from 'react';
import { LogEntry, LogFilter, LogStats, LogViewerConfig, SavedFilter } from '../types';
import { generateMockLogs, generateMockStats, mockSavedFilters, logStreamService } from '../data/mockData';

const DEFAULT_CONFIG: LogViewerConfig = {
  autoRefresh: false,
  refreshInterval: 30000,
  maxEntries: 1000,
  colorCoding: true,
  timestamps: 'relative',
  lineWrapping: true,
  jsonPrettyPrint: true,
};

export function useLogs(initialFilter: LogFilter = {}) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [filter, setFilter] = useState<LogFilter>(initialFilter);
  const [config, setConfig] = useState<LogViewerConfig>(DEFAULT_CONFIG);
  const [stats, setStats] = useState<LogStats | null>(null);
  const [savedFilters, setSavedFilters] = useState<SavedFilter[]>(mockSavedFilters);
  const [isStreaming, setIsStreaming] = useState(false);

  // Filter logs based on current filter
  const filteredLogs = useMemo(() => {
    let filtered = [...logs];

    // Apply text search
    if (filter.search) {
      const searchLower = filter.search.toLowerCase();
      filtered = filtered.filter(log => 
        log.message.toLowerCase().includes(searchLower) ||
        log.service.toLowerCase().includes(searchLower) ||
        (log.userId && log.userId.toLowerCase().includes(searchLower)) ||
        (log.requestId && log.requestId.toLowerCase().includes(searchLower))
      );
    }

    // Apply regex search
    if (filter.regex) {
      try {
        const regex = new RegExp(filter.regex, 'i');
        filtered = filtered.filter(log => 
          regex.test(log.message) || 
          regex.test(log.service) ||
          regex.test(log.raw || '')
        );
      } catch (e) {
        // Invalid regex, ignore
      }
    }

    // Apply level filter
    if (filter.levels && filter.levels.length > 0) {
      filtered = filtered.filter(log => filter.levels!.includes(log.level));
    }

    // Apply service filter
    if (filter.services && filter.services.length > 0) {
      filtered = filtered.filter(log => filter.services!.includes(log.service));
    }

    // Apply environment filter
    if (filter.environments && filter.environments.length > 0) {
      filtered = filtered.filter(log => 
        log.environment && filter.environments!.includes(log.environment)
      );
    }

    // Apply date range filter
    if (filter.dateRange) {
      const start = new Date(filter.dateRange.start);
      const end = new Date(filter.dateRange.end);
      filtered = filtered.filter(log => {
        const logDate = new Date(log.timestamp);
        return logDate >= start && logDate <= end;
      });
    }

    // Apply user ID filter
    if (filter.userId) {
      filtered = filtered.filter(log => 
        log.userId && log.userId.toLowerCase().includes(filter.userId!.toLowerCase())
      );
    }

    // Apply request ID filter
    if (filter.requestId) {
      filtered = filtered.filter(log => 
        log.requestId && log.requestId.toLowerCase().includes(filter.requestId!.toLowerCase())
      );
    }

    // Apply IP filter
    if (filter.ip) {
      filtered = filtered.filter(log => 
        log.ip && log.ip.includes(filter.ip!)
      );
    }

    // Apply tags filter
    if (filter.tags && filter.tags.length > 0) {
      filtered = filtered.filter(log => 
        log.tags && filter.tags!.some(tag => log.tags!.includes(tag))
      );
    }

    return filtered;
  }, [logs, filter]);

  // Load initial logs
  const loadLogs = useCallback(async (reset = false) => {
    setLoading(true);
    
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 500));
    
    const newLogs = generateMockLogs(reset ? 50 : 25);
    
    if (reset) {
      setLogs(newLogs);
    } else {
      setLogs(prev => [...prev, ...newLogs]);
    }
    
    setHasMore(newLogs.length >= 25);
    setLoading(false);
  }, []);

  // Load more logs
  const loadMore = useCallback(() => {
    if (!loading && hasMore) {
      loadLogs(false);
    }
  }, [loading, hasMore, loadLogs]);

  // Refresh logs
  const refresh = useCallback(() => {
    loadLogs(true);
    loadStats();
  }, [loadLogs]);

  // Load stats
  const loadStats = useCallback(async () => {
    setLoading(true);
    await new Promise(resolve => setTimeout(resolve, 300));
    setStats(generateMockStats());
    setLoading(false);
  }, []);

  // Export logs
  const exportLogs = useCallback((format: 'json' | 'csv' | 'txt') => {
    const dataToExport = filteredLogs;
    
    switch (format) {
      case 'json':
        const json = JSON.stringify(dataToExport, null, 2);
        downloadFile(json, `logs-${new Date().toISOString()}.json`, 'application/json');
        break;
      
      case 'csv':
        const csv = convertToCSV(dataToExport);
        downloadFile(csv, `logs-${new Date().toISOString()}.csv`, 'text/csv');
        break;
      
      case 'txt':
        const txt = dataToExport.map(log => 
          `[${log.timestamp}] ${log.level.toUpperCase()} ${log.service}: ${log.message}`
        ).join('\n');
        downloadFile(txt, `logs-${new Date().toISOString()}.txt`, 'text/plain');
        break;
    }
  }, [filteredLogs]);

  // Save filter
  const saveFilter = useCallback((name: string, description: string) => {
    const newFilter: SavedFilter = {
      id: `filter_${Date.now()}`,
      name,
      description,
      filter: { ...filter },
      isPublic: false,
      createdBy: 'current_user',
      createdAt: new Date().toISOString(),
      usageCount: 0
    };
    
    setSavedFilters(prev => [...prev, newFilter]);
  }, [filter]);

  // Load saved filter
  const loadSavedFilter = useCallback((savedFilter: SavedFilter) => {
    setFilter(savedFilter.filter);
    savedFilter.usageCount++;
  }, []);

  // Toggle streaming
  const toggleStreaming = useCallback(() => {
    if (isStreaming) {
      logStreamService.stop();
      setIsStreaming(false);
    } else {
      logStreamService.start();
      setIsStreaming(true);
    }
  }, [isStreaming]);

  // Handle streaming logs
  useEffect(() => {
    if (isStreaming) {
      const unsubscribe = logStreamService.subscribe((newLog) => {
        setLogs(prev => [newLog, ...prev].slice(0, config.maxEntries));
      });
      
      return unsubscribe;
    }
  }, [isStreaming, config.maxEntries]);

  // Auto-refresh
  useEffect(() => {
    if (config.autoRefresh && !isStreaming) {
      const interval = setInterval(() => {
        refresh();
      }, config.refreshInterval);
      
      return () => clearInterval(interval);
    }
  }, [config.autoRefresh, config.refreshInterval, refresh, isStreaming]);

  // Initial load
  useEffect(() => {
    loadLogs(true);
    loadStats();
  }, []);

  return {
    logs: filteredLogs,
    loading,
    hasMore,
    filter,
    setFilter,
    config,
    setConfig,
    stats,
    savedFilters,
    isStreaming,
    loadMore,
    refresh,
    exportLogs,
    saveFilter,
    loadSavedFilter,
    toggleStreaming,
  };
}

// Helper functions
function convertToCSV(logs: LogEntry[]): string {
  const headers = ['timestamp', 'level', 'service', 'message', 'userId', 'requestId', 'ip', 'environment'];
  const csvRows = [
    headers.join(','),
    ...logs.map(log => [
      log.timestamp,
      log.level,
      log.service,
      `"${log.message.replace(/"/g, '""')}"`, // Escape quotes
      log.userId || '',
      log.requestId || '',
      log.ip || '',
      log.environment || ''
    ].join(','))
  ];
  
  return csvRows.join('\n');
}

function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}