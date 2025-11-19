"use client";

import { useState, useEffect, useRef, useCallback } from 'react';
import { 
  ChevronDown, 
  ChevronRight, 
  Copy, 
  Download, 
  Eye, 
  EyeOff, 
  Maximize2, 
  Pause, 
  Play, 
  RefreshCw,
  Search,
  X,
  Clock,
  User,
  Server,
  Tag
} from 'lucide-react';
import { LogEntry, LogLevel, LogViewerConfig } from '../types';

interface LogViewerProps {
  logs: LogEntry[];
  loading?: boolean;
  config: LogViewerConfig;
  onConfigChange: (config: LogViewerConfig) => void;
  onExport?: (format: 'json' | 'csv' | 'txt') => void;
  onRefresh?: () => void;
  onLoadMore?: () => void;
  hasMore?: boolean;
}

const LOG_LEVEL_COLORS: Record<LogLevel, { bg: string; text: string; border: string }> = {
  trace: { bg: 'bg-gray-100', text: 'text-gray-700', border: 'border-gray-300' },
  debug: { bg: 'bg-blue-100', text: 'text-blue-700', border: 'border-blue-300' },
  info: { bg: 'bg-green-100', text: 'text-green-700', border: 'border-green-300' },
  warn: { bg: 'bg-yellow-100', text: 'text-yellow-700', border: 'border-yellow-300' },
  error: { bg: 'bg-red-100', text: 'text-red-700', border: 'border-red-300' },
  fatal: { bg: 'bg-purple-100', text: 'text-purple-700', border: 'border-purple-300' },
};

const LOG_LEVEL_ICONS: Record<LogLevel, string> = {
  trace: '⋯',
  debug: '🐛',
  info: 'ℹ️',
  warn: '⚠️',
  error: '❌',
  fatal: '💀',
};

export function LogViewer({ 
  logs, 
  loading = false, 
  config, 
  onConfigChange, 
  onExport,
  onRefresh,
  onLoadMore,
  hasMore = false
}: LogViewerProps) {
  const [expandedLogs, setExpandedLogs] = useState<Set<string>>(new Set());
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [showMetadata, setShowMetadata] = useState(true);
  const observerRef = useRef<IntersectionObserver | null>(null);
  const loadMoreRef = useRef<HTMLDivElement>(null);

  const formatTimestamp = useCallback((timestamp: string) => {
    const date = new Date(timestamp);
    switch (config.timestamps) {
      case 'utc':
        return date.toUTCString();
      case 'local':
        return date.toLocaleString();
      case 'relative':
        const now = new Date();
        const diff = now.getTime() - date.getTime();
        const seconds = Math.floor(diff / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        
        if (days > 0) return `${days}d ago`;
        if (hours > 0) return `${hours}h ago`;
        if (minutes > 0) return `${minutes}m ago`;
        return `${seconds}s ago`;
      default:
        return date.toISOString();
    }
  }, [config.timestamps]);

  const toggleLogExpansion = useCallback((logId: string) => {
    setExpandedLogs(prev => {
      const newSet = new Set(prev);
      if (newSet.has(logId)) {
        newSet.delete(logId);
      } else {
        newSet.add(logId);
      }
      return newSet;
    });
  }, []);

  const copyToClipboard = useCallback((text: string) => {
    navigator.clipboard.writeText(text);
  }, []);

  const highlightSearchTerm = useCallback((text: string) => {
    if (!searchTerm) return text;
    
    const parts = text.split(new RegExp(`(${searchTerm})`, 'gi'));
    
    return parts.map((part, index) => 
      part.toLowerCase() === searchTerm.toLowerCase() ? (
        <mark key={index} className="bg-yellow-200 text-yellow-900 px-0.5 rounded">
          {part}
        </mark>
      ) : (
        part
      )
    );
  }, [searchTerm]);

  const renderJsonMetadata = useCallback((metadata: Record<string, any>) => {
    if (!config.jsonPrettyPrint) {
      return <pre className="text-xs text-gray-600">{JSON.stringify(metadata, null, 2)}</pre>;
    }

    return (
      <div className="text-xs">
        {Object.entries(metadata).map(([key, value]) => (
          <div key={key} className="ml-4">
            <span className="text-blue-600">{key}:</span>{' '}
            <span className="text-gray-700">
              {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
            </span>
          </div>
        ))}
      </div>
    );
  }, [config.jsonPrettyPrint]);

  // Infinite scroll observer
  useEffect(() => {
    if (loadMoreRef.current && onLoadMore) {
      observerRef.current = new IntersectionObserver(
        (entries) => {
          if (entries[0].isIntersecting && hasMore && !loading) {
            onLoadMore();
          }
        },
        { threshold: 0.1 }
      );
      observerRef.current.observe(loadMoreRef.current);
    }

    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect();
      }
    };
  }, [onLoadMore, hasMore, loading]);

  return (
    <div className="bg-white border border-gray-200 rounded-lg">
      {/* Header Controls */}
      <div className="border-b border-gray-200 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Search className="h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search in logs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="px-3 py-1 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowMetadata(!showMetadata)}
                className={`p-2 rounded-lg ${showMetadata ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700'}`}
                title={showMetadata ? 'Hide metadata' : 'Show metadata'}
              >
                {showMetadata ? <Eye className="h-4 w-4" /> : <EyeOff className="h-4 w-4" />}
              </button>
              
              <button
                onClick={() => onConfigChange({ ...config, lineWrapping: !config.lineWrapping })}
                className={`p-2 rounded-lg ${config.lineWrapping ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700'}`}
                title={config.lineWrapping ? 'Disable line wrapping' : 'Enable line wrapping'}
              >
                <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={config.timestamps}
              onChange={(e) => onConfigChange({ ...config, timestamps: e.target.value as any })}
              className="px-3 py-1 border border-gray-300 rounded-lg text-sm"
            >
              <option value="utc">UTC</option>
              <option value="local">Local</option>
              <option value="relative">Relative</option>
            </select>

            <div className="flex items-center gap-1 border border-gray-300 rounded-lg">
              <button
                onClick={() => onConfigChange({ ...config, colorCoding: !config.colorCoding })}
                className={`p-2 rounded-l-lg ${config.colorCoding ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700'}`}
                title="Toggle color coding"
              >
                <div className="w-4 h-4 rounded bg-gradient-to-r from-green-400 to-red-400" />
              </button>
              <button
                onClick={onRefresh}
                className="p-2 border-l border-gray-300 hover:bg-gray-50"
                title="Refresh"
              >
                <RefreshCw className="h-4 w-4" />
              </button>
              <div className="relative group">
                <button className="p-2 border-l border-gray-300 hover:bg-gray-50" title="Export">
                  <Download className="h-4 w-4" />
                </button>
                <div className="absolute right-0 mt-1 w-32 bg-white border border-gray-200 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible z-10">
                  <button
                    onClick={() => onExport?.('json')}
                    className="block w-full text-left px-3 py-2 text-sm hover:bg-gray-50"
                  >
                    JSON
                  </button>
                  <button
                    onClick={() => onExport?.('csv')}
                    className="block w-full text-left px-3 py-2 text-sm hover:bg-gray-50"
                  >
                    CSV
                  </button>
                  <button
                    onClick={() => onExport?.('txt')}
                    className="block w-full text-left px-3 py-2 text-sm hover:bg-gray-50"
                  >
                    TXT
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Logs List */}
      <div className="divide-y divide-gray-100">
        {logs.map((log) => {
          const isExpanded = expandedLogs.has(log.id);
          const levelColors = LOG_LEVEL_COLORS[log.level];
          
          return (
            <div
              key={log.id}
              className={`group hover:bg-gray-50 transition-colors ${
                config.colorCoding ? levelColors.bg : ''
              }`}
            >
              <div className="p-4">
                <div className="flex items-start gap-3">
                  {/* Expand/Collapse Button */}
                  <button
                    onClick={() => toggleLogExpansion(log.id)}
                    className="mt-1 text-gray-400 hover:text-gray-600"
                  >
                    {isExpanded ? (
                      <ChevronDown className="h-4 w-4" />
                    ) : (
                      <ChevronRight className="h-4 w-4" />
                    )}
                  </button>

                  {/* Log Level */}
                  <div className={`px-2 py-1 text-xs font-medium rounded border ${
                    config.colorCoding 
                      ? `${levelColors.bg} ${levelColors.text} ${levelColors.border}`
                      : 'bg-gray-100 text-gray-700 border-gray-300'
                  }`}>
                    <span className="mr-1">{LOG_LEVEL_ICONS[log.level]}</span>
                    {log.level.toUpperCase()}
                  </div>

                  {/* Timestamp */}
                  <div className="flex items-center gap-1 text-sm text-gray-500 min-w-fit">
                    <Clock className="h-3 w-3" />
                    {formatTimestamp(log.timestamp)}
                  </div>

                  {/* Service */}
                  <div className="flex items-center gap-1 text-sm text-gray-600 min-w-fit">
                    <Server className="h-3 w-3" />
                    {log.service}
                  </div>

                  {/* Message */}
                  <div className={`flex-1 ${config.lineWrapping ? '' : 'overflow-x-auto'}`}>
                    <p className="text-sm text-gray-900 font-mono">
                      {highlightSearchTerm(log.message)}
                    </p>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      onClick={() => copyToClipboard(log.raw || log.message)}
                      className="p-1 text-gray-400 hover:text-gray-600"
                      title="Copy log"
                    >
                      <Copy className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => setSelectedLog(log)}
                      className="p-1 text-gray-400 hover:text-gray-600"
                      title="View details"
                    >
                      <Maximize2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                {/* Expanded Content */}
                {isExpanded && (
                  <div className="mt-3 ml-8 space-y-3">
                    {/* Additional Info */}
                    <div className="flex flex-wrap gap-4 text-sm">
                      {log.userId && (
                        <div className="flex items-center gap-1 text-gray-600">
                          <User className="h-3 w-3" />
                          <span>User: {log.userId}</span>
                        </div>
                      )}
                      {log.requestId && (
                        <div className="flex items-center gap-1 text-gray-600">
                          <Tag className="h-3 w-3" />
                          <span>Request: {log.requestId}</span>
                        </div>
                      )}
                      {log.ip && (
                        <div className="text-gray-600">
                          IP: {log.ip}
                        </div>
                      )}
                      {log.tags && log.tags.length > 0 && (
                        <div className="flex gap-1">
                          {log.tags.map((tag, index) => (
                            <span
                              key={index}
                              className="px-2 py-1 bg-blue-100 text-blue-700 text-xs rounded-full"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Metadata */}
                    {showMetadata && log.metadata && Object.keys(log.metadata).length > 0 && (
                      <div className="bg-gray-50 rounded-lg p-3">
                        <h4 className="text-sm font-medium text-gray-700 mb-2">Metadata</h4>
                        {renderJsonMetadata(log.metadata)}
                      </div>
                    )}

                    {/* Raw Log */}
                    {log.raw && (
                      <div className="bg-gray-900 text-gray-100 rounded-lg p-3">
                        <h4 className="text-sm font-medium mb-2">Raw Log</h4>
                        <pre className="text-xs font-mono whitespace-pre-wrap">
                          {log.raw}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {/* Loading Indicator */}
        {loading && (
          <div className="p-8 text-center">
            <RefreshCw className="h-6 w-6 animate-spin mx-auto text-gray-400" />
            <p className="text-sm text-gray-500 mt-2">Loading logs...</p>
          </div>
        )}

        {/* Load More Trigger */}
        {!loading && hasMore && (
          <div ref={loadMoreRef} className="p-4 text-center">
            <button
              onClick={onLoadMore}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Load More
            </button>
          </div>
        )}

        {/* Empty State */}
        {!loading && logs.length === 0 && (
          <div className="p-8 text-center">
            <div className="text-6xl mb-4">📋</div>
            <h3 className="text-lg font-medium text-gray-900 mb-2">No logs found</h3>
            <p className="text-sm text-gray-500">
              Try adjusting your filters or refresh to see the latest logs.
            </p>
          </div>
        )}
      </div>

      {/* Log Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[80vh] overflow-hidden">
            <div className="border-b border-gray-200 p-4 flex items-center justify-between">
              <h3 className="text-lg font-medium text-gray-900">Log Details</h3>
              <button
                onClick={() => setSelectedLog(null)}
                className="p-2 hover:bg-gray-100 rounded-lg"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="p-6 overflow-y-auto max-h-[60vh]">
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="font-medium text-gray-700">Timestamp:</span>
                    <p className="text-gray-900">{formatTimestamp(selectedLog.timestamp)}</p>
                  </div>
                  <div>
                    <span className="font-medium text-gray-700">Level:</span>
                    <span className={`ml-2 px-2 py-1 text-xs font-medium rounded border ${
                      LOG_LEVEL_COLORS[selectedLog.level].bg
                    } ${LOG_LEVEL_COLORS[selectedLog.level].text} ${
                      LOG_LEVEL_COLORS[selectedLog.level].border
                    }`}>
                      {selectedLog.level.toUpperCase()}
                    </span>
                  </div>
                  <div>
                    <span className="font-medium text-gray-700">Service:</span>
                    <p className="text-gray-900">{selectedLog.service}</p>
                  </div>
                  {selectedLog.userId && (
                    <div>
                      <span className="font-medium text-gray-700">User ID:</span>
                      <p className="text-gray-900">{selectedLog.userId}</p>
                    </div>
                  )}
                  {selectedLog.requestId && (
                    <div>
                      <span className="font-medium text-gray-700">Request ID:</span>
                      <p className="text-gray-900">{selectedLog.requestId}</p>
                    </div>
                  )}
                  {selectedLog.ip && (
                    <div>
                      <span className="font-medium text-gray-700">IP Address:</span>
                      <p className="text-gray-900">{selectedLog.ip}</p>
                    </div>
                  )}
                </div>

                <div>
                  <span className="font-medium text-gray-700">Message:</span>
                  <p className="mt-1 text-gray-900 font-mono text-sm bg-gray-50 p-3 rounded-lg">
                    {selectedLog.message}
                  </p>
                </div>

                {selectedLog.metadata && Object.keys(selectedLog.metadata).length > 0 && (
                  <div>
                    <span className="font-medium text-gray-700">Metadata:</span>
                    <div className="mt-1 bg-gray-50 p-3 rounded-lg">
                      {renderJsonMetadata(selectedLog.metadata)}
                    </div>
                  </div>
                )}

                {selectedLog.raw && (
                  <div>
                    <span className="font-medium text-gray-700">Raw Log:</span>
                    <pre className="mt-1 bg-gray-900 text-gray-100 p-3 rounded-lg text-xs font-mono overflow-x-auto">
                      {selectedLog.raw}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}