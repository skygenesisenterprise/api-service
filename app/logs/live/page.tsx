"use client";

import { useState, useEffect, useRef } from 'react';
import { LogSidebar } from '../components/LogSidebar';
import { LogViewer } from '../components/LogViewer';
import { useLogs } from '../hooks/useLogs';
import { LogEntry, LogViewerConfig } from '../types';
import { logStreamService, generateMockLogEntry } from '../data/mockData';
import { 
  Play, 
  Pause, 
  RotateCcw, 
  Settings, 
  Download,
  Activity,
  Zap,
  Clock,
  BarChart3
} from 'lucide-react';

const STREAMING_CONFIG: LogViewerConfig = {
  autoRefresh: false,
  refreshInterval: 1000,
  maxEntries: 500,
  colorCoding: true,
  timestamps: 'relative',
  lineWrapping: true,
  jsonPrettyPrint: true,
};

export default function LiveLogsPage() {
  const [isStreaming, setIsStreaming] = useState(false);
  const [streamLogs, setStreamLogs] = useState<LogEntry[]>([]);
  const [bufferSize, setBufferSize] = useState(500);
  const [streamSpeed, setStreamSpeed] = useState<'slow' | 'normal' | 'fast'>('normal');
  const [showStats, setShowStats] = useState(true);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const statsRef = useRef({
    total: 0,
    errors: 0,
    warnings: 0,
    startTime: Date.now(),
    logsPerSecond: 0
  });

  const { config, setConfig } = useLogs();

  useEffect(() => {
    setConfig(STREAMING_CONFIG);
  }, []);

  useEffect(() => {
    if (isStreaming) {
      const speedMap = {
        slow: 2000,
        normal: 1000,
        fast: 500
      };

      intervalRef.current = setInterval(() => {
        const newLog = generateMockLogEntry(Date.now());
        setStreamLogs(prev => {
          const updated = [newLog, ...prev];
          return updated.slice(0, bufferSize);
        });

        // Update stats
        statsRef.current.total++;
        if (newLog.level === 'error' || newLog.level === 'fatal') {
          statsRef.current.errors++;
        }
        if (newLog.level === 'warn') {
          statsRef.current.warnings++;
        }

        // Calculate logs per second
        const elapsed = (Date.now() - statsRef.current.startTime) / 1000;
        statsRef.current.logsPerSecond = statsRef.current.total / elapsed;
      }, speedMap[streamSpeed]);
    } else {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [isStreaming, streamSpeed, bufferSize]);

  const toggleStreaming = () => {
    setIsStreaming(!isStreaming);
  };

  const clearLogs = () => {
    setStreamLogs([]);
    statsRef.current = {
      total: 0,
      errors: 0,
      warnings: 0,
      startTime: Date.now(),
      logsPerSecond: 0
    };
  };

  const exportLogs = (format: 'json' | 'csv' | 'txt') => {
    const dataToExport = streamLogs;
    
    switch (format) {
      case 'json':
        const json = JSON.stringify(dataToExport, null, 2);
        downloadFile(json, `live-logs-${new Date().toISOString()}.json`, 'application/json');
        break;
      
      case 'csv':
        const csv = convertToCSV(dataToExport);
        downloadFile(csv, `live-logs-${new Date().toISOString()}.csv`, 'text/csv');
        break;
      
      case 'txt':
        const txt = dataToExport.map(log => 
          `[${log.timestamp}] ${log.level.toUpperCase()} ${log.service}: ${log.message}`
        ).join('\n');
        downloadFile(txt, `live-logs-${new Date().toISOString()}.txt`, 'text/plain');
        break;
    }
  };

  const formatDuration = (ms: number) => {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  };

  const stats = statsRef.current;
  const elapsed = Date.now() - stats.startTime;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-full px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Zap className={`h-6 w-6 ${isStreaming ? 'text-green-500 animate-pulse' : 'text-gray-400'}`} />
                <div>
                  <h1 className="text-2xl font-bold text-gray-900">Live Log Stream</h1>
                  <p className="text-gray-600">Real-time log monitoring and analysis</p>
                </div>
              </div>
              
              {isStreaming && (
                <div className="flex items-center gap-2 px-3 py-1 bg-green-100 text-green-700 rounded-full">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                  <span className="text-sm font-medium">LIVE</span>
                </div>
              )}
            </div>
            
            <div className="flex items-center gap-4">
              {/* Stream Controls */}
              <button
                onClick={toggleStreaming}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
                  isStreaming
                    ? 'bg-red-100 text-red-700 hover:bg-red-200'
                    : 'bg-green-100 text-green-700 hover:bg-green-200'
                }`}
              >
                {isStreaming ? (
                  <>
                    <Pause className="h-4 w-4" />
                    Stop Stream
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" />
                    Start Stream
                  </>
                )}
              </button>

              <button
                onClick={clearLogs}
                className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
              >
                <RotateCcw className="h-4 w-4" />
                Clear
              </button>

              {/* Export */}
              <div className="relative group">
                <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
                  <Download className="h-4 w-4" />
                  Export
                </button>
                <div className="absolute right-0 mt-1 w-32 bg-white border border-gray-200 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible z-10">
                  <button
                    onClick={() => exportLogs('json')}
                    className="block w-full text-left px-3 py-2 text-sm hover:bg-gray-50"
                  >
                    JSON
                  </button>
                  <button
                    onClick={() => exportLogs('csv')}
                    className="block w-full text-left px-3 py-2 text-sm hover:bg-gray-50"
                  >
                    CSV
                  </button>
                  <button
                    onClick={() => exportLogs('txt')}
                    className="block w-full text-left px-3 py-2 text-sm hover:bg-gray-50"
                  >
                    TXT
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Stats Bar */}
          <div className="flex items-center justify-between mt-4">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-gray-500" />
                <span className="text-sm text-gray-600">
                  {stats.logsPerSecond.toFixed(1)} logs/sec
                </span>
              </div>
              <div className="text-sm text-gray-600">
                {stats.total.toLocaleString()} total logs
              </div>
              <div className="text-sm text-red-600">
                {stats.errors.toLocaleString()} errors
              </div>
              <div className="text-sm text-yellow-600">
                {stats.warnings.toLocaleString()} warnings
              </div>
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-gray-500" />
                <span className="text-sm text-gray-600">
                  {formatDuration(elapsed)}
                </span>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {/* Stream Speed */}
              <div className="flex items-center gap-2">
                <span className="text-sm text-gray-600">Speed:</span>
                <select
                  value={streamSpeed}
                  onChange={(e) => setStreamSpeed(e.target.value as any)}
                  className="px-2 py-1 border border-gray-300 rounded text-sm"
                >
                  <option value="slow">Slow</option>
                  <option value="normal">Normal</option>
                  <option value="fast">Fast</option>
                </select>
              </div>

              {/* Buffer Size */}
              <div className="flex items-center gap-2">
                <span className="text-sm text-gray-600">Buffer:</span>
                <select
                  value={bufferSize}
                  onChange={(e) => setBufferSize(Number(e.target.value))}
                  className="px-2 py-1 border border-gray-300 rounded text-sm"
                >
                  <option value="100">100</option>
                  <option value="250">250</option>
                  <option value="500">500</option>
                  <option value="1000">1000</option>
                </select>
              </div>

              <button
                onClick={() => setShowStats(!showStats)}
                className={`p-2 rounded-lg ${showStats ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700'}`}
              >
                <BarChart3 className="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="flex">
        {/* Sidebar */}
        <div className="w-80 bg-white border-r border-gray-200 min-h-screen">
          <LogSidebar />
        </div>

        {/* Main Content */}
        <div className="flex-1 p-6">
          {/* Live Stats Panel */}
          {showStats && (
            <div className="mb-6 grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-white border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Logs/Second</p>
                    <p className="text-2xl font-bold text-blue-600">
                      {stats.logsPerSecond.toFixed(1)}
                    </p>
                  </div>
                  <Activity className="h-8 w-8 text-blue-500" />
                </div>
              </div>

              <div className="bg-white border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Error Rate</p>
                    <p className="text-2xl font-bold text-red-600">
                      {stats.total > 0 ? ((stats.errors / stats.total) * 100).toFixed(1) : '0'}%
                    </p>
                  </div>
                  <div className="h-8 w-8 bg-red-100 rounded-lg flex items-center justify-center">
                    <span className="text-red-600 font-bold">!</span>
                  </div>
                </div>
              </div>

              <div className="bg-white border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Buffer Usage</p>
                    <p className="text-2xl font-bold text-gray-900">
                      {streamLogs.length}/{bufferSize}
                    </p>
                  </div>
                  <div className="h-8 w-8 bg-gray-100 rounded-lg flex items-center justify-center">
                    <BarChart3 className="h-4 w-4 text-gray-600" />
                  </div>
                </div>
              </div>

              <div className="bg-white border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Runtime</p>
                    <p className="text-2xl font-bold text-gray-900">
                      {formatDuration(elapsed)}
                    </p>
                  </div>
                  <Clock className="h-8 w-8 text-gray-500" />
                </div>
              </div>
            </div>
          )}

          {/* Log Viewer */}
          <LogViewer
            logs={streamLogs}
            loading={false}
            config={config}
            onConfigChange={setConfig}
            onExport={exportLogs}
            hasMore={false}
          />
        </div>
      </div>
    </div>
  );
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
      `"${log.message.replace(/"/g, '""')}"`,
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