"use client";

import React, { useState, useMemo } from 'react';
import { 
  LineChart, 
  Line, 
  AreaChart, 
  Area, 
  BarChart, 
  Bar, 
  PieChart, 
  Pie, 
  Cell,
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer 
} from 'recharts';
import { 
  TrendingUp, 
  TrendingDown, 
  Activity, 
  AlertTriangle, 
  Clock,
  Zap,
  BarChart3,
  PieChart as PieChartIcon,
  Calendar,
  RefreshCw
} from 'lucide-react';
import { LogEntry, LogLevel, LogStats } from '../types';

interface LogDashboardProps {
  logs: LogEntry[];
  stats: LogStats;
  loading?: boolean;
  onRefresh?: () => void;
  timeRange?: '1h' | '6h' | '24h' | '7d' | '30d';
  onTimeRangeChange?: (range: '1h' | '6h' | '24h' | '7d' | '30d') => void;
}

const LOG_LEVEL_COLORS: Record<LogLevel, string> = {
  trace: '#9CA3AF',
  debug: '#3B82F6',
  info: '#10B981',
  warn: '#F59E0B',
  error: '#EF4444',
  fatal: '#991B1B',
};

const CHART_COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#991B1B', '#9CA3AF'];

export function LogDashboard({ 
  logs, 
  stats, 
  loading = false, 
  onRefresh,
  timeRange = '24h',
  onTimeRangeChange
}: LogDashboardProps) {
  const [selectedChart, setSelectedChart] = useState<'timeline' | 'levels' | 'services' | 'heatmap'>('timeline');

  // Generate timeline data
  const timelineData = useMemo(() => {
    const now = new Date();
    const intervals = timeRange === '1h' ? 12 : timeRange === '6h' ? 24 : timeRange === '24h' ? 24 : timeRange === '7d' ? 7 : 30;
    const intervalMs = timeRange === '1h' ? 5 * 60 * 1000 : 
                      timeRange === '6h' ? 15 * 60 * 1000 : 
                      timeRange === '24h' ? 60 * 60 * 1000 : 
                      timeRange === '7d' ? 24 * 60 * 60 * 1000 : 
                      24 * 60 * 60 * 1000;

    const data = [];
    
    for (let i = intervals - 1; i >= 0; i--) {
      const time = new Date(now.getTime() - i * intervalMs);
      const timeEnd = new Date(time.getTime() + intervalMs);
      
      const intervalLogs = logs.filter(log => {
        const logTime = new Date(log.timestamp);
        return logTime >= time && logTime < timeEnd;
      });

      const levelCounts = intervalLogs.reduce((acc, log) => {
        acc[log.level] = (acc[log.level] || 0) + 1;
        return acc;
      }, {} as Record<LogLevel, number>);

      data.push({
        time: timeRange === '7d' || timeRange === '30d' ? 
          time.toLocaleDateString() : 
          time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        timestamp: time.toISOString(),
        total: intervalLogs.length,
        ...levelCounts
      });
    }

    return data;
  }, [logs, timeRange]);

  // Generate service distribution data
  const serviceData = useMemo(() => {
    return Object.entries(stats.byService)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([service, count]) => ({
        name: service,
        value: count,
        percentage: (count / stats.total) * 100
      }));
  }, [stats]);

  // Generate level distribution data
  const levelData = useMemo(() => {
    return Object.entries(stats.byLevel)
      .map(([level, count]) => ({
        name: level.toUpperCase(),
        value: count,
        percentage: (count / stats.total) * 100,
        color: LOG_LEVEL_COLORS[level as LogLevel]
      }))
      .filter(item => item.value > 0);
  }, [stats]);

  // Calculate trends
  const trends = useMemo(() => {
    const recentLogs = logs.slice(0, 100);
    const olderLogs = logs.slice(100, 200);
    
    const recentErrors = recentLogs.filter(log => log.level === 'error' || log.level === 'fatal').length;
    const olderErrors = olderLogs.filter(log => log.level === 'error' || log.level === 'fatal').length;
    
    const errorTrend = recentErrors - olderErrors;
    const avgResponseTime = recentLogs.reduce((acc, log) => 
      acc + (log.metadata?.responseTime || 0), 0) / recentLogs.length;
    
    return {
      errorTrend: errorTrend > 0 ? 'up' : errorTrend < 0 ? 'down' : 'stable',
      errorTrendValue: Math.abs(errorTrend),
      avgResponseTime: Math.round(avgResponseTime),
      totalRequests: logs.length,
      uniqueServices: Object.keys(stats.byService).length
    };
  }, [logs, stats]);

  const timeRangeOptions = [
    { value: '1h', label: 'Last Hour' },
    { value: '6h', label: 'Last 6 Hours' },
    { value: '24h', label: 'Last 24 Hours' },
    { value: '7d', label: 'Last 7 Days' },
    { value: '30d', label: 'Last 30 Days' },
  ];

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="animate-pulse">
                <div className="h-4 bg-gray-200 rounded w-1/2 mb-2"></div>
                <div className="h-8 bg-gray-200 rounded w-3/4"></div>
              </div>
            </div>
          ))}
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <div className="animate-pulse">
            <div className="h-64 bg-gray-200 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Log Analytics Dashboard</h2>
          <p className="text-gray-600">Real-time monitoring and analysis of system logs</p>
        </div>
        <div className="flex items-center gap-4">
          {/* Time Range Selector */}
          <div className="flex items-center gap-2">
            <Calendar className="h-4 w-4 text-gray-500" />
            <select
              value={timeRange}
              onChange={(e) => onTimeRangeChange?.(e.target.value as any)}
              className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500"
            >
              {timeRangeOptions.map(option => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          
          <button
            onClick={onRefresh}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Logs</p>
              <p className="text-2xl font-bold text-gray-900">{stats.total.toLocaleString()}</p>
              <div className="flex items-center gap-1 mt-1">
                {trends.errorTrend === 'up' ? (
                  <TrendingUp className="h-3 w-3 text-red-500" />
                ) : trends.errorTrend === 'down' ? (
                  <TrendingDown className="h-3 w-3 text-green-500" />
                ) : (
                  <Activity className="h-3 w-3 text-gray-500" />
                )}
                <span className={`text-xs ${
                  trends.errorTrend === 'up' ? 'text-red-500' : 
                  trends.errorTrend === 'down' ? 'text-green-500' : 'text-gray-500'
                }`}>
                  {trends.errorTrend === 'stable' ? 'Stable' : 
                   trends.errorTrend === 'up' ? 'Increasing' : 'Decreasing'}
                </span>
              </div>
            </div>
            <div className="p-3 bg-blue-100 rounded-lg">
              <BarChart3 className="h-6 w-6 text-blue-600" />
            </div>
          </div>
        </div>

        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Error Rate</p>
              <p className="text-2xl font-bold text-red-600">
                {((stats.byLevel.error || 0) + (stats.byLevel.fatal || 0)) / stats.total * 100}%
              </p>
              <div className="flex items-center gap-1 mt-1">
                <AlertTriangle className="h-3 w-3 text-red-500" />
                <span className="text-xs text-red-500">
                  {stats.byLevel.error || 0} errors, {stats.byLevel.fatal || 0} fatal
                </span>
              </div>
            </div>
            <div className="p-3 bg-red-100 rounded-lg">
              <AlertTriangle className="h-6 w-6 text-red-600" />
            </div>
          </div>
        </div>

        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Avg Response Time</p>
              <p className="text-2xl font-bold text-gray-900">{trends.avgResponseTime}ms</p>
              <div className="flex items-center gap-1 mt-1">
                <Clock className="h-3 w-3 text-gray-500" />
                <span className="text-xs text-gray-500">Last 100 requests</span>
              </div>
            </div>
            <div className="p-3 bg-green-100 rounded-lg">
              <Clock className="h-6 w-6 text-green-600" />
            </div>
          </div>
        </div>

        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Services</p>
              <p className="text-2xl font-bold text-gray-900">{trends.uniqueServices}</p>
              <div className="flex items-center gap-1 mt-1">
                <Zap className="h-3 w-3 text-gray-500" />
                <span className="text-xs text-gray-500">Total requests: {trends.totalRequests}</span>
              </div>
            </div>
            <div className="p-3 bg-purple-100 rounded-lg">
              <Zap className="h-6 w-6 text-purple-600" />
            </div>
          </div>
        </div>
      </div>

      {/* Chart Tabs */}
      <div className="bg-white border border-gray-200 rounded-lg">
        <div className="border-b border-gray-200">
          <div className="flex space-x-8 px-6">
            {[
              { id: 'timeline', label: 'Timeline', icon: Activity },
              { id: 'levels', label: 'Log Levels', icon: PieChartIcon },
              { id: 'services', label: 'Services', icon: BarChart3 },
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setSelectedChart(id as any)}
                className={`flex items-center gap-2 py-4 border-b-2 transition-colors ${
                  selectedChart === id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                <Icon className="h-4 w-4" />
                {label}
              </button>
            ))}
          </div>
        </div>

        <div className="p-6">
          {/* Timeline Chart */}
          {selectedChart === 'timeline' && (
            <div>
              <h3 className="text-lg font-medium text-gray-900 mb-4">Log Volume Over Time</h3>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={timelineData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Area
                    type="monotone"
                    dataKey="total"
                    stackId="1"
                    stroke="#3B82F6"
                    fill="#3B82F6"
                    fillOpacity={0.6}
                  />
                  <Area
                    type="monotone"
                    dataKey="error"
                    stackId="2"
                    stroke="#EF4444"
                    fill="#EF4444"
                    fillOpacity={0.8}
                  />
                  <Area
                    type="monotone"
                    dataKey="warn"
                    stackId="2"
                    stroke="#F59E0B"
                    fill="#F59E0B"
                    fillOpacity={0.8}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Log Levels Chart */}
          {selectedChart === 'levels' && (
            <div>
              <h3 className="text-lg font-medium text-gray-900 mb-4">Log Levels Distribution</h3>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={levelData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percentage }: any) => `${name} ${percentage.toFixed(1)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {levelData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
                
                <div className="space-y-3">
                  {levelData.map((item) => (
                    <div key={item.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div
                          className="w-4 h-4 rounded"
                          style={{ backgroundColor: item.color }}
                        />
                        <span className="text-sm font-medium text-gray-900">{item.name}</span>
                      </div>
                      <div className="text-right">
                        <div className="text-sm font-medium text-gray-900">{item.value.toLocaleString()}</div>
                        <div className="text-xs text-gray-500">{item.percentage.toFixed(1)}%</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Services Chart */}
          {selectedChart === 'services' && (
            <div>
              <h3 className="text-lg font-medium text-gray-900 mb-4">Top Services by Log Volume</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={serviceData} layout="horizontal">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" width={120} />
                  <Tooltip />
                  <Bar dataKey="value" fill="#3B82F6" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}