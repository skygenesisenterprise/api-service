"use client";

import React from 'react';
import { BarChart3, TrendingUp, AlertTriangle, Activity } from 'lucide-react';
import { LogStats, LogLevel } from '../types';

interface LogStatsProps {
  stats: LogStats;
  loading?: boolean;
}

const LOG_LEVEL_COLORS: Record<LogLevel, string> = {
  trace: 'bg-gray-400',
  debug: 'bg-blue-400',
  info: 'bg-green-400',
  warn: 'bg-yellow-400',
  error: 'bg-red-400',
  fatal: 'bg-purple-400',
};

const LOG_LEVEL_ORDER: LogLevel[] = ['fatal', 'error', 'warn', 'info', 'debug', 'trace'];

export function LogStatsComponent({ stats, loading = false }: LogStatsProps) {
  if (loading) {
    return (
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
    );
  }

  const totalByLevel = LOG_LEVEL_ORDER.reduce((acc, level) => acc + (stats.byLevel[level] || 0), 0);
  const errorRate = ((stats.byLevel.error || 0) + (stats.byLevel.fatal || 0)) / stats.total * 100;

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Logs</p>
              <p className="text-2xl font-bold text-gray-900">{stats.total.toLocaleString()}</p>
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
              <p className="text-2xl font-bold text-red-600">{errorRate.toFixed(1)}%</p>
            </div>
            <div className="p-3 bg-red-100 rounded-lg">
              <AlertTriangle className="h-6 w-6 text-red-600" />
            </div>
          </div>
        </div>

        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Services</p>
              <p className="text-2xl font-bold text-gray-900">{Object.keys(stats.byService).length}</p>
            </div>
            <div className="p-3 bg-green-100 rounded-lg">
              <Activity className="h-6 w-6 text-green-600" />
            </div>
          </div>
        </div>

        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Time Range</p>
              <p className="text-sm text-gray-900">
                {new Date(stats.timeRange.start).toLocaleDateString()} - {new Date(stats.timeRange.end).toLocaleDateString()}
              </p>
            </div>
            <div className="p-3 bg-purple-100 rounded-lg">
              <TrendingUp className="h-6 w-6 text-purple-600" />
            </div>
          </div>
        </div>
      </div>

      {/* Log Levels Distribution */}
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <h3 className="text-lg font-medium text-gray-900 mb-4">Log Levels Distribution</h3>
        
        <div className="space-y-3">
          {LOG_LEVEL_ORDER.map((level) => {
            const count = stats.byLevel[level] || 0;
            const percentage = stats.total > 0 ? (count / stats.total) * 100 : 0;
            
            return (
              <div key={level} className="flex items-center gap-4">
                <div className="w-16 text-sm font-medium text-gray-700 uppercase">
                  {level}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <div className="flex-1 bg-gray-200 rounded-full h-6 relative overflow-hidden">
                      <div
                        className={`h-full ${LOG_LEVEL_COLORS[level]} transition-all duration-300`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                    <div className="text-sm text-gray-600 min-w-fit">
                      {count.toLocaleString()} ({percentage.toFixed(1)}%)
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Services Breakdown */}
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <h3 className="text-lg font-medium text-gray-900 mb-4">Services Breakdown</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Object.entries(stats.byService)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 9)
            .map(([service, count]) => {
              const percentage = stats.total > 0 ? (count / stats.total) * 100 : 0;
              
              return (
                <div key={service} className="border border-gray-200 rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-900 truncate">{service}</span>
                    <span className="text-sm text-gray-600">{count.toLocaleString()}</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${Math.min(percentage, 100)}%` }}
                    />
                  </div>
                  <div className="text-xs text-gray-500 mt-1">{percentage.toFixed(1)}%</div>
                </div>
              );
            })}
        </div>

        {Object.keys(stats.byService).length > 9 && (
          <div className="mt-4 text-center">
            <button className="text-sm text-blue-600 hover:text-blue-700">
              View all {Object.keys(stats.byService).length} services →
            </button>
          </div>
        )}
      </div>
    </div>
  );
}