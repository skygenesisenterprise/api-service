"use client";

import React, { useState } from 'react';
import { Search, Filter, Calendar, X, ChevronDown, Plus } from 'lucide-react';
import { LogFilter, LogLevel, SavedFilter } from '../types';

interface LogFiltersProps {
  filter: LogFilter;
  onFilterChange: (filter: LogFilter) => void;
  savedFilters?: SavedFilter[];
  onSaveFilter?: (name: string, description: string) => void;
  onLoadFilter?: (filter: LogFilter) => void;
}

const LOG_LEVELS: LogLevel[] = ['trace', 'debug', 'info', 'warn', 'error', 'fatal'];
const LOG_LEVEL_COLORS: Record<LogLevel, string> = {
  trace: 'bg-gray-100 text-gray-700 border-gray-300',
  debug: 'bg-blue-100 text-blue-700 border-blue-300',
  info: 'bg-green-100 text-green-700 border-green-300',
  warn: 'bg-yellow-100 text-yellow-700 border-yellow-300',
  error: 'bg-red-100 text-red-700 border-red-300',
  fatal: 'bg-purple-100 text-purple-700 border-purple-300',
};

const SERVICES = [
  'api-gateway', 'auth-service', 'payment-service', 'notification-service',
  'user-service', 'order-service', 'inventory-service', 'analytics-service'
];

const ENVIRONMENTS = ['dev', 'staging', 'prod'];

const TIME_PRESETS = [
  { label: 'Last 15 minutes', value: 15 },
  { label: 'Last hour', value: 60 },
  { label: 'Last 6 hours', value: 360 },
  { label: 'Last 24 hours', value: 1440 },
  { label: 'Last 7 days', value: 10080 },
];

export function LogFilters({ 
  filter, 
  onFilterChange, 
  savedFilters = [], 
  onSaveFilter,
  onLoadFilter 
}: LogFiltersProps) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showSaveFilter, setShowSaveFilter] = useState(false);
  const [newFilterName, setNewFilterName] = useState('');
  const [newFilterDescription, setNewFilterDescription] = useState('');

  const handleLevelToggle = (level: LogLevel) => {
    const levels = filter.levels || [];
    const newLevels = levels.includes(level)
      ? levels.filter(l => l !== level)
      : [...levels, level];
    onFilterChange({ ...filter, levels: newLevels });
  };

  const handleServiceToggle = (service: string) => {
    const services = filter.services || [];
    const newServices = services.includes(service)
      ? services.filter(s => s !== service)
      : [...services, service];
    onFilterChange({ ...filter, services: newServices });
  };

  const handleEnvironmentToggle = (env: string) => {
    const environments = filter.environments || [];
    const newEnvironments = environments.includes(env)
      ? environments.filter(e => e !== env)
      : [...environments, env];
    onFilterChange({ ...filter, environments: newEnvironments });
  };

  const handleTimePreset = (minutes: number) => {
    const end = new Date();
    const start = new Date(end.getTime() - minutes * 60 * 1000);
    onFilterChange({
      ...filter,
      dateRange: {
        start: start.toISOString(),
        end: end.toISOString(),
      },
    });
  };

  const handleSaveFilter = () => {
    if (newFilterName.trim() && onSaveFilter) {
      onSaveFilter(newFilterName.trim(), newFilterDescription.trim());
      setNewFilterName('');
      setNewFilterDescription('');
      setShowSaveFilter(false);
    }
  };

  const clearAllFilters = () => {
    onFilterChange({});
  };

  const hasActiveFilters = Object.keys(filter).length > 0;

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4 space-y-4">
      {/* Search Bar */}
      <div className="flex gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search logs... (use quotes for exact match, regex: /pattern/)"
            value={filter.search || ''}
            onChange={(e) => onFilterChange({ ...filter, search: e.target.value })}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
        >
          <Filter className="h-4 w-4" />
          Advanced Filters
          <ChevronDown className={`h-4 w-4 transform transition-transform ${showAdvanced ? 'rotate-180' : ''}`} />
        </button>
        {hasActiveFilters && (
          <button
            onClick={clearAllFilters}
            className="flex items-center gap-2 px-4 py-2 border border-red-300 text-red-700 rounded-lg hover:bg-red-50"
          >
            <X className="h-4 w-4" />
            Clear All
          </button>
        )}
      </div>

      {/* Quick Filters */}
      <div className="flex flex-wrap gap-4">
        {/* Log Levels */}
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-gray-700">Level:</span>
          <div className="flex gap-1">
            {LOG_LEVELS.map((level) => (
              <button
                key={level}
                onClick={() => handleLevelToggle(level)}
                className={`px-2 py-1 text-xs font-medium rounded border transition-colors ${
                  filter.levels?.includes(level)
                    ? LOG_LEVEL_COLORS[level]
                    : 'bg-gray-50 text-gray-600 border-gray-200 hover:bg-gray-100'
                }`}
              >
                {level.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {/* Time Presets */}
        <div className="flex items-center gap-2">
          <Calendar className="h-4 w-4 text-gray-500" />
          <div className="flex gap-1">
            {TIME_PRESETS.map((preset) => (
              <button
                key={preset.value}
                onClick={() => handleTimePreset(preset.value)}
                className="px-2 py-1 text-xs font-medium bg-gray-50 text-gray-600 border border-gray-200 rounded hover:bg-gray-100"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Advanced Filters */}
      {showAdvanced && (
        <div className="border-t border-gray-200 pt-4 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* Date Range */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Date Range</label>
              <div className="flex gap-2">
                <input
                  type="datetime-local"
                  value={filter.dateRange?.start?.slice(0, 16) || ''}
                  onChange={(e) => onFilterChange({
                    ...filter,
                    dateRange: { 
                      start: new Date(e.target.value).toISOString(),
                      end: filter.dateRange?.end || new Date().toISOString()
                    }
                  })}
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm"
                />
                <input
                  type="datetime-local"
                  value={filter.dateRange?.end?.slice(0, 16) || ''}
                  onChange={(e) => onFilterChange({
                    ...filter,
                    dateRange: { 
                      start: filter.dateRange?.start || new Date(Date.now() - 60 * 60 * 1000).toISOString(),
                      end: new Date(e.target.value).toISOString()
                    }
                  })}
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm"
                />
              </div>
            </div>

            {/* Services */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Services</label>
              <div className="max-h-32 overflow-y-auto border border-gray-200 rounded-lg p-2">
                {SERVICES.map((service) => (
                  <label key={service} className="flex items-center gap-2 p-1 hover:bg-gray-50">
                    <input
                      type="checkbox"
                      checked={filter.services?.includes(service) || false}
                      onChange={() => handleServiceToggle(service)}
                      className="rounded border-gray-300"
                    />
                    <span className="text-sm">{service}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Environments */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Environments</label>
              <div className="space-y-2">
                {ENVIRONMENTS.map((env) => (
                  <label key={env} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={filter.environments?.includes(env) || false}
                      onChange={() => handleEnvironmentToggle(env)}
                      className="rounded border-gray-300"
                    />
                    <span className="text-sm capitalize">{env}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* User ID */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">User ID</label>
              <input
                type="text"
                value={filter.userId || ''}
                onChange={(e) => onFilterChange({ ...filter, userId: e.target.value })}
                placeholder="Enter user ID"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              />
            </div>

            {/* Request ID */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Request ID</label>
              <input
                type="text"
                value={filter.requestId || ''}
                onChange={(e) => onFilterChange({ ...filter, requestId: e.target.value })}
                placeholder="Enter request ID"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              />
            </div>

            {/* IP Address */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">IP Address</label>
              <input
                type="text"
                value={filter.ip || ''}
                onChange={(e) => onFilterChange({ ...filter, ip: e.target.value })}
                placeholder="Enter IP address"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              />
            </div>
          </div>

          {/* Saved Filters */}
          {savedFilters.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Saved Filters</label>
              <div className="flex flex-wrap gap-2">
                {savedFilters.map((savedFilter) => (
                  <button
                    key={savedFilter.id}
                    onClick={() => onLoadFilter?.(savedFilter.filter)}
                    className="px-3 py-1 bg-blue-50 text-blue-700 border border-blue-200 rounded-lg text-sm hover:bg-blue-100"
                  >
                    {savedFilter.name}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Save Filter */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowSaveFilter(!showSaveFilter)}
              className="flex items-center gap-2 px-3 py-1 bg-green-50 text-green-700 border border-green-200 rounded-lg text-sm hover:bg-green-100"
            >
              <Plus className="h-4 w-4" />
              Save Current Filter
            </button>
          </div>

          {/* Save Filter Form */}
          {showSaveFilter && (
            <div className="border border-gray-200 rounded-lg p-4 space-y-3">
              <input
                type="text"
                placeholder="Filter name"
                value={newFilterName}
                onChange={(e) => setNewFilterName(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              />
              <textarea
                placeholder="Description (optional)"
                value={newFilterDescription}
                onChange={(e) => setNewFilterDescription(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                rows={2}
              />
              <div className="flex gap-2">
                <button
                  onClick={handleSaveFilter}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700"
                >
                  Save Filter
                </button>
                <button
                  onClick={() => setShowSaveFilter(false)}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-sm hover:bg-gray-50"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}