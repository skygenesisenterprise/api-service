"use client";

import { useState, useEffect } from 'react';
import { LogSidebar } from './components/LogSidebar';
import { LogFilters } from './components/LogFilters';
import { LogViewer } from './components/LogViewer';
import { LogDashboard } from './components/LogDashboard';
import { useLogs } from './hooks/useLogs';
import { useAuth } from '../context/UnifiedAuthContext';
import { 
  BarChart3, 
  List, 
  Filter, 
  Settings, 
  Play, 
  Pause, 
  Download,
  RefreshCw,
  Zap,
  User,
  Shield,
  LogOut,
  Bell,
  ChevronDown,
  Search,
  Plus,
  Bookmark,
  Share2,
  Eye,
  EyeOff,
  Clock,
  Calendar,
  Tag,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Loader2
} from 'lucide-react';

export default function LogsPage() {
  const [activeView, setActiveView] = useState<'dashboard' | 'logs' | 'filters'>('dashboard');
  const [user, setUser] = useState<any>(null);
  const [userPermissions, setUserPermissions] = useState<any>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [debugInfo, setDebugInfo] = useState<any>(null);
  
  const {
    logs,
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
  } = useLogs();
  
  const { user: authUser, permissions, loading: authHookLoading } = useAuth();

  // Vérifier l'authentification et charger les permissions
  useEffect(() => {
    const checkAuth = async () => {
      try {
        setAuthLoading(true);
        setAuthError(null);
        
        const token = localStorage.getItem('token');
        if (!token) {
          throw new Error('No authentication token found');
        }

        console.log('🔍 Checking authentication with token...');
        
        // Valider le token et obtenir les informations utilisateur
        const validateResponse = await fetch('/api/v1/auth/validate', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!validateResponse.ok) {
          throw new Error(`Token validation failed: ${validateResponse.status}`);
        }

        const validateResult = await validateResponse.json();
        console.log('✅ Token validation result:', validateResult);
        setUser(validateResult.data.user);
        
        // Obtenir les permissions détaillées
        console.log('🔍 Fetching permissions...');
        const permsResponse = await fetch('/api/v1/auth/permissions', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!permsResponse.ok) {
          throw new Error(`Permissions fetch failed: ${permsResponse.status}`);
        }
        
        const permsResult = await permsResponse.json();
        console.log('✅ Permissions result:', permsResult);
        setUserPermissions(permsResult.data);
        
        // Stocker les informations de debug
        setDebugInfo({
          user: validateResult.data.user,
          permissions: permsResult.data,
          canAccessLogs: checkLogsAccess(permsResult.data),
          timestamp: new Date().toISOString()
        });
        
      } catch (error) {
        console.error('❌ Auth check failed:', error);
        setAuthError(error instanceof Error ? error.message : 'Authentication failed');
        
        // Rediriger vers la page de login après un délai
        setTimeout(() => {
          window.location.href = '/login';
        }, 3000);
      } finally {
        setAuthLoading(false);
      }
    };

    checkAuth();
  }, []);

  // Fonction pour vérifier l'accès aux logs
  const checkLogsAccess = (permissions: any) => {
    if (!permissions) {
      console.log('❌ No permissions provided');
      return false;
    }

    console.log('🔍 Checking logs access with permissions:', {
      services: permissions.services,
      permissions: permissions.permissions,
      roles: permissions.roles
    });

    // Vérifications multiples avec logging détaillé
    const checks = [
      {
        name: 'services includes logs',
        result: permissions.services?.includes('logs') || false,
        value: permissions.services
      },
      {
        name: 'services includes *',
        result: permissions.services?.includes('*') || false,
        value: permissions.services
      },
      {
        name: 'permissions includes logs:read',
        result: permissions.permissions?.includes('logs:read') || false,
        value: permissions.permissions
      },
      {
        name: 'permissions includes logs:*',
        result: permissions.permissions?.includes('logs:*') || false,
        value: permissions.permissions
      },
      {
        name: 'roles includes admin',
        result: permissions.roles?.includes('admin') || false,
        value: permissions.roles
      },
      {
        name: 'roles includes owner',
        result: permissions.roles?.includes('owner') || false,
        value: permissions.roles
      }
    ];

    console.log('📊 Access checks:', checks);
    
    const hasAccess = checks.some(check => check.result);
    console.log(`${hasAccess ? '✅' : '❌'} Logs access ${hasAccess ? 'GRANTED' : 'DENIED'}`);
    
    return hasAccess;
  };

  // Vérifier les permissions d'accès aux logs
  const canAccessLogs = userPermissions ? checkLogsAccess(userPermissions) : false;
  const canManageLogs = userPermissions ? (
    userPermissions.permissions?.includes('logs:write') ||
    userPermissions.permissions?.includes('logs:*') ||
    userPermissions.roles?.includes('admin') ||
    userPermissions.roles?.includes('owner')
  ) : false;

  const canExportLogs = userPermissions ? (
    userPermissions.permissions?.includes('logs:export') ||
    userPermissions.permissions?.includes('logs:*') ||
    userPermissions.roles?.includes('admin') ||
    userPermissions.roles?.includes('owner')
  ) : false;

  // Gérer la déconnexion
  const handleLogout = async () => {
    try {
      const token = localStorage.getItem('token');
      if (token) {
        await fetch('/api/v1/auth/logout', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` }
        });
      }
      
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
      window.location.href = '/login';
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  // Gérer le changement de vue
  const handleViewChange = (view: 'dashboard' | 'logs' | 'filters') => {
    if (view === 'logs' && !canAccessLogs) {
      return; // Ne pas autoriser l'accès si pas de permission
    }
    setActiveView(view);
  };

  // Quick filters prédéfinis
  const quickFilters = [
    {
      id: 'errors-only',
      name: 'Errors Only',
      icon: AlertTriangle,
      color: 'bg-red-100 text-red-700',
                      filter: { levels: ['error', 'fatal'] } as any as any
    },
    {
      id: 'last-hour',
      name: 'Last Hour',
      icon: RefreshCw,
      color: 'bg-blue-100 text-blue-700',
      filter: { 
        dateRange: {
          start: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
          end: new Date().toISOString()
        }
      }
    },
    {
      id: 'my-logs',
      name: 'My Logs',
      icon: User,
      color: 'bg-green-100 text-green-700',
      filter: { userId: user?.sub }
    },
    {
      id: 'critical',
      name: 'Critical Issues',
      icon: XCircle,
      color: 'bg-purple-100 text-purple-700',
      filter: { 
        levels: ['fatal'],
        search: 'critical OR severe OR urgent'
      }
    }
  ];

  // Actions rapides
  const quickActions = [
    {
      id: 'create-alert',
      name: 'Create Alert',
      icon: Bell,
      description: 'Create alert from current filter',
      action: () => {
        console.log('Create alert from filter:', filter);
      }
    },
    {
      id: 'save-search',
      name: 'Save Search',
      icon: Bookmark,
      description: 'Save current search as filter',
      action: () => {
        const name = prompt('Enter a name for this search:');
        if (name) {
          saveFilter(name, 'Saved from logs page');
        }
      }
    },
    {
      id: 'share-view',
      name: 'Share View',
      icon: Share2,
      description: 'Share current view with team',
      action: () => {
        console.log('Share current view');
      }
    }
  ];

  // Notifications simulées
  const notifications = [
    {
      id: 1,
      type: 'error',
      title: 'High Error Rate',
      message: 'Error rate increased by 25% in the last hour',
      time: '2 minutes ago',
      read: false
    },
    {
      id: 2,
      type: 'warning',
      title: 'Service Degradation',
      message: 'API Gateway response time above threshold',
      time: '15 minutes ago',
      read: false
    },
    {
      id: 3,
      type: 'info',
      title: 'System Update',
      message: 'Log system updated to v2.1.3',
      time: '1 hour ago',
      read: true
    }
  ];

  // État de chargement
  if (authLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full">
          <div className="text-center">
            <Loader2 className="h-12 w-12 text-blue-600 mx-auto mb-4 animate-spin" />
            <h2 className="text-2xl font-bold text-gray-900 mb-2">Loading...</h2>
            <p className="text-gray-600">
              Verifying your authentication and permissions...
            </p>
          </div>
        </div>
      </div>
    );
  }

  // État d'erreur
  if (authError) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full">
          <div className="text-center">
            <XCircle className="h-16 w-16 text-red-500 mx-auto mb-4" />
            <h2 className="text-2xl font-bold text-gray-900 mb-2">Authentication Error</h2>
            <p className="text-gray-600 mb-4">{authError}</p>
            <p className="text-sm text-gray-500 mb-6">
              Redirecting to login page...
            </p>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div className="bg-blue-600 h-2 rounded-full animate-pulse" style={{ width: '60%' }} />
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Accès refusé
  if (!canAccessLogs && !authLoading && !authError) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full">
          <div className="text-center">
            <Shield className="h-16 w-16 text-red-500 mx-auto mb-4" />
            <h2 className="text-2xl font-bold text-gray-900 mb-2">Access Denied</h2>
            <p className="text-gray-600 mb-6">
              You don't have permission to access the logs system.
            </p>
            
            {/* Debug information */}
            {debugInfo && (
              <div className="mb-6 p-4 bg-gray-50 rounded-lg text-left">
                <h3 className="font-medium text-gray-900 mb-2">Debug Information:</h3>
                <div className="text-xs text-gray-600 space-y-1">
                  <p><strong>User:</strong> {debugInfo.user?.primaryEmail}</p>
                  <p><strong>Roles:</strong> {JSON.stringify(debugInfo.permissions?.roles)}</p>
                  <p><strong>Services:</strong> {JSON.stringify(debugInfo.permissions?.services)}</p>
                  <p><strong>Permissions:</strong> {JSON.stringify(debugInfo.permissions?.permissions)}</p>
                  <p><strong>Can Access:</strong> {debugInfo.canAccessLogs ? 'Yes' : 'No'}</p>
                </div>
              </div>
            )}
            
            <button
              onClick={() => window.location.href = '/dashboard'}
              className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Return to Dashboard
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-full px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <BarChart3 className="h-8 w-8 text-blue-600" />
                <div>
                  <h1 className="text-3xl font-bold text-gray-900">Enterprise Logs</h1>
                  <p className="text-gray-600 mt-1">
                    Real-time log monitoring and analysis
                  </p>
                </div>
              </div>
              
              {/* Status Badge */}
              <div className="flex items-center gap-2">
                <div className={`px-3 py-1 rounded-full text-sm font-medium ${
                  isStreaming
                    ? 'bg-green-100 text-green-700 animate-pulse'
                    : 'bg-gray-100 text-gray-700'
                }`}>
                  {isStreaming ? 'LIVE' : 'STATIC'}
                </div>
                {user && (
                  <div className="px-3 py-1 bg-blue-100 text-blue-700 rounded-full text-sm font-medium">
                    {user.primaryEmail}
                  </div>
                )}
                {canAccessLogs && (
                  <div className="px-3 py-1 bg-green-100 text-green-700 rounded-full text-sm font-medium flex items-center gap-1">
                    <CheckCircle className="h-3 w-3" />
                    Access Granted
                  </div>
                )}
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {/* Search Bar */}
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search logs..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter' && searchQuery) {
                      setFilter({ ...filter, search: searchQuery });
                    }
                  }}
                  className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent w-64"
                />
              </div>

              {/* Quick Filters */}
              <div className="flex items-center gap-2">
                {quickFilters.map((quickFilter) => {
                  const Icon = quickFilter.icon;
                  return (
                    <button
                      key={quickFilter.id}
                      onClick={() => setFilter({ ...filter, ...quickFilter.filter })}
                      className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${quickFilter.color} hover:opacity-80`}
                      title={quickFilter.name}
                    >
                      <Icon className="h-4 w-4" />
                      <span className="hidden sm:inline">{quickFilter.name}</span>
                    </button>
                  );
                })}
              </div>

              {/* View Toggle */}
              <div className="flex items-center bg-gray-100 rounded-lg p-1">
                <button
                  onClick={() => handleViewChange('dashboard')}
                  className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeView === 'dashboard'
                      ? 'bg-white text-blue-600 shadow-sm'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  <BarChart3 className="h-4 w-4" />
                  <span className="hidden sm:inline">Dashboard</span>
                </button>
                <button
                  onClick={() => handleViewChange('logs')}
                  className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeView === 'logs'
                      ? 'bg-white text-blue-600 shadow-sm'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  <List className="h-4 w-4" />
                  <span className="hidden sm:inline">Logs</span>
                </button>
                <button
                  onClick={() => handleViewChange('filters')}
                  className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeView === 'filters'
                      ? 'bg-white text-blue-600 shadow-sm'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  <Filter className="h-4 w-4" />
                  <span className="hidden sm:inline">Filters</span>
                </button>
              </div>

              {/* Streaming Toggle */}
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
                    Live Stream
                  </>
                )}
              </button>

              {/* Refresh */}
              <button
                onClick={refresh}
                disabled={loading}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>

              {/* Export */}
              {canExportLogs && (
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
              )}

              {/* Quick Actions */}
              <div className="relative group">
                <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
                  <Zap className="h-4 w-4" />
                  Actions
                  <ChevronDown className="h-4 w-4" />
                </button>
                <div className="absolute right-0 mt-1 w-48 bg-white border border-gray-200 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible z-10">
                  {quickActions.map((action) => {
                    const Icon = action.icon;
                    return (
                      <button
                        key={action.id}
                        onClick={action.action}
                        className="block w-full text-left px-3 py-2 text-sm hover:bg-gray-50"
                        title={action.description}
                      >
                        <div className="flex items-center gap-3">
                          <Icon className="h-4 w-4 text-gray-500" />
                          <div>
                            <div className="font-medium">{action.name}</div>
                            <div className="text-xs text-gray-500">{action.description}</div>
                          </div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Notifications */}
              <div className="relative group">
                <button className="relative p-2 text-gray-600 hover:text-gray-900">
                  <Bell className="h-5 w-5" />
                  {notifications.filter(n => !n.read).length > 0 && (
                    <div className="absolute -top-1 -right-1 h-5 w-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center font-medium">
                      {notifications.filter(n => !n.read).length}
                    </div>
                  )}
                </button>
                <div className="absolute right-0 mt-2 w-80 bg-white border border-gray-200 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible z-10">
                  <div className="p-4 border-b border-gray-100">
                    <h3 className="font-medium text-gray-900">Notifications</h3>
                  </div>
                  <div className="max-h-96 overflow-y-auto">
                    {notifications.map((notification) => (
                      <div
                        key={notification.id}
                        className={`p-4 hover:bg-gray-50 cursor-pointer border-b border-gray-100 ${
                          !notification.read ? 'bg-blue-50' : ''
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <div className={`h-2 w-2 rounded-full mt-2 ${
                            notification.type === 'error' ? 'bg-red-500' :
                            notification.type === 'warning' ? 'bg-yellow-500' :
                            'bg-blue-500'
                          }`} />
                          <div className="flex-1">
                            <p className="text-sm font-medium text-gray-900">{notification.title}</p>
                            <p className="text-xs text-gray-500 mt-1">{notification.message}</p>
                            <p className="text-xs text-gray-400 mt-2">{notification.time}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="p-3 border-t border-gray-100">
                    <button className="w-full text-sm text-blue-600 hover:text-blue-700 hover:bg-blue-50 py-2 rounded">
                      View all notifications
                    </button>
                  </div>
                </div>
              </div>

              {/* User Menu */}
              {user && (
                <div className="relative group">
                  <button className="flex items-center gap-3 p-2 hover:bg-gray-50 rounded-lg">
                    <div className="h-8 w-8 bg-blue-500 rounded-full flex items-center justify-center text-white font-medium">
                      {user.primaryEmail.charAt(0).toUpperCase()}
                    </div>
                    <div className="hidden md:block text-left">
                      <div className="text-sm font-medium text-gray-900">{user.primaryEmail}</div>
                      <div className="text-xs text-gray-500">
                        {userPermissions?.roles?.join(', ') || 'User'}
                      </div>
                    </div>
                    <ChevronDown className="h-4 w-4 text-gray-400" />
                  </button>
                  <div className="absolute right-0 mt-2 w-56 bg-white border border-gray-200 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible z-10">
                    <div className="p-4 border-b border-gray-100">
                      <div className="flex items-center gap-3">
                        <div className="h-10 w-10 bg-blue-500 rounded-full flex items-center justify-center text-white font-medium">
                          {user.primaryEmail.charAt(0).toUpperCase()}
                        </div>
                        <div>
                          <div className="font-medium text-gray-900">{user.primaryEmail}</div>
                          <div className="text-sm text-gray-500">
                            {user.globalId || user.username || 'User'}
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="p-2">
                      <button
                        onClick={() => window.location.href = '/profile'}
                        className="flex items-center gap-3 w-full px-3 py-2 text-sm hover:bg-gray-50 rounded-lg"
                      >
                        <User className="h-4 w-4 text-gray-500" />
                        Profile
                      </button>
                      <button
                        onClick={() => window.location.href = '/settings'}
                        className="flex items-center gap-3 w-full px-3 py-2 text-sm hover:bg-gray-50 rounded-lg"
                      >
                        <Settings className="h-4 w-4 text-gray-500" />
                        Settings
                      </button>
                      <button
                        onClick={handleLogout}
                        className="flex items-center gap-3 w-full px-3 py-2 text-sm hover:bg-gray-50 rounded-lg text-red-600"
                      >
                        <LogOut className="h-4 w-4" />
                        Sign out
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Status Bar */}
          <div className="flex items-center justify-between mt-4 text-sm">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${isStreaming ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
                <span className="text-gray-600">
                  {isStreaming ? 'Live streaming' : 'Static view'}
                </span>
              </div>
              <div className="text-gray-600">
                {logs.length.toLocaleString()} logs loaded
              </div>
              {stats && (
                <div className="text-gray-600">
                  {((stats.byLevel.error || 0) + (stats.byLevel.fatal || 0)) / stats.total * 100}% error rate
                </div>
              )}
            </div>
            
            <div className="flex items-center gap-4">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={config.autoRefresh}
                  onChange={(e) => setConfig({ ...config, autoRefresh: e.target.checked })}
                  className="rounded border-gray-300"
                />
                <span className="text-gray-600">Auto-refresh</span>
              </label>
              
              <select
                value={config.timestamps}
                onChange={(e) => setConfig({ ...config, timestamps: e.target.value as any })}
                className="px-3 py-1 border border-gray-300 rounded-lg text-sm"
              >
                <option value="utc">UTC</option>
                <option value="local">Local</option>
                <option value="relative">Relative</option>
              </select>
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
          {/* Filters */}
          <div className="mb-6">
            <LogFilters
              filter={filter}
              onFilterChange={setFilter}
              savedFilters={savedFilters}
              onSaveFilter={(name, description) => saveFilter(name, description)}
              onLoadFilter={(savedFilter) => loadSavedFilter(savedFilter)}
            />
          </div>

          {/* Content Area */}
          {activeView === 'dashboard' && stats && (
            <LogDashboard
              logs={logs}
              stats={stats}
              loading={loading}
              onRefresh={refresh}
            />
          )}

          {activeView === 'logs' && (
            <LogViewer
              logs={logs}
              loading={loading}
              config={config}
              onConfigChange={setConfig}
              onExport={exportLogs}
              onRefresh={refresh}
              onLoadMore={loadMore}
              hasMore={hasMore}
            />
          )}

          {activeView === 'filters' && (
            <div className="bg-white border border-gray-200 rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Advanced Filter Management</h3>
              <div className="space-y-6">
                {/* Current Filter */}
                <div>
                  <h4 className="text-md font-medium text-gray-800 mb-2">Current Active Filter</h4>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <pre className="text-sm text-gray-700">
                      {JSON.stringify(filter, null, 2)}
                    </pre>
                  </div>
                </div>

                {/* Saved Filters */}
                <div>
                  <h4 className="text-md font-medium text-gray-800 mb-2">Saved Filters</h4>
                  <div className="space-y-2">
                    {savedFilters.map((savedFilter) => (
                      <div
                        key={savedFilter.id}
                        className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50"
                      >
                        <div className="flex items-center justify-between">
                          <div>
                            <h5 className="font-medium text-gray-900">{savedFilter.name}</h5>
                            <p className="text-sm text-gray-600">{savedFilter.description}</p>
                            <p className="text-xs text-gray-500 mt-1">
                              Used {savedFilter.usageCount} times • Created by {savedFilter.createdBy}
                            </p>
                          </div>
                          <div className="flex gap-2">
                            <button
                              onClick={() => loadSavedFilter(savedFilter)}
                              className="px-3 py-1 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700"
                            >
                              Load
                            </button>
                            <button
                              onClick={() => setFilter(savedFilter.filter)}
                              className="px-3 py-1 border border-gray-300 text-sm rounded-lg hover:bg-gray-50"
                            >
                              Apply
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}