"use client";

import { useState, useEffect } from "react";
import { useAuth } from "../context/JwtAuthContext";
import DashboardPageLayout from "../components/DashboardPageLayout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { 
  Key, 
  Shield, 
  Activity, 
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Database,
  Zap,
  Globe,
  Lock,
  BarChart3
} from "lucide-react";

interface DashboardStats {
  totalKeys: number;
  activeKeys: number;
  revokedKeys: number;
  totalCertificates: number;
  recentActivity: number;
  systemHealth: 'healthy' | 'warning' | 'error';
}

export default function DashboardPage() {
  const { token, isAuthenticated, user } = useAuth();
  const [stats, setStats] = useState<DashboardStats>({
    totalKeys: 0,
    activeKeys: 0,
    revokedKeys: 0,
    totalCertificates: 0,
    recentActivity: 0,
    systemHealth: 'healthy'
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulate loading dashboard data
    const loadDashboardData = async () => {
      setLoading(true);
      try {
        // In a real implementation, this would fetch from the API
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        setStats({
          totalKeys: 12,
          activeKeys: 8,
          revokedKeys: 4,
          totalCertificates: 8,
          recentActivity: 24,
          systemHealth: 'healthy'
        });
      } catch (error) {
        console.error('Failed to load dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    if (isAuthenticated) {
      loadDashboardData();
    }
  }, [isAuthenticated, token]);

  

  const getHealthIcon = (health: string) => {
    switch (health) {
      case 'healthy': return <CheckCircle className="w-4 h-4" />;
      case 'warning': return <AlertTriangle className="w-4 h-4" />;
      case 'error': return <AlertTriangle className="w-4 h-4" />;
      default: return <Clock className="w-4 h-4" />;
    }
  };

  if (loading) {
    return (
      <DashboardPageLayout title="Tableau de bord" subtitle="Vue d'ensemble de votre système">
        <div className="max-w-6xl mx-auto">
          <div className="animate-pulse">
            <div className="h-8 bg-gray-200 rounded w-1/3 mb-8"></div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="h-32 bg-gray-200 rounded"></div>
              ))}
            </div>
            <div className="h-96 bg-gray-200 rounded"></div>
          </div>
        </div>
      </DashboardPageLayout>
    );
  }

  return (
    <DashboardPageLayout title="Tableau de bord" subtitle="Vue d'ensemble de votre système">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Hero Section */}
        <div className="mb-12 text-center">
          <h1 className="text-5xl font-bold gradient-text mb-4">
            Welcome back, {user?.fullName || user?.email || 'User'}
          </h1>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Here's your comprehensive overview of the Sky Genesis Enterprise API service
          </p>
        </div>

        {/* System Health Banner */}
        <div className={`mb-12 p-6 rounded-2xl border flex items-center justify-between warm-shadow ${
          stats.systemHealth === 'healthy' ? 'bg-gradient-to-r from-green-50 to-orange-50 border-green-200' :
          stats.systemHealth === 'warning' ? 'bg-gradient-to-r from-yellow-50 to-orange-50 border-yellow-200' :
          'bg-gradient-to-r from-red-50 to-orange-50 border-red-200'
        }`}>
          <div className="flex items-center gap-4">
            <div className={`p-3 rounded-full ${
              stats.systemHealth === 'healthy' ? 'bg-green-100' :
              stats.systemHealth === 'warning' ? 'bg-yellow-100' :
              'bg-red-100'
            }`}>
              {getHealthIcon(stats.systemHealth)}
            </div>
            <div>
              <h3 className="text-lg font-semibold">System Status</h3>
              <p className="text-sm text-muted-foreground">
                {stats.systemHealth === 'healthy' && 'All systems operational and running smoothly'}
                {stats.systemHealth === 'warning' && 'Some systems require attention'}
                {stats.systemHealth === 'error' && 'Critical issues detected'}
              </p>
            </div>
          </div>
          <Button variant="outline" size="sm" className="shrink-0">
            View Details
          </Button>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          <div className="relative overflow-hidden rounded-xl border border-border bg-card p-6 transition-all duration-300 hover:transform hover:-translate-y-1 hover:shadow-lg hover:shadow-orange-500/20">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 rounded-lg bg-gradient-to-br from-orange-100 to-red-100">
                <Key className="h-6 w-6 text-orange-600" />
              </div>
              <TrendingUp className="h-4 w-4 text-green-500" />
            </div>
            <div className="space-y-1">
              <div className="text-3xl font-bold">{stats.totalKeys}</div>
              <p className="text-sm text-muted-foreground">Total API Keys</p>
              <p className="text-xs text-green-600 font-medium">+2 from last month</p>
            </div>
          </div>

          <div className="relative overflow-hidden rounded-xl border border-border bg-card p-6 transition-all duration-300 hover:transform hover:-translate-y-1 hover:shadow-lg hover:shadow-green-500/20">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 rounded-lg bg-gradient-to-br from-green-100 to-emerald-100">
                <Zap className="h-6 w-6 text-green-600" />
              </div>
              <Activity className="h-4 w-4 text-blue-500" />
            </div>
            <div className="space-y-1">
              <div className="text-3xl font-bold text-green-600">{stats.activeKeys}</div>
              <p className="text-sm text-muted-foreground">Active Keys</p>
              <p className="text-xs text-muted-foreground">
                {Math.round((stats.activeKeys / stats.totalKeys) * 100)}% of total
              </p>
            </div>
          </div>

          <div className="relative overflow-hidden rounded-xl border border-border bg-card p-6 transition-all duration-300 hover:transform hover:-translate-y-1 hover:shadow-lg hover:shadow-blue-500/20">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 rounded-lg bg-gradient-to-br from-blue-100 to-indigo-100">
                <Shield className="h-6 w-6 text-blue-600" />
              </div>
              <Lock className="h-4 w-4 text-purple-500" />
            </div>
            <div className="space-y-1">
              <div className="text-3xl font-bold">{stats.totalCertificates}</div>
              <p className="text-sm text-muted-foreground">Certificates</p>
              <p className="text-xs text-green-600 font-medium">All valid</p>
            </div>
          </div>

          <div className="relative overflow-hidden rounded-xl border border-border bg-card p-6 transition-all duration-300 hover:transform hover:-translate-y-1 hover:shadow-lg hover:shadow-purple-500/20">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 rounded-lg bg-gradient-to-br from-purple-100 to-pink-100">
                <BarChart3 className="h-6 w-6 text-purple-600" />
              </div>
              <Globe className="h-4 w-4 text-orange-500" />
            </div>
            <div className="space-y-1">
              <div className="text-3xl font-bold">{stats.recentActivity}</div>
              <p className="text-sm text-muted-foreground">Recent Activity</p>
              <p className="text-xs text-muted-foreground">Last 24 hours</p>
            </div>
          </div>
        </div>

        {/* Quick Actions & System Info */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
          <div className="lg:col-span-2">
            <Card className="warm-shadow-lg">
              <CardHeader className="pb-6">
                <CardTitle className="text-2xl font-semibold">Quick Actions</CardTitle>
                <CardDescription className="text-base">
                  Common tasks and management options
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <button 
                    className="h-24 flex flex-col items-start justify-start p-4 rounded-xl border border-border bg-card hover:bg-accent hover:border-accent transition-all duration-200 group"
                    onClick={() => window.location.href = '/settings/api'}
                  >
                    <Key className="w-8 h-8 mb-3 text-orange-500 group-hover:scale-110 transition-transform" />
                    <div className="text-left">
                      <div className="font-semibold text-base mb-1">Manage API Keys</div>
                      <div className="text-sm text-muted-foreground">Create, view, and revoke keys</div>
                    </div>
                  </button>
                  
                  <button 
                    className="h-24 flex flex-col items-start justify-start p-4 rounded-xl border border-border bg-card hover:bg-accent hover:border-accent transition-all duration-200 group"
                    onClick={() => window.location.href = '/settings/security'}
                  >
                    <Shield className="w-8 h-8 mb-3 text-blue-500 group-hover:scale-110 transition-transform" />
                    <div className="text-left">
                      <div className="font-semibold text-base mb-1">Security Settings</div>
                      <div className="text-sm text-muted-foreground">Configure authentication</div>
                    </div>
                  </button>
                  
                  <button 
                    className="h-24 flex flex-col items-start justify-start p-4 rounded-xl border border-border bg-card hover:bg-accent hover:border-accent transition-all duration-200 group"
                    onClick={() => window.location.href = '/logs/audit'}
                  >
                    <Activity className="w-8 h-8 mb-3 text-green-500 group-hover:scale-110 transition-transform" />
                    <div className="text-left">
                      <div className="font-semibold text-base mb-1">View Logs</div>
                      <div className="text-sm text-muted-foreground">Audit and access logs</div>
                    </div>
                  </button>
                  
                  <button 
                    className="h-24 flex flex-col items-start justify-start p-4 rounded-xl border border-border bg-card hover:bg-accent hover:border-accent transition-all duration-200 group"
                    onClick={() => window.location.href = '/docs/swagger'}
                  >
                    <Database className="w-8 h-8 mb-3 text-purple-500 group-hover:scale-110 transition-transform" />
                    <div className="text-left">
                      <div className="font-semibold text-base mb-1">API Documentation</div>
                      <div className="text-sm text-muted-foreground">Swagger UI docs</div>
                    </div>
                  </button>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card className="warm-shadow-lg">
            <CardHeader className="pb-6">
              <CardTitle className="text-xl font-semibold">System Status</CardTitle>
              <CardDescription>
                Current service status
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">API Service</span>
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium bg-green-50 text-green-700 border border-green-200">
                  <div className="w-2 h-2 bg-green-600 rounded-full animate-pulse"></div>
                  Online
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Database</span>
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium bg-green-50 text-green-700 border border-green-200">
                  <div className="w-2 h-2 bg-green-600 rounded-full animate-pulse"></div>
                  Connected
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Vault</span>
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium bg-green-50 text-green-700 border border-green-200">
                  <div className="w-2 h-2 bg-green-600 rounded-full animate-pulse"></div>
                  Available
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Keycloak</span>
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium bg-green-50 text-green-700 border border-green-200">
                  <div className="w-2 h-2 bg-green-600 rounded-full animate-pulse"></div>
                  Auth Ready
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Recent Activity */}
        <Card className="warm-shadow-lg">
          <CardHeader className="pb-6">
            <CardTitle className="text-2xl font-semibold">Recent Activity</CardTitle>
            <CardDescription className="text-base">
              Latest API key operations and system events
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {[
                { id: 1, action: 'API Key Created', entity: 'sandbox-key-001', time: '2 minutes ago', type: 'success' },
                { id: 2, action: 'Certificate Generated', entity: 'cert-rsa-042', time: '15 minutes ago', type: 'success' },
                { id: 3, action: 'API Key Revoked', entity: 'prod-key-003', time: '1 hour ago', type: 'warning' },
                { id: 4, action: 'Authentication Success', entity: 'user@example.com', time: '2 hours ago', type: 'info' },
                { id: 5, action: 'System Backup', entity: 'daily-backup', time: '3 hours ago', type: 'info' },
              ].map((activity) => (
                <div key={activity.id} className="flex items-center justify-between py-3 border-b border-border last:border-b-0 transition-colors hover:bg-muted/50">
                  <div className="flex items-center gap-4">
                    <div className={`w-3 h-3 rounded-full ${
                      activity.type === 'success' ? 'bg-green-500' :
                      activity.type === 'warning' ? 'bg-yellow-500' :
                      'bg-blue-500'
                    }`}></div>
                    <div className="flex-1">
                      <p className="font-medium">{activity.action}</p>
                      <p className="text-sm text-muted-foreground">{activity.entity}</p>
                    </div>
                  </div>
                  <span className="text-sm text-muted-foreground">{activity.time}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardPageLayout>
  );
}