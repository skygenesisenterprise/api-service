"use client";

import { useState, useEffect } from "react";
import { useAuth } from "../context/JwtAuthContext";
import DashboardPageLayout from "../components/DashboardPageLayout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { 
  Key, 
  Shield, 
  Activity, 
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Database
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

  const getHealthColor = (health: string) => {
    switch (health) {
      case 'healthy': return 'text-green-600 bg-green-100';
      case 'warning': return 'text-yellow-600 bg-yellow-100';
      case 'error': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

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
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Welcome back, {user?.name || 'User'}
          </h1>
          <p className="text-gray-600">
            Here's an overview of your Sky Genesis Enterprise API service
          </p>
        </div>

        {/* System Health Banner */}
        <div className={`mb-8 p-4 rounded-lg border flex items-center justify-between ${getHealthColor(stats.systemHealth)}`}>
          <div className="flex items-center gap-3">
            {getHealthIcon(stats.systemHealth)}
            <div>
              <h3 className="font-medium">System Status</h3>
              <p className="text-sm opacity-80">
                {stats.systemHealth === 'healthy' && 'All systems operational'}
                {stats.systemHealth === 'warning' && 'Some systems require attention'}
                {stats.systemHealth === 'error' && 'Critical issues detected'}
              </p>
            </div>
          </div>
          <Button variant="outline" size="sm">
            View Details
          </Button>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total API Keys</CardTitle>
              <Key className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.totalKeys}</div>
              <p className="text-xs text-muted-foreground">
                +2 from last month
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Keys</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{stats.activeKeys}</div>
              <p className="text-xs text-muted-foreground">
                {Math.round((stats.activeKeys / stats.totalKeys) * 100)}% of total
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Certificates</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.totalCertificates}</div>
              <p className="text-xs text-muted-foreground">
                All valid
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Recent Activity</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.recentActivity}</div>
              <p className="text-xs text-muted-foreground">
                Last 24 hours
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
              <CardDescription>
                Common tasks and management options
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Button 
                  variant="outline" 
                  className="h-20 flex-col items-start justify-start"
                  onClick={() => window.location.href = '/settings/api'}
                >
                  <Key className="w-6 h-6 mb-2" />
                  <div className="text-left">
                    <div className="font-medium">Manage API Keys</div>
                    <div className="text-xs text-muted-foreground">Create, view, and revoke keys</div>
                  </div>
                </Button>
                
                <Button 
                  variant="outline" 
                  className="h-20 flex-col items-start justify-start"
                  onClick={() => window.location.href = '/settings/security'}
                >
                  <Shield className="w-6 h-6 mb-2" />
                  <div className="text-left">
                    <div className="font-medium">Security Settings</div>
                    <div className="text-xs text-muted-foreground">Configure authentication</div>
                  </div>
                </Button>
                
                <Button 
                  variant="outline" 
                  className="h-20 flex-col items-start justify-start"
                  onClick={() => window.location.href = '/logs/audit'}
                >
                  <Activity className="w-6 h-6 mb-2" />
                  <div className="text-left">
                    <div className="font-medium">View Logs</div>
                    <div className="text-xs text-muted-foreground">Audit and access logs</div>
                  </div>
                </Button>
                
                <Button 
                  variant="outline" 
                  className="h-20 flex-col items-start justify-start"
                  onClick={() => window.location.href = '/docs/swagger'}
                >
                  <Database className="w-6 h-6 mb-2" />
                  <div className="text-left">
                    <div className="font-medium">API Documentation</div>
                    <div className="text-xs text-muted-foreground">Swagger UI docs</div>
                  </div>
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>System Info</CardTitle>
              <CardDescription>
                Current service status
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">API Service</span>
                <Badge variant="outline" className="text-green-600 border-green-600">
                  <div className="w-2 h-2 bg-green-600 rounded-full mr-2"></div>
                  Online
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Database</span>
                <Badge variant="outline" className="text-green-600 border-green-600">
                  <div className="w-2 h-2 bg-green-600 rounded-full mr-2"></div>
                  Connected
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Vault</span>
                <Badge variant="outline" className="text-green-600 border-green-600">
                  <div className="w-2 h-2 bg-green-600 rounded-full mr-2"></div>
                  Available
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Keycloak</span>
                <Badge variant="outline" className="text-green-600 border-green-600">
                  <div className="w-2 h-2 bg-green-600 rounded-full mr-2"></div>
                  Auth Ready
                </Badge>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Recent Activity */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
            <CardDescription>
              Latest API key operations and system events
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                { id: 1, action: 'API Key Created', entity: 'sandbox-key-001', time: '2 minutes ago', type: 'success' },
                { id: 2, action: 'Certificate Generated', entity: 'cert-rsa-042', time: '15 minutes ago', type: 'success' },
                { id: 3, action: 'API Key Revoked', entity: 'prod-key-003', time: '1 hour ago', type: 'warning' },
                { id: 4, action: 'Authentication Success', entity: 'user@example.com', time: '2 hours ago', type: 'info' },
                { id: 5, action: 'System Backup', entity: 'daily-backup', time: '3 hours ago', type: 'info' },
              ].map((activity) => (
                <div key={activity.id} className="flex items-center justify-between py-2 border-b last:border-b-0">
                  <div className="flex items-center gap-3">
                    <div className={`w-2 h-2 rounded-full ${
                      activity.type === 'success' ? 'bg-green-500' :
                      activity.type === 'warning' ? 'bg-yellow-500' :
                      'bg-blue-500'
                    }`}></div>
                    <div>
                      <p className="font-medium text-sm">{activity.action}</p>
                      <p className="text-xs text-muted-foreground">{activity.entity}</p>
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground">{activity.time}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardPageLayout>
  );
}