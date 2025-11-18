"use client";

import { useState, useEffect } from "react";
import { useAuth } from "../context/JwtAuthContext";
import DashboardPageLayout from "../components/DashboardPageLayout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
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
  BarChart3,
  Users,
  Server,
  Cpu,
  HardDrive,
  Wifi,
  ArrowUp,
  ArrowDown,
  MoreHorizontal,
  RefreshCw,
  Download,
  Calendar,
  Eye,
  Settings
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
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
  ResponsiveContainer,
  Legend
} from "recharts";

interface DashboardStats {
  totalKeys: number;
  activeKeys: number;
  revokedKeys: number;
  totalCertificates: number;
  recentActivity: number;
  systemHealth: 'healthy' | 'warning' | 'error';
  apiCalls: number;
  uptime: number;
  storage: number;
  bandwidth: number;
}

interface ActivityItem {
  id: string;
  action: string;
  entity: string;
  time: string;
  type: 'success' | 'warning' | 'error' | 'info';
  user?: string;
}

interface SystemMetric {
  name: string;
  value: number;
  status: 'good' | 'warning' | 'critical';
  unit: string;
}

export default function DashboardPage() {
  const { token, isAuthenticated, user } = useAuth();
  const [stats, setStats] = useState<DashboardStats>({
    totalKeys: 0,
    activeKeys: 0,
    revokedKeys: 0,
    totalCertificates: 0,
    recentActivity: 0,
    systemHealth: 'healthy',
    apiCalls: 0,
    uptime: 0,
    storage: 0,
    bandwidth: 0
  });
  const [loading, setLoading] = useState(true);
  const [selectedTimeRange, setSelectedTimeRange] = useState('7d');
  const [activities, setActivities] = useState<ActivityItem[]>([]);

  // Données pour les graphiques
  const [apiCallsData, setApiCallsData] = useState([
    { name: 'Lun', calls: 2400, requests: 1400 },
    { name: 'Mar', calls: 1398, requests: 2210 },
    { name: 'Mer', calls: 9800, requests: 2290 },
    { name: 'Jeu', calls: 3908, requests: 2000 },
    { name: 'Ven', calls: 4800, requests: 2181 },
    { name: 'Sam', calls: 3800, requests: 2500 },
    { name: 'Dim', calls: 4300, requests: 2100 },
  ]);

  const [categoryData, setCategoryData] = useState([
    { name: 'Client', value: 45, color: '#3b82f6' },
    { name: 'Serveur', value: 30, color: '#10b981' },
    { name: 'Database', value: 25, color: '#f59e0b' },
  ]);

  const [systemMetrics, setSystemMetrics] = useState<SystemMetric[]>([
    { name: 'CPU', value: 45, status: 'good', unit: '%' },
    { name: 'Mémoire', value: 62, status: 'good', unit: '%' },
    { name: 'Stockage', value: 78, status: 'warning', unit: '%' },
    { name: 'Réseau', value: 23, status: 'good', unit: 'Mbps' },
  ]);

  useEffect(() => {
    const loadDashboardData = async () => {
      setLoading(true);
      try {
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        setStats({
          totalKeys: 24,
          activeKeys: 18,
          revokedKeys: 6,
          totalCertificates: 16,
          recentActivity: 142,
          systemHealth: 'healthy',
          apiCalls: 2847,
          uptime: 99.8,
          storage: 78,
          bandwidth: 23
        });

        setActivities([
          { id: '1', action: 'API Key Created', entity: 'sk_client_abc123', time: 'Il y a 2 minutes', type: 'success', user: 'Jean Dupont' },
          { id: '2', action: 'Certificate Generated', entity: 'cert-rsa-042', time: 'Il y a 15 minutes', type: 'success', user: 'Marie Martin' },
          { id: '3', action: 'API Key Revoked', entity: 'sk_server_xyz789', time: 'Il y a 1 heure', type: 'warning', user: 'Pierre Durand' },
          { id: '4', action: 'Authentication Success', entity: 'user@example.com', time: 'Il y a 2 heures', type: 'info', user: 'Sophie Bernard' },
          { id: '5', action: 'System Backup', entity: 'daily-backup', time: 'Il y a 3 heures', type: 'info', user: 'System' },
          { id: '6', action: 'High CPU Usage', entity: 'server-01', time: 'Il y a 4 heures', type: 'warning', user: 'Monitor' },
        ]);
      } catch (error) {
        console.error('Failed to load dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    // Charger les données du dashboard même sans authentification (mode développement)
    loadDashboardData();
  }, []);

  const getHealthIcon = (health: string) => {
    switch (health) {
      case 'healthy': return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'warning': return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      case 'error': return <AlertTriangle className="w-5 h-5 text-red-500" />;
      default: return <Clock className="w-5 h-5 text-gray-500" />;
    }
  };

  const getMetricColor = (status: string) => {
    switch (status) {
      case 'good': return 'text-green-600 bg-green-50 border-green-200';
      case 'warning': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: {
        type: "spring" as const,
        stiffness: 100
      }
    }
  };

  if (loading) {
    return (
      <DashboardPageLayout title="Tableau de bord" subtitle="Vue d'ensemble de votre système">
        <div className="space-y-8">
          <div className="animate-pulse">
            <div className="h-12 bg-gray-200 rounded-xl w-1/3 mb-8"></div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="h-32 bg-gray-200 rounded-2xl"></div>
              ))}
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 h-96 bg-gray-200 rounded-2xl"></div>
              <div className="h-96 bg-gray-200 rounded-2xl"></div>
            </div>
          </div>
        </div>
      </DashboardPageLayout>
    );
  }

  return (
    <DashboardPageLayout title="Tableau de bord" subtitle="Vue d'ensemble de votre système">
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="space-y-8"
      >
        {/* Header Section */}
        <motion.div variants={itemVariants} className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-6">
          <div>
            <h1 className="text-4xl lg:text-5xl font-bold bg-gradient-to-r from-gray-900 to-gray-600 bg-clip-text text-transparent mb-2">
              Bienvenue, {user?.fullName || user?.email || 'Utilisateur'}
            </h1>
            <p className="text-xl text-gray-600 dark:text-gray-400">
              Voici votre aperçu complet du service API Sky Genesis Enterprise
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Button variant="outline" size="sm" className="gap-2">
              <Calendar className="w-4 h-4" />
              {selectedTimeRange === '7d' ? '7 jours' : selectedTimeRange === '30d' ? '30 jours' : 'Aujourd\'hui'}
            </Button>
            <Button variant="outline" size="sm" className="gap-2">
              <RefreshCw className="w-4 h-4" />
              Actualiser
            </Button>
            <Button size="sm" className="gap-2">
              <Download className="w-4 h-4" />
              Exporter
            </Button>
          </div>
        </motion.div>

        {/* System Health Banner */}
        <motion.div variants={itemVariants}>
          <Card className={`border-2 ${
            stats.systemHealth === 'healthy' ? 'border-green-200 bg-gradient-to-r from-green-50 to-emerald-50' :
            stats.systemHealth === 'warning' ? 'border-yellow-200 bg-gradient-to-r from-yellow-50 to-orange-50' :
            'border-red-200 bg-gradient-to-r from-red-50 to-pink-50'
          }`}>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className={`p-3 rounded-2xl ${
                    stats.systemHealth === 'healthy' ? 'bg-green-100' :
                    stats.systemHealth === 'warning' ? 'bg-yellow-100' :
                    'bg-red-100'
                  }`}>
                    {getHealthIcon(stats.systemHealth)}
                  </div>
                  <div>
                    <h3 className="text-xl font-semibold text-gray-900">
                      {stats.systemHealth === 'healthy' ? 'Système Opérationnel' :
                       stats.systemHealth === 'warning' ? 'Attention Requise' :
                       'Problèmes Critiques'}
                    </h3>
                    <p className="text-gray-600">
                      {stats.systemHealth === 'healthy' ? 'Tous les services fonctionnent normalement' :
                       stats.systemHealth === 'warning' ? 'Certains services nécessitent une attention' :
                       'Des problèmes critiques ont été détectés'}
                    </p>
                  </div>
                </div>
                <Button variant="outline" size="sm" className="gap-2">
                  <Eye className="w-4 h-4" />
                  Voir les détails
                </Button>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Stats Grid */}
        <motion.div variants={itemVariants} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card className="group hover:shadow-xl transition-all duration-300 hover:-translate-y-1 border-0 shadow-lg">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 rounded-2xl bg-gradient-to-br from-blue-500 to-blue-600 group-hover:scale-110 transition-transform">
                  <Key className="h-6 w-6 text-white" />
                </div>
                <div className="flex items-center gap-1 text-green-600 text-sm font-medium">
                  <ArrowUp className="w-4 h-4" />
                  12%
                </div>
              </div>
              <div>
                <div className="text-3xl font-bold text-gray-900">{stats.totalKeys}</div>
                <p className="text-gray-600">Clés API totales</p>
                <p className="text-sm text-gray-500 mt-1">+2 ce mois-ci</p>
              </div>
            </CardContent>
          </Card>

          <Card className="group hover:shadow-xl transition-all duration-300 hover:-translate-y-1 border-0 shadow-lg">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 rounded-2xl bg-gradient-to-br from-green-500 to-emerald-600 group-hover:scale-110 transition-transform">
                  <Zap className="h-6 w-6 text-white" />
                </div>
                <div className="flex items-center gap-1 text-green-600 text-sm font-medium">
                  <ArrowUp className="w-4 h-4" />
                  8%
                </div>
              </div>
              <div>
                <div className="text-3xl font-bold text-green-600">{stats.activeKeys}</div>
                <p className="text-gray-600">Clés actives</p>
                <p className="text-sm text-gray-500 mt-1">{Math.round((stats.activeKeys / stats.totalKeys) * 100)}% du total</p>
              </div>
            </CardContent>
          </Card>

          <Card className="group hover:shadow-xl transition-all duration-300 hover:-translate-y-1 border-0 shadow-lg">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 rounded-2xl bg-gradient-to-br from-purple-500 to-pink-600 group-hover:scale-110 transition-transform">
                  <Shield className="h-6 w-6 text-white" />
                </div>
                <div className="flex items-center gap-1 text-blue-600 text-sm font-medium">
                  <Activity className="w-4 h-4" />
                  Stable
                </div>
              </div>
              <div>
                <div className="text-3xl font-bold text-purple-600">{stats.totalCertificates}</div>
                <p className="text-gray-600">Certificats</p>
                <p className="text-sm text-gray-500 mt-1">Tous valides</p>
              </div>
            </CardContent>
          </Card>

          <Card className="group hover:shadow-xl transition-all duration-300 hover:-translate-y-1 border-0 shadow-lg">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 rounded-2xl bg-gradient-to-br from-orange-500 to-red-600 group-hover:scale-110 transition-transform">
                  <BarChart3 className="h-6 w-6 text-white" />
                </div>
                <div className="flex items-center gap-1 text-orange-600 text-sm font-medium">
                  <ArrowUp className="w-4 h-4" />
                  24%
                </div>
              </div>
              <div>
                <div className="text-3xl font-bold text-orange-600">{stats.recentActivity}</div>
                <p className="text-gray-600">Activité récente</p>
                <p className="text-sm text-gray-500 mt-1">Dernières 24h</p>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <motion.div variants={itemVariants} className="lg:col-span-2">
            <Card className="border-0 shadow-lg">
              <CardHeader className="pb-4">
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-xl font-semibold">Tendances des API</CardTitle>
                    <CardDescription>Appels et requêtes sur les 7 derniers jours</CardDescription>
                  </div>
                  <Button variant="ghost" size="sm">
                    <MoreHorizontal className="w-4 h-4" />
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="p-6">
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={apiCallsData}>
                    <defs>
                      <linearGradient id="colorCalls" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#10b981" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                    <XAxis dataKey="name" stroke="#888" />
                    <YAxis stroke="#888" />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#fff', border: '1px solid #e5e7eb', borderRadius: '8px' }}
                      labelStyle={{ color: '#111827', fontWeight: 'bold' }}
                    />
                    <Area type="monotone" dataKey="calls" stroke="#3b82f6" fillOpacity={1} fill="url(#colorCalls)" strokeWidth={2} />
                    <Area type="monotone" dataKey="requests" stroke="#10b981" fillOpacity={1} fill="url(#colorRequests)" strokeWidth={2} />
                    <Legend />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div variants={itemVariants}>
            <Card className="border-0 shadow-lg">
              <CardHeader className="pb-4">
                <div>
                  <CardTitle className="text-xl font-semibold">Répartition des clés</CardTitle>
                  <CardDescription>Par catégorie</CardDescription>
                </div>
              </CardHeader>
              <CardContent className="p-6">
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={categoryData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {categoryData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </motion.div>
        </div>

        {/* System Metrics */}
        <motion.div variants={itemVariants}>
          <Card className="border-0 shadow-lg">
            <CardHeader className="pb-4">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-xl font-semibold">Métriques système</CardTitle>
                  <CardDescription>Performance en temps réel</CardDescription>
                </div>
                <Badge variant="outline" className="gap-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  En ligne
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {systemMetrics.map((metric, index) => (
                  <div key={metric.name} className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {metric.name === 'CPU' && <Cpu className="w-4 h-4 text-gray-600" />}
                        {metric.name === 'Mémoire' && <Server className="w-4 h-4 text-gray-600" />}
                        {metric.name === 'Stockage' && <HardDrive className="w-4 h-4 text-gray-600" />}
                        {metric.name === 'Réseau' && <Wifi className="w-4 h-4 text-gray-600" />}
                        <span className="font-medium text-gray-900">{metric.name}</span>
                      </div>
                      <Badge className={getMetricColor(metric.status)}>
                        {metric.value}{metric.unit}
                      </Badge>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className={`h-2 rounded-full transition-all duration-500 ${
                          metric.status === 'good' ? 'bg-green-500' :
                          metric.status === 'warning' ? 'bg-yellow-500' :
                          'bg-red-500'
                        }`}
                        style={{ width: `${metric.value}%` }}
                      ></div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Recent Activity */}
        <motion.div variants={itemVariants}>
          <Card className="border-0 shadow-lg">
            <CardHeader className="pb-4">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-xl font-semibold">Activité récente</CardTitle>
                  <CardDescription>Dernières opérations et événements système</CardDescription>
                </div>
                <Button variant="outline" size="sm">
                  Voir tout
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-6">
              <div className="space-y-4">
                <AnimatePresence>
                  {activities.slice(0, 6).map((activity, index) => (
                    <motion.div
                      key={activity.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: 20 }}
                      transition={{ delay: index * 0.1 }}
                      className="flex items-center justify-between p-4 rounded-xl hover:bg-gray-50 transition-colors"
                    >
                      <div className="flex items-center gap-4">
                        <div className={`w-3 h-3 rounded-full ${
                          activity.type === 'success' ? 'bg-green-500' :
                          activity.type === 'warning' ? 'bg-yellow-500' :
                          activity.type === 'error' ? 'bg-red-500' :
                          'bg-blue-500'
                        }`}></div>
                        <div>
                          <p className="font-medium text-gray-900">{activity.action}</p>
                          <p className="text-sm text-gray-600">{activity.entity}</p>
                          {activity.user && (
                            <p className="text-xs text-gray-500">par {activity.user}</p>
                          )}
                        </div>
                      </div>
                      <div className="text-right">
                        <span className="text-sm text-gray-500">{activity.time}</span>
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>
    </DashboardPageLayout>
  );
}