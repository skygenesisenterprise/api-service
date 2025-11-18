import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient({
  datasources: {
    db: {
      url: 'file:../prisma/dev.db',
    },
  },
});

export interface DashboardStats {
  totalUsers: number;
  activeUsers: number;
  totalApiKeys: number;
  activeApiKeys: number;
  totalOrganizations: number;
  recentLogins: number;
  systemHealth: 'healthy' | 'warning' | 'error';
  apiCallsToday: number;
  storageUsed: number;
  storageTotal: number;
}

export interface ActivityItem {
  id: string;
  action: string;
  entity: string;
  time: string;
  type: 'success' | 'warning' | 'error' | 'info';
  user?: string;
}

export interface SystemMetric {
  name: string;
  value: number;
  status: 'good' | 'warning' | 'critical';
  unit: string;
}

export class DashboardService {
  async getDashboardStats(): Promise<DashboardStats> {
    const [
      totalUsers,
      activeUsers,
      totalApiKeys,
      activeApiKeys,
      totalOrganizations,
      recentLogins
    ] = await Promise.all([
      prisma.user.count(),
      prisma.user.count({ where: { isActive: true } }),
      prisma.apiKey.count(),
      prisma.apiKey.count({ where: { isActive: true } }),
      prisma.organization.count(),
      this.getRecentLoginsCount()
    ]);

    return {
      totalUsers,
      activeUsers,
      totalApiKeys,
      activeApiKeys,
      totalOrganizations,
      recentLogins,
      systemHealth: 'healthy',
      apiCallsToday: await this.getApiCallsToday(),
      storageUsed: await this.getStorageUsed(),
      storageTotal: 100 // MB
    };
  }

  async getRecentActivities(limit: number = 10): Promise<ActivityItem[]> {
    const recentApiKeys = await prisma.apiKey.findMany({
      take: limit,
      orderBy: { createdAt: 'desc' },
      include: {
        organization: {
          select: { name: true }
        }
      }
    });

    const recentUsers = await prisma.user.findMany({
      take: limit,
      orderBy: { createdAt: 'desc' },
      include: {
        organization: {
          select: { name: true }
        }
      }
    });

    const activities: ActivityItem[] = [];

    // Ajouter les activités des clés API
    recentApiKeys.forEach(key => {
      activities.push({
        id: `key-${key.id}`,
        action: 'Clé API Créée',
        entity: key.name,
        time: this.formatDate(key.createdAt),
        type: 'success',
        user: key.organization?.name
      });
    });

    // Ajouter les activités des utilisateurs
    recentUsers.forEach(user => {
      activities.push({
        id: `user-${user.id}`,
        action: 'Utilisateur Inscrit',
        entity: user.email,
        time: this.formatDate(user.createdAt),
        type: 'info',
        user: user.fullName || user.email
      });
    });

    return activities.slice(0, limit);
  }

  async getSystemMetrics(): Promise<SystemMetric[]> {
    return [
      { name: 'CPU', value: 45, status: 'good', unit: '%' },
      { name: 'Mémoire', value: 62, status: 'good', unit: '%' },
      { name: 'Stockage', value: 78, status: 'warning', unit: '%' },
      { name: 'Réseau', value: 23, status: 'good', unit: 'Mbps' }
    ];
  }

  async getApiCallsData(days: number = 7) {
    // Simuler des données d'appels API sur les derniers jours
    const data = [];
    const now = new Date();
    
    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
      const dayName = this.getDayName(date);
      const calls = Math.floor(Math.random() * 5000) + 1000;
      const requests = Math.floor(Math.random() * 3000) + 1000;
      
      data.push({ name: dayName, calls, requests });
    }
    
    return data;
  }

  async getApiKeysByType() {
    const [clientKeys, serverKeys, databaseKeys] = await Promise.all([
      prisma.apiKey.count({ where: { category: 'client' } }),
      prisma.apiKey.count({ where: { category: 'server' } }),
      prisma.apiKey.count({ where: { category: 'database' } })
    ]);

    return [
      { name: 'Client', value: clientKeys, color: '#3b82f6' },
      { name: 'Serveur', value: serverKeys, color: '#10b981' },
      { name: 'Base de données', value: databaseKeys, color: '#f59e0b' }
    ];
  }

  private async getRecentLoginsCount(): Promise<number> {
    // Pour l'instant, retourner un nombre simulé
    // Dans une vraie implémentation, cela viendrait des logs de connexion
    return Math.floor(Math.random() * 50) + 10;
  }

  private async getApiCallsToday(): Promise<number> {
    // Simuler le nombre d'appels API aujourd'hui
    return Math.floor(Math.random() * 10000) + 2000;
  }

  private async getStorageUsed(): Promise<number> {
    // Simuler l'utilisation du stockage
    return Math.floor(Math.random() * 80) + 10;
  }

  private formatDate(date: Date): string {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / (1000 * 60));
    
    if (diffMins < 60) {
      return `Il y a ${diffMins} minute${diffMins > 1 ? 's' : ''}`;
    } else if (diffMins < 1440) {
      const hours = Math.floor(diffMins / 60);
      return `Il y a ${hours} heure${hours > 1 ? 's' : ''}`;
    } else {
      const days = Math.floor(diffMins / 1440);
      return `Il y a ${days} jour${days > 1 ? 's' : ''}`;
    }
  }

  private getDayName(date: Date): string {
    const days = ['Dim', 'Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam'];
    return days[date.getDay()];
  }
}