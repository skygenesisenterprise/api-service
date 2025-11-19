import { Request, Response } from 'express';
import { unifiedAuthService, AuthCredentials } from '../services/unifiedAuthService';

// Contrôleur pour l'authentification unifiée
export class UnifiedAuthController {
  // Endpoint de connexion principal
  static async login(req: Request, res: Response) {
    try {
      const { identifier, password, deviceInfo } = req.body as AuthCredentials;

      if (!identifier || !password) {
        return res.status(400).json({
          success: false,
          error: 'Identifier and password are required'
        });
      }

      const result = await unifiedAuthService.authenticate({
        identifier,
        password,
        deviceInfo: deviceInfo || {
          userAgent: req.get('User-Agent'),
          ip: req.ip,
          timestamp: new Date().toISOString()
        }
      });

      if (result.success) {
        res.json({
          success: true,
          data: {
            user: result.user,
            token: result.token,
            refreshToken: result.refreshToken,
            session: result.session
          }
        });
      } else {
        res.status(401).json({
          success: false,
          error: result.error
        });
      }
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  // Rafraîchir le token
  static async refreshToken(req: Request, res: Response) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({
          success: false,
          error: 'Refresh token is required'
        });
      }

      const result = await unifiedAuthService.refreshToken(refreshToken);

      if (result.success) {
        res.json({
          success: true,
          data: {
            user: result.user,
            token: result.token,
            refreshToken: result.refreshToken
          }
        });
      } else {
        res.status(401).json({
          success: false,
          error: result.error
        });
      }
    } catch (error) {
      console.error('Token refresh error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  // Déconnexion
  static async logout(req: Request, res: Response) {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        return res.status(400).json({
          success: false,
          error: 'Token is required'
        });
      }

      // TODO: Implémenter la révocation du token
      // Pour l'instant, on retourne succès
      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  // Valider un token
  static async validateToken(req: Request, res: Response) {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        return res.status(400).json({
          success: false,
          error: 'Token is required'
        });
      }

      const result = await unifiedAuthService.validateAccessToken(token);
      
      res.json({
        success: true,
        data: {
          valid: true,
          user: result.user,
          expiresAt: result.exp
        }
      });
    } catch (error) {
      res.status(401).json({
        success: false,
        error: 'Invalid or expired token',
        valid: false
      });
    }
  }

  // Obtenir les permissions de l'utilisateur courant
  static async getPermissions(req: Request, res: Response) {
    try {
      const user = (req as any).user; // Injecté par le middleware
      
      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'User not authenticated'
        });
      }

      const permissions = await unifiedAuthService.getUserPermissions(user.sub);
      
      res.json({
        success: true,
        data: permissions
      });
    } catch (error) {
      console.error('Get permissions error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }
}

// Contrôleur pour la gestion des accès aux services
export class AccessController {
  // Vérifier l'accès à un service spécifique
  static async checkServiceAccess(req: Request, res: Response) {
    try {
      const user = (req as any).user;
      const { serviceId } = req.params;

      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'User not authenticated'
        });
      }

      if (!serviceId) {
        return res.status(400).json({
          success: false,
          error: 'Service ID is required'
        });
      }

      const access = await unifiedAuthService.checkServiceAccess(user.sub, serviceId);
      
      res.json({
        success: true,
        data: access
      });
    } catch (error) {
      console.error('Check service access error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  // Vérifier l'accès à une application spécifique
  static async checkApplicationAccess(req: Request, res: Response) {
    try {
      const user = (req as any).user;
      const { applicationId } = req.params;

      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'User not authenticated'
        });
      }

      if (!applicationId) {
        return res.status(400).json({
          success: false,
          error: 'Application ID is required'
        });
      }

      const access = await unifiedAuthService.checkApplicationAccess(user.sub, applicationId);
      
      res.json({
        success: true,
        data: access
      });
    } catch (error) {
      console.error('Check application access error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  // Lister tous les services accessibles
  static async listAccessibleServices(req: Request, res: Response) {
    try {
      const user = (req as any).user;

      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'User not authenticated'
        });
      }

      const permissions = await unifiedAuthService.getUserPermissions(user.sub);
      
      // TODO: Récupérer la liste réelle des services depuis la base de données
      const availableServices = [
        { id: 'logs', name: 'Log Management', description: 'View and analyze system logs' },
        { id: 'dashboard', name: 'Dashboard', description: 'Main dashboard and analytics' },
        { id: 'api-gateway', name: 'API Gateway', description: 'API management and monitoring' },
        { id: 'user-management', name: 'User Management', description: 'Manage users and permissions' },
        { id: 'billing', name: 'Billing', description: 'Billing and subscription management' },
        { id: 'analytics', name: 'Analytics', description: 'Advanced analytics and reporting' },
        { id: 'monitoring', name: 'Monitoring', description: 'System monitoring and alerts' },
        { id: 'security', name: 'Security', description: 'Security settings and audit logs' }
      ];

      const accessibleServices = availableServices.filter(service => 
        permissions.services.includes(service.id) || 
        permissions.services.includes('*')
      ).map(service => ({
        ...service,
        permissions: permissions.permissions.filter(p => 
          p.includes(`service:${service.id}`) || p.startsWith('service:')
        )
      }));

      res.json({
        success: true,
        data: {
          services: accessibleServices,
          total: accessibleServices.length
        }
      });
    } catch (error) {
      console.error('List accessible services error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  // Lister toutes les applications accessibles
  static async listAccessibleApplications(req: Request, res: Response) {
    try {
      const user = (req as any).user;

      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'User not authenticated'
        });
      }

      const permissions = await unifiedAuthService.getUserPermissions(user.sub);
      
      // TODO: Récupérer la liste réelle des applications depuis la base de données
      const availableApplications = [
        { id: 'admin-console', name: 'Admin Console', description: 'Main administration interface' },
        { id: 'customer-portal', name: 'Customer Portal', description: 'Customer-facing portal' },
        { id: 'developer-api', name: 'Developer API', description: 'API documentation and testing' },
        { id: 'mobile-app', name: 'Mobile Application', description: 'Mobile application access' },
        { id: 'partner-portal', name: 'Partner Portal', description: 'Partner management portal' },
        { id: 'reporting', name: 'Reporting', description: 'Advanced reporting and BI' }
      ];

      const accessibleApplications = availableApplications.filter(app => 
        permissions.applications.includes(app.id) || 
        permissions.applications.includes('*')
      ).map(app => ({
        ...app,
        role: permissions.roles.find(r => r !== 'member') || 'user',
        permissions: permissions.permissions.filter(p => 
          p.includes(`app:${app.id}`) || p.startsWith('app:')
        )
      }));

      res.json({
        success: true,
        data: {
          applications: accessibleApplications,
          total: accessibleApplications.length
        }
      });
    } catch (error) {
      console.error('List accessible applications error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }
}