import { Request, Response, NextFunction } from 'express';
import { unifiedAuthService } from '../services/unifiedAuthService';

// Middleware pour authentifier les requêtes avec JWT
export async function authenticateToken(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access token is required'
      });
    }

    // Valider le token et obtenir les informations utilisateur
    const user = await unifiedAuthService.validateAccessToken(token);
    
    // Ajouter les informations utilisateur à la requête
    (req as any).user = user;
    (req as any).token = token;
    
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired access token'
    });
  }
}

// Middleware pour vérifier les permissions spécifiques
export function requirePermission(permission: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as any).user;
      
      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Obtenir les permissions de l'utilisateur
      const permissions = await unifiedAuthService.getUserPermissions(user.sub);
      
      // Vérifier si l'utilisateur a la permission requise
      const hasPermission = permissions.permissions.includes(permission) ||
                           permissions.permissions.includes('*') ||
                           permissions.roles.includes('owner') ||
                           permissions.roles.includes('admin');

      if (!hasPermission) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions',
          required: permission
        });
      }

      // Ajouter les permissions à la requête pour usage ultérieur
      (req as any).permissions = permissions;
      
      next();
    } catch (error) {
      console.error('Permission check error:', error);
      return res.status(500).json({
        success: false,
        error: 'Permission check failed'
      });
    }
  };
}

// Middleware pour vérifier l'accès à un service spécifique
export function requireServiceAccess(serviceId: string, action: string = 'access') {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as any).user;
      
      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Vérifier l'accès au service
      const access = await unifiedAuthService.checkServiceAccess(user.sub, serviceId);
      
      if (!access.hasAccess) {
        return res.status(403).json({
          success: false,
          error: 'Access denied to service',
          service: serviceId,
          action
        });
      }

      // Vérifier si l'action spécifique est permise
      const requiredPermission = `service:${serviceId}:${action}`;
      const hasActionPermission = access.permissions.includes(requiredPermission) ||
                                 access.permissions.includes(`service:${serviceId}:*`) ||
                                 access.permissions.includes('service:*');

      if (!hasActionPermission) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions for action',
          service: serviceId,
          action,
          required: requiredPermission
        });
      }

      // Ajouter les informations d'accès à la requête
      (req as any).serviceAccess = access;
      
      next();
    } catch (error) {
      console.error('Service access check error:', error);
      return res.status(500).json({
        success: false,
        error: 'Service access check failed'
      });
    }
  };
}

// Middleware pour vérifier l'accès à une application spécifique
export function requireApplicationAccess(applicationId: string, action: string = 'access') {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as any).user;
      
      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Vérifier l'accès à l'application
      const access = await unifiedAuthService.checkApplicationAccess(user.sub, applicationId);
      
      if (!access.hasAccess) {
        return res.status(403).json({
          success: false,
          error: 'Access denied to application',
          application: applicationId,
          action
        });
      }

      // Vérifier si l'action spécifique est permise
      const requiredPermission = `app:${applicationId}:${action}`;
      const hasActionPermission = access.permissions.includes(requiredPermission) ||
                                 access.permissions.includes(`app:${applicationId}:*`) ||
                                 access.permissions.includes('app:*');

      if (!hasActionPermission) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions for action',
          application: applicationId,
          action,
          required: requiredPermission
        });
      }

      // Ajouter les informations d'accès à la requête
      (req as any).applicationAccess = access;
      
      next();
    } catch (error) {
      console.error('Application access check error:', error);
      return res.status(500).json({
        success: false,
        error: 'Application access check failed'
      });
    }
  };
}

// Middleware pour vérifier les rôles
export function requireRole(role: string | string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as any).user;
      
      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      const permissions = await unifiedAuthService.getUserPermissions(user.sub);
      
      const requiredRoles = Array.isArray(role) ? role : [role];
      const hasRole = requiredRoles.some(r => permissions.roles.includes(r));

      if (!hasRole) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient role privileges',
          required: requiredRoles,
          current: permissions.roles
        });
      }

      // Ajouter les permissions à la requête
      (req as any).permissions = permissions;
      
      next();
    } catch (error) {
      console.error('Role check error:', error);
      return res.status(500).json({
        success: false,
        error: 'Role check failed'
      });
    }
  };
}

// Middleware optionnel pour l'authentification (ne retourne pas d'erreur si non authentifié)
export async function optionalAuth(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      try {
        const user = await unifiedAuthService.validateAccessToken(token);
        (req as any).user = user;
        (req as any).token = token;
        (req as any).isAuthenticated = true;
      } catch (error) {
        // Token invalide, mais on continue sans authentification
        (req as any).isAuthenticated = false;
      }
    } else {
      (req as any).isAuthenticated = false;
    }
    
    next();
  } catch (error) {
    // En cas d'erreur, on continue sans authentification
    (req as any).isAuthenticated = false;
    next();
  }
}

// Middleware pour limiter le taux de requêtes par utilisateur
export function createUserRateLimit(maxRequests: number, windowMs: number) {
  const requests = new Map<string, { count: number; resetTime: number }>();

  return (req: Request, _res: Response, next: NextFunction) => {
    const user = (req as any).user;
    
    if (!user) {
      // Si pas d'utilisateur, appliquer une limite générale
      return next();
    }

    const userId = user.sub;
    const now = Date.now();
    const userRequests = requests.get(userId);

    if (!userRequests || now > userRequests.resetTime) {
      // Nouvelle fenêtre de temps
      requests.set(userId, {
        count: 1,
        resetTime: now + windowMs
      });
      return next();
    }

    if (userRequests.count >= maxRequests) {
      return _res.status(429).json({
        success: false,
        error: 'Too many requests',
        retryAfter: Math.ceil((userRequests.resetTime - now) / 1000)
      });
    }

    userRequests.count++;
    next();
  };
}