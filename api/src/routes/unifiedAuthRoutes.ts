import { Request, Response, Router } from 'express';
import { UnifiedAuthController, AccessController } from '../controllers/unifiedAuthController';
import { authenticateToken, requirePermission, requireServiceAccess, requireApplicationAccess, requireRole } from '../middlewares/auth';

const router = Router();

// ========================================
// ROUTES D'AUTHENTIFICATION UNIFIÉE
// ========================================

// Connexion principale (accepte email, username, ou téléphone)
router.post('/auth/login', UnifiedAuthController.login);

// Rafraîchir le token d'accès
router.post('/auth/refresh', UnifiedAuthController.refreshToken);

// Déconnexion
router.post('/auth/logout', UnifiedAuthController.logout);

// Valider un token
router.get('/auth/validate', UnifiedAuthController.validateToken);

// Obtenir les permissions de l'utilisateur courant
router.get('/auth/permissions', authenticateToken, UnifiedAuthController.getPermissions);

// ========================================
// ROUTES DE VÉRIFICATION D'ACCÈS
// ========================================

// Vérifier l'accès à un service spécifique
router.get('/access/services/:serviceId', authenticateToken, AccessController.checkServiceAccess);

// Vérifier l'accès à une application spécifique
router.get('/access/applications/:applicationId', authenticateToken, AccessController.checkApplicationAccess);

// Lister tous les services accessibles
router.get('/access/services', authenticateToken, AccessController.listAccessibleServices);

// Lister toutes les applications accessibles
router.get('/access/applications', authenticateToken, AccessController.listAccessibleApplications);

// ========================================
// EXEMPLES DE ROUTES PROTÉGÉES
// ========================================

// Route protégée nécessitant une authentification simple
router.get('/protected/profile', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'Access granted to protected resource',
    user: (req as any).user
  });
});

// Route protégée nécessitant une permission spécifique
router.get('/protected/admin', 
  authenticateToken, 
  requirePermission('admin:access'), 
  (req, res) => {
    res.json({
      success: true,
      message: 'Access granted to admin resource',
      permissions: (req as any).permissions
    });
  }
);

// Route protégée nécessitant l'accès à un service spécifique
router.get('/protected/logs', 
  authenticateToken, 
  requireServiceAccess('logs', 'read'), 
  (req, res) => {
    res.json({
      success: true,
      message: 'Access granted to logs service',
      serviceAccess: (req as any).serviceAccess
    });
  }
);

// Route protégée nécessitant l'accès à une application spécifique
router.get('/protected/admin-console', 
  authenticateToken, 
  requireApplicationAccess('admin-console', 'access'), 
  (req, res) => {
    res.json({
      success: true,
      message: 'Access granted to admin console',
      applicationAccess: (req as any).applicationAccess
    });
  }
);

// Route protégée nécessitant un rôle spécifique
router.get('/protected/owner-only', 
  authenticateToken, 
  requireRole(['owner', 'admin']), 
  (req, res) => {
    res.json({
      success: true,
      message: 'Access granted to owner/admin resource',
      permissions: (req as any).permissions
    });
  }
);

// Route avec permissions multiples
router.delete('/protected/users/:userId', 
  authenticateToken, 
  requirePermission('user:delete'), 
  requireRole('admin'), 
  (req, res) => {
    res.json({
      success: true,
      message: 'User deletion access granted'
    });
  }
);

// ========================================
// ROUTES DE GESTION DES UTILISATEURS
// ========================================

// Obtenir le profil de l'utilisateur courant
router.get('/users/me', authenticateToken, async (req, res) => {
  try {
    const user = (req as any).user;
    const permissions = (req as any).permissions;
    
    res.json({
      success: true,
      data: {
        user,
        permissions
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch user profile'
    });
  }
});

// Mettre à jour le profil de l'utilisateur courant
router.put('/users/me', authenticateToken, async (req, res) => {
  try {
    const { profile, preferences } = req.body;
    const userId = (req as any).user.sub;
    
    // TODO: Implémenter la mise à jour du profil dans la base de données
    
    res.json({
      success: true,
      message: 'Profile updated successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to update profile'
    });
  }
});

// ========================================
// ROUTES DE TEST DES PERMISSIONS
// ========================================

// Endpoint de test pour vérifier les permissions
router.post('/test/permissions', authenticateToken, async (req, res) => {
  try {
    const { permissions: testPermissions, services: testServices, applications: testApplications } = req.body;
    const userId = (req as any).user.sub;
    
    // TODO: Implémenter les tests de permissions
    
    res.json({
      success: true,
      message: 'Permission tests completed',
      data: {
        testedPermissions: testPermissions,
        testedServices: testServices,
        testedApplications: testApplications
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Permission test failed'
    });
  }
});

export default router;