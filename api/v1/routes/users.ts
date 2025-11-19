import { Router } from 'express';
import { UnifiedUserController } from '../../src/controllers/unifiedUserController';
import { authenticateToken, requirePermission, requireRole } from '../../src/middlewares/auth';

const router = Router();

// ========================================
// ROUTES DE GESTION DES UTILISATEURS
// ========================================

// Créer un nouvel utilisateur (admin/owner seulement)
router.post('/users', 
  authenticateToken, 
  requireRole(['admin', 'owner']), 
  UnifiedUserController.createUser
);

// Obtenir un utilisateur par ID
router.get('/users/:id', 
  authenticateToken, 
  UnifiedUserController.getUser
);

// Mettre à jour un utilisateur
router.put('/users/:id', 
  authenticateToken, 
  UnifiedUserController.updateUser
);

// Supprimer un utilisateur (admin/owner seulement)
router.delete('/users/:id', 
  authenticateToken, 
  requireRole(['admin', 'owner']), 
  UnifiedUserController.deleteUser
);

// ========================================
// ROUTES DES ORGANISATIONS DES UTILISATEURS
// ========================================

// Lister les organisations d'un utilisateur
router.get('/users/:id/organizations', 
  authenticateToken, 
  UnifiedUserController.getUserOrganizations
);

// Ajouter un utilisateur à une organisation
router.post('/users/:id/organizations', 
  authenticateToken, 
  requirePermission('organization:manage'), 
  UnifiedUserController.addToOrganization
);

// Mettre à jour le membership d'une organisation
router.put('/users/:id/organizations/:organizationId', 
  authenticateToken, 
  requirePermission('organization:manage'), 
  UnifiedUserController.updateOrganizationMembership
);

// Retirer un utilisateur d'une organisation
router.delete('/users/:id/organizations/:organizationId', 
  authenticateToken, 
  UnifiedUserController.removeFromOrganization
);

// ========================================
// ROUTES DE GESTION DES MOTS DE PASSE
// ========================================

// Changer le mot de passe
router.post('/users/:id/change-password', 
  authenticateToken, 
  UnifiedUserController.changePassword
);

// Réinitialiser le mot de passe (public)
router.post('/users/reset-password', 
  UnifiedUserController.resetPassword
);

// ========================================
// ROUTES DE GESTION DES IDENTIFIANTS
// ========================================

// Ajouter un identifiant à un utilisateur
router.post('/users/:id/identifiers', 
  authenticateToken, 
  requirePermission('user:write'), 
  async (req, res) => {
    try {
      const { type, value, provider, providerId, isPrimary } = req.body;
      const userId = req.params.id;
      const currentUser = (req as any).user;

      // L'utilisateur peut modifier ses propres identifiants
      const canModify = currentUser.sub === userId || 
                       currentUser.roles?.includes('admin') || 
                       currentUser.roles?.includes('owner');

      if (!canModify) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions to modify user identifiers'
        });
      }

      // TODO: Implémenter l'ajout d'identifiant
      res.json({
        success: true,
        message: 'Identifier added successfully',
        data: { type, value, message: 'TODO: implement' }
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Failed to add identifier'
      });
    }
  }
);

// ========================================
// ROUTES DE RECHERCHE D'UTILISATEURS
// ========================================

// Rechercher des utilisateurs (admin seulement)
router.get('/users/search/:query', 
  authenticateToken, 
  requireRole(['admin', 'owner']), 
  async (req, res) => {
    try {
      const { query } = req.params;
      const { limit = 20, offset = 0 } = req.query;

      // TODO: Implémenter la recherche d'utilisateurs
      res.json({
        success: true,
        data: {
          users: [],
          total: 0,
          query,
          limit,
          offset
        }
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Failed to search users'
      });
    }
  }
);

// Lister les utilisateurs d'une organisation
router.get('/organizations/:organizationId/users', 
  authenticateToken, 
  requirePermission('organization:read'), 
  async (req, res) => {
    try {
      const { organizationId } = req.params;
      const { limit = 50, offset = 0, role, status } = req.query;

      // TODO: Implémenter la liste des utilisateurs d'une organisation
      res.json({
        success: true,
        data: {
          users: [],
          total: 0,
          organizationId,
          filters: { limit, offset, role, status }
        }
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Failed to fetch organization users'
      });
    }
  }
);

// ========================================
// ROUTES DE STATISTIQUES
// ========================================

// Obtenir les statistiques des utilisateurs (admin seulement)
router.get('/users/stats', 
  authenticateToken, 
  requireRole(['admin', 'owner']), 
  async (req, res) => {
    try {
      // TODO: Implémenter les statistiques
      res.json({
        success: true,
        data: {
          totalUsers: 0,
          activeUsers: 0,
          newUsersToday: 0,
          usersByRole: {},
          usersByStatus: {},
          usersByOrganization: {}
        }
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Failed to fetch user statistics'
      });
    }
  }
);

// ========================================
// ROUTES DE VALIDATION
// ========================================

// Vérifier si un identifiant est disponible
router.get('/users/check-availability/:type/:value', 
  authenticateToken, 
  async (req, res) => {
    try {
      const { type, value } = req.params;

      // TODO: Implémenter la vérification de disponibilité
      res.json({
        success: true,
        data: {
          type,
          value,
          available: true,
          message: 'TODO: implement availability check'
        }
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Failed to check availability'
      });
    }
  }
);

// Valider un identifiant (email, phone)
router.post('/users/validate-identifier', 
  authenticateToken, 
  async (req, res) => {
    try {
      const { type, value } = req.body;

      // TODO: Implémenter la validation (envoyer code de confirmation)
      res.json({
        success: true,
        message: 'Validation code sent',
        data: {
          type,
          value: value.replace(/(.{2}).*(@.*)/, '$1***$2'), // Masquer l'email
          message: 'TODO: implement validation'
        }
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Failed to send validation code'
      });
    }
  }
);

// Confirmer un identifiant avec code
router.post('/users/confirm-identifier', 
  authenticateToken, 
  async (req, res) => {
    try {
      const { type, value, code } = req.body;

      // TODO: Implémenter la confirmation du code
      res.json({
        success: true,
        message: 'Identifier validated successfully',
        data: {
          type,
          value,
          message: 'TODO: implement confirmation'
        }
      });

    } catch (error) {
      res.status(400).json({
        success: false,
        error: 'Invalid or expired validation code'
      });
    }
  }
);

export default router;