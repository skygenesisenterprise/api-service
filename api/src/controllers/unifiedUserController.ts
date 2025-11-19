import { Request, Response } from 'express';
import { unifiedUserService, CreateUserData, UpdateUserData, OrganizationMembership } from '../services/unifiedUserService';
import { authenticateToken, requirePermission, requireRole } from '../middlewares/auth';

// Contrôleur pour la gestion des utilisateurs unifiés
export class UnifiedUserController {
  // Créer un nouvel utilisateur
  static async createUser(req: Request, res: Response) {
    try {
      const userData: CreateUserData = req.body;
      const currentUser = (req as any).user;

      // Vérifier les permissions
      if (!currentUser) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Seuls les admins et owners peuvent créer des utilisateurs
      const userRole = currentUser.roles?.includes('admin') || currentUser.roles?.includes('owner');
      if (!userRole) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions to create users'
        });
      }

      // Valider les données
      if (!userData.primaryEmail || !userData.password) {
        return res.status(400).json({
          success: false,
          error: 'Primary email and password are required'
        });
      }

      if (userData.password.length < 8) {
        return res.status(400).json({
          success: false,
          error: 'Password must be at least 8 characters long'
        });
      }

      const user = await unifiedUserService.createUser(userData);

      res.status(201).json({
        success: true,
        data: user,
        message: 'User created successfully'
      });

    } catch (error) {
      console.error('Create user error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to create user'
      });
    }
  }

  // Obtenir un utilisateur par ID
  static async getUser(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const currentUser = (req as any).user;

      if (!currentUser) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // L'utilisateur peut voir son propre profil ou les autres s'il est admin
      const canView = currentUser.sub === id || 
                     currentUser.roles?.includes('admin') || 
                     currentUser.roles?.includes('owner');

      if (!canView) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions to view this user'
        });
      }

      // TODO: Implémenter getUserById dans le service
      res.json({
        success: true,
        data: { id, message: 'User details - TODO: implement' }
      });

    } catch (error) {
      console.error('Get user error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to fetch user'
      });
    }
  }

  // Mettre à jour un utilisateur
  static async updateUser(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const updateData: UpdateUserData = req.body;
      const currentUser = (req as any).user;

      if (!currentUser) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // L'utilisateur peut mettre à jour son propre profil ou les autres s'il est admin
      const canUpdate = currentUser.sub === id || 
                       currentUser.roles?.includes('admin') || 
                       currentUser.roles?.includes('owner');

      if (!canUpdate) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions to update this user'
        });
      }

      const updatedUser = await unifiedUserService.updateUser(id, updateData);

      res.json({
        success: true,
        data: updatedUser,
        message: 'User updated successfully'
      });

    } catch (error) {
      console.error('Update user error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to update user'
      });
    }
  }

  // Supprimer un utilisateur
  static async deleteUser(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const currentUser = (req as any).user;

      if (!currentUser) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Seuls les admins et owners peuvent supprimer des utilisateurs
      const canDelete = currentUser.roles?.includes('admin') || 
                       currentUser.roles?.includes('owner');

      if (!canDelete) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions to delete users'
        });
      }

      // Empêcher l'auto-suppression
      if (currentUser.sub === id) {
        return res.status(400).json({
          success: false,
          error: 'Cannot delete your own account'
        });
      }

      await unifiedUserService.deleteUser(id);

      res.json({
        success: true,
        message: 'User deleted successfully'
      });

    } catch (error) {
      console.error('Delete user error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to delete user'
      });
    }
  }

  // Lister les organisations d'un utilisateur
  static async getUserOrganizations(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const currentUser = (req as any).user;

      if (!currentUser) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // L'utilisateur peut voir ses propres organisations ou celles des autres s'il est admin
      const canView = currentUser.sub === id || 
                     currentUser.roles?.includes('admin') || 
                     currentUser.roles?.includes('owner');

      if (!canView) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions to view user organizations'
        });
      }

      const organizations = await unifiedUserService.getUserOrganizations(id);

      res.json({
        success: true,
        data: organizations
      });

    } catch (error) {
      console.error('Get user organizations error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to fetch user organizations'
      });
    }
  }

  // Ajouter un utilisateur à une organisation
  static async addToOrganization(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const membershipData: OrganizationMembership = req.body;
      const currentUser = (req as any).user;

      if (!currentUser) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Vérifier si l'utilisateur actuel peut gérer cette organisation
      const canManage = currentUser.roles?.includes('admin') || 
                       currentUser.roles?.includes('owner') ||
                       currentUser.permissions?.includes(`organization:${membershipData.organizationId}:manage`);

      if (!canManage) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions to manage organization members'
        });
      }

      const membership = await unifiedUserService.addUserToOrganization(id, membershipData.organizationId, membershipData);

      res.status(201).json({
        success: true,
        data: membership,
        message: 'User added to organization successfully'
      });

    } catch (error) {
      console.error('Add to organization error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to add user to organization'
      });
    }
  }

  // Mettre à jour le membership d'une organisation
  static async updateOrganizationMembership(req: Request, res: Response) {
    try {
      const { id, organizationId } = req.params;
      const updates = req.body;
      const currentUser = (req as any).user;

      if (!currentUser) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Vérifier les permissions
      const canManage = currentUser.roles?.includes('admin') || 
                       currentUser.roles?.includes('owner') ||
                       currentUser.permissions?.includes(`organization:${organizationId}:manage`);

      if (!canManage) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions to manage organization members'
        });
      }

      const membership = await unifiedUserService.updateOrganizationMembership(id, organizationId, updates);

      res.json({
        success: true,
        data: membership,
        message: 'Organization membership updated successfully'
      });

    } catch (error) {
      console.error('Update membership error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to update membership'
      });
    }
  }

  // Retirer un utilisateur d'une organisation
  static async removeFromOrganization(req: Request, res: Response) {
    try {
      const { id, organizationId } = req.params;
      const currentUser = (req as any).user;

      if (!currentUser) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Vérifier les permissions (ou auto-suppression)
      const canRemove = currentUser.sub === id || // L'utilisateur peut se retirer lui-même
                       currentUser.roles?.includes('admin') || 
                       currentUser.roles?.includes('owner') ||
                       currentUser.permissions?.includes(`organization:${organizationId}:manage`);

      if (!canRemove) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions to remove user from organization'
        });
      }

      await unifiedUserService.removeFromOrganization(id, organizationId);

      res.json({
        success: true,
        message: 'User removed from organization successfully'
      });

    } catch (error) {
      console.error('Remove from organization error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to remove user from organization'
      });
    }
  }

  // Changer le mot de passe
  static async changePassword(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const { currentPassword, newPassword } = req.body;
      const currentUser = (req as any).user;

      if (!currentUser) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // L'utilisateur peut changer son propre mot de passe
      const canChange = currentUser.sub === id || 
                       currentUser.roles?.includes('admin') || 
                       currentUser.roles?.includes('owner');

      if (!canChange) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions to change password'
        });
      }

      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          success: false,
          error: 'Current password and new password are required'
        });
      }

      if (newPassword.length < 8) {
        return res.status(400).json({
          success: false,
          error: 'New password must be at least 8 characters long'
        });
      }

      await unifiedUserService.changePassword(id, currentPassword, newPassword);

      res.json({
        success: true,
        message: 'Password changed successfully'
      });

    } catch (error) {
      console.error('Change password error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to change password'
      });
    }
  }

  // Réinitialiser le mot de passe
  static async resetPassword(req: Request, res: Response) {
    try {
      const { identifier } = req.body;

      if (!identifier) {
        return res.status(400).json({
          success: false,
          error: 'Identifier (email, username, or phone) is required'
        });
      }

      const tempPassword = await unifiedUserService.resetPassword(identifier);

      // TODO: Envoyer par email/SMS au lieu de retourner dans la réponse
      res.json({
        success: true,
        message: 'Password reset instructions sent',
        // En développement seulement:
        // tempPassword
      });

    } catch (error) {
      console.error('Reset password error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to reset password'
      });
    }
  }
}