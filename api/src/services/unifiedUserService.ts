import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Types pour la gestion des utilisateurs
export interface CreateUserData {
  primaryEmail: string;
  username?: string;
  phoneNumber?: string;
  password: string;
  profile?: any;
  preferences?: any;
  organizationId?: string;
  role?: string;
  permissions?: string[];
}

export interface UpdateUserData {
  primaryEmail?: string;
  username?: string;
  phoneNumber?: string;
  profile?: any;
  preferences?: any;
  status?: string;
}

export interface UserIdentifier {
  type: 'email' | 'phone' | 'username' | 'oauth';
  value: string;
  provider?: string;
  providerId?: string;
  isPrimary?: boolean;
}

export interface OrganizationMembership {
  organizationId: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
  permissions?: string[];
  isActive?: boolean;
}

// Service de gestion des utilisateurs unifiés
export class UnifiedUserService {
  // Créer un nouvel utilisateur
  async createUser(userData: CreateUserData): Promise<any> {
    try {
      // 1. Vérifier si l'email ou username existe déjà
      const existingUser = await prisma.unifiedAccount.findFirst({
        where: {
          OR: [
            { primaryEmail: userData.primaryEmail },
            ...(userData.username ? [{ username: userData.username }] : []),
            ...(userData.phoneNumber ? [{ phoneNumber: userData.phoneNumber }] : [])
          ]
        }
      });

      if (existingUser) {
        throw new Error('User with this email, username, or phone number already exists');
      }

      // 2. Générer un ID global unique
      const globalId = this.generateGlobalId();

      // 3. Hasher le mot de passe
      const passwordHash = await bcrypt.hash(userData.password, 12);

      // 4. Créer le compte unifié
      const account = await prisma.unifiedAccount.create({
        data: {
          globalId,
          primaryEmail: userData.primaryEmail,
          username: userData.username,
          phoneNumber: userData.phoneNumber,
          passwordHash,
          profile: userData.profile || {},
          preferences: userData.preferences || {},
          status: 'active',
          isVerified: false
        },
        include: {
          identifiers: true,
          memberships: {
            include: {
              organization: true
            }
          }
        }
      });

      // 5. Créer les identifiants
      const identifiers = [];
      
      // Email primaire
      identifiers.push(await prisma.accountIdentifier.create({
        data: {
          accountId: account.id,
          type: 'email',
          value: userData.primaryEmail,
          isPrimary: true,
          isVerified: false
        }
      }));

      // Username si fourni
      if (userData.username) {
        identifiers.push(await prisma.accountIdentifier.create({
          data: {
            accountId: account.id,
            type: 'username',
            value: userData.username,
            isPrimary: false,
            isVerified: true
          }
        }));
      }

      // Phone number si fourni
      if (userData.phoneNumber) {
        identifiers.push(await prisma.accountIdentifier.create({
          data: {
            accountId: account.id,
            type: 'phone',
            value: userData.phoneNumber,
            isPrimary: false,
            isVerified: false
          }
        }));
      }

      // 6. Ajouter à l'organisation si spécifiée
      if (userData.organizationId) {
        await this.addUserToOrganization(account.id, userData.organizationId, {
          organizationId: userData.organizationId,
          role: (userData.role as any) || 'member',
          permissions: userData.permissions || []
        });
      }

      // 7. Retourner l'utilisateur créé (sans mot de passe)
      const { passwordHash: _, ...userWithoutPassword } = account;
      
      return {
        ...userWithoutPassword,
        identifiers
      };

    } catch (error) {
      console.error('Create user error:', error);
      throw error;
    }
  }

  // Mettre à jour un utilisateur
  async updateUser(accountId: string, updateData: UpdateUserData): Promise<any> {
    try {
      // Vérifier si l'utilisateur existe
      const existingUser = await prisma.unifiedAccount.findUnique({
        where: { id: accountId }
      });

      if (!existingUser) {
        throw new Error('User not found');
      }

      // Préparer les données de mise à jour
      const updateFields: any = {};

      if (updateData.primaryEmail && updateData.primaryEmail !== existingUser.primaryEmail) {
        // Vérifier si le nouvel email est disponible
        const emailExists = await prisma.unifiedAccount.findFirst({
          where: { primaryEmail: updateData.primaryEmail }
        });

        if (emailExists) {
          throw new Error('Email already exists');
        }

        updateFields.primaryEmail = updateData.primaryEmail;
        
        // Mettre à jour l'identifiant email primaire
        await prisma.accountIdentifier.updateMany({
          where: {
            accountId,
            type: 'email',
            isPrimary: true
          },
          data: {
            value: updateData.primaryEmail,
            isVerified: false // Nécessite re-vérification
          }
        });
      }

      if (updateData.username && updateData.username !== existingUser.username) {
        // Vérifier si le username est disponible
        const usernameExists = await prisma.unifiedAccount.findFirst({
          where: { username: updateData.username }
        });

        if (usernameExists) {
          throw new Error('Username already exists');
        }

        updateFields.username = updateData.username;
        
        // Mettre à jour l'identifiant username
        await prisma.accountIdentifier.updateMany({
          where: {
            accountId,
            type: 'username'
          },
          data: {
            value: updateData.username
          }
        });
      }

      if (updateData.phoneNumber !== undefined) {
        updateFields.phoneNumber = updateData.phoneNumber;
        
        // Gérer l'identifiant phone
        if (updateData.phoneNumber) {
          const existingPhoneIdentifier = await prisma.accountIdentifier.findFirst({
            where: {
              accountId,
              type: 'phone'
            }
          });

          if (existingPhoneIdentifier) {
            await prisma.accountIdentifier.update({
              where: { id: existingPhoneIdentifier.id },
              data: {
                value: updateData.phoneNumber,
                isVerified: false
              }
            });
          } else {
            await prisma.accountIdentifier.create({
              data: {
                accountId,
                type: 'phone',
                value: updateData.phoneNumber,
                isPrimary: false,
                isVerified: false
              }
            });
          }
        } else {
          // Supprimer l'identifiant phone si fourni comme null
          await prisma.accountIdentifier.deleteMany({
            where: {
              accountId,
              type: 'phone'
            }
          });
        }
      }

      if (updateData.profile) {
        updateFields.profile = updateData.profile;
      }

      if (updateData.preferences) {
        updateFields.preferences = updateData.preferences;
      }

      if (updateData.status) {
        updateFields.status = updateData.status;
      }

      // Mettre à jour l'utilisateur
      const updatedUser = await prisma.unifiedAccount.update({
        where: { id: accountId },
        data: updateFields,
        include: {
          identifiers: true,
          memberships: {
            include: {
              organization: true
            }
          }
        }
      });

      // Retourner sans mot de passe
      const { passwordHash: _, ...userWithoutPassword } = updatedUser;
      return userWithoutPassword;

    } catch (error) {
      console.error('Update user error:', error);
      throw error;
    }
  }

  // Ajouter un identifiant à un utilisateur
  async addIdentifier(accountId: string, identifier: UserIdentifier): Promise<any> {
    try {
      // Vérifier si l'identifiant existe déjà
      const existingIdentifier = await prisma.accountIdentifier.findFirst({
        where: { value: identifier.value }
      });

      if (existingIdentifier) {
        throw new Error('Identifier already exists');
      }

      // Si c'est un identifiant primaire, désactiver les autres primaires du même type
      if (identifier.isPrimary) {
        await prisma.accountIdentifier.updateMany({
          where: {
            accountId,
            type: identifier.type,
            isPrimary: true
          },
          data: { isPrimary: false }
        });
      }

      const newIdentifier = await prisma.accountIdentifier.create({
        data: {
          accountId,
          type: identifier.type,
          value: identifier.value,
          provider: identifier.provider,
          providerId: identifier.providerId,
          isPrimary: identifier.isPrimary || false,
          isVerified: identifier.type === 'oauth' // OAuth est pré-vérifié
        }
      });

      return newIdentifier;

    } catch (error) {
      console.error('Add identifier error:', error);
      throw error;
    }
  }

  // Ajouter un utilisateur à une organisation
  async addUserToOrganization(accountId: string, organizationId: string, membership: OrganizationMembership): Promise<any> {
    try {
      // Vérifier si l'organisation existe
      const organization = await prisma.organization.findUnique({
        where: { id: organizationId }
      });

      if (!organization) {
        throw new Error('Organization not found');
      }

      // Vérifier si le membership existe déjà
      const existingMembership = await prisma.organizationMembership.findUnique({
        where: {
          accountId_organizationId: {
            accountId,
            organizationId
          }
        }
      });

      if (existingMembership) {
        throw new Error('User is already a member of this organization');
      }

      const newMembership = await prisma.organizationMembership.create({
        data: {
          accountId,
          organizationId,
          role: membership.role,
          permissions: membership.permissions || [],
          isActive: membership.isActive !== undefined ? membership.isActive : true
        },
        include: {
          organization: true,
          account: {
            select: {
              id: true,
              globalId: true,
              primaryEmail: true,
              username: true
            }
          }
        }
      });

      return newMembership;

    } catch (error) {
      console.error('Add to organization error:', error);
      throw error;
    }
  }

  // Mettre à jour le membership d'une organisation
  async updateOrganizationMembership(accountId: string, organizationId: string, updates: Partial<OrganizationMembership>): Promise<any> {
    try {
      const updatedMembership = await prisma.organizationMembership.update({
        where: {
          accountId_organizationId: {
            accountId,
            organizationId
          }
        },
        data: {
          ...(updates.role && { role: updates.role }),
          ...(updates.permissions && { permissions: updates.permissions }),
          ...(updates.isActive !== undefined && { isActive: updates.isActive })
        },
        include: {
          organization: true,
          account: {
            select: {
              id: true,
              globalId: true,
              primaryEmail: true,
              username: true
            }
          }
        }
      });

      return updatedMembership;

    } catch (error) {
      console.error('Update membership error:', error);
      throw error;
    }
  }

  // Retirer un utilisateur d'une organisation
  async removeFromOrganization(accountId: string, organizationId: string): Promise<void> {
    try {
      await prisma.organizationMembership.delete({
        where: {
          accountId_organizationId: {
            accountId,
            organizationId
          }
        }
      });

    } catch (error) {
      console.error('Remove from organization error:', error);
      throw error;
    }
  }

  // Lister les organisations d'un utilisateur
  async getUserOrganizations(accountId: string): Promise<any[]> {
    try {
      const memberships = await prisma.organizationMembership.findMany({
        where: {
          accountId,
          isActive: true
        },
        include: {
          organization: true
        },
        orderBy: {
          joinedAt: 'desc'
        }
      });

      return memberships;

    } catch (error) {
      console.error('Get user organizations error:', error);
      throw error;
    }
  }

  // Lister les membres d'une organisation
  async getOrganizationMembers(organizationId: string): Promise<any[]> {
    try {
      const memberships = await prisma.organizationMembership.findMany({
        where: {
          organizationId,
          isActive: true
        },
        include: {
          account: {
            select: {
              id: true,
              globalId: true,
              primaryEmail: true,
              username: true,
              profile: true,
              status: true,
              lastLoginAt: true,
              createdAt: true
            }
          }
        },
        orderBy: {
          joinedAt: 'asc'
        }
      });

      return memberships;

    } catch (error) {
      console.error('Get organization members error:', error);
      throw error;
    }
  }

  // Changer le mot de passe
  async changePassword(accountId: string, currentPassword: string, newPassword: string): Promise<void> {
    try {
      const user = await prisma.unifiedAccount.findUnique({
        where: { id: accountId }
      });

      if (!user) {
        throw new Error('User not found');
      }

      if (!user.passwordHash) {
        throw new Error('User has no password set');
      }

      // Vérifier le mot de passe actuel
      const isValidPassword = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!isValidPassword) {
        throw new Error('Current password is incorrect');
      }

      // Hasher et mettre à jour le nouveau mot de passe
      const newPasswordHash = await bcrypt.hash(newPassword, 12);
      
      await prisma.unifiedAccount.update({
        where: { id: accountId },
        data: { passwordHash: newPasswordHash }
      });

    } catch (error) {
      console.error('Change password error:', error);
      throw error;
    }
  }

  // Réinitialiser le mot de passe
  async resetPassword(identifier: string): Promise<string> {
    try {
      // Trouver l'utilisateur par n'importe quel identifiant
      const user = await this.findUserByIdentifier(identifier);
      
      if (!user) {
        throw new Error('User not found');
      }

      // Générer un mot de passe temporaire
      const tempPassword = this.generateTempPassword();
      const tempPasswordHash = await bcrypt.hash(tempPassword, 12);

      // Mettre à jour le mot de passe
      await prisma.unifiedAccount.update({
        where: { id: user.id },
        data: { passwordHash: tempPasswordHash }
      });

      // TODO: Envoyer le mot de passe par email/SMS
      console.log(`Temp password for ${user.primaryEmail}: ${tempPassword}`);

      return tempPassword;

    } catch (error) {
      console.error('Reset password error:', error);
      throw error;
    }
  }

  // Supprimer un utilisateur
  async deleteUser(accountId: string): Promise<void> {
    try {
      // Marquer comme supprimé au lieu de supprimer réellement
      await prisma.unifiedAccount.update({
        where: { id: accountId },
        data: { 
          status: 'deleted',
          // Anonymiser les données
          primaryEmail: `deleted_${accountId}@deleted.com`,
          username: null,
          phoneNumber: null,
          profile: {},
          passwordHash: null
        }
      });

    } catch (error) {
      console.error('Delete user error:', error);
      throw error;
    }
  }

  // Helper: trouver un utilisateur par identifiant
  private async findUserByIdentifier(identifier: string) {
    const cleanIdentifier = identifier.trim().toLowerCase();

    // Chercher dans les identifiants
    const accountIdentifier = await prisma.accountIdentifier.findFirst({
      where: {
        OR: [
          { value: cleanIdentifier },
          { value: identifier }
        ]
      },
      include: {
        account: true
      }
    });

    if (accountIdentifier) {
      return accountIdentifier.account;
    }

    // Chercher directement dans les comptes
    return await prisma.unifiedAccount.findFirst({
      where: {
        OR: [
          { primaryEmail: cleanIdentifier },
          { primaryEmail: identifier },
          { username: cleanIdentifier },
          { username: identifier }
        ]
      }
    });
  }

  // Helper: générer un ID global unique
  private generateGlobalId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `USR_${timestamp}_${random}`.toUpperCase();
  }

  // Helper: générer un mot de passe temporaire
  private generateTempPassword(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < 12; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
  }
}

export const unifiedUserService = new UnifiedUserService();