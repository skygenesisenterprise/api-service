import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Types pour la gestion des utilisateurs
export interface AuthCredentials {
  identifier: string; // email, username, ou phone
  password: string;
  deviceId?: string;
  deviceInfo?: any;
}

export interface AuthResult {
  success: boolean;
  user?: any;
  token?: string;
  refreshToken?: string;
  session?: any;
  error?: string;
  requiresTwoFactor?: boolean;
}

export interface UserPermissions {
  applications: string[]; // IDs des applications accessibles
  services: string[]; // IDs des services accessibles
  roles: string[]; // Rôles de l'utilisateur
  permissions: string[]; // Permissions spécifiques
  organizations: string[]; // Organizations accessibles
}

export interface ServiceAccess {
  serviceId: string;
  serviceName: string;
  hasAccess: boolean;
  permissions: string[];
  lastAccess?: Date;
}

export interface ApplicationAccess {
  applicationId: string;
  applicationName: string;
  hasAccess: boolean;
  role: string;
  permissions: string[];
}

// Service d'authentification unifiée
export class UnifiedAuthService {
  private readonly JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
  private readonly REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'refresh-secret';
  private readonly TOKEN_EXPIRY = '15m';
  private readonly REFRESH_TOKEN_EXPIRY = '7d';

  // Authentification principale
  async authenticate(credentials: AuthCredentials): Promise<AuthResult> {
    try {
      // 1. Trouver l'utilisateur par n'importe quel identifiant
      const user = await this.findUserByIdentifier(credentials.identifier);
      
      if (!user) {
        return { success: false, error: 'Invalid credentials' };
      }

      // 2. Vérifier le statut du compte
      if (user.status !== 'active') {
        return { success: false, error: 'Account is suspended or deleted' };
      }

      // 3. Vérifier le mot de passe
      if (user.passwordHash) {
        const isValidPassword = await bcrypt.compare(credentials.password, user.passwordHash);
        if (!isValidPassword) {
          return { success: false, error: 'Invalid credentials' };
        }
      }

      // 4. Mettre à jour la dernière connexion
      await prisma.unifiedAccount.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() }
      });

      // 5. Créer la session
      const session = await this.createSession(user.id, credentials.deviceInfo);

      // 6. Générer les tokens
      const token = this.generateAccessToken(user);
      const refreshToken = this.generateRefreshToken(user);

      return {
        success: true,
        user: this.sanitizeUser(user),
        token,
        refreshToken,
        session
      };

    } catch (error) {
      console.error('Authentication error:', error);
      return { success: false, error: 'Authentication failed' };
    }
  }

  // Trouver un utilisateur par n'importe quel identifiant
  private async findUserByIdentifier(identifier: string) {
    // Nettoyer l'identifiant
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
        account: {
          include: {
            memberships: {
              include: {
                organization: true
              }
            }
          }
        }
      }
    });

    if (accountIdentifier) {
      return accountIdentifier.account;
    }

    // Chercher directement dans les comptes (email primaire, username)
    return await prisma.unifiedAccount.findFirst({
      where: {
        OR: [
          { primaryEmail: cleanIdentifier },
          { primaryEmail: identifier },
          { username: cleanIdentifier },
          { username: identifier }
        ]
      },
      include: {
        memberships: {
          include: {
            organization: true
          }
        }
      }
    });
  }

  // Créer une nouvelle session
  private async createSession(accountId: string, deviceInfo?: any) {
    const tokenHash = crypto.createHash('sha256').update(crypto.randomUUID()).digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 jours

    return await prisma.session.create({
      data: {
        accountId,
        tokenHash,
        deviceInfo,
        expiresAt,
        lastAccessAt: new Date()
      }
    });
  }

  // Générer un token d'accès
  private generateAccessToken(user: any): string {
    const payload = {
      sub: user.id,
      globalId: user.globalId,
      email: user.primaryEmail,
      username: user.username,
      type: 'access'
    };

    return jwt.sign(payload, this.JWT_SECRET, {
      expiresIn: this.TOKEN_EXPIRY,
      issuer: 'sky-genesis-api',
      audience: 'sky-genesis-apps'
    });
  }

  // Générer un token de rafraîchissement
  private generateRefreshToken(user: any): string {
    const payload = {
      sub: user.id,
      globalId: user.globalId,
      type: 'refresh'
    };

    return jwt.sign(payload, this.REFRESH_TOKEN_SECRET, {
      expiresIn: this.REFRESH_TOKEN_EXPIRY
    });
  }

  // Valider un token d'accès
  async validateAccessToken(token: string): Promise<any> {
    try {
      const decoded = jwt.verify(token, this.JWT_SECRET) as any;
      
      if (decoded.type !== 'access') {
        throw new Error('Invalid token type');
      }

      // Vérifier que l'utilisateur existe toujours
      const user = await prisma.unifiedAccount.findUnique({
        where: { id: decoded.sub },
        include: {
          memberships: true
        }
      });

      if (!user || user.status !== 'active') {
        throw new Error('User not found or inactive');
      }

      return { ...decoded, user };
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  }

  // Rafraîchir un token
  async refreshToken(refreshToken: string): Promise<AuthResult> {
    try {
      const decoded = jwt.verify(refreshToken, this.REFRESH_TOKEN_SECRET) as any;
      
      if (decoded.type !== 'refresh') {
        return { success: false, error: 'Invalid refresh token' };
      }

      const user = await prisma.unifiedAccount.findUnique({
        where: { id: decoded.sub },
        include: {
          memberships: {
            include: {
              organization: true
            }
          }
        }
      });

      if (!user || user.status !== 'active') {
        return { success: false, error: 'User not found or inactive' };
      }

      // Générer nouveaux tokens
      const newToken = this.generateAccessToken(user);
      const newRefreshToken = this.generateRefreshToken(user);

      return {
        success: true,
        user: this.sanitizeUser(user),
        token: newToken,
        refreshToken: newRefreshToken
      };

    } catch (error) {
      return { success: false, error: 'Invalid or expired refresh token' };
    }
  }

  // Obtenir les permissions d'un utilisateur
  async getUserPermissions(accountId: string): Promise<UserPermissions> {
    const user = await prisma.unifiedAccount.findUnique({
      where: { id: accountId },
      include: {
        memberships: {
          include: {
            organization: true
          }
        }
      }
    });

    if (!user) {
      throw new Error('User not found');
    }

    // Agréger les permissions de toutes les organisations
    const permissions: UserPermissions = {
      applications: [],
      services: [],
      roles: [],
      permissions: [],
      organizations: []
    };

    user.memberships.forEach(membership => {
      if (membership.isActive) {
        permissions.organizations.push(membership.organizationId);
        permissions.roles.push(membership.role);
        
        // Ajouter les permissions spécifiques de l'organisation
        const orgPermissions = membership.permissions as any[];
        if (orgPermissions) {
          permissions.permissions.push(...orgPermissions);
        }

        // Ajouter les permissions basées sur le rôle
        const rolePermissions = this.getRolePermissions(membership.role);
        permissions.permissions.push(...rolePermissions);
      }
    });

    // Déduire les applications et services accessibles
    permissions.applications = this.extractApplicationsFromPermissions(permissions.permissions);
    permissions.services = this.extractServicesFromPermissions(permissions.permissions);

    // Dédoublonner
    permissions.applications = [...new Set(permissions.applications)];
    permissions.services = [...new Set(permissions.services)];
    permissions.roles = [...new Set(permissions.roles)];
    permissions.permissions = [...new Set(permissions.permissions)];

    return permissions;
  }

  // Vérifier l'accès à un service
  async checkServiceAccess(accountId: string, serviceId: string): Promise<ServiceAccess> {
    const permissions = await this.getUserPermissions(accountId);
    const hasAccess = permissions.services.includes(serviceId) || 
                     permissions.services.includes('*') ||
                     permissions.permissions.includes(`service:${serviceId}:access`);

    return {
      serviceId,
      serviceName: serviceId, // TODO: Récupérer le nom réel du service
      hasAccess,
      permissions: hasAccess ? permissions.permissions.filter(p => 
        p.includes(`service:${serviceId}`) || p.startsWith('service:')
      ) : []
    };
  }

  // Vérifier l'accès à une application
  async checkApplicationAccess(accountId: string, applicationId: string): Promise<ApplicationAccess> {
    const permissions = await this.getUserPermissions(accountId);
    const hasAccess = permissions.applications.includes(applicationId) || 
                     permissions.applications.includes('*') ||
                     permissions.permissions.includes(`app:${applicationId}:access`);

    // Déterminer le rôle pour cette application
    const role = permissions.roles.find(r => r !== 'member') || 'user';

    return {
      applicationId,
      applicationName: applicationId, // TODO: Récupérer le nom réel
      hasAccess,
      role,
      permissions: hasAccess ? permissions.permissions.filter(p => 
        p.includes(`app:${applicationId}`) || p.startsWith('app:')
      ) : []
    };
  }

  // Obtenir les permissions basées sur le rôle
  private getRolePermissions(role: string): string[] {
    const rolePermissions: Record<string, string[]> = {
      owner: [
        'organization:*',
        'app:*',
        'service:*',
        'user:*',
        'logs:*',
        'billing:*'
      ],
      admin: [
        'organization:read',
        'organization:write',
        'app:*',
        'service:*',
        'user:read',
        'user:write',
        'logs:*'
      ],
      member: [
        'organization:read',
        'app:read',
        'service:read',
        'logs:read'
      ],
      viewer: [
        'organization:read',
        'app:read',
        'service:read',
        'logs:read'
      ]
    };

    return rolePermissions[role] || [];
  }

  // Extraire les applications des permissions
  private extractApplicationsFromPermissions(permissions: string[]): string[] {
    const apps = new Set<string>();
    
    permissions.forEach(permission => {
      if (permission.startsWith('app:')) {
        const parts = permission.split(':');
        if (parts[1] === '*' || parts[1]) {
          apps.add(parts[1]);
        }
      }
    });

    return Array.from(apps);
  }

  // Extraire les services des permissions
  private extractServicesFromPermissions(permissions: string[]): string[] {
    const services = new Set<string>();
    
    permissions.forEach(permission => {
      if (permission.startsWith('service:')) {
        const parts = permission.split(':');
        if (parts[1] === '*' || parts[1]) {
          services.add(parts[1]);
        }
      }
    });

    return Array.from(services);
  }

  // Nettoyer les données utilisateur
  private sanitizeUser(user: any) {
    const { passwordHash, ...sanitized } = user;
    return sanitized;
  }

  // Déconnexion
  async logout(tokenHash: string): Promise<void> {
    await prisma.session.updateMany({
      where: { tokenHash },
      data: { isActive: false }
    });
  }

  // Révoquer toutes les sessions d'un utilisateur
  async revokeAllSessions(accountId: string): Promise<void> {
    await prisma.session.updateMany({
      where: { accountId },
      data: { isActive: false }
    });
  }
}

export const unifiedAuthService = new UnifiedAuthService();