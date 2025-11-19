import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { 
  IUnifiedAccount, 
  IAccountIdentifier, 
  IOrganizationMembership,
  ICreateUnifiedAccountRequest,
  ILinkIdentifierRequest,
  IAuthResponse,
  ISession
} from '../models/unifiedAccountModels';

const prisma = new PrismaClient();

export class UnifiedAccountService {
  private readonly jwtSecret = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
  private readonly jwtExpiresIn = '24h';
  private readonly refreshTokenExpiresIn = '7d';

  // ========================================
  // ACCOUNT CREATION & MANAGEMENT
  // ========================================

  async createAccount(accountData: ICreateUnifiedAccountRequest): Promise<IAuthResponse> {
    const { email, username, phoneNumber, password, profile, organizationId } = accountData;

    // Check if email already exists
    const existingEmail = await prisma.accountIdentifier.findUnique({
      where: { value: email }
    });

    if (existingEmail) {
      throw new Error('Email already registered');
    }

    // Check username uniqueness if provided
    if (username) {
      const existingUsername = await prisma.accountIdentifier.findUnique({
        where: { value: username }
      });

      if (existingUsername) {
        throw new Error('Username already taken');
      }
    }

    // Generate global ID for the account
    const globalId = this.generateGlobalId();

    // Hash password if provided
    const passwordHash = password ? await bcrypt.hash(password, 10) : null;

    // Create the unified account
    const account = await prisma.unifiedAccount.create({
      data: {
        globalId,
        primaryEmail: email,
        username,
        phoneNumber,
        profile: profile || {},
        preferences: {
          theme: 'auto',
          notifications: {
            email: true,
            push: true,
            sms: false
          },
          privacy: {
            profileVisibility: 'private',
            dataSharing: false
          }
        },
        status: 'active',
        isVerified: false,
        passwordHash
      }
    });

    // Create primary email identifier
    await prisma.accountIdentifier.create({
      data: {
        accountId: account.id,
        type: 'email',
        value: email,
        isPrimary: true,
        isVerified: false
      }
    });

    // Create username identifier if provided
    if (username) {
      await prisma.accountIdentifier.create({
        data: {
          accountId: account.id,
          type: 'username',
          value: username,
          isPrimary: false,
          isVerified: true
        }
      });
    }

    // Create phone identifier if provided
    if (phoneNumber) {
      await prisma.accountIdentifier.create({
        data: {
          accountId: account.id,
          type: 'phone',
          value: phoneNumber,
          isPrimary: false,
          isVerified: false
        }
      });
    }

    // Handle organization membership
    let memberships: IOrganizationMembership[] = [];
    
    if (organizationId) {
      const membership = await prisma.organizationMembership.create({
        data: {
          accountId: account.id,
          organizationId,
          role: 'member',
          permissions: ['read'],
          isActive: true
        }
      });

      memberships.push({
        id: membership.id,
        accountId: membership.accountId,
        organizationId: membership.organizationId,
        role: membership.role as any,
        permissions: membership.permissions,
        isActive: membership.isActive,
        joinedAt: membership.joinedAt
      });
    } else {
      // Create default organization for the user
      const defaultOrg = await prisma.organization.create({
        data: {
          name: `${profile?.firstName || email}'s Organization`
        }
      });

      const membership = await prisma.organizationMembership.create({
        data: {
          accountId: account.id,
          organizationId: defaultOrg.id,
          role: 'owner',
          permissions: ['read', 'write', 'admin'],
          isActive: true
        }
      });

      memberships.push({
        id: membership.id,
        accountId: membership.accountId,
        organizationId: membership.organizationId,
        role: membership.role as any,
        permissions: membership.permissions,
        isActive: membership.isActive,
        joinedAt: membership.joinedAt
      });
    }

    // Generate tokens
    const tokens = this.generateTokens(account);

    // Create session
    await this.createSession(account.id, tokens.accessToken);

    return {
      account: this.formatAccount(account),
      tokens,
      memberships
    };
  }

  async authenticateUser(identifier: string, password?: string): Promise<IAuthResponse> {
    // Find account by any identifier
    const accountIdentifier = await prisma.accountIdentifier.findFirst({
      where: { value: identifier },
      include: {
        account: true
      }
    });

    if (!accountIdentifier || !accountIdentifier.account) {
      throw new Error('Invalid credentials');
    }

    const account = accountIdentifier.account;

    if (account.status !== 'active') {
      throw new Error('Account is not active');
    }

    // For OAuth users, no password needed
    if (accountIdentifier.type === 'oauth') {
      const tokens = this.generateTokens(account);
      const memberships = await this.getAccountMemberships(account.id);
      
      await this.createSession(account.id, tokens.accessToken);

      return {
        account: this.formatAccount(account),
        tokens,
        memberships
      };
    }

    // For password-based auth
    if (!password || !account.passwordHash) {
      throw new Error('Password required');
    }

    const isPasswordValid = await bcrypt.compare(password, account.passwordHash);
    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }

    // Update last login
    await prisma.unifiedAccount.update({
      where: { id: account.id },
      data: { lastLoginAt: new Date() }
    });

    const tokens = this.generateTokens(account);
    const memberships = await this.getAccountMemberships(account.id);
    
    await this.createSession(account.id, tokens.accessToken);

    return {
      account: this.formatAccount(account),
      tokens,
      memberships
    };
  }

  async linkOAuthAccount(accountId: string, provider: string, providerId: string, email?: string): Promise<void> {
    // Check if OAuth identifier already exists
    const existingOAuth = await prisma.accountIdentifier.findFirst({
      where: {
        type: 'oauth',
        provider,
        providerId
      }
    });

    if (existingOAuth) {
      throw new Error('OAuth account already linked');
    }

    // Create OAuth identifier
    await prisma.accountIdentifier.create({
      data: {
        accountId,
        type: 'oauth',
        value: email || `${provider}_${providerId}`,
        provider,
        providerId,
        isPrimary: false,
        isVerified: true
      }
    });
  }

  async linkIdentifier(accountId: string, identifierData: ILinkIdentifierRequest): Promise<void> {
    const { type, value, provider, providerId, isPrimary } = identifierData;

    // Check if identifier already exists
    const existing = await prisma.accountIdentifier.findUnique({
      where: { value }
    });

    if (existing) {
      throw new Error('Identifier already exists');
    }

    // If setting as primary, update other identifiers
    if (isPrimary) {
      await prisma.accountIdentifier.updateMany({
        where: {
          accountId,
          type,
          isPrimary: true
        },
        data: {
          isPrimary: false
        }
      });
    }

    await prisma.accountIdentifier.create({
      data: {
        accountId,
        type,
        value,
        provider,
        providerId,
        isPrimary: isPrimary || false,
        isVerified: type === 'oauth' // OAuth identifiers are pre-verified
      }
    });
  }

  async getAccountById(accountId: string): Promise<IUnifiedAccount | null> {
    const account = await prisma.unifiedAccount.findUnique({
      where: { id: accountId }
    });

    return account ? this.formatAccount(account) : null;
  }

  async getAccountByGlobalId(globalId: string): Promise<IUnifiedAccount | null> {
    const account = await prisma.unifiedAccount.findUnique({
      where: { globalId }
    });

    return account ? this.formatAccount(account) : null;
  }

  async getAccountMemberships(accountId: string): Promise<IOrganizationMembership[]> {
    const memberships = await prisma.organizationMembership.findMany({
      where: { accountId, isActive: true }
    });

    return memberships.map(membership => ({
      id: membership.id,
      accountId: membership.accountId,
      organizationId: membership.organizationId,
      role: membership.role as any,
      permissions: membership.permissions,
      isActive: membership.isActive,
      joinedAt: membership.joinedAt
    }));
  }

  // ========================================
  // SESSION MANAGEMENT
  // ========================================

  async createSession(accountId: string, token: string, deviceInfo?: any): Promise<ISession> {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    
    const session = await prisma.session.create({
      data: {
        accountId,
        tokenHash,
        deviceInfo,
        isActive: true,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
        lastAccessAt: new Date()
      }
    });

    return {
      id: session.id,
      accountId: session.accountId,
      tokenHash: session.tokenHash,
      deviceInfo: session.deviceInfo as any,
      isActive: session.isActive,
      expiresAt: session.expiresAt,
      createdAt: session.createdAt,
      lastAccessAt: session.lastAccessAt
    };
  }

  async validateSession(token: string): Promise<IUnifiedAccount | null> {
    try {
      const decoded = jwt.verify(token, this.jwtSecret) as { accountId: string };
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

      const session = await prisma.session.findFirst({
        where: {
          accountId: decoded.accountId,
          tokenHash,
          isActive: true,
          expiresAt: { gt: new Date() }
        },
        include: {
          account: true
        }
      });

      if (!session || !session.account) {
        return null;
      }

      // Update last access
      await prisma.session.update({
        where: { id: session.id },
        data: { lastAccessAt: new Date() }
      });

      return this.formatAccount(session.account);
    } catch (error) {
      return null;
    }
  }

  async revokeSession(sessionId: string): Promise<void> {
    await prisma.session.update({
      where: { id: sessionId },
      data: { isActive: false }
    });
  }

  async revokeAllSessions(accountId: string): Promise<void> {
    await prisma.session.updateMany({
      where: { accountId },
      data: { isActive: false }
    });
  }

  // ========================================
  // UTILITY METHODS
  // ========================================

  private generateGlobalId(): string {
    return `acct_${crypto.randomBytes(16).toString('hex')}`;
  }

  public generateTokens(account: any): { accessToken: string; refreshToken: string; idToken?: string } {
    const accessToken = jwt.sign(
      { 
        accountId: account.id,
        globalId: account.globalId,
        email: account.primaryEmail
      },
      this.jwtSecret,
      { expiresIn: this.jwtExpiresIn }
    );

    const refreshToken = jwt.sign(
      { accountId: account.id },
      this.jwtSecret,
      { expiresIn: this.refreshTokenExpiresIn }
    );

    const idToken = jwt.sign(
      {
        sub: account.globalId,
        email: account.primaryEmail,
        name: `${account.profile?.firstName || ''} ${account.profile?.lastName || ''}`.trim(),
        picture: account.profile?.avatar
      },
      this.jwtSecret,
      { expiresIn: this.jwtExpiresIn }
    );

    return { accessToken, refreshToken, idToken };
  }

  private formatAccount(account: any): IUnifiedAccount {
    return {
      id: account.id,
      globalId: account.globalId,
      primaryEmail: account.primaryEmail,
      username: account.username || undefined,
      phoneNumber: account.phoneNumber || undefined,
      profile: account.profile as any,
      preferences: account.preferences as any,
      status: account.status as any,
      isVerified: account.isVerified,
      lastLoginAt: account.lastLoginAt || undefined,
      createdAt: account.createdAt,
      updatedAt: account.updatedAt
    };
  }

  async verifyToken(token: string): Promise<IUnifiedAccount | null> {
    try {
      const decoded = jwt.verify(token, this.jwtSecret) as { accountId: string };
      return await this.getAccountById(decoded.accountId);
    } catch (error) {
      return null;
    }
  }
}