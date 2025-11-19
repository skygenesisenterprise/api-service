import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const prisma = new PrismaClient();

interface IAuthResponse {
  account: {
    id: string;
    email: string;
    fullName: string;
    organizationId?: string;
  };
  tokens: {
    accessToken: string;
    refreshToken: string;
    idToken?: string;
  };
  memberships: any[];
}

export class SimpleAuthService {
  private readonly jwtSecret = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
  private readonly jwtExpiresIn = '24h';
  private readonly refreshTokenExpiresIn = '7d';

  async authenticateUser(identifier: string, password: string): Promise<IAuthResponse> {
    // Find user by email or username
    let user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: identifier },
          // Si vous avez un champ username, ajoutez-le ici
        ]
      },
      include: {
        organization: true
      }
    });

    if (!user) {
      throw new Error('Invalid credentials');
    }

    if (!user.isActive) {
      throw new Error('Account is not active');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }

    // Generate tokens
    const tokens = this.generateTokens(user);
    
    // Get memberships (simplifié)
    const memberships = [{
      id: '1',
      accountId: user.id,
      organizationId: user.organizationId || '1',
      role: 'owner',
      permissions: ['*'],
      isActive: true,
      joinedAt: new Date().toISOString()
    }];

    return {
      account: {
        id: user.id,
        email: user.email,
        fullName: user.fullName || 'Admin Demo',
        organizationId: user.organizationId
      },
      tokens,
      memberships
    };
  }

  private generateTokens(user: any) {
    const payload = {
      userId: user.id,
      email: user.email,
      organizationId: user.organizationId
    };

    const accessToken = jwt.sign(payload, this.jwtSecret, { expiresIn: this.jwtExpiresIn });
    const refreshToken = jwt.sign({ userId: user.id }, this.jwtSecret, { expiresIn: this.refreshTokenExpiresIn });
    const idToken = jwt.sign({ ...payload, type: 'id' }, this.jwtSecret, { expiresIn: this.jwtExpiresIn });

    return {
      accessToken,
      refreshToken,
      idToken
    };
  }

  async createAccount(accountData: {
    email: string;
    password: string;
    fullName: string;
    organizationId?: string;
  }): Promise<IAuthResponse> {
    // Check if email already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: accountData.email }
    });

    if (existingUser) {
      throw new Error('Email already registered');
    }

    // Hash password
    const passwordHash = await bcrypt.hash(accountData.password, 10);

    // Create user
    const user = await prisma.user.create({
      data: {
        email: accountData.email,
        fullName: accountData.fullName,
        passwordHash,
        organizationId: accountData.organizationId,
        isActive: true
      },
      include: {
        organization: true
      }
    });

    // Generate tokens
    const tokens = this.generateTokens(user);
    
    // Get memberships
    const memberships = [{
      id: '1',
      accountId: user.id,
      organizationId: user.organizationId || '1',
      role: 'owner',
      permissions: ['*'],
      isActive: true,
      joinedAt: new Date().toISOString()
    }];

    return {
      account: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        organizationId: user.organizationId
      },
      tokens,
      memberships
    };
  }
}