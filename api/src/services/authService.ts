import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { ILoginRequest, IRegisterRequest, IAuthResponse, IUser } from '../models/authModels';

const prisma = new PrismaClient();

export class AuthService {
  private readonly jwtSecret = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
  private readonly jwtExpiresIn = '24h';

  async login(credentials: ILoginRequest): Promise<IAuthResponse> {
    const { email, password } = credentials;

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email },
      include: { organization: true }
    });

    if (!user) {
      throw new Error('Invalid credentials');
    }

    if (!user.isActive) {
      throw new Error('Account is inactive');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }

    // Generate JWT token
    const token = this.generateToken(user);
    const refreshToken = this.generateRefreshToken(user);

    // Update last login
    await prisma.user.update({
      where: { id: user.id },
      data: { updatedAt: new Date() }
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName || undefined,
        organizationId: user.organizationId || undefined
      },
      token,
      refreshToken
    };
  }

  async register(userData: IRegisterRequest): Promise<IAuthResponse> {
    const { email, password, fullName, organizationId } = userData;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      throw new Error('User already exists');
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user
    let orgId = organizationId;
    
    // If no organization provided, create a default one
    if (!orgId) {
      const defaultOrg = await prisma.organization.create({
        data: {
          name: `${fullName || email}'s Organization`
        }
      });
      orgId = defaultOrg.id;
    }

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        fullName,
        organizationId: orgId,
        isActive: true
      },
      include: { organization: true }
    });

    // Generate tokens
    const token = this.generateToken(user);
    const refreshToken = this.generateRefreshToken(user);

    return {
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName || undefined,
        organizationId: user.organizationId || undefined
      },
      token,
      refreshToken
    };
  }

  async getUserById(userId: string): Promise<IUser | null> {
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      return null;
    }

    return {
      id: user.id,
      email: user.email,
      fullName: user.fullName || undefined,
      organizationId: user.organizationId || undefined,
      isActive: user.isActive,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
  }

  async verifyToken(token: string): Promise<IUser | null> {
    try {
      const decoded = jwt.verify(token, this.jwtSecret) as { userId: string };
      return await this.getUserById(decoded.userId);
    } catch (error) {
      return null;
    }
  }

  public generateToken(user: any): string {
    return jwt.sign(
      { 
        userId: user.id,
        email: user.email,
        organizationId: user.organizationId
      },
      this.jwtSecret,
      { expiresIn: this.jwtExpiresIn }
    );
  }

  public generateRefreshToken(user: any): string {
    return jwt.sign(
      { userId: user.id },
      this.jwtSecret,
      { expiresIn: '7d' }
    );
  }
}