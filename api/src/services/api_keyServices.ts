import { randomBytes } from 'crypto';
import { PrismaClient } from '@prisma/client';
import { 
  IApiKey, 
  ICreateApiKeyRequest, 
  IUpdateApiKeyRequest, 
  IApiKeyService,
  ApiKeyCategory,
  ApiKeyPermission 
} from '../models/api_keyModels';

const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL || 'file:./dev.db',
    },
  },
});

export class ApiKeyService implements IApiKeyService {
  private generateApiKey(category: ApiKeyCategory): string {
    const timestamp = Date.now().toString(36);
    const randomBytesStr = randomBytes(24).toString('hex');
    return `sk_${category}_${timestamp}_${randomBytesStr}`;
  }

  async createApiKey(data: ICreateApiKeyRequest): Promise<IApiKey> {
    const apiKey = this.generateApiKey(data.category);
    
    const createdKey = await prisma.apiKey.create({
      data: {
        key: apiKey,
        name: data.name,
        category: data.category,
        permissions: data.permissions,
        organizationId: data.organizationId,
        userId: data.userId,
        expiresAt: data.expiresAt,
        isActive: true,
      },
    });

    return createdKey as IApiKey;
  }

  async getApiKeyById(id: string): Promise<IApiKey | null> {
    const apiKey = await prisma.apiKey.findUnique({
      where: { id },
    });
    
    return apiKey as IApiKey | null;
  }

  async getApiKeyByKey(key: string): Promise<IApiKey | null> {
    const apiKey = await prisma.apiKey.findUnique({
      where: { key },
    });
    
    return apiKey as IApiKey | null;
  }

  async getApiKeysByOrganization(organizationId: string): Promise<IApiKey[]> {
    const apiKeys = await prisma.apiKey.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
    });
    
    return apiKeys as IApiKey[];
  }

  async updateApiKey(id: string, data: IUpdateApiKeyRequest): Promise<IApiKey> {
    const updatedKey = await prisma.apiKey.update({
      where: { id },
      data: {
        ...(data.name && { name: data.name }),
        ...(data.permissions && { permissions: data.permissions }),
        ...(data.isActive !== undefined && { isActive: data.isActive }),
        ...(data.expiresAt && { expiresAt: data.expiresAt }),
        updatedAt: new Date(),
      },
    });
    
    return updatedKey as IApiKey;
  }

  async deleteApiKey(id: string): Promise<void> {
    await prisma.apiKey.delete({
      where: { id },
    });
  }

  async validateApiKey(key: string, requiredPermission?: ApiKeyPermission): Promise<IApiKey | null> {
    const apiKey = await this.getApiKeyByKey(key);
    
    if (!apiKey) {
      return null;
    }

    if (!apiKey.isActive) {
      return null;
    }

    if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
      return null;
    }

    if (requiredPermission && !apiKey.permissions.includes(requiredPermission)) {
      return null;
    }

    await this.updateLastUsed(apiKey.id);
    
    return apiKey;
  }

  async updateLastUsed(id: string): Promise<void> {
    await prisma.apiKey.update({
      where: { id },
      data: { lastUsedAt: new Date() },
    });
  }
}