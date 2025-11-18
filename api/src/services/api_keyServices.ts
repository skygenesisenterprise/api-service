import { randomBytes } from 'crypto';
import { PrismaClient } from '@prisma/client';
import { 
  IApiKey, 
  ICreateApiKeyRequest, 
  IUpdateApiKeyRequest, 
  IApiKeyService,
  ApiKeyType,
  ApiKeyStatus,
  ApiKeyPermission 
} from '../models/api_keyModels';

const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL || 'file:./prisma/dev.db',
    },
  },
});

export class ApiKeyService implements IApiKeyService {
  private generateApiKey(type: ApiKeyType): string {
    const timestamp = Date.now().toString(36);
    const randomBytesStr = randomBytes(24).toString('hex');
    return `sk_${type}_${timestamp}_${randomBytesStr}`;
  }

  async createApiKey(data: ICreateApiKeyRequest): Promise<IApiKey> {
    const apiKey = this.generateApiKey(data.type);
    
    const createdKey = await prisma.apiKey.create({
      data: {
        key: apiKey,
        name: data.name,
        type: data.type,
        status: data.status,
        permissions: JSON.stringify(data.permissions),
        organizationId: data.organizationId,
        userId: data.userId,
        expiresAt: data.expiresAt,
        isActive: true,
      },
    });

    return {
      ...createdKey,
      permissions: JSON.parse(createdKey.permissions),
    } as IApiKey;
  }

  async getApiKeyById(id: string): Promise<IApiKey | null> {
    const apiKey = await prisma.apiKey.findUnique({
      where: { id },
    });
    
    if (!apiKey) return null;
    
    return {
      ...apiKey,
      permissions: JSON.parse(apiKey.permissions),
    } as IApiKey;
  }

  async getApiKeyByKey(key: string): Promise<IApiKey | null> {
    const apiKey = await prisma.apiKey.findUnique({
      where: { key },
    });
    
    if (!apiKey) return null;
    
    return {
      ...apiKey,
      permissions: JSON.parse(apiKey.permissions),
    } as IApiKey;
  }

  async getApiKeysByOrganization(organizationId: string): Promise<IApiKey[]> {
    const apiKeys = await prisma.apiKey.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
    });
    
    return apiKeys.map(key => ({
      ...key,
      permissions: JSON.parse(key.permissions),
    })) as IApiKey[];
  }

  async updateApiKey(id: string, data: IUpdateApiKeyRequest): Promise<IApiKey> {
    const updateData: any = {
      updatedAt: new Date(),
    };

    if (data.name) updateData.name = data.name;
    if (data.type) updateData.type = data.type;
    if (data.status) updateData.status = data.status;
    if (data.permissions) updateData.permissions = JSON.stringify(data.permissions);
    if (data.isActive !== undefined) updateData.isActive = data.isActive;
    if (data.expiresAt) updateData.expiresAt = data.expiresAt;

    const updatedKey = await prisma.apiKey.update({
      where: { id },
      data: updateData,
    });
    
    return {
      ...updatedKey,
      permissions: JSON.parse(updatedKey.permissions),
    } as IApiKey;
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