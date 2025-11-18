import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export const apiKeyQueries = {
  async createApiKey(data: any) {
    return await prisma.apiKey.create({
      data: {
        ...data,
        permissions: data.permissions || [],
      },
    });
  },

  async getApiKeyById(id: string) {
    return await prisma.apiKey.findUnique({
      where: { id },
    });
  },

  async getApiKeyByKey(key: string) {
    return await prisma.apiKey.findUnique({
      where: { key },
    });
  },

  async getApiKeysByOrganization(organizationId: string) {
    return await prisma.apiKey.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
    });
  },

  async updateApiKey(id: string, data: any) {
    return await prisma.apiKey.update({
      where: { id },
      data: {
        ...data,
        updatedAt: new Date(),
      },
    });
  },

  async deleteApiKey(id: string) {
    return await prisma.apiKey.delete({
      where: { id },
    });
  },

  async updateLastUsed(id: string) {
    return await prisma.apiKey.update({
      where: { id },
      data: { lastUsedAt: new Date() },
    });
  },
};