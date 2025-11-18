import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { ApiKeyService } from '../services/api_keyServices';
import { ApiKeyCategory, ApiKeyPermission } from '../models/api_keyModels';

jest.mock('@prisma/client', () => ({
  PrismaClient: jest.fn().mockImplementation(() => ({
    apiKey: {
      create: jest.fn(),
      findUnique: jest.fn(),
      findMany: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    },
  })),
}));

describe('ApiKeyService', () => {
  let apiKeyService: ApiKeyService;
  let mockPrisma: any;

  beforeEach(() => {
    apiKeyService = new ApiKeyService();
    mockPrisma = (apiKeyService as any).prisma;
  });

  describe('createApiKey', () => {
    it('should create an API key with correct format', async () => {
      const createData = {
        name: 'Test Key',
        category: ApiKeyCategory.CLIENT,
        permissions: [ApiKeyPermission.READ],
        organizationId: 'org-123',
      };

      const expectedApiKey = {
        id: 'key-123',
        key: 'sk_client_abc123_def456...',
        name: 'Test Key',
        category: ApiKeyCategory.CLIENT,
        permissions: [ApiKeyPermission.READ],
        organizationId: 'org-123',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockPrisma.apiKey.create.mockResolvedValue(expectedApiKey);

      const result = await apiKeyService.createApiKey(createData);

      expect(result).toEqual(expectedApiKey);
      expect(result.key).toMatch(/^sk_client_[a-z0-9]+_[a-f0-9]+$/);
      expect(mockPrisma.apiKey.create).toHaveBeenCalledWith({
        data: {
          ...createData,
          key: expect.stringMatching(/^sk_client_[a-z0-9]+_[a-f0-9]+$/),
          isActive: true,
        },
      });
    });
  });

  describe('validateApiKey', () => {
    it('should validate a valid API key', async () => {
      const validKey = {
        id: 'key-123',
        key: 'sk_client_abc123_def456',
        isActive: true,
        permissions: [ApiKeyPermission.READ],
        expiresAt: null,
      };

      mockPrisma.apiKey.findUnique.mockResolvedValue(validKey);
      mockPrisma.apiKey.update.mockResolvedValue({});

      const result = await apiKeyService.validateApiKey('sk_client_abc123_def456');

      expect(result).toEqual(validKey);
      expect(mockPrisma.apiKey.update).toHaveBeenCalledWith({
        where: { id: 'key-123' },
        data: { lastUsedAt: expect.any(Date) },
      });
    });

    it('should reject inactive API key', async () => {
      const inactiveKey = {
        id: 'key-123',
        key: 'sk_client_abc123_def456',
        isActive: false,
        permissions: [ApiKeyPermission.READ],
      };

      mockPrisma.apiKey.findUnique.mockResolvedValue(inactiveKey);

      const result = await apiKeyService.validateApiKey('sk_client_abc123_def456');

      expect(result).toBeNull();
    });

    it('should reject expired API key', async () => {
      const expiredKey = {
        id: 'key-123',
        key: 'sk_client_abc123_def456',
        isActive: true,
        permissions: [ApiKeyPermission.READ],
        expiresAt: new Date('2023-01-01'),
      };

      mockPrisma.apiKey.findUnique.mockResolvedValue(expiredKey);

      const result = await apiKeyService.validateApiKey('sk_client_abc123_def456');

      expect(result).toBeNull();
    });
  });
});