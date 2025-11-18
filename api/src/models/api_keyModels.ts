export enum ApiKeyCategory {
  CLIENT = 'client',
  SERVER = 'server',
  DATABASE = 'database'
}

export enum ApiKeyPermission {
  READ = 'read',
  WRITE = 'write',
  DELETE = 'delete',
  ADMIN = 'admin'
}

export interface IApiKey {
  id: string;
  key: string;
  name: string;
  category: ApiKeyCategory;
  permissions: ApiKeyPermission[];
  organizationId: string;
  userId?: string;
  isActive: boolean;
  expiresAt?: Date;
  lastUsedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface ICreateApiKeyRequest {
  name: string;
  category: ApiKeyCategory;
  permissions: ApiKeyPermission[];
  organizationId: string;
  userId?: string;
  expiresAt?: Date;
}

export interface IUpdateApiKeyRequest {
  name?: string;
  permissions?: ApiKeyPermission[];
  isActive?: boolean;
  expiresAt?: Date;
}

export interface IApiKeyService {
  createApiKey(data: ICreateApiKeyRequest): Promise<IApiKey>;
  getApiKeyById(id: string): Promise<IApiKey | null>;
  getApiKeyByKey(key: string): Promise<IApiKey | null>;
  getApiKeysByOrganization(organizationId: string): Promise<IApiKey[]>;
  updateApiKey(id: string, data: IUpdateApiKeyRequest): Promise<IApiKey>;
  deleteApiKey(id: string): Promise<void>;
  validateApiKey(key: string, requiredPermission?: ApiKeyPermission): Promise<IApiKey | null>;
  updateLastUsed(id: string): Promise<void>;
}