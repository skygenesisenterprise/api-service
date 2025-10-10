import pool from '../config/database';

export interface ApiKeyData {
  id: string;
  organization_id: string;
  key_value: string;
  label?: string;
  permissions: string[];
  quota_limit: number;
  usage_count: number;
  status: string;
  created_at: Date;
}

export class ApiKeyService {
  static async validateApiKey(apiKey: string): Promise<ApiKeyData | null> {
    const query = `
      SELECT * FROM api_service.api_keys
      WHERE key_value = $1 AND status = 'active'
    `;

    const result = await pool.query(query, [apiKey]);

    if (result.rows.length === 0) {
      return null;
    }

    const keyData = result.rows[0];

    // Check quota
    if (keyData.usage_count >= keyData.quota_limit) {
      throw new Error('API quota exceeded');
    }

    // Increment usage count
    await this.incrementUsageCount(keyData.id);

    return keyData;
  }

  static async incrementUsageCount(apiKeyId: string): Promise<void> {
    const query = `
      UPDATE api_service.api_keys
      SET usage_count = usage_count + 1
      WHERE id = $1
    `;

    await pool.query(query, [apiKeyId]);
  }

  static hasPermission(apiKeyData: ApiKeyData, requiredPermission: string): boolean {
    return apiKeyData.permissions.includes('*') ||
           apiKeyData.permissions.includes(requiredPermission);
  }

  static async createApiKey(
    organizationId: string,
    label?: string,
    permissions: string[] = ['read']
  ): Promise<ApiKeyData> {
    const keyValue = this.generateApiKey();

    const query = `
      INSERT INTO api_service.api_keys (organization_id, key_value, label, permissions)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `;

    const result = await pool.query(query, [organizationId, keyValue, label, permissions]);
    return result.rows[0];
  }

  static async getApiKeysForOrganization(organizationId: string): Promise<ApiKeyData[]> {
    const query = `
      SELECT * FROM api_service.api_keys
      WHERE organization_id = $1
      ORDER BY created_at DESC
    `;

    const result = await pool.query(query, [organizationId]);
    return result.rows;
  }

  static async revokeApiKey(apiKeyId: string, organizationId: string): Promise<boolean> {
    const query = `
      UPDATE api_service.api_keys
      SET status = 'revoked'
      WHERE id = $1 AND organization_id = $2
    `;

    const result = await pool.query(query, [apiKeyId, organizationId]);
    return (result.rowCount ?? 0) > 0;
  }

  private static generateApiKey(): string {
    // Generate a secure API key
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = 'sk_'; // Prefix for server keys
    for (let i = 0; i < 32; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }
}