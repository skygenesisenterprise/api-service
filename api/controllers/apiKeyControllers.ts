import { Request, Response } from 'express';
import { ApiKeyService } from '../services/apiKeyService';

export const createApiKey = async (req: Request, res: Response) => {
  try {
    const { organization_id } = req.params;
    const apiKeyData = (req as any).apiKey;
    const { label, permissions } = req.body;

    // Verify the API key belongs to the organization (or has admin permissions)
    if (apiKeyData.organization_id !== organization_id && !apiKeyData.permissions.includes('*')) {
      return res.status(403).json({ error: 'Insufficient permissions to create API keys for this organization' });
    }

    const apiKey = await ApiKeyService.createApiKey(
      organization_id,
      label,
      permissions || ['read']
    );

    return res.status(201).json({
      message: 'API key created successfully',
      data: {
        id: apiKey.id,
        key_value: apiKey.key_value,
        label: apiKey.label,
        permissions: apiKey.permissions,
        created_at: apiKey.created_at
      }
    });
  } catch (error) {
    console.error('Create API key error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const getApiKeys = async (req: Request, res: Response) => {
  try {
    const { organization_id } = req.params;
    const apiKeyData = (req as any).apiKey;

    // Verify the API key belongs to the organization
    if (apiKeyData.organization_id !== organization_id && !apiKeyData.permissions.includes('*')) {
      return res.status(403).json({ error: 'Insufficient permissions to view API keys for this organization' });
    }

    const apiKeys = await ApiKeyService.getApiKeysForOrganization(organization_id);

    // Don't return the actual key values in the response for security
    const sanitizedKeys = apiKeys.map(key => ({
      id: key.id,
      label: key.label,
      permissions: key.permissions,
      quota_limit: key.quota_limit,
      usage_count: key.usage_count,
      status: key.status,
      created_at: key.created_at
    }));

    return res.status(200).json({ data: sanitizedKeys });
  } catch (error) {
    console.error('Get API keys error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const revokeApiKey = async (req: Request, res: Response) => {
  try {
    const { organization_id, key_id } = req.params;
    const apiKeyData = (req as any).apiKey;

    // Verify the API key belongs to the organization (or has admin permissions)
    if (apiKeyData.organization_id !== organization_id && !apiKeyData.permissions.includes('*')) {
      return res.status(403).json({ error: 'Insufficient permissions to revoke API keys for this organization' });
    }

    const success = await ApiKeyService.revokeApiKey(key_id, organization_id);
    if (!success) {
      return res.status(404).json({ error: 'API key not found' });
    }

    return res.status(200).json({ message: 'API key revoked successfully' });
  } catch (error) {
    console.error('Revoke API key error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const validateApiKey = async (req: Request, res: Response) => {
  try {
    const apiKeyData = (req as any).apiKey;

    return res.status(200).json({
      message: 'API key is valid',
      data: {
        organization_id: apiKeyData.organization_id,
        permissions: apiKeyData.permissions,
        quota_limit: apiKeyData.quota_limit,
        usage_count: apiKeyData.usage_count
      }
    });
  } catch (error) {
    console.error('Validate API key error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};