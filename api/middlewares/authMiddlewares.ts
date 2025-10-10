import { Request, Response, NextFunction } from 'express';
import { ApiKeyService, ApiKeyData } from '../services/apiKeyService';

export const validateAuthRequest = (req: Request, res: Response, next: NextFunction) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  next();
};

export const authenticateApiKey = async (req: Request, res: Response, next: NextFunction) => {
  const apiKey = req.headers['x-api-key'] as string ||
                 req.headers['authorization']?.replace('Bearer ', '') ||
                 req.query.api_key as string;

  if (!apiKey) {
    return res.status(401).json({
      error: 'API key required',
      message: 'Please provide an API key in X-API-Key header, Authorization header, or api_key query parameter'
    });
  }

  try {
    const apiKeyData = await ApiKeyService.validateApiKey(apiKey);

    if (!apiKeyData) {
      return res.status(401).json({
        error: 'Invalid API key',
        message: 'The provided API key is invalid or inactive'
      });
    }

    // Attach API key data to request
    (req as any).apiKey = apiKeyData;
    (req as any).organization = { id: apiKeyData.organization_id };

    next();
  } catch (error) {
    if (error instanceof Error && error.message === 'API quota exceeded') {
      return res.status(429).json({
        error: 'Quota exceeded',
        message: 'API quota limit has been reached'
      });
    }

    console.error('API key validation error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const requirePermission = (permission: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const apiKeyData = (req as any).apiKey as ApiKeyData;

    if (!apiKeyData) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!ApiKeyService.hasPermission(apiKeyData, permission)) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        message: `Required permission: ${permission}`
      });
    }

    next();
  };
};

export default authenticateApiKey;