import { Request, Response, NextFunction } from 'express';
import { ApiKeyService } from '../services/api_keyServices';
import { ApiKeyPermission } from '../models/api_keyModels';

const apiKeyService = new ApiKeyService();

export interface AuthenticatedRequest extends Request {
  apiKey?: any;
}

export const authenticateApiKey = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const xApiKey = req.headers['x-api-key'] as string;
    const queryApiKey = req.query.api_key as string;

    let apiKey: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      apiKey = authHeader.substring(7);
    } else if (xApiKey) {
      apiKey = xApiKey;
    } else if (queryApiKey) {
      apiKey = queryApiKey;
    }

    if (!apiKey) {
      res.status(401).json({ error: 'API key required' });
      return;
    }

    if (!apiKey.startsWith('sk_')) {
      res.status(401).json({ error: 'Invalid API key format' });
      return;
    }

    const validApiKey = await apiKeyService.validateApiKey(apiKey);
    
    if (!validApiKey) {
      res.status(401).json({ error: 'Invalid or expired API key' });
      return;
    }

    (req as AuthenticatedRequest).apiKey = validApiKey;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const requirePermission = (permission: ApiKeyPermission) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const apiKey = (req as AuthenticatedRequest).apiKey;
    
    if (!apiKey) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (!apiKey.permissions.includes(permission) && !apiKey.permissions.includes(ApiKeyPermission.ADMIN)) {
      res.status(403).json({ error: `Insufficient permissions. Required: ${permission}` });
      return;
    }

    next();
  };
};

export const requireCategory = (category: string) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const apiKey = (req as AuthenticatedRequest).apiKey;
    
    if (!apiKey) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (apiKey.category !== category) {
      res.status(403).json({ error: `API key category '${category}' required` });
      return;
    }

    next();
  };
};