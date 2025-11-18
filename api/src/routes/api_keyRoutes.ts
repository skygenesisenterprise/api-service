import { Router, Request, Response } from 'express';
import { ApiKeyService } from '../services/api_keyServices';
import { AuthenticatedRequest } from '../middlewares/api_keyMiddlewares';
import { ICreateApiKeyRequest, IUpdateApiKeyRequest } from '../models/api_keyModels';

const router: Router = Router();
const apiKeyService = new ApiKeyService();

// GET /api/v1/api-keys - List all API keys for an organization
router.get('/', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.apiKey?.permissions.includes('read') && !req.apiKey?.permissions.includes('admin')) {
      res.status(403).json({ error: 'Insufficient permissions' });
      return;
    }

    const { organizationId } = req.query;

    if (!organizationId || typeof organizationId !== 'string') {
      res.status(400).json({ error: 'Organization ID required' });
      return;
    }

    const apiKeys = await apiKeyService.getApiKeysByOrganization(organizationId);
    
    res.status(200).json({ data: apiKeys });
  } catch (error) {
    console.error('Get API keys error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/v1/api-keys - Create a new API key
router.post('/', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.apiKey?.permissions.includes('write') && !req.apiKey?.permissions.includes('admin')) {
      res.status(403).json({ error: 'Insufficient permissions' });
      return;
    }

    const body: ICreateApiKeyRequest = req.body;
    
    if (!body.name || !body.category || !body.permissions || !body.organizationId) {
      res.status(400).json({ 
        error: 'Missing required fields: name, category, permissions, organizationId' 
      });
      return;
    }

    const apiKey = await apiKeyService.createApiKey(body);
    
    res.status(201).json({ data: apiKey });
  } catch (error) {
    console.error('Create API key error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/v1/api-keys/:id - Get a specific API key
router.get('/:id', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.apiKey?.permissions.includes('read') && !req.apiKey?.permissions.includes('admin')) {
      res.status(403).json({ error: 'Insufficient permissions' });
      return;
    }

    const apiKey = await apiKeyService.getApiKeyById(req.params.id);
    
    if (!apiKey) {
      res.status(404).json({ error: 'API key not found' });
      return;
    }
    
    res.status(200).json({ data: apiKey });
  } catch (error) {
    console.error('Get API key error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/v1/api-keys/:id - Update an API key
router.put('/:id', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.apiKey?.permissions.includes('write') && !req.apiKey?.permissions.includes('admin')) {
      res.status(403).json({ error: 'Insufficient permissions' });
      return;
    }

    const body: IUpdateApiKeyRequest = req.body;
    
    const apiKey = await apiKeyService.updateApiKey(req.params.id, body);
    
    res.status(200).json({ data: apiKey });
  } catch (error) {
    console.error('Update API key error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/v1/api-keys/:id - Delete an API key
router.delete('/:id', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.apiKey?.permissions.includes('delete') && !req.apiKey?.permissions.includes('admin')) {
      res.status(403).json({ error: 'Insufficient permissions' });
      return;
    }

    await apiKeyService.deleteApiKey(req.params.id);
    
    res.status(200).json({ message: 'API key deleted successfully' });
  } catch (error) {
    console.error('Delete API key error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;