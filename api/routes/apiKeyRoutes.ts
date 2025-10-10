import express from 'express';
import {
  createApiKey,
  getApiKeys,
  revokeApiKey,
  validateApiKey
} from '../controllers/apiKeyControllers';
import { authenticateApiKey, requirePermission } from '../middlewares/authMiddlewares';

const router = express.Router();

// Apply API key authentication to all routes
router.use(authenticateApiKey);

// API Key management routes
router.post('/organizations/:organization_id/api-keys', requirePermission('admin'), createApiKey);
router.get('/organizations/:organization_id/api-keys', requirePermission('admin'), getApiKeys);
router.delete('/organizations/:organization_id/api-keys/:key_id', requirePermission('admin'), revokeApiKey);

// API Key validation route
router.get('/validate', validateApiKey);

export default router;