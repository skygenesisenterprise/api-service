import { Router } from 'express';
import { endpointController } from '../controllers/endpointController';

const router = Router();

// GET /api/v1/endpoints - Get all endpoints
router.get('/', endpointController.getAllEndpoints);

// GET /api/v1/endpoints/:id - Get endpoint by ID
router.get('/:id', endpointController.getEndpointById);

// POST /api/v1/endpoints - Create new endpoint
router.post('/', endpointController.createEndpoint);

// PUT /api/v1/endpoints/:id - Update endpoint
router.put('/:id', endpointController.updateEndpoint);

// DELETE /api/v1/endpoints/:id - Delete endpoint
router.delete('/:id', endpointController.deleteEndpoint);

// GET /api/v1/endpoints/:id/metrics - Get endpoint metrics
router.get('/:id/metrics', endpointController.getEndpointMetrics);

// GET /api/v1/endpoints/:id/calls - Get endpoint calls
router.get('/:id/calls', endpointController.getEndpointCalls);

// POST /api/v1/endpoints/:id/test - Test endpoint
router.post('/:id/test', endpointController.testEndpoint);

export default router;