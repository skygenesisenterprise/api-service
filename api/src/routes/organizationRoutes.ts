import { Router } from 'express';
import { organizationController } from '../controllers/organizationController';

const router = Router();

// GET /api/v1/organizations - Get all organizations
router.get('/', organizationController.getAllOrganizations);

// GET /api/v1/organizations/:id - Get organization by ID
router.get('/:id', organizationController.getOrganizationById);

// POST /api/v1/organizations - Create new organization
router.post('/', organizationController.createOrganization);

// PUT /api/v1/organizations/:id - Update organization
router.put('/:id', organizationController.updateOrganization);

// DELETE /api/v1/organizations/:id - Delete organization
router.delete('/:id', organizationController.deleteOrganization);

// GET /api/v1/organizations/:id/workspaces - Get organization workspaces
router.get('/:id/workspaces', organizationController.getOrganizationWorkspaces);

// GET /api/v1/organizations/:id/stats - Get organization stats
router.get('/:id/stats', organizationController.getOrganizationStats);

export default router;