import { Router } from 'express';
import { projectController } from '../controllers/projectController';

const router = Router();

// GET /api/v1/projects - Get all projects
router.get('/', projectController.getAllProjects);

// GET /api/v1/projects/:id - Get project by ID
router.get('/:id', projectController.getProjectById);

// POST /api/v1/projects - Create new project
router.post('/', projectController.createProject);

// PUT /api/v1/projects/:id - Update project
router.put('/:id', projectController.updateProject);

// DELETE /api/v1/projects/:id - Delete project
router.delete('/:id', projectController.deleteProject);

// GET /api/v1/projects/:id/services - Get project services
router.get('/:id/services', projectController.getProjectServices);

// GET /api/v1/projects/:id/endpoints - Get project endpoints
router.get('/:id/endpoints', projectController.getProjectEndpoints);

// GET /api/v1/projects/:id/stats - Get project stats
router.get('/:id/stats', projectController.getProjectStats);

export default router;