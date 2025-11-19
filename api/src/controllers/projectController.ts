import { Request, Response } from 'express';
import { projectService } from '../services/projectService';
import { ApiResponse } from '../utils/apiResponse';

export const projectController = {
  // Get all projects with pagination and filters
  async getAllProjects(req: Request, res: Response) {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const search = req.query.search as string || '';
      const status = req.query.status as string || '';
      const workspaceId = req.query.workspaceId as string;
      const organizationId = req.query.organizationId as string;
      const skip = (page - 1) * limit;

      const result = await projectService.getAllProjects({
        page,
        limit,
        search,
        status,
        workspaceId,
        organizationId,
        skip,
      });

      return ApiResponse.success(res, result, 'Projects retrieved successfully');
    } catch (error) {
      console.error('Error fetching projects:', error);
      return ApiResponse.error(res, 'Failed to fetch projects', 500);
    }
  },

  // Get project by ID
  async getProjectById(req: Request, res: Response) {
    try {
      const { id } = req.params;
      
      const project = await projectService.getProjectById(id);
      
      if (!project) {
        return ApiResponse.error(res, 'Project not found', 404);
      }

      return ApiResponse.success(res, project, 'Project retrieved successfully');
    } catch (error) {
      console.error('Error fetching project:', error);
      return ApiResponse.error(res, 'Failed to fetch project', 500);
    }
  },

  // Create new project
  async createProject(req: Request, res: Response) {
    try {
      const projectData = req.body;
      
      const project = await projectService.createProject(projectData);
      
      return ApiResponse.success(res, project, 'Project created successfully', 201);
    } catch (error) {
      console.error('Error creating project:', error);
      return ApiResponse.error(res, 'Failed to create project', 500);
    }
  },

  // Update project
  async updateProject(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const updateData = req.body;
      
      const project = await projectService.updateProject(id, updateData);
      
      if (!project) {
        return ApiResponse.error(res, 'Project not found', 404);
      }

      return ApiResponse.success(res, project, 'Project updated successfully');
    } catch (error) {
      console.error('Error updating project:', error);
      return ApiResponse.error(res, 'Failed to update project', 500);
    }
  },

  // Delete project
  async deleteProject(req: Request, res: Response) {
    try {
      const { id } = req.params;
      
      const success = await projectService.deleteProject(id);
      
      if (!success) {
        return ApiResponse.error(res, 'Project not found', 404);
      }

      return ApiResponse.success(res, null, 'Project deleted successfully');
    } catch (error) {
      console.error('Error deleting project:', error);
      return ApiResponse.error(res, 'Failed to delete project', 500);
    }
  },

  // Get project services
  async getProjectServices(req: Request, res: Response) {
    try {
      const { id } = req.params;
      
      const services = await projectService.getProjectServices(id);
      
      return ApiResponse.success(res, services, 'Project services retrieved successfully');
    } catch (error) {
      console.error('Error fetching project services:', error);
      return ApiResponse.error(res, 'Failed to fetch project services', 500);
    }
  },

  // Get project endpoints
  async getProjectEndpoints(req: Request, res: Response) {
    try {
      const { id } = req.params;
      
      const endpoints = await projectService.getProjectEndpoints(id);
      
      return ApiResponse.success(res, endpoints, 'Project endpoints retrieved successfully');
    } catch (error) {
      console.error('Error fetching project endpoints:', error);
      return ApiResponse.error(res, 'Failed to fetch project endpoints', 500);
    }
  },

  // Get project stats
  async getProjectStats(req: Request, res: Response) {
    try {
      const { id } = req.params;
      
      const stats = await projectService.getProjectStats(id);
      
      return ApiResponse.success(res, stats, 'Project stats retrieved successfully');
    } catch (error) {
      console.error('Error fetching project stats:', error);
      return ApiResponse.error(res, 'Failed to fetch project stats', 500);
    }
  },
};