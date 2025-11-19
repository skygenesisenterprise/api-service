import { Request, Response } from 'express';
import { organizationService } from '../services/organizationService';
import { ApiResponse } from '../utils/apiResponse';

export const organizationController = {
  // Get all organizations with pagination
  async getAllOrganizations(req: Request, res: Response) {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const search = req.query.search as string || '';
      const skip = (page - 1) * limit;

      const result = await organizationService.getAllOrganizations({
        page,
        limit,
        search,
        skip,
      });

      return ApiResponse.success(res, result, 'Organizations retrieved successfully');
    } catch (error) {
      console.error('Error fetching organizations:', error);
      return ApiResponse.error(res, 'Failed to fetch organizations', 500);
    }
  },

  // Get organization by ID
  async getOrganizationById(req: Request, res: Response) {
    try {
      const { id } = req.params;
      
      const organization = await organizationService.getOrganizationById(id);
      
      if (!organization) {
        return ApiResponse.error(res, 'Organization not found', 404);
      }

      return ApiResponse.success(res, organization, 'Organization retrieved successfully');
    } catch (error) {
      console.error('Error fetching organization:', error);
      return ApiResponse.error(res, 'Failed to fetch organization', 500);
    }
  },

  // Create new organization
  async createOrganization(req: Request, res: Response) {
    try {
      const organizationData = req.body;
      
      const organization = await organizationService.createOrganization(organizationData);
      
      return ApiResponse.success(res, organization, 'Organization created successfully', 201);
    } catch (error) {
      console.error('Error creating organization:', error);
      return ApiResponse.error(res, 'Failed to create organization', 500);
    }
  },

  // Update organization
  async updateOrganization(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const updateData = req.body;
      
      const organization = await organizationService.updateOrganization(id, updateData);
      
      if (!organization) {
        return ApiResponse.error(res, 'Organization not found', 404);
      }

      return ApiResponse.success(res, organization, 'Organization updated successfully');
    } catch (error) {
      console.error('Error updating organization:', error);
      return ApiResponse.error(res, 'Failed to update organization', 500);
    }
  },

  // Delete organization
  async deleteOrganization(req: Request, res: Response) {
    try {
      const { id } = req.params;
      
      const success = await organizationService.deleteOrganization(id);
      
      if (!success) {
        return ApiResponse.error(res, 'Organization not found', 404);
      }

      return ApiResponse.success(res, null, 'Organization deleted successfully');
    } catch (error) {
      console.error('Error deleting organization:', error);
      return ApiResponse.error(res, 'Failed to delete organization', 500);
    }
  },

  // Get organization workspaces
  async getOrganizationWorkspaces(req: Request, res: Response) {
    try {
      const { id } = req.params;
      
      const workspaces = await organizationService.getOrganizationWorkspaces(id);
      
      return ApiResponse.success(res, workspaces, 'Workspaces retrieved successfully');
    } catch (error) {
      console.error('Error fetching workspaces:', error);
      return ApiResponse.error(res, 'Failed to fetch workspaces', 500);
    }
  },

  // Get organization stats
  async getOrganizationStats(req: Request, res: Response) {
    try {
      const { id } = req.params;
      
      const stats = await organizationService.getOrganizationStats(id);
      
      return ApiResponse.success(res, stats, 'Organization stats retrieved successfully');
    } catch (error) {
      console.error('Error fetching organization stats:', error);
      return ApiResponse.error(res, 'Failed to fetch organization stats', 500);
    }
  },
};