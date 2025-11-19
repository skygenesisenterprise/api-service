import { Request, Response } from 'express';
import { endpointService } from '../services/endpointService';
import { ApiResponse } from '../utils/apiResponse';

export const endpointController = {
  // Get all endpoints with pagination and filters
  async getAllEndpoints(req: Request, res: Response) {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const search = req.query.search as string || '';
      const method = req.query.method as string || '';
      const service = req.query.service as string || '';
      const status = req.query.status as string || '';
      const projectId = req.query.projectId as string;
      const skip = (page - 1) * limit;

      const result = await endpointService.getAllEndpoints({
        page,
        limit,
        search,
        method,
        service,
        status,
        projectId,
        skip,
      });

      return ApiResponse.success(res, result, 'Endpoints retrieved successfully');
    } catch (error) {
      console.error('Error fetching endpoints:', error);
      return ApiResponse.error(res, 'Failed to fetch endpoints', 500);
    }
  },

  // Get endpoint by ID
  async getEndpointById(req: Request, res: Response) {
    try {
      const { id } = req.params;
      
      const endpoint = await endpointService.getEndpointById(id);
      
      if (!endpoint) {
        return ApiResponse.error(res, 'Endpoint not found', 404);
      }

      return ApiResponse.success(res, endpoint, 'Endpoint retrieved successfully');
    } catch (error) {
      console.error('Error fetching endpoint:', error);
      return ApiResponse.error(res, 'Failed to fetch endpoint', 500);
    }
  },

  // Create new endpoint
  async createEndpoint(req: Request, res: Response) {
    try {
      const endpointData = req.body;
      
      const endpoint = await endpointService.createEndpoint(endpointData);
      
      return ApiResponse.success(res, endpoint, 'Endpoint created successfully', 201);
    } catch (error) {
      console.error('Error creating endpoint:', error);
      return ApiResponse.error(res, 'Failed to create endpoint', 500);
    }
  },

  // Update endpoint
  async updateEndpoint(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const updateData = req.body;
      
      const endpoint = await endpointService.updateEndpoint(id, updateData);
      
      if (!endpoint) {
        return ApiResponse.error(res, 'Endpoint not found', 404);
      }

      return ApiResponse.success(res, endpoint, 'Endpoint updated successfully');
    } catch (error) {
      console.error('Error updating endpoint:', error);
      return ApiResponse.error(res, 'Failed to update endpoint', 500);
    }
  },

  // Delete endpoint
  async deleteEndpoint(req: Request, res: Response) {
    try {
      const { id } = req.params;
      
      const success = await endpointService.deleteEndpoint(id);
      
      if (!success) {
        return ApiResponse.error(res, 'Endpoint not found', 404);
      }

      return ApiResponse.success(res, null, 'Endpoint deleted successfully');
    } catch (error) {
      console.error('Error deleting endpoint:', error);
      return ApiResponse.error(res, 'Failed to delete endpoint', 500);
    }
  },

  // Get endpoint metrics
  async getEndpointMetrics(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const timeRange = req.query.timeRange as string || '24h';
      
      const metrics = await endpointService.getEndpointMetrics(id, timeRange);
      
      return ApiResponse.success(res, metrics, 'Endpoint metrics retrieved successfully');
    } catch (error) {
      console.error('Error fetching endpoint metrics:', error);
      return ApiResponse.error(res, 'Failed to fetch endpoint metrics', 500);
    }
  },

  // Get endpoint calls
  async getEndpointCalls(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 50;
      const skip = (page - 1) * limit;
      
      const result = await endpointService.getEndpointCalls(id, { page, limit, skip });
      
      return ApiResponse.success(res, result, 'Endpoint calls retrieved successfully');
    } catch (error) {
      console.error('Error fetching endpoint calls:', error);
      return ApiResponse.error(res, 'Failed to fetch endpoint calls', 500);
    }
  },

  // Test endpoint
  async testEndpoint(req: Request, res: Response) {
    try {
      const { id } = req.params;
      const testConfig = req.body;
      
      const result = await endpointService.testEndpoint(id, testConfig);
      
      return ApiResponse.success(res, result, 'Endpoint test completed successfully');
    } catch (error) {
      console.error('Error testing endpoint:', error);
      return ApiResponse.error(res, 'Failed to test endpoint', 500);
    }
  },
};