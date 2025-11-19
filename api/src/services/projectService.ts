import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export interface ProjectFilters {
  page: number;
  limit: number;
  search: string;
  status: string;
  workspaceId: string;
  organizationId: string;
  skip: number;
}

export interface ProjectStats {
  totalEndpoints: number;
  totalRequests: number;
  totalErrors: number;
  avgLatency: number;
  uptime: number;
  requestsToday: number;
}

export const projectService = {
  // Get all projects with pagination and filters
  async getAllProjects(filters: ProjectFilters) {
    const { page, limit, search, status, workspaceId, organizationId, skip } = filters;
    
    const where = {
      ...(organizationId && { organizationId }),
      ...(workspaceId && { workspaceId }),
      ...(status && { status }),
      ...(search && {
        OR: [
          { name: { contains: search, mode: 'insensitive' as const } },
          { description: { contains: search, mode: 'insensitive' as const } },
        ],
      }),
    };

    const [projects, total] = await Promise.all([
      prisma.project.findMany({
        where,
        include: {
          _count: {
            select: {
              endpoints: true,
            },
          },
          services: true,
          workspace: {
            select: {
              id: true,
              name: true,
              environment: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      prisma.project.count({ where }),
    ]);

    return {
      data: projects,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  },

  // Get project by ID
  async getProjectById(id: string) {
    return await prisma.project.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            endpoints: true,
          },
        },
        services: true,
        workspace: true,
        organization: true,
        creator: {
          select: {
            id: true,
            fullName: true,
            email: true,
          },
        },
        endpoints: {
          include: {
            _count: {
              select: {
                metrics: true,
                calls: true,
              },
            },
          },
        },
      },
    });
  },

  // Create new project
  async createProject(data: {
    name: string;
    description?: string;
    repository?: string;
    website?: string;
    organizationId: string;
    workspaceId: string;
    createdBy: string;
  }) {
    return await prisma.project.create({
      data: {
        name: data.name,
        description: data.description,
        repository: data.repository,
        website: data.website,
        organizationId: data.organizationId,
        workspaceId: data.workspaceId,
        createdBy: data.createdBy,
      },
      include: {
        _count: {
          select: {
            endpoints: true,
          },
        },
        services: true,
        workspace: true,
      },
    });
  },

  // Update project
  async updateProject(id: string, data: {
    name?: string;
    description?: string;
    repository?: string;
    website?: string;
    status?: string;
  }) {
    return await prisma.project.update({
      where: { id },
      data,
      include: {
        _count: {
          select: {
            endpoints: true,
          },
        },
        services: true,
        workspace: true,
      },
    });
  },

  // Delete project
  async deleteProject(id: string) {
    try {
      await prisma.project.delete({
        where: { id },
      });
      return true;
    } catch (error) {
      return false;
    }
  },

  // Get project services
  async getProjectServices(projectId: string) {
    return await prisma.projectService.findMany({
      where: { projectId },
      orderBy: { createdAt: 'desc' },
    });
  },

  // Get project endpoints
  async getProjectEndpoints(projectId: string) {
    return await prisma.endpoint.findMany({
      where: { projectId },
      include: {
        _count: {
          select: {
            metrics: true,
            calls: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });
  },

  // Get project statistics
  async getProjectStats(projectId: string): Promise<ProjectStats> {
    const [
      totalEndpoints,
      todayStats,
      recentMetrics,
    ] = await Promise.all([
      prisma.endpoint.count({
        where: { projectId },
      }),
      prisma.dashboardStats.findFirst({
        where: {
          date: new Date().toISOString().split('T')[0],
        },
      }),
      prisma.endpointMetric.aggregate({
        where: {
          endpoint: {
            projectId,
          },
          timestamp: {
            gte: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
          },
        },
        _avg: {
          avgLatency: true,
        },
        _sum: {
          requests: true,
          errors: true,
        },
      }),
    ]);

    return {
      totalEndpoints,
      totalRequests: todayStats?.totalRequests || recentMetrics?._sum.requests || 0,
      totalErrors: todayStats?.totalErrors || recentMetrics?._sum.errors || 0,
      avgLatency: todayStats?.avgLatency || recentMetrics?._avg.avgLatency || 0,
      uptime: todayStats?.uptime || 100,
      requestsToday: recentMetrics?._sum.requests || 0,
    };
  },
};