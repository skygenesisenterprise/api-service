import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export interface OrganizationFilters {
  page: number;
  limit: number;
  search: string;
  skip: number;
}

export interface OrganizationStats {
  totalProjects: number;
  totalEndpoints: number;
  totalUsers: number;
  totalWorkspaces: number;
  avgLatency: number;
  uptime: number;
  requestsToday: number;
}

export const organizationService = {
  // Get all organizations with pagination and search
  async getAllOrganizations(filters: OrganizationFilters) {
    const { page, limit, search, skip } = filters;
    
    const where = search
      ? {
          OR: [
            { name: { contains: search, mode: 'insensitive' as const } },
          ],
        }
      : {};

    const [organizations, total] = await Promise.all([
      prisma.organization.findMany({
        where,
        include: {
          _count: {
            select: {
              users: true,
              workspaces: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      prisma.organization.count({ where }),
    ]);

    return {
      data: organizations,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  },

  // Get organization by ID
  async getOrganizationById(id: string) {
    return await prisma.organization.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            users: true,
            workspaces: true,
          },
        },
        workspaces: {
          include: {
            _count: {
              select: {
                projects: true,
              },
            },
          },
        },
      },
    });
  },

  // Create new organization
  async createOrganization(data: {
    name: string;
    logo?: string;
    website?: string;
  }) {
    return await prisma.organization.create({
      data: {
        name: data.name,
        logo: data.logo,
        website: data.website,
      },
      include: {
        _count: {
          select: {
            users: true,
            workspaces: true,
          },
        },
      },
    });
  },

  // Update organization
  async updateOrganization(id: string, data: {
    name?: string;
    logo?: string;
    website?: string;
  }) {
    return await prisma.organization.update({
      where: { id },
      data,
      include: {
        _count: {
          select: {
            users: true,
            workspaces: true,
          },
        },
      },
    });
  },

  // Delete organization
  async deleteOrganization(id: string) {
    try {
      await prisma.organization.delete({
        where: { id },
      });
      return true;
    } catch (error) {
      return false;
    }
  },

  // Get organization workspaces
  async getOrganizationWorkspaces(organizationId: string) {
    return await prisma.workspace.findMany({
      where: { organizationId },
      include: {
        _count: {
          select: {
            projects: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });
  },

  // Get organization statistics
  async getOrganizationStats(organizationId: string): Promise<OrganizationStats> {
    const [
      totalProjects,
      totalEndpoints,
      totalUsers,
      totalWorkspaces,
      todayStats,
    ] = await Promise.all([
      prisma.project.count({
        where: { organizationId },
      }),
      prisma.endpoint.count({
        where: {
          project: {
            organizationId,
          },
        },
      }),
      prisma.user.count({
        where: { organizationId },
      }),
      prisma.workspace.count({
        where: { organizationId },
      }),
      prisma.dashboardStats.findFirst({
        where: {
          organizationId,
          date: new Date().toISOString().split('T')[0],
        },
      }),
    ]);

    return {
      totalProjects,
      totalEndpoints,
      totalUsers,
      totalWorkspaces,
      avgLatency: todayStats?.avgLatency || 0,
      uptime: todayStats?.uptime || 100,
      requestsToday: todayStats?.totalRequests || 0,
    };
  },
};