import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export interface EndpointFilters {
  page: number;
  limit: number;
  search: string;
  method: string;
  service: string;
  status: string;
  projectId: string;
  skip: number;
}

export interface EndpointStats {
  totalRequests: number;
  totalErrors: number;
  avgLatency: number;
  p95Latency: number;
  p99Latency: number;
  errorRate: number;
  uptime: number;
  requestsToday: number;
}

export interface TestResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: any;
  time: number;
}

export const endpointService = {
  // Get all endpoints with pagination and filters
  async getAllEndpoints(filters: EndpointFilters) {
    const { page, limit, search, method, service, status, projectId, skip } = filters;
    
    const where = {
      ...(projectId && { projectId }),
      ...(method && { method }),
      ...(service && { service }),
      ...(status && { status }),
      ...(search && {
        OR: [
          { name: { contains: search, mode: 'insensitive' as const } },
          { route: { contains: search, mode: 'insensitive' as const } },
          { description: { contains: search, mode: 'insensitive' as const } },
        ],
      }),
    };

    const [endpoints, total] = await Promise.all([
      prisma.endpoint.findMany({
        where,
        include: {
          _count: {
            select: {
              metrics: true,
              calls: true,
            },
          },
          project: {
            select: {
              id: true,
              name: true,
              organizationId: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      prisma.endpoint.count({ where }),
    ]);

    return {
      data: endpoints,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  },

  // Get endpoint by ID
  async getEndpointById(id: string) {
    return await prisma.endpoint.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            metrics: true,
            calls: true,
          },
        },
        project: {
          include: {
            organization: {
              select: {
                id: true,
                name: true,
              },
            },
          },
        },
        metrics: {
          orderBy: { timestamp: 'desc' },
          take: 100,
        },
        calls: {
          orderBy: { timestamp: 'desc' },
          take: 50,
        },
      },
    });
  },

  // Create new endpoint
  async createEndpoint(data: {
    name: string;
    method: string;
    route: string;
    description?: string;
    version?: string;
    projectId: string;
    service: string;
    tags?: string;
    scopes?: string;
    rateLimit?: number;
  }) {
    return await prisma.endpoint.create({
      data: {
        name: data.name,
        method: data.method,
        route: data.route,
        description: data.description,
        version: data.version || 'v1',
        projectId: data.projectId,
        service: data.service,
        tags: data.tags,
        scopes: data.scopes,
        rateLimit: data.rateLimit || 1000,
      },
      include: {
        project: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    });
  },

  // Update endpoint
  async updateEndpoint(id: string, data: {
    name?: string;
    description?: string;
    status?: string;
    tags?: string;
    scopes?: string;
    rateLimit?: number;
    deprecated?: boolean;
  }) {
    return await prisma.endpoint.update({
      where: { id },
      data,
      include: {
        project: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    });
  },

  // Delete endpoint
  async deleteEndpoint(id: string) {
    try {
      await prisma.endpoint.delete({
        where: { id },
      });
      return true;
    } catch (error) {
      return false;
    }
  },

  // Get endpoint metrics
  async getEndpointMetrics(endpointId: string, timeRange: string = '24h') {
    const now = new Date();
    let startTime: Date;

    switch (timeRange) {
      case '1h':
        startTime = new Date(now.getTime() - 60 * 60 * 1000);
        break;
      case '24h':
        startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      default:
        startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    }

    const metrics = await prisma.endpointMetric.findMany({
      where: {
        endpointId,
        timestamp: {
          gte: startTime,
        },
      },
      orderBy: { timestamp: 'desc' },
      take: 1000,
    });

    const recentCalls = await prisma.endpointCall.aggregate({
      where: {
        endpointId,
        timestamp: {
          gte: startTime,
        },
      },
      _sum: {
        requests: true,
        errors: true,
      },
      _avg: {
        avgLatency: true,
      },
    });

    const totalRequests = recentCalls._sum.requests || 0;
    const totalErrors = recentCalls._sum.errors || 0;
    const avgLatency = recentCalls._avg.avgLatency || 0;

    // Calculate percentiles
    const latencies = metrics.map(m => m.avgLatency).filter(l => l > 0);
    latencies.sort((a, b) => a - b);
    
    const p95Index = Math.floor(latencies.length * 0.95);
    const p99Index = Math.floor(latencies.length * 0.99);
    
    const p95Latency = latencies[p95Index] || 0;
    const p99Latency = latencies[p99Index] || 0;

    return {
      metrics,
      stats: {
        totalRequests,
        totalErrors,
        avgLatency,
        p95Latency,
        p99Latency,
        errorRate: totalRequests > 0 ? (totalErrors / totalRequests) * 100 : 0,
        uptime: totalRequests > 0 ? ((totalRequests - totalErrors) / totalRequests) * 100 : 100,
        requestsToday: totalRequests,
      },
    };
  },

  // Get endpoint calls
  async getEndpointCalls(endpointId: string, pagination: { page: number; limit: number; skip: number }) {
    const { page, limit, skip } = pagination;

    const [calls, total] = await Promise.all([
      prisma.endpointCall.findMany({
        where: { endpointId },
        orderBy: { timestamp: 'desc' },
        skip,
        take: limit,
      }),
      prisma.endpointCall.count({
        where: { endpointId },
      }),
    ]);

    return {
      data: calls,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  },

  // Test endpoint (mock implementation)
  async testEndpoint(endpointId: string, config: {
    method?: string;
    headers?: Record<string, string>;
    body?: any;
  }): Promise<TestResult> {
    // Simulate API call
    const startTime = Date.now();
    
    // Mock response based on endpoint
    await new Promise(resolve => setTimeout(resolve, Math.random() * 500 + 100));
    
    const endTime = Date.now();
    const responseTime = endTime - startTime;

    // Mock different response scenarios
    const isSuccess = Math.random() > 0.1; // 90% success rate
    
    return {
      status: isSuccess ? 200 : 500,
      statusText: isSuccess ? 'OK' : 'Internal Server Error',
      headers: {
        'content-type': 'application/json',
        'x-request-id': `req_${Date.now()}`,
        'x-response-time': `${responseTime}ms`,
      },
      body: isSuccess ? {
        message: 'Success',
        data: { test: true, timestamp: new Date().toISOString() },
      } : {
        error: 'Internal Server Error',
        message: 'Simulated error for testing',
      },
      time: responseTime,
    };
  },
};