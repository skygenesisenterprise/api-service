import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function seedDatabase() {
  console.log('🌱 Starting database seeding...');

  try {
    // Clean existing data
    await prisma.dashboardStats.deleteMany();
    await prisma.endpointCall.deleteMany();
    await prisma.endpointMetric.deleteMany();
    await prisma.projectService.deleteMany();
    await prisma.endpoint.deleteMany();
    await prisma.project.deleteMany();
    await prisma.workspace.deleteMany();
    await prisma.user.deleteMany();
    await prisma.apiKey.deleteMany();
    await prisma.organization.deleteMany();

    console.log('🧹 Cleaned existing data');

    // Create Organizations
    const organizations = await Promise.all([
      prisma.organization.create({
        data: {
          name: 'Sky Genesis Enterprise',
          website: 'https://skygenesis.com',
        },
      }),
      prisma.organization.create({
        data: {
          name: 'TechCorp Solutions',
          website: 'https://techcorp.com',
        },
      }),
      prisma.organization.create({
        data: {
          name: 'Digital Innovations Lab',
          website: 'https://digitalinnovations.io',
        },
      }),
    ]);

    console.log('🏢 Created organizations');

    // Create Users
    const users = await Promise.all([
      prisma.user.create({
        data: {
          email: 'admin@skygenesis.com',
          fullName: 'John Administrator',
          role: 'admin',
          organizationId: organizations[0].id,
          passwordHash: 'hashed_password_here',
        },
      }),
      prisma.user.create({
        data: {
          email: 'dev@techcorp.com',
          fullName: 'Sarah Developer',
          role: 'user',
          organizationId: organizations[1].id,
          passwordHash: 'hashed_password_here',
        },
      }),
      prisma.user.create({
        data: {
          email: 'user@digitalinnovations.io',
          fullName: 'Mike User',
          role: 'user',
          organizationId: organizations[2].id,
          passwordHash: 'hashed_password_here',
        },
      }),
    ]);

    console.log('👥 Created users');

    // Create Workspaces
    const workspaces = await Promise.all([
      prisma.workspace.create({
        data: {
          name: 'Development',
          slug: 'dev-skygenesis',
          environment: 'development',
          organizationId: organizations[0].id,
        },
      }),
      prisma.workspace.create({
        data: {
          name: 'Staging',
          slug: 'staging-skygenesis',
          environment: 'staging',
          organizationId: organizations[0].id,
        },
      }),
      prisma.workspace.create({
        data: {
          name: 'Production',
          slug: 'prod-skygenesis',
          environment: 'production',
          organizationId: organizations[0].id,
        },
      }),
      prisma.workspace.create({
        data: {
          name: 'Dev Environment',
          slug: 'dev-techcorp',
          environment: 'development',
          organizationId: organizations[1].id,
        },
      }),
    ]);

    console.log('🗂️ Created workspaces');

    // Create Projects
    const projects = await Promise.all([
      prisma.project.create({
        data: {
          name: 'E-commerce Platform',
          slug: 'ecommerce-platform',
          description: 'Production e-commerce platform with real-time inventory management',
          status: 'active',
          repository: 'https://github.com/skygenesis/ecommerce',
          website: 'https://shop.skygenesis.com',
          organizationId: organizations[0].id,
          workspaceId: workspaces[2].id, // Production
          createdBy: users[0].id,
        },
      }),
      prisma.project.create({
        data: {
          name: 'Mobile App Backend',
          slug: 'mobile-app-backend',
          description: 'Backend services for iOS and Android mobile applications',
          status: 'active',
          repository: 'https://github.com/skygenesis/mobile-backend',
          organizationId: organizations[0].id,
          workspaceId: workspaces[2].id,
          createdBy: users[0].id,
        },
      }),
      prisma.project.create({
        data: {
          name: 'Analytics Service',
          slug: 'analytics-service',
          description: 'Data processing and analytics pipeline for business intelligence',
          status: 'active',
          repository: 'https://github.com/skygenesis/analytics',
          organizationId: organizations[0].id,
          workspaceId: workspaces[1].id, // Staging
          createdBy: users[0].id,
        },
      }),
      prisma.project.create({
        data: {
          name: 'Admin Dashboard',
          slug: 'admin-dashboard',
          description: 'Internal administration dashboard for system management',
          status: 'active',
          repository: 'https://github.com/skygenesis/admin-dashboard',
          organizationId: organizations[0].id,
          workspaceId: workspaces[0].id, // Development
          createdBy: users[0].id,
        },
      }),
      prisma.project.create({
        data: {
          name: 'API Gateway',
          slug: 'api-gateway',
          description: 'Central API gateway for microservices architecture',
          status: 'active',
          repository: 'https://github.com/techcorp/api-gateway',
          organizationId: organizations[1].id,
          workspaceId: workspaces[3].id,
          createdBy: users[1].id,
        },
      }),
    ]);

    console.log('📁 Created projects');

    // Create Project Services
    const projectServices = await Promise.all([
      // E-commerce Platform services
      prisma.projectService.createMany({
        data: [
          {
            projectId: projects[0].id,
            name: 'Grafana',
            type: 'grafana',
            status: 'connected',
            endpoint: 'grafana.skygenesis.com',
            version: '9.5.0',
          },
          {
            projectId: projects[0].id,
            name: 'Prometheus',
            type: 'prometheus',
            status: 'connected',
            endpoint: 'prometheus.skygenesis.com',
            version: '2.45.0',
          },
          {
            projectId: projects[0].id,
            name: 'MinIO',
            type: 'minio',
            status: 'connected',
            endpoint: 'minio.skygenesis.com',
            version: 'RELEASE.2023-12-23T01-27-55Z',
          },
        ],
      }),
      // Mobile App Backend services
      prisma.projectService.createMany({
        data: [
          {
            projectId: projects[1].id,
            name: 'Grafana',
            type: 'grafana',
            status: 'connected',
            endpoint: 'grafana.mobile.skygenesis.com',
            version: '9.5.0',
          },
          {
            projectId: projects[1].id,
            name: 'Vault',
            type: 'vault',
            status: 'connected',
            endpoint: 'vault.mobile.skygenesis.com',
            version: '1.14.0',
          },
        ],
      }),
      // Analytics Service services
      prisma.projectService.createMany({
        data: [
          {
            projectId: projects[2].id,
            name: 'Grafana',
            type: 'grafana',
            status: 'connected',
            endpoint: 'grafana.analytics.skygenesis.com',
            version: '9.5.0',
          },
          {
            projectId: projects[2].id,
            name: 'Loki',
            type: 'loki',
            status: 'connected',
            endpoint: 'loki.analytics.skygenesis.com',
            version: '2.8.0',
          },
        ],
      }),
    ]);

    console.log('⚙️ Created project services');

    // Create Endpoints
    const endpoints = await Promise.all([
      // E-commerce Platform endpoints
      prisma.endpoint.createMany({
        data: [
          {
            name: 'Get Projects',
            method: 'GET',
            route: '/api/v1/projects',
            description: 'Retrieve all projects with pagination and filtering',
            version: 'v1',
            status: 'active',
            projectId: projects[0].id,
            service: 'Project Service',
            tags: JSON.stringify(['projects', 'read', 'public']),
            scopes: JSON.stringify(['projects:read']),
            rateLimit: 1000,
          },
          {
            name: 'Create Project',
            method: 'POST',
            route: '/api/v1/projects',
            description: 'Create a new project with validation and auto-scaling',
            version: 'v1',
            status: 'active',
            projectId: projects[0].id,
            service: 'Project Service',
            tags: JSON.stringify(['projects', 'write', 'authenticated']),
            scopes: JSON.stringify(['projects:write']),
            rateLimit: 100,
          },
          {
            name: 'Get Project by ID',
            method: 'GET',
            route: '/api/v1/projects/{id}',
            description: 'Retrieve specific project details by ID',
            version: 'v1',
            status: 'active',
            projectId: projects[0].id,
            service: 'Project Service',
            tags: JSON.stringify(['projects', 'read', 'authenticated']),
            scopes: JSON.stringify(['projects:read']),
            rateLimit: 2000,
          },
          {
            name: 'Update Project',
            method: 'PUT',
            route: '/api/v1/projects/{id}',
            description: 'Update project configuration and settings',
            version: 'v1',
            status: 'active',
            projectId: projects[0].id,
            service: 'Project Service',
            tags: JSON.stringify(['projects', 'write', 'authenticated']),
            scopes: JSON.stringify(['projects:write']),
            rateLimit: 200,
          },
          {
            name: 'Delete Project',
            method: 'DELETE',
            route: '/api/v1/projects/{id}',
            description: 'Delete project and associated resources',
            version: 'v1',
            status: 'active',
            projectId: projects[0].id,
            service: 'Project Service',
            tags: JSON.stringify(['projects', 'delete', 'authenticated']),
            scopes: JSON.stringify(['projects:delete']),
            rateLimit: 50,
          },
        ],
      }),
      // Mobile App Backend endpoints
      prisma.endpoint.createMany({
        data: [
          {
            name: 'Get Users',
            method: 'GET',
            route: '/api/v1/users',
            description: 'Retrieve user list with role-based filtering',
            version: 'v2',
            status: 'active',
            projectId: projects[1].id,
            service: 'User Service',
            tags: JSON.stringify(['users', 'read', 'authenticated']),
            scopes: JSON.stringify(['users:read']),
            rateLimit: 5000,
          },
          {
            name: 'User Login',
            method: 'POST',
            route: '/api/v1/auth/login',
            description: 'User authentication with JWT token generation',
            version: 'v1',
            status: 'active',
            projectId: projects[1].id,
            service: 'Auth Service',
            tags: JSON.stringify(['auth', 'public', 'login']),
            scopes: JSON.stringify([]),
            rateLimit: 100,
          },
        ],
      }),
      // Analytics Service endpoints
      prisma.endpoint.createMany({
        data: [
          {
            name: 'Get Metrics',
            method: 'GET',
            route: '/api/v1/metrics',
            description: 'System metrics and performance data',
            version: 'v1',
            status: 'active',
            projectId: projects[2].id,
            service: 'Monitoring Service',
            tags: JSON.stringify(['metrics', 'read', 'authenticated']),
            scopes: JSON.stringify(['metrics:read']),
            rateLimit: 1000,
          },
          {
            name: 'Deprecated Metrics',
            method: 'GET',
            route: '/api/v1/old-metrics',
            description: 'Legacy metrics endpoint - use /api/v1/metrics instead',
            version: 'v1',
            status: 'deprecated',
            deprecated: true,
            projectId: projects[2].id,
            service: 'Monitoring Service',
            tags: JSON.stringify(['metrics', 'read', 'deprecated']),
            scopes: JSON.stringify(['metrics:read']),
            rateLimit: 500,
          },
        ],
      }),
    ]);

    console.log('🔌 Created endpoints');

    // Create Endpoint Metrics (sample data)
    const now = new Date();
    const metricsData = [];
    
    for (let i = 0; i < 30; i++) {
      const timestamp = new Date(now.getTime() - i * 60 * 60 * 1000); // Last 30 days
      metricsData.push({
        endpointId: endpoints[0].id, // Get Projects endpoint
        timestamp,
        requests: Math.floor(Math.random() * 1000) + 500,
        errors: Math.floor(Math.random() * 10),
        avgLatency: Math.random() * 200 + 50,
        p95Latency: Math.random() * 300 + 100,
        p99Latency: Math.random() * 500 + 200,
        statusCodes: JSON.stringify({
          200: Math.floor(Math.random() * 900) + 100,
          400: Math.floor(Math.random() * 20) + 5,
          500: Math.floor(Math.random() * 10) + 2,
        }),
      });
    }

    await prisma.endpointMetric.createMany({
      data: metricsData,
    });

    console.log('📊 Created endpoint metrics');

    // Create Endpoint Calls (sample data)
    const callsData = [];
    const applications = ['Web Dashboard', 'Mobile App', 'CLI Tool', 'Third Party API'];
    const userAgents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15',
      'cli-tool/2.1.0',
      'axios/1.6.0',
    ];

    for (let i = 0; i < 100; i++) {
      const timestamp = new Date(now.getTime() - i * 5 * 60 * 1000); // Last 500 minutes
      const isSuccess = Math.random() > 0.05; // 95% success rate
      const statusCode = isSuccess ? 
        (Math.random() > 0.8 ? 201 : 200) : 
        (Math.random() > 0.5 ? 500 : 400);
      
      callsData.push({
        endpointId: endpoints[Math.floor(Math.random() * endpoints.length)].id,
        application: applications[Math.floor(Math.random() * applications.length)],
        userId: Math.random() > 0.3 ? users[Math.floor(Math.random() * users.length)].id : undefined,
        statusCode,
        latency: Math.floor(Math.random() * 500) + 50,
        payload: Math.random() > 0.7 ? JSON.stringify({ test: 'data' }) : undefined,
        response: isSuccess ? JSON.stringify({ success: true, data: { id: '123' } }) : undefined,
        errorMessage: !isSuccess ? 'Simulated error for testing' : undefined,
        userAgent: userAgents[Math.floor(Math.random() * userAgents.length)],
        ipAddress: `192.168.1.${Math.floor(Math.random() * 254)}`,
        timestamp,
      });
    }

    await prisma.endpointCall.createMany({
      data: callsData,
    });

    console.log('📞 Created endpoint calls');

    // Create Dashboard Stats
    const today = new Date().toISOString().split('T')[0];
    await prisma.dashboardStats.createMany({
      data: [
        {
          organizationId: organizations[0].id,
          workspaceId: workspaces[2].id, // Production
          date: new Date(today),
          totalProjects: 4,
          totalEndpoints: 7,
          totalRequests: 15420,
          totalErrors: 31,
          avgLatency: 120.5,
          uptime: 99.8,
        },
        {
          organizationId: organizations[1].id,
          workspaceId: workspaces[3].id, // Dev
          date: new Date(today),
          totalProjects: 1,
          totalEndpoints: 2,
          totalRequests: 3420,
          totalErrors: 68,
          avgLatency: 185.2,
          uptime: 98.0,
        },
      ],
    });

    console.log('📈 Created dashboard stats');

    // Create API Keys
    await prisma.apiKey.createMany({
      data: [
        {
          key: 'sk-skygenesis-prod-1234567890abcdef',
          name: 'Production API Key',
          type: 'client',
          status: 'production',
          permissions: JSON.stringify(['read', 'write', 'admin']),
          organizationId: organizations[0].id,
          userId: users[0].id,
          isActive: true,
          expiresAt: new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000), // 1 year
        },
        {
          key: 'sk-techcorp-dev-abcdef1234567890',
          name: 'Development API Key',
          type: 'client',
          status: 'development',
          permissions: JSON.stringify(['read', 'write']),
          organizationId: organizations[1].id,
          userId: users[1].id,
          isActive: true,
        },
      ],
    });

    console.log('🔑 Created API keys');

    console.log('✅ Database seeding completed successfully!');
    console.log('\n📊 Summary:');
    console.log(`- Organizations: ${organizations.length}`);
    console.log(`- Users: ${users.length}`);
    console.log(`- Workspaces: ${workspaces.length}`);
    console.log(`- Projects: ${projects.length}`);
    console.log(`- Project Services: ${projectServices.length}`);
    console.log(`- Endpoints: ${endpoints.length}`);
    console.log(`- Endpoint Metrics: ${metricsData.length}`);
    console.log(`- Endpoint Calls: ${callsData.length}`);
    console.log(`- Dashboard Stats: 2`);
    console.log(`- API Keys: 2`);

  } catch (error) {
    console.error('❌ Error during database seeding:', error);
    throw error;
  }
}

// Run seeding if called directly
if (require.main === module) {
  seedDatabase()
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}