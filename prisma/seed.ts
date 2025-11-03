import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Seeding database with roles and permissions...');

  // Create a sample organization
  const org = await prisma.organization.upsert({
    where: { name: 'Sky Genesis Enterprise' },
    update: {},
    create: {
      name: 'Sky Genesis Enterprise',
      countryCode: 'FR',
    },
  });

  console.log('✅ Created organization:', org.name);

  // Create roles
  const adminRole = await prisma.role.upsert({
    where: { name: 'admin' },
    update: {},
    create: {
      name: 'admin',
      description: 'Administrateur système avec tous les droits',
      isSystem: true,
    },
  });

  const managerRole = await prisma.role.upsert({
    where: { name: 'manager' },
    update: {},
    create: {
      name: 'manager',
      description: 'Gestionnaire avec droits étendus',
      isSystem: true,
    },
  });

  const userRole = await prisma.role.upsert({
    where: { name: 'user' },
    update: {},
    create: {
      name: 'user',
      description: 'Utilisateur standard avec droits limités',
      isSystem: true,
    },
  });

  console.log('✅ Created roles');

  // Create permissions
  const permissions = [
    { name: 'users:create', resource: 'users', action: 'create', module: 'admin' },
    { name: 'users:read', resource: 'users', action: 'read', module: 'admin' },
    { name: 'users:update', resource: 'users', action: 'update', module: 'admin' },
    { name: 'users:delete', resource: 'users', action: 'delete', module: 'admin' },
    { name: 'projects:create', resource: 'projects', action: 'create', module: 'projects' },
    { name: 'projects:read', resource: 'projects', action: 'read', module: 'projects' },
    { name: 'projects:update', resource: 'projects', action: 'update', module: 'projects' },
    { name: 'projects:delete', resource: 'projects', action: 'delete', module: 'projects' },
    { name: 'dashboard:read', resource: 'dashboard', action: 'read', module: 'dashboard' },
    { name: 'logs:read', resource: 'logs', action: 'read', module: 'logs' },
    { name: 'settings:read', resource: 'settings', action: 'read', module: 'settings' },
    { name: 'settings:update', resource: 'settings', action: 'update', module: 'settings' },
  ];

  for (const permission of permissions) {
    await prisma.permission.upsert({
      where: { name: permission.name },
      update: {},
      create: permission,
    });
  }

  console.log('✅ Created permissions');

  // Assign permissions to roles
  const allPermissions = await prisma.permission.findMany();
  
  // Admin gets all permissions
  for (const permission of allPermissions) {
    await prisma.rolePermission.upsert({
      where: {
        roleId_permissionId: {
          roleId: adminRole.id,
          permissionId: permission.id,
        },
      },
      update: {},
      create: {
        roleId: adminRole.id,
        permissionId: permission.id,
      },
    });
  }

  // Manager gets limited permissions
  const managerPermissions = allPermissions.filter(p => 
    !p.name.includes('delete') && !p.name.includes('admin')
  );
  
  for (const permission of managerPermissions) {
    await prisma.rolePermission.upsert({
      where: {
        roleId_permissionId: {
          roleId: managerRole.id,
          permissionId: permission.id,
        },
      },
      update: {},
      create: {
        roleId: managerRole.id,
        permissionId: permission.id,
      },
    });
  }

  // User gets read permissions only
  const userPermissions = allPermissions.filter(p => p.action === 'read');
  
  for (const permission of userPermissions) {
    await prisma.rolePermission.upsert({
      where: {
        roleId_permissionId: {
          roleId: userRole.id,
          permissionId: permission.id,
        },
      },
      update: {},
      create: {
        roleId: userRole.id,
        permissionId: permission.id,
      },
    });
  }

  console.log('✅ Assigned permissions to roles');

  // Create admin user
  const defaultPassword = 'admin123';
  const passwordHash = Buffer.from(defaultPassword).toString('base64');

  const adminUser = await prisma.user.upsert({
    where: { email: 'admin@skygenesisenterprise.com' },
    update: {},
    create: {
      email: 'admin@skygenesisenterprise.com',
      fullName: 'Administrateur',
      passwordHash,
      organizationId: org.id,
      status: 'active',
    },
  });

  // Assign admin role to admin user
  await prisma.userRole.upsert({
    where: {
      userId_roleId: {
        userId: adminUser.id,
        roleId: adminRole.id,
      },
    },
    update: {},
    create: {
      userId: adminUser.id,
      roleId: adminRole.id,
    },
  });

  console.log('✅ Created admin user:', adminUser.email);

  // Create test users
  const testUsers = [
    {
      email: 'manager@skygenesisenterprise.com',
      fullName: 'Jean Manager',
      role: managerRole,
    },
    {
      email: 'user@skygenesisenterprise.com',
      fullName: 'Marie Utilisateur',
      role: userRole,
    },
  ];

  for (const testUser of testUsers) {
    const user = await prisma.user.upsert({
      where: { email: testUser.email },
      update: {},
      create: {
        email: testUser.email,
        fullName: testUser.fullName,
        passwordHash,
        organizationId: org.id,
        status: 'active',
      },
    });

    await prisma.userRole.upsert({
      where: {
        userId_roleId: {
          userId: user.id,
          roleId: testUser.role.id,
        },
      },
      update: {},
      create: {
        userId: user.id,
        roleId: testUser.role.id,
      },
    });
  }

  console.log('✅ Created test users');

  // Create sample API routes
  const routes = await prisma.apiRoute.createMany({
    data: [
      {
        name: 'Get Organizations',
        method: 'GET',
        path: '/api/v1/organizations',
        serviceName: 'api-service',
        isPublic: false,
      },
      {
        name: 'Create Organization',
        method: 'POST',
        path: '/api/v1/organizations',
        serviceName: 'api-service',
        isPublic: false,
      },
      {
        name: 'Get Users',
        method: 'GET',
        path: '/api/v1/users',
        serviceName: 'api-service',
        isPublic: false,
      },
    ],
  });

  console.log(`✅ Created ${routes.count} API routes`);

  // Create sample API key
  const apiKey = await prisma.apiKey.create({
    data: {
      organizationId: org.id,
      keyValue: 'sk_test_' + Math.random().toString(36).substring(2, 15),
      label: 'Development API Key',
      permissions: ['read', 'write'],
      quotaLimit: 100000,
      usageCount: 0,
      status: 'active',
    },
  });

  console.log('✅ Created API key:', apiKey.label);

  console.log('🎉 Database seeding completed!');
}

main()
  .catch((e) => {
    console.error('❌ Error seeding database:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });