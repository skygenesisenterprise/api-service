import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Seeding database...');

  // Create a sample organization
  const org = await prisma.organization.create({
    data: {
      name: 'Sky Genesis Enterprise',
      countryCode: 'US',
    },
  });

  console.log('✅ Created organization:', org.name);

  // Create a sample user
  const user = await prisma.user.create({
    data: {
      organizationId: org.id,
      email: 'admin@skygenesisenterprise.com',
      fullName: 'System Administrator',
      passwordHash: '$2b$10$example.hash.here', // Replace with actual hash
      role: 'admin',
      status: 'active',
    },
  });

  console.log('✅ Created user:', user.email);

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