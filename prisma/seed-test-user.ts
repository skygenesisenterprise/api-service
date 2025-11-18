const { PrismaClient } = require('@prisma/client')
const bcrypt = require('bcryptjs')

const prisma = new PrismaClient()

async function main() {
  console.log('Création d\'un utilisateur de test...')

  // Créer une organisation de test
  const org = await prisma.organization.upsert({
    where: { name: 'Test Organization' },
    update: {},
    create: {
      name: 'Test Organization',
    },
  })

  // Créer un utilisateur de test
  const hashedPassword = await bcrypt.hash('password123', 10)
  
  const user = await prisma.user.upsert({
    where: { email: 'test@example.com' },
    update: {},
    create: {
      email: 'test@example.com',
      fullName: 'Test User',
      passwordHash: hashedPassword,
      organizationId: org.id,
      isActive: true,
    },
  })

  console.log('Utilisateur de test créé avec succès:')
  console.log('Email: test@example.com')
  console.log('Password: password123')
  console.log('User ID:', user.id)
  console.log('Organization ID:', org.id)
}

main()
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })