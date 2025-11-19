import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'

const prisma = new PrismaClient()

export async function seedDemoUser() {
  try {
    // Créer l'organisation de démo
    const demoOrg = await prisma.organization.upsert({
      where: { name: 'Sky Genesis Enterprise' },
      update: {},
      create: {
        name: 'Sky Genesis Enterprise',
      },
    })

    // Créer l'utilisateur de démo avec le modèle User existant
    const hashedPassword = await bcrypt.hash('admin123', 10)
    
    const demoUser = await prisma.user.upsert({
      where: { email: 'admin@skygenesisenterprise.com' },
      update: {},
      create: {
        email: 'admin@skygenesisenterprise.com',
        fullName: 'Admin Demo',
        passwordHash: hashedPassword,
        organizationId: demoOrg.id,
        isActive: true,
      },
    })

    console.log('✅ Utilisateur de démo créé avec succès!')
    console.log('📧 Email: admin@skygenesisenterprise.com')
    console.log('🔑 Password: admin123')
    console.log('🏢 Organisation: Sky Genesis Demo')
    console.log('👤 Nom complet: Admin Demo')
    
  } catch (error) {
    console.error('❌ Erreur lors de la création de l\'utilisateur de démo:', error)
  } finally {
    await prisma.$disconnect()
  }
}

// Exécuter si ce fichier est lancé directement
if (require.main === module) {
  seedDemoUser()
}