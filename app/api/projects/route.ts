import { NextRequest, NextResponse } from 'next/server'

// Mock project service for now since Prisma models aren't fully synchronized
const mockProjects = [
  {
    id: '1',
    name: 'Site Web Enterprise',
    key: 'WEB-001',
    description: 'Développement du site web principal',
    status: 'active',
    priority: 'high',
    progress: 75,
    createdAt: new Date('2024-01-15'),
    updatedAt: new Date('2024-01-20'),
    organization: { id: '1', name: 'Sky Genesis Enterprise' },
    creatorRelation: { id: '1', fullName: 'Administrateur' },
    members: []
  },
  {
    id: '2',
    name: 'Application Mobile',
    key: 'MOB-002',
    description: 'Application iOS et Android',
    status: 'active',
    priority: 'medium',
    progress: 45,
    createdAt: new Date('2024-01-10'),
    updatedAt: new Date('2024-01-18'),
    organization: { id: '1', name: 'Sky Genesis Enterprise' },
    creatorRelation: { id: '1', fullName: 'Administrateur' },
    members: []
  },
  {
    id: '3',
    name: 'API Backend',
    key: 'API-003',
    description: 'Refactorisation de l\'API backend',
    status: 'planning',
    priority: 'low',
    progress: 10,
    createdAt: new Date('2024-01-05'),
    updatedAt: new Date('2024-01-15'),
    organization: { id: '1', name: 'Sky Genesis Enterprise' },
    creatorRelation: { id: '1', fullName: 'Administrateur' },
    members: []
  }
]

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '20')
    const search = searchParams.get('search') || undefined
    const status = searchParams.get('status') || undefined

    let filteredProjects = mockProjects

    if (search) {
      filteredProjects = filteredProjects.filter(project =>
        project.name.toLowerCase().includes(search.toLowerCase()) ||
        project.key.toLowerCase().includes(search.toLowerCase()) ||
        project.description?.toLowerCase().includes(search.toLowerCase())
      )
    }

    if (status) {
      filteredProjects = filteredProjects.filter(project => project.status === status)
    }

    const total = filteredProjects.length
    const startIndex = (page - 1) * limit
    const endIndex = startIndex + limit
    const projects = filteredProjects.slice(startIndex, endIndex)

    return NextResponse.json({
      success: true,
      data: projects,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    })
  } catch (error) {
    console.error('Error fetching projects:', error)
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { name, description, key, status, priority, startDate, endDate, budget } = body

    if (!name || !key) {
      return NextResponse.json(
        { success: false, error: 'Name and key are required' },
        { status: 400 }
      )
    }

    // Check if project key already exists
    const existingProject = mockProjects.find(p => p.key === key)
    if (existingProject) {
      return NextResponse.json(
        { success: false, error: 'Project with this key already exists' },
        { status: 409 }
      )
    }

    const newProject = {
      id: (mockProjects.length + 1).toString(),
      name,
      description,
      key,
      status: status || 'active',
      priority: priority || 'medium',
      progress: 0,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      budget,
      createdAt: new Date(),
      updatedAt: new Date(),
      organization: { id: '1', name: 'Sky Genesis Enterprise' },
      creatorRelation: { id: '1', fullName: 'Administrateur' },
      members: []
    }

    mockProjects.push(newProject)

    return NextResponse.json({
      success: true,
      data: newProject,
    })
  } catch (error) {
    console.error('Error creating project:', error)
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    )
  }
}