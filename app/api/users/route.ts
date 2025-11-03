import { NextRequest, NextResponse } from 'next/server'
import { backendService } from '@/app/lib/services/backend-service'

// Fallback mock data for development when backend is unavailable
const mockUsers = [
  {
    id: '1',
    email: 'admin@skygenesisenterprise.com',
    fullName: 'Administrateur',
    status: 'active',
    role: 'admin',
    department: 'IT',
    position: 'System Administrator',
    phone: '+33612345678',
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-20'),
    organization: { id: '1', name: 'Sky Genesis Enterprise' }
  },
  {
    id: '2',
    email: 'manager@skygenesisenterprise.com',
    fullName: 'Jean Manager',
    status: 'active',
    role: 'manager',
    department: 'Management',
    position: 'Project Manager',
    phone: '+33623456789',
    createdAt: new Date('2024-01-05'),
    updatedAt: new Date('2024-01-18'),
    organization: { id: '1', name: 'Sky Genesis Enterprise' }
  },
  {
    id: '3',
    email: 'user@skygenesisenterprise.com',
    fullName: 'Marie Utilisateur',
    status: 'active',
    role: 'user',
    department: 'Development',
    position: 'Developer',
    phone: '+33634567890',
    createdAt: new Date('2024-01-10'),
    updatedAt: new Date('2024-01-15'),
    organization: { id: '1', name: 'Sky Genesis Enterprise' }
  }
]

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '20')
    const search = searchParams.get('search') || undefined
    const status = searchParams.get('status') || undefined

    // Try to get data from Rust backend first
    try {
      const response = await backendService.getUsers({
        page,
        limit,
        search,
        status,
      })

      if (response.data) {
        return NextResponse.json({
          success: true,
          data: response.data.users,
          pagination: {
            page: response.data.page,
            limit: response.data.limit,
            total: response.data.total,
            pages: Math.ceil(response.data.total / response.data.limit),
          },
        })
      }
    } catch (backendError) {
      console.warn('Backend unavailable, using mock data:', backendError)
    }

    // Fallback to mock data
    let filteredUsers = mockUsers

    if (search) {
      filteredUsers = filteredUsers.filter(user =>
        user.email.toLowerCase().includes(search.toLowerCase()) ||
        user.fullName.toLowerCase().includes(search.toLowerCase()) ||
        user.department?.toLowerCase().includes(search.toLowerCase())
      )
    }

    if (status) {
      filteredUsers = filteredUsers.filter(user => user.status === status)
    }

    const total = filteredUsers.length
    const startIndex = (page - 1) * limit
    const endIndex = startIndex + limit
    const users = filteredUsers.slice(startIndex, endIndex)

    return NextResponse.json({
      success: true,
      data: users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    })
  } catch (error) {
    console.error('Error fetching users:', error)
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { email, fullName, password, department, position, phone } = body

    if (!email || !password) {
      return NextResponse.json(
        { success: false, error: 'Email and password are required' },
        { status: 400 }
      )
    }

    // Try to create user via Rust backend first
    try {
      const response = await backendService.createUser({
        email,
        fullName,
        password,
        department,
        position,
        phone,
      })

      if (response.data) {
        return NextResponse.json({
          success: true,
          data: response.data,
        })
      } else if (response.error) {
        return NextResponse.json(
          { success: false, error: response.error },
          { status: 400 }
        )
      }
    } catch (backendError) {
      console.warn('Backend unavailable, using mock data:', backendError)
    }

    // Fallback to mock data
    // Check if user already exists
    const existingUser = mockUsers.find(user => user.email === email)
    if (existingUser) {
      return NextResponse.json(
        { success: false, error: 'User with this email already exists' },
        { status: 409 }
      )
    }

    const newUser = {
      id: (mockUsers.length + 1).toString(),
      email,
      fullName,
      status: 'active',
      role: 'user',
      department,
      position,
      phone,
      createdAt: new Date(),
      updatedAt: new Date(),
      organization: { id: '1', name: 'Sky Genesis Enterprise' }
    }

    mockUsers.push(newUser)

    return NextResponse.json({
      success: true,
      data: newUser,
    })
  } catch (error) {
    console.error('Error creating user:', error)
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    )
  }
}