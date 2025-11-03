import { NextRequest, NextResponse } from 'next/server'

// Mock users data
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

export async function GET(
  _request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const user = mockUsers.find(u => u.id === params.id)

    if (!user) {
      return NextResponse.json(
        { success: false, error: 'User not found' },
        { status: 404 }
      )
    }

    return NextResponse.json({
      success: true,
      data: user,
    })
  } catch (error) {
    console.error('Error fetching user:', error)
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    )
  }
}

export async function PUT(
  _request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const body = await _request.json()
    const { fullName, department, position, phone, status } = body

    const userIndex = mockUsers.findIndex(u => u.id === params.id)
    
    if (userIndex === -1) {
      return NextResponse.json(
        { success: false, error: 'User not found' },
        { status: 404 }
      )
    }

    const updatedUser = {
      ...mockUsers[userIndex],
      fullName: fullName || mockUsers[userIndex].fullName,
      department: department || mockUsers[userIndex].department,
      position: position || mockUsers[userIndex].position,
      phone: phone || mockUsers[userIndex].phone,
      status: status || mockUsers[userIndex].status,
      updatedAt: new Date()
    }

    mockUsers[userIndex] = updatedUser

    return NextResponse.json({
      success: true,
      data: updatedUser,
    })
  } catch (error) {
    console.error('Error updating user:', error)
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    )
  }
}

export async function DELETE(
  _request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const userIndex = mockUsers.findIndex(u => u.id === params.id)
    
    if (userIndex === -1) {
      return NextResponse.json(
        { success: false, error: 'User not found' },
        { status: 404 }
      )
    }

    mockUsers.splice(userIndex, 1)

    return NextResponse.json({
      success: true,
      message: 'User deleted successfully',
    })
  } catch (error) {
    console.error('Error deleting user:', error)
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    )
  }
}