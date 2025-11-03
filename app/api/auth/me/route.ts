import { NextRequest, NextResponse } from 'next/server'
import { authService } from '@/app/lib/services/backend-auth-service'

export async function GET() {
  try {
    const user = await authService.getCurrentUser()

    if (user) {
      return NextResponse.json({
        success: true,
        data: user,
      })
    } else {
      return NextResponse.json(
        { success: false, error: 'Not authenticated' },
        { status: 401 }
      )
    }
  } catch (error) {
    console.error('Get current user error:', error)
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    )
  }
}