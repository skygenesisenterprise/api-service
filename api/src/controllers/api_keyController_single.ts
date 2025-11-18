import { NextRequest, NextResponse } from 'next/server';
import { ApiKeyService } from '../services/api_keyServices';
import { IUpdateApiKeyRequest } from '../models/api_keyModels';
import { authenticateApiKey, requirePermission } from '../middlewares/api_keyMiddlewares';

const apiKeyService = new ApiKeyService();

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const auth = await authenticateApiKey(req);
    if (auth.error) return auth.error;

    const permissionCheck = requirePermission('read' as any)(auth.apiKey);
    if (permissionCheck) return permissionCheck;

    const apiKey = await apiKeyService.getApiKeyById(params.id);
    
    if (!apiKey) {
      return NextResponse.json({ error: 'API key not found' }, { status: 404 });
    }
    
    return NextResponse.json({ data: apiKey });
  } catch (error) {
    console.error('Get API key error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function PUT(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const auth = await authenticateApiKey(req);
    if (auth.error) return auth.error;

    const permissionCheck = requirePermission('write' as any)(auth.apiKey);
    if (permissionCheck) return permissionCheck;

    const body: IUpdateApiKeyRequest = await req.json();
    
    const apiKey = await apiKeyService.updateApiKey(params.id, body);
    
    return NextResponse.json({ data: apiKey });
  } catch (error) {
    console.error('Update API key error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const auth = await authenticateApiKey(req);
    if (auth.error) return auth.error;

    const permissionCheck = requirePermission('delete' as any)(auth.apiKey);
    if (permissionCheck) return permissionCheck;

    await apiKeyService.deleteApiKey(params.id);
    
    return NextResponse.json({ message: 'API key deleted successfully' });
  } catch (error) {
    console.error('Delete API key error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}