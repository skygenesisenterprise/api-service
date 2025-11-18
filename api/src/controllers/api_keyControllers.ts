import { NextRequest, NextResponse } from 'next/server';
import { ApiKeyService } from '../services/api_keyServices';
import { ICreateApiKeyRequest } from '../models/api_keyModels';
import { authenticateApiKey, requirePermission } from '../middlewares/api_keyMiddlewares';

const apiKeyService = new ApiKeyService();

export async function GET(req: NextRequest) {
  try {
    const auth = await authenticateApiKey(req);
    if (auth.error) return auth.error;

    const permissionCheck = requirePermission('read' as any)(auth.apiKey);
    if (permissionCheck) return permissionCheck;

    const { searchParams } = new URL(req.url);
    const organizationId = searchParams.get('organizationId');

    if (!organizationId) {
      return NextResponse.json({ error: 'Organization ID required' }, { status: 400 });
    }

    const apiKeys = await apiKeyService.getApiKeysByOrganization(organizationId);
    
    return NextResponse.json({ data: apiKeys });
  } catch (error) {
    console.error('Get API keys error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const auth = await authenticateApiKey(req);
    if (auth.error) return auth.error;

    const permissionCheck = requirePermission('write' as any)(auth.apiKey);
    if (permissionCheck) return permissionCheck;

    const body: ICreateApiKeyRequest = await req.json();
    
    if (!body.name || !body.category || !body.permissions || !body.organizationId) {
      return NextResponse.json({ 
        error: 'Missing required fields: name, category, permissions, organizationId' 
      }, { status: 400 });
    }

    const apiKey = await apiKeyService.createApiKey(body);
    
    return NextResponse.json({ data: apiKey }, { status: 201 });
  } catch (error) {
    console.error('Create API key error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}