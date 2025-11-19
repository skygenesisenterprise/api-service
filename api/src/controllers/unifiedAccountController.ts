import { Request, Response } from 'express';
import { UnifiedAccountService } from '../services/unifiedAccountService';
import { SimpleAuthService } from '../services/simpleAuthService';
import { ICreateUnifiedAccountRequest, ILinkIdentifierRequest } from '../models/unifiedAccountModels';

const unifiedAccountService = new UnifiedAccountService();
const simpleAuthService = new SimpleAuthService();

export const createAccount = async (req: Request, res: Response): Promise<void> => {
  try {
    const accountData: ICreateUnifiedAccountRequest = req.body;

    if (!accountData.email) {
      res.status(400).json({ error: 'Email is required' });
      return;
    }

    if (accountData.password && accountData.password.length < 6) {
      res.status(400).json({ error: 'Password must be at least 6 characters long' });
      return;
    }

    const result = await unifiedAccountService.createAccount(accountData);
    
    res.status(201).json({
      message: 'Account created successfully',
      data: result
    });
  } catch (error) {
    console.error('Create account error:', error);
    res.status(400).json({ 
      error: error instanceof Error ? error.message : 'Account creation failed' 
    });
  }
};

export const authenticate = async (req: Request, res: Response): Promise<void> => {
  try {
    const { identifier, password } = req.body;
    
    if (!identifier) {
      res.status(400).json({ error: 'Identifier (email, username, or phone) is required' });
      return;
    }
    
    if (!password) {
      res.status(400).json({ error: 'Password is required' });
      return;
    }
    
    // Utiliser uniquement le service d'authentification simplifié
    console.log('Attempting authentication with:', identifier);
    const result = await simpleAuthService.authenticateUser(identifier, password);
    console.log('Authentication successful for:', identifier);
    
    res.status(200).json({
      message: 'Authentication successful',
      data: result
    });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({ 
      error: error instanceof Error ? error.message : 'Authentication failed' 
    });
  }
};

export const getProfile = async (req: Request, res: Response): Promise<void> => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      res.status(401).json({ error: 'No token provided' });
      return;
    }

    const account = await unifiedAccountService.validateSession(token);
    
    if (!account) {
      res.status(401).json({ error: 'Invalid or expired token' });
      return;
    }

    const memberships = await unifiedAccountService.getAccountMemberships(account.id);

    res.status(200).json({
      message: 'Profile retrieved successfully',
      data: { 
        account,
        memberships
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const linkOAuthAccount = async (req: Request, res: Response): Promise<void> => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      res.status(401).json({ error: 'No token provided' });
      return;
    }

    const account = await unifiedAccountService.validateSession(token);
    
    if (!account) {
      res.status(401).json({ error: 'Invalid or expired token' });
      return;
    }

    const { provider, providerId, email } = req.body;

    if (!provider || !providerId) {
      res.status(400).json({ error: 'Provider and providerId are required' });
      return;
    }

    await unifiedAccountService.linkOAuthAccount(account.id, provider, providerId, email);

    res.status(200).json({
      message: 'OAuth account linked successfully'
    });
  } catch (error) {
    console.error('Link OAuth account error:', error);
    res.status(400).json({ 
      error: error instanceof Error ? error.message : 'Failed to link OAuth account' 
    });
  }
};

export const linkIdentifier = async (req: Request, res: Response): Promise<void> => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      res.status(401).json({ error: 'No token provided' });
      return;
    }

    const account = await unifiedAccountService.validateSession(token);
    
    if (!account) {
      res.status(401).json({ error: 'Invalid or expired token' });
      return;
    }

    const identifierData: ILinkIdentifierRequest = req.body;

    if (!identifierData.type || !identifierData.value) {
      res.status(400).json({ error: 'Identifier type and value are required' });
      return;
    }

    await unifiedAccountService.linkIdentifier(account.id, identifierData);

    res.status(200).json({
      message: 'Identifier linked successfully'
    });
  } catch (error) {
    console.error('Link identifier error:', error);
    res.status(400).json({ 
      error: error instanceof Error ? error.message : 'Failed to link identifier' 
    });
  }
};

export const refreshToken = async (req: Request, res: Response): Promise<void> => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({ error: 'Refresh token is required' });
      return;
    }

    const account = await unifiedAccountService.verifyToken(refreshToken);
    
    if (!account) {
      res.status(401).json({ error: 'Invalid refresh token' });
      return;
    }

    // Generate new tokens
    const tokens = unifiedAccountService.generateTokens(account);

    res.status(200).json({
      message: 'Token refreshed successfully',
      data: tokens
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(401).json({ error: 'Token refresh failed' });
  }
};

export const logout = async (req: Request, res: Response): Promise<void> => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      res.status(400).json({ error: 'No token provided' });
      return;
    }

    const account = await unifiedAccountService.validateSession(token);
    
    if (!account) {
      res.status(401).json({ error: 'Invalid or expired token' });
      return;
    }

    // Revoke all sessions for the account
    await unifiedAccountService.revokeAllSessions(account.id);

    res.status(200).json({
      message: 'Logout successful'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const getAccountByGlobalId = async (req: Request, res: Response): Promise<void> => {
  try {
    const { globalId } = req.params;

    if (!globalId) {
      res.status(400).json({ error: 'Global ID is required' });
      return;
    }

    const account = await unifiedAccountService.getAccountByGlobalId(globalId);
    
    if (!account) {
      res.status(404).json({ error: 'Account not found' });
      return;
    }

    res.status(200).json({
      message: 'Account retrieved successfully',
      data: { account }
    });
  } catch (error) {
    console.error('Get account by global ID error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};