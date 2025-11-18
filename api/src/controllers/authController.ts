import { Request, Response } from 'express';
import { AuthService } from '../services/authService';
import { ILoginRequest, IRegisterRequest } from '../models/authModels';

const authService = new AuthService();

export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const credentials: ILoginRequest = req.body;

    if (!credentials.email || !credentials.password) {
      res.status(400).json({ error: 'Email and password are required' });
      return;
    }

    const result = await authService.login(credentials);
    
    res.status(200).json({
      message: 'Login successful',
      data: result
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({ 
      error: error instanceof Error ? error.message : 'Authentication failed' 
    });
  }
};

export const register = async (req: Request, res: Response): Promise<void> => {
  try {
    const userData: IRegisterRequest = req.body;

    if (!userData.email || !userData.password) {
      res.status(400).json({ error: 'Email and password are required' });
      return;
    }

    if (userData.password.length < 6) {
      res.status(400).json({ error: 'Password must be at least 6 characters long' });
      return;
    }

    const result = await authService.register(userData);
    
    res.status(201).json({
      message: 'Registration successful',
      data: result
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(400).json({ 
      error: error instanceof Error ? error.message : 'Registration failed' 
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

    const user = await authService.verifyToken(token);
    
    if (!user) {
      res.status(401).json({ error: 'Invalid token' });
      return;
    }

    res.status(200).json({
      message: 'Profile retrieved successfully',
      data: { user }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const refreshToken = async (req: Request, res: Response): Promise<void> => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({ error: 'Refresh token is required' });
      return;
    }

    // For now, we'll implement a simple refresh token logic
    // In production, you might want to store refresh tokens in the database
    const user = await authService.verifyToken(refreshToken);
    
    if (!user) {
      res.status(401).json({ error: 'Invalid refresh token' });
      return;
    }

    // Generate new tokens
    const newToken = authService.generateToken(user);
    const newRefreshToken = authService.generateRefreshToken(user);

    res.status(200).json({
      message: 'Token refreshed successfully',
      data: {
        token: newToken,
        refreshToken: newRefreshToken
      }
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(401).json({ error: 'Token refresh failed' });
  }
};