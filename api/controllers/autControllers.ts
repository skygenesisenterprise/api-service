import { Request, Response } from 'express';
import authService from '../services/authService';

export const authenticate = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const result = await authService.authenticate(username, password);
    return res.status(200).json({ message: 'Authentication successful', data: result });
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};