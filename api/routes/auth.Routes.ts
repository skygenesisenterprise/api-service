import express, { Request, Response } from 'express';
import axios from 'axios';

const router = express.Router();

router.post('/auth', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const response = await axios.post('https://sso.skygenesisenterprise.com/auth', {
      username,
      password
    });

    if (response.status === 200) {
      return res.status(200).json({ message: 'Authentication successful', data: response.data });
    } else {
      return res.status(response.status).json({ error: 'Authentication failed' });
    }
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Ajoutez une route GET pour /auth
router.get('/auth', (req: Request, res: Response) => {
  res.send('This is the auth route');
});

export default router;