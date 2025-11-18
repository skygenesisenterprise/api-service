import { Router } from 'express';
import { login, register, getProfile, refreshToken } from '../controllers/authController';

const router: Router = Router();

// POST /api/v1/auth/login - Login user
router.post('/login', login);

// POST /api/v1/auth/register - Register new user
router.post('/register', register);

// GET /api/v1/auth/profile - Get user profile (protected)
router.get('/profile', getProfile);

// POST /api/v1/auth/refresh - Refresh access token
router.post('/refresh', refreshToken);

export default router;