import { Router } from 'express';
import {
  createAccount,
  authenticate,
  getProfile,
  linkOAuthAccount,
  linkIdentifier,
  refreshToken,
  logout,
  getAccountByGlobalId
} from '../controllers/unifiedAccountController';

const router = Router();

// ========================================
// UNIFIED ACCOUNT ROUTES
// ========================================

/**
 * @route   POST /api/v1/accounts/register
 * @desc    Create a new unified account
 * @access  Public
 */
router.post('/register', createAccount);

/**
 * @route   POST /api/v1/accounts/authenticate
 * @desc    Authenticate user with any identifier
 * @access  Public
 */
router.post('/authenticate', authenticate);

/**
 * @route   GET /api/v1/accounts/profile
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/profile', getProfile);

/**
 * @route   POST /api/v1/accounts/link-oauth
 * @desc    Link OAuth provider to account
 * @access  Private
 */
router.post('/link-oauth', linkOAuthAccount);

/**
 * @route   POST /api/v1/accounts/link-identifier
 * @desc    Link additional identifier (email, phone, username)
 * @access  Private
 */
router.post('/link-identifier', linkIdentifier);

/**
 * @route   POST /api/v1/accounts/refresh-token
 * @desc    Refresh access token
 * @access  Public
 */
router.post('/refresh-token', refreshToken);

/**
 * @route   POST /api/v1/accounts/logout
 * @desc    Logout user (revoke all sessions)
 * @access  Private
 */
router.post('/logout', logout);

/**
 * @route   GET /api/v1/accounts/:globalId
 * @desc    Get account by global ID
 * @access  Public (with limited info)
 */
router.get('/:globalId', getAccountByGlobalId);

export default router;