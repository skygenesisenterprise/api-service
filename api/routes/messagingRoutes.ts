import express from 'express';
import {
  createConversation,
  getOrganizationConversations,
  getConversation,
  deleteConversation,
  sendMessage,
  getMessages,
  updateMessage,
  deleteMessage,
  addParticipant,
  removeParticipant,
  addReaction,
  removeReaction,
  markMessageAsRead,
  markConversationAsRead
} from '../controllers/messagingControllers';
import { authenticateApiKey, requirePermission } from '../middlewares/authMiddlewares';

const router = express.Router();

// Apply API key authentication to all routes
router.use(authenticateApiKey);

// Conversation routes
router.post('/organizations/:organization_id/conversations', requirePermission('write'), createConversation);
router.get('/organizations/:organization_id/conversations', requirePermission('read'), getOrganizationConversations);
router.get('/organizations/:organization_id/conversations/:conversation_id', requirePermission('read'), getConversation);
router.delete('/organizations/:organization_id/conversations/:conversation_id', requirePermission('write'), deleteConversation);

// Message routes
router.post('/organizations/:organization_id/conversations/:conversation_id/messages', requirePermission('write'), sendMessage);
router.get('/organizations/:organization_id/conversations/:conversation_id/messages', requirePermission('read'), getMessages);
router.put('/organizations/:organization_id/messages/:message_id', requirePermission('write'), updateMessage);
router.delete('/organizations/:organization_id/messages/:message_id', requirePermission('write'), deleteMessage);

// Participant management routes
router.post('/organizations/:organization_id/conversations/:conversation_id/participants', requirePermission('write'), addParticipant);
router.delete('/organizations/:organization_id/conversations/:conversation_id/participants/:user_id', requirePermission('write'), removeParticipant);

// Reaction routes
router.post('/organizations/:organization_id/messages/:message_id/reactions', requirePermission('write'), addReaction);
router.delete('/organizations/:organization_id/messages/:message_id/reactions/:reaction', requirePermission('write'), removeReaction);

// Read status routes
router.post('/organizations/:organization_id/messages/:message_id/read', requirePermission('write'), markMessageAsRead);
router.post('/organizations/:organization_id/conversations/:conversation_id/read', requirePermission('write'), markConversationAsRead);

export default router;