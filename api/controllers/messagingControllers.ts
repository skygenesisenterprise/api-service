import { Request, Response } from 'express';
import { MessagingService } from '../services/messagingService';
import { CreateConversationRequest, SendMessageRequest, UpdateMessageRequest } from '../models/messagingModels';

// Conversation Controllers
export const createConversation = async (req: Request, res: Response) => {
  try {
    const { organization_id } = req.params;
    const apiKeyData = (req as any).apiKey;
    const data: CreateConversationRequest = req.body;

    if (!apiKeyData) {
      return res.status(401).json({ error: 'API key authentication required' });
    }

    // Verify the API key belongs to the requested organization
    if (apiKeyData.organization_id !== organization_id) {
      return res.status(403).json({ error: 'API key does not belong to this organization' });
    }

    if (!data.participant_ids || !Array.isArray(data.participant_ids)) {
      return res.status(400).json({ error: 'participant_ids must be an array' });
    }

    // For API-based messaging, we'll use the API key ID as the creator
    // In a real implementation, you might want to map API keys to users
    const creatorId = apiKeyData.id;

    // Add creator to participants if not already included
    if (!data.participant_ids.includes(creatorId)) {
      data.participant_ids.push(creatorId);
    }

    const conversation = await MessagingService.createConversation(organization_id, creatorId, data);
    return res.status(201).json({ message: 'Conversation created successfully', data: conversation });
  } catch (error) {
    console.error('Create conversation error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const getOrganizationConversations = async (req: Request, res: Response) => {
  try {
    const apiKeyData = (req as any).apiKey;
    const organizationId = apiKeyData.organization_id;

    if (!apiKeyData) {
      return res.status(401).json({ error: 'API key authentication required' });
    }

    // For API-based access, we'll get all conversations for the organization
    // In a real implementation, you might want to filter based on API key permissions
    const conversations = await MessagingService.getOrganizationConversations(organizationId);
    return res.status(200).json({ data: conversations });
  } catch (error) {
    console.error('Get conversations error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const getConversation = async (req: Request, res: Response) => {
  try {
    const { conversation_id } = req.params;
    const apiKeyData = (req as any).apiKey;
    const organizationId = apiKeyData.organization_id;

    if (!apiKeyData) {
      return res.status(401).json({ error: 'API key authentication required' });
    }

    const conversation = await MessagingService.getConversationByOrganization(conversation_id, organizationId);
    if (!conversation) {
      return res.status(404).json({ error: 'Conversation not found or access denied' });
    }

    return res.status(200).json({ data: conversation });
  } catch (error) {
    console.error('Get conversation error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const deleteConversation = async (req: Request, res: Response) => {
  try {
    const { conversation_id } = req.params;
    const apiKeyData = (req as any).apiKey;
    const organizationId = apiKeyData.organization_id;

    if (!apiKeyData) {
      return res.status(401).json({ error: 'API key authentication required' });
    }

    const success = await MessagingService.deleteConversationByOrganization(conversation_id, organizationId);
    if (!success) {
      return res.status(404).json({ error: 'Conversation not found or access denied' });
    }

    return res.status(200).json({ message: 'Conversation deleted successfully' });
  } catch (error) {
    console.error('Delete conversation error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// Message Controllers
export const sendMessage = async (req: Request, res: Response) => {
  try {
    const { conversation_id } = req.params;
    const apiKeyData = (req as any).apiKey;
    const data: SendMessageRequest = req.body;

    if (!apiKeyData) {
      return res.status(401).json({ error: 'API key authentication required' });
    }

    if (!data.content && !data.message_type) {
      return res.status(400).json({ error: 'Message content is required' });
    }

    // Use API key ID as sender
    const senderId = apiKeyData.id;

    const message = await MessagingService.sendMessage(conversation_id, senderId, data);
    return res.status(201).json({ message: 'Message sent successfully', data: message });
  } catch (error) {
    console.error('Send message error:', error);
    if (error instanceof Error && error.message === 'User is not a participant in this conversation') {
      return res.status(403).json({ error: error.message });
    }
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const getMessages = async (req: Request, res: Response) => {
  try {
    const { conversation_id } = req.params;
    const apiKeyData = (req as any).apiKey;
    const organizationId = apiKeyData.organization_id;
    const limit = parseInt(req.query.limit as string) || 50;
    const offset = parseInt(req.query.offset as string) || 0;

    if (!apiKeyData) {
      return res.status(401).json({ error: 'API key authentication required' });
    }

    const messages = await MessagingService.getMessagesByOrganization(conversation_id, organizationId, limit, offset);
    return res.status(200).json({ data: messages });
  } catch (error) {
    console.error('Get messages error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const updateMessage = async (req: Request, res: Response) => {
  try {
    const { message_id } = req.params;
    const userId = (req as any).user?.id;
    const data: UpdateMessageRequest = req.body;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!data.content) {
      return res.status(400).json({ error: 'Message content is required' });
    }

    const message = await MessagingService.updateMessage(message_id, userId, data);
    if (!message) {
      return res.status(404).json({ error: 'Message not found or permission denied' });
    }

    return res.status(200).json({ message: 'Message updated successfully', data: message });
  } catch (error) {
    console.error('Update message error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const deleteMessage = async (req: Request, res: Response) => {
  try {
    const { message_id } = req.params;
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const success = await MessagingService.deleteMessage(message_id, userId);
    if (!success) {
      return res.status(404).json({ error: 'Message not found or permission denied' });
    }

    return res.status(200).json({ message: 'Message deleted successfully' });
  } catch (error) {
    console.error('Delete message error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// Participant Controllers
export const addParticipant = async (req: Request, res: Response) => {
  try {
    const { conversation_id } = req.params;
    const { user_id } = req.body;
    const adderId = (req as any).user?.id;

    if (!adderId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!user_id) {
      return res.status(400).json({ error: 'user_id is required' });
    }

    const participant = await MessagingService.addParticipant(conversation_id, user_id, user_id, adderId);
    if (!participant) {
      return res.status(403).json({ error: 'Permission denied or user already a participant' });
    }

    return res.status(200).json({ message: 'Participant added successfully', data: participant });
  } catch (error) {
    console.error('Add participant error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const removeParticipant = async (req: Request, res: Response) => {
  try {
    const { conversation_id, user_id } = req.params;
    const removerId = (req as any).user?.id;

    if (!removerId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const success = await MessagingService.removeParticipant(conversation_id, user_id, removerId);
    if (!success) {
      return res.status(403).json({ error: 'Permission denied or participant not found' });
    }

    return res.status(200).json({ message: 'Participant removed successfully' });
  } catch (error) {
    console.error('Remove participant error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// Reaction Controllers
export const addReaction = async (req: Request, res: Response) => {
  try {
    const { message_id } = req.params;
    const { reaction } = req.body;
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!reaction) {
      return res.status(400).json({ error: 'reaction is required' });
    }

    const messageReaction = await MessagingService.addReaction(message_id, userId, reaction);
    if (!messageReaction) {
      return res.status(409).json({ error: 'Reaction already exists' });
    }

    return res.status(200).json({ message: 'Reaction added successfully', data: messageReaction });
  } catch (error) {
    console.error('Add reaction error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const removeReaction = async (req: Request, res: Response) => {
  try {
    const { message_id, reaction } = req.params;
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const success = await MessagingService.removeReaction(message_id, userId, decodeURIComponent(reaction));
    if (!success) {
      return res.status(404).json({ error: 'Reaction not found' });
    }

    return res.status(200).json({ message: 'Reaction removed successfully' });
  } catch (error) {
    console.error('Remove reaction error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// Read Status Controllers
export const markMessageAsRead = async (req: Request, res: Response) => {
  try {
    const { message_id } = req.params;
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const readStatus = await MessagingService.markMessageAsRead(message_id, userId);
    return res.status(200).json({ message: 'Message marked as read', data: readStatus });
  } catch (error) {
    console.error('Mark message as read error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const markConversationAsRead = async (req: Request, res: Response) => {
  try {
    const { conversation_id } = req.params;
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const success = await MessagingService.markConversationAsRead(conversation_id, userId);
    if (!success) {
      return res.status(404).json({ error: 'Conversation not found or user not a participant' });
    }

    return res.status(200).json({ message: 'Conversation marked as read' });
  } catch (error) {
    console.error('Mark conversation as read error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};