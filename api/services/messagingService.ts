import pool from '../config/database';
import {
  Conversation,
  ConversationParticipant,
  Message,
  MessageAttachment,
  MessageReaction,
  MessageRead,
  CreateConversationRequest,
  SendMessageRequest,
  UpdateMessageRequest,
  ConversationWithParticipants,
  MessageWithDetails
} from '../models/messagingModels';

export class MessagingService {
  // Conversation operations
  static async createConversation(
    organizationId: string,
    createdBy: string,
    data: CreateConversationRequest
  ): Promise<Conversation> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Create conversation
      const conversationQuery = `
        INSERT INTO api_service.conversations (organization_id, title, type, created_by)
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `;
      const conversationResult = await client.query(conversationQuery, [
        organizationId,
        data.title,
        data.type,
        createdBy
      ]);
      const conversation = conversationResult.rows[0];

      // Add participants
      const participantValues = data.participant_ids.map((userId, index) =>
        `($${index * 2 + 1}, $${index * 2 + 2})`
      ).join(', ');

      const participantParams = data.participant_ids.flatMap(userId => [conversation.id, userId]);

      const participantsQuery = `
        INSERT INTO api_service.conversation_participants (conversation_id, user_id)
        VALUES ${participantValues}
      `;
      await client.query(participantsQuery, participantParams);

      await client.query('COMMIT');
      return conversation;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  static async getUserConversations(userId: string): Promise<ConversationWithParticipants[]> {
    const query = `
      SELECT
        c.*,
        json_agg(
          json_build_object(
            'id', cp.id,
            'conversation_id', cp.conversation_id,
            'user_id', cp.user_id,
            'role', cp.role,
            'joined_at', cp.joined_at,
            'last_read_at', cp.last_read_at,
            'is_muted', cp.is_muted
          )
        ) as participants,
        (
          SELECT json_build_object(
            'id', m.id,
            'content', m.content,
            'sender_id', m.sender_id,
            'created_at', m.created_at,
            'sender_name', u.full_name
          )
          FROM api_service.messages m
          LEFT JOIN api_service.users u ON m.sender_id = u.id
          WHERE m.conversation_id = c.id
          ORDER BY m.created_at DESC
          LIMIT 1
        ) as last_message,
        (
          SELECT COUNT(*)
          FROM api_service.messages m
          WHERE m.conversation_id = c.id
          AND m.created_at > cp.last_read_at
        ) as unread_count
      FROM api_service.conversations c
      JOIN api_service.conversation_participants cp ON c.id = cp.conversation_id
      WHERE cp.user_id = $1 AND c.is_archived = false
      GROUP BY c.id, cp.user_id, cp.last_read_at
      ORDER BY c.last_message_at DESC NULLS LAST
    `;

    const result = await pool.query(query, [userId]);
    return result.rows;
  }

  static async getOrganizationConversations(organizationId: string): Promise<ConversationWithParticipants[]> {
    const query = `
      SELECT
        c.*,
        json_agg(
          json_build_object(
            'id', cp.id,
            'conversation_id', cp.conversation_id,
            'user_id', cp.user_id,
            'role', cp.role,
            'joined_at', cp.joined_at,
            'last_read_at', cp.last_read_at,
            'is_muted', cp.is_muted
          )
        ) as participants,
        (
          SELECT json_build_object(
            'id', m.id,
            'content', m.content,
            'sender_id', m.sender_id,
            'created_at', m.created_at
          )
          FROM api_service.messages m
          WHERE m.conversation_id = c.id
          ORDER BY m.created_at DESC
          LIMIT 1
        ) as last_message
      FROM api_service.conversations c
      LEFT JOIN api_service.conversation_participants cp ON c.id = cp.conversation_id
      WHERE c.organization_id = $1 AND c.is_archived = false
      GROUP BY c.id
      ORDER BY c.last_message_at DESC NULLS LAST
    `;

    const result = await pool.query(query, [organizationId]);
    return result.rows;
  }

  static async getConversation(conversationId: string, userId: string): Promise<ConversationWithParticipants | null> {
    const query = `
      SELECT
        c.*,
        json_agg(
          json_build_object(
            'id', cp.id,
            'conversation_id', cp.conversation_id,
            'user_id', cp.user_id,
            'role', cp.role,
            'joined_at', cp.joined_at,
            'last_read_at', cp.last_read_at,
            'is_muted', cp.is_muted
          )
        ) as participants
      FROM api_service.conversations c
      JOIN api_service.conversation_participants cp ON c.id = cp.conversation_id
      WHERE c.id = $1 AND cp.user_id = $2 AND c.is_archived = false
      GROUP BY c.id
    `;

    const result = await pool.query(query, [conversationId, userId]);
    return result.rows[0] || null;
  }

  static async getConversationByOrganization(conversationId: string, organizationId: string): Promise<ConversationWithParticipants | null> {
    const query = `
      SELECT
        c.*,
        json_agg(
          json_build_object(
            'id', cp.id,
            'conversation_id', cp.conversation_id,
            'user_id', cp.user_id,
            'role', cp.role,
            'joined_at', cp.joined_at,
            'last_read_at', cp.last_read_at,
            'is_muted', cp.is_muted
          )
        ) as participants
      FROM api_service.conversations c
      LEFT JOIN api_service.conversation_participants cp ON c.id = cp.conversation_id
      WHERE c.id = $1 AND c.organization_id = $2 AND c.is_archived = false
      GROUP BY c.id
    `;

    const result = await pool.query(query, [conversationId, organizationId]);
    return result.rows[0] || null;
  }

  static async deleteConversation(conversationId: string, userId: string): Promise<boolean> {
    // Check if user is admin or creator
    const checkQuery = `
      SELECT c.created_by, cp.role
      FROM api_service.conversations c
      JOIN api_service.conversation_participants cp ON c.id = cp.conversation_id
      WHERE c.id = $1 AND cp.user_id = $2
    `;

    const checkResult = await pool.query(checkQuery, [conversationId, userId]);
    if (checkResult.rows.length === 0) {
      return false;
    }

    const { created_by, role } = checkResult.rows[0];
    if (created_by !== userId && role !== 'admin') {
      return false;
    }

    const deleteQuery = 'UPDATE api_service.conversations SET is_archived = true WHERE id = $1';
    await pool.query(deleteQuery, [conversationId]);
    return true;
  }

  static async deleteConversationByOrganization(conversationId: string, organizationId: string): Promise<boolean> {
    // Check if conversation belongs to organization
    const checkQuery = `
      SELECT id FROM api_service.conversations
      WHERE id = $1 AND organization_id = $2 AND is_archived = false
    `;

    const checkResult = await pool.query(checkQuery, [conversationId, organizationId]);
    if (checkResult.rows.length === 0) {
      return false;
    }

    const deleteQuery = 'UPDATE api_service.conversations SET is_archived = true WHERE id = $1';
    await pool.query(deleteQuery, [conversationId]);
    return true;
  }

  // Message operations
  static async sendMessage(
    conversationId: string,
    senderId: string,
    data: SendMessageRequest
  ): Promise<Message> {
    // Verify user is participant
    const participantQuery = `
      SELECT 1 FROM api_service.conversation_participants
      WHERE conversation_id = $1 AND user_id = $2
    `;
    const participantResult = await pool.query(participantQuery, [conversationId, senderId]);
    if (participantResult.rows.length === 0) {
      throw new Error('User is not a participant in this conversation');
    }

    const query = `
      INSERT INTO api_service.messages (conversation_id, sender_id, content, message_type, reply_to_id)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `;

    const result = await pool.query(query, [
      conversationId,
      senderId,
      data.content,
      data.message_type || 'text',
      data.reply_to_id
    ]);

    return result.rows[0];
  }

  static async getMessages(
    conversationId: string,
    userId: string,
    limit: number = 50,
    offset: number = 0
  ): Promise<MessageWithDetails[]> {
    // Verify user is participant
    const participantQuery = `
      SELECT 1 FROM api_service.conversation_participants
      WHERE conversation_id = $1 AND user_id = $2
    `;
    const participantResult = await pool.query(participantQuery, [conversationId, userId]);
    if (participantResult.rows.length === 0) {
      throw new Error('User is not a participant in this conversation');
    }

    const query = `
      SELECT
        m.*,
        u.full_name as sender_name,
        json_agg(
          DISTINCT jsonb_build_object(
            'id', ma.id,
            'filename', ma.filename,
            'original_filename', ma.original_filename,
            'mime_type', ma.mime_type,
            'file_size', ma.file_size,
            'file_url', ma.file_url
          )
        ) FILTER (WHERE ma.id IS NOT NULL) as attachments,
        json_agg(
          DISTINCT jsonb_build_object(
            'id', mr.id,
            'reaction', mr.reaction,
            'user_id', mr.user_id
          )
        ) FILTER (WHERE mr.id IS NOT NULL) as reactions,
        json_agg(
          DISTINCT jsonb_build_object(
            'id', mread.id,
            'user_id', mread.user_id,
            'read_at', mread.read_at
          )
        ) FILTER (WHERE mread.id IS NOT NULL) as read_by,
        json_build_object(
          'id', reply_m.id,
          'content', reply_m.content,
          'sender_id', reply_m.sender_id,
          'created_at', reply_m.created_at,
          'sender_name', reply_u.full_name
        ) as reply_to
      FROM api_service.messages m
      LEFT JOIN api_service.users u ON m.sender_id = u.id
      LEFT JOIN api_service.message_attachments ma ON m.id = ma.message_id
      LEFT JOIN api_service.message_reactions mr ON m.id = mr.message_id
      LEFT JOIN api_service.message_reads mread ON m.id = mread.message_id
      LEFT JOIN api_service.messages reply_m ON m.reply_to_id = reply_m.id
      LEFT JOIN api_service.users reply_u ON reply_m.sender_id = reply_u.id
      WHERE m.conversation_id = $1
      GROUP BY m.id, u.full_name, reply_m.id, reply_m.content, reply_m.sender_id, reply_m.created_at, reply_u.full_name
      ORDER BY m.created_at DESC
      LIMIT $2 OFFSET $3
    `;

    const result = await pool.query(query, [conversationId, limit, offset]);
    return result.rows;
  }

  static async getMessagesByOrganization(
    conversationId: string,
    organizationId: string,
    limit: number = 50,
    offset: number = 0
  ): Promise<MessageWithDetails[]> {
    // Verify conversation belongs to organization
    const conversationQuery = `
      SELECT 1 FROM api_service.conversations
      WHERE id = $1 AND organization_id = $2 AND is_archived = false
    `;
    const conversationResult = await pool.query(conversationQuery, [conversationId, organizationId]);
    if (conversationResult.rows.length === 0) {
      throw new Error('Conversation not found or access denied');
    }

    const query = `
      SELECT
        m.*,
        json_agg(
          DISTINCT jsonb_build_object(
            'id', ma.id,
            'filename', ma.filename,
            'original_filename', ma.original_filename,
            'mime_type', ma.mime_type,
            'file_size', ma.file_size,
            'file_url', ma.file_url
          )
        ) FILTER (WHERE ma.id IS NOT NULL) as attachments,
        json_agg(
          DISTINCT jsonb_build_object(
            'id', mr.id,
            'reaction', mr.reaction,
            'user_id', mr.user_id
          )
        ) FILTER (WHERE mr.id IS NOT NULL) as reactions,
        json_agg(
          DISTINCT jsonb_build_object(
            'id', mread.id,
            'user_id', mread.user_id,
            'read_at', mread.read_at
          )
        ) FILTER (WHERE mread.id IS NOT NULL) as read_by,
        json_build_object(
          'id', reply_m.id,
          'content', reply_m.content,
          'sender_id', reply_m.sender_id,
          'created_at', reply_m.created_at
        ) as reply_to
      FROM api_service.messages m
      LEFT JOIN api_service.message_attachments ma ON m.id = ma.message_id
      LEFT JOIN api_service.message_reactions mr ON m.id = mr.message_id
      LEFT JOIN api_service.message_reads mread ON m.id = mread.message_id
      LEFT JOIN api_service.messages reply_m ON m.reply_to_id = reply_m.id
      WHERE m.conversation_id = $1
      GROUP BY m.id, reply_m.id, reply_m.content, reply_m.sender_id, reply_m.created_at
      ORDER BY m.created_at DESC
      LIMIT $2 OFFSET $3
    `;

    const result = await pool.query(query, [conversationId, limit, offset]);
    return result.rows;
  }

  static async updateMessage(
    messageId: string,
    userId: string,
    data: UpdateMessageRequest
  ): Promise<Message | null> {
    const query = `
      UPDATE api_service.messages
      SET content = $1, is_edited = true, edited_at = NOW()
      WHERE id = $2 AND sender_id = $3
      RETURNING *
    `;

    const result = await pool.query(query, [data.content, messageId, userId]);
    return result.rows[0] || null;
  }

  static async deleteMessage(messageId: string, userId: string): Promise<boolean> {
    const query = 'DELETE FROM api_service.messages WHERE id = $1 AND sender_id = $2';
    const result = await pool.query(query, [messageId, userId]);
    return (result.rowCount ?? 0) > 0;
  }

  // Participant operations
  static async addParticipant(
    conversationId: string,
    userId: string,
    participantId: string,
    adderId: string
  ): Promise<ConversationParticipant | null> {
    // Check if adder has permission (admin or creator)
    const permissionQuery = `
      SELECT c.created_by, cp.role
      FROM api_service.conversations c
      JOIN api_service.conversation_participants cp ON c.id = cp.conversation_id
      WHERE c.id = $1 AND cp.user_id = $2
    `;

    const permissionResult = await pool.query(permissionQuery, [conversationId, adderId]);
    if (permissionResult.rows.length === 0) {
      return null;
    }

    const { created_by, role } = permissionResult.rows[0];
    if (created_by !== adderId && role !== 'admin') {
      return null;
    }

    const query = `
      INSERT INTO api_service.conversation_participants (conversation_id, user_id)
      VALUES ($1, $2)
      ON CONFLICT (conversation_id, user_id) DO NOTHING
      RETURNING *
    `;

    const result = await pool.query(query, [conversationId, participantId]);
    return result.rows[0] || null;
  }

  static async removeParticipant(
    conversationId: string,
    userId: string,
    removerId: string
  ): Promise<boolean> {
    // Check if remover has permission or is removing themselves
    if (userId === removerId) {
    const query = 'DELETE FROM api_service.conversation_participants WHERE conversation_id = $1 AND user_id = $2';
    const result = await pool.query(query, [conversationId, userId]);
    return (result.rowCount ?? 0) > 0;
    }

    const permissionQuery = `
      SELECT c.created_by, cp.role
      FROM api_service.conversations c
      JOIN api_service.conversation_participants cp ON c.id = cp.conversation_id
      WHERE c.id = $1 AND cp.user_id = $2
    `;

    const permissionResult = await pool.query(permissionQuery, [conversationId, removerId]);
    if (permissionResult.rows.length === 0) {
      return false;
    }

    const { created_by, role } = permissionResult.rows[0];
    if (created_by !== removerId && role !== 'admin') {
      return false;
    }

    const query = 'DELETE FROM api_service.conversation_participants WHERE conversation_id = $1 AND user_id = $2';
    const result = await pool.query(query, [conversationId, userId]);
    return (result.rowCount ?? 0) > 0;
  }

  // Message reactions
  static async addReaction(
    messageId: string,
    userId: string,
    reaction: string
  ): Promise<MessageReaction | null> {
    const query = `
      INSERT INTO api_service.message_reactions (message_id, user_id, reaction)
      VALUES ($1, $2, $3)
      ON CONFLICT (message_id, user_id, reaction) DO NOTHING
      RETURNING *
    `;

    const result = await pool.query(query, [messageId, userId, reaction]);
    return result.rows[0] || null;
  }

  static async removeReaction(
    messageId: string,
    userId: string,
    reaction: string
  ): Promise<boolean> {
    const query = 'DELETE FROM api_service.message_reactions WHERE message_id = $1 AND user_id = $2 AND reaction = $3';
    const result = await pool.query(query, [messageId, userId, reaction]);
    return (result.rowCount ?? 0) > 0;
  }

  // Message read status
  static async markMessageAsRead(
    messageId: string,
    userId: string
  ): Promise<MessageRead | null> {
    const query = `
      INSERT INTO api_service.message_reads (message_id, user_id)
      VALUES ($1, $2)
      ON CONFLICT (message_id, user_id) DO NOTHING
      RETURNING *
    `;

    const result = await pool.query(query, [messageId, userId]);
    return result.rows[0] || null;
  }

  static async markConversationAsRead(
    conversationId: string,
    userId: string
  ): Promise<boolean> {
    const query = `
      UPDATE api_service.conversation_participants
      SET last_read_at = NOW()
      WHERE conversation_id = $1 AND user_id = $2
    `;

    const result = await pool.query(query, [conversationId, userId]);
    return (result.rowCount ?? 0) > 0;
  }
}