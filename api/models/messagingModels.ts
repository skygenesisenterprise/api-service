export interface Conversation {
  id: string;
  organization_id: string;
  title?: string;
  type: 'direct' | 'group' | 'channel';
  created_by: string;
  is_archived: boolean;
  last_message_at?: Date;
  created_at: Date;
  updated_at: Date;
}

export interface ConversationParticipant {
  id: string;
  conversation_id: string;
  user_id: string;
  role: 'admin' | 'member' | 'guest';
  joined_at: Date;
  last_read_at?: Date;
  is_muted: boolean;
}

export interface Message {
  id: string;
  conversation_id: string;
  sender_id: string;
  content?: string;
  message_type: 'text' | 'image' | 'file' | 'system';
  reply_to_id?: string;
  is_edited: boolean;
  edited_at?: Date;
  created_at: Date;
  updated_at: Date;
}

export interface MessageAttachment {
  id: string;
  message_id: string;
  filename: string;
  original_filename: string;
  mime_type?: string;
  file_size?: number;
  file_url?: string;
  created_at: Date;
}

export interface MessageReaction {
  id: string;
  message_id: string;
  user_id: string;
  reaction: string;
  created_at: Date;
}

export interface MessageRead {
  id: string;
  message_id: string;
  user_id: string;
  read_at: Date;
}

// DTOs for API requests/responses
export interface CreateConversationRequest {
  title?: string;
  type: 'direct' | 'group' | 'channel';
  participant_ids: string[];
}

export interface SendMessageRequest {
  content?: string;
  message_type?: 'text' | 'image' | 'file' | 'system';
  reply_to_id?: string;
}

export interface UpdateMessageRequest {
  content: string;
}

export interface ConversationWithParticipants extends Conversation {
  participants: ConversationParticipant[];
  last_message?: Message & { sender_name?: string };
  unread_count?: number;
}

export interface MessageWithDetails extends Message {
  sender_name?: string;
  attachments?: MessageAttachment[];
  reactions?: MessageReaction[];
  read_by?: MessageRead[];
  reply_to?: Message & { sender_name?: string };
}