use diesel::prelude::*;
use std::error::Error;
use uuid::Uuid;

use crate::models::conversation::{Conversation, NewConversation, ConversationWithParticipants, ConversationParticipant, NewConversationParticipant, CreateConversationRequest};
use crate::models::message::{Message, NewMessage, MessageWithDetails, SendMessageRequest, UpdateMessage, UpdateMessageRequest, MessageReaction, NewMessageReaction, MessageRead, NewMessageRead, MessageAttachment, NewMessageAttachment};
use crate::models::schema::{conversations, conversation_participants, messages, message_reactions, message_reads, message_attachments};
use crate::utils::db::DbPooledConnection;

pub struct MessagingService;

impl MessagingService {
    // Conversation operations
    pub fn create_conversation(
        conn: &mut DbPooledConnection,
        organization_id: Uuid,
        created_by: Uuid,
        data: CreateConversationRequest,
    ) -> Result<Conversation, Box<dyn Error>> {
        conn.transaction(|conn| {
            // Create conversation
            let new_conversation = NewConversation {
                organization_id,
                title: data.title,
                type_: data.type_,
                created_by: Some(created_by),
            };

            let conversation = diesel::insert_into(conversations::table)
                .values(&new_conversation)
                .get_result::<Conversation>(conn)?;

            // Add participants
            let participant_values: Vec<NewConversationParticipant> = data.participant_ids
                .into_iter()
                .map(|user_id| NewConversationParticipant {
                    conversation_id: conversation.id,
                    user_id,
                    role: Some("member".to_string()),
                })
                .collect();

            diesel::insert_into(conversation_participants::table)
                .values(&participant_values)
                .execute(conn)?;

            Ok(conversation)
        })
    }

    pub fn get_organization_conversations(
        conn: &mut DbPooledConnection,
        organization_id: Uuid,
    ) -> Result<Vec<ConversationWithParticipants>, Box<dyn Error>> {
        // This is a simplified version - in practice, you'd need complex joins
        // For now, just return conversations
        let convs = conversations::table
            .filter(conversations::organization_id.eq(organization_id))
            .filter(conversations::is_archived.eq(false))
            .order(conversations::last_message_at.desc().nulls_last())
            .load::<Conversation>(conn)?;

        // TODO: Add participants and other details
        let result = convs.into_iter().map(|conv| ConversationWithParticipants {
            conversation: conv,
            participants: vec![], // TODO: fetch participants
            last_message: None,
            unread_count: None,
        }).collect();

        Ok(result)
    }

    pub fn get_conversation(
        conn: &mut DbPooledConnection,
        conversation_id: Uuid,
        organization_id: Uuid,
    ) -> Result<Option<ConversationWithParticipants>, Box<dyn Error>> {
        let conversation = conversations::table
            .filter(conversations::id.eq(conversation_id))
            .filter(conversations::organization_id.eq(organization_id))
            .filter(conversations::is_archived.eq(false))
            .first::<Conversation>(conn)
            .optional()?;

        match conversation {
            Some(conv) => {
                // TODO: fetch participants
                Ok(Some(ConversationWithParticipants {
                    conversation: conv,
                    participants: vec![],
                    last_message: None,
                    unread_count: None,
                }))
            }
            None => Ok(None),
        }
    }

    pub fn delete_conversation(
        conn: &mut DbPooledConnection,
        conversation_id: Uuid,
        organization_id: Uuid,
    ) -> Result<bool, Box<dyn Error>> {
        let count = diesel::update(
            conversations::table
                .filter(conversations::id.eq(conversation_id))
                .filter(conversations::organization_id.eq(organization_id))
        )
        .set(conversations::is_archived.eq(true))
        .execute(conn)?;

        Ok(count > 0)
    }

    // Message operations
    pub fn send_message(
        conn: &mut DbPooledConnection,
        conversation_id: Uuid,
        sender_id: Uuid,
        data: SendMessageRequest,
    ) -> Result<Message, Box<dyn Error>> {
        // Verify user is participant
        let participant_exists = conversation_participants::table
            .filter(conversation_participants::conversation_id.eq(conversation_id))
            .filter(conversation_participants::user_id.eq(sender_id))
            .first::<ConversationParticipant>(conn)
            .is_ok();

        if !participant_exists {
            return Err("User is not a participant in this conversation".into());
        }

        let new_message = NewMessage {
            conversation_id,
            sender_id: Some(sender_id),
            content: data.content,
            message_type: Some(data.message_type.unwrap_or_else(|| "text".to_string())),
            reply_to_id: data.reply_to_id,
        };

        let message = diesel::insert_into(messages::table)
            .values(&new_message)
            .get_result::<Message>(conn)?;

        Ok(message)
    }

    pub fn get_messages(
        conn: &mut DbPooledConnection,
        conversation_id: Uuid,
        organization_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MessageWithDetails>, Box<dyn Error>> {
        // Verify conversation belongs to organization
        let conversation_exists = conversations::table
            .filter(conversations::id.eq(conversation_id))
            .filter(conversations::organization_id.eq(organization_id))
            .filter(conversations::is_archived.eq(false))
            .first::<Conversation>(conn)
            .is_ok();

        if !conversation_exists {
            return Err("Conversation not found or access denied".into());
        }

        let msgs = messages::table
            .filter(messages::conversation_id.eq(conversation_id))
            .order(messages::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<Message>(conn)?;

        // TODO: Add attachments, reactions, etc.
        let result = msgs.into_iter().map(|msg| MessageWithDetails {
            message: msg,
            sender_name: None, // TODO: fetch sender name
            attachments: None,
            reactions: None,
            read_by: None,
            reply_to: None,
        }).collect();

        Ok(result)
    }

    pub fn update_message(
        conn: &mut DbPooledConnection,
        message_id: Uuid,
        user_id: Uuid,
        data: UpdateMessageRequest,
    ) -> Result<Option<Message>, Box<dyn Error>> {
        let result = diesel::update(
            messages::table
                .filter(messages::id.eq(message_id))
                .filter(messages::sender_id.eq(user_id))
        )
        .set((
            messages::content.eq(&data.content),
            messages::is_edited.eq(true),
            messages::edited_at.eq(diesel::dsl::now),
        ))
        .get_result::<Message>(conn)
        .optional()?;

        Ok(result)
    }

    pub fn delete_message(
        conn: &mut DbPooledConnection,
        message_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, Box<dyn Error>> {
        let count = diesel::delete(
            messages::table
                .filter(messages::id.eq(message_id))
                .filter(messages::sender_id.eq(user_id))
        )
        .execute(conn)?;

        Ok(count > 0)
    }

    // Participant operations
    pub fn add_participant(
        conn: &mut DbPooledConnection,
        conversation_id: Uuid,
        user_id: Uuid,
        adder_id: Uuid,
    ) -> Result<Option<ConversationParticipant>, Box<dyn Error>> {
        // TODO: Check permissions

        let new_participant = NewConversationParticipant {
            conversation_id,
            user_id,
            role: Some("member".to_string()),
        };

        let participant = diesel::insert_into(conversation_participants::table)
            .values(&new_participant)
            .on_conflict_do_nothing()
            .get_result::<ConversationParticipant>(conn)
            .optional()?;

        Ok(participant)
    }

    pub fn remove_participant(
        conn: &mut DbPooledConnection,
        conversation_id: Uuid,
        user_id: Uuid,
        remover_id: Uuid,
    ) -> Result<bool, Box<dyn Error>> {
        if user_id == remover_id {
            // User removing themselves
            let count = diesel::delete(
                conversation_participants::table
                    .filter(conversation_participants::conversation_id.eq(conversation_id))
                    .filter(conversation_participants::user_id.eq(user_id))
            )
            .execute(conn)?;
            Ok(count > 0)
        } else {
            // TODO: Check if remover has admin permissions
            let count = diesel::delete(
                conversation_participants::table
                    .filter(conversation_participants::conversation_id.eq(conversation_id))
                    .filter(conversation_participants::user_id.eq(user_id))
            )
            .execute(conn)?;
            Ok(count > 0)
        }
    }

    // Message reactions
    pub fn add_reaction(
        conn: &mut DbPooledConnection,
        message_id: Uuid,
        user_id: Uuid,
        reaction: String,
    ) -> Result<Option<MessageReaction>, Box<dyn Error>> {
        let new_reaction = NewMessageReaction {
            message_id,
            user_id,
            reaction,
        };

        let reaction = diesel::insert_into(message_reactions::table)
            .values(&new_reaction)
            .on_conflict_do_nothing()
            .get_result::<MessageReaction>(conn)
            .optional()?;

        Ok(reaction)
    }

    pub fn remove_reaction(
        conn: &mut DbPooledConnection,
        message_id: Uuid,
        user_id: Uuid,
        reaction: String,
    ) -> Result<bool, Box<dyn Error>> {
        let count = diesel::delete(
            message_reactions::table
                .filter(message_reactions::message_id.eq(message_id))
                .filter(message_reactions::user_id.eq(user_id))
                .filter(message_reactions::reaction.eq(reaction))
        )
        .execute(conn)?;

        Ok(count > 0)
    }

    // Message read status
    pub fn mark_message_as_read(
        conn: &mut DbPooledConnection,
        message_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<MessageRead>, Box<dyn Error>> {
        let new_read = NewMessageRead {
            message_id,
            user_id,
        };

        let read = diesel::insert_into(message_reads::table)
            .values(&new_read)
            .on_conflict_do_nothing()
            .get_result::<MessageRead>(conn)
            .optional()?;

        Ok(read)
    }

    pub fn mark_conversation_as_read(
        conn: &mut DbPooledConnection,
        conversation_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, Box<dyn Error>> {
        let count = diesel::update(
            conversation_participants::table
                .filter(conversation_participants::conversation_id.eq(conversation_id))
                .filter(conversation_participants::user_id.eq(user_id))
        )
        .set(conversation_participants::last_read_at.eq(diesel::dsl::now))
        .execute(conn)?;

        Ok(count > 0)
    }

    // Message attachments
    pub fn add_attachment(
        conn: &mut DbPooledConnection,
        message_id: Uuid,
        attachment_data: NewMessageAttachment,
    ) -> Result<MessageAttachment, Box<dyn Error>> {
        // Verify message exists
        messages::table
            .filter(messages::id.eq(message_id))
            .first::<Message>(conn)?;

        let attachment = diesel::insert_into(message_attachments::table)
            .values(&attachment_data)
            .get_result::<MessageAttachment>(conn)?;

        Ok(attachment)
    }

    pub fn get_message_attachments(
        conn: &mut DbPooledConnection,
        message_id: Uuid,
    ) -> Result<Vec<MessageAttachment>, Box<dyn Error>> {
        let attachments = message_attachments::table
            .filter(message_attachments::message_id.eq(message_id))
            .load::<MessageAttachment>(conn)?;

        Ok(attachments)
    }

    pub fn delete_attachment(
        conn: &mut DbPooledConnection,
        attachment_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, Box<dyn Error>> {
        // First verify the attachment exists and belongs to a message sent by the user
        let attachment = message_attachments::table
            .filter(message_attachments::id.eq(attachment_id))
            .first::<MessageAttachment>(conn)?;

        let message_sender = messages::table
            .filter(messages::id.eq(attachment.message_id))
            .filter(messages::sender_id.eq(user_id))
            .first::<Message>(conn)
            .is_ok();

        if !message_sender {
            return Ok(false);
        }

        // Delete the attachment
        let count = diesel::delete(
            message_attachments::table
                .filter(message_attachments::id.eq(attachment_id))
        )
        .execute(conn)?;

        Ok(count > 0)
    }

    // Conversation archiving
    pub fn archive_conversation(
        conn: &mut DbPooledConnection,
        conversation_id: Uuid,
        organization_id: Uuid,
    ) -> Result<bool, Box<dyn Error>> {
        let count = diesel::update(
            conversations::table
                .filter(conversations::id.eq(conversation_id))
                .filter(conversations::organization_id.eq(organization_id))
        )
        .set(conversations::is_archived.eq(true))
        .execute(conn)?;

        Ok(count > 0)
    }

    pub fn unarchive_conversation(
        conn: &mut DbPooledConnection,
        conversation_id: Uuid,
        organization_id: Uuid,
    ) -> Result<bool, Box<dyn Error>> {
        let count = diesel::update(
            conversations::table
                .filter(conversations::id.eq(conversation_id))
                .filter(conversations::organization_id.eq(organization_id))
        )
        .set(conversations::is_archived.eq(false))
        .execute(conn)?;

        Ok(count > 0)
    }

    // Search functionality
    pub fn search_messages(
        conn: &mut DbPooledConnection,
        organization_id: Uuid,
        query: String,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MessageWithDetails>, Box<dyn Error>> {
        // First get conversation IDs for the organization
        let conversation_ids = conversations::table
            .filter(conversations::organization_id.eq(organization_id))
            .filter(conversations::is_archived.eq(false))
            .select(conversations::id)
            .load::<Uuid>(conn)?;

        let msgs = messages::table
            .filter(messages::conversation_id.eq_any(conversation_ids))
            .filter(messages::content.like(format!("%{}%", query)))
            .order(messages::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<Message>(conn)?;

        // TODO: Add attachments, reactions, etc.
        let result = msgs.into_iter().map(|msg| MessageWithDetails {
            message: msg,
            sender_name: None,
            attachments: None,
            reactions: None,
            read_by: None,
            reply_to: None,
        }).collect();

        Ok(result)
    }

    // Statistics
    pub fn get_unread_count(
        conn: &mut DbPooledConnection,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> Result<i64, Box<dyn Error>> {
        // Get conversation IDs where user is participant
        let conversation_ids = conversation_participants::table
            .filter(conversation_participants::user_id.eq(user_id))
            .select(conversation_participants::conversation_id)
            .load::<Uuid>(conn)?;

        if conversation_ids.is_empty() {
            return Ok(0);
        }

        // Get conversations that belong to the organization and are not archived
        let org_conversation_ids = conversations::table
            .filter(conversations::organization_id.eq(organization_id))
            .filter(conversations::is_archived.eq(false))
            .filter(conversations::id.eq_any(conversation_ids))
            .select(conversations::id)
            .load::<Uuid>(conn)?;

        if org_conversation_ids.is_empty() {
            return Ok(0);
        }

        // Count total messages in those conversations
        let total_messages = messages::table
            .filter(messages::conversation_id.eq_any(org_conversation_ids.clone()))
            .count()
            .get_result::<i64>(conn)?;

        // Get message IDs in those conversations
        let message_ids = messages::table
            .filter(messages::conversation_id.eq_any(org_conversation_ids))
            .select(messages::id)
            .load::<Uuid>(conn)?;

        // Count read messages
        let read_messages = message_reads::table
            .filter(message_reads::user_id.eq(user_id))
            .filter(message_reads::message_id.eq_any(message_ids))
            .count()
            .get_result::<i64>(conn)?;

        Ok(total_messages - read_messages)
    }

    pub fn get_conversation_unread_count(
        conn: &mut DbPooledConnection,
        conversation_id: Uuid,
        user_id: Uuid,
    ) -> Result<i64, Box<dyn Error>> {
        // Get all message IDs in the conversation
        let message_ids = messages::table
            .filter(messages::conversation_id.eq(conversation_id))
            .select(messages::id)
            .load::<Uuid>(conn)?;

        // Count how many of those messages haven't been read by the user
        let read_count = message_reads::table
            .filter(message_reads::user_id.eq(user_id))
            .filter(message_reads::message_id.eq_any(message_ids.clone()))
            .count()
            .get_result::<i64>(conn)?;

        Ok(message_ids.len() as i64 - read_count)
    }
}