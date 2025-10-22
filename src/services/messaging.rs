use diesel::prelude::*;
use std::error::Error;
use uuid::Uuid;

use crate::models::conversation::{Conversation, NewConversation, ConversationWithParticipants, ConversationParticipant, NewConversationParticipant, CreateConversationRequest};
use crate::models::message::{Message, NewMessage, MessageWithDetails, SendMessageRequest, UpdateMessage, UpdateMessageRequest, MessageReaction, NewMessageReaction, MessageRead, NewMessageRead};
use crate::models::schema::{conversations, conversation_participants, messages, message_reactions, message_reads};
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
}