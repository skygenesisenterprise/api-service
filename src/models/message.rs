use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::schema::messages;

#[derive(Queryable, Identifiable, Serialize, Deserialize, Debug)]
#[diesel(table_name = messages)]
pub struct Message {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub sender_id: Option<Uuid>,
    pub content: Option<String>,
    pub message_type: String,
    pub reply_to_id: Option<Uuid>,
    pub is_edited: bool,
    pub edited_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = messages)]
pub struct NewMessage {
    pub conversation_id: Uuid,
    pub sender_id: Option<Uuid>,
    pub content: Option<String>,
    pub message_type: Option<String>,
    pub reply_to_id: Option<Uuid>,
}

#[derive(AsChangeset, Deserialize, Debug)]
#[diesel(table_name = messages)]
pub struct UpdateMessage {
    pub content: Option<String>,
    pub is_edited: Option<bool>,
    pub edited_at: Option<NaiveDateTime>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SendMessageRequest {
    pub content: Option<String>,
    pub message_type: Option<String>,
    pub reply_to_id: Option<Uuid>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateMessageRequest {
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageWithDetails {
    #[serde(flatten)]
    pub message: Message,
    pub sender_name: Option<String>,
    pub attachments: Option<Vec<MessageAttachment>>,
    pub reactions: Option<Vec<MessageReaction>>,
    pub read_by: Option<Vec<MessageRead>>,
    pub reply_to: Option<Box<MessageWithDetails>>,
}

use super::schema::message_attachments;

#[derive(Queryable, Identifiable, Serialize, Deserialize, Debug)]
#[diesel(table_name = message_attachments)]
pub struct MessageAttachment {
    pub id: Uuid,
    pub message_id: Uuid,
    pub filename: String,
    pub original_filename: String,
    pub mime_type: Option<String>,
    pub file_size: Option<i32>,
    pub file_url: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = message_attachments)]
pub struct NewMessageAttachment {
    pub message_id: Uuid,
    pub filename: String,
    pub original_filename: String,
    pub mime_type: Option<String>,
    pub file_size: Option<i32>,
    pub file_url: Option<String>,
}

use super::schema::message_reactions;

#[derive(Queryable, Identifiable, Serialize, Deserialize, Debug)]
#[diesel(table_name = message_reactions)]
pub struct MessageReaction {
    pub id: Uuid,
    pub message_id: Uuid,
    pub user_id: Uuid,
    pub reaction: String,
    pub created_at: NaiveDateTime,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = message_reactions)]
pub struct NewMessageReaction {
    pub message_id: Uuid,
    pub user_id: Uuid,
    pub reaction: String,
}

use super::schema::message_reads;

#[derive(Queryable, Identifiable, Serialize, Deserialize, Debug)]
#[diesel(table_name = message_reads)]
pub struct MessageRead {
    pub id: Uuid,
    pub message_id: Uuid,
    pub user_id: Uuid,
    pub read_at: NaiveDateTime,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = message_reads)]
pub struct NewMessageRead {
    pub message_id: Uuid,
    pub user_id: Uuid,
}