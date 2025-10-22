use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::schema::conversations;

#[derive(Queryable, Identifiable, Serialize, Deserialize, Debug)]
#[diesel(table_name = conversations)]
pub struct Conversation {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub title: Option<String>,
    #[serde(rename = "type")]
    pub type_: String,
    pub created_by: Option<Uuid>,
    pub is_archived: bool,
    pub last_message_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = conversations)]
pub struct NewConversation {
    pub organization_id: Uuid,
    pub title: Option<String>,
    #[serde(rename = "type")]
    pub type_: String,
    pub created_by: Option<Uuid>,
}

#[derive(AsChangeset, Deserialize, Debug)]
#[diesel(table_name = conversations)]
pub struct UpdateConversation {
    pub title: Option<String>,
    pub is_archived: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConversationWithParticipants {
    #[serde(flatten)]
    pub conversation: Conversation,
    pub participants: Vec<ConversationParticipant>,
    pub last_message: Option<MessageSummary>,
    pub unread_count: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageSummary {
    pub id: Uuid,
    pub content: Option<String>,
    pub sender_id: Option<Uuid>,
    pub created_at: NaiveDateTime,
    pub sender_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateConversationRequest {
    pub title: Option<String>,
    #[serde(rename = "type")]
    pub type_: String,
    pub participant_ids: Vec<Uuid>,
}

use super::schema::conversation_participants;

#[derive(Queryable, Identifiable, Serialize, Deserialize, Debug)]
#[diesel(table_name = conversation_participants)]
pub struct ConversationParticipant {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub joined_at: NaiveDateTime,
    pub last_read_at: Option<NaiveDateTime>,
    pub is_muted: bool,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = conversation_participants)]
pub struct NewConversationParticipant {
    pub conversation_id: Uuid,
    pub user_id: Uuid,
    pub role: Option<String>,
}