use actix_web::{web, HttpResponse, Result};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::api_key::ApiKey;
use crate::models::conversation::{CreateConversationRequest, Conversation, ConversationParticipant};
use crate::models::message::{Message};
use crate::models::message::{SendMessageRequest, UpdateMessageRequest, NewMessageAttachment};
use crate::models::schema::{conversations, conversation_participants, messages};
use crate::services::messaging::MessagingService;
use crate::utils::db::DbPool;

pub async fn create_conversation(
    pool: web::Data<DbPool>,
    organization_id: web::Path<Uuid>,
    api_key_data: web::ReqData<ApiKey>,
    req: web::Json<CreateConversationRequest>,
) -> Result<HttpResponse> {
    // Verify the API key belongs to the requested organization
    if (&*api_key_data).organization_id != *organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    if req.participant_ids.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "participant_ids must not be empty"
        })));
    }

    // For API-based messaging, we'll use the API key ID as the creator
    let creator_id = (&*api_key_data).id;

    // Add creator to participants if not already included
    let mut participant_ids = req.participant_ids.clone();
    if !participant_ids.contains(&creator_id) {
        participant_ids.push(creator_id);
    }

    let create_req = CreateConversationRequest {
        title: req.title.clone(),
        type_: req.type_.clone(),
        participant_ids,
    };

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::create_conversation(&mut conn, *organization_id, creator_id, create_req) {
        Ok(conversation) => Ok(HttpResponse::Created().json(serde_json::json!({
            "message": "Conversation created successfully",
            "data": conversation
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create conversation: {}", e)
        }))),
    }
}

pub async fn get_organization_conversations(
    pool: web::Data<DbPool>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let organization_id = (&*api_key_data).organization_id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::get_organization_conversations(&mut conn, organization_id) {
        Ok(conversations) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "data": conversations
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get conversations: {}", e)
        }))),
    }
}

pub async fn get_conversation(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::get_conversation(&mut conn, conversation_id, organization_id) {
        Ok(Some(conversation)) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "data": conversation
        }))),
        Ok(None) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Conversation not found or access denied"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get conversation: {}", e)
        }))),
    }
}

pub async fn delete_conversation(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::delete_conversation(&mut conn, conversation_id, organization_id) {
        Ok(true) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Conversation deleted successfully"
        }))),
        Ok(false) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Conversation not found or access denied"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to delete conversation: {}", e)
        }))),
    }
}

pub async fn send_message(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
    req: web::Json<SendMessageRequest>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    if req.content.is_none() && req.message_type.as_deref() != Some("system") {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Message content is required"
        })));
    }

    // Use API key ID as sender
    let sender_id = (&*api_key_data).id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::send_message(&mut conn, conversation_id, sender_id, req.into_inner()) {
        Ok(message) => Ok(HttpResponse::Created().json(serde_json::json!({
            "message": "Message sent successfully",
            "data": message
        }))),
        Err(e) => {
            if e.to_string().contains("not a participant") {
                Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": e.to_string()
                })))
            } else {
                Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to send message: {}", e)
                })))
            }
        }
    }
}

pub async fn get_messages(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let limit: i64 = query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50);
    let offset: i64 = query.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::get_messages(&mut conn, conversation_id, organization_id, limit, offset) {
        Ok(messages) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "data": messages
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get messages: {}", e)
        }))),
    }
}

pub async fn update_message(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
    req: web::Json<UpdateMessageRequest>,
) -> Result<HttpResponse> {
    let (organization_id, message_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    // Use API key ID as user ID for API-based updates
    let user_id = (&*api_key_data).id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::update_message(&mut conn, message_id, user_id, req.into_inner()) {
        Ok(Some(message)) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Message updated successfully",
            "data": message
        }))),
        Ok(None) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Message not found or access denied"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to update message: {}", e)
        }))),
    }
}

pub async fn delete_message(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, message_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    // Use API key ID as user ID for API-based deletes
    let user_id = (&*api_key_data).id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::delete_message(&mut conn, message_id, user_id) {
        Ok(true) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Message deleted successfully"
        }))),
        Ok(false) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Message not found or access denied"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to delete message: {}", e)
        }))),
    }
}

pub async fn add_participant(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
    req: web::Json<serde_json::Value>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let user_id = req.get("user_id").and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok());

    let user_id = match user_id {
        Some(id) => id,
        None => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "user_id is required"
        }))),
    };

    // Use API key ID as adder
    let adder_id = (&*api_key_data).id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::add_participant(&mut conn, conversation_id, user_id, adder_id) {
        Ok(Some(participant)) => Ok(HttpResponse::Created().json(serde_json::json!({
            "message": "Participant added successfully",
            "data": participant
        }))),
        Ok(None) => Ok(HttpResponse::Conflict().json(serde_json::json!({
            "error": "Participant already exists"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to add participant: {}", e)
        }))),
    }
}

pub async fn remove_participant(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id, user_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    // Use API key ID as remover
    let remover_id = (&*api_key_data).id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::remove_participant(&mut conn, conversation_id, user_id, remover_id) {
        Ok(true) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Participant removed successfully"
        }))),
        Ok(false) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Participant not found"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to remove participant: {}", e)
        }))),
    }
}

pub async fn add_reaction(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
    req: web::Json<serde_json::Value>,
) -> Result<HttpResponse> {
    let (organization_id, message_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let reaction = req.get("reaction").and_then(|v| v.as_str());

    let reaction = match reaction {
        Some(r) => r.to_string(),
        None => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "reaction is required"
        }))),
    };

    // Use API key ID as user ID
    let user_id = (&*api_key_data).id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::add_reaction(&mut conn, message_id, user_id, reaction) {
        Ok(Some(reaction)) => Ok(HttpResponse::Created().json(serde_json::json!({
            "message": "Reaction added successfully",
            "data": reaction
        }))),
        Ok(None) => Ok(HttpResponse::Conflict().json(serde_json::json!({
            "error": "Reaction already exists"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to add reaction: {}", e)
        }))),
    }
}

pub async fn remove_reaction(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid, String)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, message_id, reaction) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    // Use API key ID as user ID
    let user_id = (&*api_key_data).id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::remove_reaction(&mut conn, message_id, user_id, reaction) {
        Ok(true) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Reaction removed successfully"
        }))),
        Ok(false) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Reaction not found"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to remove reaction: {}", e)
        }))),
    }
}

pub async fn mark_message_as_read(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, message_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    // Use API key ID as user ID
    let user_id = (&*api_key_data).id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::mark_message_as_read(&mut conn, message_id, user_id) {
        Ok(Some(read)) => Ok(HttpResponse::Created().json(serde_json::json!({
            "message": "Message marked as read",
            "data": read
        }))),
        Ok(None) => Ok(HttpResponse::Conflict().json(serde_json::json!({
            "error": "Message already read"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to mark message as read: {}", e)
        }))),
    }
}

pub async fn mark_conversation_as_read(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    // Use API key ID as user ID
    let user_id = (&*api_key_data).id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::mark_conversation_as_read(&mut conn, conversation_id, user_id) {
        Ok(true) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Conversation marked as read"
        }))),
        Ok(false) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Conversation or participant not found"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to mark conversation as read: {}", e)
        }))),
    }
}

pub async fn get_participants(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    // Verify conversation exists and belongs to organization
    let conversation_exists = conversations::table
        .filter(conversations::id.eq(conversation_id))
        .filter(conversations::organization_id.eq(organization_id))
        .filter(conversations::is_archived.eq(false))
        .first::<Conversation>(&mut conn)
        .is_ok();

    if !conversation_exists {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Conversation not found"
        })));
    }

    let participants = conversation_participants::table
        .filter(conversation_participants::conversation_id.eq(conversation_id))
        .load::<ConversationParticipant>(&mut conn)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "data": participants
    })))
}

pub async fn add_attachment(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
    req: web::Json<NewMessageAttachment>,
) -> Result<HttpResponse> {
    let (organization_id, message_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    // Verify message belongs to organization
    let message_exists = messages::table
        .filter(messages::id.eq(message_id))
        .first::<Message>(&mut conn)
        .and_then(|msg| {
            conversations::table
                .filter(conversations::id.eq(msg.conversation_id))
                .filter(conversations::organization_id.eq(organization_id))
                .first::<Conversation>(&mut conn)
        })
        .is_ok();

    if !message_exists {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Message not found"
        })));
    }

    let attachment_data = NewMessageAttachment {
        message_id,
        ..req.into_inner()
    };

    match MessagingService::add_attachment(&mut conn, message_id, attachment_data) {
        Ok(attachment) => Ok(HttpResponse::Created().json(serde_json::json!({
            "message": "Attachment added successfully",
            "data": attachment
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to add attachment: {}", e)
        }))),
    }
}

pub async fn get_message_attachments(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, message_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    // Verify message belongs to organization
    let message_exists = messages::table
        .filter(messages::id.eq(message_id))
        .first::<Message>(&mut conn)
        .and_then(|msg| {
            conversations::table
                .filter(conversations::id.eq(msg.conversation_id))
                .filter(conversations::organization_id.eq(organization_id))
                .first::<Conversation>(&mut conn)
        })
        .is_ok();

    if !message_exists {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Message not found"
        })));
    }

    match MessagingService::get_message_attachments(&mut conn, message_id) {
        Ok(attachments) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "data": attachments
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get attachments: {}", e)
        }))),
    }
}

pub async fn delete_attachment(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, message_id, attachment_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let user_id = (&*api_key_data).id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::delete_attachment(&mut conn, attachment_id, user_id) {
        Ok(true) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Attachment deleted successfully"
        }))),
        Ok(false) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Attachment not found or access denied"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to delete attachment: {}", e)
        }))),
    }
}

pub async fn archive_conversation(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::archive_conversation(&mut conn, conversation_id, organization_id) {
        Ok(true) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Conversation archived successfully"
        }))),
        Ok(false) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Conversation not found"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to archive conversation: {}", e)
        }))),
    }
}

pub async fn unarchive_conversation(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::unarchive_conversation(&mut conn, conversation_id, organization_id) {
        Ok(true) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Conversation unarchived successfully"
        }))),
        Ok(false) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Conversation not found"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to unarchive conversation: {}", e)
        }))),
    }
}

pub async fn search_messages(
    pool: web::Data<DbPool>,
    organization_id: web::Path<Uuid>,
    api_key_data: web::ReqData<ApiKey>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> Result<HttpResponse> {
    let organization_id = organization_id.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let search_query = query.get("q").cloned().unwrap_or_default();
    if search_query.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Search query is required"
        })));
    }

    let limit: i64 = query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50);
    let offset: i64 = query.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::search_messages(&mut conn, organization_id, search_query, limit, offset) {
        Ok(messages) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "data": messages
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to search messages: {}", e)
        }))),
    }
}

pub async fn get_unread_count(
    pool: web::Data<DbPool>,
    organization_id: web::Path<Uuid>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let organization_id = organization_id.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let user_id = (&*api_key_data).id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::get_unread_count(&mut conn, user_id, organization_id) {
        Ok(count) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "data": {
                "unread_count": count
            }
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get unread count: {}", e)
        }))),
    }
}

pub async fn get_conversation_unread_count(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id) = path.into_inner();

    if (&*api_key_data).organization_id != organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "API key does not belong to this organization"
        })));
    }

    let user_id = (&*api_key_data).id;

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match MessagingService::get_conversation_unread_count(&mut conn, conversation_id, user_id) {
        Ok(count) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "data": {
                "unread_count": count
            }
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get conversation unread count: {}", e)
        }))),
    }
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/organizations/{organization_id}")
            .service(
                web::scope("/conversations")
                    .route("", web::post().to(create_conversation))
                    .route("", web::get().to(get_organization_conversations))
                    .route("/{conversation_id}", web::get().to(get_conversation))
                    .route("/{conversation_id}", web::delete().to(delete_conversation))
                    .route("/{conversation_id}/archive", web::post().to(archive_conversation))
                    .route("/{conversation_id}/unarchive", web::post().to(unarchive_conversation))
                    .route("/{conversation_id}/unread", web::get().to(get_conversation_unread_count))
                    .service(
                        web::scope("/{conversation_id}/messages")
                            .route("", web::post().to(send_message))
                            .route("", web::get().to(get_messages))
                    )
                    .service(
                        web::scope("/{conversation_id}/participants")
                            .route("", web::get().to(get_participants))
                            .route("", web::post().to(add_participant))
                            .route("/{user_id}", web::delete().to(remove_participant))
                    )
            )
            .service(
                web::scope("/messages/{message_id}")
                    .route("", web::put().to(update_message))
                    .route("", web::delete().to(delete_message))
                    .route("/read", web::post().to(mark_message_as_read))
                    .service(
                        web::scope("/attachments")
                            .route("", web::post().to(add_attachment))
                            .route("", web::get().to(get_message_attachments))
                            .route("/{attachment_id}", web::delete().to(delete_attachment))
                    )
                    .service(
                        web::scope("/reactions")
                            .route("", web::post().to(add_reaction))
                            .route("/{reaction}", web::delete().to(remove_reaction))
                    )
            )
            .service(
                web::scope("/conversations/{conversation_id}/read")
                    .route("", web::post().to(mark_conversation_as_read))
            )
            .service(
                web::scope("/search")
                    .route("/messages", web::get().to(search_messages))
            )
            .service(
                web::scope("/stats")
                    .route("/unread", web::get().to(get_unread_count))
            )
    );
}