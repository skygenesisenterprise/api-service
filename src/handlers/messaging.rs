use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::api_key::ApiKey;
use crate::models::conversation::{CreateConversationRequest};
use crate::models::message::{SendMessageRequest, UpdateMessageRequest};
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
    req: web::Json<UpdateMessageRequest>,
) -> Result<HttpResponse> {
    let (organization_id, message_id) = path.into_inner();

    // For API-based updates, we need user authentication, not just API key
    // This is a simplified version - in practice, you'd need user auth
    return Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "Message update requires user authentication"
    })));
}

pub async fn delete_message(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse> {
    let (organization_id, message_id) = path.into_inner();

    // For API-based deletes, we need user authentication, not just API key
    return Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "Message delete requires user authentication"
    })));
}

pub async fn add_participant(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    req: web::Json<serde_json::Value>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id) = path.into_inner();
    let user_id = req.get("user_id").and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok());

    let user_id = match user_id {
        Some(id) => id,
        None => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "user_id is required"
        }))),
    };

    // Simplified - using API key as adder
    return Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "Participant management requires user authentication"
    })));
}

pub async fn remove_participant(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid, Uuid)>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id, user_id) = path.into_inner();

    return Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "Participant management requires user authentication"
    })));
}

pub async fn add_reaction(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    req: web::Json<serde_json::Value>,
) -> Result<HttpResponse> {
    let (organization_id, message_id) = path.into_inner();
    let reaction = req.get("reaction").and_then(|v| v.as_str());

    let reaction = match reaction {
        Some(r) => r,
        None => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "reaction is required"
        }))),
    };

    return Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "Reactions require user authentication"
    })));
}

pub async fn remove_reaction(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid, String)>,
) -> Result<HttpResponse> {
    let (organization_id, message_id, reaction) = path.into_inner();

    return Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "Reactions require user authentication"
    })));
}

pub async fn mark_message_as_read(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse> {
    let (organization_id, message_id) = path.into_inner();

    return Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "Read status requires user authentication"
    })));
}

pub async fn mark_conversation_as_read(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse> {
    let (organization_id, conversation_id) = path.into_inner();

    return Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "Read status requires user authentication"
    })));
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
                    .service(
                        web::scope("/{conversation_id}/messages")
                            .route("", web::post().to(send_message))
                            .route("", web::get().to(get_messages))
                    )
                    .service(
                        web::scope("/{conversation_id}/participants")
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
                        web::scope("/reactions")
                            .route("", web::post().to(add_reaction))
                            .route("/{reaction}", web::delete().to(remove_reaction))
                    )
            )
            .service(
                web::scope("/conversations/{conversation_id}/read")
                    .route("", web::post().to(mark_conversation_as_read))
            )
    );
}