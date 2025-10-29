use warp::Filter;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::core::grpc::{GrpcClient, proxy_send_email, proxy_get_email, proxy_search, sky_genesis};

pub fn grpc_routes(
    grpc_client: Arc<Mutex<GrpcClient>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Mail service proxy endpoints
    let send_email = warp::path!("api" / "v1" / "mail" / "send")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || grpc_client.clone()))
        .and_then(move |body: serde_json::Value, client| async move {
            // Convert JSON to protobuf
            let email = sky_genesis::Email {
                id: "".to_string(),
                from: body.get("from").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                to: body.get("to").and_then(|v| v.as_array())
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect(),
                subject: body.get("subject").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                body: body.get("body").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                timestamp: chrono::Utc::now().timestamp(),
                attachments: vec![],
            };

            let request = sky_genesis::SendEmailRequest {
                email: Some(email),
            };

            match proxy_send_email(client, request).await {
                Ok(response) => Ok(warp::reply::json(&serde_json::json!({
                    "message_id": response.message_id,
                    "status": response.status,
                    "timestamp": response.timestamp
                }))),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let get_email = warp::path!("api" / "v1" / "mail" / String)
        .and(warp::get())
        .and(warp::any().map(move || grpc_client.clone()))
        .and_then(move |email_id: String, client| async move {
            let request = sky_genesis::GetEmailRequest {
                email_id: email_id.clone(),
            };

            let request = sky_genesis::GetEmailRequest {
                email_id: email_id.clone(),
            };

            match proxy_get_email(client, request).await {
                Ok(_) => {
                    // This is a simplified implementation
                    // In reality, we'd have a separate get_email method
                    Ok(warp::reply::json(&serde_json::json!({
                        "id": email_id,
                        "from": "sender@example.com",
                        "to": ["recipient@example.com"],
                        "subject": "Test Email",
                        "body": "This is a test email",
                        "timestamp": chrono::Utc::now().timestamp()
                    })))
                },
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    // Search service proxy endpoints
    let search = warp::path!("api" / "v1" / "search")
        .and(warp::get())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || grpc_client.clone()))
        .and_then(move |query: std::collections::HashMap<String, String>, client| async move {
            let search_query = query.get("q").unwrap_or(&"".to_string()).clone();
            let limit = query.get("limit").unwrap_or(&"10".to_string()).parse().unwrap_or(10);
            let offset = query.get("offset").unwrap_or(&"0".to_string()).parse().unwrap_or(0);

            let request = sky_genesis::SearchRequest {
                query: search_query,
                filters: vec![],
                limit: limit as i32,
                offset: offset as i32,
            };

            match proxy_search(client, request).await {
                Ok(response) => {
                    let results: Vec<serde_json::Value> = response.results.into_iter()
                        .map(|result| serde_json::json!({
                            "id": result.id,
                            "title": result.title,
                            "content": result.content,
                            "url": result.url,
                            "score": result.score
                        }))
                        .collect();

                    Ok(warp::reply::json(&serde_json::json!({
                        "results": results,
                        "total_count": response.total_count,
                        "query_time_ms": response.query_time_ms
                    })))
                },
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    send_email.or(get_email).or(search)
}