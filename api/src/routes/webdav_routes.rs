use warp::Filter;
use std::sync::Arc;
use crate::core::webdav::{WebDavHandler, CalDavHandler, CardDavHandler, handle_propfind, handle_proppatch, handle_mkcol, handle_put, handle_delete, handle_move};

pub fn webdav_routes(
    webdav_handler: Arc<WebDavHandler>,
    caldav_handler: Arc<CalDavHandler>,
    carddav_handler: Arc<CardDavHandler>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // WebDAV file management endpoints
    let propfind = warp::path!("api" / "v1" / "dav" / "files" / ..)
        .and(warp::method())
        .and(warp::method().map(|method: warp::http::Method| method == warp::http::Method::from_bytes(b"PROPFIND").unwrap()))
        .and(warp::header::optional::<String>("depth"))
        .and(warp::any().map(move || webdav_handler.clone()))
        .and_then(move |depth, handler| async move {
            let path = "/api/v1/dav/files"; // Simplified path handling
            match handle_propfind(handler, path, depth.as_deref()).await {
                Ok(xml) => Ok(warp::reply::with_header(
                    xml,
                    "Content-Type",
                    "application/xml"
                )),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let proppatch = warp::path!("api" / "v1" / "dav" / "files" / ..)
        .and(warp::method())
        .and(warp::method().map(|method: warp::http::Method| method == warp::http::Method::from_bytes(b"PROPPATCH").unwrap()))
        .and(warp::body::json())
        .and(warp::any().map(move || webdav_handler.clone()))
        .and_then(move |properties: serde_json::Value, handler| async move {
            let path = "/api/v1/dav/files"; // Simplified path handling
            let props_map: std::collections::HashMap<String, String> = serde_json::from_value(properties).unwrap_or_default();

            match handle_proppatch(handler, path, props_map).await {
                Ok(xml) => Ok(warp::reply::with_header(
                    xml,
                    "Content-Type",
                    "application/xml"
                )),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let mkcol = warp::path!("api" / "v1" / "dav" / "files" / ..)
        .and(warp::method())
        .and(warp::method().map(|method: warp::http::Method| method == warp::http::Method::from_bytes(b"MKCOL").unwrap()))
        .and(warp::any().map(move || webdav_handler.clone()))
        .and_then(move |handler| async move {
            let path = "/api/v1/dav/files/new_collection"; // Simplified path handling

            match handle_mkcol(handler, path).await {
                Ok(_) => Ok(warp::reply::with_status(
                    "",
                    warp::http::StatusCode::CREATED
                )),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let put_file = warp::path!("api" / "v1" / "dav" / "files" / ..)
        .and(warp::put())
        .and(warp::body::bytes())
        .and(warp::header::optional::<String>("content-type"))
        .and(warp::any().map(move || webdav_handler.clone()))
        .and_then(move |data: bytes::Bytes, content_type, handler| async move {
            let path = "/api/v1/dav/files/new_file"; // Simplified path handling

            match handle_put(handler, path, &data, content_type.as_deref()).await {
                Ok(_) => Ok(warp::reply::with_status(
                    "",
                    warp::http::StatusCode::CREATED
                )),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let delete_resource = warp::path!("api" / "v1" / "dav" / "files" / ..)
        .and(warp::delete())
        .and(warp::any().map(move || webdav_handler.clone()))
        .and_then(move |handler| async move {
            let path = "/api/v1/dav/files/resource"; // Simplified path handling

            match handle_delete(handler, path).await {
                Ok(_) => Ok(warp::reply::with_status(
                    "",
                    warp::http::StatusCode::NO_CONTENT
                )),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let move_resource = warp::path!("api" / "v1" / "dav" / "files" / ..)
        .and(warp::method())
        .and(warp::method().map(|method: warp::http::Method| method == warp::http::Method::from_bytes(b"MOVE").unwrap()))
        .and(warp::header::<String>("destination"))
        .and(warp::any().map(move || webdav_handler.clone()))
        .and_then(move |destination: String, handler| async move {
            let from = "/api/v1/dav/files/source"; // Simplified path handling

            match handle_move(handler, from, &destination).await {
                Ok(_) => Ok(warp::reply::with_status(
                    "",
                    warp::http::StatusCode::CREATED
                )),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    // CalDAV calendar endpoints
    let create_calendar = warp::path!("api" / "v1" / "dav" / "calendar")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || caldav_handler.clone()))
        .and_then(move |body: serde_json::Value, handler| async move {
            let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("default");

            match handler.create_calendar("/api/v1/dav/calendar", name).await {
                Ok(_) => Ok(warp::reply::json(&serde_json::json!({"status": "calendar_created"}))),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let create_event = warp::path!("api" / "v1" / "dav" / "calendar" / "events")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || caldav_handler.clone()))
        .and_then(move |body: serde_json::Value, handler| async move {
            let calendar_path = "/api/v1/dav/calendar/default"; // Simplified
            let event_data = body.get("data").and_then(|v| v.as_str()).unwrap_or("");

            match handler.create_event(calendar_path, event_data).await {
                Ok(event_path) => Ok(warp::reply::json(&serde_json::json!({
                    "status": "event_created",
                    "event_path": event_path
                }))),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    // CardDAV contacts endpoints
    let create_addressbook = warp::path!("api" / "v1" / "dav" / "contacts")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || carddav_handler.clone()))
        .and_then(move |body: serde_json::Value, handler| async move {
            let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("default");

            match handler.create_addressbook("/api/v1/dav/contacts", name).await {
                Ok(_) => Ok(warp::reply::json(&serde_json::json!({"status": "addressbook_created"}))),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let create_contact = warp::path!("api" / "v1" / "dav" / "contacts" / "cards")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || carddav_handler.clone()))
        .and_then(move |body: serde_json::Value, handler| async move {
            let addressbook_path = "/api/v1/dav/contacts/default"; // Simplified
            let contact_data = body.get("data").and_then(|v| v.as_str()).unwrap_or("");

            match handler.create_contact(addressbook_path, contact_data).await {
                Ok(contact_path) => Ok(warp::reply::json(&serde_json::json!({
                    "status": "contact_created",
                    "contact_path": contact_path
                }))),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    propfind.or(proppatch).or(mkcol).or(put_file).or(delete_resource).or(move_resource)
        .or(create_calendar).or(create_event)
        .or(create_addressbook).or(create_contact)
}