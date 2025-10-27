// Controllers for handling API requests

use warp::Reply;
use crate::models::ApiKey;

pub async fn handle_protected(api_key: ApiKey) -> Result<impl Reply, warp::Rejection> {
    // Business logic here
    Ok(warp::reply::json(&serde_json::json!({
        "message": "Access granted",
        "key_type": format!("{:?}", api_key.key_type),
        "permissions": api_key.permissions
    })))
}