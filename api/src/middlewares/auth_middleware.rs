use warp::{Filter, Rejection};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    scopes: Vec<String>,
}

pub fn jwt_auth() -> impl Filter<Extract = (Claims,), Error = Rejection> + Clone {
    warp::header::<String>("authorization")
        .and_then(|auth: String| async move {
            if !auth.starts_with("Bearer ") {
                return Err(warp::reject::custom(AuthError::InvalidToken));
            }
            let token = auth.trim_start_matches("Bearer ");
            let secret = std::env::var("JWT_SECRET").unwrap_or("secret".to_string());
            let decoding_key = DecodingKey::from_secret(secret.as_ref());
            let validation = Validation::new(Algorithm::HS256);
            match decode::<Claims>(token, &decoding_key, &validation) {
                Ok(token_data) => Ok(token_data.claims),
                Err(_) => Err(warp::reject::custom(AuthError::InvalidToken)),
            }
        })
}

#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
}

impl warp::reject::Reject for AuthError {}