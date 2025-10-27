use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey, errors::Error};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub roles: Vec<String>,
    pub exp: usize,
    pub iat: usize,
}

pub fn generate_jwt(user: &crate::models::user::User) -> Result<String, Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(1))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user.id.clone(),
        email: user.email.clone(),
        roles: user.roles.clone(),
        exp: expiration,
        iat: Utc::now().timestamp() as usize,
    };

    let secret = std::env::var("JWT_SECRET").unwrap_or("secret".to_string());
    let encoding_key = EncodingKey::from_secret(secret.as_ref());
    encode(&Header::default(), &claims, &encoding_key)
}

pub fn validate_jwt(token: &str) -> Result<Claims, Error> {
    let secret = std::env::var("JWT_SECRET").unwrap_or("secret".to_string());
    let decoding_key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}