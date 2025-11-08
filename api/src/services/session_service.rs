use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use uuid::Uuid;
use chrono::{Utc, Duration};
use crate::models::user::User;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user_id: String,
    pub email: String,
    pub roles: Vec<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    pub last_activity: chrono::DateTime<Utc>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionToken {
    pub session_id: String,
    pub user_id: String,
    pub expires_at: chrono::DateTime<Utc>,
}

pub struct SessionService {
    redis_client: redis::Client,
    session_ttl: usize, // in seconds
    cookie_name: String,
    cookie_domain: String,
    cookie_secure: bool,
}

impl SessionService {
    pub fn new(redis_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let redis_client = redis::Client::open(redis_url)?;

        // Load configuration from environment
        let defaults = load_defaults_from_env_example();
        let session_ttl = std::env::var("SESSION_TTL_SECONDS")
            .unwrap_or_else(|_| defaults.get("SESSION_TTL_SECONDS").unwrap_or(&"604800".to_string()).clone())
            .parse::<usize>()
            .unwrap_or(604800); // 7 days default

        let cookie_name = std::env::var("SESSION_COOKIE_NAME")
            .unwrap_or_else(|_| "sky_genesis_session".to_string());

        let cookie_domain = std::env::var("SESSION_COOKIE_DOMAIN")
            .unwrap_or_else(|_| defaults.get("SESSION_COOKIE_DOMAIN").unwrap_or(&"skygenesisenterprise.com".to_string()).clone());

        let cookie_secure = std::env::var("SESSION_COOKIE_SECURE")
            .unwrap_or_else(|_| "true".to_string()) == "true";

        Ok(SessionService {
            redis_client,
            session_ttl,
            cookie_name,
            cookie_domain,
            cookie_secure,
        })
    }

    pub async fn create_session(&self, user: &User, user_agent: Option<String>, ip_address: Option<String>) -> Result<Session, Box<dyn std::error::Error>> {
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.session_ttl as i64);

        let session = Session {
            session_id: session_id.clone(),
            user_id: user.id.clone(),
            email: user.email.clone(),
            roles: user.roles.clone(),
            created_at: now,
            expires_at,
            last_activity: now,
            user_agent,
            ip_address,
        };

        // Store session in Redis
        let mut conn = self.redis_client.get_async_connection().await?;
        let session_key = format!("session:{}", session_id);
        let session_data = serde_json::to_string(&session)?;

        // Set session data with TTL
        conn.set_ex(&session_key, session_data, self.session_ttl).await?;

        // Also store user -> sessions mapping for logout
        let user_sessions_key = format!("user_sessions:{}", user.id);
        conn.sadd(&user_sessions_key, &session_id).await?;
        conn.expire(&user_sessions_key, self.session_ttl).await?;

        Ok(session)
    }

    pub async fn validate_session(&self, session_id: &str) -> Result<Option<Session>, Box<dyn std::error::Error>> {
        let mut conn = self.redis_client.get_async_connection().await?;
        let session_key = format!("session:{}", session_id);

        let session_data: Option<String> = conn.get(&session_key).await?;

        match session_data {
            Some(data) => {
                let mut session: Session = serde_json::from_str(&data)?;

                // Check if session is expired
                if Utc::now() > session.expires_at {
                    // Clean up expired session
                    self.destroy_session(session_id).await?;
                    return Ok(None);
                }

                // Update last activity
                session.last_activity = Utc::now();
                let updated_data = serde_json::to_string(&session)?;
                conn.set_ex(&session_key, updated_data, self.session_ttl).await?;

                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    pub async fn extend_session(&self, session_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.redis_client.get_async_connection().await?;
        let session_key = format!("session:{}", session_id);

        let session_data: Option<String> = conn.get(&session_key).await?;

        if let Some(data) = session_data {
            let mut session: Session = serde_json::from_str(&data)?;
            session.expires_at = Utc::now() + Duration::seconds(self.session_ttl as i64);
            session.last_activity = Utc::now();

            let updated_data = serde_json::to_string(&session)?;
            conn.set_ex(&session_key, updated_data, self.session_ttl).await?;
        }

        Ok(())
    }

    pub async fn destroy_session(&self, session_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.redis_client.get_async_connection().await?;
        let session_key = format!("session:{}", session_id);

        // Get session data to find user_id for cleanup
        let session_data: Option<String> = conn.get(&session_key).await?;

        if let Some(data) = session_data {
            let session: Session = serde_json::from_str(&data)?;
            let user_sessions_key = format!("user_sessions:{}", session.user_id);

            // Remove from user's sessions
            conn.srem(&user_sessions_key, session_id).await?;
        }

        // Delete session
        conn.del(&session_key).await?;

        Ok(())
    }

    pub async fn destroy_all_user_sessions(&self, user_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.redis_client.get_async_connection().await?;
        let user_sessions_key = format!("user_sessions:{}", user_id);

        let session_ids: Vec<String> = conn.smembers(&user_sessions_key).await?;

        // Delete all user sessions
        for session_id in session_ids {
            let session_key = format!("session:{}", session_id);
            conn.del(&session_key).await?;
        }

        // Delete user sessions set
        conn.del(&user_sessions_key).await?;

        Ok(())
    }

    pub async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<Session>, Box<dyn std::error::Error>> {
        let mut conn = self.redis_client.get_async_connection().await?;
        let user_sessions_key = format!("user_sessions:{}", user_id);

        let session_ids: Vec<String> = conn.smembers(&user_sessions_key).await?;
        let mut sessions = Vec::new();

        for session_id in session_ids {
            if let Some(session) = self.validate_session(&session_id).await? {
                sessions.push(session);
            }
        }

        Ok(sessions)
    }

    pub fn get_cookie_name(&self) -> &str {
        &self.cookie_name
    }

    pub fn get_cookie_domain(&self) -> &str {
        &self.cookie_domain
    }

    pub fn is_cookie_secure(&self) -> bool {
        self.cookie_secure
    }

    pub fn generate_session_token(&self, session: &Session) -> Result<String, Box<dyn std::error::Error>> {
        let token_data = SessionToken {
            session_id: session.session_id.clone(),
            user_id: session.user_id.clone(),
            expires_at: session.expires_at,
        };

        let token = serde_json::to_string(&token_data)?;
        // In production, you might want to encrypt this token
        Ok(token)
    }

    pub fn validate_session_token(&self, token: &str) -> Result<SessionToken, Box<dyn std::error::Error>> {
        let token_data: SessionToken = serde_json::from_str(token)?;
        Ok(token_data)
    }
}

// Function to load default values from .env.example
fn load_defaults_from_env_example() -> std::collections::HashMap<String, String> {
    let mut defaults = std::collections::HashMap::new();

    // Read .env.example file
    if let Ok(content) = std::fs::read_to_string(".env.example") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                defaults.insert(key.to_string(), value.to_string());
            }
        }
    }

    defaults
}