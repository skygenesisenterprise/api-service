use crate::core::keycloak::KeycloakClient;
use crate::core::vault::VaultClient;
use crate::models::user::User;
use crate::utils::tokens;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub user: User,
}

pub struct AuthService {
    keycloak: Arc<KeycloakClient>,
    vault: Arc<VaultClient>,
}

impl AuthService {
    pub fn new(keycloak: Arc<KeycloakClient>, vault: Arc<VaultClient>) -> Self {
        AuthService { keycloak, vault }
    }

    pub async fn login(&self, req: LoginRequest, app_token: &str) -> Result<LoginResponse, Box<dyn std::error::Error>> {
        // Validate app_token via Vault
        let valid = self.vault.validate_access("app", app_token).await?;
        if !valid {
            return Err("Invalid app token".into());
        }

        let token_resp = self.keycloak.login(&req.email, &req.password).await?;
        let user_info = self.keycloak.get_user_info(&token_resp.access_token).await?;

        let user = User {
            id: user_info["sub"].as_str().unwrap_or("").to_string(),
            email: req.email,
            first_name: user_info.get("given_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
            last_name: user_info.get("family_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
            roles: vec!["employee".to_string()], // From user_info
            created_at: chrono::Utc::now(),
            enabled: true,
        };

        let internal_token = tokens::generate_jwt(&user)?;

        Ok(LoginResponse {
            access_token: internal_token,
            refresh_token: token_resp.refresh_token,
            expires_in: token_resp.expires_in,
            user,
        })
    }

    pub async fn register(&self, user: User, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.keycloak.register(&user, password).await
    }

    pub async fn recover_password(&self, email: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.keycloak.recover_password(email).await
    }

    pub async fn get_me(&self, token: &str) -> Result<User, Box<dyn std::error::Error>> {
        let claims = tokens::validate_jwt(token)?;
        // Fetch user from Keycloak or local
        Ok(User {
            id: claims.sub,
            email: claims.email,
            first_name: None,
            last_name: None,
            roles: claims.roles,
            created_at: chrono::Utc::now(),
            enabled: true,
        })
    }
}