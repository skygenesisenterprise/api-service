// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Authentication Controller
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide authentication commands for CLI tool.
//  NOTICE: This module implements login/logout and token management
//  using JWT authentication with the Enterprise API.
//  COMMANDS: login, logout, status, refresh
//  SECURITY: Secure token storage and automatic refresh
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use clap::{Args, Subcommand};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use dirs;

#[derive(Args)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommands,
}

#[derive(Subcommand)]
pub enum AuthCommands {
    /// Login to the Enterprise API
    Login {
        /// Email address
        email: String,
        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Logout and clear stored tokens
    Logout,
    /// Show current authentication status
    Status,
    /// Refresh authentication token
    Refresh,
    /// Get current user information
    Me,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub user: User,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub roles: Vec<String>,
    pub created_at: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenStore {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,
    pub user: User,
}

impl TokenStore {
    fn get_store_path() -> Result<PathBuf> {
        let mut path = dirs::home_dir()
            .ok_or_else(|| anyhow!("Could not find home directory"))?;
        path.push(".sge");
        fs::create_dir_all(&path)?;
        path.push("auth.json");
        Ok(path)
    }

    pub fn load() -> Result<Option<Self>> {
        let path = Self::get_store_path()?;
        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(path)?;
        let store: TokenStore = serde_json::from_str(&content)?;
        Ok(Some(store))
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::get_store_path()?;
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn delete() -> Result<()> {
        let path = Self::get_store_path()?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.expires_at
    }
}

pub async fn handle_auth(args: AuthArgs, state: &crate::core::AppState) -> Result<()> {
    let client = &state.client;
    match args.command {
        AuthCommands::Login { email, password } => {
            let _password = match password {
                Some(p) => p,
                None => {
                    use std::io::{self, Write};
                    print!("Password: ");
                    io::stdout().flush()?;
                    let mut password = String::new();
                    io::stdin().read_line(&mut password)?;
                    password.trim().to_string()
                }
            };

            println!("Authenticating with {}...", email);

            // Step 1: Initiate OAuth2 login to get authorization URL
            let login_init_req = serde_json::json!({
                "redirect_uri": "http://localhost:8080/cli/callback",
                "state": format!("cli-{}", chrono::Utc::now().timestamp()),
                "client_id": "cli-client"
            });
            let body = serde_json::to_string(&login_init_req)?;

            let response = client.post("/api/v1/auth/login", &body).await?;
            let login_init_resp: serde_json::Value = serde_json::from_str(&response)?;

            let auth_url = login_init_resp["authorization_url"]
                .as_str()
                .ok_or_else(|| anyhow!("No authorization URL received"))?;

            println!("Please visit this URL to authenticate:");
            println!("{}", auth_url);
            println!("\nAfter authentication, paste the authorization code below:");

            use std::io::{self, Write};
            print!("Authorization code: ");
            io::stdout().flush()?;
            let mut code = String::new();
            io::stdin().read_line(&mut code)?;
            let code = code.trim();

            // Step 2: Exchange code for tokens
            let token_req = serde_json::json!({
                "code": code,
                "redirect_uri": "http://localhost:8080/cli/callback"
            });
            let body = serde_json::to_string(&token_req)?;

            let response = client.post("/api/v1/auth/callback", &body).await?;
            let token_resp: serde_json::Value = serde_json::from_str(&response)?;

            let access_token = token_resp["access_token"]
                .as_str()
                .ok_or_else(|| anyhow!("No access token received"))?;
            let refresh_token = token_resp["refresh_token"]
                .as_str()
                .unwrap_or("");
            let expires_in = token_resp["expires_in"]
                .as_u64()
                .unwrap_or(3600);

            // Step 3: Get user info
            let user_response = client.get_with_auth("/api/v1/auth/userinfo", access_token).await?;
            let user_info: serde_json::Value = serde_json::from_str(&user_response)?;

            let user = User {
                id: user_info["sub"].as_str().unwrap_or("").to_string(),
                email: user_info["email"].as_str().unwrap_or(&email).to_string(),
                first_name: user_info["given_name"].as_str().map(|s| s.to_string()),
                last_name: user_info["family_name"].as_str().map(|s| s.to_string()),
                roles: user_info["roles"].as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect(),
                created_at: chrono::Utc::now().to_rfc3339(),
                enabled: true,
            };

            let expires_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() + expires_in;

            let token_store = TokenStore {
                access_token: access_token.to_string(),
                refresh_token: refresh_token.to_string(),
                expires_at,
                user,
            };

            token_store.save()?;
            println!("Successfully logged in as {}", token_store.user.email);
        }

        AuthCommands::Logout => {
            TokenStore::delete()?;
            println!("Successfully logged out");
        }

        AuthCommands::Status => {
            match TokenStore::load()? {
                Some(store) => {
                    if store.is_expired() {
                        println!("Token expired");
                    } else {
                        println!("Logged in as: {}", store.user.email);
                        println!("Roles: {}", store.user.roles.join(", "));
                        println!("Token expires in: {} seconds",
                            store.expires_at.saturating_sub(
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)?
                                    .as_secs()
                            )
                        );
                    }
                }
                None => {
                    println!("Not logged in");
                }
            }
        }

        AuthCommands::Refresh => {
            let mut store = TokenStore::load()?
                .ok_or_else(|| anyhow!("Not logged in"))?;

            if !store.is_expired() {
                println!("Token is still valid");
                return Ok(());
            }

            // Refresh token using OAuth2 endpoint
            let refresh_req = serde_json::json!({
                "refresh_token": store.refresh_token
            });
            let body = serde_json::to_string(&refresh_req)?;

            let response = client.post("/api/v1/auth/refresh", &body).await?;
            let refresh_resp: serde_json::Value = serde_json::from_str(&response)?;

            let new_access_token = refresh_resp["access_token"]
                .as_str()
                .ok_or_else(|| anyhow!("No new access token received"))?;
            let new_refresh_token = refresh_resp["refresh_token"]
                .as_str()
                .unwrap_or(&store.refresh_token);
            let expires_in = refresh_resp["expires_in"]
                .as_u64()
                .unwrap_or(3600);

            store.access_token = new_access_token.to_string();
            store.refresh_token = new_refresh_token.to_string();
            store.expires_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() + expires_in;

            store.save()?;
            println!("Token refreshed successfully");
        }

        AuthCommands::Me => {
            let store = TokenStore::load()?
                .ok_or_else(|| anyhow!("Not logged in"))?;

            if store.is_expired() {
                return Err(anyhow!("Token expired, please login again"));
            }

            let response = client.get_with_auth("/api/v1/auth/userinfo", &store.access_token).await?;
            let user_info: serde_json::Value = serde_json::from_str(&response)?;

            println!("User ID: {}", user_info["sub"].as_str().unwrap_or("N/A"));
            println!("Email: {}", user_info["email"].as_str().unwrap_or("N/A"));
            println!("Name: {} {}", user_info["given_name"].as_str().unwrap_or(""), user_info["family_name"].as_str().unwrap_or(""));
            if let Some(roles) = user_info["roles"].as_array() {
                println!("Roles: {}", roles.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", "));
            }
            println!("Enabled: {}", user_info["email_verified"].as_bool().unwrap_or(false));
        }
    }

    Ok(())
}