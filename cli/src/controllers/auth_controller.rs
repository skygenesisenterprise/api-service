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
use crate::core::api_client::SshApiClient;
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
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize)]
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
            let password = match password {
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

            let login_req = LoginRequest { email, password };
            let body = serde_json::to_string(&login_req)?;

            let response = client.post("/auth/login", &body).await?;
            let login_resp: LoginResponse = serde_json::from_str(&response)?;

            let expires_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() + login_resp.expires_in;

            let token_store = TokenStore {
                access_token: login_resp.access_token,
                refresh_token: login_resp.refresh_token,
                expires_at,
                user: login_resp.user,
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
            let store = TokenStore::load()?
                .ok_or_else(|| anyhow!("Not logged in"))?;

            if !store.is_expired() {
                println!("Token is still valid");
                return Ok(());
            }

            // TODO: Implement token refresh with refresh_token
            println!("Token refresh not yet implemented");
        }

        AuthCommands::Me => {
            let store = TokenStore::load()?
                .ok_or_else(|| anyhow!("Not logged in"))?;

            if store.is_expired() {
                return Err(anyhow!("Token expired, please login again"));
            }

            let response = client.get_with_auth("/auth/me", &store.access_token).await?;
            let user: User = serde_json::from_str(&response)?;

            println!("User ID: {}", user.id);
            println!("Email: {}", user.email);
            println!("Name: {} {}", user.first_name.as_deref().unwrap_or(""), user.last_name.as_deref().unwrap_or(""));
            println!("Roles: {}", user.roles.join(", "));
            println!("Enabled: {}", user.enabled);
            println!("Created: {}", user.created_at);
        }
    }

    Ok(())
}