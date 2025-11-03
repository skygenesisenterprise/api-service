// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: User Management Controller
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide user management commands for CLI tool.
//  NOTICE: This module implements user CRUD operations
//  using the Enterprise API with proper authentication.
//  COMMANDS: list, create, update, delete, info
//  SECURITY: All operations require admin privileges
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use clap::{Args, Subcommand};
use crate::controllers::auth_controller::TokenStore;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Args)]
pub struct UserArgs {
    #[command(subcommand)]
    pub command: UserCommands,
}

#[derive(Subcommand)]
pub enum UserCommands {
    /// List all users
    List,
    /// Create a new user
    Create {
        /// Email address
        email: String,
        /// First name
        #[arg(long)]
        first_name: Option<String>,
        /// Last name
        #[arg(long)]
        last_name: Option<String>,
        /// User roles (comma-separated)
        #[arg(long, value_delimiter = ',')]
        roles: Vec<String>,
        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Get user information
    Info {
        /// User ID or email
        user_id: String,
    },
    /// Update user information
    Update {
        /// User ID
        user_id: String,
        /// New email address
        #[arg(long)]
        email: Option<String>,
        /// New first name
        #[arg(long)]
        first_name: Option<String>,
        /// New last name
        #[arg(long)]
        last_name: Option<String>,
        /// New roles (comma-separated)
        #[arg(long, value_delimiter = ',')]
        roles: Option<Vec<String>>,
        /// Enable/disable user
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Delete a user
    Delete {
        /// User ID
        user_id: String,
        /// Confirm deletion
        #[arg(long)]
        confirm: bool,
    },
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
pub struct CreateUserRequest {
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub roles: Vec<String>,
    pub password: String,
}

pub async fn handle_user(args: UserArgs, state: &crate::core::AppState) -> Result<()> {
    let client = &state.client;
    let token_store = TokenStore::load()?
        .ok_or_else(|| anyhow!("Not authenticated. Please login first."))?;

    if token_store.is_expired() {
        return Err(anyhow!("Authentication token expired. Please login again."));
    }

    match args.command {
        UserCommands::List => {
            let response = client.get_with_auth("/api/v1/users", &token_store.access_token).await?;
            let users: Vec<User> = serde_json::from_str(&response)?;

            println!("{:<36} {:<30} {:<20} {:<10}", "ID", "Email", "Name", "Enabled");
            println!("{}", "-".repeat(100));

            for user in users {
                let first_name = user.first_name.as_deref().unwrap_or("");
                let last_name = user.last_name.as_deref().unwrap_or("");
                let name = format!("{} {}", first_name, last_name).trim().to_string();
                println!("{:<36} {:<30} {:<20} {:<10}",
                    user.id,
                    user.email,
                    name,
                    user.enabled
                );
            }
        }

        UserCommands::Create { email, first_name, last_name, roles, password } => {
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

            if roles.is_empty() {
                return Err(anyhow!("At least one role must be specified"));
            }

            let create_req = CreateUserRequest {
                email,
                first_name,
                last_name,
                roles,
                password,
            };

            let body = serde_json::to_string(&create_req)?;
            let response = client.post_with_auth("/api/v1/users", &body, &token_store.access_token).await?;
            let user: User = serde_json::from_str(&response)?;

            println!("User created successfully:");
            println!("ID: {}", user.id);
            println!("Email: {}", user.email);
            println!("Roles: {}", user.roles.join(", "));
            println!("Enabled: {}", user.enabled);
        }

        UserCommands::Info { user_id } => {
            let path = format!("/api/v1/users/{}", user_id);
            let response = client.get_with_auth(&path, &token_store.access_token).await?;
            let user: User = serde_json::from_str(&response)?;

            println!("User Information:");
            println!("ID: {}", user.id);
            println!("Email: {}", user.email);
            if let Some(first_name) = &user.first_name {
                println!("First Name: {}", first_name);
            }
            if let Some(last_name) = &user.last_name {
                println!("Last Name: {}", last_name);
            }
            println!("Roles: {}", user.roles.join(", "));
            println!("Enabled: {}", user.enabled);
            println!("Created: {}", user.created_at);
        }

        UserCommands::Update { user_id, email, first_name, last_name, roles, enabled } => {
            let mut update_data = serde_json::Map::new();

            if let Some(email) = email {
                update_data.insert("email".to_string(), serde_json::Value::String(email));
            }
            if let Some(first_name) = first_name {
                update_data.insert("first_name".to_string(), serde_json::Value::String(first_name));
            }
            if let Some(last_name) = last_name {
                update_data.insert("last_name".to_string(), serde_json::Value::String(last_name));
            }
            if let Some(roles) = roles {
                update_data.insert("roles".to_string(), serde_json::to_value(roles)?);
            }
            if let Some(enabled) = enabled {
                update_data.insert("enabled".to_string(), serde_json::Value::Bool(enabled));
            }

            if update_data.is_empty() {
                return Err(anyhow!("No fields to update specified"));
            }

            let body = serde_json::to_string(&update_data)?;
            let path = format!("/api/v1/users/{}", user_id);
            let response = client.put_with_auth(&path, &body, &token_store.access_token).await?;
            let user: User = serde_json::from_str(&response)?;

            println!("User updated successfully:");
            println!("ID: {}", user.id);
            println!("Email: {}", user.email);
            println!("Roles: {}", user.roles.join(", "));
            println!("Enabled: {}", user.enabled);
        }

        UserCommands::Delete { user_id, confirm } => {
            if !confirm {
                println!("This will permanently delete user {}. Use --confirm to proceed.", user_id);
                return Ok(());
            }

            let path = format!("/api/v1/users/{}", user_id);
            client.delete_with_auth(&path, &token_store.access_token).await?;

            println!("User {} deleted successfully", user_id);
        }
    }

    Ok(())
}