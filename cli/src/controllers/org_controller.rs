// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Organization Management Controller
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide organization/tenant management commands for CLI tool.
//  NOTICE: This module implements organization CRUD operations
//  using the Enterprise API with proper authentication.
//  COMMANDS: list, create, update, delete, info, members
//  SECURITY: All operations require admin privileges
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use clap::{Args, Subcommand};
use crate::controllers::auth_controller::TokenStore;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Args)]
pub struct OrgArgs {
    #[command(subcommand)]
    pub command: OrgCommands,
}

#[derive(Subcommand)]
pub enum OrgCommands {
    /// List all organizations
    List,
    /// Create a new organization
    Create {
        /// Organization name
        name: String,
        /// Organization description
        #[arg(long)]
        description: Option<String>,
        /// Organization domain
        #[arg(long)]
        domain: Option<String>,
        /// Maximum number of users
        #[arg(long)]
        max_users: Option<u32>,
    },
    /// Get organization information
    Info {
        /// Organization ID
        org_id: String,
    },
    /// Update organization information
    Update {
        /// Organization ID
        org_id: String,
        /// New name
        #[arg(long)]
        name: Option<String>,
        /// New description
        #[arg(long)]
        description: Option<String>,
        /// New domain
        #[arg(long)]
        domain: Option<String>,
        /// New max users
        #[arg(long)]
        max_users: Option<u32>,
        /// Enable/disable organization
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Delete an organization
    Delete {
        /// Organization ID
        org_id: String,
        /// Confirm deletion
        #[arg(long)]
        confirm: bool,
    },
    /// List organization members
    Members {
        /// Organization ID
        org_id: String,
    },
    /// Add member to organization
    AddMember {
        /// Organization ID
        org_id: String,
        /// User ID to add
        user_id: String,
        /// Member role in organization
        #[arg(long, default_value = "member")]
        role: String,
    },
    /// Remove member from organization
    RemoveMember {
        /// Organization ID
        org_id: String,
        /// User ID to remove
        user_id: String,
        /// Confirm removal
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub domain: Option<String>,
    pub max_users: Option<u32>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub member_count: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OrganizationMember {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub joined_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateOrgRequest {
    pub name: String,
    pub description: Option<String>,
    pub domain: Option<String>,
    pub max_users: Option<u32>,
}

pub async fn handle_org(args: OrgArgs, state: &crate::core::AppState) -> Result<()> {
    let client = &state.client;
    let token_store = TokenStore::load()?
        .ok_or_else(|| anyhow!("Not authenticated. Please login first."))?;

    if token_store.is_expired() {
        return Err(anyhow!("Authentication token expired. Please login again."));
    }

    match args.command {
        OrgCommands::List => {
            let response = client.get_with_auth("/api/v1/organizations", &token_store.access_token).await?;
            let orgs: Vec<Organization> = serde_json::from_str(&response)?;

            println!("{:<36} {:<30} {:<20} {:<10} {:<8}", "ID", "Name", "Domain", "Members", "Enabled");
            println!("{}", "-".repeat(110));

            for org in orgs {
                println!("{:<36} {:<30} {:<20} {:<10} {:<8}",
                    org.id,
                    org.name,
                    org.domain.as_deref().unwrap_or("-"),
                    org.member_count,
                    org.enabled
                );
            }
        }

        OrgCommands::Create { name, description, domain, max_users } => {
            let create_req = CreateOrgRequest {
                name,
                description,
                domain,
                max_users,
            };

            let body = serde_json::to_string(&create_req)?;
            let response = client.post_with_auth("/api/v1/organizations", &body, &token_store.access_token).await?;
            let org: Organization = serde_json::from_str(&response)?;

            println!("Organization created successfully:");
            println!("ID: {}", org.id);
            println!("Name: {}", org.name);
            if let Some(desc) = &org.description {
                println!("Description: {}", desc);
            }
            if let Some(domain) = &org.domain {
                println!("Domain: {}", domain);
            }
            if let Some(max_users) = org.max_users {
                println!("Max Users: {}", max_users);
            }
            println!("Enabled: {}", org.enabled);
        }

        OrgCommands::Info { org_id } => {
            let path = format!("/api/v1/organizations/{}", org_id);
            let response = client.get_with_auth(&path, &token_store.access_token).await?;
            let org: Organization = serde_json::from_str(&response)?;

            println!("Organization Information:");
            println!("ID: {}", org.id);
            println!("Name: {}", org.name);
            if let Some(desc) = &org.description {
                println!("Description: {}", desc);
            }
            if let Some(domain) = &org.domain {
                println!("Domain: {}", domain);
            }
            if let Some(max_users) = org.max_users {
                println!("Max Users: {}", max_users);
            }
            println!("Members: {}", org.member_count);
            println!("Enabled: {}", org.enabled);
            println!("Created: {}", org.created_at);
            println!("Updated: {}", org.updated_at);
        }

        OrgCommands::Update { org_id, name, description, domain, max_users, enabled } => {
            let mut update_data = serde_json::Map::new();

            if let Some(name) = name {
                update_data.insert("name".to_string(), serde_json::Value::String(name));
            }
            if let Some(description) = description {
                update_data.insert("description".to_string(), serde_json::Value::String(description));
            }
            if let Some(domain) = domain {
                update_data.insert("domain".to_string(), serde_json::Value::String(domain));
            }
            if let Some(max_users) = max_users {
                update_data.insert("max_users".to_string(), serde_json::to_value(max_users)?);
            }
            if let Some(enabled) = enabled {
                update_data.insert("enabled".to_string(), serde_json::Value::Bool(enabled));
            }

            if update_data.is_empty() {
                return Err(anyhow!("No fields to update specified"));
            }

            let body = serde_json::to_string(&update_data)?;
            let path = format!("/api/v1/organizations/{}", org_id);
            let response = client.put_with_auth(&path, &body, &token_store.access_token).await?;
            let org: Organization = serde_json::from_str(&response)?;

            println!("Organization updated successfully:");
            println!("ID: {}", org.id);
            println!("Name: {}", org.name);
            println!("Enabled: {}", org.enabled);
        }

        OrgCommands::Delete { org_id, confirm } => {
            if !confirm {
                println!("This will permanently delete organization {}. Use --confirm to proceed.", org_id);
                return Ok(());
            }

            let path = format!("/api/v1/organizations/{}", org_id);
            client.delete_with_auth(&path, &token_store.access_token).await?;

            println!("Organization {} deleted successfully", org_id);
        }

        OrgCommands::Members { org_id } => {
            let path = format!("/api/v1/organizations/{}/members", org_id);
            let response = client.get_with_auth(&path, &token_store.access_token).await?;
            let members: Vec<OrganizationMember> = serde_json::from_str(&response)?;

            println!("Members of organization {}:", org_id);
            println!("{:<36} {:<30} {:<15} {:<20}", "User ID", "Email", "Role", "Joined");
            println!("{}", "-".repeat(105));

            for member in members {
                println!("{:<36} {:<30} {:<15} {:<20}",
                    member.user_id,
                    member.email,
                    member.role,
                    member.joined_at.split('T').next().unwrap_or(&member.joined_at)
                );
            }
        }

        OrgCommands::AddMember { org_id, user_id, role } => {
            let body = serde_json::json!({
                "user_id": user_id,
                "role": role
            });

            let path = format!("/api/v1/organizations/{}/members", org_id);
            client.post_with_auth(&path, &body.to_string(), &token_store.access_token).await?;

            println!("User {} added to organization {} with role {}", user_id, org_id, role);
        }

        OrgCommands::RemoveMember { org_id, user_id, confirm } => {
            if !confirm {
                println!("This will remove user {} from organization {}. Use --confirm to proceed.", user_id, org_id);
                return Ok(());
            }

            let path = format!("/api/v1/organizations/{}/members/{}", org_id, user_id);
            client.delete_with_auth(&path, &token_store.access_token).await?;

            println!("User {} removed from organization {}", user_id, org_id);
        }
    }

    Ok(())
}