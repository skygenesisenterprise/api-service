// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: API Key Management Controller
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide API key management commands for CLI tool.
//  NOTICE: This module implements API key CRUD operations
//  including certificate-coupled keys for enhanced security.
//  COMMANDS: create, list, revoke, info, public-key
//  SECURITY: All operations require authentication and proper permissions
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use clap::{Args, Subcommand};
use crate::core::api_client::SshApiClient;
use crate::controllers::auth_controller::TokenStore;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Args)]
pub struct KeyArgs {
    #[command(subcommand)]
    pub command: KeyCommands,
}

#[derive(Subcommand)]
pub enum KeyCommands {
    /// Create a new API key
    Create {
        /// Key type (client, server, database)
        #[arg(short, long)]
        key_type: String,
        /// Tenant identifier
        #[arg(short, long)]
        tenant: String,
        /// Time to live in seconds (default: 3600)
        #[arg(long)]
        ttl: Option<u64>,
        /// Create certificate-coupled key
        #[arg(long)]
        with_certificate: bool,
        /// Certificate type (rsa or ecdsa, default: rsa)
        #[arg(long)]
        cert_type: Option<String>,
    },
    /// List API keys
    List {
        /// Tenant identifier (optional filter)
        #[arg(short, long)]
        tenant: Option<String>,
    },
    /// Get API key information
    Info {
        /// API key ID
        key_id: String,
    },
    /// Get public key for certificate-coupled key
    PublicKey {
        /// API key ID
        key_id: String,
    },
    /// Revoke an API key
    Revoke {
        /// API key ID
        key_id: String,
        /// Confirm revocation
        #[arg(long)]
        confirm: bool,
    },
    /// Revoke certificate for certificate-coupled key
    RevokeCert {
        /// API key ID
        key_id: String,
        /// Confirm certificate revocation
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ApiKey {
    pub id: String,
    pub key_type: String,
    pub tenant: String,
    pub ttl: u64,
    pub created_at: String,
    pub permissions: Vec<String>,
    pub vault_path: String,
    pub certificate: Option<CertificateInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CertificateInfo {
    pub public_key: String,
    pub private_key_path: String,
    pub certificate_type: String,
    pub fingerprint: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PublicKeyResponse {
    pub public_key: String,
    pub certificate_type: String,
    pub fingerprint: String,
}

pub async fn handle_keys(args: KeyArgs, state: &crate::core::AppState) -> Result<()> {
    let client = &state.client;
    let token_store = TokenStore::load()?
        .ok_or_else(|| anyhow!("Not authenticated. Please login first."))?;

    if token_store.is_expired() {
        return Err(anyhow!("Authentication token expired. Please login again."));
    }

    match args.command {
        KeyCommands::Create { key_type, tenant, ttl, with_certificate, cert_type } => {
            let ttl = ttl.unwrap_or(3600);
            let cert_type = cert_type.unwrap_or_else(|| "rsa".to_string());

            let mut query_params = vec![
                format!("type={}", key_type),
                format!("tenant={}", tenant),
                format!("ttl={}", ttl),
            ];

            if with_certificate {
                query_params.push(format!("cert_type={}", cert_type));
            }

            let path = format!("/api/keys{}?{}",
                if with_certificate { "/with-certificate" } else { "" },
                query_params.join("&")
            );

            let response = client.post_with_auth(&path, "{}", &token_store.access_token).await?;
            let api_key: ApiKey = serde_json::from_str(&response)?;

            println!("API Key created successfully:");
            println!("ID: {}", api_key.id);
            println!("Type: {}", api_key.key_type);
            println!("Tenant: {}", api_key.tenant);
            println!("TTL: {} seconds", api_key.ttl);
            println!("Permissions: {}", api_key.permissions.join(", "));
            println!("Vault Path: {}", api_key.vault_path);

            if let Some(cert) = &api_key.certificate {
                println!("\nCertificate Information:");
                println!("Type: {}", cert.certificate_type);
                println!("Fingerprint: {}", cert.fingerprint);
                println!("Private Key Path: {}", cert.private_key_path);
                println!("\nPublic Key:");
                println!("{}", cert.public_key);
            }
        }

        KeyCommands::List { tenant } => {
            let path = match tenant {
                Some(t) => format!("/api/keys?tenant={}", t),
                None => "/api/keys".to_string(),
            };

            let response = client.get_with_auth(&path, &token_store.access_token).await?;
            let keys: Vec<ApiKey> = serde_json::from_str(&response)?;

            println!("{:<36} {:<10} {:<15} {:<8} {:<15}", "ID", "Type", "Tenant", "TTL", "Created");
            println!("{}", "-".repeat(90));

            for key in keys {
                println!("{:<36} {:<10} {:<15} {:<8} {:<15}",
                    key.id,
                    key.key_type,
                    key.tenant,
                    key.ttl,
                    key.created_at.split('T').next().unwrap_or(&key.created_at)
                );
            }
        }

        KeyCommands::Info { key_id } => {
            let path = format!("/api/keys/{}", key_id);
            let response = client.get_with_auth(&path, &token_store.access_token).await?;
            let key: ApiKey = serde_json::from_str(&response)?;

            println!("API Key Information:");
            println!("ID: {}", key.id);
            println!("Type: {}", key.key_type);
            println!("Tenant: {}", key.tenant);
            println!("TTL: {} seconds", key.ttl);
            println!("Created: {}", key.created_at);
            println!("Permissions: {}", key.permissions.join(", "));
            println!("Vault Path: {}", key.vault_path);

            if let Some(cert) = &key.certificate {
                println!("\nCertificate Information:");
                println!("Type: {}", cert.certificate_type);
                println!("Fingerprint: {}", cert.fingerprint);
                println!("Private Key Path: {}", cert.private_key_path);
            }
        }

        KeyCommands::PublicKey { key_id } => {
            let path = format!("/api/keys/{}/public-key", key_id);
            let response = client.get_with_auth(&path, &token_store.access_token).await?;
            let pub_key: PublicKeyResponse = serde_json::from_str(&response)?;

            println!("Public Key for API Key {}:", key_id);
            println!("Type: {}", pub_key.certificate_type);
            println!("Fingerprint: {}", pub_key.fingerprint);
            println!("\nPublic Key:");
            println!("{}", pub_key.public_key);
        }

        KeyCommands::Revoke { key_id, confirm } => {
            if !confirm {
                println!("This will permanently revoke API key {}. Use --confirm to proceed.", key_id);
                return Ok(());
            }

            let path = format!("/api/keys/{}", key_id);
            client.delete_with_auth(&path, &token_store.access_token).await?;

            println!("API key {} revoked successfully", key_id);
        }

        KeyCommands::RevokeCert { key_id, confirm } => {
            if !confirm {
                println!("This will revoke the certificate for API key {}. Use --confirm to proceed.", key_id);
                return Ok(());
            }

            let path = format!("/api/keys/{}/certificate", key_id);
            client.delete_with_auth(&path, &token_store.access_token).await?;

            println!("Certificate for API key {} revoked successfully", key_id);
        }
    }

    Ok(())
}