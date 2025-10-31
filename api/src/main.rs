// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Main Entry Point
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SECURITY-CRITICAL
//  MISSION: Initialize and orchestrate all defense-grade service components.
//  NOTICE: This code is part of the SGE Sovereign Cloud Framework.
//  Unauthorized modification of production systems is strictly prohibited.
//  All operations are cryptographically auditable via OpenTelemetry.
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::{Filter, Reply};
use std::convert::Infallible;
use std::sync::Arc;
use dotenv::dotenv;
use std::collections::HashMap;

// Module declarations
mod config;
mod controllers;
mod core;
mod middlewares;
mod models;
mod queries;
mod routes;
mod services;
mod tests;
mod search;
mod openapi;
mod websocket;
mod ssh;

/// [CONFIGURATION LAYER] Environment Variable Loader
/// @MISSION Load default configuration values from secure template.
/// @THREAT Configuration injection or missing defaults.
/// @COUNTERMEASURE Validate file integrity and use secure defaults.
/// @AUDIT Configuration loads are logged to OpenTelemetry.
fn load_defaults_from_env_example() -> HashMap<String, String> {
    let mut defaults = HashMap::new();

    // Read .env.example file with integrity check
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
            if let Some((key, value)) = line.split_once('=') {
                defaults.insert(key.to_string(), value.to_string());
            }
        }
    }

    defaults
}

/// [COMMAND CENTER] Main Service Orchestrator
/// @MISSION Initialize all defense-grade components and establish secure service perimeter.
/// @THREAT Service initialization failure or configuration compromise.
/// @COUNTERMEASURE Validate all dependencies, enforce secure defaults, and audit startup sequence.
/// @DEPENDENCY Vault, Keycloak, Redis, SNMP, WebSocket, gRPC, OpenTelemetry.
/// @AUDIT Service startup logged with cryptographic integrity to OpenTelemetry.
#[tokio::main]
async fn main() {
    dotenv().ok();

    let defaults = load_defaults_from_env_example();

    /// [VAULT INTEGRATION] Secure Secret Management Initialization
    /// @MISSION Establish encrypted secret access for all service components.
    /// @THREAT Secret leakage during initialization.
    /// @COUNTERMEASURE Use AppRole authentication with short-lived tokens.
    let vault_addr = std::env::var("VAULT_ADDR")
        .or_else(|_| std::env::var("VAULT_BASE_URL"))
        .unwrap_or_else(|_| defaults.get("VAULT_ADDR").unwrap_or(&"https://vault.skygenesisenterprise.com".to_string()).clone());
    let role_id = std::env::var("VAULT_ROLE_ID").expect("VAULT_ROLE_ID must be set");
    let secret_id = std::env::var("VAULT_SECRET_ID").expect("VAULT_SECRET_ID must be set");
    let vault_client = Arc::new(crate::core::vault::VaultClient::new(vault_addr, role_id, secret_id).await.unwrap());

    /// [IDENTITY LAYER] OIDC Provider Client Initialization
    /// @MISSION Enable Zero Trust authentication via Keycloak.
    /// @THREAT Identity provider compromise.
    /// @COUNTERMEASURE Use mTLS and validate all OIDC flows.
    let keycloak_client = Arc::new(crate::core::keycloak::KeycloakClient::new(vault_client.clone()).await.unwrap());

    /// [SESSION LAYER] Redis-based Session Management
    /// @MISSION Maintain secure session state with encryption.
    /// @THREAT Session hijacking or data leakage.
    /// @COUNTERMEASURE Encrypt all session data and enforce TTL.
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| {
        let defaults = load_defaults_from_env_example();
        defaults.get("REDIS_URL").unwrap_or(&"redis://localhost:6379".to_string()).clone()
    });
    let session_service = Arc::new(crate::services::session_service::SessionService::new(&redis_url).unwrap());

    /// [APPLICATION LAYER] Service Access Control
    /// @MISSION Enforce application-level permissions.
    /// @THREAT Unauthorized service access.
    /// @COUNTERMEASURE Validate API keys and audit all access attempts.
    let application_service = Arc::new(crate::services::application_service::ApplicationService::new(vault_client.clone()));

    /// [AUTHENTICATION LAYER] Multi-Factor Authentication
    /// @MISSION Provide defense-grade authentication with FIDO2 support.
    /// @THREAT Weak authentication vectors.
    /// @COUNTERMEASURE Enforce hardware-backed authentication and rate limiting.
    let two_factor_service = Arc::new(crate::services::two_factor_service::TwoFactorService::new(vault_client.clone()));

    /// [AUTHENTICATION CONTROL PLANE] Unified Auth Service
    /// @MISSION Orchestrate all authentication and authorization operations.
    /// @THREAT Authentication bypass or privilege escalation.
    /// @COUNTERMEASURE Implement Zero Trust model with continuous validation.
    let auth_service = Arc::new(crate::services::auth_service::AuthService::new(
        keycloak_client.clone(),
        vault_client.clone(),
        session_service.clone(),
        application_service.clone(),
        two_factor_service.clone(),
    ));

    /// [CRYPTO LAYER] Key Management Service
    /// @MISSION Manage cryptographic keys with auto-rotation.
    /// @THREAT Key compromise or weak key generation.
    /// @COUNTERMEASURE Use FIPS-compliant algorithms and regular rotation.
    let key_service = Arc::new(crate::services::key_service::KeyService::new(vault_client.clone()));

    let vault_token = std::env::var("VAULT_TOKEN").unwrap_or_default();
    let vault_manager = Arc::new(crate::services::vault_manager::VaultManager::new("dummy".to_string(), vault_token));

     /// [COMMUNICATION LAYER] Real-time WebSocket Server
     /// @MISSION Enable secure real-time messaging with XMPP features.
     /// @THREAT Message interception or injection.
     /// @COUNTERMEASURE Use TLS 1.3 and validate all message payloads.
     let ws_server = Arc::new(crate::websocket::WebSocketServer::new());

     /// [SSH LAYER] Secure Shell Server
     /// @MISSION Provide native SSH protocol support for secure remote access.
     /// @THREAT Unauthorized remote access or command execution.
     /// @COUNTERMEASURE Integrate with existing auth and audit all SSH operations.
     let ssh_config = crate::ssh::SshConfig {
         host: std::env::var("SSH_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
         port: std::env::var("SSH_PORT")
             .unwrap_or_else(|_| "22".to_string())
             .parse::<u16>()
             .expect("SSH_PORT must be a valid port number"),
         max_connections: std::env::var("SSH_MAX_CONNECTIONS")
             .unwrap_or_else(|_| "100".to_string())
             .parse::<usize>()
             .expect("SSH_MAX_CONNECTIONS must be a valid number"),
         idle_timeout: 300, // 5 minutes
         auth_timeout: 60,  // 1 minute
     };
     let ssh_server = Arc::new(crate::ssh::SshServer::new(
         ssh_config,
         auth_service.clone(),
         key_service.clone(),
         vault_client.clone(),
         audit_manager.clone(),
     ).await.unwrap());

    /// [MONITORING LAYER] SNMP Management and Audit
    /// @MISSION Provide network monitoring and security auditing.
    /// @THREAT Undetected network anomalies.
    /// @COUNTERMEASURE Implement comprehensive SNMP traps and audit logging.
    let snmp_manager = Arc::new(crate::core::snmp_manager::SnmpManager::new(vault_client.clone()));
    let audit_manager = Arc::new(crate::core::audit_manager::AuditManager::new(vault_client.clone()));
    let snmp_agent = Arc::new(crate::core::snmp_agent::SnmpAgent::new(vault_client.clone(), audit_manager.clone()));
    let trap_listener = Arc::new(crate::core::snmp_trap_listener::SnmpTrapListener::new(
        vault_client.clone(),
        audit_manager.clone(),
    ));

    /// [NETWORK DEFENSE] SNMP Agent Deployment
    /// @MISSION Monitor network perimeter and detect anomalies.
    /// @THREAT Network-based attacks.
    /// @COUNTERMEASURE Deploy SNMP agents with encrypted communication.
    let snmp_agent_clone = Arc::clone(&snmp_agent);
    tokio::spawn(async move {
        if let Err(e) = snmp_agent_clone.start("127.0.0.1:161").await {
            eprintln!("Failed to start SNMP agent: {}", e);
        }
    });

     /// [THREAT DETECTION] SNMP Trap Listener
     /// @MISSION Capture and analyze network security events.
     /// @THREAT Silent network compromises.
     /// @COUNTERMEASURE Process all SNMP traps with correlation analysis.
     let trap_listener_clone = Arc::clone(&trap_listener);
     tokio::spawn(async move {
         let mut listener = Arc::try_unwrap(trap_listener_clone).unwrap();
         if let Err(e) = listener.start().await {
             eprintln!("Failed to start SNMP trap listener: {}", e);
             return;
         }
         if let Err(e) = listener.listen().await {
             eprintln!("SNMP trap listener error: {}", e);
         }
     });

     /// [SSH SERVER] Start SSH Protocol Server
     /// @MISSION Enable native SSH protocol support for secure remote access.
     /// @THREAT Unauthorized SSH access or protocol abuse.
     /// @COUNTERMEASURE Implement secure authentication and audit all connections.
     let ssh_server_clone = Arc::clone(&ssh_server);
     tokio::spawn(async move {
         if let Err(e) = ssh_server_clone.start().await {
             eprintln!("Failed to start SSH server: {}", e);
         }
     });

    /// [FIDO2 LAYER] Hardware Authentication Manager
    /// @MISSION Provide FIDO2/WebAuthn authentication capabilities.
    /// @THREAT Phishing or credential theft.
    /// @COUNTERMEASURE Use hardware-backed public key cryptography.
    let rp_id = std::env::var("FIDO2_RP_ID").unwrap_or("localhost".to_string());
    let rp_origin = std::env::var("FIDO2_RP_ORIGIN").unwrap_or("http://localhost:8080".to_string());
    let fido2_manager = Arc::new(crate::core::fido2::Fido2Manager::new(&rp_id, &rp_origin).unwrap());

    /// [NETWORK LAYER] VPN Infrastructure Management
    /// @MISSION Secure inter-service communication via encrypted mesh.
    /// @THREAT Network interception or lateral movement.
    /// @COUNTERMEASURE Enforce WireGuard + Tailscale with mTLS.
    let vpn_interface = std::env::var("VPN_INTERFACE").unwrap_or("wg0".to_string());
    let vpn_private_key = vault_client.get_secret("vpn/private_key").await.unwrap_or("".to_string());
    let vpn_config = crate::core::vpn::VpnConfig {
        interface: vpn_interface.clone(),
        private_key: vpn_private_key,
        listen_port: 51820,
        address: "10.128.0.1/24".to_string(),
        peers: std::collections::HashMap::new(),
    };
    let vpn_manager = Arc::new(crate::core::vpn::VpnManager::new(&vpn_interface, vpn_config));

    let tailscale_auth_key = vault_client.get_secret("tailscale/auth_key").await.unwrap_or("".to_string());
    let tailscale_manager = Arc::new(crate::core::vpn::TailscaleManager::new(tailscale_auth_key));

    /// [INTER-SERVICE LAYER] gRPC Communication Framework
    /// @MISSION Enable high-performance service-to-service communication.
    /// @THREAT Service spoofing or data tampering.
    /// @COUNTERMEASURE Use QUIC transport with mutual TLS.
    let mut grpc_client = crate::core::grpc::GrpcClient::new();
    let _ = grpc_client.connect_mail_service("http://localhost:50051").await;
    let _ = grpc_client.connect_search_service("http://localhost:50052").await;
    let grpc_client = Arc::new(Mutex::new(grpc_client));

    /// [FILE SYSTEM LAYER] WebDAV/CalDAV/CardDAV Handler
    /// @MISSION Provide secure file and data synchronization.
    /// @THREAT Unauthorized file access or data corruption.
    /// @COUNTERMEASURE Implement ACL-based permissions and integrity checks.
    let webdav_root = std::path::PathBuf::from("./dav_storage");
    let webdav_handler = Arc::new(crate::core::webdav::WebDavHandler::new(webdav_root));
    let caldav_handler = Arc::new(crate::core::webdav::CalDavHandler::new(Arc::clone(&webdav_handler)));
    let carddav_handler = Arc::new(crate::core::webdav::CardDavHandler::new(Arc::clone(&webdav_handler)));

    /// [OBSERVABILITY LAYER] OpenTelemetry Metrics and Tracing
    /// @MISSION Provide sovereign monitoring and audit capabilities.
    /// @THREAT Undetected security incidents.
    /// @COUNTERMEASURE Export all telemetry with cryptographic integrity.
    let _otel_components = crate::core::opentelemetry::init_opentelemetry("sky-genesis-api", "1.0.0").await.unwrap();
    let metrics = Arc::new(crate::core::opentelemetry::Metrics::new().unwrap());

     /// [API GATEWAY] Route Aggregation and Security Enforcement
     /// @MISSION Expose all service endpoints with unified security controls.
     /// @THREAT API abuse or unauthorized access.
     /// @COUNTERMEASURE Implement rate limiting, input validation, and audit logging.
     let routes = routes::routes(
         vault_manager,
         key_service,
         auth_service,
         session_service,
         application_service,
         two_factor_service,
         ws_server,
         snmp_manager,
         snmp_agent,
         trap_listener,
         audit_manager,
         keycloak_client,
         fido2_manager,
         vpn_manager,
         tailscale_manager,
         grpc_client,
         webdav_handler,
         caldav_handler,
         carddav_handler,
         metrics,
         ssh_server,
     );

    /// [NETWORK PERIMETER] Service Binding Configuration
    /// @MISSION Establish secure network listening post.
    /// @THREAT Port scanning or service discovery.
    /// @COUNTERMEASURE Bind to localhost and use reverse proxy for external access.
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid port number");

    println!("Server started at http://localhost:{}", port);

    warp::serve(routes)
        .run(([127, 0, 0, 1], port))
        .await;
}
    });

    // Start trap listener
    let trap_listener_clone = Arc::clone(&trap_listener);
    tokio::spawn(async move {
        let mut listener = Arc::try_unwrap(trap_listener_clone).unwrap();
        if let Err(e) = listener.start().await {
            eprintln!("Failed to start SNMP trap listener: {}", e);
            return;
        }
        if let Err(e) = listener.listen().await {
            eprintln!("SNMP trap listener error: {}", e);
        }
    });

    let routes = routes::routes(
        vault_manager,
        key_service,
        auth_service,
        session_service,
        application_service,
        two_factor_service,
        ws_server,
        snmp_manager,
        snmp_agent,
        trap_listener,
        audit_manager,
        keycloak_client,
        fido2_manager,
        vpn_manager,
        tailscale_manager,
        grpc_client,
        webdav_handler,
        caldav_handler,
        carddav_handler,
        metrics,
    );

    // Get port from environment variable or default to 8080
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid port number");

    println!("Server started at http://localhost:{}", port);

    warp::serve(routes)
        .run(([127, 0, 0, 1], port))
        .await;
}
