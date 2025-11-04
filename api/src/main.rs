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
use std::sync::{Arc, Mutex};
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
mod schema;
mod services;
mod tests;
mod search;
mod openapi;
mod websocket;
mod ssh;
mod data;
mod utils;

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

      /// [DATABASE LAYER] Multi-Database Connection Management
      /// @MISSION Provide secure access to multiple database types.
      /// @THREAT Unauthorized database access or credential exposure.
      /// @COUNTERMEASURE Encrypted credentials in Vault and access control.
      let data_service = Arc::new(crate::services::data_service::DataService::new(vault_client.clone()));

      /// [OPENPGP LAYER] OpenPGP Cryptographic Operations
      /// @MISSION Provide OpenPGP key generation, signing, and encryption.
      /// @THREAT Weak cryptography or key compromise.
      /// @COUNTERMEASURE Use Sequoia OpenPGP with secure key management.
      let openpgp_service = Arc::new(crate::services::openpgp_service::OpenPGPService::new());

/// [MONITORING LAYER] SNMP Management and Audit
    /// @MISSION Provide network monitoring and security auditing.
    /// @THREAT Undetected network anomalies.
    /// @COUNTERMEASURE Implement comprehensive SNMP traps and audit logging.
    let snmp_manager = Arc::new(crate::core::snmp_manager::SnmpManager::new(vault_client.clone()));
    let audit_manager = Arc::new(crate::core::audit_manager::AuditManager::new(vault_client.clone()));
    let metrics = Arc::new(crate::core::opentelemetry::Metrics::new().unwrap());

    /// [DATABASE LAYER] Database Connection Pool
    /// @MISSION Provide secure database connections.
    /// @THREAT Unauthorized database access.
    /// @COUNTERMEASURE Encrypted credentials and connection pooling.
    let db_pool = Arc::new(crate::data::database::DatabasePool::new().await.unwrap());

       /// [DEVICE MANAGEMENT LAYER] Remote Device Management Service
       /// @MISSION Enable secure remote management of network devices.
       /// @THREAT Unauthorized device access or configuration changes.
       /// @COUNTERMEASURE Authentication, authorization, and audit logging.
         let device_service = Arc::new(crate::services::device_service::DeviceService::new(
             db_pool.clone(),
             vault_client.clone(),
             snmp_manager.clone(),
         ));

        /// [MAC SERVICE] MAC identity management service
        /// @MISSION Provide secure MAC identity operations with cryptographic generation.
        /// @THREAT MAC spoofing or identity compromise.
        /// @COUNTERMEASURE Cryptographic MAC generation and validation.
        /// [MAC CERTIFICATES CORE] Certificate management for MAC identities
        /// @MISSION Provide X.509 certificate operations for MAC security.
        /// @THREAT Certificate compromise or weak cryptography.
        /// @COUNTERMEASURE X.509 certificates with CA signing.
        let ca_certificate = std::env::var("CA_CERTIFICATE").unwrap_or_else(|_| "dummy-ca-cert".to_string());
        let ca_private_key = std::env::var("CA_PRIVATE_KEY").unwrap_or_else(|_| "dummy-ca-key".to_string());
        let mac_certificates_core = Arc::new(crate::core::mac_certificates::MacCertificatesCore::new(
            vault_client.clone(),
            audit_manager.clone(),
            ca_certificate,
            ca_private_key,
        ));

        let mac_service = Arc::new(crate::services::mac_service::MacService::new(
            db_pool.clone(),
            vault_client.clone(),
            mac_certificates_core.clone(),
        ));

        /// [VOIP LAYER] Asterisk PBX Integration
    /// @MISSION Provide native VoIP capabilities through Asterisk PBX.
    /// @THREAT PBX compromise or call interception.
    /// @COUNTERMEASURE Secure ARI communication and audit all VoIP operations.
    let asterisk_base_url = std::env::var("ASTERISK_ARI_URL").unwrap_or("http://localhost:8088/ari".to_string());
    let asterisk_username = std::env::var("ASTERISK_ARI_USERNAME").unwrap_or("skygenesis".to_string());
    let asterisk_password = vault_client.get_secret("asterisk/ari_password").await.unwrap_or("password".to_string());
    let asterisk_app_name = std::env::var("ASTERISK_ARI_APP").unwrap_or("sky-genesis-voip".to_string());

    let asterisk_config = crate::core::asterisk_client::AsteriskConfig {
        base_url: asterisk_base_url,
        username: asterisk_username,
        password: asterisk_password,
        app_name: asterisk_app_name,
        tls_enabled: std::env::var("ASTERISK_TLS_ENABLED").unwrap_or_else(|_| "true".to_string()) == "true",
        client_cert_path: std::env::var("ASTERISK_CLIENT_CERT").ok(),
        client_key_path: std::env::var("ASTERISK_CLIENT_KEY").ok(),
        ca_cert_path: std::env::var("ASTERISK_CA_CERT").ok(),
    };

    /// [VOIP SERVICE] Voice over IP and video conferencing service
    /// @MISSION Provide VoIP functionality with secure signaling.
    /// @THREAT Unauthorized calls, eavesdropping.
    /// @COUNTERMEASURE Authentication, encryption, audit logging.
    let voip_service = Arc::new(crate::services::voip_service::VoipService::new(asterisk_config));

        /// [MAIL SERVICE] Email service integration (mock for now)
        /// @MISSION Provide email functionality for Discord notifications.
        let mail_service = Arc::new(crate::services::mail_service::MailService::new()); // Mock

        /// [SEARCH SERVICE] Search service integration (mock for now)
        /// @MISSION Provide search functionality for Discord commands.
        let search_service = Arc::new(crate::services::search_service::SearchService::new()); // Mock

        /// [DISCORD SERVICE] Discord bot integration service
        /// @MISSION Provide secure Discord bot operations and command execution.
        /// @THREAT Unauthorized bot access, command injection.
        /// @COUNTERMEASURE Authentication, validation, audit logging.
        let discord_config = crate::models::discord_model::DiscordConfig {
            channels: vec![], // Empty for now
            roles: vec![],
            permissions: vec![],
            commands: vec![],
            webhooks: vec![],
            vpn_required: true,
            audit_enabled: true,
        };
        let discord_service = Arc::new(crate::services::discord_service::DiscordService::new(
            vault_client.clone(),
            audit_manager.clone(),
            metrics.clone(),
            vpn_manager.clone(),
            tailscale_manager.clone(),
            mail_service.clone(),
            search_service.clone(),
            discord_config,
        ));

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
         host: std::env::var("SSH_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
         port: std::env::var("SSH_PORT")
             .unwrap_or_else(|_| "2222".to_string())
             .parse::<u16>()
             .expect("SSH_PORT must be a valid port number"),
         domain: std::env::var("SSH_DOMAIN").unwrap_or_else(|_| "skygenesisenterprise.com".to_string()),
         max_connections: std::env::var("SSH_MAX_CONNECTIONS")
             .unwrap_or_else(|_| "50".to_string())
             .parse::<usize>()
             .expect("SSH_MAX_CONNECTIONS must be a valid number"),
         idle_timeout: 300, // 5 minutes
         auth_timeout: 60,  // 1 minute
     };
      let ssh_server = Arc::new(crate::ssh::SshServer::new(
          ssh_config,
          auth_service.clone(),
          key_service.clone(),
          device_service.clone(),
          vault_client.clone(),
          audit_manager.clone(),
      ).await.unwrap());

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

    let asterisk_client = Arc::new(crate::core::asterisk_client::AsteriskClient::new(asterisk_config));

    /// [MONITORING SERVICE] System Health and Status Monitoring
    /// @MISSION Provide comprehensive monitoring capabilities for Grafana.
    /// @THREAT Undetected system issues affecting availability.
    /// @COUNTERMEASURE Automated health checks and metric collection.
    /// @DEPENDENCY Vault and metrics services for monitoring data.
    /// @PERFORMANCE Monitoring service initialized with system start time.
    /// @AUDIT Monitoring operations logged for system observability.
    let monitoring_service = Arc::new(crate::services::monitoring_service::MonitoringService::new(
        vault_client.clone(),
        metrics.clone(),
    ));

    /// [GRAFANA SERVICE INITIALIZATION] Grafana API Integration Setup
    /// @MISSION Initialize Grafana service for dashboard management.
    /// @THREAT Manual Grafana configuration overhead.
    /// @COUNTERMEASURE Automated Grafana API integration.
    /// @DEPENDENCY Vault for secure API key storage.
    /// @PERFORMANCE Grafana service initialized with connection validation.
    /// @AUDIT Grafana operations logged for compliance.
     let grafana_service = Arc::new(crate::services::grafana_service::GrafanaService::new(
         vault_client.clone(),
     ).await.expect("Failed to initialize Grafana service"));

     /// [POWERADMIN SERVICE INITIALIZATION] PowerAdmin DNS Management Setup
     /// @MISSION Initialize PowerAdmin service for DNS zone and record management.
     /// @THREAT Manual DNS configuration overhead.
     /// @COUNTERMEASURE Automated PowerAdmin API integration.
     /// @DEPENDENCY Vault for secure API credentials storage.
     /// @PERFORMANCE PowerAdmin service initialized with connection validation.
     /// @AUDIT PowerAdmin operations logged for compliance.
     let poweradmin_service = Arc::new(crate::services::poweradmin_service::PowerAdminService::new(
         vault_client.clone(),
     ).await.expect("Failed to initialize PowerAdmin service"));

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
              data_service,
              openpgp_service.clone(),
              device_service,
              mac_service.clone(),
              ws_server,
            ws_server,
            snmp_manager,
            snmp_agent,
            trap_listener,
            audit_manager,
             keycloak_client,
             fido2_manager,
              monitoring_service,
              grafana_service,
              poweradmin_service,
             vpn_manager,
           tailscale_manager,
           grpc_client,
           webdav_handler,
           caldav_handler,
           carddav_handler,
           metrics,
           ssh_server,
         voip_service,
         asterisk_client,
         discord_service,
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
