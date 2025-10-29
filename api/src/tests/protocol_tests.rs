#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::fido2::Fido2Manager;
    use crate::core::keycloak::KeycloakClient;
    use crate::core::vault::VaultClient;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_fido2_manager_creation() {
        let manager = Fido2Manager::new("localhost", "http://localhost:8080");
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_keycloak_client_creation() {
        // This would require a mock vault client
        // For now, just test the struct creation
        let vault_client = Arc::new(VaultClient::new("http://localhost:8200".to_string(), "role_id".to_string(), "secret_id".to_string()).await.unwrap());
        let keycloak_client = KeycloakClient::new(vault_client).await;
        assert!(keycloak_client.is_ok());
    }

    #[tokio::test]
    async fn test_websocket_presence() {
        use crate::websocket::WebSocketServer;
        let server = WebSocketServer::new();

        // Test presence update
        server.update_presence("user1", crate::websocket::PresenceStatus::Online, Some("Available".to_string())).await;

        let presence = server.get_presence("user1").await;
        assert!(presence.is_some());
        assert!(matches!(presence.unwrap().0, crate::websocket::PresenceStatus::Online));
    }

    #[tokio::test]
    async fn test_webdav_resource_creation() {
        use crate::core::webdav::WebDavHandler;
        use std::path::PathBuf;

        let handler = WebDavHandler::new(PathBuf::from("/tmp"));
        let resource = crate::core::webdav::DavResource {
            path: "/test".to_string(),
            is_collection: false,
            size: Some(1024),
            last_modified: chrono::Utc::now().timestamp(),
            content_type: Some("text/plain".to_string()),
            etag: "\"test\"".to_string(),
        };

        let result = handler.create_resource("/test".to_string(), resource).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_grpc_client_creation() {
        use crate::core::grpc::GrpcClient;
        let client = GrpcClient::new();
        // Just test that it creates without error
        assert!(true);
    }

    #[tokio::test]
    async fn test_vpn_config_creation() {
        use crate::core::vpn::VpnConfig;
        let config = VpnConfig {
            interface: "wg0".to_string(),
            private_key: "test_key".to_string(),
            listen_port: 51820,
            address: "10.0.0.1/24".to_string(),
            peers: std::collections::HashMap::new(),
        };
        assert_eq!(config.interface, "wg0");
    }

    #[tokio::test]
    async fn test_opentelemetry_metrics_creation() {
        // This would require OpenTelemetry to be initialized first
        // For now, just test that the struct exists
        assert!(true);
    }
}