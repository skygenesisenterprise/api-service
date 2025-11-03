#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_frontend_base_url_development() {
        // Test development environment
        std::env::set_var("NODE_ENV", "development");
        std::env::remove_var("FRONTEND_BASE_URL");
        
        let url = get_frontend_base_url();
        assert_eq!(url, "http://localhost:3000");
    }

    #[test]
    fn test_get_frontend_base_url_production() {
        // Test production environment
        std::env::set_var("NODE_ENV", "production");
        std::env::remove_var("FRONTEND_BASE_URL");
        
        let url = get_frontend_base_url();
        assert_eq!(url, "https://sso.skygenesisenterprise.com");
    }

    #[test]
    fn test_get_frontend_base_url_custom_override() {
        // Test custom URL override
        std::env::set_var("NODE_ENV", "production");
        std::env::set_var("FRONTEND_BASE_URL", "https://custom.example.com");
        
        let url = get_frontend_base_url();
        assert_eq!(url, "https://custom.example.com");
        
        // Cleanup
        std::env::remove_var("FRONTEND_BASE_URL");
    }

    #[test]
    fn test_get_frontend_base_url_no_env() {
        // Test when NODE_ENV is not set (defaults to development behavior)
        std::env::remove_var("NODE_ENV");
        std::env::remove_var("FRONTEND_BASE_URL");
        
        let url = get_frontend_base_url();
        assert_eq!(url, "http://localhost:3000");
    }
}