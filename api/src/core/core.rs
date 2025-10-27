// Core business logic

pub fn validate_permissions(api_key: &crate::models::ApiKey, required: &str) -> bool {
    api_key.permissions.contains(&required.to_string())
}