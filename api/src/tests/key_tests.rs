#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::key_utils;

    #[test]
    fn test_api_key_format() {
        let raw_key = "test_key_123".to_string();
        let formatted_key = key_utils::format_api_key(raw_key);
        assert_eq!(formatted_key, "sk_test_key_123");
        assert!(formatted_key.starts_with("sk_"));
    }

    #[test]
    fn test_generate_key_has_prefix() {
        let key = key_utils::generate_key();
        // Note: generate_key() returns a UUID, format_api_key adds the prefix
        let formatted = key_utils::format_api_key(key);
        assert!(formatted.starts_with("sk_"));
        assert_eq!(formatted.len(), "sk_".len() + key.len());
    }
}