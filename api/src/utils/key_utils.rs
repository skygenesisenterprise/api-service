use uuid::Uuid;

pub fn generate_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn generate_key() -> String {
    // Simple random key, in real app use crypto
    Uuid::new_v4().to_string()
}

pub fn hash_key(key: &str) -> String {
    // Placeholder hash
    format!("hashed_{}", key)
}

pub fn calculate_ttl(ttl: u64) -> u64 {
    ttl // In seconds
}