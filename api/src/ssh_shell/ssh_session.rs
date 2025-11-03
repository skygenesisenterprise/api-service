use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSession {
    pub id: Uuid,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub environment: HashMap<String, String>,
    pub working_directory: String,
}

impl SshSession {
    pub fn new(user_id: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            environment: HashMap::new(),
            working_directory: "/home".to_string(),
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }

    pub fn set_env_var(&mut self, key: String, value: String) {
        self.environment.insert(key, value);
    }

    pub fn get_env_var(&self, key: &str) -> Option<&String> {
        self.environment.get(key)
    }

    pub fn change_directory(&mut self, path: String) {
        self.working_directory = path;
    }
}