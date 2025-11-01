use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_username: String,
    pub api_host: String,
    pub api_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ssh_host: "localhost".to_string(),
            ssh_port: 22,
            ssh_username: "admin".to_string(),
            api_host: "localhost".to_string(),
            api_port: 8080,
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config_path = Path::new("cli/.env");

        if config_path.exists() {
            let content = fs::read_to_string(config_path)?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }
}