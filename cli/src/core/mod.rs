pub mod api_client;
pub mod auth;
pub mod logger;
pub mod telemetry;

use crate::config::Config;

// Re-export for convenience
pub use api_client::SshApiClient;

pub struct AppState {
    #[allow(dead_code)]
    pub config: Config,
    pub client: SshApiClient,
}

impl AppState {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let client = SshApiClient::new(
            config.ssh_host.clone(),
            config.ssh_port,
            config.ssh_username.clone(),
        )?;

        Ok(Self { config, client })
    }
}