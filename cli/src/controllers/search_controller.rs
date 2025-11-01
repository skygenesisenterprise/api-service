use clap::{Args, Subcommand};
use crate::core::api_client::SshApiClient;
use anyhow::Result;

#[derive(Args)]
pub struct SearchArgs {
    #[command(subcommand)]
    pub command: SearchCommands,
}

#[derive(Subcommand)]
pub enum SearchCommands {
    /// Search logs
    Logs { pattern: String },
    /// Search users
    Users { query: String },
}

pub async fn handle_search(args: SearchArgs, state: &crate::core::AppState) -> Result<()> {
    let client = &state.client;

    match args.command {
        SearchCommands::Logs { pattern } => {
            let result = client.search_logs(&pattern, Some(10))?;
            println!("Found {} matches for '{}'", result.total_matches, result.pattern);
            for entry in result.entries {
                println!("[{}] {}: {}", entry.timestamp, entry.level, entry.message);
            }
        }
        SearchCommands::Users { query } => {
            let params = serde_json::json!({ "query": query });
            let result = client.call_method("users.search", params)?;
            println!("Search results: {}", result);
        }
    }

    Ok(())
}
