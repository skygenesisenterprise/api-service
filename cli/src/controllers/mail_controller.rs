use clap::{Args, Subcommand};
use crate::core::api_client::SshApiClient;
use anyhow::Result;

#[derive(Args)]
pub struct MailArgs {
    #[command(subcommand)]
    pub command: MailCommands,
}

#[derive(Subcommand)]
pub enum MailCommands {
    /// Show mail service status
    Status,
    /// Send test email
    Test { to: String },
}

pub async fn handle_mail(args: MailArgs, state: &crate::core::AppState) -> Result<()> {
    let client = &state.client;

    match args.command {
        MailCommands::Status => {
            // Use the existing mail query method
            let params = serde_json::json!({ "action": "status" });
            let result = client.call_method("mail.status", params)?;
            println!("Mail service status: {}", result);
        }
        MailCommands::Test { to } => {
            let params = serde_json::json!({ "to": to, "action": "test" });
            let result = client.call_method("mail.send_test", params)?;
            println!("Test email sent: {}", result);
        }
    }

    Ok(())
}
