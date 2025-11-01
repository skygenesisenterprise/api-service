use clap::{Args, Subcommand};
use crate::core::api_client::SshApiClient;
use anyhow::Result;

// Re-export controller args and handlers
pub use network_controller::{NetworkArgs, handle_network};
pub use vpn_controller::{VpnArgs, handle_vpn};
pub use mail_controller::{MailArgs, handle_mail};
pub use search_controller::{SearchArgs, handle_search};
pub use system_controller::{TelemetryArgs, handle_telemetry};
pub use device_controller::{DeviceArgs, handle_device};

// Include controller modules
mod network_controller;
mod vpn_controller;
mod mail_controller;
mod search_controller;
mod system_controller;
mod device_controller;