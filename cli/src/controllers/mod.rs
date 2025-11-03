// Re-export controller args and handlers
pub use auth_controller::{AuthArgs, handle_auth};
pub use user_controller::{UserArgs, handle_user};
pub use key_controller::{KeyArgs, handle_keys};
pub use security_controller::{SecurityArgs, handle_security};
pub use org_controller::{OrgArgs, handle_org};
pub use network_controller::{NetworkArgs, handle_network};
pub use vpn_controller::{VpnArgs, handle_vpn};
pub use mail_controller::{MailArgs, handle_mail};
pub use search_controller::{SearchArgs, handle_search};
pub use system_controller::{TelemetryArgs, handle_telemetry};
pub use device_controller::{DeviceArgs, handle_device};

// Include controller modules
mod auth_controller;
mod user_controller;
mod key_controller;
mod security_controller;
mod org_controller;
mod network_controller;
mod vpn_controller;
mod mail_controller;
mod search_controller;
mod system_controller;
mod device_controller;