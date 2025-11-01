// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Device Management Controller
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide CLI commands for remote device management via API.
//  NOTICE: This module implements device operations using the REST API.
//  COMMANDS: device list, device show, device create, device update, device delete,
//            device command, device status, device metrics
//  SECURITY: All operations require authentication and are audited
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use clap::{Args, Subcommand};
use crate::core::api_client::SshApiClient;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// [DEVICE ARGS] Device command arguments
#[derive(Args)]
pub struct DeviceArgs {
    #[command(subcommand)]
    pub command: DeviceCommands,
}

/// [DEVICE COMMANDS] Available device subcommands
#[derive(Subcommand)]
pub enum DeviceCommands {
    /// List all managed devices
    List {
        /// Filter by device status (online, offline, maintenance, error, unknown)
        #[arg(long)]
        status: Option<String>,
        /// Filter by device type (router, switch, server, firewall, etc.)
        #[arg(long)]
        device_type: Option<String>,
        /// Page number (default: 1)
        #[arg(long, default_value = "1")]
        page: u32,
        /// Items per page (default: 50)
        #[arg(long, default_value = "50")]
        per_page: u32,
    },
    /// Show detailed information about a specific device
    Show {
        /// Device ID or name
        device_id: String,
    },
    /// Create a new device for management
    Create {
        /// Device name
        #[arg(long)]
        name: String,
        /// Device hostname or IP
        #[arg(long)]
        hostname: String,
        /// Device IP address (if different from hostname)
        #[arg(long)]
        ip_address: Option<String>,
        /// Device type (router, switch, server, firewall, loadbalancer, accesspoint, iotdevice, other)
        #[arg(long)]
        device_type: String,
        /// Connection type (snmp, ssh, rest, websocket, mqtt)
        #[arg(long, default_value = "snmp")]
        connection_type: String,
        /// Device vendor
        #[arg(long)]
        vendor: Option<String>,
        /// Device model
        #[arg(long)]
        model: Option<String>,
        /// Operating system version
        #[arg(long)]
        os_version: Option<String>,
        /// Device location
        #[arg(long)]
        location: Option<String>,
        /// Management port
        #[arg(long)]
        management_port: Option<u16>,
        /// Credentials reference in vault
        #[arg(long)]
        credentials_ref: Option<String>,
        /// Device tags (comma-separated)
        #[arg(long)]
        tags: Option<String>,
    },
    /// Update device configuration
    Update {
        /// Device ID
        device_id: String,
        /// New device name
        #[arg(long)]
        name: Option<String>,
        /// New hostname
        #[arg(long)]
        hostname: Option<String>,
        /// New IP address
        #[arg(long)]
        ip_address: Option<String>,
        /// New device type
        #[arg(long)]
        device_type: Option<String>,
        /// New connection type
        #[arg(long)]
        connection_type: Option<String>,
        /// New vendor
        #[arg(long)]
        vendor: Option<String>,
        /// New model
        #[arg(long)]
        model: Option<String>,
        /// New OS version
        #[arg(long)]
        os_version: Option<String>,
        /// New location
        #[arg(long)]
        location: Option<String>,
        /// New management port
        #[arg(long)]
        management_port: Option<u16>,
        /// New credentials reference
        #[arg(long)]
        credentials_ref: Option<String>,
        /// New tags (comma-separated)
        #[arg(long)]
        tags: Option<String>,
    },
    /// Delete a device from management
    Delete {
        /// Device ID
        device_id: String,
        /// Confirm deletion (must be 'yes')
        #[arg(long)]
        confirm: String,
    },
    /// Execute command on device
    Command {
        /// Device ID
        device_id: String,
        /// Command to execute
        command: String,
        /// Command parameters (key=value pairs, comma-separated)
        #[arg(long)]
        parameters: Option<String>,
        /// Command timeout in seconds
        #[arg(long)]
        timeout: Option<u32>,
    },
    /// Check command execution status
    CommandStatus {
        /// Command ID
        command_id: String,
    },
    /// Update device status
    Status {
        /// Device ID
        device_id: String,
        /// New status (online, offline, maintenance, error, unknown)
        status: String,
    },
    /// Get device performance metrics
    Metrics {
        /// Device ID
        device_id: String,
        /// Maximum number of metrics to retrieve
        #[arg(long)]
        limit: Option<usize>,
    },
}

/// API response structures
#[derive(Debug, Deserialize)]
struct DeviceListResponse {
    devices: Vec<Device>,
    total_count: i64,
    page: u32,
    per_page: u32,
}

#[derive(Debug, Deserialize)]
struct Device {
    id: Uuid,
    name: String,
    hostname: String,
    ip_address: Option<String>,
    device_type: String,
    connection_type: String,
    vendor: Option<String>,
    model: Option<String>,
    os_version: Option<String>,
    status: String,
    location: Option<String>,
    tags: Vec<String>,
    management_port: Option<i32>,
    last_seen: Option<String>,
    cpu_usage: Option<f32>,
    memory_usage: Option<f32>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct CommandResponse {
    command_id: Uuid,
    status: String,
    output: Option<String>,
    exit_code: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct MetricsResponse {
    metrics: Vec<DeviceMetric>,
    device_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct DeviceMetric {
    timestamp: String,
    cpu_usage: Option<f32>,
    memory_usage: Option<f32>,
    disk_usage: Option<f32>,
}

/// [DEVICE CONTROLLER] Handle device management commands
/// @MISSION Process device-related CLI commands via REST API.
/// @THREAT Unauthorized device operations.
/// @COUNTERMEASURE Validate permissions and audit all operations.
pub async fn handle_device(args: DeviceArgs, state: &crate::core::AppState) -> Result<()> {
    let client = &state.client;
    match args.command {
        DeviceCommands::List { status, device_type, page, per_page } => {
            list_devices(client, status, device_type, page, per_page).await
        }
        DeviceCommands::Show { device_id } => {
            show_device(client, &device_id).await
        }
        DeviceCommands::Create {
            name,
            hostname,
            ip_address,
            device_type,
            connection_type,
            vendor,
            model,
            os_version,
            location,
            management_port,
            credentials_ref,
            tags,
        } => {
            create_device(
                client,
                name,
                hostname,
                ip_address,
                device_type,
                connection_type,
                vendor,
                model,
                os_version,
                location,
                management_port,
                credentials_ref,
                tags,
            ).await
        }
        DeviceCommands::Update {
            device_id,
            name,
            hostname,
            ip_address,
            device_type,
            connection_type,
            vendor,
            model,
            os_version,
            location,
            management_port,
            credentials_ref,
            tags,
        } => {
            update_device(
                client,
                device_id,
                name,
                hostname,
                ip_address,
                device_type,
                connection_type,
                vendor,
                model,
                os_version,
                location,
                management_port,
                credentials_ref,
                tags,
            ).await
        }
        DeviceCommands::Delete { device_id, confirm } => {
            delete_device(client, device_id, confirm).await
        }
        DeviceCommands::Command { device_id, command, parameters, timeout } => {
            execute_command(client, device_id, command, parameters, timeout).await
        }
        DeviceCommands::CommandStatus { command_id } => {
            get_command_status(client, command_id).await
        }
        DeviceCommands::Status { device_id, status } => {
            update_device_status(client, device_id, status).await
        }
        DeviceCommands::Metrics { device_id, limit } => {
            get_device_metrics(client, device_id, limit).await
        }
    }
}

/// List devices with optional filters
async fn list_devices(
    client: &SshApiClient,
    status: Option<String>,
    device_type: Option<String>,
    page: u32,
    per_page: u32,
) -> Result<()> {
    let mut query_params = vec![
        format!("page={}", page),
        format!("per_page={}", per_page),
    ];

    if let Some(status) = status {
        query_params.push(format!("status={}", status));
    }

    if let Some(device_type) = device_type {
        query_params.push(format!("device_type={}", device_type));
    }

    let query_string = query_params.join("&");
    let url = format!("/api/v1/devices?{}", query_string);

    match client.get(&url).await {
        Ok(response) => {
            let devices_response: DeviceListResponse = serde_json::from_str(&response)?;
            println!("Managed Devices (Page {} of {}, Total: {})", page, (devices_response.total_count as f64 / per_page as f64).ceil(), devices_response.total_count);
            println!("{}", "=".repeat(120));

            if devices_response.devices.is_empty() {
                println!("No devices found.");
                return Ok(());
            }

            println!("{:<36} {:<20} {:<15} {:<12} {:<10} {:<15} {:<10}",
                     "ID", "Name", "Type", "Connection", "Status", "Hostname", "Last Seen");
            println!("{}", "-".repeat(120));

            for device in devices_response.devices {
                let last_seen = device.last_seen
                    .map(|dt| dt.split('T').next().unwrap_or("unknown").to_string())
                    .unwrap_or_else(|| "never".to_string());

                println!("{:<36} {:<20} {:<15} {:<12} {:<10} {:<15} {:<10}",
                         device.id,
                         truncate_string(&device.name, 20),
                         truncate_string(&device.device_type, 15),
                         truncate_string(&device.connection_type, 12),
                         truncate_string(&device.status, 10),
                         truncate_string(&device.hostname, 15),
                         last_seen);
            }
        }
        Err(e) => {
            println!("Error listing devices: {}", e);
        }
    }

    Ok(())
}

/// Show detailed device information
async fn show_device(client: &SshApiClient, device_id: &str) -> Result<()> {
    let url = format!("/api/v1/devices/{}", device_id);

    match client.get(&url).await {
        Ok(response) => {
            let device: Device = serde_json::from_str(&response)?;
            println!("Device Details");
            println!("{}", "=".repeat(50));
            println!("ID:              {}", device.id);
            println!("Name:            {}", device.name);
            println!("Hostname:        {}", device.hostname);
            if let Some(ip) = &device.ip_address {
                println!("IP Address:      {}", ip);
            }
            println!("Type:            {}", device.device_type);
            println!("Connection:      {}", device.connection_type);
            if let Some(vendor) = &device.vendor {
                println!("Vendor:          {}", vendor);
            }
            if let Some(model) = &device.model {
                println!("Model:           {}", model);
            }
            if let Some(os) = &device.os_version {
                println!("OS Version:      {}", os);
            }
            println!("Status:          {}", device.status);
            if let Some(location) = &device.location {
                println!("Location:        {}", location);
            }
            if !device.tags.is_empty() {
                println!("Tags:            {}", device.tags.join(", "));
            }
            if let Some(port) = device.management_port {
                println!("Management Port: {}", port);
            }
            if let Some(last_seen) = &device.last_seen {
                println!("Last Seen:       {}", last_seen);
            }
            if let Some(cpu) = device.cpu_usage {
                println!("CPU Usage:       {:.1}%", cpu);
            }
            if let Some(memory) = device.memory_usage {
                println!("Memory Usage:    {:.1}%", memory);
            }
            println!("Created:         {}", device.created_at);
            println!("Updated:         {}", device.updated_at);
        }
        Err(e) => {
            println!("Error getting device: {}", e);
        }
    }

    Ok(())
}

/// Create a new device
async fn create_device(
    client: &SshApiClient,
    name: String,
    hostname: String,
    ip_address: Option<String>,
    device_type: String,
    connection_type: String,
    vendor: Option<String>,
    model: Option<String>,
    os_version: Option<String>,
    location: Option<String>,
    management_port: Option<u16>,
    credentials_ref: Option<String>,
    tags: Option<String>,
) -> Result<()> {
    let tags_vec: Vec<String> = tags.map(|t| t.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default();

    let payload = serde_json::json!({
        "name": name,
        "hostname": hostname,
        "ip_address": ip_address,
        "device_type": device_type,
        "connection_type": connection_type,
        "vendor": vendor,
        "model": model,
        "os_version": os_version,
        "location": location,
        "management_port": management_port,
        "credentials_ref": credentials_ref,
        "tags": tags_vec
    });

    match client.post("/api/v1/devices", &serde_json::to_string(&payload)?).await {
        Ok(response) => {
            let device: Device = serde_json::from_str(&response)?;
            println!("Device created successfully:");
            println!("ID: {}", device.id);
            println!("Name: {}", device.name);
        }
        Err(e) => {
            println!("Error creating device: {}", e);
        }
    }

    Ok(())
}

/// Update device configuration
async fn update_device(
    client: &SshApiClient,
    device_id: String,
    name: Option<String>,
    hostname: Option<String>,
    ip_address: Option<String>,
    device_type: Option<String>,
    connection_type: Option<String>,
    vendor: Option<String>,
    model: Option<String>,
    os_version: Option<String>,
    location: Option<String>,
    management_port: Option<u16>,
    credentials_ref: Option<String>,
    tags: Option<String>,
) -> Result<()> {
    let tags_vec: Option<Vec<String>> = tags.map(|t| t.split(',').map(|s| s.trim().to_string()).collect());

    let payload = serde_json::json!({
        "name": name,
        "hostname": hostname,
        "ip_address": ip_address,
        "device_type": device_type,
        "connection_type": connection_type,
        "vendor": vendor,
        "model": model,
        "os_version": os_version,
        "location": location,
        "management_port": management_port,
        "credentials_ref": credentials_ref,
        "tags": tags_vec
    });

    let url = format!("/api/v1/devices/{}", device_id);

    match client.put(&url, &serde_json::to_string(&payload)?).await {
        Ok(response) => {
            let device: Device = serde_json::from_str(&response)?;
            println!("Device updated successfully:");
            println!("ID: {}", device.id);
            println!("Name: {}", device.name);
        }
        Err(e) => {
            println!("Error updating device: {}", e);
        }
    }

    Ok(())
}

/// Delete a device
async fn delete_device(client: &SshApiClient, device_id: String, confirm: String) -> Result<()> {
    if confirm != "yes" {
        println!("Deletion not confirmed. Use --confirm=yes to delete the device.");
        return Ok(());
    }

    let url = format!("/api/v1/devices/{}", device_id);

    match client.delete(&url).await {
        Ok(_) => {
            println!("Device {} deleted successfully.", device_id);
        }
        Err(e) => {
            println!("Error deleting device: {}", e);
        }
    }

    Ok(())
}

/// Execute command on device
async fn execute_command(
    client: &SshApiClient,
    device_id: String,
    command: String,
    parameters: Option<String>,
    timeout: Option<u32>,
) -> Result<()> {
    let params_map = parameters.map(|p| {
        p.split(',')
            .filter_map(|pair| {
                let mut parts = pair.split('=');
                match (parts.next(), parts.next()) {
                    (Some(key), Some(value)) => Some((key.trim().to_string(), value.trim().to_string())),
                    _ => None,
                }
            })
            .collect::<std::collections::HashMap<String, String>>()
    });

    let payload = serde_json::json!({
        "command": command,
        "parameters": params_map,
        "timeout_seconds": timeout
    });

    let url = format!("/api/v1/devices/{}/commands", device_id);

    match client.post(&url, &serde_json::to_string(&payload)?).await {
        Ok(response) => {
            let cmd_response: CommandResponse = serde_json::from_str(&response)?;
            println!("Command submitted successfully:");
            println!("Command ID: {}", cmd_response.command_id);
            println!("Status: {}", cmd_response.status);
            if let Some(output) = cmd_response.output {
                println!("Output: {}", output);
            }
            if let Some(exit_code) = cmd_response.exit_code {
                println!("Exit Code: {}", exit_code);
            }
        }
        Err(e) => {
            println!("Error executing command: {}", e);
        }
    }

    Ok(())
}

/// Get command execution status
async fn get_command_status(client: &SshApiClient, command_id: String) -> Result<()> {
    let url = format!("/api/v1/devices/0/commands/{}", command_id); // Using 0 as placeholder device_id

    match client.get(&url).await {
        Ok(response) => {
            let cmd_response: CommandResponse = serde_json::from_str(&response)?;
            println!("Command Status:");
            println!("Command ID: {}", cmd_response.command_id);
            println!("Status: {}", cmd_response.status);
            if let Some(output) = cmd_response.output {
                println!("Output: {}", output);
            }
            if let Some(exit_code) = cmd_response.exit_code {
                println!("Exit Code: {}", exit_code);
            }
        }
        Err(e) => {
            println!("Error getting command status: {}", e);
        }
    }

    Ok(())
}

/// Update device status
async fn update_device_status(client: &SshApiClient, device_id: String, status: String) -> Result<()> {
    let payload = serde_json::json!({
        "status": status
    });

    let url = format!("/api/v1/devices/{}/status", device_id);

    match client.put(&url, &serde_json::to_string(&payload)?).await {
        Ok(response) => {
            let device: Device = serde_json::from_str(&response)?;
            println!("Device status updated successfully:");
            println!("ID: {}", device.id);
            println!("Name: {}", device.name);
            println!("Status: {}", device.status);
        }
        Err(e) => {
            println!("Error updating device status: {}", e);
        }
    }

    Ok(())
}

/// Get device metrics
async fn get_device_metrics(client: &SshApiClient, device_id: String, limit: Option<usize>) -> Result<()> {
    let mut url = format!("/api/v1/devices/{}/metrics", device_id);
    if let Some(limit) = limit {
        url.push_str(&format!("?limit={}", limit));
    }

    match client.get(&url).await {
        Ok(response) => {
            let metrics_response: MetricsResponse = serde_json::from_str(&response)?;
            println!("Device Metrics (Device: {})", metrics_response.device_id);
            println!("{}", "=".repeat(80));

            if metrics_response.metrics.is_empty() {
                println!("No metrics found.");
                return Ok(());
            }

            println!("{:<20} {:<10} {:<10} {:<10}",
                     "Timestamp", "CPU %", "Memory %", "Disk %");
            println!("{}", "-".repeat(80));

            for metric in metrics_response.metrics.iter().rev().take(10) { // Show last 10
                let timestamp = metric.timestamp.split('T').next().unwrap_or("unknown");
                println!("{:<20} {:<10} {:<10} {:<10}",
                         timestamp,
                         metric.cpu_usage.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "-".to_string()),
                         metric.memory_usage.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "-".to_string()),
                         metric.disk_usage.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "-".to_string()));
            }
        }
        Err(e) => {
            println!("Error getting device metrics: {}", e);
        }
    }

    Ok(())
}

/// Helper function to truncate strings for display
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}