// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Network Models
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define data models for network-related CLI operations.
//  NOTICE: This module contains structures for representing network interfaces,
//  routing tables, connections, and network status information.
//  SECURITY: Network information properly validated and sanitized
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use chrono::{DateTime, Utc};
use crate::models::{Validate, ValidationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub status: String,
    pub interfaces: u32,
    pub routes: u32,
    pub connections: u32,
    pub bandwidth_rx: String,
    pub bandwidth_tx: String,
    pub uptime: String,
    pub hostname: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_address: IpAddr,
    pub netmask: IpAddr,
    pub broadcast: Option<IpAddr>,
    pub mac_address: String,
    pub status: InterfaceStatus,
    pub mtu: u32,
    pub speed_mbps: Option<u32>,
    pub duplex: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterfaceStatus {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub destination: IpAddr,
    pub gateway: Option<IpAddr>,
    pub netmask: IpAddr,
    pub interface: String,
    pub metric: u32,
    pub route_type: RouteType,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteType {
    Direct,
    Indirect,
    Default,
    Host,
    Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: Protocol,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub rx_queue: u32,
    pub tx_queue: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionState {
    Established,
    Listening,
    Closed,
    TimeWait,
    CloseWait,
    LastAck,
    FinWait1,
    FinWait2,
    SynSent,
    SynReceived,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub chain: String,
    pub table: String,
    pub protocol: Option<Protocol>,
    pub source: Option<IpAddr>,
    pub destination: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub action: FirewallAction,
    pub interface: Option<String>,
    pub comment: Option<String>,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FirewallAction {
    Accept,
    Drop,
    Reject,
    Log,
    Return,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServer {
    pub address: IpAddr,
    pub port: u16,
    pub protocol: DnsProtocol,
    pub timeout_ms: u32,
    pub priority: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsProtocol {
    Udp,
    Tcp,
    DnsOverHttps,
    DnsOverTls,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub ip_address: IpAddr,
    pub mac_address: String,
    pub hostname: Option<String>,
    pub lease_time: u32,
    pub remaining_time: u32,
    pub server_address: IpAddr,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScanResult {
    pub target: IpAddr,
    pub ports: Vec<PortScanResult>,
    pub os_fingerprint: Option<String>,
    pub hostname: Option<String>,
    pub response_time_ms: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    ClosedFiltered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthUsage {
    pub interface: String,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub rx_packets_per_sec: f64,
    pub tx_packets_per_sec: f64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub hostname: String,
    pub domain: Option<String>,
    pub dns_servers: Vec<DnsServer>,
    pub search_domains: Vec<String>,
    pub ntp_servers: Vec<String>,
    pub interfaces: Vec<InterfaceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    pub ip_address: Option<IpAddr>,
    pub netmask: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub dhcp: bool,
    pub auto: bool,
}

// Validation implementations
impl Validate for NetworkInterface {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.name.is_empty() {
            return Err(ValidationError::RequiredField {
                field: "name".to_string(),
            });
        }

        if self.mac_address.is_empty() {
            return Err(ValidationError::RequiredField {
                field: "mac_address".to_string(),
            });
        }

        // Validate MAC address format
        if !is_valid_mac_address(&self.mac_address) {
            return Err(ValidationError::InvalidFormat {
                field: "mac_address".to_string(),
                message: "Invalid MAC address format".to_string(),
            });
        }

        Ok(())
    }
}

impl Validate for Route {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.interface.is_empty() {
            return Err(ValidationError::RequiredField {
                field: "interface".to_string(),
            });
        }

        Ok(())
    }
}

impl Validate for FirewallRule {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.id.is_empty() {
            return Err(ValidationError::RequiredField {
                field: "id".to_string(),
            });
        }

        if self.chain.is_empty() {
            return Err(ValidationError::RequiredField {
                field: "chain".to_string(),
            });
        }

        Ok(())
    }
}

// Utility functions
fn is_valid_mac_address(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return false;
    }

    for part in parts {
        if part.len() != 2 {
            return false;
        }
        if !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }

    true
}

pub fn format_ip_addr(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(ipv4) => ipv4.to_string(),
        IpAddr::V6(ipv6) => format!("[{}]", ipv6),
    }
}

pub fn format_bandwidth(bytes_per_sec: f64) -> String {
    const UNITS: &[&str] = &["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];

    if bytes_per_sec == 0.0 {
        return "0 B/s".to_string();
    }

    let mut value = bytes_per_sec;
    let mut unit_index = 0;

    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", value, UNITS[unit_index])
}

pub fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format".to_string());
    }

    let ip: IpAddr = parts[0].parse()
        .map_err(|_| "Invalid IP address".to_string())?;

    let prefix: u8 = parts[1].parse()
        .map_err(|_| "Invalid prefix length".to_string())?;

    match ip {
        IpAddr::V4(_) => {
            if prefix > 32 {
                return Err("IPv4 prefix must be <= 32".to_string());
            }
        }
        IpAddr::V6(_) => {
            if prefix > 128 {
                return Err("IPv6 prefix must be <= 128".to_string());
            }
        }
    }

    Ok((ip, prefix))
}