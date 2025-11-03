use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use anyhow::{Result, anyhow};


#[derive(Debug, Clone)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub device_type: String,
    pub status: String,
    pub connections: u32,
    pub ip_address: Option<String>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SshSession {
    pub id: Uuid,
    pub user: String,
    pub device_id: Option<String>,
    pub start_time: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub commands: Vec<String>,
}

#[derive(Debug)]
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<Uuid, SshSession>>>,
    devices: Arc<Mutex<HashMap<String, Device>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        let manager = Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            devices: Arc::new(Mutex::new(HashMap::new())),
        };
        
        // Initialize with sample devices
        manager.initialize_devices();
        manager
    }

    fn initialize_devices(&self) {
        let devices = vec![
            Device {
                id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                name: "core-router".to_string(),
                device_type: "Router".to_string(),
                status: "Online".to_string(),
                connections: 2,
                ip_address: Some("192.168.1.1".to_string()),
                last_seen: Utc::now(),
            },
            Device {
                id: "550e8400-e29b-41d4-a716-446655440001".to_string(),
                name: "edge-firewall".to_string(),
                device_type: "Firewall".to_string(),
                status: "Online".to_string(),
                connections: 1,
                ip_address: Some("192.168.1.254".to_string()),
                last_seen: Utc::now(),
            },
            Device {
                id: "550e8400-e29b-41d4-a716-446655440002".to_string(),
                name: "backup-server".to_string(),
                device_type: "Server".to_string(),
                status: "Maintenance".to_string(),
                connections: 0,
                ip_address: Some("192.168.1.100".to_string()),
                last_seen: Utc::now(),
            },
        ];

        let mut devices_map = self.devices.lock().unwrap();
        for device in devices {
            devices_map.insert(device.id.clone(), device);
        }
    }

    pub fn create_session(&self, user: String) -> Uuid {
        let session_id = Uuid::new_v4();
        let session = SshSession {
            id: session_id,
            user,
            device_id: None,
            start_time: Utc::now(),
            last_activity: Utc::now(),
            commands: Vec::new(),
        };

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id, session);
        session_id
    }

    pub fn get_session(&self, session_id: &Uuid) -> Option<SshSession> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(session_id).cloned()
    }

    pub fn update_session_activity(&self, session_id: &Uuid, command: String) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = Utc::now();
            session.commands.push(command);
        }
    }

    pub fn list_devices(&self) -> Vec<Device> {
        let devices = self.devices.lock().unwrap();
        devices.values().cloned().collect()
    }

    pub fn get_device(&self, device_id: &str) -> Option<Device> {
        let devices = self.devices.lock().unwrap();
        devices.get(device_id).cloned()
    }

    pub fn connect_to_device(&self, session_id: &Uuid, device_id: &str) -> Result<()> {
        let device = self.get_device(device_id)
            .ok_or_else(|| anyhow!("Device not found: {}", device_id))?;

        if device.status != "Online" {
            return Err(anyhow!("Device {} is not online", device.name));
        }

        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.device_id = Some(device_id.to_string());
        }

        Ok(())
    }

    pub fn disconnect_from_device(&self, session_id: &Uuid) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.device_id = None;
        }
        Ok(())
    }
}

pub struct SshShell {
    session_manager: SessionManager,
    session_id: Uuid,
    current_user: String,
    connected_device: Option<String>,
}

impl SshShell {
    pub fn new(user: String) -> Self {
        let session_manager = SessionManager::new();
        let session_id = session_manager.create_session(user.clone());
        
        Self {
            session_manager,
            session_id,
            current_user: user,
            connected_device: None,
        }
    }

    pub fn run(&mut self) -> Result<()> {
        self.print_welcome();

        loop {
            let prompt = if let Some(device) = &self.connected_device {
                format!("{}@{}:~$ ", self.current_user, device)
            } else {
                format!("{}@sge:/$ ", self.current_user)
            };

            print!("{}", prompt);
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();

            if input.is_empty() {
                continue;
            }

            self.session_manager.update_session_activity(&self.session_id, input.to_string());

            if let Err(e) = self.handle_command(input) {
                eprintln!("Error: {}", e);
            }

            if self.should_exit() {
                break;
            }
        }

        println!("Disconnected from Sky Genesis Enterprise");
        Ok(())
    }

    fn print_welcome(&self) {
        println!("Sky Genesis Enterprise - Network Administration Console");
        println!("========================================================");
        println!();
        println!("Welcome to the SGE Interactive Shell!");
        println!("Type 'help' for available commands or 'exit' to disconnect.");
        println!();
    }

    fn handle_command(&mut self, command: &str) -> Result<()> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(());
        }

        match parts[0] {
            "help" | "?" => self.show_help(),
            "exit" | "quit" => self.handle_exit(),
            "pwd" => self.show_current_directory(),
            "whoami" => self.show_current_user(),
            "env" => self.show_environment(),
            "history" => self.show_history(),
            "session" => self.show_session_info(),
            "clear" => self.clear_screen(),
            "devices" => self.handle_devices_command(&parts[1..])?,
            "connect" => self.handle_connect_command(&parts[1..])?,
            "disconnect" => self.handle_disconnect_command(&parts[1..])?,
            "status" => self.show_system_status(),
            "ifconfig" => self.show_network_interfaces(),
            "route" => self.show_routing_table(),
            "ping" => self.handle_ping_command(&parts[1..])?,
            "traceroute" => self.handle_traceroute_command(&parts[1..])?,
            _ => {
                if self.connected_device.is_some() {
                    self.execute_device_command(command)?;
                } else {
                    eprintln!("Unknown command: {}. Type 'help' for available commands.", parts[0]);
                }
            }
        }

        Ok(())
    }

    fn show_help(&self) {
        println!("Available Commands:");
        println!("==================");
        println!();
        println!("Built-in Commands:");
        println!("  help, ?          - Show this help message");
        println!("  exit, quit        - Exit the shell");
        println!("  pwd               - Show current directory");
        println!("  whoami            - Show current user");
        println!("  env               - Show environment variables");
        println!("  history           - Show command history");
        println!("  session           - Show session information");
        println!("  clear             - Clear the screen");
        println!();
        println!("Device Management:");
        println!("  devices list      - List all managed devices");
        println!("  devices show <id> - Show device details");
        println!("  devices status    - Show device status overview");
        println!("  connect <device>  - Connect to a device");
        println!("  disconnect        - Disconnect from current device");
        println!();
        println!("Network Administration:");
        println!("  status            - Show system status");
        println!("  ifconfig          - Show network interfaces");
        println!("  route             - Show routing table");
        println!("  ping <host>       - Ping a host");
        println!("  traceroute <host> - Trace route to host");
        println!();
    }

    fn handle_exit(&mut self) {
        if self.connected_device.is_some() {
            println!("Disconnected from device '{}' after 5 minutes", self.connected_device.as_ref().unwrap());
            self.connected_device = None;
        }
    }

    fn should_exit(&self) -> bool {
        self.connected_device.is_none()
    }

    fn show_current_directory(&self) {
        if self.connected_device.is_some() {
            println!("/home/admin");
        } else {
            println!("/");
        }
    }

    fn show_current_user(&self) {
        println!("{}", self.current_user);
    }

    fn show_environment(&self) {
        println!("USER={}", self.current_user);
        println!("HOME=/home/{}", self.current_user);
        println!("SHELL=/bin/bash");
        println!("TERM=xterm-256color");
        println!("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    }

    fn show_history(&self) {
        if let Some(session) = self.session_manager.get_session(&self.session_id) {
            println!("Command History:");
            println!("===============");
            for (i, cmd) in session.commands.iter().enumerate() {
                println!("{}  {}", i + 1, cmd);
            }
        }
    }

    fn show_session_info(&self) {
        if let Some(session) = self.session_manager.get_session(&self.session_id) {
            println!("Session Information:");
            println!("==================");
            println!("Session ID: {}", session.id);
            println!("User: {}", session.user);
            println!("Start Time: {}", session.start_time.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("Last Activity: {}", session.last_activity.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("Commands Executed: {}", session.commands.len());
            if let Some(device_id) = &session.device_id {
                if let Some(device) = self.session_manager.get_device(device_id) {
                    println!("Connected Device: {} ({})", device.name, device.device_type);
                }
            }
        }
    }

    fn clear_screen(&self) {
        print!("\x1B[2J\x1B[1;1H");
        io::stdout().flush().unwrap();
    }

    fn handle_devices_command(&self, args: &[&str]) -> Result<()> {
        if args.is_empty() || args[0] == "list" {
            self.list_devices(args);
        } else if args[0] == "show" {
            if args.len() < 2 {
                return Err(anyhow!("Usage: devices show <device_id>"));
            }
            self.show_device(args[1])?;
        } else if args[0] == "status" {
            self.show_devices_status();
        } else {
            return Err(anyhow!("Unknown devices subcommand: {}", args[0]));
        }
        Ok(())
    }

    fn list_devices(&self, args: &[&str]) {
        let devices = self.session_manager.list_devices();
        
        println!("Managed Devices:");
        println!("===============");
        println!("{:<36} {:<18} {:<10} {:<12} {:<12}", "ID", "Name", "Type", "Status", "Connections");
        println!("{:<36} {:<18} {:<10} {:<12} {:<12}", "--", "----", "----", "------", "-----------");

        for device in devices {
            // Apply filters if provided
            if args.len() > 1 {
                let filter = args[1].to_lowercase();
                if device.status.to_lowercase() != filter && device.device_type.to_lowercase() != filter {
                    continue;
                }
            }

            println!("{:<36} {:<18} {:<10} {:<12} {:<12}", 
                device.id, device.name, device.device_type, device.status, format!("{} active", device.connections));
        }
    }

    fn show_device(&self, device_id: &str) -> Result<()> {
        let device = self.session_manager.get_device(device_id)
            .ok_or_else(|| anyhow!("Device not found: {}", device_id))?;

        println!("Device Details:");
        println!("===============");
        println!("ID: {}", device.id);
        println!("Name: {}", device.name);
        println!("Type: {}", device.device_type);
        println!("Status: {}", device.status);
        println!("Active Connections: {}", device.connections);
        if let Some(ip) = device.ip_address {
            println!("IP Address: {}", ip);
        }
        println!("Last Seen: {}", device.last_seen.format("%Y-%m-%d %H:%M:%S UTC"));
        Ok(())
    }

    fn show_devices_status(&self) {
        let devices = self.session_manager.list_devices();
        let total_devices = devices.len();
        let online_devices = devices.iter().filter(|d| d.status == "Online").count();
        let total_connections: u32 = devices.iter().map(|d| d.connections).sum();

        println!("Device Status Overview:");
        println!("======================");
        println!("Total Devices: {}", total_devices);
        println!("Online Devices: {}", online_devices);
        println!("Offline Devices: {}", total_devices - online_devices);
        println!("Total Active Connections: {}", total_connections);
        println!();

        let devices_by_type = {
            let mut map = std::collections::HashMap::new();
            for device in &devices {
                *map.entry(device.device_type.clone()).or_insert(0) += 1;
            }
            map
        };

        println!("Devices by Type:");
        for (device_type, count) in devices_by_type {
            println!("  {}: {}", device_type, count);
        }
    }

    fn handle_connect_command(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Usage: connect <device_id>"));
        }

        let device_identifier = args[0];
        
        // Try to find device by name or ID
        let devices = self.session_manager.list_devices();
        let device = devices.iter()
            .find(|d| d.id == device_identifier || d.name == device_identifier)
            .cloned()
            .ok_or_else(|| anyhow!("Device not found: {}", device_identifier))?;

        println!("Establishing connection to device {}...", device.name);
        println!("[SSH] Authenticating with target device...");
        
        // Simulate connection delay
        std::thread::sleep(std::time::Duration::from_millis(1000));
        
        self.session_manager.connect_to_device(&self.session_id, &device.id)?;
        self.connected_device = Some(device.name.clone());
        
        println!("[SSH] Connection established successfully!");
        println!();
        println!("You are now connected to device '{}'.", device.name);
        println!("Type 'exit' or press Ctrl+D to disconnect.");
        println!();

        Ok(())
    }

    fn handle_disconnect_command(&mut self, _args: &[&str]) -> Result<()> {
        if let Some(device) = &self.connected_device {
            self.session_manager.disconnect_from_device(&self.session_id)?;
            println!("Disconnected from device '{}'", device);
            self.connected_device = None;
        } else {
            println!("Not connected to any device");
        }
        Ok(())
    }

    fn execute_device_command(&self, command: &str) -> Result<()> {
        // Simulate executing command on connected device
        println!("Executing on device: {}", command);
        
        // Simulate some common device commands
        if command.contains("show running-config") {
            println!("Building configuration...");
            println!();
            println!("Current configuration : 1234 bytes");
            println!("!");
            println!("version 15.1");
            println!("service timestamps debug datetime msec");
            println!("service timestamps log datetime msec");
            println!("!");
            println!("hostname {}", self.connected_device.as_ref().unwrap());
            println!("!");
            println!("interface GigabitEthernet0/0");
            println!(" ip address 192.168.1.1 255.255.255.0");
            println!("!");
            println!("end");
        } else if command.contains("show interfaces") {
            println!("Interface Status:");
            println!("GigabitEthernet0/0 is up, line protocol is up");
            println!("  Internet Address is 192.168.1.1/24");
            println!("GigabitEthernet0/1 is up, line protocol is up");
            println!("  Internet Address is 10.0.0.1/24");
        } else if command.contains("show version") {
            println!("Cisco IOS Software, 7200 Software (C7200-ADVENTERPRISEK9-M), Version 15.1(4)M6");
            println!("Copyright (c) 1986-2014 by Cisco Systems, Inc.");
        } else {
            println!("Command executed successfully");
        }
        
        Ok(())
    }

    fn show_system_status(&self) {
        println!("System Status:");
        println!("=============");
        println!();
        
        // Session info
        if let Some(session) = self.session_manager.get_session(&self.session_id) {
            println!("Session Information:");
            println!("  User: {}", session.user);
            println!("  Session Duration: {}", 
                (Utc::now() - session.start_time).num_minutes());
            println!("  Commands Executed: {}", session.commands.len());
        }
        println!();
        
        // Network status
        println!("Network Status:");
        println!("  SSH Service: Running");
        println!("  Management Interface: Up");
        println!("  Active Connections: {}", 
            self.session_manager.list_devices().iter().map(|d| d.connections).sum::<u32>());
        println!();
        
        // Device summary
        let devices = self.session_manager.list_devices();
        let online_count = devices.iter().filter(|d| d.status == "Online").count();
        println!("Device Summary:");
        println!("  Total Devices: {}", devices.len());
        println!("  Online: {}", online_count);
        println!("  Offline: {}", devices.len() - online_count);
    }

    fn show_network_interfaces(&self) {
        println!("Network Interfaces:");
        println!("==================");
        println!("eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500");
        println!("    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0");
        println!("    RX: packets 1234567, bytes 987654321");
        println!("    TX: packets 987654, bytes 123456789");
        println!();
        println!("lo: <LOOPBACK,UP,LOWER_UP> mtu 65536");
        println!("    inet 127.0.0.1/8 scope host lo");
        println!("    RX: packets 45678, bytes 3456789");
        println!("    TX: packets 45678, bytes 3456789");
    }

    fn show_routing_table(&self) {
        println!("Routing Table:");
        println!("=============");
        println!("Destination     Gateway         Genmask         Flags Metric Ref    Use Iface");
        println!("0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 eth0");
        println!("192.168.1.0     0.0.0.0         255.255.255.0   U     0      0        0 eth0");
        println!("127.0.0.0       0.0.0.0         255.0.0.0       U     0      0        0 lo");
    }

    fn handle_ping_command(&self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Usage: ping <host>"));
        }

        let host = args[0];
        println!("PING {} (192.168.1.1) 56(84) bytes of data.", host);
        
        for i in 1..=4 {
            println!("64 bytes from {} (192.168.1.1): icmp_seq={} ttl=64 time=1.2{} ms", 
                host, i, if i == 3 { "3" } else { "1" });
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        
        println!("--- {} ping statistics ---", host);
        println!("4 packets transmitted, 4 received, 0% packet loss, time 3002ms");
        println!("rtt min/avg/max/mdev = 1.123/1.456/1.789/0.234 ms");
        
        Ok(())
    }

    fn handle_traceroute_command(&self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Usage: traceroute <host>"));
        }

        let host = args[0];
        println!("traceroute to {} (192.168.1.1), 30 hops max, 60 byte packets", host);
        
        let hops = vec![
            ("192.168.1.1", "1.123 ms"),
            ("10.0.0.1", "2.456 ms"),
            ("203.0.113.1", "15.789 ms"),
            ("198.51.100.1", "18.012 ms"),
            (host, "20.345 ms"),
        ];
        
        for (i, (addr, time)) in hops.iter().enumerate() {
            println!("  {}  {} ({})  {}", i + 1, addr, addr, time);
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        
        Ok(())
    }
}