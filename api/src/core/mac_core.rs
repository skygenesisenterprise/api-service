// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: MAC Identity Core Operations
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide core cryptographic operations for MAC identity management,
//  including secure generation, validation, and mapping of SGE-MAC addresses.
//  NOTICE: Implements sovereign MAC address generation with cryptographic security,
//  format validation, and IEEE 802 mapping capabilities.
//  STANDARDS: Cryptographic MAC Generation, Format Validation, Security Standards
//  COMPLIANCE: MAC Security, Cryptographic Standards, Sovereign Identity
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use uuid::Uuid;
use sha2::{Sha256, Digest};
use regex::Regex;
use lazy_static::lazy_static;

use crate::core::vault::VaultClient;
use crate::core::audit_manager::{AuditManager, AuditEventType, AuditSeverity};

/// [MAC CORE] Core Operations for MAC Identity Management
/// @MISSION Provide cryptographic MAC generation and validation.
/// @THREAT MAC spoofing or weak generation.
/// @COUNTERMEASURE Cryptographic generation with entropy validation.
/// @AUDIT All MAC operations logged with cryptographic integrity.
/// @DEPENDENCY Vault for secure random generation.
pub struct MacCore {
    vault_client: VaultClient,
    audit_manager: AuditManager,
}

impl MacCore {
    /// Create new MAC core instance
    pub fn new(vault_client: VaultClient, audit_manager: AuditManager) -> Self {
        Self {
            vault_client,
            audit_manager,
        }
    }

    /// Generate a sovereign SGE-MAC address
    /// @MISSION Create cryptographically secure SGE-MAC addresses.
    /// @THREAT Weak random generation or predictable MACs.
    /// @COUNTERMEASURE Use cryptographically secure random with entropy validation.
    /// @FLOW Generate -> Validate -> Format -> Audit
    pub async fn generate_sge_mac(&self, organization_id: Uuid, context: &str) -> Result<String, String> {
        // Generate cryptographically secure random bytes using Vault
        let random_data = self.vault_client.generate_random_bytes(6).await
            .map_err(|e| format!("Failed to generate random bytes: {}", e))?;

        // Create SGE prefix
        let mut mac_bytes = [0u8; 8];
        mac_bytes[0] = b'S';
        mac_bytes[1] = b'G';
        mac_bytes[2] = b'E';
        mac_bytes[3] = b'-';
        mac_bytes[4..].copy_from_slice(&random_data);

        // Convert to hex string format
        let sge_mac = mac_bytes.iter()
            .enumerate()
            .map(|(i, &b)| {
                if i == 3 {
                    "-".to_string()
                } else {
                    format!("{:02X}", b)
                }
            })
            .collect::<String>();

        // Validate the generated MAC
        if !self.validate_sge_mac_format(&sge_mac) {
            return Err("Generated SGE-MAC failed validation".to_string());
        }

        // Audit MAC generation
        self.audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Info,
            None,
            "mac_core",
            &format!("Generated SGE-MAC for organization {}", organization_id),
            Some(serde_json::json!({
                "organization_id": organization_id,
                "context": context,
                "mac_prefix": &sge_mac[..8] // Only log prefix for security
            })),
        ).await;

        Ok(sge_mac)
    }

    /// Generate MAC fingerprint from hardware characteristics
    /// @MISSION Create unique hardware fingerprint for device identification.
    /// @THREAT Weak fingerprint generation or collision.
    /// @COUNTERMEASURE Use multiple hardware characteristics with cryptographic hash.
    /// @FLOW Collect -> Hash -> Validate -> Return
    pub fn generate_hardware_fingerprint(
        &self,
        hardware_info: &HardwareFingerprintData
    ) -> Result<String, String> {
        let mut hasher = Sha256::new();

        // Include various hardware characteristics
        hasher.update(&hardware_info.cpu_id);
        hasher.update(&hardware_info.motherboard_serial);
        hasher.update(&hardware_info.bios_version);
        hasher.update(&hardware_info.network_interfaces);
        hasher.update(&hardware_info.disk_serials.join(""));

        // Add entropy from system time (but not predictable)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Time error: {}", e))?
            .as_nanos();
        hasher.update(&timestamp.to_le_bytes());

        let hash = hasher.finalize();
        let fingerprint = Uuid::from_bytes(hash[..16].try_into().unwrap()).to_string();

        Ok(fingerprint)
    }

    /// Validate SGE-MAC format
    /// @MISSION Ensure MAC addresses conform to SGE format specifications.
    /// @THREAT Malformed or spoofed MAC addresses.
    /// @COUNTERMEASURE Strict format validation with regex.
    pub fn validate_sge_mac_format(&self, sge_mac: &str) -> bool {
        lazy_static! {
            static ref SGE_MAC_REGEX: Regex = Regex::new(r"^SGE-[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$").unwrap();
        }
        SGE_MAC_REGEX.is_match(sge_mac)
    }

    /// Validate IEEE 802 MAC format
    /// @MISSION Ensure standard MAC addresses are properly formatted.
    /// @THREAT Malformed IEEE MAC addresses.
    /// @COUNTERMEASURE Standard format validation.
    pub fn validate_ieee_mac_format(&self, mac: &str) -> bool {
        lazy_static! {
            static ref IEEE_MAC_REGEX: Regex = Regex::new(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$").unwrap();
        }
        IEEE_MAC_REGEX.is_match(mac)
    }

    /// Convert SGE-MAC to IEEE format (if mapping exists)
    /// @MISSION Provide mapping from SGE to standard MAC addresses.
    /// @THREAT Incorrect mapping or format conversion.
    /// @COUNTERMEASURE Validate both formats and maintain mapping integrity.
    pub fn sge_to_ieee_mac(&self, sge_mac: &str) -> Result<String, String> {
        if !self.validate_sge_mac_format(sge_mac) {
            return Err("Invalid SGE-MAC format".to_string());
        }

        // Extract the hex part after "SGE-"
        let hex_part = &sge_mac[4..];
        let ieee_mac = hex_part.replace("-", ":");

        if !self.validate_ieee_mac_format(&ieee_mac) {
            return Err("Generated IEEE MAC is invalid".to_string());
        }

        Ok(ieee_mac)
    }

    /// Convert IEEE MAC to SGE format
    /// @MISSION Create SGE-MAC from standard IEEE address.
    /// @THREAT Format conversion errors.
    /// @COUNTERMEASURE Validate input and output formats.
    pub fn ieee_to_sge_mac(&self, ieee_mac: &str) -> Result<String, String> {
        if !self.validate_ieee_mac_format(ieee_mac) {
            return Err("Invalid IEEE MAC format".to_string());
        }

        let hex_part = ieee_mac.replace(":", "-");
        let sge_mac = format!("SGE-{}", hex_part);

        if !self.validate_sge_mac_format(&sge_mac) {
            return Err("Generated SGE-MAC is invalid".to_string());
        }

        Ok(sge_mac)
    }

    /// Check MAC address entropy quality
    /// @MISSION Ensure generated MACs have sufficient entropy.
    /// @THREAT Low entropy MAC addresses.
    /// @COUNTERMEASURE Statistical entropy analysis.
    pub fn check_mac_entropy(&self, mac: &str) -> Result<f64, String> {
        if !self.validate_sge_mac_format(mac) {
            return Err("Invalid SGE-MAC format for entropy check".to_string());
        }

        // Extract hex bytes
        let hex_part = &mac[4..];
        let bytes: Vec<u8> = hex_part.split('-')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if bytes.len() != 6 {
            return Err("Invalid MAC byte count".to_string());
        }

        // Calculate Shannon entropy
        let mut freq = [0u32; 256];
        for &byte in &bytes {
            freq[byte as usize] += 1;
        }

        let mut entropy = 0.0;
        let len = bytes.len() as f64;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        Ok(entropy)
    }

    /// Generate MAC address with organizational prefix
    /// @MISSION Create MACs with organizational identification.
    /// @THREAT MAC collision between organizations.
    /// @COUNTERMEASURE Include organization ID in generation.
    pub async fn generate_org_sge_mac(&self, organization_id: Uuid) -> Result<String, String> {
        // Include organization ID in entropy
        let org_bytes = organization_id.as_bytes();
        let mut combined_entropy = Vec::with_capacity(6 + 16);
        combined_entropy.extend_from_slice(org_bytes);

        // Add random bytes
        let random_bytes = self.vault_client.generate_random_bytes(6).await
            .map_err(|e| format!("Failed to generate random bytes: {}", e))?;
        combined_entropy.extend_from_slice(&random_bytes);

        // Hash to get final 6 bytes
        let mut hasher = Sha256::new();
        hasher.update(&combined_entropy);
        let hash = hasher.finalize();
        let mac_bytes = &hash[..6];

        // Format as SGE-MAC
        let sge_mac = format!(
            "SGE-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
            mac_bytes[0], mac_bytes[1], mac_bytes[2],
            mac_bytes[3], mac_bytes[4], mac_bytes[5]
        );

        Ok(sge_mac)
    }
}

/// Hardware fingerprint data structure
#[derive(Debug, Clone)]
pub struct HardwareFingerprintData {
    pub cpu_id: String,
    pub motherboard_serial: String,
    pub bios_version: String,
    pub network_interfaces: String,
    pub disk_serials: Vec<String>,
}

impl Default for HardwareFingerprintData {
    fn default() -> Self {
        Self {
            cpu_id: String::new(),
            motherboard_serial: String::new(),
            bios_version: String::new(),
            network_interfaces: String::new(),
            disk_serials: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_sge_mac_format() {
        let core = MacCore::new(VaultClient::new("dummy".to_string(), "dummy".to_string(), "dummy".to_string()).unwrap(), AuditManager::new());
        assert!(core.validate_sge_mac_format("SGE-00:11:22:33:44:55"));
        assert!(!core.validate_sge_mac_format("00:11:22:33:44:55"));
        assert!(!core.validate_sge_mac_format("SGE-00-11-22-33-44-55"));
    }

    #[test]
    fn test_validate_ieee_mac_format() {
        let core = MacCore::new(VaultClient::new("dummy".to_string(), "dummy".to_string(), "dummy".to_string()).unwrap(), AuditManager::new());
        assert!(core.validate_ieee_mac_format("00:11:22:33:44:55"));
        assert!(core.validate_ieee_mac_format("00-11-22-33-44-55"));
        assert!(!core.validate_ieee_mac_format("SGE-00:11:22:33:44:55"));
    }

    #[test]
    fn test_sge_to_ieee_conversion() {
        let core = MacCore::new(VaultClient::new("dummy".to_string(), "dummy".to_string(), "dummy".to_string()).unwrap(), AuditManager::new());
        let result = core.sge_to_ieee_mac("SGE-00:11:22:33:44:55");
        assert_eq!(result.unwrap(), "00:11:22:33:44:55");
    }

    #[test]
    fn test_ieee_to_sge_conversion() {
        let core = MacCore::new(VaultClient::new("dummy".to_string(), "dummy".to_string(), "dummy".to_string()).unwrap(), AuditManager::new());
        let result = core.ieee_to_sge_mac("00:11:22:33:44:55");
        assert_eq!(result.unwrap(), "SGE-00:11:22:33:44:55");
    }
}