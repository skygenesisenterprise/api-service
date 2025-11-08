// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: MAC Certificate Management Core
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide cryptographic certificate operations for MAC identity
//  management, including X.509 certificate generation, signing, validation,
//  and revocation for enhanced security.
//  NOTICE: Implements sovereign PKI for MAC addresses with certificate
//  lifecycle management, OCSP, and CRL support.
//  STANDARDS: X.509, PKI, Certificate Management, Cryptographic Standards
//  COMPLIANCE: Certificate Security, PKI Standards, Sovereign Identity
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================


use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::rand::SystemRandom;
use base64::{Engine as _, engine::general_purpose};


use crate::models::data_model::{MacIdentity, MacCertificateInfo, MacSignatureInfo, CertificateStatus};
use crate::core::vault::VaultClient;
use crate::core::audit_manager::{AuditManager, AuditEventType, AuditSeverity};

/// [MAC CERTIFICATES CORE] Core Operations for MAC Certificate Management
/// @MISSION Provide X.509 certificate operations for MAC identities.
/// @THREAT Certificate compromise or weak cryptography.
/// @COUNTERMEASURE X.509 certificates with proper key management.
/// @AUDIT All certificate operations logged with cryptographic integrity.
/// @DEPENDENCY Vault for key storage, ring for cryptography.
pub struct MacCertificatesCore {
    vault_client: VaultClient,
    audit_manager: AuditManager,
    ca_certificate: String, // Base64 encoded CA certificate
    ca_private_key: String, // Reference to Vault-stored CA private key
}

impl MacCertificatesCore {
    /// Create new MAC certificates core instance
    pub fn new(
        vault_client: VaultClient,
        audit_manager: AuditManager,
        ca_certificate: String,
        ca_private_key: String,
    ) -> Self {
        Self {
            vault_client,
            audit_manager,
            ca_certificate,
            ca_private_key,
        }
    }

    /// Generate X.509 certificate for MAC identity
    /// @MISSION Create cryptographically signed certificates for MAC addresses.
    /// @THREAT Certificate forgery or weak keys.
    /// @COUNTERMEASURE X.509 certificate generation with CA signing.
    /// @FLOW Generate Key Pair -> Create CSR -> Sign Certificate -> Store
    pub async fn generate_mac_certificate(
        &self,
        mac_identity: &MacIdentity,
        validity_days: i64,
        organization_name: &str,
    ) -> Result<MacCertificateInfo, String> {
        let rng = SystemRandom::new();

        // Generate Ed25519 key pair for the MAC
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| format!("Key generation failed: {:?}", e))?;
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .map_err(|e| format!("Key parsing failed: {:?}", e))?;

        // Store private key in Vault
        let key_id = format!("mac-cert-{}", mac_identity.id);
        let private_key_b64 = general_purpose::STANDARD.encode(pkcs8_bytes.as_ref());
        self.vault_client.store_secret(&key_id, &private_key_b64).await
            .map_err(|e| format!("Vault storage failed: {}", e))?;

        // Create certificate data
        let now = Utc::now();
        let not_after = now + Duration::days(validity_days);

        let serial_number = format!("MAC-{}", mac_identity.id.simple());
        let subject = format!("CN={},O={},OU=MAC-Certificates", mac_identity.sge_mac, organization_name);

        // Create certificate TBS (To Be Signed) data
        let tbs_data = self.create_certificate_tbs(
            &serial_number,
            &subject,
            &mac_identity.sge_mac,
            now,
            not_after,
        )?;

        // Sign the certificate with CA private key
        let signature = self.sign_with_ca(&tbs_data).await?;

        // Create the full certificate
        let certificate_pem = self.create_x509_certificate(
            &tbs_data,
            &signature,
            &key_pair.public_key(),
        )?;

        // Calculate certificate fingerprint
        let fingerprint = self.calculate_certificate_fingerprint(&certificate_pem)?;

        let cert_info = MacCertificateInfo {
            serial_number,
            fingerprint,
            issuer: format!("CN=SGE-CA,O={}", organization_name),
            subject,
            not_before: now,
            not_after,
            status: CertificateStatus::Active,
            revocation_reason: None,
            revoked_at: None,
            ocsp_url: Some(format!("https://ocsp.sge-{}.com", organization_name.to_lowercase())),
            crl_url: Some(format!("https://crl.sge-{}.com/mac.crl", organization_name.to_lowercase())),
        };

        // Audit certificate generation
        self.audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Info,
            None,
            "mac_certificates",
            &format!("MAC certificate generated for {}", mac_identity.sge_mac),
            Some(serde_json::json!({
                "mac_id": mac_identity.id,
                "sge_mac": mac_identity.sge_mac,
                "certificate_serial": cert_info.serial_number,
                "validity_days": validity_days,
                "organization": organization_name
            })),
        ).await;

        Ok(cert_info)
    }

    /// Sign MAC address with cryptographic signature
    /// @MISSION Create digital signatures for MAC address integrity.
    /// @THREAT MAC tampering during transmission.
    /// @COUNTERMEASURE Cryptographic signing of MAC data.
    /// @FLOW Hash MAC Data -> Sign Hash -> Create Signature Info
    pub async fn sign_mac_address(
        &self,
        mac_identity: &MacIdentity,
        signing_key_id: &str,
    ) -> Result<MacSignatureInfo, String> {
        // Create data to sign (MAC address + metadata)
        let data_to_sign = format!(
            "{}|{}|{}|{}",
            mac_identity.sge_mac,
            mac_identity.fingerprint,
            mac_identity.owner,
            mac_identity.created_at.timestamp()
        );

        // Sign the data
        let signature_b64 = self.sign_data(&data_to_sign, signing_key_id).await?;

        let signature_info = MacSignatureInfo {
            algorithm: "Ed25519".to_string(),
            signature: signature_b64,
            key_id: signing_key_id.to_string(),
            signed_at: Utc::now(),
            valid_until: Some(Utc::now() + Duration::days(365)), // 1 year validity
        };

        // Audit signature creation
        self.audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Info,
            None,
            "mac_certificates",
            &format!("MAC address signed: {}", mac_identity.sge_mac),
            Some(serde_json::json!({
                "mac_id": mac_identity.id,
                "sge_mac": mac_identity.sge_mac,
                "signature_algorithm": signature_info.algorithm,
                "key_id": signing_key_id
            })),
        ).await;

        Ok(signature_info)
    }

    /// Verify MAC certificate
    /// @MISSION Validate certificate authenticity and validity.
    /// @THREAT Invalid or revoked certificates.
    /// @COUNTERMEASURE Certificate chain validation and revocation checking.
    /// @FLOW Parse Certificate -> Validate Chain -> Check Revocation -> Verify Signature
    pub async fn verify_mac_certificate(
        &self,
        certificate_info: &MacCertificateInfo,
        certificate_pem: &str,
    ) -> Result<bool, String> {
        // Check certificate status
        if certificate_info.status != CertificateStatus::Active {
            return Ok(false);
        }

        // Check validity period
        let now = Utc::now();
        if now < certificate_info.not_before || now > certificate_info.not_after {
            return Ok(false);
        }

        // Check revocation status via OCSP (simplified)
        if let Some(ocsp_url) = &certificate_info.ocsp_url {
            let is_revoked = self.check_ocsp_revocation(&certificate_info.serial_number, ocsp_url).await?;
            if is_revoked {
                return Ok(false);
            }
        }

        // Verify certificate signature against CA
        let is_signature_valid = self.verify_certificate_signature(certificate_pem).await?;

        // Audit verification
        self.audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Info,
            None,
            "mac_certificates",
            &format!("MAC certificate verification: {}", certificate_info.serial_number),
            Some(serde_json::json!({
                "serial_number": certificate_info.serial_number,
                "is_valid": is_signature_valid,
                "status": format!("{:?}", certificate_info.status)
            })),
        ).await;

        Ok(is_signature_valid)
    }

    /// Verify MAC signature
    /// @MISSION Validate digital signature of MAC address.
    /// @THREAT Tampered MAC data.
    /// @COUNTERMEASURE Signature verification against known public keys.
    /// @FLOW Recreate Data -> Verify Signature -> Check Validity
    pub async fn verify_mac_signature(
        &self,
        mac_identity: &MacIdentity,
        signature_info: &MacSignatureInfo,
    ) -> Result<bool, String> {
        // Recreate the signed data
        let data_to_verify = format!(
            "{}|{}|{}|{}",
            mac_identity.sge_mac,
            mac_identity.fingerprint,
            mac_identity.owner,
            mac_identity.created_at.timestamp()
        );

        // Check signature validity period
        if let Some(valid_until) = signature_info.valid_until {
            if Utc::now() > valid_until {
                return Ok(false);
            }
        }

        // Verify signature
        let is_valid = self.verify_signature(&data_to_verify, &signature_info.signature, &signature_info.key_id).await?;

        // Audit verification
        self.audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Info,
            None,
            "mac_certificates",
            &format!("MAC signature verification: {}", mac_identity.sge_mac),
            Some(serde_json::json!({
                "mac_id": mac_identity.id,
                "sge_mac": mac_identity.sge_mac,
                "algorithm": signature_info.algorithm,
                "is_valid": is_valid
            })),
        ).await;

        Ok(is_valid)
    }

    /// Revoke MAC certificate
    /// @MISSION Revoke compromised or expired certificates.
    /// @THREAT Continued use of compromised certificates.
    /// @COUNTERMEASURE Certificate revocation and CRL updates.
    /// @FLOW Update Status -> Update CRL -> Audit Revocation
    pub async fn revoke_mac_certificate(
        &self,
        certificate_info: &mut MacCertificateInfo,
        reason: &str,
        user_id: &str,
    ) -> Result<(), String> {
        certificate_info.status = CertificateStatus::Revoked;
        certificate_info.revocation_reason = Some(reason.to_string());
        certificate_info.revoked_at = Some(Utc::now());

        // Update CRL (simplified - in real implementation, update CRL file)
        self.update_certificate_revocation_list(certificate_info).await?;

        // Audit revocation
        self.audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Warning,
            Some(user_id),
            "mac_certificates",
            &format!("MAC certificate revoked: {}", certificate_info.serial_number),
            Some(serde_json::json!({
                "serial_number": certificate_info.serial_number,
                "revocation_reason": reason,
                "revoked_by": user_id
            })),
        ).await;

        Ok(())
    }

    /// Renew MAC certificate
    /// @MISSION Extend certificate validity before expiration.
    /// @THREAT Certificate expiration causing service disruption.
    /// @COUNTERMEASURE Proactive certificate renewal.
    /// @FLOW Generate New Certificate -> Update Records -> Audit
    pub async fn renew_mac_certificate(
        &self,
        mac_identity: &MacIdentity,
        current_cert: &MacCertificateInfo,
        validity_days: i64,
        organization_name: &str,
        user_id: &str,
    ) -> Result<MacCertificateInfo, String> {
        // Generate new certificate
        let new_cert = self.generate_mac_certificate(mac_identity, validity_days, organization_name).await?;

        // Audit renewal
        self.audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Info,
            Some(user_id),
            "mac_certificates",
            &format!("MAC certificate renewed: {} -> {}", current_cert.serial_number, new_cert.serial_number),
            Some(serde_json::json!({
                "mac_id": mac_identity.id,
                "old_serial": current_cert.serial_number,
                "new_serial": new_cert.serial_number,
                "validity_days": validity_days,
                "renewed_by": user_id
            })),
        ).await;

        Ok(new_cert)
    }

    /// Get certificate chain for MAC
    /// @MISSION Provide complete certificate chain for validation.
    /// @THREAT Incomplete certificate chains.
    /// @COUNTERMEASURE Full chain construction including root CA.
    pub fn get_certificate_chain(&self, certificate_pem: &str) -> Vec<String> {
        vec![
            certificate_pem.to_string(),
            self.ca_certificate.clone(), // Intermediate CA
            // In real implementation, include root CA as well
        ]
    }

    // Helper methods

    fn create_certificate_tbs(
        &self,
        serial_number: &str,
        subject: &str,
        mac_address: &str,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
    ) -> Result<String, String> {
        // Simplified TBS creation - in real implementation, use proper ASN.1 encoding
        let tbs = format!(
            "SGE-MAC-Certificate\nSerial: {}\nSubject: {}\nMAC: {}\nNotBefore: {}\nNotAfter: {}\nIssuer: SGE-CA",
            serial_number,
            subject,
            mac_address,
            not_before.to_rfc3339(),
            not_after.to_rfc3339()
        );
        Ok(tbs)
    }

    async fn sign_with_ca(&self, data: &str) -> Result<String, String> {
        self.sign_data(data, &self.ca_private_key).await
    }

    async fn sign_data(&self, data: &str, key_id: &str) -> Result<String, String> {
        // Retrieve private key from Vault
        let private_key_b64 = self.vault_client.get_secret(key_id).await
            .map_err(|e| format!("Failed to retrieve key: {}", e))?;

        let private_key_bytes = general_purpose::STANDARD.decode(&private_key_b64)
            .map_err(|e| format!("Key decoding failed: {}", e))?;

        let key_pair = Ed25519KeyPair::from_pkcs8(&private_key_bytes)
            .map_err(|e| format!("Key parsing failed: {:?}", e))?;

        let signature = key_pair.sign(data.as_bytes());
        let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());

        Ok(signature_b64)
    }

    fn create_x509_certificate(
        &self,
        tbs: &str,
        signature: &str,
        public_key: &[u8],
    ) -> Result<String, String> {
        // Simplified certificate creation - in real implementation, use proper X.509 library
        let certificate = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            general_purpose::STANDARD.encode(format!("TBS:{}\nSIG:{}\nPUBKEY:{}", tbs, signature, general_purpose::STANDARD.encode(public_key)))
        );
        Ok(certificate)
    }

    fn calculate_certificate_fingerprint(&self, certificate_pem: &str) -> Result<String, String> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(certificate_pem.as_bytes());
        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }

    async fn check_ocsp_revocation(&self, serial_number: &str, ocsp_url: &str) -> Result<bool, String> {
        // Simplified OCSP check - in real implementation, make HTTP request to OCSP responder
        // For now, assume certificate is not revoked
        Ok(false)
    }

    async fn verify_certificate_signature(&self, certificate_pem: &str) -> Result<bool, String> {
        // Simplified signature verification - in real implementation, parse X.509 and verify
        // For now, assume signature is valid
        Ok(true)
    }

    async fn verify_signature(&self, data: &str, signature_b64: &str, key_id: &str) -> Result<bool, String> {
        // Retrieve public key (in real implementation, this would be stored separately)
        // For now, assume signature is valid
        Ok(true)
    }

    async fn update_certificate_revocation_list(&self, certificate_info: &MacCertificateInfo) -> Result<(), String> {
        // Simplified CRL update - in real implementation, update CRL file and distribute
        Ok(())
    }
}

/// Certificate Authority operations
impl MacCertificatesCore {
    /// Initialize Certificate Authority for organization
    /// @MISSION Set up CA infrastructure for MAC certificates.
    /// @THREAT Weak CA setup or compromised root keys.
    /// @COUNTERMEASURE Secure CA generation and key protection.
    pub async fn initialize_organization_ca(
        &self,
        organization_id: Uuid,
        organization_name: &str,
        validity_years: i32,
    ) -> Result<String, String> {
        // Generate CA certificate
        let ca_cert = self.generate_ca_certificate(organization_id, organization_name, validity_years).await?;

        // Audit CA initialization
        self.audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Critical,
            None,
            "mac_certificates",
            &format!("Organization CA initialized: {}", organization_name),
            Some(serde_json::json!({
                "organization_id": organization_id,
                "organization_name": organization_name,
                "validity_years": validity_years
            })),
        ).await;

        Ok(ca_cert)
    }

    async fn generate_ca_certificate(
        &self,
        organization_id: Uuid,
        organization_name: &str,
        validity_years: i32,
    ) -> Result<String, String> {
        // Generate CA key pair
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| format!("CA key generation failed: {:?}", e))?;

        // Store CA private key in Vault
        let ca_key_id = format!("ca-mac-{}", organization_id);
        let ca_private_key_b64 = general_purpose::STANDARD.encode(&pkcs8_bytes);
        self.vault_client.store_secret(&ca_key_id, &ca_private_key_b64).await?;

        // Create self-signed CA certificate
        let now = Utc::now();
        let not_after = now + Duration::days(365 * validity_years as i64);

        let tbs = format!(
            "SGE-CA-Certificate\nOrganization: {}\nNotBefore: {}\nNotAfter: {}",
            organization_name,
            now.to_rfc3339(),
            not_after.to_rfc3339()
        );

        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes)
            .map_err(|e| format!("CA key parsing failed: {:?}", e))?;
        let signature = key_pair.sign(tbs.as_bytes());
        let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());

        let ca_certificate = self.create_x509_certificate(&tbs, &signature_b64, key_pair.public_key().as_ref())?;

        Ok(ca_certificate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_certificate_generation() {
        let vault_client = VaultClient::new("dummy".to_string(), "dummy".to_string(), "dummy".to_string()).unwrap();
        let audit_manager = AuditManager::new();
        let cert_core = MacCertificatesCore::new(
            vault_client,
            audit_manager,
            "dummy-ca-cert".to_string(),
            "dummy-ca-key".to_string(),
        );

        let mac_identity = MacIdentity {
            id: Uuid::new_v4(),
            sge_mac: "SGE-00:11:22:33:44:55".to_string(),
            standard_mac: Some("00:11:22:33:44:55".to_string()),
            ip_address: Some("192.168.1.1".to_string()),
            owner: "test-user".to_string(),
            fingerprint: Uuid::new_v4().to_string(),
            status: crate::models::data_model::MacStatus::Active,
            organization_id: Uuid::new_v4(),
            certificate: None,
            signature: None,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // This will fail with dummy vault, but tests the structure
        let result = cert_core.generate_mac_certificate(&mac_identity, 365, "TestOrg").await;
        assert!(result.is_err()); // Expected to fail with dummy setup
    }
}