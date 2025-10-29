#!/bin/bash
# Certificate and Key Rotation Script for Sky Genesis Enterprise
# Military-grade security: Automated rotation every 7-30 days

set -euo pipefail

# Configuration
VAULT_ADDR="${VAULT_ADDR:-https://vault.skygenesisenterprise.com:8200}"
STALWART_URL="${STALWART_URL:-https://stalwart.skygenesisenterprise.com}"
PKI_MOUNT="${PKI_MOUNT:-pki}"
ROLE_NAME="${ROLE_NAME:-server-cert}"
COMMON_NAME="${COMMON_NAME:-stalwart.skygenesisenterprise.com}"
ALT_NAMES="${ALT_NAMES:-mail.skygenesisenterprise.com,imap.skygenesisenterprise.com,smtp.skygenesisenterprise.com}"

# Logging
LOG_FILE="/var/log/sge/certificate-rotation.log"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $*" >&2 | tee -a "$LOG_FILE"
    exit 1
}

# Authenticate with Vault
vault_auth() {
    log "Authenticating with Vault..."

    if [ -z "${VAULT_ROLE_ID:-}" ] || [ -z "${VAULT_SECRET_ID:-}" ]; then
        error "VAULT_ROLE_ID and VAULT_SECRET_ID must be set"
    fi

    VAULT_TOKEN=$(vault write -format=json auth/approle/login \
        role_id="$VAULT_ROLE_ID" \
        secret_id="$VAULT_SECRET_ID" | jq -r '.auth.client_token')

    if [ -z "$VAULT_TOKEN" ] || [ "$VAULT_TOKEN" = "null" ]; then
        error "Failed to authenticate with Vault"
    fi

    export VAULT_TOKEN
    log "Successfully authenticated with Vault"
}

# Issue new certificate
issue_certificate() {
    log "Issuing new certificate for $COMMON_NAME..."

    CERT_DATA=$(vault write -format=json "$PKI_MOUNT/issue/$ROLE_NAME" \
        common_name="$COMMON_NAME" \
        alt_names="$ALT_NAMES" \
        ttl="720h")  # 30 days

    if [ $? -ne 0 ]; then
        error "Failed to issue certificate"
    fi

    log "Certificate issued successfully"
}

# Extract certificate components
extract_certificates() {
    log "Extracting certificate components..."

    echo "$CERT_DATA" | jq -r '.data.certificate' > /tmp/new_cert.pem
    echo "$CERT_DATA" | jq -r '.data.private_key' > /tmp/new_key.pem
    echo "$CERT_DATA" | jq -r '.data.issuing_ca' > /tmp/ca_cert.pem

    # Create fullchain
    cat /tmp/new_cert.pem /tmp/ca_cert.pem > /tmp/fullchain.pem

    # Validate certificates
    if ! openssl x509 -in /tmp/new_cert.pem -noout -dates > /dev/null 2>&1; then
        error "Invalid certificate generated"
    fi

    if ! openssl rsa -in /tmp/new_key.pem -noout -check > /dev/null 2>&1; then
        error "Invalid private key generated"
    fi

    log "Certificate components extracted and validated"
}

# Backup current certificates
backup_certificates() {
    log "Backing up current certificates..."

    BACKUP_DIR="/etc/ssl/stalwart/backup/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"

    if [ -f /etc/ssl/stalwart/fullchain.pem ]; then
        cp /etc/ssl/stalwart/fullchain.pem "$BACKUP_DIR/"
        cp /etc/ssl/stalwart/privkey.pem "$BACKUP_DIR/"
        log "Current certificates backed up to $BACKUP_DIR"
    else
        log "No existing certificates to backup"
    fi
}

# Install new certificates
install_certificates() {
    log "Installing new certificates..."

    # Install certificates atomically
    cp /tmp/fullchain.pem /etc/ssl/stalwart/fullchain.pem.new
    cp /tmp/new_key.pem /etc/ssl/stalwart/privkey.pem.new

    # Atomic move
    mv /etc/ssl/stalwart/fullchain.pem.new /etc/ssl/stalwart/fullchain.pem
    mv /etc/ssl/stalwart/privkey.pem.new /etc/ssl/stalwart/privkey.pem

    # Set proper permissions
    chown stalwart:stalwart /etc/ssl/stalwart/*.pem
    chmod 644 /etc/ssl/stalwart/fullchain.pem
    chmod 600 /etc/ssl/stalwart/privkey.pem

    log "New certificates installed successfully"
}

# Reload Stalwart service
reload_stalwart() {
    log "Reloading Stalwart service..."

    if systemctl is-active --quiet stalwart; then
        systemctl reload stalwart
        if [ $? -eq 0 ]; then
            log "Stalwart service reloaded successfully"
        else
            error "Failed to reload Stalwart service"
        fi
    else
        log "Stalwart service not active, starting..."
        systemctl start stalwart
    fi
}

# Verify certificate installation
verify_installation() {
    log "Verifying certificate installation..."

    # Test SSL connection
    if timeout 10 openssl s_client -connect "$COMMON_NAME:993" -servername "$COMMON_NAME" \
        -CAfile /tmp/ca_cert.pem < /dev/null > /dev/null 2>&1; then
        log "SSL certificate verification successful"
    else
        error "SSL certificate verification failed"
    fi

    # Check certificate expiry
    EXPIRY=$(openssl x509 -in /etc/ssl/stalwart/fullchain.pem -noout -enddate | cut -d= -f2)
    log "New certificate expires: $EXPIRY"
}

# Rotate encryption keys in Vault Transit
rotate_transit_keys() {
    log "Rotating Vault Transit encryption keys..."

    # Rotate mail storage key
    vault write -f transit/keys/mail_storage_key/rotate
    if [ $? -eq 0 ]; then
        log "Mail storage key rotated successfully"
    else
        error "Failed to rotate mail storage key"
    fi

    # Rotate DKIM key
    vault write -f transit/keys/dkim_key/rotate
    if [ $? -eq 0 ]; then
        log "DKIM key rotated successfully"
    else
        error "Failed to rotate DKIM key"
    fi

    # Rotate API HMAC key
    vault write -f transit/keys/api_hmac_key/rotate
    if [ $? -eq 0 ]; then
        log "API HMAC key rotated successfully"
    else
        error "Failed to rotate API HMAC key"
    fi

    # Rotate PGP key encryption key
    vault write -f transit/keys/pgp_key_encryption/rotate
    if [ $? -eq 0 ]; then
        log "PGP key encryption key rotated successfully"
    else
        error "Failed to rotate PGP key encryption key"
    fi
}

# Update mTLS certificates in Vault
update_mtls_certificates() {
    log "Updating mTLS certificates in Vault..."

    # Store new client certificate in Vault
    vault kv put secret/stalwart/client_cert @"$CERT_DATA" || error "Failed to store client certificate"

    # Store new client key in Vault (encrypted)
    ENCRYPTED_KEY=$(vault write -format=json transit/encrypt/pgp_key_encryption plaintext="$(base64 -w 0 /tmp/new_key.pem)" | jq -r '.data.ciphertext')
    vault kv put secret/stalwart/client_key encrypted_key="$ENCRYPTED_KEY" || error "Failed to store client key"

    # Store CA certificate
    vault kv put secret/stalwart/ca_cert @"$CA_CERT" || error "Failed to store CA certificate"

    log "mTLS certificates updated in Vault"
}

# Send notification
send_notification() {
    log "Sending rotation notification..."

    # This would integrate with your notification system
    # For now, just log
    log "Certificate rotation completed successfully"
    log "Next rotation due: $(date -d '+7 days' '+%Y-%m-%d %H:%M:%S')"
}

# Cleanup
cleanup() {
    log "Cleaning up temporary files..."
    rm -f /tmp/new_cert.pem /tmp/new_key.pem /tmp/ca_cert.pem /tmp/fullchain.pem
}

# Main execution
main() {
    log "Starting certificate rotation for Sky Genesis Enterprise"

    vault_auth
    issue_certificate
    extract_certificates
    backup_certificates
    install_certificates
    reload_stalwart
    verify_installation
    rotate_transit_keys
    update_mtls_certificates
    send_notification
    cleanup

    log "Certificate rotation completed successfully"
}

# Run main function
main "$@"