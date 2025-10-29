#!/bin/bash
# Key Rotation Script for Sky Genesis Enterprise
# Military-grade security: Automated key rotation every 90 days

set -euo pipefail

# Configuration
VAULT_ADDR="${VAULT_ADDR:-https://vault.skygenesisenterprise.com:8200}"
ROTATION_INTERVAL="${ROTATION_INTERVAL:-90}"  # days
LOG_FILE="/var/log/sge/key-rotation.log"

# Logging
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

# Check if rotation is needed
should_rotate() {
    local key_name="$1"
    local last_rotation_file="/var/lib/sge/last_rotation_$key_name"

    if [ ! -f "$last_rotation_file" ]; then
        log "No previous rotation record for $key_name, rotation needed"
        return 0
    fi

    local last_rotation=$(cat "$last_rotation_file")
    local days_since=$(( ( $(date +%s) - $(date -d "$last_rotation" +%s) ) / 86400 ))

    if [ "$days_since" -ge "$ROTATION_INTERVAL" ]; then
        log "Key $key_name was rotated $days_since days ago, rotation needed"
        return 0
    else
        log "Key $key_name was rotated $days_since days ago, no rotation needed"
        return 1
    fi
}

# Update last rotation timestamp
update_rotation_timestamp() {
    local key_name="$1"
    local timestamp_file="/var/lib/sge/last_rotation_$key_name"
    mkdir -p "$(dirname "$timestamp_file")"
    date '+%Y-%m-%d %H:%M:%S' > "$timestamp_file"
    log "Updated rotation timestamp for $key_name"
}

# Rotate encryption key
rotate_encryption_key() {
    local key_name="$1"
    local description="$2"

    if ! should_rotate "$key_name"; then
        return 0
    fi

    log "Rotating $description key..."

    # Create backup of current key version
    local current_version
    current_version=$(vault read -format=json "transit/keys/$key_name" | jq -r '.data.latest_version')

    if [ "$current_version" != "null" ] && [ -n "$current_version" ]; then
        log "Current version of $key_name is $current_version"
    fi

    # Rotate the key
    vault write -f "transit/keys/$key_name/rotate"
    if [ $? -eq 0 ]; then
        log "$description key rotated successfully"
        update_rotation_timestamp "$key_name"
    else
        error "Failed to rotate $description key"
    fi
}

# Rotate signing key
rotate_signing_key() {
    local key_name="$1"
    local description="$2"

    if ! should_rotate "$key_name"; then
        return 0
    fi

    log "Rotating $description signing key..."

    # For signing keys, we need to generate a new keypair
    # Delete old key and create new one
    vault delete "transit/keys/$key_name" 2>/dev/null || true

    vault write -f "transit/keys/$key_name" type=ed25519
    if [ $? -eq 0 ]; then
        log "$description signing key rotated successfully"
        update_rotation_timestamp "$key_name"
    else
        error "Failed to rotate $description signing key"
    fi
}

# Rotate HMAC key
rotate_hmac_key() {
    local key_name="$1"
    local description="$2"

    if ! should_rotate "$key_name"; then
        return 0
    fi

    log "Rotating $description HMAC key..."

    # For HMAC keys, we need to generate a new key
    vault delete "transit/keys/$key_name" 2>/dev/null || true

    vault write -f "transit/keys/$key_name" type=hmac
    if [ $? -eq 0 ]; then
        log "$description HMAC key rotated successfully"
        update_rotation_timestamp "$key_name"
    else
        error "Failed to rotate $description HMAC key"
    fi
}

# Test key functionality after rotation
test_key_functionality() {
    log "Testing key functionality after rotation..."

    # Test mail storage key
    local test_plaintext="test message for encryption"
    local encrypted
    encrypted=$(vault write -format=json transit/encrypt/mail_storage_key plaintext="$(echo -n "$test_plaintext" | base64)" | jq -r '.data.ciphertext')

    if [ -z "$encrypted" ] || [ "$encrypted" = "null" ]; then
        error "Mail storage key encryption test failed"
    fi

    local decrypted
    decrypted=$(vault write -format=json transit/decrypt/mail_storage_key ciphertext="$encrypted" | jq -r '.data.plaintext' | base64 -d)

    if [ "$decrypted" != "$test_plaintext" ]; then
        error "Mail storage key decryption test failed"
    fi

    # Test DKIM signing key
    local test_data="test data for signing"
    local signature
    signature=$(vault write -format=json transit/sign/dkim_key/sha2-512 input="$(echo -n "$test_data" | base64)" | jq -r '.data.signature')

    if [ -z "$signature" ] || [ "$signature" = "null" ]; then
        error "DKIM signing key test failed"
    fi

    local verification
    verification=$(vault write -format=json transit/verify/dkim_key/sha2-512 input="$(echo -n "$test_data" | base64)" signature="$signature" | jq -r '.data.valid')

    if [ "$verification" != "true" ]; then
        error "DKIM signature verification test failed"
    fi

    # Test API HMAC key
    local hmac
    hmac=$(vault write -format=json transit/hmac/api_hmac_key/sha2-512 input="$(echo -n "$test_data" | base64)" | jq -r '.data.hmac')

    if [ -z "$hmac" ] || [ "$hmac" = "null" ]; then
        error "API HMAC key test failed"
    fi

    log "All key functionality tests passed"
}

# Send notification
send_notification() {
    log "Sending key rotation notification..."

    # Count rotated keys
    local rotated_count=0
    for key in mail_storage_key dkim_key api_hmac_key pgp_key_encryption; do
        if should_rotate "$key"; then
            ((rotated_count++))
        fi
    done

    if [ "$rotated_count" -gt 0 ]; then
        log "Key rotation completed: $rotated_count keys rotated"
        log "Next rotation due: $(date -d "+$ROTATION_INTERVAL days" '+%Y-%m-%d %H:%M:%S')"
    else
        log "Key rotation completed: no keys needed rotation"
    fi
}

# Main execution
main() {
    log "Starting key rotation for Sky Genesis Enterprise"

    vault_auth

    # Rotate encryption keys
    rotate_encryption_key "mail_storage_key" "mail storage"
    rotate_encryption_key "pgp_key_encryption" "PGP key encryption"

    # Rotate signing keys
    rotate_signing_key "dkim_key" "DKIM"

    # Rotate HMAC keys
    rotate_hmac_key "api_hmac_key" "API HMAC"

    # Test functionality
    test_key_functionality

    # Send notification
    send_notification

    log "Key rotation completed successfully"
}

# Run main function
main "$@"