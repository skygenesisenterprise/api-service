#!/bin/bash
# DNS Security Setup Script for Sky Genesis Enterprise
# Configures DKIM, SPF, DMARC, MTA-STS, and DANE/TLSA records

set -euo pipefail

# Configuration
DOMAIN="${DOMAIN:-skygenesisenterprise.com}"
VAULT_ADDR="${VAULT_ADDR:-https://vault.skygenesisenterprise.com:8200}"
DKIM_SELECTOR="${DKIM_SELECTOR:-default}"
LOG_FILE="/var/log/sge/dns-security-setup.log"

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

# Generate DKIM key pair
generate_dkim_key() {
    log "Generating DKIM key pair..."

    # Generate Ed25519 keypair for DKIM
    DKIM_PRIVATE_KEY=$(vault write -format=json transit/keys/dkim_key type=ed25519 | jq -r '.data.keys."1".public_key')

    if [ -z "$DKIM_PRIVATE_KEY" ] || [ "$DKIM_PRIVATE_KEY" = "null" ]; then
        error "Failed to generate DKIM key"
    fi

    # Convert to DNS format (base64url encoding)
    DKIM_DNS_RECORD=$(echo "$DKIM_PRIVATE_KEY" | base64 -w 0 | tr '+/' '-_')

    log "DKIM key pair generated successfully"
}

# Generate MTA-STS policy
generate_mta_sts_policy() {
    log "Generating MTA-STS policy..."

    MTA_STS_POLICY="version: STSv1
mode: enforce
max_age: 604800
mx: mail.skygenesisenterprise.com"

    log "MTA-STS policy generated"
}

# Generate TLSA records for DANE
generate_tlsa_records() {
    log "Generating TLSA records for DANE..."

    # Get certificate from Vault
    CERT_PEM=$(vault read -format=json secret/stalwart/client_cert | jq -r '.data.certificate')

    if [ -z "$CERT_PEM" ] || [ "$CERT_PEM" = "null" ]; then
        error "Failed to retrieve certificate for TLSA records"
    fi

    # Extract certificate data (remove PEM headers/footers)
    CERT_DATA=$(echo "$CERT_PEM" | sed '/-----BEGIN CERTIFICATE-----/d; /-----END CERTIFICATE-----/d' | tr -d '\n')

    # Calculate SHA-256 hash for TLSA record
    TLSA_SHA256=$(echo "$CERT_DATA" | xxd -r -p | openssl x509 -noout -fingerprint -sha256 | cut -d'=' -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]')

    # Generate TLSA records
    TLSA_443="3 0 1 $TLSA_SHA256"  # TCP port 443, full certificate
    TLSA_993="3 0 1 $TLSA_SHA256"  # TCP port 993 (IMAPS)
    TLSA_587="3 0 1 $TLSA_SHA256"  # TCP port 587 (SMTP Submission)
    TLSA_465="3 0 1 $TLSA_SHA256"  # TCP port 465 (SMTPS)

    log "TLSA records generated for DANE"
}

# Generate DNS records
generate_dns_records() {
    log "Generating DNS records..."

    cat << EOF > /tmp/dns_records.txt
; Sky Genesis Enterprise DNS Security Records
; Generated on $(date)

; SPF Record
$DOMAIN. IN TXT "v=spf1 mx a:mail.$DOMAIN a:stalwart.$DOMAIN -all"

; DMARC Record
_dmarc.$DOMAIN. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@$DOMAIN; ruf=mailto:dmarc@$DOMAIN; fo=1; adkim=s; aspf=s; pct=100"

; DKIM Record
$DKIM_SELECTOR._domainkey.$DOMAIN. IN TXT "v=DKIM1; k=ed25519; p=$DKIM_DNS_RECORD"

; MTA-STS Record
_mta-sts.$DOMAIN. IN TXT "v=STSv1; id=$(date +%Y%m%d%H%M%S);"

; MTA-STS Policy
mta-sts.$DOMAIN. IN CNAME _mta-sts.$DOMAIN.

; HTTPS Record (for MTA-STS)
_https.$DOMAIN. IN TXT "v=1; mode=enforce; mx=mail.$DOMAIN;"

; TLSA Records for DANE
_443._tcp.$DOMAIN. IN TLSA $TLSA_443
_993._tcp.stalwart.$DOMAIN. IN TLSA $TLSA_993
_587._tcp.stalwart.$DOMAIN. IN TLSA $TLSA_587
_465._tcp.stalwart.$DOMAIN. IN TLSA $TLSA_465

; CAA Records
$DOMAIN. IN CAA 0 issue "letsencrypt.org"
$DOMAIN. IN CAA 0 issuewild "letsencrypt.org"
$DOMAIN. IN CAA 0 iodef "mailto:security@$DOMAIN"

; Additional security records
mail.$DOMAIN. IN MX 10 stalwart.$DOMAIN.
stalwart.$DOMAIN. IN A 192.0.2.1  ; Replace with actual IP
imap.$DOMAIN. IN CNAME stalwart.$DOMAIN.
smtp.$DOMAIN. IN CNAME stalwart.$DOMAIN.
EOF

    log "DNS records generated in /tmp/dns_records.txt"
}

# Validate DNS records
validate_dns_records() {
    log "Validating DNS records..."

    # Check DKIM record format
    if ! echo "$DKIM_DNS_RECORD" | grep -q '^[A-Za-z0-9_-]\+$'; then
        error "Invalid DKIM record format"
    fi

    # Check TLSA record format
    if ! echo "$TLSA_443" | grep -q '^3 0 1 [a-f0-9]\{64\}$'; then
        error "Invalid TLSA record format"
    fi

    log "DNS records validation passed"
}

# Deploy DNS records
deploy_dns_records() {
    log "Deploying DNS records..."

    # This would integrate with your DNS provider's API
    # For now, just display the records

    echo "=========================================="
    echo "DNS RECORDS TO DEPLOY"
    echo "=========================================="
    cat /tmp/dns_records.txt
    echo "=========================================="

    log "DNS records prepared for deployment"
    log "Please manually deploy these records to your DNS provider"
}

# Test DNS records
test_dns_records() {
    log "Testing DNS records..."

    # Test SPF
    if dig +short TXT "$DOMAIN" | grep -q "v=spf1"; then
        log "SPF record found"
    else
        log "WARNING: SPF record not found (may not be deployed yet)"
    fi

    # Test DMARC
    if dig +short TXT "_dmarc.$DOMAIN" | grep -q "v=DMARC1"; then
        log "DMARC record found"
    else
        log "WARNING: DMARC record not found (may not be deployed yet)"
    fi

    # Test DKIM
    if dig +short TXT "$DKIM_SELECTOR._domainkey.$DOMAIN" | grep -q "v=DKIM1"; then
        log "DKIM record found"
    else
        log "WARNING: DKIM record not found (may not be deployed yet)"
    fi

    log "DNS record testing completed"
}

# Generate MTA-STS policy file
generate_mta_sts_file() {
    log "Generating MTA-STS policy file..."

    mkdir -p /var/www/mta-sts/.well-known

    cat << EOF > /var/www/mta-sts/.well-known/mta-sts.txt
version: STSv1
mode: enforce
max_age: 604800
mx: mail.skygenesisenterprise.com
EOF

    log "MTA-STS policy file generated"
}

# Main execution
main() {
    log "Starting DNS security setup for Sky Genesis Enterprise"

    vault_auth
    generate_dkim_key
    generate_mta_sts_policy
    generate_tlsa_records
    generate_dns_records
    validate_dns_records
    deploy_dns_records
    test_dns_records
    generate_mta_sts_file

    log "DNS security setup completed"
    log "Next steps:"
    log "1. Deploy the DNS records shown above to your DNS provider"
    log "2. Wait for DNS propagation (may take up to 24 hours)"
    log "3. Test email delivery and security features"
}

# Run main function
main "$@"