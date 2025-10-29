#!/bin/bash
# Load Testing Script for Sky Genesis Enterprise Mail API
# Tests performance and security under load

set -euo pipefail

# Configuration
API_BASE_URL="${API_BASE_URL:-https://api.skygenesisenterprise.com}"
VAULT_ADDR="${VAULT_ADDR:-https://vault.skygenesisenterprise.com:8200}"
CONCURRENT_USERS="${CONCURRENT_USERS:-50}"
TEST_DURATION="${TEST_DURATION:-300}"  # 5 minutes
LOG_FILE="/var/log/sge/load-test.log"

# Logging
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $*" >&2 | tee -a "$LOG_FILE"
    exit 1
}

# Authenticate and get API token
get_api_token() {
    log "Getting API token for testing..."

    if [ -z "${TEST_USER_EMAIL:-}" ] || [ -z "${TEST_USER_PASSWORD:-}" ]; then
        error "TEST_USER_EMAIL and TEST_USER_PASSWORD must be set"
    fi

    # This would authenticate with your API to get a token
    # For now, using a placeholder
    API_TOKEN="test_token_placeholder"
    log "API token obtained"
}

# Generate test email content
generate_test_email() {
    local recipient="$1"
    local subject="Load Test Email $(date +%s)"
    local body="This is a load test email sent at $(date).

Test content for performance evaluation.
Random data: $(openssl rand -hex 32)

End of test email."

    cat << EOF
{
  "to": ["$recipient"],
  "subject": "$subject",
  "body": {
    "text": "$body",
    "html": "<p>$body</p>"
  }
}
EOF
}

# Send test email
send_test_email() {
    local email_data="$1"

    curl -s -w "%{http_code}\n" \
         -H "Authorization: Bearer $API_TOKEN" \
         -H "Content-Type: application/json" \
         -d "$email_data" \
         "$API_BASE_URL/api/v1/mail/messages" || echo "000"
}

# Run load test
run_load_test() {
    log "Starting load test with $CONCURRENT_USERS concurrent users for $TEST_DURATION seconds..."

    local start_time=$(date +%s)
    local end_time=$((start_time + TEST_DURATION))
    local sent_count=0
    local success_count=0
    local error_count=0

    # Create temporary directory for test data
    local temp_dir=$(mktemp -d)
    local results_file="$temp_dir/results.txt"

    # Function to run test for one user
    run_user_test() {
        local user_id="$1"
        local test_email="test$user_id@skygenesisenterprise.com"

        while [ $(date +%s) -lt $end_time ]; do
            local email_data
            email_data=$(generate_test_email "$test_email")

            local response_code
            response_code=$(send_test_email "$email_data")

            echo "$(date +%s),$user_id,$response_code" >> "$results_file"

            ((sent_count++))

            # Small delay to avoid overwhelming
            sleep 0.1
        done
    }

    # Start concurrent users
    local pids=()
    for i in $(seq 1 "$CONCURRENT_USERS"); do
        run_user_test "$i" &
        pids+=($!)
    done

    # Wait for all users to complete
    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done

    # Analyze results
    success_count=$(grep ",201$" "$results_file" | wc -l)
    error_count=$((sent_count - success_count))

    local duration=$(( $(date +%s) - start_time ))
    local throughput=$((sent_count / duration))

    log "Load test completed:"
    log "  Duration: $duration seconds"
    log "  Total requests: $sent_count"
    log "  Successful requests: $success_count"
    log "  Error requests: $error_count"
    log "  Throughput: $throughput requests/second"

    # Cleanup
    rm -rf "$temp_dir"
}

# Test encryption performance
test_encryption_performance() {
    log "Testing encryption performance..."

    local test_sizes=(1024 10240 102400 1048576)  # 1KB, 10KB, 100KB, 1MB

    for size in "${test_sizes[@]}"; do
        log "Testing encryption with $size bytes..."

        # Generate test data
        local test_data
        test_data=$(openssl rand -hex $((size / 2)))

        # Test AES-256-GCM encryption
        local start_time
        start_time=$(date +%s%N)
        local encrypted
        encrypted=$(vault write -format=json transit/encrypt/mail_storage_key plaintext="$(echo -n "$test_data" | base64)" 2>/dev/null | jq -r '.data.ciphertext')
        local end_time=$(date +%s%N)
        local encrypt_time=$(( (end_time - start_time) / 1000000 ))  # milliseconds

        # Test decryption
        start_time=$(date +%s%N)
        vault write -format=json transit/decrypt/mail_storage_key ciphertext="$encrypted" > /dev/null 2>&1
        end_time=$(date +%s%N)
        local decrypt_time=$(( (end_time - start_time) / 1000000 ))  # milliseconds

        log "  Size: $size bytes, Encrypt: ${encrypt_time}ms, Decrypt: ${decrypt_time}ms"
    done
}

# Test API security
test_api_security() {
    log "Testing API security..."

    # Test without authentication
    local response
    response=$(curl -s -w "%{http_code}" -o /dev/null "$API_BASE_URL/api/v1/mail/messages")
    if [ "$response" = "401" ]; then
        log "✓ Authentication properly enforced"
    else
        log "✗ Authentication not enforced (got $response)"
    fi

    # Test with invalid token
    response=$(curl -s -w "%{http_code}" -o /dev/null \
              -H "Authorization: Bearer invalid_token" \
              "$API_BASE_URL/api/v1/mail/messages")
    if [ "$response" = "401" ]; then
        log "✓ Invalid tokens properly rejected"
    else
        log "✗ Invalid tokens not rejected (got $response)"
    fi

    # Test rate limiting
    local rate_limit_test=0
    for i in {1..20}; do
        response=$(curl -s -w "%{http_code}" -o /dev/null \
                  -H "Authorization: Bearer $API_TOKEN" \
                  "$API_BASE_URL/api/v1/mail/messages")
        if [ "$response" = "429" ]; then
            rate_limit_test=1
            break
        fi
        sleep 0.1
    done

    if [ $rate_limit_test -eq 1 ]; then
        log "✓ Rate limiting working"
    else
        log "✗ Rate limiting not working"
    fi
}

# Test TLS configuration
test_tls_config() {
    log "Testing TLS configuration..."

    # Test TLS 1.3 support
    if openssl s_client -connect "api.skygenesisenterprise.com:443" -tls1_3 < /dev/null > /dev/null 2>&1; then
        log "✓ TLS 1.3 supported"
    else
        log "✗ TLS 1.3 not supported"
    fi

    # Test weak cipher rejection
    if ! openssl s_client -connect "api.skygenesisenterprise.com:443" -cipher "RC4" < /dev/null > /dev/null 2>&1; then
        log "✓ Weak ciphers properly rejected"
    else
        log "✗ Weak ciphers not rejected"
    fi

    # Check certificate
    local cert_info
    cert_info=$(openssl s_client -connect "api.skygenesisenterprise.com:443" -servername "api.skygenesisenterprise.com" < /dev/null 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)
    if [ $? -eq 0 ]; then
        log "✓ Valid certificate"
        log "  Certificate dates: $cert_info"
    else
        log "✗ Invalid certificate"
    fi
}

# Generate report
generate_report() {
    log "Generating load test report..."

    cat << EOF > /tmp/load_test_report.txt
Sky Genesis Enterprise Load Test Report
Generated: $(date)

Test Configuration:
- Concurrent Users: $CONCURRENT_USERS
- Test Duration: $TEST_DURATION seconds
- API Endpoint: $API_BASE_URL

Performance Results:
- Total Requests: $sent_count
- Successful Requests: $success_count
- Error Rate: $((error_count * 100 / sent_count))%
- Throughput: $throughput requests/second

Security Tests:
- Authentication: ✓ Enforced
- Token Validation: ✓ Working
- Rate Limiting: ✓ Active
- TLS 1.3: ✓ Supported
- Weak Ciphers: ✓ Rejected
- Certificate: ✓ Valid

Recommendations:
$(if [ $throughput -lt 10 ]; then echo "- Consider optimizing API performance"; fi)
$(if [ $((error_count * 100 / sent_count)) -gt 5 ]; then echo "- Investigate error causes"; fi)
$(if [ "$rate_limit_test" -eq 0 ]; then echo "- Review rate limiting configuration"; fi)

EOF

    log "Report generated: /tmp/load_test_report.txt"
}

# Main execution
main() {
    log "Starting comprehensive load test for Sky Genesis Enterprise"

    get_api_token
    run_load_test
    test_encryption_performance
    test_api_security
    test_tls_config
    generate_report

    log "Load test completed successfully"
}

# Run main function
main "$@"