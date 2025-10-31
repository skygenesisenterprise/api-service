#!/bin/bash

# ============================================================================
#  SKY GENESIS ENTERPRISE (SGE)
#  Network Health Check Script
# ============================================================================
#  This script performs a comprehensive network health check using the SGE CLI
#  It checks network status, VPN connections, services, and security alerts
# ============================================================================

set -e

echo "🔍 Sky Genesis Enterprise - Network Health Check"
echo "================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    local status=$1
    local message=$2

    case $status in
        "OK")
            echo -e "${GREEN}✓${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}⚠${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}✗${NC} $message"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ${NC} $message"
            ;;
    esac
}

echo "1. Checking Network Status..."
echo "-----------------------------"
if sge network status > /dev/null 2>&1; then
    print_status "OK" "Network status check passed"
else
    print_status "ERROR" "Network status check failed"
fi

echo ""
echo "2. Checking VPN Connections..."
echo "------------------------------"
VPN_STATUS=$(sge vpn status 2>/dev/null || echo "ERROR")
if echo "$VPN_STATUS" | grep -q "active\|connected"; then
    print_status "OK" "VPN connections are active"
else
    print_status "ERROR" "VPN connections have issues"
fi

echo ""
echo "3. Checking Critical Services..."
echo "--------------------------------"
SERVICES=$(sge services list 2>/dev/null || echo "")
CRITICAL_SERVICES=("api-server" "ssh-admin" "vault-client" "keycloak-client")

for service in "${CRITICAL_SERVICES[@]}"; do
    if echo "$SERVICES" | grep -q "$service.*running"; then
        print_status "OK" "Service $service is running"
    else
        print_status "ERROR" "Service $service is not running"
    fi
done

echo ""
echo "4. Checking Security Alerts..."
echo "------------------------------"
ALERTS=$(sge security alerts 2>/dev/null || echo "")
CRITICAL_ALERTS=$(echo "$ALERTS" | grep -c "critical\|high" || echo "0")

if [ "$CRITICAL_ALERTS" -eq 0 ]; then
    print_status "OK" "No critical security alerts"
else
    print_status "ERROR" "$CRITICAL_ALERTS critical security alerts found"
fi

echo ""
echo "5. Checking System Metrics..."
echo "-----------------------------"
METRICS=$(sge monitoring metrics 2>/dev/null || echo "")
CPU_USAGE=$(echo "$METRICS" | grep "usage_percent" | head -1 | grep -o '[0-9.]*' || echo "100")
MEM_USAGE=$(echo "$METRICS" | grep "usage_percent" | tail -1 | grep -o '[0-9.]*' || echo "100")

if (( $(echo "$CPU_USAGE < 80" | bc -l) )); then
    print_status "OK" "CPU usage is normal ($CPU_USAGE%)"
else
    print_status "WARN" "High CPU usage detected ($CPU_USAGE%)"
fi

if (( $(echo "$MEM_USAGE < 85" | bc -l) )); then
    print_status "OK" "Memory usage is normal ($MEM_USAGE%)"
else
    print_status "WARN" "High memory usage detected ($MEM_USAGE%)"
fi

echo ""
echo "6. Checking Recent Logs..."
echo "--------------------------"
ERROR_LOGS=$(sge logs search "error" --limit 5 2>/dev/null | grep -c "error" || echo "0")

if [ "$ERROR_LOGS" -eq 0 ]; then
    print_status "OK" "No recent error logs found"
else
    print_status "WARN" "$ERROR_LOGS error entries found in recent logs"
fi

echo ""
echo "7. Network Connectivity Test..."
echo "-------------------------------"
# Test connectivity to key services
if timeout 5 bash -c "</dev/tcp/skygenesisenterprise.com/443" 2>/dev/null; then
    print_status "OK" "External connectivity to skygenesisenterprise.com:443"
else
    print_status "ERROR" "Cannot connect to skygenesisenterprise.com:443"
fi

echo ""
echo "================================================"
echo "Network Health Check Complete"
echo "================================================"

# Summary
TOTAL_CHECKS=8
PASSED_CHECKS=$(grep -c "✓" /tmp/sge_check.log 2>/dev/null || echo "0")

echo "Summary: $PASSED_CHECKS/$TOTAL_CHECKS checks passed"

if [ "$PASSED_CHECKS" -eq "$TOTAL_CHECKS" ]; then
    print_status "OK" "All systems operational"
    exit 0
elif [ "$PASSED_CHECKS" -ge 6 ]; then
    print_status "WARN" "Minor issues detected"
    exit 1
else
    print_status "ERROR" "Critical issues detected - immediate attention required"
    exit 2
fi