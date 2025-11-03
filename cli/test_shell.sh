#!/bin/bash

echo "Testing Sky Genesis Enterprise SSH Shell"
echo "========================================"
echo ""

# Build the CLI first
echo "Building CLI..."
cargo build --bin cli --quiet

echo ""
echo "=== SSH Shell Demo ==="
echo ""

# Test the SSH shell with various commands
echo -e "help\ndevices list\nconnect core-router\nshow running-config\ndisconnect\nstatus\nexit" | timeout 15 cargo run --bin cli shell 2>/dev/null | grep -v "INFO\|WARN\|Starting"

echo ""
echo "=== Demo Complete ==="