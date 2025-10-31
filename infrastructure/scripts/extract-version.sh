#!/bin/bash

# Sky Genesis Enterprise API Service - Version Extraction Script
# Extracts version from package.json, api/Cargo.toml, and cli/Cargo.toml
# Outputs the version in vx.x.x format for Docker tagging

set -e

# Function to extract version from package.json
extract_package_json_version() {
    local file="$1"
    if [ -f "$file" ]; then
        grep '"version"' "$file" | head -1 | sed 's/.*"version": "\([^"]*\)".*/\1/'
    fi
}

# Function to extract version from Cargo.toml
extract_cargo_version() {
    local file="$1"
    if [ -f "$file" ]; then
        grep '^version =' "$file" | head -1 | sed 's/version = "\([^"]*\)"/\1/'
    fi
}

# Get versions from different components
PACKAGE_VERSION=$(extract_package_json_version "package.json")
API_VERSION=$(extract_cargo_version "api/Cargo.toml")
CLI_VERSION=$(extract_cargo_version "cli/Cargo.toml")

# Validate that all versions are present
if [ -z "$PACKAGE_VERSION" ]; then
    echo "Error: Could not extract version from package.json" >&2
    exit 1
fi

if [ -z "$API_VERSION" ]; then
    echo "Error: Could not extract version from api/Cargo.toml" >&2
    exit 1
fi

if [ -z "$CLI_VERSION" ]; then
    echo "Error: Could not extract version from cli/Cargo.toml" >&2
    exit 1
fi

# Check if all versions match
if [ "$PACKAGE_VERSION" != "$API_VERSION" ] || [ "$PACKAGE_VERSION" != "$CLI_VERSION" ]; then
    echo "Warning: Version mismatch detected!" >&2
    echo "package.json: $PACKAGE_VERSION" >&2
    echo "api/Cargo.toml: $API_VERSION" >&2
    echo "cli/Cargo.toml: $CLI_VERSION" >&2
    echo "Using package.json version as primary: $PACKAGE_VERSION" >&2
fi

# Output version in vx.x.x format
echo "v$PACKAGE_VERSION"