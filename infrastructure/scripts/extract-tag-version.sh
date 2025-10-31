#!/bin/bash

# Sky Genesis Enterprise API Service - Tag Version Extraction Script
# Extracts version from GitHub release tag (e.g., "v1.2.6-api" -> "1.2.6")

set -e

# Function to extract version from tag
extract_version_from_tag() {
    local tag="$1"
    if [ -z "$tag" ]; then
        echo "Error: No tag provided" >&2
        exit 1
    fi

    # Extract version from tag (e.g., "v1.2.6-api" -> "1.2.6")
    local version=$(echo "$tag" | sed 's/^v\([0-9]\+\.[0-9]\+\.[0-9]\+\).*/\1/')

    if [ "$version" = "$tag" ]; then
        echo "Error: Invalid tag format. Expected format: v1.2.3 or v1.2.3-component" >&2
        exit 1
    fi

    echo "$version"
}

# Main logic
if [ $# -eq 0 ]; then
    # If no argument provided, try to get from git tag
    if git describe --tags --exact-match 2>/dev/null; then
        TAG=$(git describe --tags --exact-match)
    else
        echo "Error: No tag provided and not on a tagged commit" >&2
        echo "Usage: $0 <tag> or run from a tagged commit" >&2
        exit 1
    fi
else
    TAG="$1"
fi

VERSION=$(extract_version_from_tag "$TAG")
echo "$VERSION"