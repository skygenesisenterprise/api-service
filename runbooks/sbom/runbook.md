# SBOM (Software Bill of Materials) Runbook

## Overview
This runbook covers the generation, management, and usage of Software Bill of Materials for the Sky Genesis Enterprise API Service.

## SBOM Generation

### Tools Used
- CycloneDX for SBOM generation
- OWASP Dependency-Check for vulnerability scanning

### Generating SBOM
```bash
# Generate SBOM for Rust dependencies
cargo cyclonedx

# Generate SBOM for Node.js dependencies
cyclonedx-npm --output-file sbom.json

# Combine SBOMs
cyclonedx merge --input-files rust-sbom.json nodejs-sbom.json --output-file combined-sbom.json
```

### Automated Generation
- SBOM generated on every build
- Stored in artifact repository
- Versioned with release tags

## Vulnerability Scanning

### Scan Process
1. Generate SBOM
2. Scan against vulnerability databases
3. Generate vulnerability report
4. Block builds with critical vulnerabilities

### Tools
- Trivy for container scanning
- OWASP Dependency-Check for dependency scanning
- Snyk for additional vulnerability intelligence

## Compliance

### Standards
- CycloneDX 1.4 format
- SPDX 2.3 compatible
- NTIA minimum elements included

### Audit Requirements
- SBOM available for all releases
- Vulnerability reports maintained
- License compliance verified

## Distribution

### Internal Use
- SBOM stored in Nexus repository
- Accessible to security team
- Used for compliance audits

### External Sharing
- SBOM provided to customers on request
- Redacted for sensitive information
- Signed for authenticity

## Maintenance

### Updates
- SBOM regenerated on dependency changes
- Vulnerability database updated daily
- Reports reviewed weekly

### Retention
- SBOMs retained for 7 years
- Archived with release artifacts
- Version controlled in repository