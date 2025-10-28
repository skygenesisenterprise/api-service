# SCA (Software Composition Analysis) Runbook

## Overview
This runbook covers Software Composition Analysis processes for identifying and managing open source dependencies and their vulnerabilities.

## Dependency Scanning

### Tools Used
- OWASP Dependency-Check
- Snyk
- SonarQube for code quality

### Scan Execution
```bash
# Run dependency check
dependency-check --project "API Service" --scan . --format JSON --out reports/

# Snyk scan
snyk test --json > snyk-report.json

# Container scanning
trivy image --format json --output trivy-report.json api-service:latest
```

### Automated Scanning
- Scans run on every PR
- Nightly full scans
- Pre-deployment scans

## License Compliance

### License Inventory
- All dependencies cataloged
- Licenses classified (permissive/copyleft/proprietary)
- Compliance matrix maintained

### Policy Enforcement
- Block dependencies with incompatible licenses
- Require license approval for new dependencies
- Maintain license whitelist

## Vulnerability Management

### Risk Assessment
- CVSS scoring for vulnerabilities
- Business impact analysis
- Mitigation planning

### Remediation Process
1. Identify vulnerable dependency
2. Check for available patches/updates
3. Assess upgrade impact
4. Plan and execute upgrade
5. Test thoroughly
6. Deploy fix

### Exceptions
- Documented risk acceptance for unavoidable vulnerabilities
- Time-bound exceptions with remediation plans
- Regular review of exceptions

## Reporting

### Dashboards
- Vulnerability trends
- License compliance status
- Dependency health metrics

### Compliance Reports
- Generated monthly
- Distributed to stakeholders
- Audited annually

## Integration

### CI/CD Integration
- SCA checks in build pipeline
- Fail builds on policy violations
- Generate evidence for compliance

### Development Workflow
- Pre-commit hooks for local scanning
- IDE plugins for real-time feedback
- Training for developers on SCA best practices