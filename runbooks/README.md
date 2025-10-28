# Runbooks

This directory contains operational runbooks and templates for the Sky Genesis Enterprise API Service. Runbooks provide detailed procedures for various aspects of development, deployment, and maintenance.

## Categories

### CI/CD
Operational procedures for Continuous Integration and Continuous Deployment.

- **runbook.md**: General CI/CD processes, deployment procedures, and rollback instructions.
- **github-actions/**: GitHub Actions workflow templates.
  - `ci.yml`: Continuous integration pipeline for testing and building.
  - `deploy.yml`: Automated deployment to Kubernetes.
  - `security.yml`: Security scanning and vulnerability assessment.

### Containers
Container management and orchestration procedures.

- **runbook.md**: Docker and Kubernetes operations, troubleshooting, and scaling.

### Monitoring
Observability and monitoring setup and procedures.

- **runbook.md**: Metrics collection, logging, alerting, and incident response.

### SBOM (Software Bill of Materials)
Software composition and bill of materials management.

- **runbook.md**: SBOM generation, vulnerability scanning, and compliance procedures.

### SCA (Software Composition Analysis)
Dependency analysis and license compliance.

- **runbook.md**: Dependency scanning, license management, and vulnerability remediation.

### Secrets
Secret management and security procedures.

- **runbook.md**: Vault setup, key rotation, and access control.

### Static Analysis
Code quality and security analysis procedures.

- **runbook.md**: Linting, code quality checks, and security scanning.

### Template
Code and infrastructure templates.

- **runbook.md**: Template management and usage guidelines.
- **component.tsx.template**: React component boilerplate.
- **controller.rs.template**: Rust API controller template.
- **test.ts.template**: Test file template.

### Testing
Testing strategies and procedures.

- **runbook.md**: Unit, integration, and end-to-end testing processes.

## Usage

1. Review the relevant runbook before performing operations.
2. Follow the step-by-step procedures outlined in each document.
3. Update runbooks as processes evolve.
4. Use templates to maintain consistency across the codebase.

## Contributing

When adding new runbooks or updating existing ones:
- Follow the established format and structure.
- Include prerequisites, step-by-step instructions, and troubleshooting.
- Test procedures in a safe environment before documenting.
- Keep documentation current with process changes.