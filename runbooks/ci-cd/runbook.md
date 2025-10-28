# CI/CD Runbook

## Overview
This runbook covers the Continuous Integration and Continuous Deployment processes for the Sky Genesis Enterprise API Service.

## Prerequisites
- Access to GitHub repository
- Docker installed
- Kubernetes cluster access (for production)
- Terraform CLI (for infrastructure)

## CI Pipeline

### Automated Triggers
- Push to main branch
- Pull requests to main branch
- Scheduled nightly builds

### Build Process
1. Checkout code
2. Install dependencies: `pnpm install`
3. Run linting: `npm run lint`
4. Run type checking: `tsc --noEmit`
5. Run tests: `npm test`
6. Build application: `next build --turbopack`
7. Build Docker images

### Deployment Process

#### Staging Environment
1. Deploy to staging Kubernetes cluster
2. Run integration tests
3. Verify application health

#### Production Environment
1. Tag release in Git
2. Deploy to production cluster
3. Run smoke tests
4. Monitor for 30 minutes

## Manual Deployment
```bash
# Build and push Docker images
make build
make push

# Deploy to Kubernetes
kubectl apply -f infrastructure/kubernetes/base/
```

## Rollback Procedure
1. Identify failing deployment
2. Rollback to previous version: `kubectl rollout undo deployment/api-service`
3. Verify rollback success
4. Investigate root cause

## Monitoring
- Check GitHub Actions status
- Monitor Kubernetes pod health
- Review application logs