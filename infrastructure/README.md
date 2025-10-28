# 🏭 Infrastructure as Code

This directory contains the complete infrastructure setup for the Sky Genesis Enterprise API Service, designed for production deployment across multiple environments.

## 📁 Structure Overview

```
infrastructure/
├── docker/                 # 🐳 Container definitions
│   ├── Dockerfile.api      # Rust API container
│   ├── Dockerfile.frontend # Next.js container
│   ├── docker-compose.yml  # Local development
│   └── docker-compose.prod.yml  # Production stack
├── kubernetes/            # ☸️ Kubernetes manifests
│   ├── base/              # Base configurations
│   ├── overlays/          # Environment-specific configs
│   ├── helm/              # Helm charts
│   └── kustomization.yaml
├── terraform/             # 🌍 Infrastructure as Code
│   ├── modules/           # Reusable Terraform modules
│   ├── environments/      # Environment-specific configs
│   └── main.tf            # Root configuration
├── ansible/               # 🔧 Configuration management
│   ├── playbooks/         # Ansible playbooks
│   ├── roles/             # Ansible roles
│   └── inventory/         # Inventory files
├── monitoring/            # 📊 Observability stack
│   ├── prometheus/        # Metrics collection
│   ├── grafana/           # Dashboards
│   ├── loki/              # Log aggregation
│   └── alertmanager/      # Alert management
├── ci-cd/                 # 🚀 CI/CD pipelines
│   ├── github-actions/    # GitHub Actions workflows
│   ├── jenkins/           # Jenkins pipelines
│   └── gitlab-ci.yml      # GitLab CI/CD
├── security/              # 🔒 Security tools
│   ├── trivy/             # Container scanning
│   ├── falco/             # Runtime security
│   └── vault/             # Secret management
├── backup/                # 💾 Backup solutions
│   ├── postgresql/        # Database backups
│   ├── velero/            # Kubernetes backups
│   └── scripts/           # Backup automation
└── scripts/               # 🛠️ Utility scripts
    ├── deploy.sh          # Deployment script
    ├── backup.sh          # Backup script
    └── monitoring.sh      # Monitoring setup
```

## 🚀 Quick Deployment

### Local Development

```bash
# Start complete stack with Docker Compose
cd infrastructure/docker
docker-compose up -d

# Or use the convenience script
./infrastructure/scripts/deploy.sh local
```

### Production Deployment

```bash
# Deploy to Kubernetes with Helm
cd infrastructure/kubernetes/helm
helm install sky-genesis ./sky-genesis

# Or use Terraform for full infrastructure
cd infrastructure/terraform
terraform init
terraform plan
terraform apply
```

## 🏗️ Infrastructure Components

### Containerization (Docker)

- **Multi-stage builds** for optimized images
- **Security scanning** with Trivy
- **Development** and **production** configurations
- **Docker Compose** for local development

### Orchestration (Kubernetes)

- **Helm charts** for easy deployment
- **Kustomize** for environment management
- **Horizontal Pod Autoscaling** (HPA)
- **ConfigMaps** and **Secrets** management
- **Network policies** for security

### Infrastructure as Code (Terraform)

- **Modular architecture** with reusable components
- **Multi-environment** support (dev/staging/prod)
- **State management** with remote backends
- **Provider integrations** (AWS, GCP, Azure)

### Configuration Management (Ansible)

- **Server provisioning** and configuration
- **Application deployment** automation
- **Security hardening** playbooks
- **Inventory management** for multiple environments

### Monitoring & Observability

- **Prometheus** for metrics collection
- **Grafana** for visualization
- **Loki** for log aggregation
- **AlertManager** for notifications
- **Custom dashboards** for application metrics

### CI/CD Pipelines

- **GitHub Actions** for cloud-native CI/CD
- **Jenkins** for enterprise environments
- **GitLab CI** for self-hosted solutions
- **Automated testing** and deployment
- **Security scanning** integration

### Security

- **Container scanning** with Trivy
- **Runtime security** with Falco
- **Secret management** with Vault
- **Network policies** and security contexts
- **Compliance** automation

### Backup & Recovery

- **Database backups** with pg_dump
- **Kubernetes backups** with Velero
- **Automated scheduling** with cron
- **Point-in-time recovery** capabilities

## 🌍 Environment Management

### Development Environment

```bash
# Quick local setup
make dev-setup

# Start all services
make dev-up

# Run tests
make test

# Clean up
make dev-down
```

### Staging Environment

```bash
# Deploy to staging
make staging-deploy

# Run integration tests
make staging-test

# Rollback if needed
make staging-rollback
```

### Production Environment

```bash
# Production deployment
make prod-deploy

# Health checks
make prod-health

# Monitoring
make prod-monitor
```

## 🔧 Configuration Management

### Environment Variables

All configurations use environment variables for flexibility:

```bash
# Application
APP_ENV=production
APP_PORT=8080
APP_DEBUG=false

# Database
DB_HOST=postgresql.service.consul
DB_PORT=5432
DB_NAME=api_service
DB_SSL_MODE=require

# External Services
VAULT_ADDR=https://vault.company.com
KEYCLOAK_URL=https://auth.company.com
REDIS_URL=redis://redis.service.consul:6379

# Monitoring
PROMETHEUS_URL=http://prometheus.monitoring.svc
GRAFANA_URL=http://grafana.monitoring.svc
```

### Secrets Management

Sensitive data is managed through Vault:

```hcl
# Vault secrets structure
secret/skygenesisenterprise/
├── database/
│   ├── username
│   ├── password
│   └── ssl_cert
├── keycloak/
│   ├── client_secret
│   └── admin_token
└── certificates/
    ├── api_cert
    └── api_key
```

## 📊 Monitoring & Alerting

### Key Metrics

- **Application Performance**: Response times, throughput, error rates
- **Infrastructure**: CPU, memory, disk usage, network I/O
- **Business Metrics**: API calls, active users, certificate usage
- **Security**: Failed authentications, suspicious activities

### Alert Rules

```yaml
# Example Prometheus alerting rules
groups:
  - name: sky-genesis
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"

      - alert: CertificateExpiry
        expr: certificate_expiry_days < 30
        labels:
          severity: warning
        annotations:
          summary: "Certificate expiring soon"
```

## 🔒 Security Best Practices

### Container Security

- **Non-root users** in containers
- **Minimal base images** (Alpine Linux)
- **No secrets in images** (use Vault)
- **Regular security scanning**

### Network Security

- **Network policies** in Kubernetes
- **TLS everywhere** (cert-manager)
- **Service mesh** (Istio/Linkerd)
- **Zero-trust architecture**

### Access Control

- **RBAC** in Kubernetes
- **Least privilege** principle
- **Multi-factor authentication**
- **Audit logging** for all access

## 🚀 Deployment Strategies

### Blue-Green Deployment

```bash
# Deploy new version alongside old
kubectl apply -f blue-deployment.yaml

# Switch traffic to new version
kubectl patch service sky-genesis -p '{"spec":{"selector":{"version":"blue"}}}'

# Verify and cleanup
kubectl delete -f green-deployment.yaml
```

### Canary Deployment

```bash
# Deploy canary version
kubectl apply -f canary-deployment.yaml

# Route 10% of traffic to canary
kubectl apply -f canary-service.yaml

# Monitor and promote or rollback
kubectl apply -f production-service.yaml
```

### Rolling Updates

```bash
# Zero-downtime rolling update
kubectl set image deployment/sky-genesis api=sky-genesis:v2.0.0
kubectl rollout status deployment/sky-genesis
```

## 📈 Scaling Strategies

### Horizontal Pod Autoscaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: sky-genesis-api
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: sky-genesis-api
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

### Cluster Autoscaling

```hcl
# Terraform AWS example
resource "aws_eks_node_group" "sky_genesis" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "sky-genesis-nodes"
  instance_types  = ["t3.medium"]

  scaling_config {
    min_size     = 3
    max_size     = 10
    desired_size = 5
  }
}
```

## 🛠️ Maintenance & Operations

### Backup Strategy

```bash
# Daily database backup
0 2 * * * /usr/local/bin/backup-postgres.sh

# Weekly Kubernetes backup
0 3 * * 0 /usr/local/bin/backup-k8s.sh

# Monthly disaster recovery test
0 4 1 * * /usr/local/bin/dr-test.sh
```

### Log Management

```yaml
# Fluent Bit configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
data:
  fluent-bit.conf: |
    [INPUT]
        Name tail
        Path /var/log/containers/*sky-genesis*.log
        Parser docker

    [OUTPUT]
        Name loki
        Match *
        Url http://loki.monitoring.svc:3100/loki/api/v1/push
```

## 📚 Documentation Links

- [Docker Setup](./docker/README.md)
- [Kubernetes Deployment](./kubernetes/README.md)
- [Terraform Infrastructure](./terraform/README.md)
- [Ansible Configuration](./ansible/README.md)
- [Monitoring Guide](./monitoring/README.md)
- [CI/CD Pipelines](./ci-cd/README.md)
- [Security Guidelines](./security/README.md)
- [Backup Procedures](./backup/README.md)

## 🤝 Contributing

When contributing to infrastructure:

1. **Test locally** before committing
2. **Update documentation** for any changes
3. **Use infrastructure as code** principles
4. **Follow security best practices**
5. **Test in staging** before production

## 🆘 Troubleshooting

### Common Issues

- **Port conflicts**: Check `netstat -tlnp | grep 8080`
- **Permission denied**: Ensure proper RBAC configuration
- **Certificate errors**: Verify cert-manager and issuers
- **Pod crashes**: Check logs with `kubectl logs <pod-name>`

### Debug Commands

```bash
# Check pod status
kubectl get pods -n sky-genesis

# View logs
kubectl logs -f deployment/sky-genesis-api

# Check services
kubectl get svc -n sky-genesis

# Debug network issues
kubectl exec -it <pod-name> -- curl localhost:8080/health
```

---

**🏭 Production-Ready Infrastructure • 🔒 Secure by Design • 🚀 Cloud-Native**