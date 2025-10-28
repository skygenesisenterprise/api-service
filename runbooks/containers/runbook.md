# Containers Runbook

## Overview
This runbook covers container management for the Sky Genesis Enterprise API Service using Docker and Kubernetes.

## Docker Images

### Building Images
```bash
# Build API image
docker build -f infrastructure/docker/Dockerfile.api -t api-service:latest .

# Build frontend image
docker build -f infrastructure/docker/Dockerfile.frontend -t frontend-service:latest .
```

### Running Locally
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Kubernetes Deployment

### Prerequisites
- kubectl configured
- Access to Kubernetes cluster

### Deploying
```bash
# Apply base configurations
kubectl apply -f infrastructure/kubernetes/base/

# Check pod status
kubectl get pods

# View logs
kubectl logs -f deployment/api-service
```

### Scaling
```bash
# Scale API deployment
kubectl scale deployment api-service --replicas=3

# Autoscale based on CPU
kubectl autoscale deployment api-service --cpu-percent=70 --min=1 --max=10
```

## Troubleshooting

### Common Issues
1. **Image pull failures**: Check registry credentials
2. **Pod crashes**: Check logs with `kubectl logs`
3. **Resource limits**: Adjust resource requests/limits in YAML

### Health Checks
- Readiness probes: `/health/ready`
- Liveness probes: `/health/live`

## Security
- Scan images for vulnerabilities before deployment
- Use non-root users in containers
- Regularly update base images