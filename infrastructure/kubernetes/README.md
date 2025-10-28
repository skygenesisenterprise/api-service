# ☸️ Kubernetes Infrastructure

Production-ready Kubernetes deployment for Sky Genesis Enterprise API Service with Helm charts, Kustomize overlays, and GitOps-ready configurations.

## 📁 Structure

```
kubernetes/
├── base/                  # 🏗️ Base configurations
│   ├── api/              # API service manifests
│   ├── frontend/         # Frontend service manifests
│   ├── database/         # PostgreSQL manifests
│   └── monitoring/       # Monitoring manifests
├── overlays/             # 🌍 Environment overlays
│   ├── development/     # Development environment
│   ├── staging/         # Staging environment
│   └── production/      # Production environment
├── helm/                 # ⎈ Helm charts
│   ├── sky-genesis/     # Main application chart
│   ├── database/        # PostgreSQL chart
│   └── monitoring/      # Monitoring stack chart
├── kustomization.yaml   # 🎯 Root kustomization
└── scripts/             # 🚀 Deployment scripts
```

## 🚀 Quick Start

### Using Helm (Recommended)

```bash
# Add Helm repository
helm repo add sky-genesis https://charts.sky-genesis.com
helm repo update

# Install with default values
helm install sky-genesis sky-genesis/sky-genesis

# Install with custom values
helm install sky-genesis sky-genesis/sky-genesis \
  --values values.production.yaml \
  --namespace sky-genesis \
  --create-namespace
```

### Using Kustomize

```bash
# Development environment
kubectl apply -k infrastructure/kubernetes/overlays/development

# Production environment
kubectl apply -k infrastructure/kubernetes/overlays/production
```

### Manual Deployment

```bash
# Create namespace
kubectl create namespace sky-genesis

# Apply base configurations
kubectl apply -f infrastructure/kubernetes/base/

# Apply environment overlay
kubectl apply -f infrastructure/kubernetes/overlays/production/
```

## ⎈ Helm Charts

### Main Application Chart

```yaml
# values.yaml
api:
  image:
    repository: sky-genesis/api
    tag: "latest"
    pullPolicy: IfNotPresent

  replicaCount: 3

  service:
    type: ClusterIP
    port: 8080

  resources:
    limits:
      cpu: 1000m
      memory: 1Gi
    requests:
      cpu: 500m
      memory: 512Mi

  env:
    - name: DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: sky-genesis-secrets
          key: database-url
    - name: JWT_SECRET
      valueFrom:
        secretKeyRef:
          name: sky-genesis-secrets
          key: jwt-secret

frontend:
  image:
    repository: sky-genesis/frontend
    tag: "latest"
    pullPolicy: IfNotPresent

  replicaCount: 2

  service:
    type: ClusterIP
    port: 3000

  ingress:
    enabled: true
    className: "nginx"
    hosts:
      - host: app.sky-genesis.com
        paths:
          - path: /
            pathType: Prefix

database:
  enabled: true
  postgresql:
    image:
      tag: "15"
    auth:
      database: api_service
      username: sky_genesis
      password: ""  # Use secret
    metrics:
      enabled: true
```

### Installation Commands

```bash
# Dry run to validate
helm template sky-genesis ./infrastructure/kubernetes/helm/sky-genesis \
  --values values.production.yaml

# Install with wait
helm install sky-genesis ./infrastructure/kubernetes/helm/sky-genesis \
  --values values.production.yaml \
  --wait \
  --timeout 600s

# Upgrade
helm upgrade sky-genesis ./infrastructure/kubernetes/helm/sky-genesis \
  --values values.production.yaml

# Rollback
helm rollback sky-genesis 1

# Uninstall
helm uninstall sky-genesis
```

## 🎯 Kustomize Overlays

### Development Overlay

```yaml
# overlays/development/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: sky-genesis-dev

resources:
  - ../../base

patchesStrategicMerge:
  - api-deployment.yaml
  - frontend-deployment.yaml

images:
  - name: sky-genesis/api
    newTag: dev
  - name: sky-genesis/frontend
    newTag: dev

configMapGenerator:
  - name: api-config
    literals:
      - APP_ENV=development
      - LOG_LEVEL=debug
```

### Production Overlay

```yaml
# overlays/production/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: sky-genesis-prod

resources:
  - ../../base

patchesStrategicMerge:
  - api-deployment.yaml
  - frontend-deployment.yaml
  - ingress.yaml

images:
  - name: sky-genesis/api
    newTag: v1.2.3
  - name: sky-genesis/frontend
    newTag: v1.2.3

configMapGenerator:
  - name: api-config
    literals:
      - APP_ENV=production
      - LOG_LEVEL=info

secretGenerator:
  - name: sky-genesis-secrets
    type: Opaque
    literals:
      - database-url=postgresql://...
      - jwt-secret=...
      - vault-token=...
```

## 📊 Monitoring & Observability

### Prometheus ServiceMonitor

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: sky-genesis-api
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: sky-genesis-api
  endpoints:
  - port: metrics
    path: /metrics
    interval: 30s
```

### Grafana Dashboards

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sky-genesis-dashboard
  namespace: monitoring
  labels:
    grafana_dashboard: "1"
data:
  sky-genesis.json: |
    {
      "dashboard": {
        "title": "Sky Genesis API",
        "panels": [
          {
            "title": "API Response Time",
            "type": "graph",
            "targets": [
              {
                "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job=\"sky-genesis-api\"}[5m]))",
                "legendFormat": "95th percentile"
              }
            ]
          }
        ]
      }
    }
```

## 🔒 Security

### Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sky-genesis-api
  namespace: sky-genesis
spec:
  podSelector:
    matchLabels:
      app: sky-genesis-api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: sky-genesis-frontend
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: sky-genesis-postgres
    ports:
    - protocol: TCP
      port: 5432
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
```

### Pod Security Standards

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: sky-genesis-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  runAsUser:
    rule: MustRunAsNonRoot
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: MustRunAs
    ranges:
    - min: 1
      max: 65535
  fsGroup:
    rule: MustRunAs
    ranges:
    - min: 1
      max: 65535
  volumes:
  - configMap
  - downwardAPI
  - emptyDir
  - persistentVolumeClaim
  - secret
  - projected
```

### RBAC Configuration

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: sky-genesis
  name: sky-genesis-api
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sky-genesis-api
  namespace: sky-genesis
subjects:
- kind: ServiceAccount
  name: sky-genesis-api
  namespace: sky-genesis
roleRef:
  kind: Role
  name: sky-genesis-api
  apiGroup: rbac.authorization.k8s.io
```

## 🚀 Deployment Strategies

### Rolling Updates

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sky-genesis-api
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  template:
    spec:
      containers:
      - name: api
        image: sky-genesis/api:v1.2.3
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 1000m
            memory: 1Gi
```

### Blue-Green Deployment

```bash
# Create blue deployment
kubectl apply -f blue-deployment.yaml

# Switch service selector
kubectl patch service sky-genesis-api \
  -p '{"spec":{"selector":{"version":"blue"}}}'

# Verify and cleanup
kubectl delete -f green-deployment.yaml
```

### Canary Deployment

```yaml
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: sky-genesis-api
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: sky-genesis-api
  service:
    port: 8080
    targetPort: 8080
  analysis:
    interval: 30s
    threshold: 5
    stepWeight: 10
    metrics:
    - name: request-success-rate
      thresholdRange:
        min: 99
      interval: 1m
    - name: request-duration
      thresholdRange:
        max: 500
      interval: 30s
```

## 📈 Scaling

### Horizontal Pod Autoscaler

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
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Cluster Autoscaler (AWS)

```yaml
apiVersion: karpenter.sh/v1alpha5
kind: Provisioner
metadata:
  name: sky-genesis
spec:
  requirements:
    - key: karpenter.sh/capacity-type
      operator: In
      values: ["on-demand"]
    - key: node.kubernetes.io/instance-type
      operator: In
      values: ["t3.medium", "t3.large", "m5.large"]
  limits:
    resources:
      cpu: 1000
      memory: 1000Gi
  provider:
    instanceProfile: KarpenterInstanceProfile
    subnetSelector:
      karpenter.sh/discovery: "sky-genesis"
    securityGroupSelector:
      karpenter.sh/discovery: "sky-genesis"
```

## 💾 Storage

### Persistent Volumes

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
  storageClassName: gp3
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redis-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: gp3
```

### Backup with Velero

```yaml
apiVersion: velero.io/v1
kind: Backup
metadata:
  name: sky-genesis-daily
  namespace: velero
spec:
  includedNamespaces:
  - sky-genesis
  includedResources:
  - persistentvolumeclaims
  - persistentvolumes
  - secrets
  - configmaps
  storageLocation: aws-s3
  ttl: 720h0m0s
  schedule: "0 2 * * *"
```

## 🔧 Troubleshooting

### Common Issues

**Pods not starting:**
```bash
# Check pod status
kubectl get pods -n sky-genesis

# View pod logs
kubectl logs -f deployment/sky-genesis-api -n sky-genesis

# Describe pod for events
kubectl describe pod <pod-name> -n sky-genesis
```

**Service not accessible:**
```bash
# Check service endpoints
kubectl get endpoints -n sky-genesis

# Test service connectivity
kubectl run test --image=busybox --rm -it --restart=Never \
  -- nslookup sky-genesis-api.sky-genesis.svc.cluster.local
```

**Database connection issues:**
```bash
# Check database pod
kubectl logs -f deployment/sky-genesis-postgres -n sky-genesis

# Test database connectivity
kubectl exec -it deployment/sky-genesis-api -n sky-genesis -- \
  pg_isready -h sky-genesis-postgres -U sky_genesis
```

### Debug Commands

```bash
# Get all resources in namespace
kubectl get all -n sky-genesis

# View cluster events
kubectl get events -n sky-genesis --sort-by=.metadata.creationTimestamp

# Check resource usage
kubectl top pods -n sky-genesis

# Debug with temporary pod
kubectl run debug --image=busybox --rm -it --restart=Never \
  -- nslookup sky-genesis-api.sky-genesis.svc.cluster.local
```

## 📚 Additional Resources

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Helm Documentation](https://helm.sh/docs/)
- [Kustomize Documentation](https://kubectl.docs.kubernetes.io/references/kustomize/)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)

---

**☸️ Production-Ready • 🔒 Secure • 🚀 Scalable**