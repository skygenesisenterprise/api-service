# 🌍 Terraform Infrastructure

Infrastructure as Code for Sky Genesis Enterprise API Service with multi-cloud support, automated provisioning, and GitOps-ready configurations.

## 📁 Structure

```
terraform/
├── modules/               # 🧩 Reusable modules
│   ├── vpc/              # Network infrastructure
│   ├── eks/              # Kubernetes cluster
│   ├── rds/              # Database instance
│   ├── s3/               # Object storage
│   ├── cloudfront/       # CDN distribution
│   └── waf/              # Web application firewall
├── environments/         # 🌍 Environment configs
│   ├── development/     # Development environment
│   ├── staging/         # Staging environment
│   └── production/      # Production environment
├── main.tf              # 🎯 Root configuration
├── variables.tf         # 📝 Input variables
├── outputs.tf           # 📤 Output values
├── providers.tf         # ☁️ Provider configurations
├── terraform.tfvars     # 🔒 Variable values
└── scripts/             # 🚀 Helper scripts
```

## 🚀 Quick Start

### Prerequisites

```bash
# Install Terraform
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install terraform

# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Configure AWS credentials
aws configure
```

### Initialize Infrastructure

```bash
# Clone infrastructure
cd infrastructure/terraform

# Initialize Terraform
terraform init

# Plan deployment
terraform plan -var-file=environments/development/terraform.tfvars

# Apply changes
terraform apply -var-file=environments/development/terraform.tfvars
```

### Environment Management

```bash
# Development
terraform workspace select development
terraform apply

# Staging
terraform workspace select staging
terraform apply

# Production
terraform workspace select production
terraform apply
```

## 🏗️ Architecture Overview

### AWS Infrastructure

```
┌─────────────────────────────────────────────────────────────┐
│                    🌐 CloudFront (CDN)                       │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                 🌐 Application Load Balancer         │    │
│  │  ┌─────────────────┐    ┌─────────────────┐          │    │
│  │  │   EKS Cluster   │    │   RDS Aurora    │          │    │
│  │  │  ┌─────────┐    │    │   PostgreSQL    │          │    │
│  │  │  │  Pods   │    │    │                 │          │    │
│  │  │  │  • API  │    │    └─────────────────┘          │    │
│  │  │  │  • Web  │    │    ┌─────────────────┐          │    │
│  │  │  └─────────┘    │    │   ElastiCache   │          │    │
│  │  └─────────────────┘    │     Redis       │          │    │
│  │                         └─────────────────┘          │    │
│  └─────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    🔒 Security Services              │    │
│  │  ┌─────────────────┐    ┌─────────────────┐          │    │
│  │  │   AWS WAF       │    │   AWS Shield    │          │    │
│  │  │                 │    │                 │          │    │
│  │  └─────────────────┘    └─────────────────┘          │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                                 │
┌─────────────────────────────────────────────────────────────┐
│                    💾 Storage & Backup                      │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────┐  │
│  │     S3          │    │   EFS/FSx       │    │  AWS    │  │
│  │   Backups       │    │   Persistent    │    │ Backup  │  │
│  │                 │    │   Storage       │    │         │  │
│  └─────────────────┘    └─────────────────┘    └─────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Multi-Cloud Support

The infrastructure supports multiple cloud providers:

- **AWS** (Primary): EKS, RDS, CloudFront, S3
- **GCP** (Alternative): GKE, Cloud SQL, Cloud Storage
- **Azure** (Alternative): AKS, Database, Blob Storage

## 📋 Core Components

### Network Infrastructure

```hcl
# VPC with multi-AZ setup
module "vpc" {
  source = "./modules/vpc"

  name = "sky-genesis"
  cidr = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = false
}
```

### Kubernetes Cluster

```hcl
# EKS cluster with managed node groups
module "eks" {
  source = "./modules/eks"

  cluster_name    = "sky-genesis"
  cluster_version = "1.28"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  node_groups = {
    general = {
      desired_capacity = 3
      max_capacity     = 10
      min_capacity     = 1

      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"
    }

    spot = {
      desired_capacity = 2
      max_capacity     = 20
      min_capacity     = 0

      instance_types = ["t3.medium", "t3.large"]
      capacity_type  = "SPOT"
    }
  }
}
```

### Database Infrastructure

```hcl
# Aurora PostgreSQL cluster
module "rds" {
  source = "./modules/rds"

  identifier = "sky-genesis"

  engine         = "aurora-postgresql"
  engine_version = "15.4"
  instance_class = "db.r6g.large"

  database_name = "api_service"
  username      = "sky_genesis"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  backup_retention_period = 30
  preferred_backup_window = "03:00-04:00"

  enabled_cloudwatch_logs_exports = ["postgresql"]
}
```

### Content Delivery Network

```hcl
# CloudFront distribution
module "cloudfront" {
  source = "./modules/cloudfront"

  aliases = ["api.sky-genesis.com", "app.sky-genesis.com"]

  origin = {
    api = {
      domain_name = module.alb.dns_name
      origin_id   = "api-origin"

      custom_origin_config = {
        http_port              = 80
        https_port             = 443
        origin_protocol_policy = "https-only"
        origin_ssl_protocols   = ["TLSv1.2"]
      }
    }
  }

  default_cache_behavior = {
    target_origin_id       = "api-origin"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods  = ["GET", "HEAD"]

    forwarded_values = {
      query_string = true
      cookies = {
        forward = "all"
      }
    }
  }
}
```

## 🔒 Security & Compliance

### Web Application Firewall

```hcl
module "waf" {
  source = "./modules/waf"

  name = "sky-genesis-waf"

  rules = [
    {
      name     = "AWSManagedRulesCommonRuleSet"
      priority = 1
      override_action = "none"
      visibility_config = {
        sampled_requests_enabled   = true
        cloudwatch_metrics_enabled = true
        metric_name               = "AWSManagedRulesCommonRuleSet"
      }
    },
    {
      name     = "AWSManagedRulesSQLiRuleSet"
      priority = 2
      override_action = "none"
      visibility_config = {
        sampled_requests_enabled   = true
        cloudwatch_metrics_enabled = true
        metric_name               = "AWSManagedRulesSQLiRuleSet"
      }
    }
  ]

  visibility_config = {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name               = "sky-genesis-waf"
  }
}
```

### Encryption at Rest

```hcl
# S3 bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.backups.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# RDS encryption
resource "aws_db_instance" "this" {
  storage_encrypted = true
  kms_key_id       = aws_kms_key.rds.arn
}

# EKS encryption
resource "aws_eks_cluster" "this" {
  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }
}
```

### Access Control

```hcl
# IAM roles with least privilege
resource "aws_iam_role" "eks_nodes" {
  name = "sky-genesis-eks-nodes"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Attach minimal policies
resource "aws_iam_role_policy_attachment" "eks_nodes" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  ])

  role       = aws_iam_role.eks_nodes.name
  policy_arn = each.value
}
```

## 📊 Monitoring & Observability

### CloudWatch Integration

```hcl
# CloudWatch alarms
resource "aws_cloudwatch_metric_alarm" "api_cpu" {
  alarm_name          = "sky-genesis-api-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

# CloudWatch logs
resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/sky-genesis/cluster"
  retention_in_days = 30
}
```

### X-Ray Tracing

```hcl
# X-Ray configuration
resource "aws_xray_sampling_rule" "api" {
  rule_name      = "sky-genesis-api"
  priority       = 10
  reservoir_size = 100
  fixed_rate     = 0.1
  url_path       = "/api/*"
  service_name   = "sky-genesis-api"
  service_type   = "AWS::EC2::Instance"
  host           = "*"
  http_method    = "*"

  version = 1
}
```

## 💾 Backup & Disaster Recovery

### Automated Backups

```hcl
# RDS automated backups
resource "aws_db_instance" "this" {
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"

  # Cross-region backup
  replicate_source_db = aws_db_instance.primary.id
}

# S3 backup bucket
resource "aws_s3_bucket" "backups" {
  bucket = "sky-genesis-backups-${var.environment}"

  versioning {
    enabled = true
  }

  lifecycle_rule {
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}
```

### Disaster Recovery

```hcl
# Multi-region setup
module "dr_region" {
  source = "./modules/vpc"
  providers = {
    aws = aws.dr
  }

  name = "sky-genesis-dr"
  # ... DR configuration
}

# Route 53 failover routing
resource "aws_route53_health_check" "primary" {
  fqdn              = "api.sky-genesis.com"
  port              = 443
  type              = "HTTPS"
  resource_path     = "/health"
  failure_threshold = "3"
  request_interval  = "30"
}

resource "aws_route53_record" "failover" {
  set_identifier = "primary"
  failover_routing_policy {
    type = "PRIMARY"
  }
}
```

## 🚀 Deployment Automation

### GitHub Actions CI/CD

```yaml
# .github/workflows/terraform.yml
name: 'Terraform'

on:
  push:
    branches: [ main ]
    paths: [ 'infrastructure/terraform/**' ]
  pull_request:
    branches: [ main ]
    paths: [ 'infrastructure/terraform/**' ]

jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3

    - name: Setup Terraform
      uses: hashicorp/setup-terraform@v2

    - name: Terraform Init
      run: terraform init
      working-directory: infrastructure/terraform

    - name: Terraform Format
      run: terraform fmt -check
      working-directory: infrastructure/terraform

    - name: Terraform Validate
      run: terraform validate
      working-directory: infrastructure/terraform

    - name: Terraform Plan
      run: terraform plan -no-color
      working-directory: infrastructure/terraform
```

### Atlantis for Pull Requests

```yaml
# atlantis.yaml
version: 3
projects:
- name: sky-genesis-infrastructure
  dir: infrastructure/terraform
  workspace: default
  terraform_version: v1.5.0
  apply_requirements: [approved]
  workflow: custom

workflows:
  custom:
    plan:
      steps:
      - init
      - plan
    apply:
      steps:
      - apply
```

## 📈 Cost Optimization

### Reserved Instances

```hcl
resource "aws_ec2_capacity_reservation" "this" {
  instance_type     = "t3.medium"
  instance_platform = "Linux/UNIX"
  availability_zone = "us-east-1a"

  instance_count = 5

  tags = {
    Name = "sky-genesis-reserved"
  }
}
```

### Spot Instances

```hcl
module "eks" {
  source = "./modules/eks"

  node_groups = {
    spot = {
      desired_capacity = 10
      max_capacity     = 50
      min_capacity     = 5

      instance_types = ["t3.medium", "t3.large", "m5.large"]
      capacity_type  = "SPOT"

      spot_allocation_strategy = "diversified"
    }
  }
}
```

### Auto Scaling

```hcl
resource "aws_appautoscaling_policy" "cpu" {
  name               = "cpu-autoscaling"
  service_namespace  = "ecs"
  resource_id        = "service/sky-genesis/sky-genesis-api"
  scalable_dimension = "ecs:service:DesiredCount"

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown               = 60
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_lower_bound = 0
      scaling_adjustment          = 1
    }
  }
}
```

## 🔧 Troubleshooting

### Common Issues

**State Lock Errors:**
```bash
# Force unlock (use with caution)
terraform force-unlock LOCK_ID

# Check state
terraform state list
terraform state show aws_instance.example
```

**Provider Issues:**
```bash
# Reinitialize providers
terraform init -upgrade

# Clear provider cache
rm -rf .terraform/providers
terraform init
```

**Resource Conflicts:**
```bash
# Import existing resources
terraform import aws_instance.example i-1234567890abcdef0

# Remove from state
terraform state rm aws_instance.example
```

### Debug Commands

```bash
# Enable debug logging
export TF_LOG=DEBUG

# Show current state
terraform show

# Graph dependencies
terraform graph | dot -Tsvg > graph.svg

# Validate syntax
terraform validate

# Format code
terraform fmt -recursive
```

## 📚 Additional Resources

- [Terraform Documentation](https://www.terraform.io/docs)
- [AWS Provider Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Terraform Best Practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)
- [Infrastructure as Code](https://www.terraform.io/docs/language/index.html)

---

**🌍 Cloud-Native • 🔒 Secure • 🚀 Automated**