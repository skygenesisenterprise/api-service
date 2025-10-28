# ================================
# Sky Genesis Infrastructure
# ================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "~> 1.14"
    }
  }

  # Remote state configuration (uncomment and configure for production)
  # backend "s3" {
  #   bucket         = "sky-genesis-terraform-state"
  #   key            = "terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "sky-genesis-terraform-locks"
  # }
}

# ================================
# Local Variables
# ================================

locals {
  name        = "sky-genesis"
  environment = var.environment
  region      = var.aws_region

  common_tags = {
    Project     = "Sky Genesis"
    Environment = local.environment
    ManagedBy   = "Terraform"
    Owner       = "DevOps Team"
  }

  # CIDR blocks
  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
}

# ================================
# Data Sources
# ================================

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# ================================
# VPC Infrastructure
# ================================

module "vpc" {
  source = "./modules/vpc"

  name = "${local.name}-${local.environment}"
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 4)]

  enable_nat_gateway   = true
  single_nat_gateway   = local.environment == "development"
  enable_dns_hostnames = true
  enable_dns_support   = true

  # VPC Flow Logs
  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true

  # Tags
  tags = merge(local.common_tags, {
    Name = "${local.name}-vpc"
  })

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# ================================
# Security Groups
# ================================

resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "${local.name}-vpc-endpoints-"
  description = "Security group for VPC endpoints"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name}-vpc-endpoints"
  })
}

# ================================
# VPC Endpoints
# ================================

module "vpc_endpoints" {
  source = "./modules/vpc-endpoints"

  vpc_id             = module.vpc.vpc_id
  security_group_ids = [aws_security_group.vpc_endpoints.id]
  subnet_ids         = module.vpc.private_subnets

  endpoints = {
    s3 = {
      service             = "s3"
      private_dns_enabled = true
      tags = {
        Name = "${local.name}-s3"
      }
    }
    dynamodb = {
      service             = "dynamodb"
      private_dns_enabled = true
      tags = {
        Name = "${local.name}-dynamodb"
      }
    }
    ecr_api = {
      service             = "ecr.api"
      private_dns_enabled = true
      tags = {
        Name = "${local.name}-ecr-api"
      }
    }
    ecr_dkr = {
      service             = "ecr.dkr"
      private_dns_enabled = true
      tags = {
        Name = "${local.name}-ecr-dkr"
      }
    }
    logs = {
      service             = "logs"
      private_dns_enabled = true
      tags = {
        Name = "${local.name}-logs"
      }
    }
  }

  tags = local.common_tags
}

# ================================
# EKS Cluster
# ================================

module "eks" {
  source = "./modules/eks"

  cluster_name    = "${local.name}-${local.environment}"
  cluster_version = var.eks_cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # EKS Managed Node Groups
  eks_managed_node_groups = {
    general = {
      name            = "general"
      instance_types  = ["t3.medium"]
      capacity_type   = "ON_DEMAND"
      min_size        = var.eks_node_min_size
      max_size        = var.eks_node_max_size
      desired_size    = var.eks_node_desired_size
      disk_size       = 50

      # Security
      create_security_group = false
      enable_monitoring     = true

      # Taints/Tolerations (optional)
      taints = []
      labels = {
        Environment = local.environment
        NodeGroup   = "general"
      }
    }

    # Spot instances for cost optimization (only in non-production)
    spot = local.environment != "production" ? {
      name            = "spot"
      instance_types  = ["t3.medium", "t3.large"]
      capacity_type   = "SPOT"
      min_size        = 0
      max_size        = 10
      desired_size    = 2
      disk_size       = 50

      create_security_group = false
      enable_monitoring     = true

      taints = []
      labels = {
        Environment = local.environment
        NodeGroup   = "spot"
      }
    } : {}
  }

  # EKS Add-ons
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent = true
    }
  }

  # Security
  enable_irsa = true

  # Encryption
  cluster_encryption_config = [
    {
      provider_key_arn = aws_kms_key.eks.arn
      resources        = ["secrets"]
    }
  ]

  # CloudWatch logging
  cloudwatch_log_group_retention_in_days = 30
  cluster_enabled_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

  tags = merge(local.common_tags, {
    Name = "${local.name}-eks"
  })
}

# ================================
# KMS Keys
# ================================

resource "aws_kms_key" "eks" {
  description             = "EKS cluster encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "${local.name}-eks-key"
  })
}

resource "aws_kms_key" "rds" {
  description             = "RDS database encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "${local.name}-rds-key"
  })
}

# ================================
# RDS Database
# ================================

module "rds" {
  source = "./modules/rds"

  identifier = "${local.name}-${local.environment}"

  # Engine configuration
  engine         = "aurora-postgresql"
  engine_version = "15.4"
  instance_class = var.rds_instance_class

  # Database configuration
  database_name = "api_service"
  username      = "sky_genesis"
  port          = 5432

  # Network configuration
  vpc_id               = module.vpc.vpc_id
  db_subnet_group_name = aws_db_subnet_group.this.name
  vpc_security_group_ids = [
    aws_security_group.rds.id
  ]

  # Backup configuration
  backup_retention_period = var.rds_backup_retention_period
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"

  # Monitoring
  enabled_cloudwatch_logs_exports = ["postgresql"]
  monitoring_interval            = 60
  monitoring_role_arn           = aws_iam_role.rds_enhanced_monitoring.arn

  # Performance Insights
  performance_insights_enabled = true
  performance_insights_kms_key_id = aws_kms_key.rds.arn

  # Encryption
  storage_encrypted = true
  kms_key_id       = aws_kms_key.rds.arn

  # High availability
  multi_az = local.environment == "production"

  tags = merge(local.common_tags, {
    Name = "${local.name}-rds"
  })
}

# RDS Subnet Group
resource "aws_db_subnet_group" "this" {
  name       = "${local.name}-${local.environment}"
  subnet_ids = module.vpc.private_subnets

  tags = merge(local.common_tags, {
    Name = "${local.name}-rds-subnet-group"
  })
}

# RDS Security Group
resource "aws_security_group" "rds" {
  name_prefix = "${local.name}-rds-"
  description = "Security group for RDS database"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name}-rds-sg"
  })
}

# RDS Enhanced Monitoring IAM Role
resource "aws_iam_role" "rds_enhanced_monitoring" {
  name = "${local.name}-rds-enhanced-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name}-rds-monitoring-role"
  })
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  role       = aws_iam_role.rds_enhanced_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# ================================
# ElastiCache (Redis)
# ================================

module "redis" {
  source = "./modules/redis"

  cluster_id      = "${local.name}-${local.environment}"
  engine_version  = "7.0"
  node_type       = var.redis_node_type
  num_cache_nodes = var.redis_num_cache_nodes

  # Network configuration
  vpc_id               = module.vpc.vpc_id
  subnet_ids          = module.vpc.private_subnets
  security_group_ids  = [aws_security_group.redis.id]

  # Backup configuration
  snapshot_retention_limit = var.redis_snapshot_retention_limit

  # Maintenance
  maintenance_window = "sun:05:00-sun:06:00"

  tags = merge(local.common_tags, {
    Name = "${local.name}-redis"
  })
}

# Redis Security Group
resource "aws_security_group" "redis" {
  name_prefix = "${local.name}-redis-"
  description = "Security group for Redis cluster"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name}-redis-sg"
  })
}

# ================================
# S3 Buckets
# ================================

module "s3_backups" {
  source = "./modules/s3"

  bucket = "${local.name}-backups-${local.environment}-${random_string.suffix.result}"

  # Versioning
  versioning = {
    enabled = true
  }

  # Encryption
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
      bucket_key_enabled = true
    }
  }

  # Lifecycle rules
  lifecycle_rule = [
    {
      id      = "backup_lifecycle"
      enabled = true

      transition = [
        {
          days          = 30
          storage_class = "STANDARD_IA"
        },
        {
          days          = 90
          storage_class = "GLACIER"
        }
      ]

      expiration = {
        days = var.s3_backup_retention_days
      }
    }
  ]

  # Public access block
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = merge(local.common_tags, {
    Name        = "${local.name}-backups"
    Purpose     = "Database and application backups"
  })
}

# Random suffix for S3 bucket names
resource "random_string" "suffix" {
  length  = 8
  lower   = true
  upper   = false
  numeric = true
  special = false
}

# ================================
# Application Load Balancer
# ================================

module "alb" {
  source = "./modules/alb"

  name    = "${local.name}-${local.environment}"
  vpc_id  = module.vpc.vpc_id
  subnets = module.vpc.public_subnets

  # Security groups
  security_groups = [aws_security_group.alb.id]

  # Target groups
  target_groups = {
    api = {
      name_prefix          = "api-"
      protocol            = "HTTP"
      port                = 8080
      target_type         = "ip"
      deregistration_delay = 30

      health_check = {
        enabled             = true
        healthy_threshold   = 2
        interval            = 30
        matcher             = "200"
        path                = "/health"
        port                = "traffic-port"
        protocol            = "HTTP"
        timeout             = 5
        unhealthy_threshold = 2
      }
    }

    frontend = {
      name_prefix          = "web-"
      protocol            = "HTTP"
      port                = 3000
      target_type         = "ip"
      deregistration_delay = 30

      health_check = {
        enabled             = true
        healthy_threshold   = 2
        interval            = 30
        matcher             = "200"
        path                = "/"
        port                = "traffic-port"
        protocol            = "HTTP"
        timeout             = 5
        unhealthy_threshold = 2
      }
    }
  }

  # HTTP to HTTPS redirect
  http_tcp_listeners = [
    {
      port               = 80
      protocol           = "HTTP"
      action_type        = "redirect"
      redirect = {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  ]

  # HTTPS listeners
  https_listeners = [
    {
      port               = 443
      protocol           = "HTTPS"
      certificate_arn    = aws_acm_certificate.this.arn
      action_type        = "forward"
      target_group_index = 0
    }
  ]

  # HTTPS listeners for frontend
  https_listener_rules = [
    {
      https_listener_index = 0
      priority             = 1

      actions = [
        {
          type               = "forward"
          target_group_index = 1
        }
      ]

      conditions = [
        {
          path_patterns = ["/", "/admin", "/api"]
        }
      ]
    }
  ]

  tags = merge(local.common_tags, {
    Name = "${local.name}-alb"
  })
}

# ALB Security Group
resource "aws_security_group" "alb" {
  name_prefix = "${local.name}-alb-"
  description = "Security group for Application Load Balancer"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name}-alb-sg"
  })
}

# ================================
# SSL Certificate
# ================================

resource "aws_acm_certificate" "this" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  subject_alternative_names = [
    "*.${var.domain_name}"
  ]

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name}-ssl-cert"
  })
}

# Route 53 validation records
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.this.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.this.zone_id
}

# Certificate validation
resource "aws_acm_certificate_validation" "this" {
  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# Route 53 zone data source
data "aws_route53_zone" "this" {
  name         = var.domain_name
  private_zone = false
}

# ================================
# CloudFront Distribution
# ================================

module "cloudfront" {
  source = "./modules/cloudfront"

  aliases = [var.domain_name, "api.${var.domain_name}"]

  comment             = "CloudFront distribution for ${local.name}"
  enabled             = true
  is_ipv6_enabled     = true
  price_class         = "PriceClass_100"
  retain_on_delete    = false
  wait_for_deployment = false

  # Origin configuration
  origin = {
    alb = {
      domain_name = module.alb.dns_name
      origin_id   = "alb-origin"

      custom_origin_config = {
        http_port              = 80
        https_port             = 443
        origin_protocol_policy = "https-only"
        origin_ssl_protocols   = ["TLSv1.2"]
      }
    }
  }

  # Default cache behavior
  default_cache_behavior = {
    target_origin_id       = "alb-origin"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods  = ["GET", "HEAD"]

    forwarded_values = {
      query_string = true
      cookies = {
        forward = "all"
      }
    }

    min_ttl     = 0
    default_ttl = 86400
    max_ttl     = 31536000
  }

  # Custom cache behaviors
  ordered_cache_behavior = [
    {
      path_pattern     = "/api/*"
      target_origin_id = "alb-origin"

      viewer_protocol_policy = "redirect-to-https"

      allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
      cached_methods  = ["GET", "HEAD"]

      forwarded_values = {
        query_string = true
        cookies = {
          forward = "all"
        }
      }

      min_ttl     = 0
      default_ttl = 0
      max_ttl     = 0
    }
  ]

  # WAF integration
  web_acl_id = aws_wafv2_web_acl.this.arn

  tags = merge(local.common_tags, {
    Name = "${local.name}-cloudfront"
  })
}

# ================================
# WAF (Web Application Firewall)
# ================================

resource "aws_wafv2_web_acl" "this" {
  name  = "${local.name}-${local.environment}"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # AWS Managed Rules
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled  = true
    }
  }

  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "AWSManagedRulesSQLiRuleSet"
      sampled_requests_enabled  = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled  = true
    }
  }

  # Rate limiting
  rule {
    name     = "RateLimit"
    priority = 4

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "RateLimit"
      sampled_requests_enabled  = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name               = "${local.name}-waf"
    sampled_requests_enabled  = true
  }
}

# ================================
# Route 53 Records
# ================================

resource "aws_route53_record" "cloudfront" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = module.cloudfront.cloudfront_distribution_domain_name
    zone_id               = module.cloudfront.cloudfront_distribution_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "api" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = "api.${var.domain_name}"
  type    = "A"

  alias {
    name                   = module.cloudfront.cloudfront_distribution_domain_name
    zone_id               = module.cloudfront.cloudfront_distribution_zone_id
    evaluate_target_health = false
  }
}

# ================================
# Outputs
# ================================

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "eks_cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "rds_endpoint" {
  description = "RDS database endpoint"
  value       = module.rds.db_instance_address
}

output "redis_endpoint" {
  description = "Redis cluster endpoint"
  value       = module.redis.elasticache_replication_group_primary_endpoint_address
}

output "alb_dns_name" {
  description = "Application Load Balancer DNS name"
  value       = module.alb.dns_name
}

output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name"
  value       = module.cloudfront.cloudfront_distribution_domain_name
}

output "s3_backup_bucket" {
  description = "S3 backup bucket name"
  value       = module.s3_backups.s3_bucket_id
}