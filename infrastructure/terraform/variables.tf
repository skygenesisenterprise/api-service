# ================================
# Terraform Variables
# ================================

# ================================
# Environment Configuration
# ================================

variable "environment" {
  description = "Environment name (development, staging, production)"
  type        = string
  default     = "development"

  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production"
  }
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = "sky-genesis.com"
}

# ================================
# EKS Configuration
# ================================

variable "eks_cluster_version" {
  description = "Kubernetes version for EKS cluster"
  type        = string
  default     = "1.28"
}

variable "eks_node_min_size" {
  description = "Minimum number of nodes in EKS node group"
  type        = number
  default     = 1
}

variable "eks_node_max_size" {
  description = "Maximum number of nodes in EKS node group"
  type        = number
  default     = 10
}

variable "eks_node_desired_size" {
  description = "Desired number of nodes in EKS node group"
  type        = number
  default     = 3
}

# ================================
# Database Configuration
# ================================

variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.r6g.large"
}

variable "rds_backup_retention_period" {
  description = "Number of days to retain RDS backups"
  type        = number
  default     = 30
}

# ================================
# Cache Configuration
# ================================

variable "redis_node_type" {
  description = "Redis node instance type"
  type        = string
  default     = "cache.t3.micro"
}

variable "redis_num_cache_nodes" {
  description = "Number of Redis cache nodes"
  type        = number
  default     = 1
}

variable "redis_snapshot_retention_limit" {
  description = "Number of days to retain Redis snapshots"
  type        = number
  default     = 7
}

# ================================
# Storage Configuration
# ================================

variable "s3_backup_retention_days" {
  description = "Number of days to retain S3 backups"
  type        = number
  default     = 365
}

# ================================
# Monitoring Configuration
# ================================

variable "enable_monitoring" {
  description = "Enable monitoring and alerting"
  type        = bool
  default     = true
}

variable "enable_logging" {
  description = "Enable comprehensive logging"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 30
}

# ================================
# Security Configuration
# ================================

variable "enable_waf" {
  description = "Enable Web Application Firewall"
  type        = bool
  default     = true
}

variable "enable_shield" {
  description = "Enable AWS Shield protection"
  type        = bool
  default     = false
}

variable "enable_backup" {
  description = "Enable automated backups"
  type        = bool
  default     = true
}

# ================================
# Cost Optimization
# ================================

variable "enable_spot_instances" {
  description = "Enable spot instances for cost optimization"
  type        = bool
  default     = true
}

variable "reserved_instance_term" {
  description = "Term for reserved instances (1_year, 3_year)"
  type        = string
  default     = "1_year"
}

# ================================
# Tags
# ================================

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "sky-genesis"
}

variable "owner" {
  description = "Owner of the infrastructure"
  type        = string
  default     = "DevOps Team"
}

variable "cost_center" {
  description = "Cost center for billing"
  type        = string
  default     = "engineering"
}

# ================================
# Feature Flags
# ================================

variable "enable_vpc_endpoints" {
  description = "Enable VPC endpoints for AWS services"
  type        = bool
  default     = true
}

variable "enable_nat_gateway" {
  description = "Enable NAT gateway for private subnets"
  type        = bool
  default     = true
}

variable "enable_vpn_gateway" {
  description = "Enable VPN gateway for hybrid connectivity"
  type        = bool
  default     = false
}

variable "enable_flow_logs" {
  description = "Enable VPC flow logs"
  type        = bool
  default     = true
}

# ================================
# Compliance
# ================================

variable "enable_encryption" {
  description = "Enable encryption for data at rest"
  type        = bool
  default     = true
}

variable "enable_audit_logs" {
  description = "Enable audit logging for compliance"
  type        = bool
  default     = true
}

variable "data_retention_days" {
  description = "Number of days to retain data for compliance"
  type        = number
  default     = 2555  # 7 years
}

# ================================
# Multi-Cloud Configuration
# ================================

variable "primary_cloud_provider" {
  description = "Primary cloud provider (aws, gcp, azure)"
  type        = string
  default     = "aws"

  validation {
    condition     = contains(["aws", "gcp", "azure"], var.primary_cloud_provider)
    error_message = "Primary cloud provider must be one of: aws, gcp, azure"
  }
}

variable "enable_multi_cloud" {
  description = "Enable multi-cloud deployment"
  type        = bool
  default     = false
}

variable "secondary_cloud_provider" {
  description = "Secondary cloud provider for disaster recovery"
  type        = string
  default     = "gcp"
}

# ================================
# CI/CD Configuration
# ================================

variable "ci_cd_provider" {
  description = "CI/CD provider (github, gitlab, jenkins)"
  type        = string
  default     = "github"

  validation {
    condition     = contains(["github", "gitlab", "jenkins"], var.ci_cd_provider)
    error_message = "CI/CD provider must be one of: github, gitlab, jenkins"
  }
}

variable "enable_ci_cd" {
  description = "Enable CI/CD pipeline deployment"
  type        = bool
  default     = true
}

# ================================
# Network Configuration
# ================================

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "public_subnets" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

variable "private_subnets" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

# ================================
# Application Configuration
# ================================

variable "api_port" {
  description = "Port for API service"
  type        = number
  default     = 8080
}

variable "frontend_port" {
  description = "Port for frontend service"
  type        = number
  default     = 3000
}

variable "enable_ssl" {
  description = "Enable SSL/TLS for all services"
  type        = bool
  default     = true
}

variable "ssl_certificate_arn" {
  description = "ARN of SSL certificate (leave empty for auto-generation)"
  type        = string
  default     = ""
}

# ================================
# Database Advanced Configuration
# ================================

variable "database_name" {
  description = "Name of the database"
  type        = string
  default     = "api_service"
}

variable "database_username" {
  description = "Database username"
  type        = string
  default     = "sky_genesis"
  sensitive   = true
}

variable "database_port" {
  description = "Database port"
  type        = number
  default     = 5432
}

# ================================
# Cache Advanced Configuration
# ================================

variable "cache_port" {
  description = "Cache service port"
  type        = number
  default     = 6379
}

variable "cache_engine" {
  description = "Cache engine (redis, memcached)"
  type        = string
  default     = "redis"
}

# ================================
# Load Balancer Configuration
# ================================

variable "alb_idle_timeout" {
  description = "ALB idle timeout in seconds"
  type        = number
  default     = 60
}

variable "alb_enable_deletion_protection" {
  description = "Enable deletion protection for ALB"
  type        = bool
  default     = true
}

variable "alb_enable_http2" {
  description = "Enable HTTP/2 for ALB"
  type        = bool
  default     = true
}

# ================================
# CDN Configuration
# ================================

variable "cloudfront_price_class" {
  description = "CloudFront price class"
  type        = string
  default     = "PriceClass_100"

  validation {
    condition = contains([
      "PriceClass_All",
      "PriceClass_200",
      "PriceClass_100"
    ], var.cloudfront_price_class)
    error_message = "CloudFront price class must be one of: PriceClass_All, PriceClass_200, PriceClass_100"
  }
}

variable "cloudfront_min_ttl" {
  description = "Minimum TTL for CloudFront cache"
  type        = number
  default     = 0
}

variable "cloudfront_default_ttl" {
  description = "Default TTL for CloudFront cache"
  type        = number
  default     = 86400
}

variable "cloudfront_max_ttl" {
  description = "Maximum TTL for CloudFront cache"
  type        = number
  default     = 31536000
}

# ================================
# Backup Configuration
# ================================

variable "backup_schedule" {
  description = "Cron schedule for backups"
  type        = string
  default     = "0 2 * * *"  # Daily at 2 AM
}

variable "backup_retention_count" {
  description = "Number of backups to retain"
  type        = number
  default     = 30
}

# ================================
# Alerting Configuration
# ================================

variable "alert_email" {
  description = "Email address for alerts"
  type        = string
  default     = ""
}

variable "alert_slack_webhook" {
  description = "Slack webhook URL for alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "alert_pagerduty_integration_key" {
  description = "PagerDuty integration key"
  type        = string
  default     = ""
  sensitive   = true
}

# ================================
# Performance Configuration
# ================================

variable "enable_performance_insights" {
  description = "Enable RDS Performance Insights"
  type        = bool
  default     = true
}

variable "enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring for RDS"
  type        = bool
  default     = true
}

variable "monitoring_interval" {
  description = "Monitoring interval in seconds"
  type        = number
  default     = 60
}

# ================================
# Scaling Configuration
# ================================

variable "autoscaling_enabled" {
  description = "Enable autoscaling for services"
  type        = bool
  default     = true
}

variable "min_capacity" {
  description = "Minimum capacity for autoscaling"
  type        = number
  default     = 1
}

variable "max_capacity" {
  description = "Maximum capacity for autoscaling"
  type        = number
  default     = 10
}

variable "target_cpu_utilization" {
  description = "Target CPU utilization for autoscaling"
  type        = number
  default     = 70
}

variable "scale_in_cooldown" {
  description = "Cooldown period for scale-in actions"
  type        = number
  default     = 300
}

variable "scale_out_cooldown" {
  description = "Cooldown period for scale-out actions"
  type        = number
  default     = 60
}