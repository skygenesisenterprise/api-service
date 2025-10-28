# ================================
# Terraform Providers Configuration
# ================================

# ================================
# AWS Provider
# ================================

terraform {
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
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# AWS Provider Configuration
provider "aws" {
  region = var.aws_region

  # Default tags applied to all resources
  default_tags {
    tags = merge({
      Environment = var.environment
      Project     = var.project_name
      Owner       = var.owner
      CostCenter  = var.cost_center
      ManagedBy   = "Terraform"
    }, var.tags)
  }

  # Assume role for cross-account access (optional)
  # assume_role {
  #   role_arn     = "arn:aws:iam::123456789012:role/TerraformRole"
  #   session_name = "terraform-session"
  # }

  # Retry configuration
  retry_mode      = "adaptive"
  max_retries     = 3
}

# AWS Provider for secondary region (DR)
provider "aws" {
  alias  = "dr"
  region = var.dr_region != "" ? var.dr_region : "${var.aws_region}-dr"

  default_tags {
    tags = merge({
      Environment = var.environment
      Project     = var.project_name
      Owner       = var.owner
      CostCenter  = var.cost_center
      ManagedBy   = "Terraform"
      Purpose     = "Disaster Recovery"
    }, var.tags)
  }
}

# ================================
# Kubernetes Provider
# ================================

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      module.eks.cluster_name
    ]
  }
}

# Kubernetes provider for DR region
provider "kubernetes" {
  alias                  = "dr"
  host                   = module.eks_dr.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_dr.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "--region",
      var.dr_region,
      "eks",
      "get-token",
      "--cluster-name",
      module.eks_dr.cluster_name
    ]
  }
}

# ================================
# Helm Provider
# ================================

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = [
        "eks",
        "get-token",
        "--cluster-name",
        module.eks.cluster_name
      ]
    }
  }
}

# Helm provider for DR region
provider "helm" {
  alias = "dr"
  kubernetes {
    host                   = module.eks_dr.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_dr.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = [
        "--region",
        var.dr_region,
        "eks",
        "get-token",
        "--cluster-name",
        module.eks_dr.cluster_name
      ]
    }
  }
}

# ================================
# Kubectl Provider
# ================================

provider "kubectl" {
  apply_retry_count      = 5
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      module.eks.cluster_name
    ]
  }
}

# ================================
# Random Provider
# ================================

provider "random" {}

# ================================
# TLS Provider
# ================================

provider "tls" {}

# ================================
# External Providers (Optional)
# ================================

# Google Cloud Provider (for multi-cloud)
provider "google" {
  count  = var.enable_multi_cloud && var.secondary_cloud_provider == "gcp" ? 1 : 0
  project = var.gcp_project_id
  region  = var.gcp_region
}

# Azure Provider (for multi-cloud)
provider "azurerm" {
  count = var.enable_multi_cloud && var.secondary_cloud_provider == "azure" ? 1 : 0

  features {}

  subscription_id = var.azure_subscription_id
  tenant_id       = var.azure_tenant_id
}

# ================================
# Backend Configuration
# ================================

# S3 Backend for state management (uncomment and configure)
# terraform {
#   backend "s3" {
#     bucket         = "sky-genesis-terraform-state"
#     key            = "terraform.tfstate"
#     region         = "us-east-1"
#     encrypt        = true
#     dynamodb_table = "sky-genesis-terraform-locks"
#     kms_key_id     = "alias/terraform-bucket-key"
#   }
# }

# GCS Backend (alternative for Google Cloud)
# terraform {
#   backend "gcs" {
#     bucket = "sky-genesis-terraform-state"
#     prefix = "terraform/state"
#   }
# }

# Azure Backend (alternative for Azure)
# terraform {
#   backend "azurerm" {
#     resource_group_name  = "terraform-state"
#     storage_account_name = "skygenesisterraform"
#     container_name       = "tfstate"
#     key                  = "terraform.tfstate"
#   }
# }

# ================================
# Required Variables for Providers
# ================================

variable "dr_region" {
  description = "Disaster recovery region"
  type        = string
  default     = ""
}

variable "gcp_project_id" {
  description = "Google Cloud Project ID"
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "Google Cloud region"
  type        = string
  default     = "us-central1"
}

variable "azure_subscription_id" {
  description = "Azure subscription ID"
  type        = string
  default     = ""
}

variable "azure_tenant_id" {
  description = "Azure tenant ID"
  type        = string
  default     = ""
}