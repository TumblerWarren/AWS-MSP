terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = "msp-sandbox"
      ManagedBy = "terraform-bootstrap"
    }
  }
}

data "aws_caller_identity" "current" {}

variable "aws_region" {
  type    = string
  default = "ap-south-1"
}

variable "github_repo" {
  type        = string
  description = "Sandbox IaC GitHub repository in 'owner/repo' format (e.g. 'your-org/msp-sandbox-infra')."
}

variable "platform_github_repo" {
  type        = string
  default     = ""
  description = "Optional platform GitHub repository in 'owner/repo' format (e.g. 'your-org/msp-platform') also allowed to assume the OIDC CI role."
}

variable "state_bucket_name" {
  type        = string
  default     = ""
  description = "Optional custom S3 state bucket name. Defaults to msp-sandbox-tfstate-<account_id>."
}

locals {
  bucket_name             = var.state_bucket_name != "" ? var.state_bucket_name : "msp-sandbox-tfstate-${data.aws_caller_identity.current.account_id}"
  drift_report_bucket_arn = "arn:aws:s3:::msp-drift-reports-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
  repo_parts              = split("/", var.github_repo)
  allowed_subs = compact([
    "repo:${var.github_repo}:*",
    "repo:${local.repo_parts[0]}@*/${local.repo_parts[1]}@*:*",
    var.platform_github_repo != "" ? "repo:${var.platform_github_repo}:*" : ""
  ])
}

# --- Terraform State Bucket (native S3 lockfile locking in TF >= 1.10) ---
resource "aws_s3_bucket" "tfstate" {
  bucket        = local.bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- GitHub Actions OIDC Provider + Scoped CI Role ---
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"]
}

data "aws_iam_policy_document" "github_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.allowed_subs
    }
  }
}

resource "aws_iam_role" "ci_terraform" {
  name               = "msp-ci-terraform"
  assume_role_policy = data.aws_iam_policy_document.github_assume.json
}

data "aws_iam_policy_document" "ci_terraform_permissions" {
  statement {
    sid    = "TerraformStateBucket"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject"
    ]
    resources = [
      aws_s3_bucket.tfstate.arn,
      "${aws_s3_bucket.tfstate.arn}/*"
    ]
  }

  statement {
    sid    = "SandboxAndPlatformInfraResources"
    effect = "Allow"
    actions = [
      "ec2:*",
      "rds:*",
      "ecr:*",
      "ecs:*",
      "logs:*",
      "iam:GetRole",
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:PassRole",
      "iam:TagRole",
      "iam:CreateServiceLinkedRole",
      "secretsmanager:CreateSecret",
      "secretsmanager:DeleteSecret",
      "secretsmanager:DescribeSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:TagResource",
      "secretsmanager:UpdateSecret",
      "kms:CreateGrant",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }

  statement {
    sid = "ManageDriftReportBucket"
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:ListBucket",
      "s3:GetBucket*",
      "s3:GetAccelerateConfiguration",
      "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration",
      "s3:GetReplicationConfiguration",
      "s3:PutBucketTagging",
      "s3:PutBucketPublicAccessBlock",
      "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration"
    ]
    resources = [local.drift_report_bucket_arn]
  }

  statement {
    sid       = "PublishDriftReports"
    actions   = ["s3:PutObject"]
    resources = ["${local.drift_report_bucket_arn}/drift-reports/*"]
  }
}

resource "aws_iam_role_policy" "ci_terraform" {
  name   = "msp-ci-terraform-policy"
  role   = aws_iam_role.ci_terraform.id
  policy = data.aws_iam_policy_document.ci_terraform_permissions.json
}

output "state_bucket_name" {
  value = aws_s3_bucket.tfstate.bucket
}

output "state_bucket_arn" {
  value = aws_s3_bucket.tfstate.arn
}

output "ci_role_arn" {
  value = aws_iam_role.ci_terraform.arn
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}
