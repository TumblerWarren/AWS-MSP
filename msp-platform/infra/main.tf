terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }

  # Configured via -backend-config="bucket=..." in GitHub Actions (deploy-platform-infra.yml)
  backend "s3" {
    key          = "platform/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "msp-platform"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# 1. ECR Repository & CloudWatch Logs for Agent + Backend Container
# ---------------------------------------------------------------------------

resource "aws_ecr_repository" "platform" {
  name                 = "msp-platform"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_cloudwatch_log_group" "platform" {
  name              = "/ecs/msp-platform"
  retention_in_days = 14
}

# ---------------------------------------------------------------------------
# 2. ECS Task Role (Strands + Claude Agent SDK runtime) & Execution Role
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_execution" {
  name               = "msp-platform-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "ecs_execution_default" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "platform_task" {
  name               = "msp-platform-task-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

# ---------------------------------------------------------------------------
# 3. Read-Only Investigator Role (assumed by Strands MCP servers via STS)
# ---------------------------------------------------------------------------

locals {
  investigator_principals = distinct(concat(
    length(var.trusted_principal_arns) > 0 ? var.trusted_principal_arns : [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
    ],
    [aws_iam_role.platform_task.arn]
  ))
}

data "aws_iam_policy_document" "investigator_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = local.investigator_principals
    }
  }
}

resource "aws_iam_role" "investigator_readonly" {
  name               = "msp-investigator-readonly"
  assume_role_policy = data.aws_iam_policy_document.investigator_assume.json
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.investigator_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "cloudtrail_readonly" {
  role       = aws_iam_role.investigator_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCloudTrail_ReadOnlyAccess"
}

data "aws_iam_policy_document" "investigator_guardrails" {
  statement {
    sid    = "ExplicitDenySecretsAndKeys"
    effect = "Deny"
    actions = [
      "secretsmanager:GetSecretValue",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "kms:Decrypt"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ExplicitDenyTerraformState"
    effect = "Deny"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:ListBucket"
    ]
    resources = [
      var.state_bucket_arn,
      "${var.state_bucket_arn}/*"
    ]
  }

  statement {
    sid    = "AllowBedrockInference"
    effect = "Allow"
    actions = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "investigator_guardrails" {
  name   = "msp-investigator-guardrails"
  role   = aws_iam_role.investigator_readonly.id
  policy = data.aws_iam_policy_document.investigator_guardrails.json
}

# Task role can invoke Bedrock (Strands + Claude Agent SDK) and assume only the read-only investigator role
data "aws_iam_policy_document" "platform_task_permissions" {
  statement {
    sid    = "AllowBedrockForStrandsAndClaudeSDK"
    effect = "Allow"
    actions = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream"
    ]
    resources = ["*"]
  }

  statement {
    sid       = "AllowAssumeInvestigatorReadOnlyRole"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.investigator_readonly.arn]
  }
}

resource "aws_iam_role_policy" "platform_task_permissions" {
  name   = "msp-platform-task-policy"
  role   = aws_iam_role.platform_task.id
  policy = data.aws_iam_policy_document.platform_task_permissions.json
}

# ---------------------------------------------------------------------------
# 4. ECS Fargate Cluster, Task Definition & Optional Service
# ---------------------------------------------------------------------------

resource "aws_ecs_cluster" "main" {
  name = "msp-platform-cluster"
}

resource "aws_ecs_task_definition" "platform" {
  family                   = "msp-platform"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.platform_task.arn

  container_definitions = jsonencode([
    {
      name      = "msp-platform"
      image     = "${aws_ecr_repository.platform.repository_url}:${var.container_image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ]
      environment = [
        { name = "MSP_AWS_REGION", value = var.aws_region },
        { name = "MSP_INVESTIGATOR_ROLE_ARN", value = aws_iam_role.investigator_readonly.arn },
        { name = "MSP_STRANDS_MODEL_ID", value = var.strands_model_id },
        { name = "MSP_CLAUDE_MODEL", value = var.claude_model_id },
        { name = "MSP_CLAUDE_USE_BEDROCK", value = "true" },
        { name = "MSP_AWS_MCP_ENABLED", value = "true" },
        { name = "MSP_GITHUB_REPO", value = var.github_repo },
        { name = "MSP_GITHUB_TOKEN", value = var.github_token }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.platform.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

data "aws_vpc" "default" {
  count   = var.deploy_ecs_service ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.deploy_ecs_service ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default[0].id]
  }
}

resource "aws_security_group" "platform_service" {
  count       = var.deploy_ecs_service ? 1 : 0
  name        = "msp-platform-service-sg"
  description = "Allow HTTP 8080 to MSP platform & agent service"
  vpc_id      = data.aws_vpc.default[0].id

  ingress {
    description = "HTTP UI & API"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_service" "platform" {
  count           = var.deploy_ecs_service ? 1 : 0
  name            = "msp-platform-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.platform.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default[0].ids
    security_groups  = [aws_security_group.platform_service[0].id]
    assign_public_ip = true
  }
}
