variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "state_bucket_arn" {
  type        = string
  description = "ARN of the Terraform state bucket to explicitly DENY the AI investigator from reading."
}

variable "trusted_principal_arns" {
  type        = list(string)
  default     = []
  description = "IAM principal ARNs allowed to assume the investigator role in addition to the ECS task role."
}

variable "deploy_ecs_service" {
  type        = bool
  default     = false
  description = "Set true once the msp-platform container image has been pushed to the ECR repository."
}

variable "container_image_tag" {
  type    = string
  default = "latest"
}

variable "strands_model_id" {
  type    = string
  default = "us.anthropic.claude-sonnet-4-20250514-v1:0"
}

variable "claude_model_id" {
  type    = string
  default = "us.anthropic.claude-sonnet-4-20250514-v1:0"
}

variable "github_repo" {
  type        = string
  default     = ""
  description = "Target IaC GitHub repo in 'owner/repo' format."
}

variable "github_token" {
  type        = string
  default     = ""
  sensitive   = true
  description = "GitHub token with repo + workflow permissions for dispatching workflows and opening PRs."
}
