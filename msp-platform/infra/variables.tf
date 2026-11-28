variable "aws_region" {
  type    = string
  default = "ap-south-1"
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

variable "bedrock_region" {
  type        = string
  default     = ""
  description = "Optional Bedrock source region override for model inference."
}

variable "strands_model_id" {
  type    = string
  default = "au.anthropic.claude-sonnet-4-6"
}

variable "claude_model_id" {
  type    = string
  default = "au.anthropic.claude-sonnet-4-6"
}

variable "github_repo" {
  type        = string
  default     = ""
  description = "Target IaC GitHub repo in 'owner/repo' format."
}

variable "terraform_repositories" {
  type        = map(string)
  default     = {}
  description = "Additional registered Terraform GitHub repositories mapped to their deployment branches."
}

variable "github_token" {
  type        = string
  default     = ""
  sensitive   = true
  description = "GitHub token with repo + workflow permissions for dispatching workflows and opening PRs."
}
