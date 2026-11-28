variable "aws_region" {
  type    = string
  default = "ap-south-1"
}

variable "project_name" {
  type    = string
  default = "msp-split-sandbox"
}

variable "environment" {
  type    = string
  default = "sandbox"
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

variable "allowed_app_cidr" {
  type        = string
  default     = "10.42.0.0/16"
  description = "CIDR allowed to reach the application security group on HTTPS."
}
