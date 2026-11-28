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

variable "rds_instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "rds_backup_retention_period" {
  type    = number
  default = 1
}
