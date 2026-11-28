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

variable "ec2_instance_type" {
  type    = string
  default = "t3.micro"
}
