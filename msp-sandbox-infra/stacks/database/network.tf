data "aws_vpc" "network" {
  tags = {
    Name = "${var.project_name}-vpc"
  }
}

data "aws_subnet" "private_a" {
  vpc_id = data.aws_vpc.network.id
  tags = {
    Name = "${var.project_name}-private-a"
  }
}

data "aws_subnet" "private_b" {
  vpc_id = data.aws_vpc.network.id
  tags = {
    Name = "${var.project_name}-private-b"
  }
}

data "aws_security_group" "rds" {
  vpc_id = data.aws_vpc.network.id
  name   = "${var.project_name}-rds-sg"
}
