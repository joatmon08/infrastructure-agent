resource "aws_security_group" "alb_ingress" {
  name_prefix = "${var.project_name}-alb-ingress-"
  description = "Security group for helloworld, test-client, and summarizer ALB ingresses"
  vpc_id      = data.terraform_remote_state.base.outputs.vpc_id

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = concat(
      [data.terraform_remote_state.base.outputs.vpc_cidr_block],
      var.inbound_cidrs_for_lbs
    )
  }

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = concat(
      [data.terraform_remote_state.base.outputs.vpc_cidr_block],
      var.inbound_cidrs_for_lbs
    )
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-alb-ingress"
  }

  lifecycle {
    create_before_destroy = true
  }
}
