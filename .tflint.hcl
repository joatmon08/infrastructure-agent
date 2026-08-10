# Global TFLint configuration
config {
  # Format output mapping (choices: default, json, checkstyle, junit, compact)
  format = "compact"

  # Allow linting deep inside referenced local modules
  call_module_type = "local"

  # Ensure TFLint fails if an unhandled error occurs
  force = false
}

# Core Terraform language rules (Enforces best practices for syntax, variables, and outputs)
plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

# AWS-specific ruleset plugin
plugin "aws" {
  enabled = true
  version = "0.48.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

# Example: Customizing specific AWS rules
# Over 700 rules are available. You can selectively disable or alter rules here.

rule "aws_instance_invalid_type" {
  enabled = true # Flags invalid EC2 instance types (e.g., typing t3.xlargee instead of t3.xlarge)
}

rule "aws_resource_missing_tags" {
  enabled = true
  tags    = ["Environment", "Project", "ManagedBy"]
}
