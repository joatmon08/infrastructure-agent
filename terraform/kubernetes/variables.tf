variable "inbound_cidrs_for_lbs" {
  type        = list(string)
  description = "Comma-separated list of inbound CIDRs"
  default     = ["0.0.0.0/0"]
}