variable "aws_region" {
  description = "AWS region for regional lab resources."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix used for lab resource names."
  type        = string
  default     = "cloudguard-lab"
}

variable "trusted_owner" {
  description = "Owner tag value for lab resources."
  type        = string
  default     = "cloudguard-automator"
}

