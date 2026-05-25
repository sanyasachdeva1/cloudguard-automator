data "aws_caller_identity" "current" {}

data "aws_vpc" "default" {
  default = true
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-${random_id.suffix.hex}"

  tags = {
    Project = "CloudGuard Automator"
    Owner   = var.trusted_owner
    Purpose = "Intentionally vulnerable cloud security lab"
  }
}

resource "aws_s3_bucket" "public_data" {
  bucket        = local.bucket_name
  force_destroy = true

  tags = local.tags
}

resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket = aws_s3_bucket.public_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.public_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadForDemo"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.public_data.arn}/*"
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.public_data]
}

resource "aws_security_group" "public_ingress" {
  name        = "${var.name_prefix}-public-ingress-${random_id.suffix.hex}"
  description = "Intentionally insecure public ingress for CloudGuard Automator demo"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Public SSH for scanner demo"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description      = "Public PostgreSQL IPv6 for scanner demo"
    from_port        = 5432
    to_port          = 5432
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "Broad public app range for scanner demo"
    from_port   = 8000
    to_port     = 8200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Default outbound access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

resource "aws_iam_user" "wildcard_user" {
  name = "${var.name_prefix}-wildcard-user-${random_id.suffix.hex}"
  path = "/cloudguard-lab/"

  tags = local.tags
}

resource "aws_iam_user_policy" "wildcard_admin" {
  name = "${var.name_prefix}-wildcard-admin"
  user = aws_iam_user.wildcard_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WildcardAdminForDemo"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
