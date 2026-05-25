output "public_bucket_name" {
  description = "Name of the intentionally exposed S3 bucket."
  value       = aws_s3_bucket.public_data.bucket
}

output "public_security_group_id" {
  description = "ID of the intentionally exposed security group."
  value       = aws_security_group.public_ingress.id
}

output "wildcard_iam_user" {
  description = "IAM user with an intentionally over-permissive inline policy."
  value       = aws_iam_user.wildcard_user.name
}

