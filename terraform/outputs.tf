output "region" {
  value = var.region
}

output "identity_account_id" {
  value = data.aws_caller_identity.identity.account_id
}

output "payment_account_id" {
  value = data.aws_caller_identity.payment.account_id
}

output "inventory_account_id" {
  value = data.aws_caller_identity.inventory.account_id
}

output "trust_anchor_arn" {
  value = aws_rolesanywhere_trust_anchor.issuing.arn
}

output "trust_anchor_name" {
  value = aws_rolesanywhere_trust_anchor.issuing.name
}

output "payment_bucket" {
  value = aws_s3_bucket.payment.bucket
}

output "inventory_bucket" {
  value = aws_s3_bucket.inventory.bucket
}

output "payment_role_arn" {
  value = aws_iam_role.workload["payment"].arn
}

output "inventory_role_arn" {
  value = aws_iam_role.workload["inventory"].arn
}

output "payment_role_name" {
  value = aws_iam_role.workload["payment"].name
}

output "inventory_role_name" {
  value = aws_iam_role.workload["inventory"].name
}

output "payment_profile_arn" {
  value = aws_rolesanywhere_profile.workload["payment"].arn
}

output "inventory_profile_arn" {
  value = aws_rolesanywhere_profile.workload["inventory"].arn
}
