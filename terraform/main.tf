data "aws_caller_identity" "identity" {}

data "aws_caller_identity" "payment" {
  provider = aws.payment
}

data "aws_caller_identity" "inventory" {
  provider = aws.inventory
}

check "three_accounts" {
  assert {
    condition = length(distinct([
      data.aws_caller_identity.identity.account_id,
      data.aws_caller_identity.payment.account_id,
      data.aws_caller_identity.inventory.account_id,
    ])) == 3
    error_message = "identity, payment, and inventory must be three different accounts."
  }
}

locals {
  organizational_unit = "production"
  trust_anchor_name   = "${var.name_prefix}lab-issuing-ca"

  workloads = {
    payment = {
      role_name   = "${var.name_prefix}PaymentReconcilerRole"
      profile     = "${var.name_prefix}payment-reconciler"
      common_name = "payment-reconciler"
    }
    inventory = {
      role_name   = "${var.name_prefix}InventoryWorkerRole"
      profile     = "${var.name_prefix}inventory-worker"
      common_name = "inventory-worker"
    }
  }
}

resource "aws_s3_bucket" "payment" {
  provider      = aws.payment
  bucket        = "ra-lab-payment-${data.aws_caller_identity.payment.account_id}-${var.region}"
  force_destroy = true
}

resource "aws_s3_bucket" "inventory" {
  provider      = aws.inventory
  bucket        = "ra-lab-inventory-${data.aws_caller_identity.inventory.account_id}-${var.region}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "payment" {
  provider                = aws.payment
  bucket                  = aws_s3_bucket.payment.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "inventory" {
  provider                = aws.inventory
  bucket                  = aws_s3_bucket.inventory.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "payment" {
  provider = aws.payment
  bucket   = aws_s3_bucket.payment.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "inventory" {
  provider = aws.inventory
  bucket   = aws_s3_bucket.inventory.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "payment" {
  provider = aws.payment
  bucket   = aws_s3_bucket.payment.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_ownership_controls" "inventory" {
  provider = aws.inventory
  bucket   = aws_s3_bucket.inventory.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_object" "payment" {
  provider     = aws.payment
  bucket       = aws_s3_bucket.payment.id
  key          = "payment-reconciler/input.json"
  content_type = "application/json"
  content = jsonencode({
    purpose  = "roles-anywhere-lab"
    workload = "payment-reconciler"
    account  = "payment"
  })

  depends_on = [
    aws_s3_bucket_public_access_block.payment,
    aws_s3_bucket_ownership_controls.payment,
  ]
}

resource "aws_s3_object" "audit" {
  provider     = aws.payment
  bucket       = aws_s3_bucket.payment.id
  key          = "audit/input.json"
  content_type = "application/json"
  content = jsonencode({
    purpose = "roles-anywhere-lab"
    object  = "audit"
    account = "payment"
  })

  depends_on = [
    aws_s3_bucket_public_access_block.payment,
    aws_s3_bucket_ownership_controls.payment,
  ]
}

resource "aws_s3_object" "inventory" {
  provider     = aws.inventory
  bucket       = aws_s3_bucket.inventory.id
  key          = "inventory-worker/input.json"
  content_type = "application/json"
  content = jsonencode({
    purpose  = "roles-anywhere-lab"
    workload = "inventory-worker"
    account  = "inventory"
  })

  depends_on = [
    aws_s3_bucket_public_access_block.inventory,
    aws_s3_bucket_ownership_controls.inventory,
  ]
}

resource "aws_rolesanywhere_trust_anchor" "issuing" {
  name    = local.trust_anchor_name
  enabled = true

  source {
    source_type = "CERTIFICATE_BUNDLE"
    source_data {
      x509_certificate_data = file(var.issuing_ca_pem_path)
    }
  }
}

resource "aws_iam_role" "workload" {
  for_each = local.workloads

  name = each.value.role_name
  assume_role_policy = templatefile("${path.module}/templates/trust-policy.json.tftpl", {
    trust_anchor_arn    = aws_rolesanywhere_trust_anchor.issuing.arn
    common_name         = each.value.common_name
    organizational_unit = local.organizational_unit
  })
}

resource "aws_iam_role_policy" "payment" {
  name = "read-both-data-buckets"
  role = aws_iam_role.workload["payment"].id
  policy = templatefile("${path.module}/templates/identity-payment.json.tftpl", {
    payment_bucket_arn   = aws_s3_bucket.payment.arn
    inventory_bucket_arn = aws_s3_bucket.inventory.arn
  })
}

resource "aws_iam_role_policy" "inventory" {
  name = "read-inventory-bucket"
  role = aws_iam_role.workload["inventory"].id
  policy = templatefile("${path.module}/templates/identity-inventory.json.tftpl", {
    inventory_bucket_arn = aws_s3_bucket.inventory.arn
  })
}

resource "aws_rolesanywhere_profile" "workload" {
  for_each = local.workloads

  name             = each.value.profile
  enabled          = true
  role_arns        = [aws_iam_role.workload[each.key].arn]
  duration_seconds = var.session_duration_seconds
  session_policy = each.key == "payment" ? templatefile("${path.module}/templates/session-payment.json.tftpl", {
    payment_bucket_arn   = aws_s3_bucket.payment.arn
    inventory_bucket_arn = aws_s3_bucket.inventory.arn
    }) : templatefile("${path.module}/templates/session-inventory.json.tftpl", {
    inventory_bucket_arn = aws_s3_bucket.inventory.arn
  })
}

resource "aws_s3_bucket_policy" "payment" {
  provider = aws.payment
  bucket   = aws_s3_bucket.payment.id
  policy = templatefile("${path.module}/templates/bucket-policy.json.tftpl", {
    role_arn   = aws_iam_role.workload["payment"].arn
    bucket_arn = aws_s3_bucket.payment.arn
  })

  depends_on = [aws_s3_bucket_public_access_block.payment]
}

resource "aws_s3_bucket_policy" "inventory" {
  provider = aws.inventory
  bucket   = aws_s3_bucket.inventory.id
  policy = templatefile("${path.module}/templates/bucket-policy.json.tftpl", {
    role_arn   = aws_iam_role.workload["inventory"].arn
    bucket_arn = aws_s3_bucket.inventory.arn
  })

  depends_on = [aws_s3_bucket_public_access_block.inventory]
}
