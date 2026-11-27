resource "aws_s3_bucket" "drift_reports" {
  bucket = "msp-drift-reports-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
}

resource "aws_s3_bucket_public_access_block" "drift_reports" {
  bucket                  = aws_s3_bucket.drift_reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "drift_reports" {
  bucket = aws_s3_bucket.drift_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "drift_reports" {
  bucket = aws_s3_bucket.drift_reports.id

  rule {
    id     = "expire-drift-reports"
    status = "Enabled"

    filter {
      prefix = "drift-reports/"
    }

    expiration {
      days = 14
    }
  }
}
