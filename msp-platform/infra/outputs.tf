output "investigator_role_arn" {
  value = aws_iam_role.investigator_readonly.arn
}

output "platform_task_role_arn" {
  value = aws_iam_role.platform_task.arn
}

output "ecr_repository_url" {
  value = aws_ecr_repository.platform.repository_url
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "drift_report_bucket" {
  value = aws_s3_bucket.drift_reports.bucket
}
