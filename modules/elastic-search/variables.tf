variable aws_s3_bucket_id {}
variable aws_s3_bucket_arn {}

variable tags {
  default = {
    "owner"   = "belal "
    "project" = "cloudtrail-test"
    "client"  = "Internal"
  }
}

variable aws_es_domain_name {}
variable aws_es_version {}
variable aws_es_instance_type {}

variable vpc_subnet_ids {
  type = "list"
}
