variable "aws_access_key" {
  description = "AWS Console ACCESS KEY"
}

variable "aws_secret_key" {
  description = "AWS Console SECRET KEY"
}

variable "aws_region" {
  description = "AWS Console Region"
}

variable "aws_account_id" {
  description = "AWS Account ID"
}

variable "tags" {
  description = "consistent tags for resources"

  default = {
    "owner"   = "belal"
    "project" = "tf-uc2-aws-modules"
    "client"  = "internal"
  }
}

variable trail_name {
  description = "Name for your cloudtrail"
}

variable metric_name_space {
  description = "Name_space for your cloudtrail"
}

variable bucket_prefix {
  description = "prefix for s3 bucket name"
}

variable lambda_function_name {
  description = "flow-logs-to-s3"
}

variable log_reader {
  description = "user that can decrypt s3 bucket logs"
}

variable aws_es_domain_name {
  description = "elastic-search domain name"
}

variable aws_es_version {
  description = "elastic-search version"
}

variable aws_es_instance_type {
  description = "elastic-search instance type"
}

variable vpc_name {}
variable vpc_cidr {}

variable vpc_azs {
  type = "list"
}

variable vpc_private_subnets {
  type = "list"
}

variable vpc_public_subnets {
  type = "list"
}

variable bastion_allowed_cidrs {
  type        = "list"
  description = "cidrs that can connect to the bastion"
}

variable bastion_egress_cidrs {
  type        = "list"
  description = "cidrs allowed to be reached from the bastion"
}

variable bastion_load_balancer_names {
  type = "list"
}

variable bastion_min {}
variable bastion_max {}
variable bastion_desired {}
variable bastion_key_path {}
