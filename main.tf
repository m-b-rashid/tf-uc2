provider "aws" {
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
  region     = "${var.aws_region}"
}

module "cloudtrail-cloudwatch" {
  source               = "./modules/cloudtrail-cloudwatch"
  tags                 = "${var.tags}"
  trail_name           = "${var.trail_name}"
  metric_name_space    = "${var.metric_name_space}"
  aws_region           = "${var.aws_region}"
  bucket_prefix        = "${var.bucket_prefix}"
  lambda_function_name = "${var.lambda_function_name}"
  aws_vpc_id           = "${module.vpc.vpc_id}"
  aws_account_id       = "${var.aws_account_id}"
  log_reader           = "${var.log_reader}"
}

module "elastic-search" {
  source               = "./modules/elastic-search"
  aws_s3_bucket_id     = "${module.cloudtrail-cloudwatch.log_bucket_id}"
  aws_s3_bucket_arn    = "${module.cloudtrail-cloudwatch.log_bucket_arn}"
  tags                 = "${var.tags}"
  aws_es_domain_name   = "${var.aws_es_domain_name}"
  aws_es_version       = "${var.aws_es_version}"
  aws_es_instance_type = "${var.aws_es_instance_type}"
  vpc_subnet_ids       = "${module.vpc.public_subnets}"
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "${var.vpc_name}"
  cidr = "${var.vpc_cidr}"

  azs             = "${var.vpc_azs}"
  private_subnets = "${var.vpc_private_subnets}"
  public_subnets  = "${var.vpc_public_subnets}"

  enable_nat_gateway = true
  enable_vpn_gateway = true

  assign_generated_ipv6_cidr_block = true

  version = "~> 1.0"
}

module "bastion" {
  source     = "infrablocks/bastion/aws"
  region     = "${var.aws_region}"
  vpc_id     = "${module.vpc.vpc_id}"
  subnet_ids = "${module.vpc.public_subnets}"

  component             = "important-component"
  deployment_identifier = "production"

  ami           = "ami-bb373ddf"
  instance_type = "t2.micro"

  ssh_public_key_path = "${var.bastion_key_path}"

  allowed_cidrs = "${var.bastion_allowed_cidrs}"
  egress_cidrs  = "${var.bastion_egress_cidrs}"

  load_balancer_names = "${var.bastion_load_balancer_names}"

  minimum_instances = "${var.bastion_min}"
  maximum_instances = "${var.bastion_max}"
  desired_instances = "${var.bastion_desired}"
}
