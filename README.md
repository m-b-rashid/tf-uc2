TF-UC2-AWS

Terraform Version 0.11

Create a terraform.tfvars file -> look at terraform.tfvars.example 

MODULES

VPC - https://github.com/terraform-aws-modules/terraform-aws-vpc
Create a vpc with subnets
Please refer to the github repo for documentation

BASTION - https://github.com/infrablocks/terraform-aws-bastion
Create a jump-box to allow access into private subnets 
Please refer to the github repo for documentation 

CLOUDTRAIL-CLOUDWATCH - 
Create a cloudtrail and a cloudwatch group with metrics. Also an kms encrypted s3 bucket where logs are sent and stored.

Variables -  
trail_name {name of the cloudtrail},  
metric_name_space {name space of the cloudtrail},  
aws_region {},  
bucket_prefix {s3 bucket prefix},  
lambda_function_name {},  
aws_vpc_id {},  
aws_account_id {},  
log_reader {user that can decypt logs},  

Outputs -  
"encryption_key_arn" ,  
"log_bucket_arn" ,  
"log_bucket_id",  
"trail_arn",  

ELASTIC-SEARCH -
used to create an an es instance inside a private vpc. Also a lamdba function that takes logs from an s3 bucket to the es instance.

Variables -   
aws_s3_bucket_id {},  
aws_s3_bucket_arn {},  
aws_es_domain_name {},  
aws_es_version {},  
aws_es_instance_type {},  
vpc_subnet_ids {},  

Outputs -   
"es_domain" - es domain name ,  
"kibana_es" - kibana endpoint for es instance,  
