TF-UC2-AWS

Terraform Version 0.11

Create and use a module that will:

Create a cloudtrail trail that will send the logs of an account to a cloudwatch group .   
Create a cloudwatch group that will keep logs for 14 days and will send the logs to an elastic search instance .   
Create an elastic search instance to collect the logs and display them .   
Details:

The cloudtrail S3 bucket should use a KMS key created by the module .  
You can use a lambda function to send the logs to ES, this will need to be done in the same module, and the code of the lambda should be in the module too.    
Your module should have a set of variables available for its users in order to be flexible, with no (or very limited) hardcoded values.    
Your module should expose a set of meaningful outputs.    
Your module should have a readme that explains what it does, how to use it and contain a few meaningful examples.    
The HCL should be perfectly formatted, and no unnecessary files should be contained in the repository.   
Ultimately this module should be production-ready for a customer.    
Running this module should enable all (future) cloudtrail logs to be visible inside an ES instance by simply running the module.    

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
