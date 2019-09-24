CLOUDTRAIL-CLOUDWATCH - Create a cloudtrail and a cloudwatch group with metrics. Also an kms encrypted s3 bucket where logs are sent and stored.

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
