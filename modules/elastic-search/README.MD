ELASTIC-SEARCH - used to create an an es instance inside a private vpc. Also a lamdba function that takes logs from an s3 bucket to the es instance.

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
