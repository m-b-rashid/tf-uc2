resource "aws_iam_role" "iam_for_lambda_s3" {
  name = "iam_for_lambda"

  assume_role_policy = "${file("${path.module}/policies/flow_to_es.json")}"
}

resource "aws_lambda_permission" "allow_bucket" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.s3-to-es.arn}"
  principal     = "s3.amazonaws.com"
  source_arn    = "${var.aws_s3_bucket_arn}"
}

resource "aws_iam_role_policy_attachment" "s3-to-es" {
  role       = "${aws_iam_role.iam_for_lambda_s3.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaExecute"
}

# -----------------------------------------------------------
# Lambda pieces to pick up logs from s3, and put them in es
# -----------------------------------------------------------

data "archive_file" "lambda_zip_s3-to-es" {
  type        = "zip"
  source_file = "${path.module}/scripts/s3-to-es.py"
  output_path = "${path.module}/scripts/s3-to-es.zip"
}

resource "aws_lambda_function" "s3-to-es" {
  filename         = "${data.archive_file.lambda_zip_s3-to-es.output_path}"
  function_name    = "flow-to-es"
  role             = "${aws_iam_role.iam_for_lambda_s3.arn}"
  handler          = "s3-to-es.lambda_handler"
  source_code_hash = "${data.archive_file.lambda_zip_s3-to-es.output_base64sha256}"
  runtime          = "python2.7"
  timeout          = "3"
  memory_size      = "128"

  environment {
    variables = {
      bucketS3 = "${var.aws_s3_bucket_id}"
      folderS3 = "log-ingester"
      prefixS3 = "log-ingester_"
      esHost   = "${aws_elasticsearch_domain.es_domain.endpoint}"
    }
  }

  tags = "${merge(map("Name","Example-FlowLogs-To-S3"), var.tags)}"
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = "${var.aws_s3_bucket_id}"

  lambda_function {
    lambda_function_arn = "${aws_lambda_function.s3-to-es.arn}"
    events              = ["s3:ObjectCreated:*"]
  }
}

# -----------------------------------------------------------
# create an ES instance cluster/domain
# -----------------------------------------------------------
resource "aws_iam_service_linked_role" "es" {
  aws_service_name = "es.amazonaws.com"
}

resource "aws_elasticsearch_domain" "es_domain" {
  domain_name           = "${var.aws_es_domain_name}"
  elasticsearch_version = "${var.aws_es_version}"

  cluster_config {
    instance_type  = "${var.aws_es_instance_type}"
    instance_count = 1
  }

  snapshot_options {
    automated_snapshot_start_hour = 23
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 30
  }

  vpc_options {
    subnet_ids = ["${var.vpc_subnet_ids}"]
  }

}



resource "aws_elasticsearch_domain_policy" "main" {
  domain_name = "${aws_elasticsearch_domain.es_domain.domain_name}"

  access_policies = <<POLICIES
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "es:*",
      "Resource": "${aws_elasticsearch_domain.es_domain.arn}/*"
    }
  ]
}
POLICIES
}
