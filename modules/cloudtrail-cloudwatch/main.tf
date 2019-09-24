# -----------------------------------------------------------
# setup permissions to allow cloudtrail to write to cloudwatch
# -----------------------------------------------------------
resource "aws_iam_role" "cloudtrail_example" {
  name               = "cloudtrail-to-cloudwatch"
  assume_role_policy = "${file("${path.module}/policies/iam_cloudtrail_example.json")}"
}

resource "aws_iam_role_policy" "cloudtrail_example" {
  name = "cloudtrail-example"
  role = "${aws_iam_role.cloudtrail_example.id}"

  policy = "${file("${path.module}/policies/cloudtrail_example.json")}"
}

# -----------------------------------------------------------
# setup cloudwatch logs to receive cloudtrail events
# -----------------------------------------------------------

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name = "cloudtrail"

  kms_key_id        = "${aws_kms_key.cloudtrail_key.arn}"
  retention_in_days = 30
  tags              = "${merge(map("Name","Cloudtrail"), var.tags)}"
}

# -----------------------------------------------------------
# turn cloudtrail on for this region
# -----------------------------------------------------------

resource "aws_cloudtrail" "example" {
  name                          = "${var.trail_name}"
  s3_bucket_name                = "${aws_s3_bucket.log_bucket.id}"
  s3_key_prefix                 = "${var.trail_name}"
  include_global_service_events = true
  enable_logging                = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}"
  cloud_watch_logs_role_arn     = "${aws_iam_role.cloudtrail_example.arn}"
  kms_key_id                    = "${aws_kms_key.cloudtrail_key.arn}"

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = "${merge(map("Name","Example account audit"), var.tags)}"
}

# -----------------------------------------------------------
# setup audit filters
# -----------------------------------------------------------

# ----------------------
# watch for use of the root account
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "root_login" {
  name           = "root-access"
  pattern        = "{$.userIdentity.type = Root}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "RootAccessCount"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "root-access-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccessCount"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Use of the root account has been detected"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# watch for use of the console without MFA
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "console_without_mfa" {
  name           = "console-without-mfa"
  pattern        = "{$.eventName = ConsoleLogin && $.additionalEventData.MFAUsed = No}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "ConsoleWithoutMFACount"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_without_mfa" {
  alarm_name          = "console-without-mfa-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ConsoleWithoutMFACount"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Use of the console by an account without MFA has been detected"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# watch for actions triggered by accounts without MFA
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "action_without_mfa" {
  name           = "action-without-mfa"
  pattern        = "{$.userIdentity.type != AssumedRole && $.userIdentity.sessionContext.attributes.mfaAuthenticated != true}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "UseWithoutMFACount"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "action_without_mfa" {
  alarm_name          = "action-without-mfa-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "UseWithoutMFACount"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Actions triggered by a user account without MFA has been detected"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# look for key alias changes or key deletions
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "illegal_key_use" {
  name           = "key-changes"
  pattern        = "{$.eventSource = kms.amazonaws.com && ($.eventName = DeleteAlias || $.eventName = DisableKey)}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "KeyChangeOrDelete"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "illegal_key_use" {
  alarm_name          = "key-changes-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "KeyChangeOrDelete"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "A key alias has been changed or a key has been deleted"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# look for use of KMS keys by users
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "decription_with_key" {
  name           = "decription_with_key"
  pattern        = "{($.userIdentity.type = IAMUser || $.userIdentity.type = AssumeRole) && $.eventSource = kms.amazonaws.com && $.eventName = Decrypt}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "DecryptionWithKMS"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

# ----------------------
# look for changes to security groups
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "security_group_change" {
  name           = "security-group-changes"
  pattern        = "{ $.eventName = AuthorizeSecurityGroup* || $.eventName = RevokeSecurityGroup* || $.eventName = CreateSecurityGroup || $.eventName = DeleteSecurityGroup }"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_group_change" {
  alarm_name          = "security-group-changes-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "SecurityGroupChanges"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Security groups have been changed"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# look for changes to IAM resources
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "iam_change" {
  name           = "iam-changes"
  pattern        = "{$.eventSource = iam.* && $.eventName != Get* && $.eventName != List*}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "IamChanges"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_change" {
  alarm_name          = "iam-changes-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "IamChanges"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "IAM Resources have been changed"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# look for changes to route table resources
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "routetable_change" {
  name           = "route-table-changes"
  pattern        = "{$.eventSource = ec2.* && ($.eventName = AssociateRouteTable || $.eventName = CreateRoute* || $.eventName = CreateVpnConnectionRoute || $.eventName = DeleteRoute* || $.eventName = DeleteVpnConnectionRoute || $.eventName = DisableVgwRoutePropagation || $.eventName = DisassociateRouteTable || $.eventName = EnableVgwRoutePropagation || $.eventName = ReplaceRoute*)}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "RouteTableChanges"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "routetable_change" {
  alarm_name          = "route-table-changes-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RouteTableChanges"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Route Table Resources have been changed"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# look for changes to NACL
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "nacl_change" {
  name           = "nacl-changes"
  pattern        = "{$.eventSource = ec2.* && ($.eventName = CreateNetworkAcl* || $.eventName = DeleteNetworkAcl* || $.eventName = ReplaceNetworkAcl*)}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "NaclChanges"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "nacl_change" {
  alarm_name          = "nacl-changes-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "NaclChanges"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "NACL have been changed"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

#nacl

# -----------------------------------------------------------
# set up SNS for sending alerts out. note there is only rudimentary security on this
# -----------------------------------------------------------
resource "aws_sns_topic" "security_alerts" {
  name         = "security-alerts-topic"
  display_name = "Security Alerts"
}

resource "aws_sns_topic_subscription" "security_alerts_to_sqs" {
  topic_arn = "${aws_sns_topic.security_alerts.arn}"
  protocol  = "sqs"
  endpoint  = "${aws_sqs_queue.security_alerts.arn}"
}

resource "aws_sqs_queue" "security_alerts" {
  name = "security-alerts-${var.aws_region}"
  tags = "${merge(map("Name","Security Alerts"), var.tags)}"
}

resource "aws_sqs_queue_policy" "sns_to_sqs" {
  queue_url = "${aws_sqs_queue.security_alerts.id}"

  policy = "${file("${path.module}/policies/sns_to_sqs.json")}"
}

# -----------------------------------------------------------
# set up logging bucket keys
# -----------------------------------------------------------

resource "aws_kms_key" "log_key" {
  deletion_window_in_days = 7
  description             = "Log Bucket Encryption Key"
  enable_key_rotation     = true
  tags                    = "${merge(map("Name","Log Bucket Key"), var.tags)}"
}

resource "aws_kms_alias" "log_key" {
  name          = "alias/log_key"
  target_key_id = "${aws_kms_key.log_key.id}"
}

resource "aws_kms_key" "cloudtrail_key" {
  deletion_window_in_days = 7
  description             = "CloudTrail Log Encryption Key"
  enable_key_rotation     = true
  tags                    = "${merge(map("Name","CloudTrail Key"), var.tags)}"

  policy = "${file("${path.module}/policies/cloudtrail_key.json")}"
}

resource "aws_kms_alias" "cloudtrail_key" {
  name          = "alias/cloudtrail_key"
  target_key_id = "${aws_kms_key.cloudtrail_key.id}"
}

# -----------------------------------------------------------
# set up logging bucket
# -----------------------------------------------------------

resource "aws_s3_bucket" "log_bucket" {
  bucket_prefix = "${var.bucket_prefix}"
  acl           = "private"
  region        = "${var.aws_region}"
  force_destroy = true

  versioning {
    enabled = true
  }

  lifecycle {
    prevent_destroy = false
  }

  lifecycle_rule {
    enabled = true
    prefix  = "${var.trail_name}/"

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      days = 365
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.log_key.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }

  tags = "${merge(map("Name","Log Bucket"), var.tags)}"
}

resource "aws_s3_bucket_policy" "log_bucket_policy" {
  bucket = "${aws_s3_bucket.log_bucket.id}"

  policy = "${file("${path.module}/policies/log_bucket_policy.json")}"
}

# -----------------------------------------------------------
# set up log groups
# -----------------------------------------------------------
resource "aws_cloudwatch_log_group" "example" {
  name = "example"

  kms_key_id        = "${aws_kms_key.cloudtrail_key.arn}"
  retention_in_days = 90
  tags              = "${merge(map("Name","Example"), var.tags)}"
}

# -----------------------------------------------------------
# set up flow log
# -----------------------------------------------------------
resource "aws_flow_log" "example" {
  log_group_name = "${aws_cloudwatch_log_group.example.name}"
  iam_role_arn   = "${aws_iam_role.flow_example.arn}"
  vpc_id         = "${var.aws_vpc_id}"
  traffic_type   = "ALL"
}

resource "aws_iam_role" "flow_example" {
  name = "flow-example"

  assume_role_policy = "${file("${path.module}/policies/flow_to_s3.json")}"
}

resource "aws_iam_role_policy" "flow_example" {
  name = "flow-example"
  role = "${aws_iam_role.flow_example.id}"

  policy = "${file("${path.module}/policies/role_policy_cloudwatch.json")}"
}

# -----------------------------------------------------------
# Lambda pieces to pick up logs from cloudwatch, and put them in S3
# -----------------------------------------------------------
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/scripts/FlowLogsToS3.py"
  output_path = "${path.module}/scripts/FlowLogsToS3.zip"
}

resource "aws_iam_role" "flow_lambda_example" {
  name = "flow-lambda-example"

  assume_role_policy = "${file("${path.module}/policies/flow_to_es.json")}"
}

resource "aws_iam_role_policy_attachment" "flow_lambda_example" {
  role       = "${aws_iam_role.flow_lambda_example.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaExecute"
}

resource "aws_lambda_function" "example" {
  filename         = "${data.archive_file.lambda_zip.output_path}"
  function_name    = "${var.lambda_function_name}"
  role             = "${aws_iam_role.flow_lambda_example.arn}"
  handler          = "FlowLogsToS3.lambda_handler"
  source_code_hash = "${data.archive_file.lambda_zip.output_base64sha256}"
  runtime          = "python2.7"
  timeout          = "3"
  memory_size      = "128"

  environment {
    variables = {
      bucketS3 = "${aws_s3_bucket.log_bucket.id}"
      folderS3 = "FlowLogs"
      prefixS3 = "flowLog_"
    }
  }

  tags = "${merge(map("Name","Example-FlowLogs-To-S3"), var.tags)}"
}

resource "aws_lambda_permission" "example" {
  statement_id  = "flow-example"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.example.arn}"
  principal     = "logs.${var.aws_region}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.example.arn}"
}

resource "aws_cloudwatch_log_subscription_filter" "example" {
  depends_on      = ["aws_lambda_permission.example"]
  name            = "Lambda-FlowLogs-To-S3"
  log_group_name  = "${aws_cloudwatch_log_group.example.name}"
  filter_pattern  = "[version, account_id, interface_id, srcaddr != \"-\", dstaddr != \"-\", srcport != \"-\", dstport != \"-\", protocol, packets, bytes, start, end, action, log_status]"
  destination_arn = "${aws_lambda_function.example.arn}"
}
