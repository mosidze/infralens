package aws

import (
	"encoding/json"
	"fmt"
	"sort"
)

// baseActions are needed by every run regardless of the selected checks.
var baseActions = []string{
	"sts:GetCallerIdentity",
	"ec2:DescribeRegions",
	"ec2:DescribeSubnets",
	"ce:GetCostAndUsage",
	"ce:GetDimensionValues",
	"cloudwatch:GetMetricStatistics",
	"cloudwatch:GetMetricData",
}

// scannerActions lists the IAM actions each check calls. A test keeps this in
// step with the registry so the printed policy never silently falls behind.
var scannerActions = map[string][]string{
	"ec2":            {"ec2:DescribeInstances"},
	"ebs":            {"ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:DescribeImages"},
	"eip":            {"ec2:DescribeAddresses"},
	"nat":            {"ec2:DescribeNatGateways"},
	"elb":            {"elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTags", "elasticloadbalancing:DescribeTargetHealth", "elasticloadbalancing:DescribeListeners"},
	"ecs":            {"ecs:ListClusters", "ecs:DescribeClusters", "ecs:ListServices", "ecs:DescribeServices", "ecs:DescribeTaskDefinition"},
	"rds":            {"rds:DescribeDBInstances", "rds:DescribeDBClusters"},
	"opensearch":     {"es:ListDomainNames", "es:DescribeDomains", "es:ListTags"},
	"kinesis":        {"kinesis:ListStreams", "kinesis:DescribeStreamSummary", "kinesis:ListTagsForStream"},
	"logs":           {"logs:DescribeLogGroups"},
	"s3":             {"s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetLifecycleConfiguration", "s3:GetBucketPublicAccessBlock", "s3:GetBucketPolicyStatus"},
	"reservations":   {"rds:DescribeReservedDBInstances", "es:DescribeReservedInstances", "ec2:DescribeReservedInstances"},
	"lambda":         {"lambda:ListFunctions", "lambda:ListTags"},
	"vpcendpoints":   {"ec2:DescribeVpcEndpoints"},
	"redshift":       {"redshift:DescribeClusters"},
	"memorydb":       {"memorydb:DescribeClusters", "memorydb:ListTags"},
	"elasticache":    {"elasticache:DescribeCacheClusters"},
	"dynamodb":       {"dynamodb:ListTables", "dynamodb:DescribeTable", "dynamodb:ListTagsOfResource"},
	"sqs":            {"sqs:ListQueues", "sqs:ListQueueTags"},
	"firehose":       {"firehose:ListDeliveryStreams", "firehose:DescribeDeliveryStream"},
	"cloudfront":     {"cloudfront:ListDistributions"},
	"trustedadvisor": {"support:DescribeTrustedAdvisorChecks", "support:DescribeTrustedAdvisorCheckSummaries", "support:DescribeTrustedAdvisorCheckResult"},
	"costhub":        {"cost-optimization-hub:ListRecommendations"},
	"securityhub":    {"securityhub:GetFindings"},
	"iam":            {"iam:GetAccountSummary", "iam:GetAccountPasswordPolicy", "iam:ListUsers", "iam:ListMFADevices", "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed", "iam:GetLoginProfile"},
	"sgexposure":     {"ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces"},
	"cloudtrail":     {"cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"},
	"guardduty":      {"guardduty:ListDetectors", "guardduty:GetDetector"},
	"cloudformation": {"cloudformation:ListStacks", "cloudformation:ListStackResources"},
	"hygiene":        {"compute-optimizer:GetEnrollmentStatus", "ce:GetAnomalyMonitors"},
	"coverage":       {"ce:GetReservationCoverage", "ce:GetReservationUtilization", "ce:GetDimensionValues", "savingsplans:DescribeSavingsPlans"},
}

// blastActions are used by the dependency lookup that runs for waste candidates.
// tfstateActions are needed only when Terraform state is read from S3.
var tfstateActions = []string{"s3:ListBucket", "s3:GetObject", "s3:GetBucketLocation"}

var blastActions = []string{
	"route53:ListHostedZones", "route53:ListResourceRecordSets",
	"cloudfront:ListDistributions",
	"ec2:DescribeRouteTables",
	"lambda:ListEventSourceMappings",
	"kinesis:ListStreamConsumers",
}

// WatchActions are what the live Problem Monitor calls. They are listed here,
// next to the scan's, so `infralens policy --watch` stays honest.
var WatchActions = []string{
	"cloudwatch:DescribeAlarms",
	"ecs:ListClusters", "ecs:ListServices", "ecs:DescribeServices", "ecs:ListTasks", "ecs:DescribeTasks",
	"elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth",
	"rds:DescribeDBInstances", "rds:DescribeDBClusters",
	"sqs:ListQueues", "sqs:GetQueueAttributes",
	"health:DescribeEvents", "health:DescribeAffectedEntities",
}

// Policy builds the minimal read-only IAM policy for the given scanners.
func Policy(scanners []Scanner, withBlast bool) ([]string, error) {
	set := map[string]bool{}
	for _, a := range baseActions {
		set[a] = true
	}
	for _, s := range scanners {
		acts, ok := scannerActions[s.Name]
		if !ok {
			return nil, fmt.Errorf("check %q has no IAM actions listed; add it to scannerActions", s.Name)
		}
		for _, a := range acts {
			set[a] = true
		}
	}
	if withBlast {
		for _, a := range blastActions {
			set[a] = true
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out, nil
}

// PolicyDocument renders actions as an IAM policy JSON document.
func PolicyDocument(actions []string) ([]byte, error) {
	doc := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Sid":      "InfraLensReadOnly",
			"Effect":   "Allow",
			"Action":   actions,
			"Resource": "*",
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}
