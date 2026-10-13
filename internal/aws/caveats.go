package aws

// Caveats lists, per node type, what a verdict cannot see. They are shown by
// `infralens explain` and belong in front of anyone about to act on a finding:
// a metric-based verdict is evidence of non-use in a window, not proof.
func Caveats(nodeType string) []string {
	switch nodeType {
	case "aws_rds_instance":
		return []string{
			"Idle means zero DatabaseConnections in the window; a job that connects less often than the window (monthly batch, quarterly report) is invisible.",
			"Connections through a proxy or a different endpoint of the same cluster are counted on the instance that served them; check the cluster endpoint and reader endpoint consumers.",
			"Aurora readers are failover targets and are not judged. A cluster that is idle as a whole shows up as an idle writer.",
			"Cost is list price; reservations and Savings Plans are invisible from this account.",
		}
	case "aws_nat_gateway":
		return []string{
			"Idle means almost no bytes sent in the window; a route kept only for failover or rare jobs looks idle.",
			"Deleting a gateway with live route-table entries breaks egress for that subnet; check routes first.",
			"Data processing cost is extrapolated from the window.",
		}
	case "aws_lb":
		return []string{
			"No target groups with only fixed-response/redirect listeners is often a deliberate placeholder or redirector.",
			"DNS records (Route53, external DNS) and CloudFront origins pointing at the balancer are not checked yet; verify before removal.",
		}
	case "aws_ebs_volume":
		return []string{
			"Unattached is a point-in-time state; a volume detached for a planned failover or restore is not garbage.",
			"Check for a snapshot before deleting; an unattached volume may be the only copy.",
		}
	case "aws_ebs_snapshot":
		return []string{
			"Cost is an upper bound: snapshots are incremental, a snapshot can share blocks with others.",
			"Snapshots referenced by AMIs are excluded, but backup tooling outside AWS (restore catalogues) is not visible.",
		}
	case "aws_eip":
		return []string{
			"An address may be whitelisted by a third party; releasing it loses that address permanently.",
		}
	case "aws_kinesis_stream":
		return []string{
			"Idle means no incoming bytes in the window; seasonal or backfill producers are invisible.",
			"Consumers (Lambda, Firehose, KCL apps) are not enumerated yet; a stream with consumers but no producers may still be expected to receive data.",
		}
	case "aws_opensearch_domain":
		return []string{
			"Idle means zero search and indexing rate in the window; dashboards or scheduled queries outside the window are invisible.",
			"On-demand price; reserved instances are not visible from a member account.",
		}
	case "aws_cloudwatch_log_group":
		return []string{
			"A group with no retention and no ingestion may be kept deliberately for compliance.",
		}
	case "aws_lambda_function":
		return []string{
			"Cost is computed from invocations and duration in the window; provisioned concurrency, data transfer and the services a function calls are not included.",
			"A function with no invocations costs nothing while idle; it is clutter and a possible dependency, not a saving.",
		}
	case "aws_vpc_endpoint":
		return []string{
			"Interface endpoints bill per availability zone per hour plus data processed; only the standing part is estimated.",
			"Usage of an endpoint is not checked: removing one makes traffic to that service take the NAT or internet path.",
		}
	case "aws_sqs_queue":
		return []string{
			"Cost is request charges estimated from message counts; long polling and batching change the real request count.",
			"A dead-letter queue with no traffic is usually healthy, not abandoned.",
		}
	case "aws_firehose_stream":
		return []string{
			"Only ingestion is estimated; format conversion, VPC delivery and destination costs are not.",
		}
	case "aws_cloudfront_distribution":
		return []string{
			"Only request charges are estimated; data transfer out is usually the larger part and is not modelled.",
			"Aliases, certificates and DNS records pointing at a distribution are not enumerated here.",
		}
	case "aws_redshift_cluster":
		return []string{
			"Idle means zero DatabaseConnections in the window; scheduled loads and BI refreshes that run less often are invisible.",
			"Pausing a cluster is reversible and stops compute billing; deleting is not. Take a final snapshot first.",
			"On-demand price; reserved nodes are not visible from a member account.",
		}
	case "aws_memorydb_cluster":
		return []string{
			"Idle means zero client connections in the window; MemoryDB is durable and may hold the only copy of its data.",
			"The node price table is approximate; compare with the bill before quoting the figure.",
		}
	case "aws_elasticache_cluster":
		return []string{
			"Only standalone clusters are judged; members of a replication group are not, because replication links look like connections.",
			"A cache that is empty or cold costs the same as a busy one; check that nothing is waiting to be warmed.",
		}
	case "aws_dynamodb_table":
		return []string{
			"Idle means no consumed capacity in the window; DynamoDB emits no datapoints at all when nothing is consumed, so this is the expected shape of an idle table and also of one missing from the metrics.",
			"Provisioned capacity can be lowered or switched to on-demand without losing data; deletion loses it.",
			"Tables with global replicas, streams or backups have dependents that are not listed.",
		}
	}
	switch nodeType {
	case "aws_s3_bucket":
		return []string{
			"Size is the Standard storage class only; other classes, requests and transfer are not modelled.",
			"Bucket policies, replication and access patterns are not analysed; no verdict of 'unused' is issued.",
		}
	}
	return nil
}
