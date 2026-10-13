package engine

import (
	"fmt"
	"sort"
	"strings"
)

// The cost ledger turns the bill into something a resource can be held to.
//
// Cost Explorer gives real dollars per usage type (a member account cannot
// see them per resource unless the payer opts in). A rule says which
// resources a usage type belongs to and which measured quantity (the
// "driver") divides it between them. What no rule can attribute stays visible
// as unallocated, with the usage type's name, instead of disappearing into a
// catalogue estimate.

// UsageLine is one row of Cost Explorer grouped by service and usage type.
type UsageLine struct {
	Service   string
	UsageType string // as Cost Explorer returns it, region prefix included
	Cost      float64
	Quantity  float64
}

// LedgerLine is one usage type and what became of it.
type LedgerLine struct {
	Usage     string  `json:"usage"`
	Region    string  `json:"region,omitempty"`
	Cost      float64 `json:"cost"`
	Allocated float64 `json:"allocated"`
	Reason    string  `json:"reason,omitempty"` // why it could not be (fully) allocated
}

// LedgerService is the bill of one service and how much of it was attributed.
type LedgerService struct {
	Service     string       `json:"service"`
	Billed      float64      `json:"billed"`
	Allocated   float64      `json:"allocated"`
	Unallocated []LedgerLine `json:"unallocated,omitempty"` // largest first
}

type Ledger struct {
	Month     string          `json:"month,omitempty"`
	Billed    float64         `json:"billed"`
	Allocated float64         `json:"allocated"`
	Services  []LedgerService `json:"services"`
}

// AllocRule ties a usage type to the resources it is spent on.
type AllocRule struct {
	Name    string
	Service string
	// Match receives the usage type with the region prefix removed.
	Match  func(usage string) bool
	Types  []string
	Driver string
	// Filter narrows the candidates, e.g. instance class equals the usage type's class.
	Filter func(n ResourceNode, usage string) bool
}

func exact(s string) func(string) bool { return func(u string) bool { return u == s } }

func attrIs(key, want string) func(ResourceNode, string) bool {
	return func(n ResourceNode, _ string) bool { return n.Attrs[key] == want }
}

func lastAfter(u, sep string) string {
	if i := strings.LastIndex(u, sep); i >= 0 {
		return u[i+len(sep):]
	}
	return u
}

// Rules cover the usage types that dominate typical bills. They are listed,
// not inferred: a usage type without a rule is reported as unallocated.
var Rules = func() []AllocRule {
	const (
		ecs  = "Amazon Elastic Container Service"
		rds  = "Amazon Relational Database Service"
		os   = "Amazon OpenSearch Service"
		ec2o = "EC2 - Other"
		kin  = "Amazon Kinesis"
		lam  = "AWS Lambda"
		s3   = "Amazon Simple Storage Service"
		elb  = "Amazon Elastic Load Balancing"
		mdb  = "Amazon MemoryDB"
		ec   = "Amazon ElastiCache"
		ddb  = "Amazon DynamoDB"
		sqs  = "Amazon Simple Queue Service"
		fh   = "Amazon Kinesis Firehose"
	)
	svc := []string{"aws_ecs_service"}
	r := []AllocRule{
		{Name: "fargate-vcpu-spot", Service: ecs, Match: exact("SpotUsage-Fargate-vCPU-Hours:perCPU"), Types: svc, Driver: "vcpu_h_spot"},
		{Name: "fargate-vcpu", Service: ecs, Match: exact("Fargate-vCPU-Hours:perCPU"), Types: svc, Driver: "vcpu_h_od"},
		{Name: "fargate-gb-spot", Service: ecs, Match: exact("SpotUsage-Fargate-GB-Hours"), Types: svc, Driver: "gb_h_spot"},
		{Name: "fargate-gb", Service: ecs, Match: exact("Fargate-GB-Hours"), Types: svc, Driver: "gb_h_od"},
		{Name: "fargate-vcpu-arm", Service: ecs, Match: exact("Fargate-ARM-vCPU-Hours:perCPU"), Types: svc, Driver: "vcpu_h_od_arm"},
		{Name: "fargate-gb-arm", Service: ecs, Match: exact("Fargate-ARM-GB-Hours"), Types: svc, Driver: "gb_h_od_arm"},
		{Name: "fargate-vcpu-arm-spot", Service: ecs, Match: exact("SpotUsage-Fargate-ARM-vCPU-Hours:perCPU"), Types: svc, Driver: "vcpu_h_spot_arm"},
		{Name: "fargate-gb-arm-spot", Service: ecs, Match: exact("SpotUsage-Fargate-ARM-GB-Hours"), Types: svc, Driver: "gb_h_spot_arm"},
		{Name: "fargate-ephemeral", Service: ecs, Match: exact("Fargate-EphemeralStorage-GB-Hours"), Types: svc, Driver: "eph_gb_h"},

		{Name: "rds-instance", Service: rds, Types: []string{"aws_rds_instance"}, Driver: "hours",
			Match:  func(u string) bool { return strings.HasPrefix(u, "InstanceUsage:") },
			Filter: func(n ResourceNode, u string) bool { return n.Attrs["class"] == lastAfter(u, ":") }},
		{Name: "rds-multi-az", Service: rds, Types: []string{"aws_rds_instance"}, Driver: "hours",
			Match: func(u string) bool { return strings.HasPrefix(u, "Multi-AZUsage:") },
			Filter: func(n ResourceNode, u string) bool {
				return n.Attrs["class"] == lastAfter(u, ":") && n.Attrs["multi_az"] == "true"
			}},

		{Name: "opensearch-instance", Service: os, Types: []string{"aws_opensearch_domain"}, Driver: "hours",
			Match:  func(u string) bool { return strings.HasPrefix(u, "ESInstance:") },
			Filter: func(n ResourceNode, u string) bool { return n.Attrs["instance_type"] == lastAfter(u, ":")+".search" }},
		{Name: "opensearch-gp2", Service: os, Match: exact("ES:GP2-Storage"), Types: []string{"aws_opensearch_domain"}, Driver: "ebs_gb", Filter: attrIs("volume_type", "gp2")},
		{Name: "opensearch-gp3", Service: os, Match: exact("ES:GP3-Storage"), Types: []string{"aws_opensearch_domain"}, Driver: "ebs_gb", Filter: attrIs("volume_type", "gp3")},

		{Name: "nat-hours", Service: ec2o, Match: exact("NatGateway-Hours"), Types: []string{"aws_nat_gateway"}, Driver: "hours"},
		{Name: "nat-bytes", Service: ec2o, Match: exact("NatGateway-Bytes"), Types: []string{"aws_nat_gateway"}, Driver: "gb"},
	}
	// EBS volumes: all volumes are inventoried, so volume usage can be split.
	for suffix, vt := range map[string][]string{".gp2": {"gp2"}, ".gp3": {"gp3"}, ".sc1": {"sc1"}, ".st1": {"st1"}, ".piops": {"io1", "io2"}, "": {"standard"}} {
		vt := vt
		r = append(r, AllocRule{Name: "ebs-volume" + suffix, Service: ec2o, Match: exact("EBS:VolumeUsage" + suffix),
			Types: []string{"aws_ebs_volume"}, Driver: "gb",
			Filter: func(n ResourceNode, _ string) bool {
				for _, t := range vt {
					if n.Attrs["volume_type"] == t {
						return true
					}
				}
				return false
			}})
	}
	r = append(r,
		AllocRule{Name: "kinesis-on-demand-hours", Service: kin, Match: exact("OnDemand-StreamHour"), Types: []string{"aws_kinesis_stream"}, Driver: "hours_od"},
		AllocRule{Name: "kinesis-shard-hours", Service: kin, Match: exact("Storage-ShardHour"), Types: []string{"aws_kinesis_stream"}, Driver: "shard_hours"},
		AllocRule{Name: "kinesis-incoming", Service: kin, Match: exact("OnDemand-BilledIncomingBytes"), Types: []string{"aws_kinesis_stream"}, Driver: "in_gb"},

		AllocRule{Name: "lambda-gb-seconds", Service: lam, Match: exact("Lambda-GB-Second"), Types: []string{"aws_lambda_function"}, Driver: "gb_s"},
		AllocRule{Name: "lambda-gb-seconds-arm", Service: lam, Match: exact("Lambda-GB-Second-ARM"), Types: []string{"aws_lambda_function"}, Driver: "gb_s_arm"},
		AllocRule{Name: "lambda-requests", Service: lam, Match: exact("Request"), Types: []string{"aws_lambda_function"}, Driver: "invocations"},

		AllocRule{Name: "s3-standard-storage", Service: s3, Match: exact("TimedStorage-ByteHrs"), Types: []string{"aws_s3_bucket"}, Driver: "gb_std"},
		AllocRule{Name: "elb-hours", Service: elb, Match: exact("LoadBalancerUsage"), Types: []string{"aws_lb"}, Driver: "hours"},

		AllocRule{Name: "memorydb-nodes", Service: mdb, Types: []string{"aws_memorydb_cluster"}, Driver: "hours",
			Match: func(u string) bool { return strings.HasPrefix(u, "NodeUsage:") },
			Filter: func(n ResourceNode, u string) bool {
				p := strings.Split(u, ":")
				return len(p) >= 2 && n.Attrs["node_type"] == p[1]
			}},
		AllocRule{Name: "elasticache-nodes", Service: ec, Types: []string{"aws_elasticache_cluster"}, Driver: "hours",
			Match:  func(u string) bool { return strings.HasPrefix(u, "NodeUsage:") },
			Filter: func(n ResourceNode, u string) bool { return n.Attrs["node_type"] == lastAfter(u, ":") }},

		AllocRule{Name: "dynamodb-writes", Service: ddb, Match: exact("WriteRequestUnits"), Types: []string{"aws_dynamodb_table"}, Driver: "w_units"},
		AllocRule{Name: "dynamodb-reads", Service: ddb, Match: exact("ReadRequestUnits"), Types: []string{"aws_dynamodb_table"}, Driver: "r_units"},
		AllocRule{Name: "dynamodb-rcu", Service: ddb, Match: exact("ReadCapacityUnit-Hrs"), Types: []string{"aws_dynamodb_table"}, Driver: "rcu_h"},
		AllocRule{Name: "dynamodb-wcu", Service: ddb, Match: exact("WriteCapacityUnit-Hrs"), Types: []string{"aws_dynamodb_table"}, Driver: "wcu_h"},
		AllocRule{Name: "dynamodb-storage", Service: ddb, Match: exact("TimedStorage-ByteHrs"), Types: []string{"aws_dynamodb_table"}, Driver: "gb"},

		AllocRule{Name: "sqs-standard", Service: sqs, Match: exact("Requests-Tier1"), Types: []string{"aws_sqs_queue"}, Driver: "requests", Filter: attrIs("fifo", "false")},
		AllocRule{Name: "sqs-fifo", Service: sqs, Match: exact("Requests-FIFO-Tier1"), Types: []string{"aws_sqs_queue"}, Driver: "requests", Filter: attrIs("fifo", "true")},
		AllocRule{Name: "firehose-ingest", Service: fh, Match: exact("BilledBytes"), Types: []string{"aws_firehose_stream"}, Driver: "in_gb"},
	)
	return r
}()

// regionPrefix maps the prefix Cost Explorer puts in front of a usage type
// to a region. us-east-1 has no prefix.
var regionPrefix = map[string]string{
	"EUN1": "eu-north-1", "EU": "eu-west-1", "EUC1": "eu-central-1", "EUW2": "eu-west-2", "EUW3": "eu-west-3",
	"EUS1": "eu-south-1", "EUS2": "eu-south-2", "EUC2": "eu-central-2",
	"USE2": "us-east-2", "USW1": "us-west-1", "USW2": "us-west-2",
	"APN1": "ap-northeast-1", "APN2": "ap-northeast-2", "APN3": "ap-northeast-3",
	"APS1": "ap-southeast-1", "APS2": "ap-southeast-2", "APS3": "ap-south-1", "APE1": "ap-east-1",
	"CAN1": "ca-central-1", "SAE1": "sa-east-1", "AFS1": "af-south-1", "MES1": "me-south-1",
}

// SplitUsageType separates the region prefix from the usage type.
func SplitUsageType(u string) (region, usage string) {
	if i := strings.Index(u, "-"); i > 0 {
		if r, ok := regionPrefix[u[:i]]; ok {
			return r, u[i+1:]
		}
	}
	return "us-east-1", u
}

const minLedgerLine = 1.0 // lines below one dollar are not worth listing

// Allocate distributes the bill over the resources and records what remains.
// It replaces MonthlyCost by allocated money on resources that received some
// and keeps the catalogue estimate in ListCost. It is safe to run again.
func Allocate(res *ScanResult, lines []UsageLine) {
	// reset from an earlier run
	for i := range res.Nodes {
		n := &res.Nodes[i]
		if n.CostBasis == "allocated" && n.ListCost > 0 {
			n.MonthlyCost = n.ListCost
		}
		if n.ListCost == 0 {
			n.ListCost = n.MonthlyCost
		}
		n.CostBasis, n.CostNote = "", ""
		if n.CostSource == CostNotAvailable {
			n.CostBasis = "n/a"
		} else if n.ListCost > 0 || n.CostSource == CostEstimated {
			n.CostBasis = "estimated"
		}
	}

	got := make([]float64, len(res.Nodes))
	notes := make([][]string, len(res.Nodes))
	byService := map[string]*LedgerService{}
	svc := func(name string) *LedgerService {
		s := byService[name]
		if s == nil {
			s = &LedgerService{Service: name}
			byService[name] = s
		}
		return s
	}

	for _, l := range lines {
		if l.Cost <= 0 {
			continue
		}
		region, usage := SplitUsageType(l.UsageType)
		s := svc(l.Service)
		s.Billed += l.Cost

		var rule *AllocRule
		for i := range Rules {
			r := &Rules[i]
			if r.Service == l.Service && r.Match(usage) {
				rule = r
				break
			}
		}
		line := LedgerLine{Usage: usage, Region: region, Cost: l.Cost}
		if rule == nil {
			line.Reason = "no rule: usage not tied to a resource this tool inventories"
			s.Unallocated = append(s.Unallocated, line)
			continue
		}
		types := map[string]bool{}
		for _, t := range rule.Types {
			types[t] = true
		}
		var idx []int
		var sum float64
		for i, n := range res.Nodes {
			if !types[n.Type] || n.Region != region {
				continue
			}
			if rule.Filter != nil && !rule.Filter(n, usage) {
				continue
			}
			if d := n.Drivers[rule.Driver]; d > 0 {
				idx = append(idx, i)
				sum += d
			}
		}
		if len(idx) == 0 {
			line.Reason = "no current resource carries it (deleted since, or not inventoried)"
			s.Unallocated = append(s.Unallocated, line)
			continue
		}
		for _, i := range idx {
			share := l.Cost * res.Nodes[i].Drivers[rule.Driver] / sum
			got[i] += share
			notes[i] = append(notes[i], fmt.Sprintf("%s $%.2f", usage, share))
		}
		s.Allocated += l.Cost
	}

	for i := range res.Nodes {
		if got[i] > 0 {
			n := &res.Nodes[i]
			n.MonthlyCost = got[i]
			n.CostBasis = "allocated"
			n.CostNote = "allocated from last month's bill by usage: " + strings.Join(notes[i], ", ")
		}
	}

	led := &Ledger{}
	for _, s := range byService {
		sort.Slice(s.Unallocated, func(i, j int) bool { return s.Unallocated[i].Cost > s.Unallocated[j].Cost })
		kept := s.Unallocated[:0]
		for _, l := range s.Unallocated {
			if l.Cost >= minLedgerLine {
				kept = append(kept, l)
			}
		}
		if len(kept) > 12 {
			kept = kept[:12]
		}
		s.Unallocated = kept
		led.Billed += s.Billed
		led.Allocated += s.Allocated
		led.Services = append(led.Services, *s)
	}
	sort.Slice(led.Services, func(i, j int) bool { return led.Services[i].Billed > led.Services[j].Billed })
	res.Ledger = led
}

// LedgerFindings turns the largest unattributed lines and one well-known
// pricing pattern into findings. They state facts about the bill; whether
// they are a problem depends on plans the tool cannot know.
func LedgerFindings(res *ScanResult) []Finding {
	if res.Ledger == nil {
		return nil
	}
	var out []Finding
	for _, s := range res.Ledger.Services {
		for _, l := range s.Unallocated {
			// Aurora I/O gets its own, more useful finding below.
			if l.Cost < 150 || l.Cost < 0.1*s.Billed || strings.HasSuffix(l.Usage, "Aurora:StorageIOUsage") {
				continue
			}
			f := Finding{
				Pillar: PillarCost, Source: "own", Rule: "cost.unattributed-usage", Severity: SevInfo,
				Title:       fmt.Sprintf("%s: %s is $%.0f a month and is not tied to a resource", s.Service, l.Usage, l.Cost),
				MonthlyCost: l.Cost, ResourceID: "usage:" + s.Service + ":" + l.Usage + ":" + l.Region, Region: l.Region,
				Evidence:       []string{l.Reason, fmt.Sprintf("%.0f%% of this service's bill last month", l.Cost/s.Billed*100)},
				Recommendation: "Find what generates this usage (account-level feature, request volume, data transfer) before looking at individual resources.",
				Confidence:     ConfHigh, Effort: "medium",
			}
			f.ID = FindingID(f.Source, f.Rule, f.ResourceID)
			out = append(out, f)
		}
		if s.Service == "Amazon Relational Database Service" {
			if f, ok := auroraIOFinding(s); ok {
				out = append(out, f)
			}
		}
	}
	// A bill has a long tail; list only the largest so the real findings stay readable.
	sort.SliceStable(out, func(i, j int) bool { return out[i].MonthlyCost > out[j].MonthlyCost })
	const maxLedgerFindings = 8
	if len(out) > maxLedgerFindings {
		out = out[:maxLedgerFindings]
	}
	return out
}

// auroraIOFinding flags Aurora where per-request I/O charges are a large
// share of the bill. AWS's own guidance is to evaluate the I/O-Optimized
// configuration when I/O exceeds roughly a quarter of Aurora spend; the
// finding says to evaluate, not that it will be cheaper.
func auroraIOFinding(s LedgerService) (Finding, bool) {
	var io, total float64
	scan := func(u string, cost float64) {
		switch {
		case strings.HasSuffix(u, "Aurora:StorageIOUsage"):
			io += cost
			total += cost
		case strings.Contains(u, "Aurora:"), strings.HasPrefix(u, "InstanceUsage:"), strings.HasPrefix(u, "Multi-AZUsage:"):
			total += cost
		}
	}
	for _, l := range s.Unallocated {
		scan(l.Usage, l.Cost)
	}
	// allocated instance usage is not listed per line; use the service total for the denominator
	if io <= 0 {
		return Finding{}, false
	}
	if s.Billed > total {
		total = s.Billed
	}
	if io/total < 0.25 || io < 100 {
		return Finding{}, false
	}
	f := Finding{
		Pillar: PillarCost, Source: "own", Rule: "cost.aurora-io-share", Severity: SevMedium,
		Title:       fmt.Sprintf("Aurora I/O charges are %.0f%% of the RDS bill ($%.0f a month)", io/total*100, io),
		MonthlyCost: io, ResourceID: "usage:aurora-io", Confidence: ConfMedium, Effort: "low",
		Evidence: []string{
			fmt.Sprintf("StorageIOUsage $%.0f of $%.0f RDS spend last month", io, s.Billed),
			"computed across all Aurora clusters in the account; the decision is per cluster",
		},
		Recommendation: "Evaluate the Aurora I/O-Optimized configuration per cluster: it removes per-I/O charges at a higher instance price and is usually worth checking when I/O exceeds about a quarter of Aurora spend. Compare with the current pricing page before deciding.",
	}
	f.ID = FindingID(f.Source, f.Rule, f.ResourceID)
	return f, true
}
