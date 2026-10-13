package engine

import (
	"math"
	"strings"
	"testing"
)

func near(a, b float64) bool { return math.Abs(a-b) < 0.01 }

func TestSplitUsageType(t *testing.T) {
	for in, want := range map[string][2]string{
		"EUN1-NatGateway-Bytes":           {"eu-north-1", "NatGateway-Bytes"},
		"EU-NatGateway-Hours":             {"eu-west-1", "NatGateway-Hours"},
		"NatGateway-Hours":                {"us-east-1", "NatGateway-Hours"},
		"EUN1-USE1-AWS-Out-Bytes":         {"eu-north-1", "USE1-AWS-Out-Bytes"},
		"DataTransfer-Out-Bytes":          {"us-east-1", "DataTransfer-Out-Bytes"},
		"EUC1-SpotUsage-Fargate-GB-Hours": {"eu-central-1", "SpotUsage-Fargate-GB-Hours"},
		"USW2-Requests-Tier1":             {"us-west-2", "Requests-Tier1"},
	} {
		r, u := SplitUsageType(in)
		if r != want[0] || u != want[1] {
			t.Errorf("%s -> %s %s, want %v", in, r, u, want)
		}
	}
}

func node(id, typ, region string, attrs map[string]string, drv map[string]float64) ResourceNode {
	return ResourceNode{ID: id, Name: id, Type: typ, Region: region, Attrs: attrs, Drivers: drv,
		MonthlyCost: 10, CostSource: CostEstimated}
}

func TestAllocationSplitsByDriverAndConserves(t *testing.T) {
	res := ScanResult{Nodes: []ResourceNode{
		node("nat-a", "aws_nat_gateway", "eu-north-1", nil, map[string]float64{"hours": 730, "gb": 1000}),
		node("nat-b", "aws_nat_gateway", "eu-north-1", nil, map[string]float64{"hours": 730, "gb": 3000}),
		node("nat-other-region", "aws_nat_gateway", "eu-west-1", nil, map[string]float64{"hours": 730, "gb": 9999}),
	}}
	Allocate(&res, []UsageLine{
		{Service: "EC2 - Other", UsageType: "EUN1-NatGateway-Hours", Cost: 100},
		{Service: "EC2 - Other", UsageType: "EUN1-NatGateway-Bytes", Cost: 400},
		{Service: "EC2 - Other", UsageType: "EUN1-DataTransfer-Regional-Bytes", Cost: 50},
	})
	a, b, o := res.Nodes[0], res.Nodes[1], res.Nodes[2]
	// hours split equally (50/50), bytes 1:3 (100/300)
	if !near(a.MonthlyCost, 50+100) || !near(b.MonthlyCost, 50+300) {
		t.Fatalf("allocation: %v %v", a.MonthlyCost, b.MonthlyCost)
	}
	if a.CostBasis != "allocated" || a.ListCost != 10 {
		t.Fatalf("basis/list cost: %+v", a)
	}
	if o.CostBasis == "allocated" || o.MonthlyCost != 10 {
		t.Fatalf("another region's gateway must not receive eu-north-1 money: %+v", o)
	}
	l := res.Ledger
	if !near(l.Billed, 550) || !near(l.Allocated, 500) {
		t.Fatalf("ledger: %+v", l)
	}
	// conservation: allocated to resources equals allocated in the ledger
	if !near(a.MonthlyCost+b.MonthlyCost, l.Allocated) {
		t.Fatal("money must be conserved")
	}
	un := l.Services[0].Unallocated
	if len(un) != 1 || !strings.Contains(un[0].Usage, "DataTransfer") || !strings.Contains(un[0].Reason, "no rule") {
		t.Fatalf("what is not attributed must be listed with a reason: %+v", un)
	}
}

func TestAllocationIsScopedByService(t *testing.T) {
	// "TimedStorage-ByteHrs" is the usage type of both S3 and DynamoDB.
	res := ScanResult{Nodes: []ResourceNode{
		node("bucket", "aws_s3_bucket", "eu-north-1", nil, map[string]float64{"gb_std": 100}),
		node("table", "aws_dynamodb_table", "eu-north-1", nil, map[string]float64{"gb": 50}),
	}}
	Allocate(&res, []UsageLine{
		{Service: "Amazon Simple Storage Service", UsageType: "EUN1-TimedStorage-ByteHrs", Cost: 450},
		{Service: "Amazon DynamoDB", UsageType: "EUN1-TimedStorage-ByteHrs", Cost: 10},
	})
	if !near(res.Nodes[0].MonthlyCost, 450) || !near(res.Nodes[1].MonthlyCost, 10) {
		t.Fatalf("service scoping: %v %v", res.Nodes[0].MonthlyCost, res.Nodes[1].MonthlyCost)
	}
}

func TestAllocationFiltersByAttributes(t *testing.T) {
	res := ScanResult{Nodes: []ResourceNode{
		node("big", "aws_rds_instance", "eu-north-1", map[string]string{"class": "db.r6g.large"}, map[string]float64{"hours": 730}),
		node("big2", "aws_rds_instance", "eu-north-1", map[string]string{"class": "db.r6g.large"}, map[string]float64{"hours": 730}),
		node("small", "aws_rds_instance", "eu-north-1", map[string]string{"class": "db.t4g.medium"}, map[string]float64{"hours": 730}),
	}}
	Allocate(&res, []UsageLine{
		{Service: "Amazon Relational Database Service", UsageType: "EUN1-InstanceUsage:db.r6g.large", Cost: 440},
		{Service: "Amazon Relational Database Service", UsageType: "EUN1-InstanceUsage:db.t4g.medium", Cost: 210},
	})
	if !near(res.Nodes[0].MonthlyCost, 220) || !near(res.Nodes[1].MonthlyCost, 220) || !near(res.Nodes[2].MonthlyCost, 210) {
		t.Fatalf("class filter: %v %v %v", res.Nodes[0].MonthlyCost, res.Nodes[1].MonthlyCost, res.Nodes[2].MonthlyCost)
	}
}

func TestMoneyForResourcesThatNoLongerExistStaysVisible(t *testing.T) {
	res := ScanResult{}
	Allocate(&res, []UsageLine{{Service: "Amazon Relational Database Service", UsageType: "EUN1-InstanceUsage:db.m5.large", Cost: 300}})
	l := res.Ledger.Services[0]
	if !near(l.Allocated, 0) || len(l.Unallocated) != 1 || !strings.Contains(l.Unallocated[0].Reason, "no current resource") {
		t.Fatalf("%+v", l)
	}
}

func TestAllocateIsIdempotent(t *testing.T) {
	res := ScanResult{Nodes: []ResourceNode{node("n", "aws_nat_gateway", "eu-north-1", nil, map[string]float64{"hours": 730})}}
	lines := []UsageLine{{Service: "EC2 - Other", UsageType: "EUN1-NatGateway-Hours", Cost: 70}}
	Allocate(&res, lines)
	Allocate(&res, lines)
	if !near(res.Nodes[0].MonthlyCost, 70) || res.Nodes[0].ListCost != 10 {
		t.Fatalf("a second run must give the same answer: %+v", res.Nodes[0])
	}
	// without allocation data the estimate comes back
	Allocate(&res, nil)
	if res.Nodes[0].MonthlyCost != 10 || res.Nodes[0].CostBasis != "estimated" {
		t.Fatalf("estimate must be restored: %+v", res.Nodes[0])
	}
}

func TestLedgerFindings(t *testing.T) {
	res := ScanResult{}
	Allocate(&res, []UsageLine{
		{Service: "AmazonCloudWatch", UsageType: "EUN1-CW:MetricStreamUsage", Cost: 747},
		{Service: "AmazonCloudWatch", UsageType: "EUN1-CW:Requests", Cost: 50},
		{Service: "Amazon Relational Database Service", UsageType: "EUN1-Aurora:StorageIOUsage", Cost: 533},
		{Service: "Amazon Relational Database Service", UsageType: "EUN1-InstanceUsage:db.r6g.large", Cost: 441},
		{Service: "Amazon Relational Database Service", UsageType: "EUN1-Aurora:StorageUsage", Cost: 34},
	})
	fs := LedgerFindings(&res)
	var cw, aurora *Finding
	for i := range fs {
		switch fs[i].Rule {
		case "cost.unattributed-usage":
			if strings.Contains(fs[i].Title, "MetricStreamUsage") {
				cw = &fs[i]
			}
		case "cost.aurora-io-share":
			aurora = &fs[i]
		}
	}
	if cw == nil || cw.MonthlyCost != 747 {
		t.Fatalf("a large unattributed line must be reported: %+v", fs)
	}
	if aurora == nil || aurora.Severity != SevMedium {
		t.Fatalf("Aurora I/O share: %+v", fs)
	}
	lower := strings.ToLower(aurora.Recommendation)
	if !strings.Contains(lower, "evaluate") || strings.Contains(lower, "will save") || strings.Contains(lower, "cheaper than") {
		t.Fatalf("must say evaluate, not promise: %q", aurora.Recommendation)
	}
	// the Aurora I/O line is reported once, by its own finding
	for _, f := range fs {
		if f.Rule == "cost.unattributed-usage" && strings.Contains(f.Title, "StorageIOUsage") {
			t.Fatal("Aurora I/O must not appear twice")
		}
	}
	// a small request line is not worth a finding
	for _, f := range fs {
		if strings.Contains(f.Title, "CW:Requests") {
			t.Fatal("a $50 line must not become a finding")
		}
	}
}

func TestLedgerFindingsAreCapped(t *testing.T) {
	var lines []UsageLine
	for i := 0; i < 30; i++ {
		lines = append(lines, UsageLine{Service: "Svc" + string(rune('A'+i%26)) + string(rune('a'+i/26)), UsageType: "EUN1-Thing", Cost: float64(200 + i)})
	}
	res := ScanResult{}
	Allocate(&res, lines)
	fs := LedgerFindings(&res)
	if len(fs) != 8 {
		t.Fatalf("expected the 8 largest, got %d", len(fs))
	}
	if fs[0].MonthlyCost < fs[len(fs)-1].MonthlyCost {
		t.Fatal("largest first")
	}
}
