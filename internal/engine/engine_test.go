package engine

import (
	"math"
	"testing"
)

func TestClassifyManagement(t *testing.T) {
	cases := []struct {
		name    string
		tags    map[string]string
		status  ResourceStatus
		managed string
		conf    Confidence
	}{
		{"cfn", map[string]string{"aws:cloudformation:stack-id": "arn:x"}, StatusManaged, "CloudFormation", ConfHigh},
		{"terraform key", map[string]string{"Terraform": "true"}, StatusManaged, "Terraform", ConfHigh},
		{"managedby terraform", map[string]string{"ManagedBy": "terraform"}, StatusManaged, "terraform", ConfHigh},
		{"managedby unknown tool", map[string]string{"managed-by": "bob"}, StatusManaged, "bob", ConfMedium},
		{"only name tag", map[string]string{"Name": "web"}, StatusShadowIT, "", ConfMedium},
		{"no tags", nil, StatusShadowIT, "", ConfMedium},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyManagement(c.tags)
			if got.Status != c.status || got.ManagedBy != c.managed || got.Confidence != c.conf {
				t.Fatalf("got %+v, want status=%s managed=%q conf=%s", got, c.status, c.managed, c.conf)
			}
			if got.Evidence == "" {
				t.Fatal("evidence must not be empty")
			}
		})
	}
}

func TestFinalize(t *testing.T) {
	res := ScanResult{
		Nodes: []ResourceNode{
			{ID: "a", Status: StatusOrphanWaste, MonthlyCost: 10},
			{ID: "b", Status: StatusShadowIT, MonthlyCost: 5},
			{ID: "c", Status: StatusManaged, MonthlyCost: 1},
		},
		Edges: []Edge{
			{"a", "b", "x"}, {"a", "b", "x"}, // duplicate
			{"a", "zzz", "x"}, // unknown target
			{"c", "c", "x"},   // self loop
			{"b", "c", ""},
		},
	}
	Finalize(&res, map[string]string{"aws_instance": "EC2"})
	if len(res.Edges) != 2 {
		t.Fatalf("edges = %v", res.Edges)
	}
	if res.TotalLive != 3 || res.WasteCount != 1 || res.ShadowCount != 1 {
		t.Fatalf("counters wrong: %+v", res)
	}
	if res.TotalWaste != 10 || res.EstimatedTCO != 16 {
		t.Fatalf("money wrong: waste=%v tco=%v", res.TotalWaste, res.EstimatedTCO)
	}
}

func TestPricing(t *testing.T) {
	if got := EBSMonthlyCost("gp3", 100); math.Abs(got-8) > 1e-9 {
		t.Fatalf("gp3 100GB = %v", got)
	}
	if got := MonthlyFromHourly(NATGatewayHour); math.Abs(got-32.85) > 1e-9 {
		t.Fatalf("nat = %v", got)
	}
	single, known := EstimateRDSCost("db.t3.medium", 100, false, "gp3")
	multi, _ := EstimateRDSCost("db.t3.medium", 100, true, "gp3")
	if !known || math.Abs(multi-2*single) > 1e-9 {
		t.Fatalf("multi-az must double: single=%v multi=%v", single, multi)
	}
	if _, known := EstimateRDSCost("db.weird.huge", 10, false, "gp2"); known {
		t.Fatal("unknown class must report known=false")
	}
	if got := FargateMonthlyCost(1024, 2048, 2); got <= 0 {
		t.Fatalf("fargate = %v", got)
	}
}

func TestSplitTasksAndSpotBlend(t *testing.T) {
	// FARGATE base 1 + FARGATE_SPOT weight 4 (the estate's default strategy)
	ps := []ProviderShare{{"FARGATE_SPOT", 0, 4}, {"FARGATE", 1, 1}}
	got := SplitTasks(6, ps)
	if math.Abs(got["FARGATE"]-2) > 1e-9 || math.Abs(got["FARGATE_SPOT"]-4) > 1e-9 {
		t.Fatalf("split = %v", got)
	}
	if eq := FargateBlendedTasks(got); math.Abs(eq-(2+4*FargateSpotFactor)) > 1e-9 {
		t.Fatalf("blended = %v", eq)
	}
	if got := SplitTasks(1, ps); got["FARGATE"] != 1 || got["FARGATE_SPOT"] != 0 {
		t.Fatalf("single task must take the base: %v", got)
	}
	if got := SplitTasks(3, []ProviderShare{{"FARGATE_SPOT", 0, 1}}); got["FARGATE_SPOT"] != 3 {
		t.Fatalf("spot-only: %v", got)
	}
}
