package engine

import (
	"strings"
	"testing"
)

func TestOwnerFromTags(t *testing.T) {
	cases := []struct {
		tags     map[string]string
		val, src string
	}{
		{map[string]string{"Team": "payments"}, "payments", "tag:Team"},
		{map[string]string{"owner": "alice", "Team": "payments"}, "alice", "tag:owner"}, // owner beats team
		{map[string]string{"CostCenter": "cc-12", "Project": "x"}, "cc-12", "tag:CostCenter"},
		{map[string]string{"ApplicationGroup": "checkout"}, "checkout", "tag:ApplicationGroup"},
		{map[string]string{"Name": "web", "Environment": "prod"}, "", ""}, // not ownership
		{map[string]string{"Owner": "  "}, "", ""},                        // blank is not an owner
		{nil, "", ""},
	}
	for _, c := range cases {
		v, s := OwnerFromTags(c.tags)
		if v != c.val || s != c.src {
			t.Errorf("%v -> %q %q, want %q %q", c.tags, v, s, c.val, c.src)
		}
	}
}

func TestOwnerlessResourcesBecomeOneFinding(t *testing.T) {
	res := ScanResult{Nodes: []ResourceNode{
		{ID: "a", Name: "a", Type: "aws_lb", MonthlyCost: 100, Tags: map[string]string{"Team": "t"}},
		{ID: "b", Name: "b", Type: "aws_instance", MonthlyCost: 300},
		{ID: "c", Name: "c", Type: "aws_ebs_volume", MonthlyCost: 8},
		{ID: "r", Name: "rollup", Type: "aws_cloudwatch_log_group_rollup", MonthlyCost: 50}, // not ownable
	}}
	Finalize(&res, nil)
	var f *Finding
	for i := range res.Findings {
		if res.Findings[i].Rule == "ops.no-owner" {
			f = &res.Findings[i]
		}
	}
	if f == nil || f.Affected != 2 || f.MonthlyCost != 308 || f.Pillar != PillarOps {
		t.Fatalf("%+v", f)
	}
	if !strings.Contains(f.Title, "2 of 3") || !strings.Contains(f.Evidence[1], "b (instance") {
		t.Fatalf("%+v", f)
	}
	if res.Nodes[0].Owner != "t" || res.Nodes[1].Owner != "" {
		t.Fatalf("owners: %+v", res.Nodes)
	}
}
