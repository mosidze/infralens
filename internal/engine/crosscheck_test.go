package engine

import (
	"strings"
	"testing"
)

func TestCrossCheckLowersAClaimContradictedByClusterRoles(t *testing.T) {
	res := ScanResult{
		Nodes: []ResourceNode{
			{ID: "pg-1", Type: "aws_rds_instance", Attrs: map[string]string{"role": "reader"}},
			{ID: "pg-2", Type: "aws_rds_instance", Attrs: map[string]string{"role": "writer"}},
		},
		Findings: []Finding{
			{ID: "a", Source: "trusted-advisor", Pillar: PillarCost, Severity: SevMedium, Title: "Amazon RDS Idle DB Instances", Resources: []string{"pg-1"}},
			{ID: "b", Source: "trusted-advisor", Pillar: PillarCost, Severity: SevMedium, Title: "Amazon RDS Idle DB Instances", Resources: []string{"pg-1", "pg-2"}, Rule: "ta.b"},
			{ID: "c", Source: "security-hub", Pillar: PillarSecurity, Severity: SevHigh, Title: "Amazon RDS Idle DB Instances", Resources: []string{"pg-1"}, Rule: "sh.c"},
		},
	}
	CrossCheck(&res)
	by := map[string]Finding{}
	for _, f := range res.Findings {
		by[f.ID] = f
	}
	if by["a"].Severity != SevLow || !strings.Contains(strings.Join(by["a"].Evidence, " "), "idle by design") {
		t.Fatalf("all readers: %+v", by["a"])
	}
	if by["b"].Severity != SevMedium || !strings.Contains(strings.Join(by["b"].Evidence, " "), "1 of the 2") {
		t.Fatalf("a writer is among them: severity stays, the fact is recorded: %+v", by["b"])
	}
	if by["c"].Severity != SevHigh {
		t.Fatalf("only Trusted Advisor's claim is cross-checked: %+v", by["c"])
	}
	// running twice must not duplicate the evidence
	n := len(by["a"].Evidence)
	CrossCheck(&res)
	if len(res.Findings[0].Evidence) != n && len(res.Findings[1].Evidence) != n {
		t.Fatal("not idempotent")
	}
}
