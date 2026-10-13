package engine

import "testing"

func TestFindingsAreDerivedFromVerdictsAndStayStable(t *testing.T) {
	res := ScanResult{Nodes: []ResourceNode{
		{ID: "vol-1", Name: "data", Type: "aws_ebs_volume", Region: "r", Status: StatusOrphanWaste, MonthlyCost: 600, Confidence: ConfHigh, WasteReason: "Unattached EBS volume"},
		{ID: "i-1", Name: "jump", Type: "aws_instance", Region: "r", Status: StatusShadowIT, MonthlyCost: 30},
		{ID: "ok", Name: "ok", Type: "aws_instance", Status: StatusManaged},
	}}
	Finalize(&res, nil)
	own := func() []Finding {
		var out []Finding
		for _, f := range res.Findings {
			if f.Rule != "ops.no-owner" {
				out = append(out, f)
			}
		}
		return out
	}
	if len(own()) != 2 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	first := own()[0]
	if first.Pillar != PillarCost || first.Severity != SevHigh || first.ResourceID != "vol-1" || first.Source != "own" {
		t.Fatalf("highest first: %+v", first)
	}
	if own()[1].Pillar != PillarIaC || own()[1].Affected != 1 || own()[1].ResourceType != "aws_instance" {
		t.Fatalf("shadow IT belongs to the IaC pillar: %+v", own()[1])
	}
	id, total := first.ID, len(res.Findings)
	// Finalize is run more than once; derived findings must be replaced, not duplicated.
	Finalize(&res, nil)
	if len(res.Findings) != total || own()[0].ID != id {
		t.Fatalf("not idempotent / not stable: %+v", res.Findings)
	}
}

func TestForeignFindingsSurviveFinalize(t *testing.T) {
	res := ScanResult{
		Nodes: []ResourceNode{{ID: "a", Type: "aws_lb", Status: StatusOrphanWaste, MonthlyCost: 16}},
		Findings: []Finding{
			{Pillar: PillarSecurity, Source: "security-hub", Rule: "sh.x", Severity: SevCritical, Title: "Root has access keys", ResourceID: "root"},
			{Pillar: PillarSecurity, Source: "security-hub", Rule: "sh.x", Severity: SevCritical, Title: "Root has access keys", ResourceID: "root"}, // duplicate
		},
	}
	Finalize(&res, nil)
	// one imported (deduplicated), one derived waste finding, one ownership summary
	if len(res.Findings) != 3 {
		t.Fatalf("expected 3 findings: %+v", res.Findings)
	}
	if res.Findings[0].Source != "security-hub" || res.Findings[0].Severity != SevCritical {
		t.Fatalf("critical must sort first: %+v", res.Findings[0])
	}
	for _, f := range res.Findings {
		if f.ID == "" {
			t.Fatal("every finding needs an id")
		}
	}
}

func TestCountByPillarKeepsAcknowledgedApart(t *testing.T) {
	fs := []Finding{
		{Pillar: PillarCost, Severity: SevHigh, MonthlyCost: 100},
		{Pillar: PillarCost, Severity: SevLow, MonthlyCost: 10, Ack: &Ack{Note: "expected"}},
		{Pillar: PillarSecurity, Severity: SevCritical},
	}
	got := CountByPillar(fs)
	if len(got) != 2 || got[0].Pillar != PillarSecurity || got[0].Critical != 1 {
		t.Fatalf("%+v", got)
	}
	if got[1].Open != 1 || got[1].Acknowledged != 1 || got[1].MonthlyCost != 100 {
		t.Fatalf("acknowledged cost must not count: %+v", got[1])
	}
}

func TestFindingIDIsDeterministic(t *testing.T) {
	if FindingID("own", "r", "x") != FindingID("own", "r", "x") || FindingID("own", "r", "x") == FindingID("own", "r", "y") {
		t.Fatal("id must depend on source, rule and resource, and nothing else")
	}
}
