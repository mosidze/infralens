package ai

import (
	"encoding/json"
	"strings"
	"testing"

	"infralens/internal/engine"
)

func sample() engine.ScanResult {
	return engine.ScanResult{
		Regions: []string{"eu-west-1"},
		Nodes: []engine.ResourceNode{
			{ID: "arn:aws:ecs:eu-west-1:123456789012:service/prod/payments-api", Name: "payments-api", Type: "aws_ecs_service",
				Region: "eu-west-1", VPCID: "vpc-0abc", Tags: map[string]string{"owner": "alice@corp.example"},
				Attrs:    map[string]string{"desired": "2", "dns_name": "secret.internal.example"},
				Evidence: []string{"inherits from cluster prod-secret"}},
			{ID: "vol-0123456789abcdef0", Name: "orders-db-data", Type: "aws_ebs_volume", Region: "eu-west-1",
				Status: engine.StatusOrphanWaste, MonthlyCost: 8, WasteReason: "Unattached EBS volume"},
		},
		Edges: []engine.Edge{{Source: "vol-0123456789abcdef0", Target: "arn:aws:ecs:eu-west-1:123456789012:service/prod/payments-api"}},
	}
}

func TestMaskHidesIdentifiers(t *testing.T) {
	m := NewMasker()
	prompt, err := Prompt(m.Mask(sample()))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"123456789012", "payments-api", "orders-db-data", "vol-0123", "vpc-0abc", "alice", "secret.internal", "prod-secret"} {
		if strings.Contains(prompt, leak) {
			t.Errorf("payload leaks %q:\n%s", leak, prompt)
		}
	}
	if !strings.Contains(prompt, "Unattached EBS volume") || !strings.Contains(prompt, `"desired": "2"`) {
		t.Error("payload lost the data the analysis needs")
	}
}

func TestMaskEdgesUseAliases(t *testing.T) {
	m := NewMasker()
	p := m.Mask(sample())
	if len(p.Edges) != 1 {
		t.Fatalf("edges = %+v", p.Edges)
	}
	ids := map[string]bool{}
	for _, n := range p.Nodes {
		ids[n.ID] = true
	}
	if !ids[p.Edges[0].Source] || !ids[p.Edges[0].Target] {
		t.Fatalf("edge endpoints are not node aliases: %+v", p.Edges[0])
	}
	if _, err := json.Marshal(p); err != nil {
		t.Fatal(err)
	}
}

func TestUnmaskRestoresNames(t *testing.T) {
	m := NewMasker()
	p := m.Mask(sample())
	alias := p.Nodes[1].ID
	answer := "Delete " + alias + " first; " + p.Nodes[0].ID + " is fine."
	got := m.Unmask(answer)
	if !strings.Contains(got, "vol-0123456789abcdef0") && !strings.Contains(got, "orders-db-data") {
		t.Fatalf("alias not restored: %q", got)
	}
	if strings.Contains(got, "-00") {
		t.Fatalf("alias left in answer: %q", got)
	}
}
