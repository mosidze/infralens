package report

import (
	"strings"
	"testing"
	"time"

	"infralens/internal/engine"
)

func scanOf(at time.Time, nodes ...engine.ResourceNode) engine.ScanResult {
	r := engine.ScanResult{Timestamp: at, Account: "111", Regions: []string{"r"}, Nodes: nodes,
		CoveredTypes: []string{"aws_ebs_volume", "aws_lb", "aws_kinesis_stream"}}
	engine.Finalize(&r, nil)
	r.CoveredTypes = []string{"aws_ebs_volume", "aws_lb", "aws_kinesis_stream"}
	return r
}

func waste(id string, cost float64) engine.ResourceNode {
	return engine.ResourceNode{ID: id, Name: id, Type: "aws_ebs_volume", Region: "r", Status: engine.StatusOrphanWaste, MonthlyCost: cost}
}

func TestProgressSeparatesRemovedFromMerelyUnflagged(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	old := scanOf(t0,
		waste("gone", 10), waste("still", 20), waste("revived", 30), waste("acked-then", 5),
		engine.ResourceNode{ID: "stays", Name: "stays", Type: "aws_ebs_volume", Status: engine.StatusManaged, MonthlyCost: 9})
	cur := scanOf(t0.AddDate(0, 0, 30),
		waste("still", 20),
		engine.ResourceNode{ID: "revived", Name: "revived", Type: "aws_ebs_volume", Status: engine.StatusManaged, MonthlyCost: 30},
		waste("brand-new", 7),
		engine.ResourceNode{ID: "acked-then", Name: "acked-then", Type: "aws_ebs_volume", Status: engine.StatusOrphanWaste, MonthlyCost: 5,
			Ack: &engine.Ack{Note: "expected"}},
		engine.ResourceNode{ID: "stays", Name: "stays", Type: "aws_ebs_volume", Status: engine.StatusManaged, MonthlyCost: 9})
	p := CompareProgress(old, cur)

	if len(p.Resolved) != 1 || p.Resolved[0].ID != "gone" || p.ResolvedCost != 10 {
		t.Fatalf("only a resource that no longer exists is a saving: %+v", p.Resolved)
	}
	if len(p.NowActive) < 1 {
		t.Fatalf("a resource that came back to use must be listed apart: %+v", p)
	}
	foundRevived := false
	for _, c := range p.NowActive {
		if c.ID == "revived" {
			foundRevived = true
		}
		if c.ID == "gone" {
			t.Fatal("a removed resource is not 'now active'")
		}
	}
	if !foundRevived {
		t.Fatalf("revived missing: %+v", p.NowActive)
	}
	if len(p.Open) != 1 || p.Open[0].ID != "still" || p.OpenCost != 20 {
		t.Fatalf("open: %+v", p.Open)
	}
	if len(p.New) != 1 || p.New[0].ID != "brand-new" || p.NewCost != 7 {
		t.Fatalf("new: %+v", p.New)
	}
}

func TestProgressIgnoresTypesOnlyOneScanCovered(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	old := scanOf(t0, engine.ResourceNode{ID: "k", Name: "k", Type: "aws_kinesis_stream", Region: "r", Status: engine.StatusOrphanWaste, MonthlyCost: 29})
	cur := scanOf(t0.AddDate(0, 0, 10))
	cur.CoveredTypes = []string{"aws_ebs_volume"} // a partial run without the kinesis check
	p := CompareProgress(old, cur)
	if len(p.Resolved) != 0 || p.ResolvedCost != 0 {
		t.Fatalf("a check that did not run must not look like a cleanup: %+v", p.Resolved)
	}
}

func TestProgressDocumentFraming(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	old := scanOf(t0, waste("gone", 10))
	cur := scanOf(t0.AddDate(0, 0, 40))
	html, err := RenderProgress(old, cur, ProgressOptions{Client: "<i>ACME</i>", Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "<i>ACME</i>") || strings.Contains(html, "<script") {
		t.Fatal("document must escape content and carry no script")
	}
	for _, want := range []string{"It is not a measured saving", "confirm it on the invoice", "$10.00", "40 days"} {
		if !strings.Contains(html, want) {
			t.Errorf("document lacks %q", want)
		}
	}
	anon, err := RenderProgress(old, cur, ProgressOptions{Anonymize: true, Now: t0})
	if err != nil || strings.Contains(anon, ">gone<") {
		t.Fatalf("anonymised document leaks a name: %v", err)
	}
}
