package demo

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"infralens/internal/aws"
	"infralens/internal/cleanup"
	"infralens/internal/report"
)

// The demo is the product's shop window: it must stay consistent with the
// real pipeline (every node type known, every document renders).
func TestDemoRendersEveryDocument(t *testing.T) {
	r := Scan(time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC))
	if r.TotalLive < 60 || r.WasteCount < 5 || len(r.Commitments) == 0 {
		t.Fatalf("demo too thin: %d resources, %d waste", r.TotalLive, r.WasteCount)
	}
	known := map[string]bool{}
	for _, s := range aws.Scanners() {
		for ty := range s.Types {
			known[ty] = true
		}
	}
	for _, n := range r.Nodes {
		if !known[n.Type] {
			t.Errorf("demo uses node type %s that no scanner emits", n.Type)
		}
	}
	html, err := report.RenderHTML(r)
	if err != nil || !strings.Contains(html, "northwind") {
		t.Fatalf("report: %v", err)
	}
	doc, err := report.RenderAudit(r, report.AuditOptions{Client: "Example"})
	if err != nil || !strings.Contains(doc, "Waste candidates") {
		t.Fatalf("audit: %v", err)
	}
	if files := cleanup.Generate(r, cleanup.Options{}); len(files) < 4 {
		t.Fatalf("cleanup pack: %d files", len(files))
	}
	// the demo is synthetic: only the documentation example account id is allowed
	if m := regexp.MustCompile(`\b\d{12}\b`).FindString(html + doc); m != "" && m != "123456789012" {
		t.Fatalf("demo contains a 12-digit number that looks like an account id: %s", m)
	}
}
