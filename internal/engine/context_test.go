package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCtx(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "context.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestContextAcknowledgesAndExcludesFromTotals(t *testing.T) {
	c, err := LoadContext(writeCtx(t, `{"notes":[
	  {"match":{"type":"aws_kinesis_stream","name":"acme-feed-*"},"note":"low traffic by design"},
	  {"match":{"service":"Amazon OpenSearch Service"},"note":"moving to on-prem Elastic","until":"2027-06-30"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	res := ScanResult{
		TypeServices: map[string]string{"aws_kinesis_stream": "Amazon Kinesis"},
		Nodes: []ResourceNode{
			{ID: "k1", Name: "acme-feed-x", Type: "aws_kinesis_stream", Status: StatusOrphanWaste, MonthlyCost: 29},
			{ID: "k2", Name: "other", Type: "aws_kinesis_stream", Status: StatusOrphanWaste, MonthlyCost: 29},
		},
		Commitments: []Commitment{{Kind: "coverage", Service: "Amazon OpenSearch Service"}},
	}
	warns := c.Apply(&res, time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC))
	Finalize(&res, res.TypeServices)
	if res.Nodes[0].Ack == nil || res.Nodes[1].Ack != nil {
		t.Fatalf("only the matching stream is acknowledged: %+v", res.Nodes)
	}
	if res.WasteCount != 1 || res.TotalWaste != 29 || res.AckedCount != 1 || res.AckedWaste != 29 {
		t.Fatalf("acked waste must leave the totals: %+v", res)
	}
	if res.Commitments[0].Ack == nil {
		t.Fatal("commitment not acknowledged by service")
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
}

func TestContextLapsedAndUnmatchedNotesAreReported(t *testing.T) {
	c, err := LoadContext(writeCtx(t, `{"notes":[
	  {"match":{"name":"gone-*"},"note":"temporary","until":"2026-01-01"},
	  {"match":{"name":"nothing-*"},"note":"stale"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	res := ScanResult{Nodes: []ResourceNode{{ID: "a", Name: "gone-1", Status: StatusOrphanWaste, MonthlyCost: 10}}}
	warns := c.Apply(&res, time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC))
	if res.Nodes[0].Ack != nil {
		t.Fatal("an expired note must not acknowledge anything: the finding has to resurface")
	}
	if len(warns) != 2 || !strings.Contains(warns[0], "expired") || !strings.Contains(warns[1], "matched nothing") {
		t.Fatalf("warnings = %v", warns)
	}
}

func TestContextRejectsSloppyFiles(t *testing.T) {
	for name, body := range map[string]string{
		"empty match":  `{"notes":[{"match":{},"note":"x"}]}`,
		"no note text": `{"notes":[{"match":{"name":"a"},"note":""}]}`,
		"typo key":     `{"notes":[{"match":{"nmae":"a"},"note":"x"}]}`,
		"bad date":     `{"notes":[{"match":{"name":"a"},"note":"x","until":"next year"}]}`,
	} {
		if _, err := LoadContext(writeCtx(t, body)); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
	if c, err := LoadContext(""); err != nil || len(c.Notes) != 0 {
		t.Fatal("no file means no context")
	}
}
