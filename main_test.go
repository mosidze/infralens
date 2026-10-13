package main

import (
	"testing"
	"time"

	"infralens/internal/engine"
)

func TestPerProfile(t *testing.T) {
	cases := []struct {
		path, profile string
		multi         bool
		want          string
	}{
		{"report.html", "prod", false, "report.html"},
		{"report.html", "prod", true, "report-prod.html"},
		{"out/scan.json", "stage", true, "out/scan-stage.json"},
		{"report", "x", true, "report-x"},
		{"report.html", "", true, "report.html"},
	}
	for _, c := range cases {
		if got := perProfile(c.path, c.profile, c.multi); got != c.want {
			t.Errorf("perProfile(%q,%q,%v) = %q, want %q", c.path, c.profile, c.multi, got, c.want)
		}
	}
}

func TestEvaluatePolicy(t *testing.T) {
	f := &scanFlags{failOnWaste: 100, failOnNewWaste: 20}
	res := engine.ScanResult{TotalWaste: 150}
	if v := evaluatePolicy(f, res); len(v) != 1 {
		t.Fatalf("absolute breach only: %v", v)
	}
	// first run, no baseline: new-waste rule must not trigger
	res.TotalWaste = 50
	if v := evaluatePolicy(f, res); len(v) != 0 {
		t.Fatalf("no baseline must not fail: %v", v)
	}
	res.Diff = &engine.Diff{NewWasteCost: 25, Baseline: time.Now()}
	if v := evaluatePolicy(f, res); len(v) != 1 {
		t.Fatalf("new waste breach: %v", v)
	}
	res.Diff.NewWasteCost = 20 // equal to the limit is not a breach
	if v := evaluatePolicy(f, res); len(v) != 0 {
		t.Fatalf("equal must pass: %v", v)
	}
	if v := evaluatePolicy(&scanFlags{}, engine.ScanResult{TotalWaste: 1e9}); len(v) != 0 {
		t.Fatal("thresholds off by default")
	}
}
