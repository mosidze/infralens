package engine

import (
	"math"
	"testing"
)

func TestCoverageSeparatesCheckFromExplained(t *testing.T) {
	res := ScanResult{ServiceCosts: []ServiceCost{
		{Service: "A", CostHistory: CostHistory{PreviousMonthCost: 100}, Scanned: true, Estimated: 400}, // over-estimate counts as 100
		{Service: "B", CostHistory: CostHistory{PreviousMonthCost: 100}, Scanned: true, Estimated: 10},  // has a check, mostly unexplained
		{Service: "C", CostHistory: CostHistory{PreviousMonthCost: 200}},                                // no check
	}}
	c := CoverageOf(res)
	if c.Billed != 400 || c.WithCheck != 200 || c.Explained != 110 {
		t.Fatalf("%+v", c)
	}
	if math.Abs(c.CheckPct()-50) > 1e-9 || math.Abs(c.ExplainedPct()-27.5) > 1e-9 {
		t.Fatalf("pct: %v %v", c.CheckPct(), c.ExplainedPct())
	}
	if (Coverage{}).CheckPct() != 0 || (Coverage{}).ExplainedPct() != 0 {
		t.Fatal("no billing data must not divide by zero")
	}
}

func TestCoverageUsesTheLedgerWhenThereIsOne(t *testing.T) {
	res := ScanResult{
		ServiceCosts: []ServiceCost{
			{Service: "A", CostHistory: CostHistory{PreviousMonthCost: 600}, Scanned: true, Estimated: 600},
			{Service: "B", CostHistory: CostHistory{PreviousMonthCost: 400}},
		},
		Ledger: &Ledger{Billed: 1000, Allocated: 250},
	}
	c := CoverageOf(res)
	// the catalogue estimate (600) says "explained"; the ledger says 250 of real money is attributed
	if c.Explained != 250 || c.WithCheck != 600 || c.Billed != 1000 {
		t.Fatalf("%+v", c)
	}
}
