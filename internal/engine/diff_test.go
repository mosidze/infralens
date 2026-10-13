package engine

import (
	"testing"
	"time"
)

func scan(types []string, regions []string, nodes ...ResourceNode) ScanResult {
	r := ScanResult{Timestamp: time.Now(), CoveredTypes: types, Regions: regions, Nodes: nodes}
	Finalize(&r, nil)
	r.CoveredTypes = types // Finalize with nil map would clear it
	return r
}

func TestCompare(t *testing.T) {
	ty := []string{"aws_ebs_volume", "aws_lb"}
	rg := []string{"eu-north-1"}
	prev := scan(ty, rg,
		ResourceNode{ID: "a", Type: "aws_ebs_volume", Status: StatusManaged, MonthlyCost: 10},
		ResourceNode{ID: "gone", Type: "aws_lb", Status: StatusManaged, MonthlyCost: 16},
		ResourceNode{ID: "flip", Type: "aws_lb", Status: StatusManaged, MonthlyCost: 16},
		ResourceNode{ID: "steady", Type: "aws_lb", Status: StatusManaged, MonthlyCost: 16},
		ResourceNode{ID: "noise", Type: "aws_lb", Status: StatusManaged, MonthlyCost: 100},
		ResourceNode{ID: "oldwaste", Type: "aws_ebs_volume", Status: StatusOrphanWaste, MonthlyCost: 8},
	)
	cur := scan(ty, rg,
		ResourceNode{ID: "a", Type: "aws_ebs_volume", Status: StatusManaged, MonthlyCost: 30},
		ResourceNode{ID: "new", Type: "aws_ebs_volume", Status: StatusOrphanWaste, MonthlyCost: 8},
		ResourceNode{ID: "flip", Type: "aws_lb", Status: StatusOrphanWaste, MonthlyCost: 16},
		ResourceNode{ID: "steady", Type: "aws_lb", Status: StatusManaged, MonthlyCost: 16},
		ResourceNode{ID: "noise", Type: "aws_lb", Status: StatusManaged, MonthlyCost: 102},
		ResourceNode{ID: "oldwaste", Type: "aws_ebs_volume", Status: StatusOrphanWaste, MonthlyCost: 8},
	)
	d := Compare(prev, cur)
	if len(d.Added) != 1 || d.Added[0].ID != "new" {
		t.Fatalf("added = %+v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].ID != "gone" {
		t.Fatalf("removed = %+v", d.Removed)
	}
	ids := map[string]ChangeKind{}
	for _, c := range d.Changed {
		ids[c.ID] = c.Kind
	}
	if ids["a"] != ChangeCost || ids["flip"] != ChangeStatus || len(ids) != 2 {
		t.Fatalf("changed = %v (noise and steady must not appear)", ids)
	}
	// "oldwaste" was already waste: it must not count as new waste.
	if len(d.NewWaste) != 2 || d.NewWasteCost != 24 {
		t.Fatalf("new waste = %+v cost=%v", d.NewWaste, d.NewWasteCost)
	}
	if d.DeltaWaste != cur.TotalWaste-prev.TotalWaste || d.DeltaWaste != 24 {
		t.Fatalf("delta waste = %v", d.DeltaWaste)
	}
}

func TestCompareIgnoresTypesNotCoveredByBoth(t *testing.T) {
	prev := scan([]string{"aws_lb", "aws_rds_instance"}, []string{"r"},
		ResourceNode{ID: "db", Type: "aws_rds_instance", Status: StatusOrphanWaste, MonthlyCost: 100},
		ResourceNode{ID: "lb", Type: "aws_lb", Status: StatusManaged, MonthlyCost: 16})
	// partial scan: rds check was not run, so "db" is not "removed"
	cur := scan([]string{"aws_lb"}, []string{"r"},
		ResourceNode{ID: "lb", Type: "aws_lb", Status: StatusManaged, MonthlyCost: 16})
	d := Compare(prev, cur)
	if len(d.Removed) != 0 || !d.Empty() {
		t.Fatalf("partial scan must not look like deletion: %+v", d)
	}
	if d.DeltaWaste != 0 || d.DeltaCost != 0 {
		t.Fatalf("deltas must cover compared types only: %+v", d)
	}
	if len(d.Notes) == 0 {
		t.Fatal("difference in checks must be noted")
	}
}

func TestCompareNotesRegionChange(t *testing.T) {
	d := Compare(scan(nil, []string{"a"}), scan(nil, []string{"a", "b"}))
	if len(d.Notes) == 0 {
		t.Fatal("region scope change must be noted")
	}
}
