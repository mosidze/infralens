package engine

import (
	"fmt"
	"math"
	"sort"
	"time"
)

type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeRemoved ChangeKind = "removed"
	ChangeStatus  ChangeKind = "status"
	ChangeCost    ChangeKind = "cost"
)

// Change is one resource that differs between two scans.
type Change struct {
	Kind     ChangeKind     `json:"kind"`
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Region   string         `json:"region"`
	From     ResourceStatus `json:"from,omitempty"`
	To       ResourceStatus `json:"to,omitempty"`
	CostFrom float64        `json:"cost_from"`
	CostTo   float64        `json:"cost_to"`
}

// Diff is what changed between a baseline scan and the current one.
type Diff struct {
	Baseline     time.Time `json:"baseline"`
	BaselineFile string    `json:"baseline_file,omitempty"`
	Added        []Change  `json:"added,omitempty"`
	Removed      []Change  `json:"removed,omitempty"`
	Changed      []Change  `json:"changed,omitempty"`
	// NewWaste are resources that are waste now and were not before
	// (new resources, or existing ones whose verdict flipped).
	NewWaste     []Change `json:"new_waste,omitempty"`
	DeltaCost    float64  `json:"delta_cost"`
	DeltaWaste   float64  `json:"delta_waste"`
	NewWasteCost float64  `json:"new_waste_cost"`
	Notes        []string `json:"notes,omitempty"`
}

// Cost changes below both of these are noise (metrics-based estimates move a little between runs).
const (
	costChangeMinAbs = 5.0
	costChangeMinRel = 0.10
)

// Compare diffs two scans of the same account. Only node types covered by
// both runs take part; the rest is reported in Notes.
func Compare(prev, cur ScanResult) Diff {
	d := Diff{Baseline: prev.Timestamp}

	common := map[string]bool{}
	if len(prev.CoveredTypes) > 0 && len(cur.CoveredTypes) > 0 {
		inCur := map[string]bool{}
		for _, t := range cur.CoveredTypes {
			inCur[t] = true
		}
		for _, t := range prev.CoveredTypes {
			if inCur[t] {
				common[t] = true
			}
		}
		if len(common) != len(prev.CoveredTypes) || len(common) != len(cur.CoveredTypes) {
			d.Notes = append(d.Notes, fmt.Sprintf("the two scans ran different checks; compared %d resource types common to both", len(common)))
		}
	}
	in := func(t string) bool { return len(common) == 0 || common[t] }

	if !sameStrings(prev.Regions, cur.Regions) {
		d.Notes = append(d.Notes, "the two scans covered different regions; added/removed may reflect scope, not change")
	}

	old := map[string]ResourceNode{}
	for _, n := range prev.Nodes {
		if in(n.Type) {
			old[n.ID] = n
		}
	}
	seen := map[string]bool{}
	for _, n := range cur.Nodes {
		if !in(n.Type) {
			continue
		}
		seen[n.ID] = true
		o, existed := old[n.ID]
		ch := Change{ID: n.ID, Name: n.Name, Type: n.Type, Region: n.Region, To: n.Status, CostTo: n.MonthlyCost}
		switch {
		case !existed:
			ch.Kind = ChangeAdded
			d.Added = append(d.Added, ch)
			d.DeltaCost += n.MonthlyCost
			if n.Status == StatusOrphanWaste {
				d.NewWaste = append(d.NewWaste, ch)
			}
		default:
			ch.From, ch.CostFrom = o.Status, o.MonthlyCost
			d.DeltaCost += n.MonthlyCost - o.MonthlyCost
			if o.Status != n.Status {
				ch.Kind = ChangeStatus
				d.Changed = append(d.Changed, ch)
				if n.Status == StatusOrphanWaste {
					d.NewWaste = append(d.NewWaste, ch)
				}
			} else if material(o.MonthlyCost, n.MonthlyCost) {
				ch.Kind = ChangeCost
				d.Changed = append(d.Changed, ch)
			}
		}
	}
	for id, o := range old {
		if seen[id] {
			continue
		}
		d.Removed = append(d.Removed, Change{
			Kind: ChangeRemoved, ID: id, Name: o.Name, Type: o.Type, Region: o.Region,
			From: o.Status, CostFrom: o.MonthlyCost,
		})
		d.DeltaCost -= o.MonthlyCost
	}

	for _, c := range d.NewWaste {
		d.NewWasteCost += c.CostTo
	}
	// Waste delta over the compared types only; the scans' own totals cover
	// different checks when one of them was a partial run.
	var prevWaste, curWaste float64
	for _, n := range prev.Nodes {
		if in(n.Type) && n.Status == StatusOrphanWaste {
			prevWaste += n.MonthlyCost
		}
	}
	for _, n := range cur.Nodes {
		if in(n.Type) && n.Status == StatusOrphanWaste {
			curWaste += n.MonthlyCost
		}
	}
	d.DeltaWaste = curWaste - prevWaste
	for _, s := range [][]Change{d.Added, d.Removed, d.Changed, d.NewWaste} {
		sortChanges(s)
	}
	return d
}

func material(from, to float64) bool {
	delta := math.Abs(to - from)
	if delta < costChangeMinAbs {
		return false
	}
	base := math.Max(math.Abs(from), math.Abs(to))
	return base > 0 && delta/base >= costChangeMinRel
}

func sortChanges(cs []Change) {
	sort.Slice(cs, func(i, j int) bool {
		a, b := math.Max(cs[i].CostFrom, cs[i].CostTo), math.Max(cs[j].CostFrom, cs[j].CostTo)
		if a != b {
			return a > b
		}
		return cs[i].ID < cs[j].ID
	})
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// Empty reports whether nothing material changed.
func (d Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}
