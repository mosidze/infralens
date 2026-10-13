package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"sort"
	"time"

	"infralens/internal/engine"
)

//go:embed progress.html
var progressTemplate string

// ProgressOptions describe the engagement the comparison belongs to.
type ProgressOptions struct {
	Client     string
	Consultant string
	Anonymize  bool
	Version    string
	Now        time.Time
}

// Progress is the result of comparing two scans of the same account:
// what was done between them and what is still open.
type Progress struct {
	OldAt, NewAt time.Time
	// Resolved are earlier waste candidates that no longer exist.
	Resolved     []engine.Change
	ResolvedCost float64
	// NowActive are earlier candidates that still exist and are no longer
	// flagged: the resource started to be used, nothing was removed.
	NowActive []engine.Change
	// Open are candidates present in both scans.
	Open     []engine.ResourceNode
	OpenCost float64
	// New are candidates that were not candidates before.
	New      []engine.Change
	NewCost  float64
	Notes    []string
	Billed   [2]float64 // billed usage, last full month at each scan
	Compared int
	SameAcct bool
}

// CompareProgress works from engine.Compare, so it inherits its rule that
// only resource types covered by both scans take part.
func CompareProgress(old, cur engine.ScanResult) Progress {
	d := engine.Compare(old, cur)
	p := Progress{OldAt: old.Timestamp, NewAt: cur.Timestamp, Notes: d.Notes, SameAcct: old.Account == "" || cur.Account == "" || old.Account == cur.Account}
	if !p.SameAcct {
		p.Notes = append(p.Notes, fmt.Sprintf("the two scans are of different accounts (%s, %s); the comparison is not meaningful", old.Account, cur.Account))
	}

	wasWaste := map[string]engine.ResourceNode{}
	for _, n := range old.Nodes {
		if n.Status == engine.StatusOrphanWaste && n.Ack == nil {
			wasWaste[n.ID] = n
		}
	}
	now := map[string]engine.ResourceNode{}
	for _, n := range cur.Nodes {
		now[n.ID] = n
	}
	removed := map[string]engine.Change{}
	for _, c := range d.Removed {
		removed[c.ID] = c
	}
	for id, was := range wasWaste {
		if c, gone := removed[id]; gone {
			c.CostFrom = was.MonthlyCost
			p.Resolved = append(p.Resolved, c)
			p.ResolvedCost += was.MonthlyCost
			continue
		}
		n, still := now[id]
		switch {
		case !still:
			// not compared (type not covered by both scans): say nothing about it
		case n.Status == engine.StatusOrphanWaste && n.Ack == nil:
			p.Open = append(p.Open, n)
			p.OpenCost += n.MonthlyCost
		default:
			to := n.Status
			if n.Status == engine.StatusOrphanWaste && n.Ack != nil {
				to = "acknowledged"
			}
			p.NowActive = append(p.NowActive, engine.Change{Kind: engine.ChangeStatus, ID: id, Name: n.Name, Type: n.Type,
				Region: n.Region, From: engine.StatusOrphanWaste, To: to, CostFrom: was.MonthlyCost, CostTo: n.MonthlyCost})
		}
	}
	for _, c := range d.NewWaste {
		p.New = append(p.New, c)
		p.NewCost += c.CostTo
	}
	sortByCost := func(cs []engine.Change, f func(engine.Change) float64) {
		sort.SliceStable(cs, func(i, j int) bool { return f(cs[i]) > f(cs[j]) })
	}
	sortByCost(p.Resolved, func(c engine.Change) float64 { return c.CostFrom })
	sortByCost(p.NowActive, func(c engine.Change) float64 { return c.CostFrom })
	sortByCost(p.New, func(c engine.Change) float64 { return c.CostTo })
	sort.SliceStable(p.Open, func(i, j int) bool { return p.Open[i].MonthlyCost > p.Open[j].MonthlyCost })
	for i, s := range []engine.ScanResult{old, cur} {
		for _, sc := range s.ServiceCosts {
			p.Billed[i] += sc.PreviousMonthCost
		}
	}
	p.Compared = len(old.Nodes)
	return p
}

type progressRow struct {
	Name, Type, Region, Was, Now, Note string
}

type progressView struct {
	Client, Consultant, Version, Generated string
	OldDate, NewDate                       string
	Days                                   int
	Resolved, NowActive, Open, New         []progressRow
	ResolvedCost, OpenCost, NewCost        string
	ResolvedN, OpenN, NewN, ActiveN        int
	BilledOld, BilledNew                   string
	Notes                                  []string
	Anonymized                             bool
}

// RenderProgress writes the before/after document.
func RenderProgress(old, cur engine.ScanResult, o ProgressOptions) (string, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	p := CompareProgress(old, cur)
	an := newAnonymizer(o.Anonymize, mergeScans(old, cur))
	nm := func(id, name string) string {
		if o.Anonymize {
			return an.alias[id]
		}
		if name != "" {
			return name
		}
		return id
	}
	v := progressView{
		Client: o.Client, Consultant: o.Consultant, Version: o.Version, Generated: o.Now.Format("2006-01-02"),
		OldDate: old.Timestamp.Format("2006-01-02"), NewDate: cur.Timestamp.Format("2006-01-02"),
		Days: int(cur.Timestamp.Sub(old.Timestamp).Hours() / 24), Anonymized: o.Anonymize,
		ResolvedCost: engine.Money(p.ResolvedCost), OpenCost: engine.Money(p.OpenCost), NewCost: engine.Money(p.NewCost),
		ResolvedN: len(p.Resolved), OpenN: len(p.Open), NewN: len(p.New), ActiveN: len(p.NowActive),
	}
	if v.Client == "" {
		v.Client = "Client"
	}
	if p.Billed[0] > 0 {
		v.BilledOld = engine.Money(p.Billed[0])
	}
	if p.Billed[1] > 0 {
		v.BilledNew = engine.Money(p.Billed[1])
	}
	for _, n := range p.Notes {
		v.Notes = append(v.Notes, an.scrub(n))
	}
	row := func(c engine.Change, was, now float64) progressRow {
		return progressRow{Name: nm(c.ID, c.Name), Type: typeName(c.Type), Region: c.Region,
			Was: engine.Money(was), Now: engine.Money(now)}
	}
	for _, c := range p.Resolved {
		v.Resolved = append(v.Resolved, row(c, c.CostFrom, 0))
	}
	for _, c := range p.NowActive {
		r := row(c, c.CostFrom, c.CostTo)
		r.Note = "no longer flagged: the resource is in use again, nothing was removed"
		if c.To == "acknowledged" {
			r.Note = "acknowledged by the owner as expected since the last scan; nothing was removed"
		}
		v.NowActive = append(v.NowActive, r)
	}
	for _, n := range p.Open {
		v.Open = append(v.Open, progressRow{Name: nm(n.ID, n.Name), Type: typeName(n.Type), Region: n.Region,
			Was: engine.Money(n.MonthlyCost), Now: engine.Money(n.MonthlyCost), Note: an.scrub(n.WasteReason)})
	}
	for _, c := range p.New {
		v.New = append(v.New, row(c, 0, c.CostTo))
	}
	t, err := template.New("progress").Parse(progressTemplate)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

// mergeScans gives the anonymizer every name from both scans.
func mergeScans(a, b engine.ScanResult) engine.ScanResult {
	m := engine.ScanResult{Account: a.Account}
	m.Nodes = append(append(m.Nodes, a.Nodes...), b.Nodes...)
	m.Commitments = append(append(m.Commitments, a.Commitments...), b.Commitments...)
	return m
}
