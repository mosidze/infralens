package llm

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"infralens/internal/engine"
)

// Facts is the only thing a model is given: findings and totals the tool has
// already computed, with names removed. It is built so that a model has no
// need to know the account, and so that nothing it is told is a secret.
type Facts struct {
	Resources    int           `json:"resources"`
	Regions      int           `json:"regions"`
	MonthlyCost  string        `json:"monthly_cost"`
	WasteCost    string        `json:"waste_candidates_cost"`
	BillTied     string        `json:"bill_tied_to_resources,omitempty"`
	Pillars      []PillarFact  `json:"pillars"`
	Findings     []FindingFact `json:"findings"`
	Resource     *ResourceFact `json:"selected_resource,omitempty"`
	Commitments  []string      `json:"commitment_facts,omitempty"`
	IaC          string        `json:"iac,omitempty"`
	Ownership    string        `json:"ownership,omitempty"`
	NotChecked   []string      `json:"not_checked,omitempty"`
	allowedMoney []float64
	ids          map[string]bool
}

type PillarFact struct {
	Pillar   string `json:"pillar"`
	Open     int    `json:"open"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
}

type FindingFact struct {
	ID             string   `json:"id"`
	Pillar         string   `json:"pillar"`
	Severity       string   `json:"severity"`
	Source         string   `json:"source"`
	Title          string   `json:"title"`
	Affected       int      `json:"affected,omitempty"`
	MonthlyCost    string   `json:"monthly_cost,omitempty"`
	Confidence     string   `json:"confidence,omitempty"`
	Effort         string   `json:"effort,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
}

var (
	reARN     = regexp.MustCompile(`arn:aws[a-z-]*:[^\s,;)"']+`)
	reEmail   = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reAcct    = regexp.MustCompile(`\b\d{12}\b`)
	reHex     = regexp.MustCompile(`\b[0-9a-f]{12,}\b`)
	reMoneyIn = regexp.MustCompile(`\$\s?([0-9][0-9,]*(?:\.[0-9]+)?)\s?([kKmM])?`)
)

type redactor struct{ known []string }

func newRedactor(res engine.ScanResult) *redactor {
	seen := map[string]bool{}
	r := &redactor{}
	add := func(s string) {
		if len(s) >= 4 && !seen[s] {
			seen[s] = true
			r.known = append(r.known, s)
		}
	}
	for _, n := range res.Nodes {
		add(n.Name)
		add(n.ID)
		add(n.Owner)
		if n.IaC != nil {
			add(n.IaC.Origin)
			add(n.IaC.Address)
			add(n.IaC.Module)
		}
	}
	add(res.Account)
	add(res.Profile)
	sort.Slice(r.known, func(i, j int) bool { return len(r.known[i]) > len(r.known[j]) })
	return r
}

func (r *redactor) scrub(s string) string {
	for _, k := range r.known {
		if strings.Contains(s, k) {
			s = strings.ReplaceAll(s, k, "[name]")
		}
	}
	s = reARN.ReplaceAllString(s, "[arn]")
	s = reEmail.ReplaceAllString(s, "[email]")
	s = reAcct.ReplaceAllString(s, "[account]")
	return reHex.ReplaceAllString(s, "[id]")
}

// BuildFacts assembles the model's input from a finished scan. max bounds the
// number of findings (the most severe and the most expensive are kept).
func BuildFacts(res engine.ScanResult, max int) Facts {
	if max <= 0 {
		max = 60
	}
	red := newRedactor(res)
	f := Facts{
		Resources: res.TotalLive, Regions: len(res.Regions),
		MonthlyCost: engine.Money(res.EstimatedTCO), WasteCost: engine.Money(res.TotalWaste),
		ids: map[string]bool{},
	}
	f.allowedMoney = append(f.allowedMoney, res.EstimatedTCO, res.TotalWaste)
	if l := res.Ledger; l != nil && l.Billed > 0 {
		f.BillTied = fmt.Sprintf("%s of %s billed last month (%.0f%%)", engine.Money(l.Allocated), engine.Money(l.Billed), l.Allocated/l.Billed*100)
		f.allowedMoney = append(f.allowedMoney, l.Allocated, l.Billed)
	}

	for _, c := range engine.CountByPillar(res.Findings) {
		f.Pillars = append(f.Pillars, PillarFact{Pillar: string(c.Pillar), Open: c.Open, Critical: c.Critical, High: c.High})
	}
	var open []engine.Finding
	for _, x := range res.Findings {
		if x.Ack == nil && x.Severity != engine.SevInfo {
			open = append(open, x)
		}
	}
	sort.SliceStable(open, func(i, j int) bool {
		if open[i].Severity.Rank() != open[j].Severity.Rank() {
			return open[i].Severity.Rank() < open[j].Severity.Rank()
		}
		return open[i].MonthlyCost > open[j].MonthlyCost
	})
	if len(open) > max {
		open = open[:max]
	}
	for _, x := range open {
		ff := FindingFact{
			ID: x.ID, Pillar: string(x.Pillar), Severity: string(x.Severity), Source: x.Source,
			Title: red.scrub(x.Title), Affected: x.Affected, Confidence: string(x.Confidence), Effort: x.Effort,
			Recommendation: red.scrub(x.Recommendation),
		}
		if x.MonthlyCost > 0 {
			ff.MonthlyCost = engine.Money(x.MonthlyCost)
			f.allowedMoney = append(f.allowedMoney, x.MonthlyCost)
		}
		for i, e := range x.Evidence {
			if i == 2 {
				break
			}
			ff.Evidence = append(ff.Evidence, red.scrub(e))
		}
		f.ids[x.ID] = true
		f.Findings = append(f.Findings, ff)
	}
	for _, c := range res.Commitments {
		for _, fact := range c.Facts {
			f.Commitments = append(f.Commitments, red.scrub(c.Service+": "+fact))
		}
	}
	if len(f.Commitments) > 12 {
		f.Commitments = f.Commitments[:12]
	}
	if i := res.IaC; i != nil && len(i.Sources) > 0 {
		f.IaC = fmt.Sprintf("%d of %d inventoried resources confirmed in state or stacks; %d tagged but not found; %d with neither; drift found on %d of %d compared",
			i.Matched, i.Considered, i.TagOnly, i.Unmanaged, i.DriftFound, i.DriftChecked)
	}
	owned, total := 0, 0
	for _, n := range res.Nodes {
		if n.Type == "aws_cloudwatch_log_group_rollup" || n.Type == "aws_ecs_cluster" {
			continue
		}
		total++
		if n.Owner != "" {
			owned++
		}
	}
	if total > 0 {
		f.Ownership = fmt.Sprintf("%d of %d resources name an owner, team or project", owned, total)
	}
	for _, w := range res.Warnings {
		f.NotChecked = append(f.NotChecked, red.scrub(w))
		if len(f.NotChecked) == 5 {
			break
		}
	}
	return f
}

// IDs reports whether a finding id was given to the model.
func (f Facts) HasID(id string) bool { return f.ids[id] }

// moneyAllowed says whether a dollar amount quoted by a model appears among
// the facts it was given (within rounding).
func (f Facts) moneyAllowed(v float64) bool {
	for _, a := range f.allowedMoney {
		d := v - a
		if d < 0 {
			d = -d
		}
		tol := 0.01*a + 0.5
		if d <= tol {
			return true
		}
	}
	return false
}
