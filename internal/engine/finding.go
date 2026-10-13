package engine

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Pillar is the audit layer a finding belongs to. The names follow the AWS
// Well-Architected pillars that clients already know.
type Pillar string

const (
	PillarCost        Pillar = "cost"
	PillarSecurity    Pillar = "security"
	PillarReliability Pillar = "reliability"
	PillarPerformance Pillar = "performance"
	PillarIaC         Pillar = "iac"
	PillarOps         Pillar = "ops"
)

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 0
	case SevHigh:
		return 1
	case SevMedium:
		return 2
	case SevLow:
		return 3
	}
	return 4
}

// Finding is one statement about the account with the evidence behind it.
// Own checks, AWS-native services (Trusted Advisor, Security Hub, Cost
// Optimization Hub) and imported tools all end up in this shape, so the
// document and the UI can treat them alike and say where each came from.
type Finding struct {
	ID             string     `json:"id"`
	Pillar         Pillar     `json:"pillar"`
	Source         string     `json:"source"` // own | trusted-advisor | cost-hub | security-hub | compute-optimizer | prowler
	Rule           string     `json:"rule"`
	Severity       Severity   `json:"severity"`
	Title          string     `json:"title"`
	ResourceID     string     `json:"resource_id,omitempty"`
	ResourceName   string     `json:"resource_name,omitempty"`
	ResourceType   string     `json:"resource_type,omitempty"`
	Region         string     `json:"region,omitempty"`
	MonthlyCost    float64    `json:"monthly_cost,omitempty"` // size of the cost at stake, when it is a cost finding
	Evidence       []string   `json:"evidence,omitempty"`
	Recommendation string     `json:"recommendation,omitempty"`
	Confidence     Confidence `json:"confidence,omitempty"`
	Effort         string     `json:"effort,omitempty"` // low | medium | high, a hint, not an estimate
	// Affected is how many resources the rule flagged; Resources lists some of
	// them. Imported findings are grouped by rule so a document stays readable.
	Affected  int      `json:"affected,omitempty"`
	Resources []string `json:"resources,omitempty"`
	// Reference is where the rule comes from (a control id or a check name).
	Reference string `json:"reference,omitempty"`
	// GroupKey merges findings of one rule that were produced separately (per
	// region, per user) into a single line with the resources listed.
	GroupKey string `json:"group_key,omitempty"`
	Ack      *Ack   `json:"ack,omitempty"`
	// Derived marks findings computed from resource nodes by Finalize; they
	// are recomputed every time and must not be kept across runs.
	Derived bool `json:"derived,omitempty"`
}

// FindingID is stable for the same source, rule and resource, so a finding
// can be followed between scans and acknowledged by id.
func FindingID(source, rule, resource string) string {
	h := sha1.Sum([]byte(source + "\x00" + rule + "\x00" + resource))
	return hex.EncodeToString(h[:])[:12]
}

// costSeverity grades a cost finding by the money at stake. The bands are
// deliberately coarse: they order work, they do not claim precision.
func costSeverity(monthly float64) Severity {
	switch {
	case monthly >= 500:
		return SevHigh
	case monthly >= 100:
		return SevMedium
	}
	return SevLow
}

func ruleFor(prefix, nodeType string) string {
	return prefix + "." + strings.ReplaceAll(strings.TrimPrefix(nodeType, "aws_"), "_", "-")
}

// deriveFindings projects resource-level verdicts (waste candidates, missing
// IaC marker) into findings. It touches nothing else.
func deriveFindings(res *ScanResult) []Finding {
	var out []Finding
	for _, n := range res.Nodes {
		switch n.Status {
		case StatusOrphanWaste:
			f := Finding{
				Pillar: PillarCost, Source: "own", Rule: ruleFor("cost.idle", n.Type), Severity: costSeverity(n.MonthlyCost),
				Title:      n.WasteReason,
				ResourceID: n.ID, ResourceName: n.Name, ResourceType: n.Type, Region: n.Region,
				MonthlyCost: n.MonthlyCost, Evidence: n.Evidence, Confidence: n.Confidence,
				Recommendation: "Confirm with the owner that nothing depends on it, then follow the cleanup procedure (backup, quarantine, remove).",
				Effort:         "low", Ack: n.Ack, Derived: true,
			}
			f.ID = FindingID(f.Source, f.Rule, n.ID)
			out = append(out, f)
		}
	}
	out = append(out, shadowByType(res)...)
	out = append(out, postureFindings(res)...)
	return append(out, ownerFinding(res)...)
}

// shadowByType groups resources without an IaC marker by type: one finding
// per type with the count and the largest examples, not one card per bucket.
func shadowByType(res *ScanResult) []Finding {
	groups := map[string][]ResourceNode{}
	var order []string
	for _, n := range res.Nodes {
		if n.Status != StatusShadowIT {
			continue
		}
		if _, ok := groups[n.Type]; !ok {
			order = append(order, n.Type)
		}
		groups[n.Type] = append(groups[n.Type], n)
	}
	var out []Finding
	for _, t := range order {
		ns := groups[t]
		sort.SliceStable(ns, func(i, j int) bool { return ns[i].MonthlyCost > ns[j].MonthlyCost })
		var cost float64
		f := Finding{
			Pillar: PillarIaC, Source: "own", Rule: ruleFor("iac.unmanaged", t), Severity: SevLow, Derived: true,
			Title:        fmt.Sprintf("%d %s without an infrastructure-as-code marker", len(ns), strings.ReplaceAll(strings.TrimPrefix(t, "aws_"), "_", " ")),
			ResourceType: t, Affected: len(ns), Confidence: ConfMedium, Effort: "medium",
			Recommendation: "Find the owner and bring the resource under code, or tag it with how it is managed. A tag is a claim, not proof: the state files and stacks are the source of truth.",
		}
		acked := 0
		for i, n := range ns {
			cost += n.MonthlyCost
			if n.Ack != nil {
				acked++
			}
			if i < 40 {
				f.Resources = append(f.Resources, n.ID)
			}
		}
		f.ResourceID, f.ResourceName, f.Region = ns[0].ID, ns[0].Name, ns[0].Region
		f.MonthlyCost = cost
		f.Evidence = []string{"no CloudFormation, Terraform or similar tag; this is a heuristic from tags only"}
		if acked == len(ns) {
			f.Ack = ns[0].Ack
		}
		f.ID = FindingID(f.Source, f.Rule, "")
		out = append(out, f)
	}
	return out
}

// mergeFindings keeps findings that came from elsewhere, replaces the derived
// ones, and orders the result for display: severity first, then money.
func mergeFindings(kept, derived []Finding) []Finding {
	var all []Finding
	for _, f := range kept {
		if !f.Derived {
			all = append(all, f)
		}
	}
	all = append(all, derived...)
	all = groupFindings(all)
	seen := map[string]bool{}
	uniq := all[:0]
	for _, f := range all {
		if f.ID == "" {
			f.ID = FindingID(f.Source, f.Rule, f.ResourceID+"|"+f.Title)
		}
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		uniq = append(uniq, f)
	}
	sort.SliceStable(uniq, func(i, j int) bool {
		if uniq[i].Severity.Rank() != uniq[j].Severity.Rank() {
			return uniq[i].Severity.Rank() < uniq[j].Severity.Rank()
		}
		if uniq[i].MonthlyCost != uniq[j].MonthlyCost {
			return uniq[i].MonthlyCost > uniq[j].MonthlyCost
		}
		return uniq[i].ID < uniq[j].ID
	})
	return uniq
}

// groupFindings merges findings that share a source, a rule and a group key.
func groupFindings(in []Finding) []Finding {
	idx := map[string]int{}
	var out []Finding
	for _, f := range in {
		if f.GroupKey == "" {
			out = append(out, f)
			continue
		}
		k := f.Source + "\x00" + f.Rule + "\x00" + f.GroupKey
		i, ok := idx[k]
		if !ok {
			if f.Affected == 0 {
				f.Affected = 1
			}
			if len(f.Resources) == 0 && f.ResourceID != "" {
				f.Resources = []string{f.ResourceID}
			}
			f.ID = FindingID(f.Source, f.Rule, f.GroupKey)
			idx[k] = len(out)
			out = append(out, f)
			continue
		}
		g := &out[i]
		n := f.Affected
		if n == 0 {
			n = 1
		}
		g.Affected += n
		g.MonthlyCost += f.MonthlyCost
		have := map[string]bool{}
		for _, r := range g.Resources {
			have[r] = true
		}
		add := f.Resources
		if len(add) == 0 && f.ResourceID != "" {
			add = []string{f.ResourceID}
		}
		for _, r := range add {
			if !have[r] && len(g.Resources) < 40 {
				g.Resources = append(g.Resources, r)
			}
		}
	}
	return out
}

// PillarCounts summarises findings per pillar, acknowledged ones apart.
type PillarCount struct {
	Pillar       Pillar
	Open         int
	Acknowledged int
	Critical     int
	High         int
	MonthlyCost  float64
}

func CountByPillar(fs []Finding) []PillarCount {
	idx := map[Pillar]*PillarCount{}
	for _, f := range fs {
		c := idx[f.Pillar]
		if c == nil {
			c = &PillarCount{Pillar: f.Pillar}
			idx[f.Pillar] = c
		}
		if f.Ack != nil {
			c.Acknowledged++
			continue
		}
		c.Open++
		switch f.Severity {
		case SevCritical:
			c.Critical++
		case SevHigh:
			c.High++
		}
		c.MonthlyCost += f.MonthlyCost
	}
	var out []PillarCount
	for _, p := range []Pillar{PillarSecurity, PillarCost, PillarReliability, PillarPerformance, PillarIaC, PillarOps} {
		if c := idx[p]; c != nil {
			out = append(out, *c)
		}
	}
	return out
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s/%s] %s (%s)", f.Pillar, f.Severity, f.Title, f.ResourceName)
}
