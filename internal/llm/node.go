package llm

import (
	"fmt"
	"sort"
	"strings"

	"infralens/internal/engine"
)

// ResourceFact is what a model may know about one selected resource: how it
// is classified and why, what it costs and on what basis, what is connected
// (counts by kind, never names), and what was or was not compared with code.
type ResourceFact struct {
	Kind         string   `json:"kind"`
	Region       string   `json:"region,omitempty"`
	Status       string   `json:"status"`
	Confidence   string   `json:"confidence,omitempty"`
	MonthlyCost  string   `json:"monthly_cost"`
	CostBasis    string   `json:"cost_basis"`
	CostPeriod   string   `json:"cost_period,omitempty"`
	CatalogueUSD string   `json:"catalogue_price,omitempty"`
	CostNote     string   `json:"cost_note,omitempty"`
	WasteReason  string   `json:"waste_reason,omitempty"`
	Evidence     []string `json:"evidence,omitempty"`
	HasOwner     bool     `json:"has_owner"`
	IaCCheck     string   `json:"iac_check"`
	Drift        []string `json:"drift,omitempty"`
	Connected    []string `json:"connected,omitempty"`
	Acknowledged string   `json:"owner_note,omitempty"`
}

// BuildNodeFacts is BuildFacts narrowed to one resource: only the findings
// that name it, plus a description of the resource itself. It returns false
// when the node does not exist.
func BuildNodeFacts(res engine.ScanResult, nodeID string) (Facts, bool) {
	var n *engine.ResourceNode
	for i := range res.Nodes {
		if res.Nodes[i].ID == nodeID {
			n = &res.Nodes[i]
			break
		}
	}
	if n == nil {
		return Facts{}, false
	}
	red := newRedactor(res)
	f := Facts{Resources: 1, Regions: 1, MonthlyCost: engine.Money(n.MonthlyCost), WasteCost: "$0", ids: map[string]bool{}}
	f.allowedMoney = append(f.allowedMoney, n.MonthlyCost, n.ListCost)

	rf := &ResourceFact{
		Kind: strings.ReplaceAll(strings.TrimPrefix(n.Type, "aws_"), "_", " "), Region: n.Region,
		Status: string(n.Status), Confidence: string(n.Confidence),
		MonthlyCost: engine.Money(n.MonthlyCost), CostBasis: firstNonEmpty(n.CostBasis, "estimated"),
		WasteReason: red.scrub(n.WasteReason), HasOwner: n.Owner != "",
		CostNote: red.scrub(n.CostNote),
	}
	if res.Ledger != nil {
		rf.CostPeriod = res.Ledger.Month
	}
	if n.ListCost > 0 {
		rf.CatalogueUSD = engine.Money(n.ListCost)
	}
	for i, e := range n.Evidence {
		if i == 6 {
			break
		}
		rf.Evidence = append(rf.Evidence, red.scrub(e))
	}
	switch {
	case n.IaC != nil:
		rf.IaCCheck = "confirmed in Terraform state or a CloudFormation stack"
		if n.IaC.DriftChecked {
			rf.IaCCheck += "; attributes were compared"
		} else {
			rf.IaCCheck += "; attribute comparison is not available for this type"
		}
		for _, d := range n.IaC.Drift {
			rf.Drift = append(rf.Drift, red.scrub(fmt.Sprintf("%s: state %v, live %v", d.Attr, d.State, d.Live)))
		}
	case res.IaC == nil || len(res.IaC.Sources) == 0:
		rf.IaCCheck = "not checked: no Terraform state or CloudFormation stack was provided, so absence proves nothing"
	default:
		supported := false
		for _, t := range res.IaC.SupportedTypes {
			if t == n.Type {
				supported = true
			}
		}
		switch {
		case !supported:
			rf.IaCCheck = "cannot be compared: this resource type is not matched against state or stacks"
		case n.ManagedBy != "":
			rf.IaCCheck = "claimed by a tag but not found in the state that was read"
		default:
			rf.IaCCheck = "checked against the provided sources and not found; it may be created by hand or its state was not provided"
		}
	}
	if n.Ack != nil {
		rf.Acknowledged = red.scrub(n.Ack.Note)
	}
	byID := map[string]string{}
	for _, m := range res.Nodes {
		byID[m.ID] = strings.ReplaceAll(strings.TrimPrefix(m.Type, "aws_"), "_", " ")
	}
	count := map[string]int{}
	for _, e := range res.Edges {
		switch {
		case e.Source == n.ID && byID[e.Target] != "":
			count["uses "+byID[e.Target]]++
		case e.Target == n.ID && byID[e.Source] != "":
			count["used by "+byID[e.Source]]++
		}
	}
	for k, v := range count {
		rf.Connected = append(rf.Connected, fmt.Sprintf("%s ×%d", k, v))
	}
	sort.Strings(rf.Connected)
	f.Resource = rf

	for _, x := range res.Findings {
		if x.Ack != nil || x.Severity == engine.SevInfo {
			continue
		}
		hit := x.ResourceID == n.ID || (x.ResourceName != "" && x.ResourceName == n.Name)
		for _, r := range x.Resources {
			if r == n.ID || (n.Name != "" && r == n.Name) {
				hit = true
			}
		}
		if !hit {
			continue
		}
		ff := FindingFact{ID: x.ID, Pillar: string(x.Pillar), Severity: string(x.Severity), Source: x.Source,
			Title: red.scrub(x.Title), Affected: x.Affected, Confidence: string(x.Confidence), Effort: x.Effort,
			Recommendation: red.scrub(x.Recommendation)}
		if x.MonthlyCost > 0 {
			ff.MonthlyCost = engine.Money(x.MonthlyCost)
			f.allowedMoney = append(f.allowedMoney, x.MonthlyCost)
		}
		for i, e := range x.Evidence {
			if i == 3 {
				break
			}
			ff.Evidence = append(ff.Evidence, red.scrub(e))
		}
		f.ids[x.ID] = true
		f.Findings = append(f.Findings, ff)
	}
	return f, true
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
