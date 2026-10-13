package ai

import (
	"fmt"
	"sort"
	"strings"

	"infralens/internal/engine"
)

// Masker replaces real identifiers with stable aliases before anything is
// sent to an external model, and maps aliases back in the answer.
type Masker struct {
	alias map[string]string // real -> alias
	count map[string]int
}

func NewMasker() *Masker {
	return &Masker{alias: map[string]string{}, count: map[string]int{}}
}

func shortType(t string) string {
	return strings.ReplaceAll(strings.TrimPrefix(t, "aws_"), "_", "-")
}

func (m *Masker) get(real, kind string) string {
	if real == "" {
		return ""
	}
	if a, ok := m.alias[real]; ok {
		return a
	}
	m.count[kind]++
	a := fmt.Sprintf("%s-%03d", kind, m.count[kind])
	m.alias[real] = a
	return a
}

// MaskedNode carries only what the analysis needs: no names, ARNs, tags,
// IPs or free-text evidence.
type MaskedNode struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Region      string            `json:"region"`
	VPC         string            `json:"vpc,omitempty"`
	Status      string            `json:"status"`
	ManagedBy   string            `json:"managed_by,omitempty"`
	Confidence  string            `json:"confidence,omitempty"`
	MonthlyCost float64           `json:"monthly_cost"`
	WasteReason string            `json:"waste_reason,omitempty"`
	Attrs       map[string]string `json:"attrs,omitempty"`
}

type MaskedEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label,omitempty"`
}

type MaskedPayload struct {
	Regions       int                  `json:"region_count"`
	TotalWaste    float64              `json:"total_waste"`
	ShadowCount   int                  `json:"shadow_count"`
	EstimatedTCO  float64              `json:"estimated_tco"`
	PrevMonthCost float64              `json:"prev_month_cost"`
	CurrMonthCost float64              `json:"curr_month_cost"`
	Services      []engine.ServiceCost `json:"service_costs,omitempty"`
	Nodes         []MaskedNode         `json:"nodes"`
	Edges         []MaskedEdge         `json:"edges"`
}

var attrAllowlist = map[string]bool{
	"instance_type": true, "state": true, "size_gb": true, "volume_type": true, "launch_type": true,
	"desired": true, "running": true, "class": true, "engine": true, "multi_az": true, "lb_type": true,
	"scheme": true, "status": true, "storage_gb": true, "services": true, "running_tasks": true,
}

// Mask builds the payload for the model from a scan result.
func (m *Masker) Mask(res engine.ScanResult) MaskedPayload {
	p := MaskedPayload{
		Regions: len(res.Regions), TotalWaste: res.TotalWaste, ShadowCount: res.ShadowCount,
		EstimatedTCO: res.EstimatedTCO, PrevMonthCost: res.TotalPrevCost, CurrMonthCost: res.TotalCurrCost,
		Services: res.ServiceCosts,
	}
	ids := map[string]string{}
	for _, n := range res.Nodes {
		a := m.get(n.ID, shortType(n.Type))
		ids[n.ID] = a
		mn := MaskedNode{
			ID: a, Type: n.Type, Region: n.Region, VPC: m.get(n.VPCID, "vpc"),
			Status: string(n.Status), ManagedBy: n.ManagedBy, Confidence: string(n.Confidence),
			MonthlyCost: n.MonthlyCost, WasteReason: n.WasteReason,
		}
		for k, v := range n.Attrs {
			if attrAllowlist[k] {
				if mn.Attrs == nil {
					mn.Attrs = map[string]string{}
				}
				mn.Attrs[k] = v
			}
		}
		p.Nodes = append(p.Nodes, mn)
		// names are aliased too so that the answer can be unmasked by name
		m.alias[n.Name] = a
	}
	for _, e := range res.Edges {
		s, t := ids[e.Source], ids[e.Target]
		if s != "" && t != "" {
			p.Edges = append(p.Edges, MaskedEdge{s, t, e.Label})
		}
	}
	return p
}

// Unmask puts real identifiers back into the model's answer. It is applied
// locally, the real values never leave the machine.
func (m *Masker) Unmask(text string) string {
	byAlias := map[string]string{}
	for real, a := range m.alias {
		if cur, ok := byAlias[a]; !ok || len(real) > len(cur) {
			byAlias[a] = real
		}
	}
	aliases := make([]string, 0, len(byAlias))
	for a := range byAlias {
		aliases = append(aliases, a)
	}
	sort.Slice(aliases, func(i, j int) bool { return len(aliases[i]) > len(aliases[j]) })
	for _, a := range aliases {
		text = strings.ReplaceAll(text, a, byAlias[a])
	}
	return text
}
