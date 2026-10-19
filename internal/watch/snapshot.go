package watch

import (
	"sort"
	"time"
)

type NodeView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Region    string   `json:"region,omitempty"`
	Owner     string   `json:"owner,omitempty"`
	CostMonth float64  `json:"cost_month,omitempty"`
	Connected int      `json:"connected"`
	Neighbors []string `json:"neighbors,omitempty"`
	Unmapped  bool     `json:"unmapped,omitempty"`
	Signals   []Signal `json:"signals"`
}

// Incident is a set of sick resources that are connected to each other, so a
// failing database and the services that choke on it read as one event.
type Incident struct {
	ID       string     `json:"id"`
	Severity Severity   `json:"severity"`
	Since    time.Time  `json:"since"`
	Nodes    []NodeView `json:"nodes"`
}

type CollectorStatus struct {
	Name   string    `json:"name"`
	OK     bool      `json:"ok"`
	Error  string    `json:"error,omitempty"`
	Last   time.Time `json:"last,omitempty"`
	Cost   string    `json:"cost,omitempty"` // free | metered
	Signal int       `json:"signals"`
}

type Snapshot struct {
	Now        time.Time         `json:"now"`
	UpdatedAt  time.Time         `json:"updated_at"`
	Account    string            `json:"account,omitempty"`
	Profile    string            `json:"profile,omitempty"`
	Demo       bool              `json:"demo,omitempty"`
	Crit       int               `json:"crit"`
	Warn       int               `json:"warn"`
	Incidents  []Incident        `json:"incidents"`
	Suppressed int               `json:"suppressed,omitempty"`
	Collectors []CollectorStatus `json:"collectors"`
	Budget     BudgetStatus      `json:"budget"`
	Blind      []string          `json:"blind,omitempty"`
}

// buildIncidents groups signals by resource, then joins resources that are
// directly connected.
func buildIncidents(sigs []Signal, g *Graph) []Incident {
	byNode := map[string][]Signal{}
	for _, s := range sigs {
		id := s.NodeID
		if id == "" {
			id = "account"
		}
		byNode[id] = append(byNode[id], s)
	}
	ids := make([]string, 0, len(byNode))
	for id := range byNode {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	parent := map[string]string{}
	for _, id := range ids {
		parent[id] = id
	}
	var find func(string) string
	find = func(x string) string {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	for _, a := range ids {
		for _, b := range g.neighbors(a) {
			if _, sick := byNode[b]; sick {
				ra, rb := find(a), find(b)
				if ra != rb {
					parent[rb] = ra
				}
			}
		}
	}
	groups := map[string][]string{}
	for _, id := range ids {
		r := find(id)
		groups[r] = append(groups[r], id)
	}

	var out []Incident
	for _, members := range groups {
		inc := Incident{ID: members[0], Severity: SevWarn}
		for _, id := range members {
			v := NodeView{ID: id, Signals: byNode[id]}
			if n, ok := g.Node(id); ok {
				v.Name, v.Kind, v.Region, v.Owner, v.CostMonth = n.Name, kindOf(n.Type), n.Region, n.Owner, n.MonthlyCost
				if v.Name == "" {
					v.Name = n.ID
				}
				v.Connected, v.Neighbors = g.connected(id)
			} else {
				v.Unmapped, v.Name, v.Kind = true, id, "not in the last scan"
				if id == "account" {
					v.Name, v.Kind, v.Unmapped = "Account", "AWS account", false
				}
			}
			sortSignals(v.Signals)
			for _, s := range v.Signals {
				if s.Severity == SevCrit {
					inc.Severity = SevCrit
				}
				if inc.Since.IsZero() || s.Since.Before(inc.Since) {
					inc.Since = s.Since
				}
			}
			inc.Nodes = append(inc.Nodes, v)
		}
		sort.SliceStable(inc.Nodes, func(i, j int) bool {
			a, b := inc.Nodes[i], inc.Nodes[j]
			if a.Signals[0].Severity.rank() != b.Signals[0].Severity.rank() {
				return a.Signals[0].Severity.rank() < b.Signals[0].Severity.rank()
			}
			return a.Connected > b.Connected
		})
		out = append(out, inc)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.rank() != out[j].Severity.rank() {
			return out[i].Severity.rank() < out[j].Severity.rank()
		}
		wi, wj := weight(out[i]), weight(out[j])
		if wi != wj {
			return wi > wj
		}
		return out[i].Since.Before(out[j].Since)
	})
	return out
}

// weight orders incidents of equal severity: how much is connected to them,
// then what they cost.
func weight(in Incident) float64 {
	var w float64
	for _, n := range in.Nodes {
		w += float64(n.Connected)*10 + n.CostMonth/100
	}
	return w
}
