package engine

import "sort"

// attachCoverage marks which Cost Explorer services have a scanner and sums
// the node estimates against them.
func attachCoverage(res *ScanResult, ceServices map[string]string) {
	est := map[string]float64{}
	for _, n := range res.Nodes {
		if svc, ok := ceServices[n.Type]; ok {
			est[svc] += n.MonthlyCost
		}
	}
	covered := map[string]bool{}
	for _, svc := range ceServices {
		covered[svc] = true
	}
	for i := range res.ServiceCosts {
		sc := &res.ServiceCosts[i]
		sc.Scanned = covered[sc.Service]
		sc.Estimated = est[sc.Service]
	}
}

// Finalize drops edges that point at unknown nodes, removes duplicate edges
// and fills the aggregate counters from node statuses.
func Finalize(res *ScanResult, costServices map[string]string) {
	known := make(map[string]bool, len(res.Nodes))
	for _, n := range res.Nodes {
		known[n.ID] = true
	}

	seen := make(map[Edge]bool, len(res.Edges))
	edges := make([]Edge, 0, len(res.Edges))
	for _, e := range res.Edges {
		if !known[e.Source] || !known[e.Target] || e.Source == e.Target || seen[e] {
			continue
		}
		seen[e] = true
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Source != edges[j].Source {
			return edges[i].Source < edges[j].Source
		}
		return edges[i].Target < edges[j].Target
	})
	res.Edges = edges

	attachCoverage(res, costServices)
	res.CoveredTypes = res.CoveredTypes[:0]
	for t := range costServices {
		res.CoveredTypes = append(res.CoveredTypes, t)
	}
	sort.Strings(res.CoveredTypes)
	res.TypeServices = costServices

	assignOwners(res)
	res.Findings = mergeFindings(res.Findings, deriveFindings(res))
	CrossCheck(res)

	res.TotalLive = len(res.Nodes)
	res.WasteCount, res.ShadowCount = 0, 0
	res.AckedCount, res.AckedWaste = 0, 0
	res.TotalWaste, res.EstimatedTCO = 0, 0
	for _, n := range res.Nodes {
		res.EstimatedTCO += n.MonthlyCost
		switch n.Status {
		case StatusOrphanWaste:
			if n.Ack != nil {
				res.AckedCount++
				res.AckedWaste += n.MonthlyCost
				continue
			}
			res.WasteCount++
			res.TotalWaste += n.MonthlyCost
		case StatusShadowIT:
			res.ShadowCount++
		}
	}
}
