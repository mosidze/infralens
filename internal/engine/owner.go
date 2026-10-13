package engine

import (
	"fmt"
	"sort"
	"strings"
)

// Ownership is the most common practical gap in an audit: a finding without
// an owner turns into the question "whose is this?". Owners are read only
// from what the account itself says (tags); nothing is guessed.

// ownerTagKeys are tried in order, compared case-insensitively. Team and
// owner-like keys come before cost and project keys, which say who pays or
// what it belongs to rather than who answers for it.
var ownerTagKeys = []string{
	"owner", "team", "squad", "maintainer", "contact", "responsible",
	"costcenter", "cost-center", "cost_center", "businessunit", "department",
	"applicationgroup", "application", "app", "project", "service", "product",
}

// OwnerFromTags returns the first matching tag value and its key.
func OwnerFromTags(tags map[string]string) (value, source string) {
	if len(tags) == 0 {
		return "", ""
	}
	lower := make(map[string]string, len(tags))
	orig := make(map[string]string, len(tags))
	for k, v := range tags {
		lk := strings.ToLower(strings.TrimSpace(k))
		lower[lk] = strings.TrimSpace(v)
		orig[lk] = k
	}
	for _, want := range ownerTagKeys {
		if v := lower[want]; v != "" {
			return v, "tag:" + orig[want]
		}
	}
	return "", ""
}

// ownable says whether a node type is something a person answers for. Log
// group roll-ups and the like are not.
func ownable(t string) bool {
	switch t {
	case "aws_cloudwatch_log_group_rollup", "aws_ecs_cluster":
		return false
	}
	return true
}

func assignOwners(res *ScanResult) {
	for i := range res.Nodes {
		n := &res.Nodes[i]
		if v, src := OwnerFromTags(n.Tags); v != "" {
			n.Owner, n.OwnerSource = v, src
		}
	}
}

// ownerFinding summarises resources that carry no owner. One finding, not
// one per resource: the point is the size of the gap and where the money is.
func ownerFinding(res *ScanResult) []Finding {
	var missing []ResourceNode
	total := 0
	for _, n := range res.Nodes {
		if !ownable(n.Type) {
			continue
		}
		total++
		if n.Owner == "" {
			missing = append(missing, n)
		}
	}
	if total == 0 || len(missing) == 0 {
		return nil
	}
	sort.SliceStable(missing, func(i, j int) bool { return missing[i].MonthlyCost > missing[j].MonthlyCost })
	var cost float64
	for _, n := range missing {
		cost += n.MonthlyCost
	}
	var top []string
	for i, n := range missing {
		if i == 5 {
			break
		}
		top = append(top, fmt.Sprintf("%s (%s, $%.0f/mo)", n.Name, typeLabelShort(n.Type), n.MonthlyCost))
	}
	f := Finding{
		Pillar: PillarOps, Source: "own", Rule: "ops.no-owner", Severity: SevMedium, Derived: true,
		Title:       fmt.Sprintf("%d of %d resources carry no owner, team or project tag", len(missing), total),
		ResourceID:  "account:ownership",
		MonthlyCost: cost, Affected: len(missing), Confidence: ConfHigh, Effort: "medium",
		Evidence: []string{
			fmt.Sprintf("%.0f%% of inventoried resources have none of: owner, team, squad, cost centre, application, project, service", float64(len(missing))/float64(total)*100),
			"largest: " + strings.Join(top, "; "),
		},
		Recommendation: "Agree on one ownership tag and apply it, starting with the most expensive resources. Without an owner every other finding in this report stops at 'whose is this?'.",
	}
	f.ID = FindingID(f.Source, f.Rule, f.ResourceID)
	return []Finding{f}
}

func typeLabelShort(t string) string {
	return strings.ReplaceAll(strings.TrimPrefix(t, "aws_"), "_", " ")
}
