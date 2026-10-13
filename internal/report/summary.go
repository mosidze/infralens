package report

import (
	"fmt"
	"sort"
	"strings"

	"infralens/internal/engine"
)

// LocalSummary builds the Executive Summary and cleanup plan from the scan
// data alone, so the report is useful with the AI layer switched off.
func LocalSummary(res engine.ScanResult) string {
	var b strings.Builder

	managed := 0
	for _, n := range res.Nodes {
		if n.Status == engine.StatusManaged {
			managed++
		}
	}
	fmt.Fprintf(&b, "EXECUTIVE SUMMARY\n")
	fmt.Fprintf(&b, "Resources found: %d in %d region(s). Under IaC markers: %d, no IaC marker (Shadow IT): %d, waste candidates: %d.\n",
		res.TotalLive, len(res.Regions), managed, res.ShadowCount, res.WasteCount)
	fmt.Fprintf(&b, "Waste candidates (estimate, owner confirmation needed): %s/month. Estimated cost of scanned resources: %s/month.\n",
		engine.Money(res.TotalWaste), engine.Money(res.EstimatedTCO))
	if res.AckedCount > 0 {
		fmt.Fprintf(&b, "Acknowledged by the owner and not counted: %d candidate(s), %s/month.\n",
			res.AckedCount, engine.Money(res.AckedWaste))
	}
	if res.TotalCurrCost > 0 || res.TotalPrevCost > 0 {
		fmt.Fprintf(&b, "Cost Explorer: %s last month, %s so far this month.\n",
			engine.Money(res.TotalPrevCost), engine.Money(res.TotalCurrCost))
	}
	b.WriteString("Costs are list-price estimates; Shadow IT means \"no IaC tag\", not proof of manual creation.\n")

	waste := []engine.ResourceNode{}
	for _, n := range res.Nodes {
		if n.Status == engine.StatusOrphanWaste {
			waste = append(waste, n)
		}
	}
	sort.Slice(waste, func(i, j int) bool { return waste[i].MonthlyCost > waste[j].MonthlyCost })

	b.WriteString("\nWASTE\n")
	if len(waste) == 0 {
		b.WriteString("No waste candidates found by the current checks.\n")
	}
	for _, n := range waste {
		fmt.Fprintf(&b, "- [%s] %s (%s, %s) %s/month, confidence %s: %s\n",
			n.Type, n.Name, n.ID, n.Region, engine.Money(n.MonthlyCost), n.Confidence, n.WasteReason)
		for _, e := range n.Evidence {
			fmt.Fprintf(&b, "    * %s\n", e)
		}
	}

	b.WriteString("\nACTION PLAN\n")
	steps := 0
	step := func(format string, a ...any) {
		steps++
		fmt.Fprintf(&b, "%d. %s\n", steps, fmt.Sprintf(format, a...))
	}
	counts := map[string]int{}
	for _, n := range waste {
		counts[n.Type]++
	}
	if counts["aws_ebs_volume"] > 0 {
		step("EBS: snapshot each unattached volume, keep the snapshot, then delete the volume (%d).", counts["aws_ebs_volume"])
	}
	if counts["aws_eip"] > 0 {
		step("Elastic IP: confirm the address is not whitelisted by a third party, then release (%d).", counts["aws_eip"])
	}
	if counts["aws_nat_gateway"] > 0 {
		step("NAT gateway: confirm no routes point at it, remove the route entries, then delete (%d).", counts["aws_nat_gateway"])
	}
	if counts["aws_lb"] > 0 {
		step("Load balancers: check DNS/Route53 records and listener rules, then delete (%d).", counts["aws_lb"])
	}
	if counts["aws_rds_instance"] > 0 {
		step("RDS: take a final snapshot, stop or delete idle instances after owners confirm (%d).", counts["aws_rds_instance"])
	}
	if counts["aws_ebs_snapshot"] > 0 {
		step("Snapshots: review owners, delete leftovers older than the retention policy (%d). Cost shown is an upper bound.", counts["aws_ebs_snapshot"])
	}
	if res.ShadowCount > 0 {
		step("Shadow IT: tag or import the %d untagged resources into IaC; start with the most expensive.", res.ShadowCount)
	}
	if steps == 0 {
		b.WriteString("Nothing to do.\n")
	}

	if len(res.Commitments) > 0 {
		b.WriteString("\nCOMMITMENTS (facts; suggestions depend on plans the scan cannot know)\n")
		for _, c := range res.Commitments {
			label := c.Service
			if c.Kind != "coverage" {
				label += " · " + c.Detail
			}
			fmt.Fprintf(&b, "- %s\n", label)
			for _, f := range c.Facts {
				fmt.Fprintf(&b, "    * %s\n", f)
			}
			switch {
			case c.Ack != nil:
				fmt.Fprintf(&b, "    acknowledged: %s\n", c.Ack.Note)
			default:
				for _, sg := range c.Suggestions {
					fmt.Fprintf(&b, "    ? %s\n", sg)
				}
			}
		}
	}

	if len(res.ServiceCosts) > 0 {
		b.WriteString("\nCOVERAGE vs COST EXPLORER (last full month)\n")
		cv := engine.CoverageOf(res)
		if cv.Billed > 0 {
			fmt.Fprintf(&b, "Of %s billed, services with a check: %.0f%%. The checks' estimates explain %.0f%% (an estimate counts up to the bill).\n",
				engine.Money(cv.Billed), cv.CheckPct(), cv.ExplainedPct())
			b.WriteString("Where the second figure is much lower, the service is request- or usage-priced and only its standing part is modelled.\n")
		}
		b.WriteString("\nEstimate vs billed usage (scanned services):\n")
		rows := 0
		for _, sc := range res.ServiceCosts {
			if !sc.Scanned || sc.PreviousMonthCost < 100 || rows == 8 {
				continue
			}
			rows++
			fmt.Fprintf(&b, "- %s: billed %s, list-price estimate %s%s\n", sc.Service,
				engine.Money(sc.PreviousMonthCost), engine.Money(sc.Estimated), ratioNote(sc.Estimated, sc.PreviousMonthCost))
		}
		shown := 0
		for _, sc := range res.ServiceCosts {
			if sc.Scanned || sc.PreviousMonthCost < 100 || shown == 8 {
				continue
			}
			if shown == 0 {
				b.WriteString("Not covered by any scanner:\n")
			}
			fmt.Fprintf(&b, "- %s: %s\n", sc.Service, engine.Money(sc.PreviousMonthCost))
			shown++
		}
	}

	if len(res.Warnings) > 0 {
		fmt.Fprintf(&b, "\nWARNINGS\n%d check(s) could not run (missing permissions or service errors); the picture is incomplete. See warnings.\n", len(res.Warnings))
	}
	return b.String()
}

// ratioNote explains a gap between the list-price estimate and billed usage.
// Commitments (Savings Plans, reservations) live in the payer account and are
// invisible here, so an estimate far above the bill usually means "covered".
func ratioNote(estimate, billed float64) string {
	if billed <= 0 {
		return ""
	}
	switch r := estimate / billed; {
	case r > 1.5:
		return " (estimate is higher: usage is probably covered by Savings Plans or reservations that this account cannot see)"
	case r < 0.7:
		return " (estimate is lower: requests, I/O, transfer or other storage classes are not modelled yet)"
	}
	return ""
}
