package engine

// Coverage separates two claims that are easy to blur:
//   - WithCheck: billed usage of services that have a scanner at all;
//   - Explained: how much of that the scanners' estimates actually account
//     for (an estimate above the bill counts only up to the bill).
//
// A service can have a check and still be mostly unexplained, for example
// request-priced services where only the standing part is modelled.
type Coverage struct {
	Billed    float64
	WithCheck float64
	Explained float64
}

func (c Coverage) CheckPct() float64 {
	if c.Billed <= 0 {
		return 0
	}
	return c.WithCheck / c.Billed * 100
}

func (c Coverage) ExplainedPct() float64 {
	if c.Billed <= 0 {
		return 0
	}
	return c.Explained / c.Billed * 100
}

// CoverageOf computes both figures from the last full month's billed usage.
// With a cost ledger, "explained" is money actually attributed to resources;
// without one it falls back to catalogue estimates capped at the bill.
func CoverageOf(res ScanResult) Coverage {
	var c Coverage
	if res.Ledger != nil {
		for _, s := range res.ServiceCosts {
			c.Billed += s.PreviousMonthCost
			if s.Scanned {
				c.WithCheck += s.PreviousMonthCost
			}
		}
		c.Explained = res.Ledger.Allocated
		if c.Explained > c.Billed {
			c.Explained = c.Billed
		}
		return c
	}
	for _, s := range res.ServiceCosts {
		c.Billed += s.PreviousMonthCost
		if !s.Scanned {
			continue
		}
		c.WithCheck += s.PreviousMonthCost
		e := s.Estimated
		if e > s.PreviousMonthCost {
			e = s.PreviousMonthCost
		}
		c.Explained += e
	}
	return c
}
