package watch

import (
	"sync"
	"time"
)

// usdPerMetric is what CloudWatch charges per metric requested through
// GetMetricData ($0.01 per 1,000). Every other call the monitor makes is free.
const usdPerMetric = 0.01 / 1000

type BudgetStatus struct {
	CapUSD    float64 `json:"cap_usd"`
	SpentUSD  float64 `json:"spent_usd"`
	Metrics   int64   `json:"metrics"`
	Throttled bool    `json:"throttled"`
}

// Budget caps what the monitor spends on metered calls in a UTC day. It never
// overspends silently: it refuses requests and slows polling instead.
type Budget struct {
	mu      sync.Mutex
	capUSD  float64
	day     string
	metrics int64
}

func NewBudget(capUSD float64) *Budget { return &Budget{capUSD: capUSD} }

func (b *Budget) roll(now time.Time) {
	d := now.UTC().Format("2006-01-02")
	if d != b.day {
		b.day, b.metrics = d, 0
	}
}

// Allow says whether n more metrics fit in today's budget.
func (b *Budget) Allow(n int, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll(now)
	return float64(b.metrics+int64(n))*usdPerMetric <= b.capUSD
}

// Charge records metrics that were requested.
func (b *Budget) Charge(n int, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll(now)
	b.metrics += int64(n)
}

func (b *Budget) Status(now time.Time) BudgetStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll(now)
	spent := float64(b.metrics) * usdPerMetric
	return BudgetStatus{CapUSD: b.capUSD, SpentUSD: spent, Metrics: b.metrics, Throttled: b.capUSD > 0 && spent >= b.capUSD*0.98}
}

// Pace stretches the polling interval when spending runs ahead of the day.
func (b *Budget) Pace(now time.Time, base time.Duration) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll(now)
	if b.capUSD <= 0 {
		return base
	}
	u := now.UTC()
	frac := float64(u.Hour()*3600+u.Minute()*60+u.Second()) / 86400
	if frac < 0.05 {
		frac = 0.05
	}
	ratio := float64(b.metrics) * usdPerMetric / b.capUSD / frac
	switch {
	case ratio > 1.2:
		return base * 3
	case ratio > 1.0:
		return base * 2
	}
	return base
}
