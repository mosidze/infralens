package watch

import (
	"context"
	"time"
)

// Demo is a scripted source of problems for the example scan. It lets the
// screen be developed, screenshotted and shown without an AWS account: some
// problems appear, one joins another, some clear, and for a while it is quiet.
type Demo struct {
	Start time.Time
	Cycle time.Duration
}

func (d *Demo) Name() string  { return "demo" }
func (d *Demo) Metered() bool { return false }

func ramp(name, unit string, now time.Time, from, to float64, riseOver time.Duration) *Series {
	s := &Series{Name: name, Unit: unit}
	for i := 72; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * 5 * time.Minute)
		age := time.Duration(i) * 5 * time.Minute
		v := from
		if age < riseOver {
			v = from + (to-from)*float64(riseOver-age)/float64(riseOver)
		}
		s.Points = append(s.Points, Point{T: t, V: v})
	}
	return s
}

func (d *Demo) Collect(_ context.Context, env *Env) ([]Observation, error) {
	cycle := d.Cycle
	if cycle <= 0 {
		cycle = 4 * time.Minute
	}
	el := env.Now.Sub(d.Start) % cycle
	in := func(from, to time.Duration) bool { return el >= from && el < to }
	since := func(from time.Duration) time.Time { return env.Now.Add(-(el - from)) }
	now := env.Now
	sec := time.Second

	var out []Observation
	if in(20*sec, 190*sec) {
		out = append(out, Observation{Immediate: true, Signal: Signal{
			Kind: "rds.replica-lag", NodeID: "orders-2", Severity: SevCrit, Since: since(20 * sec),
			Title:     "Replica lag is growing",
			Threshold: "lag above 60 s for 10 min",
			Evidence:  []string{"ReplicaLag 214 s now, 3 s an hour ago", "the writer is healthy; the replica is falling behind"},
			Series:    ramp("ReplicaLag", "s", now, 3, 214, 70*time.Minute),
		}})
	}
	if in(10*sec, 150*sec) {
		out = append(out, Observation{Immediate: true, Signal: Signal{
			Kind: "ecs.under-replicated", NodeID: "checkout-svc-03", Severity: SevWarn, Since: since(10 * sec),
			Title:     "1 of 3 tasks is running",
			Threshold: "running below desired for 3 min",
			Evidence:  []string{"2 tasks stopped: Essential container in task exited (exit code 137)", "the last deployment is still rolling out"},
			Series:    ramp("RunningTaskCount", "tasks", now, 3, 1, 12*time.Minute),
			Changes: []Change{{When: now.Add(-14 * time.Minute), Who: "deploy-bot", What: "ECS UpdateService: new task definition", Resource: "checkout-svc-03"}},
		}})
	}
	if in(40*sec, 150*sec) {
		out = append(out, Observation{Immediate: true, Signal: Signal{
			Kind: "elb.unhealthy-targets", NodeID: "storefront", Severity: SevCrit, Since: since(40 * sec),
			Title:     "2 of 3 targets are unhealthy",
			Threshold: "any unhealthy target in a target group",
			Evidence:  []string{"health checks fail with 502 on /healthz", "5xx rate 18% over the last 5 min"},
			Series:    ramp("HTTPCode_Target_5XX_Count", "req/min", now, 2, 410, 20*time.Minute),
		}})
	}
	if in(90*sec, 210*sec) {
		out = append(out, Observation{Signal: Signal{
			Kind: "kinesis.iterator-age", NodeID: "promo-sync-raw", Severity: SevWarn, Since: since(90 * sec),
			Title:     "Consumers are falling behind",
			Threshold: "iterator age above 5 min",
			Evidence:  []string{"GetRecords.IteratorAgeMilliseconds 9 min", "no consumer has caught up in 30 min"},
			Series:    ramp("IteratorAge", "min", now, 0.1, 9, 45*time.Minute),
		}})
	}
	return out, nil
}
