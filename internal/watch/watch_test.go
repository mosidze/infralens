package watch

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"infralens/internal/demo"
	"infralens/internal/engine"
)

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func obs(key, source string, immediate bool) Observation {
	return Observation{Immediate: immediate, Signal: Signal{Key: key, Source: source, Kind: "k", Severity: SevWarn, Title: key}}
}

func TestOneBadSampleDoesNotRaiseAndOneGoodDoesNotClear(t *testing.T) {
	tr := NewTracker(2, 2)
	ok := map[string]bool{"ecs": true}
	tr.Apply([]Observation{obs("a", "ecs", false)}, ok, t0)
	if len(tr.Visible()) != 0 {
		t.Fatal("a single sighting must not raise a signal")
	}
	tr.Apply([]Observation{obs("a", "ecs", false)}, ok, t0.Add(time.Minute))
	if len(tr.Visible()) != 1 {
		t.Fatal("two consecutive sightings must raise it")
	}
	tr.Apply(nil, ok, t0.Add(2*time.Minute))
	if len(tr.Visible()) != 1 {
		t.Fatal("one clean poll must not clear it")
	}
	tr.Apply(nil, ok, t0.Add(3*time.Minute))
	if len(tr.Visible()) != 0 {
		t.Fatal("two clean polls must clear it")
	}
}

func TestImmediateSignalsAreShownAtOnce(t *testing.T) {
	tr := NewTracker(3, 2)
	tr.Apply([]Observation{obs("alarm", "alarm", true)}, map[string]bool{"alarm": true}, t0)
	if len(tr.Visible()) != 1 {
		t.Fatal("an alarm AWS already debounced needs no second look")
	}
}

func TestSilenceFromAFailedCollectorIsNotRecovery(t *testing.T) {
	tr := NewTracker(1, 1)
	tr.Apply([]Observation{obs("a", "rds", false)}, map[string]bool{"rds": true}, t0)
	tr.Apply(nil, map[string]bool{}, t0.Add(time.Minute)) // rds did not answer
	if len(tr.Visible()) != 1 {
		t.Fatal("a collector that failed must not clear its signals")
	}
}

func TestSinceSurvivesRepeatedPolls(t *testing.T) {
	tr := NewTracker(1, 1)
	o := obs("a", "rds", true)
	o.Since = t0
	tr.Apply([]Observation{o}, map[string]bool{"rds": true}, t0)
	o.Since = t0.Add(time.Hour)
	tr.Apply([]Observation{o}, map[string]bool{"rds": true}, t0.Add(time.Hour))
	if got := tr.Visible()[0].Since; !got.Equal(t0) {
		t.Fatalf("since moved to %v", got)
	}
}

func demoRunner(now *time.Time) *Runner {
	res := demo.Scan(t0)
	return &Runner{
		Collectors: []Collector{&Demo{Start: t0}},
		Tracker:    NewTracker(1, 1),
		Graph:      NewGraph(res),
		Budget:     NewBudget(0.5),
		Now:        func() time.Time { return *now },
		Demo:       true,
	}
}

func TestConnectedProblemsFormOneIncidentAndHealthyThingsAreAbsent(t *testing.T) {
	now := t0.Add(60 * time.Second) // rds, ecs, elb and no kinesis yet
	r := demoRunner(&now)
	r.PollOnce(context.Background())
	snap := r.Snapshot()
	if len(snap.Incidents) != 2 {
		t.Fatalf("incidents = %d, want 2 (storefront+checkout joined, orders-2 alone)", len(snap.Incidents))
	}
	joined := 0
	for _, in := range snap.Incidents {
		if len(in.Nodes) == 2 {
			joined++
		}
	}
	if joined != 1 {
		t.Fatalf("the load balancer and the service it routes to must be one incident: %+v", snap.Incidents)
	}
	if snap.Crit != 2 || snap.Warn != 1 {
		t.Fatalf("crit=%d warn=%d", snap.Crit, snap.Warn)
	}
	if snap.Incidents[0].Severity != SevCrit {
		t.Fatal("worst first")
	}
	b, _ := json.Marshal(snap)
	if strings.Contains(string(b), "orders-1") {
		t.Fatal("a healthy resource must not appear anywhere")
	}
}

func TestQuietScreenIsAnEmptyListNotNull(t *testing.T) {
	now := t0.Add(225 * time.Second) // after everything cleared
	r := demoRunner(&now)
	r.PollOnce(context.Background())
	b, _ := json.Marshal(r.Snapshot())
	if !strings.Contains(string(b), `"incidents":[]`) {
		t.Fatalf("quiet state must be an empty list: %s", b)
	}
}

func TestOwnerNoteSilencesOnlyWhenItNamesALiveRule(t *testing.T) {
	now := t0.Add(60 * time.Second)
	r := demoRunner(&now)
	var note engine.ContextNote
	note.Match.Name = "orders-2"
	note.Note = "failover drill"
	r.Notes = func() engine.Context { return engine.Context{Notes: []engine.ContextNote{note}} }
	r.PollOnce(context.Background())
	if n := len(r.Snapshot().Incidents); n != 2 {
		t.Fatalf("an audit-style note must not hide an outage (incidents %d)", n)
	}
	note.Match.Rule = "live.rds.replica-lag"
	r.Notes = func() engine.Context { return engine.Context{Notes: []engine.ContextNote{note}} }
	snap := r.Snapshot()
	if len(snap.Incidents) != 1 || snap.Suppressed != 1 {
		t.Fatalf("a live rule note must silence it and say so: %+v", snap)
	}
}

type failing struct{}

func (failing) Name() string  { return "ecs" }
func (failing) Metered() bool { return false }
func (failing) Collect(context.Context, *Env) ([]Observation, error) {
	return nil, errors.New("ExpiredToken: the security token included in the request is expired")
}

func TestAMonitorThatCannotSeeSaysSoAfterRepeatedFailure(t *testing.T) {
	now := t0
	r := &Runner{Collectors: []Collector{failing{}}, Tracker: NewTracker(1, 1), Graph: NewGraph(engine.ScanResult{}), Now: func() time.Time { return now }}
	r.PollOnce(context.Background())
	if len(r.Snapshot().Blind) != 0 {
		t.Fatal("one failure is a blip")
	}
	r.PollOnce(context.Background())
	snap := r.Snapshot()
	if len(snap.Blind) != 1 || !strings.Contains(snap.Blind[0], "ExpiredToken") {
		t.Fatalf("blind: %v", snap.Blind)
	}
}

func TestBudgetIsFiftyCentsAndSlowsPollingWhenAhead(t *testing.T) {
	b := NewBudget(0.5)
	noon := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	if !b.Allow(50000, noon) || b.Allow(50001, noon) {
		t.Fatal("50,000 metrics is exactly $0.50")
	}
	if b.Pace(noon, 5*time.Minute) != 5*time.Minute {
		t.Fatal("no spend: normal pace")
	}
	b.Charge(40000, noon) // $0.40 by noon: well ahead of a linear day
	if p := b.Pace(noon, 5*time.Minute); p <= 5*time.Minute {
		t.Fatalf("must slow down, got %v", p)
	}
	if !b.Status(noon).Throttled && b.Status(noon).SpentUSD < 0.39 {
		t.Fatal("status must report spend")
	}
	next := noon.Add(24 * time.Hour)
	if b.Status(next).Metrics != 0 {
		t.Fatal("budget resets with the UTC day")
	}
}

type unavailable struct{}

func (unavailable) Name() string  { return "health" }
func (unavailable) Metered() bool { return false }
func (unavailable) Collect(context.Context, *Env) ([]Observation, error) {
	return nil, errors.Join(ErrNotAvailable, errors.New("needs a Business support plan"))
}

func TestASourceTheAccountCannotUseIsSetAsideNotCalledBlind(t *testing.T) {
	now := t0
	r := &Runner{Collectors: []Collector{unavailable{}}, Tracker: NewTracker(1, 1), Graph: NewGraph(engine.ScanResult{}), Now: func() time.Time { return now }}
	r.PollOnce(context.Background())
	r.PollOnce(context.Background())
	r.PollOnce(context.Background())
	snap := r.Snapshot()
	if len(snap.Blind) != 0 {
		t.Fatalf("an unavailable source is not a failure: %v", snap.Blind)
	}
	if len(snap.Collectors) != 1 || !snap.Collectors[0].Disabled {
		t.Fatalf("collectors: %+v", snap.Collectors)
	}
}

type fixed struct{ obs []Observation }

func (fixed) Name() string                                           { return "x" }
func (fixed) Metered() bool                                          { return false }
func (f fixed) Collect(context.Context, *Env) ([]Observation, error) { return f.obs, nil }

func TestStandingProblemsAreListedApartAndDoNotCountAsIllnessNow(t *testing.T) {
	old := Observation{Immediate: true, Signal: Signal{Kind: "alarm.firing", NodeID: "", Severity: SevCrit, Title: "stale alarm", Since: t0.Add(-5 * 24 * time.Hour)}}
	flagged := Observation{Immediate: true, Signal: Signal{Kind: "sqs.dlq-standing", NodeID: "q", Severity: SevWarn, Title: "backlog", Chronic: true}}
	fresh := Observation{Immediate: true, Signal: Signal{Kind: "ecs.under-replicated", NodeID: "svc", Severity: SevCrit, Title: "down", Since: t0.Add(-10 * time.Minute)}}
	now := t0
	r := &Runner{Collectors: []Collector{fixed{[]Observation{old, flagged, fresh}}}, Tracker: NewTracker(1, 1), Graph: NewGraph(engine.ScanResult{}), Now: func() time.Time { return now }}
	r.PollOnce(context.Background())
	snap := r.Snapshot()
	if snap.Crit != 1 || snap.Warn != 0 || len(snap.Incidents) != 1 {
		t.Fatalf("only the fresh problem is sick now: crit=%d warn=%d incidents=%d", snap.Crit, snap.Warn, len(snap.Incidents))
	}
	total := 0
	for _, g := range snap.Chronic {
		total += g.Count
	}
	if total != 2 {
		t.Fatalf("both standing problems must still be listed: %+v", snap.Chronic)
	}
}

func TestSlowSourcesCanAskForFewerSightings(t *testing.T) {
	tr := NewTracker(3, 1)
	tr.SetNeed("elb", 1)
	tr.Apply([]Observation{obs("a", "elb", false), obs("b", "ecs", false)}, map[string]bool{"elb": true, "ecs": true}, t0)
	v := tr.Visible()
	if len(v) != 1 || v[0].Key != "a" {
		t.Fatalf("only the slow source's signal should show after one sighting: %+v", v)
	}
}
