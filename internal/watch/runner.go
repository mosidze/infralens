package watch

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"infralens/internal/engine"
)

// Collector looks at one kind of thing and reports what is wrong with it.
// Collect returns only problems; a healthy resource produces nothing.
type Collector interface {
	Name() string // also the Source of every signal it returns
	Metered() bool
	Collect(ctx context.Context, env *Env) ([]Observation, error)
}

// Env is what a collector may use.
type Env struct {
	Graph  *Graph
	Now    time.Time
	Budget *Budget
}

// Runner polls collectors, applies hysteresis and notes, and answers the
// screen's questions. Free collectors run every Interval; metered ones at most
// every MeteredEvery, stretched further when the budget runs ahead of the day.
type Runner struct {
	Collectors   []Collector
	Tracker      *Tracker
	Graph        *Graph
	Budget       *Budget
	Interval     time.Duration
	MeteredEvery time.Duration
	Notes        func() engine.Context
	Account      string
	Profile      string
	Demo         bool
	Now          func() time.Time

	mu         sync.Mutex
	status     map[string]*CollectorStatus
	lastRun    map[string]time.Time
	fails      map[string]int
	updated    time.Time
	suppressed int
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// PollOnce runs every collector that is due.
func (r *Runner) PollOnce(ctx context.Context) {
	now := r.now()
	r.mu.Lock()
	if r.status == nil {
		r.status, r.lastRun, r.fails = map[string]*CollectorStatus{}, map[string]time.Time{}, map[string]int{}
	}
	r.mu.Unlock()

	var obs []Observation
	collected := map[string]bool{}
	for _, c := range r.Collectors {
		name := c.Name()
		r.mu.Lock()
		st := r.status[name]
		if st == nil {
			st = &CollectorStatus{Name: name, OK: true, Cost: "free"}
			if c.Metered() {
				st.Cost = "metered"
			}
			r.status[name] = st
		}
		due := true
		if c.Metered() && r.Budget != nil {
			every := r.Budget.Pace(now, r.MeteredEvery)
			due = now.Sub(r.lastRun[name]) >= every
		}
		r.mu.Unlock()
		if !due {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		got, err := c.Collect(cctx, &Env{Graph: r.Graph, Now: now, Budget: r.Budget})
		cancel()

		r.mu.Lock()
		r.lastRun[name] = now
		st.Last = now
		if err != nil {
			r.fails[name]++
			st.OK, st.Error = false, oneLine(err.Error(), 200)
			r.mu.Unlock()
			continue // its signals stay as they were: silence is not recovery
		}
		r.fails[name] = 0
		st.OK, st.Error, st.Signal = true, "", len(got)
		r.mu.Unlock()
		collected[name] = true
		for _, o := range got {
			o.Source = name
			if o.NodeID != "" {
				if id, ok := r.Graph.Resolve(o.NodeID); ok {
					o.NodeID = id
				}
			}
			if o.Key == "" {
				o.Key = name + "|" + o.Kind + "|" + o.NodeID
			}
			obs = append(obs, o)
		}
	}
	r.Tracker.Apply(obs, collected, now)
	r.mu.Lock()
	r.updated = now
	r.mu.Unlock()
}

// Run polls until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	if r.Interval <= 0 {
		r.Interval = 30 * time.Second
	}
	if r.MeteredEvery <= 0 {
		r.MeteredEvery = 5 * time.Minute
	}
	r.PollOnce(ctx)
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.PollOnce(ctx)
		}
	}
}

// Snapshot is what the screen shows right now.
func (r *Runner) Snapshot() Snapshot {
	now := r.now()
	var notes engine.Context
	if r.Notes != nil {
		notes = r.Notes()
	}
	var shown []Signal
	suppressed := 0
	for _, s := range r.Tracker.Visible() {
		if s.NodeID != "" {
			if n, ok := r.Graph.Node(s.NodeID); ok {
				if _, hit := notes.SuppressesLive(n.ID, n.Name, n.Type, n.Region, s.Kind, now); hit {
					suppressed++
					continue
				}
			}
		}
		shown = append(shown, s)
	}
	inc := buildIncidents(shown, r.Graph)
	snap := Snapshot{Now: now, Account: r.Account, Profile: r.Profile, Demo: r.Demo, Incidents: inc, Suppressed: suppressed}
	for _, in := range inc {
		for _, n := range in.Nodes {
			if n.Signals[0].Severity == SevCrit {
				snap.Crit++
			} else {
				snap.Warn++
			}
		}
	}
	if snap.Incidents == nil {
		snap.Incidents = []Incident{}
	}
	if r.Budget != nil {
		snap.Budget = r.Budget.Status(now)
	}
	r.mu.Lock()
	snap.UpdatedAt = r.updated
	for _, c := range r.Collectors {
		if st := r.status[c.Name()]; st != nil {
			snap.Collectors = append(snap.Collectors, *st)
			if !st.OK && r.fails[c.Name()] >= 2 {
				snap.Blind = append(snap.Blind, fmt.Sprintf("%s is not answering: %s", c.Name(), st.Error))
			}
		}
	}
	r.mu.Unlock()
	if snap.Collectors == nil {
		snap.Collectors = []CollectorStatus{}
	}
	return snap
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}
