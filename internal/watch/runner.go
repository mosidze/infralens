package watch

import (
	"context"
	"errors"
	"fmt"
	"sort"
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

// Paced is implemented by collectors that need to run less often than the
// base interval (they make many calls, or the answer changes slowly).
type Paced interface{ Every() time.Duration }

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
	// Stats reports API calls made and blocked, for the screen's footer.
	Stats func() (calls, blocked int)

	mu         sync.Mutex
	status     map[string]*CollectorStatus
	lastRun    map[string]time.Time
	busy       map[string]bool
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

// PollOnce runs every collector that is due and waits for them all.
func (r *Runner) PollOnce(ctx context.Context) {
	r.launch(ctx).Wait()
}

// launch starts every due collector on its own goroutine and returns at once.
// A slow collector (many regions, many calls) must not keep a fast one's
// answer off the screen, and a collector that is still running is not started
// again.
func (r *Runner) launch(ctx context.Context) *sync.WaitGroup {
	now := r.now()
	r.mu.Lock()
	if r.status == nil {
		r.status, r.lastRun, r.fails, r.busy = map[string]*CollectorStatus{}, map[string]time.Time{}, map[string]int{}, map[string]bool{}
	}
	r.mu.Unlock()

	wg := &sync.WaitGroup{}
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
		due := !r.busy[name]
		if due {
			if st.Disabled {
				due = now.Sub(r.lastRun[name]) >= 30*time.Minute // look again now and then
			} else if c.Metered() && r.Budget != nil {
				due = now.Sub(r.lastRun[name]) >= r.Budget.Pace(now, r.MeteredEvery)
			} else if p, ok := c.(Paced); ok {
				due = now.Sub(r.lastRun[name]) >= p.Every()
			}
		}
		if due {
			r.busy[name] = true
		}
		r.mu.Unlock()
		if !due {
			continue
		}
		wg.Add(1)
		go func(c Collector) {
			defer wg.Done()
			r.runOne(ctx, c, now)
		}(c)
	}
	return wg
}

// runOne runs one collector and applies its answer to the tracker at once, so
// the screen does not wait for the slowest source.
func (r *Runner) runOne(ctx context.Context, c Collector, now time.Time) {
	name := c.Name()
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	got, err := c.Collect(cctx, &Env{Graph: r.Graph, Now: now, Budget: r.Budget})
	cancel()

	r.mu.Lock()
	st := r.status[name]
	r.busy[name] = false
	r.lastRun[name] = r.now()
	st.Last = r.lastRun[name]
	if err != nil && errors.Is(err, ErrNotAvailable) {
		st.Disabled, st.OK, st.Error = true, true, ""
		st.Why = oneLine(strings.TrimPrefix(err.Error(), ErrNotAvailable.Error()+": "), 160)
		r.fails[name] = 0
		r.updated = st.Last
		r.mu.Unlock()
		return
	}
	st.Disabled, st.Why = false, ""
	if err != nil {
		r.fails[name]++
		st.OK, st.Error = false, oneLine(err.Error(), 200)
		r.updated = st.Last
		r.mu.Unlock()
		return // its signals stay as they were: silence is not recovery
	}
	r.fails[name] = 0
	st.OK, st.Error, st.Signal = true, "", len(got)
	r.updated = st.Last
	r.mu.Unlock()

	var obs []Observation
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
	r.Tracker.Apply(obs, map[string]bool{name: true}, now)
}

// Run polls until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	if r.Interval <= 0 {
		r.Interval = 30 * time.Second
	}
	if r.MeteredEvery <= 0 {
		r.MeteredEvery = 5 * time.Minute
	}
	r.launch(ctx)
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.launch(ctx)
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
	chronic := map[string]*ChronicGroup{}
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
		if s.chronic(now) {
			g := chronic[s.Kind]
			if g == nil {
				g = &ChronicGroup{Kind: s.Kind}
				chronic[s.Kind] = g
			}
			name := s.NodeID
			if n, ok := r.Graph.Node(s.NodeID); ok && n.Name != "" {
				name = n.Name
			}
			if name == "" {
				name = s.Title
			}
			detail := ""
			if len(s.Evidence) > 0 {
				detail = s.Evidence[0]
			}
			g.Count++
			g.Items = append(g.Items, ChronicItem{Name: name, Title: s.Title, Since: s.Since, Detail: detail})
			continue
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
	snap.Chronic = []ChronicGroup{}
	for _, g := range chronic {
		sort.SliceStable(g.Items, func(i, j int) bool { return g.Items[i].Name < g.Items[j].Name })
		snap.Chronic = append(snap.Chronic, *g)
	}
	sort.Slice(snap.Chronic, func(i, j int) bool { return snap.Chronic[i].Count > snap.Chronic[j].Count })
	if r.Budget != nil {
		snap.Budget = r.Budget.Status(now)
	}
	if r.Stats != nil {
		snap.APICalls, snap.Blocked = r.Stats()
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
