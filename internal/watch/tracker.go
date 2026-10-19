package watch

import (
	"sync"
	"time"
)

// Tracker keeps a signal from flickering: one bad sample does not raise it,
// and one good sample does not clear it. Trust matters more than speed on a
// screen that is meant to be quiet.
type Tracker struct {
	mu      sync.Mutex
	need    int // consecutive polls before a signal is shown
	clear   int // consecutive polls without it before it goes away
	entries map[string]*entry
}

type entry struct {
	sig     Signal
	seen    int
	missing int
	shown   bool
	since   time.Time
}

// NewTracker shows a signal after `need` consecutive sightings and removes it
// after `clear` consecutive polls without it.
func NewTracker(need, clear int) *Tracker {
	if need < 1 {
		need = 1
	}
	if clear < 1 {
		clear = 1
	}
	return &Tracker{need: need, clear: clear, entries: map[string]*entry{}}
}

// Apply records one poll. `collected` lists the collectors that answered: a
// collector that failed says nothing about its signals, so they are kept as
// they were instead of being cleared by silence.
func (t *Tracker) Apply(obs []Observation, collected map[string]bool, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	present := map[string]bool{}
	for _, o := range obs {
		present[o.Key] = true
		e := t.entries[o.Key]
		if e == nil {
			e = &entry{since: o.Since}
			if e.since.IsZero() {
				e.since = now
			}
			t.entries[o.Key] = e
		}
		e.sig = o.Signal
		e.sig.Since = e.since
		e.missing = 0
		e.seen++
		if o.Immediate || e.seen >= t.need {
			e.shown = true
		}
	}
	for k, e := range t.entries {
		if present[k] {
			continue
		}
		if !collected[e.sig.Source] {
			continue // that source did not answer; do not read silence as recovery
		}
		e.missing++
		e.seen = 0
		if e.missing >= t.clear {
			delete(t.entries, k)
		}
	}
}

// Visible returns the signals currently shown, worst first.
func (t *Tracker) Visible() []Signal {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Signal
	for _, e := range t.entries {
		if e.shown {
			out = append(out, e.sig)
		}
	}
	sortSignals(out)
	return out
}
