// Package watch is the live layer: it turns what AWS reports right now into
// a short list of problems, tied to the resources a scan already knows. It
// shows only what is wrong. A healthy resource is not drawn, listed or
// counted, because a quiet screen is the point.
package watch

import (
	"errors"
	"sort"
	"time"
)

type Severity string

const (
	SevWarn Severity = "warn"
	SevCrit Severity = "crit"
)

func (s Severity) rank() int {
	if s == SevCrit {
		return 0
	}
	return 1
}

// ErrNotAvailable is returned by a collector whose source this account cannot
// use (a Support plan it does not have, a service that is switched off). It is
// not a failure: the source is set aside and the screen does not call it blind.
var ErrNotAvailable = errors.New("not available")

// Point is one sample of a metric.
type Point struct {
	T time.Time `json:"t"`
	V float64   `json:"v"`
}

// Series is the recent history of the metric that raised a signal, so the
// screen can show how it got there and not only where it is.
type Series struct {
	Name   string  `json:"name"`
	Unit   string  `json:"unit,omitempty"`
	Points []Point `json:"points"`
}

// Change is something that was modified on or next to a sick resource shortly
// before. It is context for a problem, never a feed of its own.
type Change struct {
	When     time.Time `json:"when"`
	Who      string    `json:"who,omitempty"`
	What     string    `json:"what"`
	Resource string    `json:"resource,omitempty"`
}

// Signal is one problem on one resource.
type Signal struct {
	Key       string    `json:"key"`    // stable: source|kind|node
	Source    string    `json:"source"` // alarm | health | ecs | elb | rds | ...
	Kind      string    `json:"kind"`
	NodeID    string    `json:"node_id,omitempty"`
	Title     string    `json:"title"`
	Severity  Severity  `json:"severity"`
	Since     time.Time `json:"since"`
	Evidence  []string  `json:"evidence,omitempty"`
	Threshold string    `json:"threshold,omitempty"`
	Series    *Series   `json:"series,omitempty"`
	Changes   []Change  `json:"changes,omitempty"`
	Note      string    `json:"note,omitempty"` // set when an owner note suppressed it
}

// Observation is a signal as a collector saw it in one poll. Immediate marks
// signals AWS has already debounced (an alarm in ALARM, a Health event), which
// need no second look.
type Observation struct {
	Signal
	Immediate bool
}

func sortSignals(s []Signal) {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Severity.rank() != s[j].Severity.rank() {
			return s[i].Severity.rank() < s[j].Severity.rank()
		}
		return s[i].Since.Before(s[j].Since)
	})
}
