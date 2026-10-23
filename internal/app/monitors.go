package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"infralens/internal/watch"
)

// MonitorSpec names one thing to watch. A monitor is an AWS profile or a
// Kubernetes context; each is a tab on the Problems screen.
type MonitorSpec struct {
	Kind       string `json:"kind"` // aws | k8s | demo
	Name       string `json:"name"` // profile or context
	Kubeconfig string `json:"kubeconfig,omitempty"`
}

func (m MonitorSpec) ID() string { return m.Kind + ":" + m.Name }

type monitor struct {
	Spec   MonitorSpec
	Src    LiveSource
	cancel context.CancelFunc
}

type monitorSet struct {
	mu   sync.Mutex
	list []*monitor
}

func (m *monitorSet) add(x *monitor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.list = append(m.list, x)
}

func (m *monitorSet) get(id string) *monitor {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id == "" && len(m.list) > 0 {
		return m.list[0]
	}
	for _, x := range m.list {
		if x.Spec.ID() == id {
			return x
		}
	}
	return nil
}

func (m *monitorSet) remove(id string) *monitor {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, x := range m.list {
		if id == "" && len(m.list) == 1 || x.Spec.ID() == id {
			m.list = append(m.list[:i], m.list[i+1:]...)
			return x
		}
	}
	return nil
}

func (m *monitorSet) all() []*monitor {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*monitor(nil), m.list...)
}

// failed stands in for a monitor that could not start, so its tab says why
// instead of vanishing.
type failed struct {
	spec MonitorSpec
	err  string
}

func (f failed) Snapshot() watch.Snapshot {
	return watch.Snapshot{Now: time.Now(), Profile: f.spec.Name, Kind: f.spec.Kind, Incidents: []watch.Incident{}, Chronic: []watch.ChronicGroup{},
		Collectors: []watch.CollectorStatus{}, Blind: []string{"cannot start: " + f.err}}
}

var safeName2 = regexp.MustCompile(`^[A-Za-z0-9._@+=,:/~ -]{1,200}$`)

func (s *Server) monitorsFile() string { return filepath.Join(s.cfg.Base, "monitors.json") }

func (s *Server) saveMonitors() {
	var specs []MonitorSpec
	for _, m := range s.mons.all() {
		if m.Spec.Kind != "demo" {
			specs = append(specs, m.Spec)
		}
	}
	b, _ := json.MarshalIndent(specs, "", "  ")
	_ = os.MkdirAll(s.cfg.Base, 0o700)
	tmp := s.monitorsFile() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.monitorsFile())
	}
}

// RestoreMonitors starts the monitors that were running last time, so the
// tabs are still there after a restart. One that cannot start keeps its tab
// and shows why.
func (s *Server) RestoreMonitors(ctx context.Context) {
	b, err := os.ReadFile(s.monitorsFile())
	if err != nil || s.cfg.Hooks.StartMonitor == nil {
		return
	}
	var specs []MonitorSpec
	if json.Unmarshal(b, &specs) != nil {
		return
	}
	for _, sp := range specs {
		if s.mons.get(sp.ID()) != nil || sp.Kind == "demo" {
			continue
		}
		s.startOne(ctx, sp)
	}
}

func (s *Server) startOne(parent context.Context, sp MonitorSpec) error {
	ctx, cancel := context.WithCancel(parent)
	src, err := s.cfg.Hooks.StartMonitor(ctx, sp)
	if err != nil {
		cancel()
		s.mons.add(&monitor{Spec: sp, Src: failed{sp, err.Error()}})
		return err
	}
	s.mons.add(&monitor{Spec: sp, Src: src, cancel: cancel})
	return nil
}

type monitorView struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Label    string `json:"label"`
	Crit     int    `json:"crit"`
	Warn     int    `json:"warn"`
	Blind    bool   `json:"blind"`
	Standing int    `json:"standing"`
}

func (s *Server) liveMonitors(w http.ResponseWriter, r *http.Request) {
	out := []monitorView{}
	for _, m := range s.mons.all() {
		snap := m.Src.Snapshot()
		v := monitorView{ID: m.Spec.ID(), Kind: m.Spec.Kind, Name: m.Spec.Name, Crit: snap.Crit, Warn: snap.Warn, Blind: len(snap.Blind) > 0}
		v.Label = m.Spec.Name
		for _, g := range snap.Chronic {
			v.Standing += g.Count
		}
		out = append(out, v)
	}
	writeJSON(w, 200, map[string]any{"monitors": out})
}

func (s *Server) liveState(w http.ResponseWriter, r *http.Request) {
	m := s.mons.get(r.URL.Query().Get("id"))
	if m == nil {
		fail(w, 404, "the monitor is not running")
		return
	}
	snap := m.Src.Snapshot()
	if snap.Kind == "" {
		snap.Kind = m.Spec.Kind
	}
	writeJSON(w, 200, snap)
}

func (s *Server) liveStart(w http.ResponseWriter, r *http.Request) {
	var q struct {
		MonitorSpec
		Profile string `json:"profile"` // older clients: an AWS profile
	}
	if err := readJSON(r, &q); err != nil {
		fail(w, 400, "bad request")
		return
	}
	sp := q.MonitorSpec
	if sp.Kind == "" {
		sp = MonitorSpec{Kind: "aws", Name: q.Profile}
	}
	if (sp.Kind != "aws" && sp.Kind != "k8s") || !safeName2.MatchString(sp.Name) || strings.Contains(sp.Name, ",") ||
		(sp.Kubeconfig != "" && (!safeName2.MatchString(sp.Kubeconfig) || strings.Contains(sp.Kubeconfig, ".."))) {
		fail(w, 400, "bad request")
		return
	}
	if s.cfg.Hooks.StartMonitor == nil {
		fail(w, 501, "the monitor is not available in this build")
		return
	}
	if old := s.mons.get(sp.ID()); old != nil {
		if _, dead := old.Src.(failed); !dead {
			fail(w, 409, "this is already being watched")
			return
		}
		s.mons.remove(sp.ID()) // a failed tab may be retried
	}
	if err := s.startOne(context.Background(), sp); err != nil {
		s.mons.remove(sp.ID()) // report the error to the caller, not as a ghost tab
		fail(w, 400, err.Error())
		return
	}
	s.saveMonitors()
	writeJSON(w, 202, map[string]string{"id": sp.ID()})
}

func (s *Server) liveStop(w http.ResponseWriter, r *http.Request) {
	var q struct {
		ID string `json:"id"`
	}
	_ = readJSON(r, &q)
	if m := s.mons.remove(q.ID); m != nil && m.cancel != nil {
		m.cancel()
	}
	s.saveMonitors()
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) k8sContexts(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Hooks.K8sContexts == nil {
		fail(w, 501, "Kubernetes is not available in this build")
		return
	}
	kc := r.URL.Query().Get("kubeconfig")
	if kc != "" && (!safeName2.MatchString(kc) || strings.Contains(kc, "..")) {
		fail(w, 400, "bad kubeconfig path")
		return
	}
	ctxs, err := s.cfg.Hooks.K8sContexts(kc)
	if err != nil {
		fail(w, 400, errors.New(fmt.Sprint("cannot read the kubeconfig: ", err)).Error())
		return
	}
	writeJSON(w, 200, map[string]any{"contexts": ctxs})
}

// Watch starts a monitor unless one with the same identity already exists.
func (s *Server) Watch(ctx context.Context, sp MonitorSpec) error {
	if old := s.mons.get(sp.ID()); old != nil {
		if _, dead := old.Src.(failed); !dead {
			return nil
		}
		s.mons.remove(sp.ID())
	}
	// a monitor that cannot start keeps its tab, which says why; the caller
	// decides whether that is fatal
	err := s.startOne(ctx, sp)
	s.saveMonitors()
	return err
}
