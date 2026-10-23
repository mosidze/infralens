package k8swatch

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"infralens/internal/watch"
)

// Collectors returns the Kubernetes collectors. Every one reports only what is
// wrong, per workload.
func Collectors(c *Cluster) []watch.Collector {
	return []watch.Collector{
		&workloads{c}, &restarts{c: c}, &nodes{c}, &services{c}, &jobsC{c}, &storage{c}, &hpaC{c},
	}
}

// podReasons says, for a set of pods, why they are not serving: the waiting
// reasons and the scheduler's complaint, most common first.
func podReasons(pods []corev1.Pod, now time.Time) []string {
	count := map[string]int{}
	for _, p := range pods {
		if p.Status.Phase == corev1.PodSucceeded {
			continue
		}
		reported := false
		for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
			if w := cs.State.Waiting; w != nil && w.Reason != "" && w.Reason != "PodInitializing" {
				if w.Reason == "ContainerCreating" && now.Sub(p.CreationTimestamp.Time) < 5*time.Minute {
					continue
				}
				msg := w.Reason
				if w.Message != "" {
					msg += " (" + short(w.Message, 90) + ")"
				}
				count[msg]++
				reported = true
				break
			}
		}
		if reported {
			continue
		}
		if p.Status.Phase == corev1.PodPending {
			for _, cd := range p.Status.Conditions {
				if cd.Type == corev1.PodScheduled && cd.Status == corev1.ConditionFalse {
					count["Unschedulable ("+short(cd.Message, 110)+")"]++
					reported = true
				}
			}
		}
		if !reported && p.Status.Phase == corev1.PodFailed {
			count["Failed ("+p.Status.Reason+")"]++
		}
	}
	return topLines(count, 3)
}

// ---- workloads below their wanted size ----------------------------------------------

type workloads struct{ c *Cluster }

func (*workloads) Name() string  { return "workloads" }
func (*workloads) Metered() bool { return false }

func (w *workloads) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	now := w.c.now()
	pods, err := w.c.pods(ctx)
	if err != nil {
		return nil, err
	}
	own, err := w.c.owners(ctx)
	if err != nil {
		return nil, err
	}
	byOwner := map[string][]corev1.Pod{}
	for _, p := range pods {
		p := p
		r := own.ofPod(&p)
		byOwner[r.ID()] = append(byOwner[r.ID()], p)
	}
	var out []watch.Observation
	emit := func(r ref, desired, ready int32, since time.Time, extra string) {
		s := watch.SevWarn
		title := fmt.Sprintf("%d of %d replicas ready", ready, desired)
		if ready == 0 {
			s = watch.SevCrit
			title = fmt.Sprintf("no replicas ready (%d wanted)", desired)
		}
		ev := podReasons(byOwner[r.ID()], now)
		if extra != "" {
			ev = append([]string{extra}, ev...)
		}
		out = append(out, watch.Observation{Signal: watch.Signal{
			Kind: "k8s.workload-unavailable", NodeID: r.ID(), Severity: sev(r.NS, s), Since: since,
			Title: title, Threshold: "ready replicas below wanted, outside a rollout", Evidence: ev,
		}})
	}

	deps, err := w.c.deployments(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range deps {
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		if desired == 0 || d.Status.AvailableReplicas >= desired {
			continue
		}
		var since time.Time
		extra := ""
		rolling := false
		for _, c := range d.Status.Conditions {
			switch c.Type {
			case "Available":
				if c.Status == corev1.ConditionFalse {
					since = c.LastTransitionTime.Time
				}
			case "Progressing":
				if c.Status == corev1.ConditionFalse {
					extra = "the rollout exceeded its progress deadline"
					if since.IsZero() {
						since = c.LastTransitionTime.Time
					}
				} else if c.Status == corev1.ConditionTrue && now.Sub(c.LastUpdateTime.Time) < 5*time.Minute &&
					(c.Reason == "ReplicaSetUpdated" || c.Reason == "NewReplicaSetCreated" || c.Reason == "ScalingReplicaSet") {
					rolling = true
				}
			}
		}
		if rolling {
			continue // a rollout in its first minutes is not a fault
		}
		emit(ref{d.Namespace, "Deployment", d.Name}, desired, d.Status.AvailableReplicas, since, extra)
	}
	sts, err := w.c.statefulSets(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range sts {
		desired := int32(1)
		if s.Spec.Replicas != nil {
			desired = *s.Spec.Replicas
		}
		if desired == 0 || s.Status.ReadyReplicas >= desired {
			continue
		}
		if s.Status.UpdateRevision != s.Status.CurrentRevision && now.Sub(s.CreationTimestamp.Time) > 0 && s.Status.UpdatedReplicas < desired {
			// an ordered rolling update walks replicas one by one; give it time
			if hasRecentPod(byOwner[(ref{s.Namespace, "StatefulSet", s.Name}).ID()], now, 10*time.Minute) {
				continue
			}
		}
		emit(ref{s.Namespace, "StatefulSet", s.Name}, desired, s.Status.ReadyReplicas, time.Time{}, "")
	}
	dss, err := w.c.daemonSets(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range dss {
		desired := d.Status.DesiredNumberScheduled
		if desired == 0 || d.Status.NumberReady >= desired {
			continue
		}
		if hasRecentPod(byOwner[(ref{d.Namespace, "DaemonSet", d.Name}).ID()], now, 5*time.Minute) {
			continue
		}
		emit(ref{d.Namespace, "DaemonSet", d.Name}, desired, d.Status.NumberReady, time.Time{}, "")
	}
	return out, nil
}

func hasRecentPod(pods []corev1.Pod, now time.Time, within time.Duration) bool {
	for _, p := range pods {
		if now.Sub(p.CreationTimestamp.Time) < within {
			return true
		}
	}
	return false
}

// ---- restarts and out-of-memory kills ---------------------------------------------------

type restarts struct {
	c *Cluster
}

func (*restarts) Name() string  { return "restarts" }
func (*restarts) Metered() bool { return false }

const (
	restartWindow = time.Hour
	oomWindow     = 6 * time.Hour
)

type group struct {
	r        ref
	delta    int32
	known    bool
	crash    bool
	total    int32
	oldest   time.Time
	last     string
	lastAt   time.Time
	ooms     int
	oomLimit string
	oomAt    time.Time
	oomPods  int
}

func (r *restarts) record(key string, n int32, now time.Time) (delta int32, known bool) {
	c := r.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.restarts == nil {
		c.restarts = map[string][]restartPoint{}
	}
	var keep []restartPoint
	for _, p := range c.restarts[key] {
		if now.Sub(p.t) <= restartWindow+10*time.Minute {
			keep = append(keep, p)
		}
	}
	if len(keep) > 0 {
		delta, known = n-keep[0].n, true
		if delta < 0 {
			delta = 0
		}
	}
	c.restarts[key] = append(keep, restartPoint{now, n})
	return delta, known
}

func (r *restarts) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	now := r.c.now()
	pods, err := r.c.pods(ctx)
	if err != nil {
		return nil, err
	}
	own, err := r.c.owners(ctx)
	if err != nil {
		return nil, err
	}
	groups := map[string]*group{}
	seen := map[string]bool{}
	for i := range pods {
		p := &pods[i]
		ref := own.ofPod(p)
		g := groups[ref.ID()]
		if g == nil {
			g = &group{r: ref}
			groups[ref.ID()] = g
		}
		podAge := now.Sub(p.CreationTimestamp.Time)
		if g.oldest.IsZero() || podAge > now.Sub(g.oldest) {
			g.oldest = p.CreationTimestamp.Time
		}
		oomedHere := false
		for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
			key := string(p.UID) + "/" + cs.Name
			seen[key] = true
			d, known := r.record(key, cs.RestartCount, now)
			if known {
				g.known = true
				g.delta += d
			}
			if cs.RestartCount > g.total {
				g.total = cs.RestartCount
			}
			if w := cs.State.Waiting; w != nil && w.Reason == "CrashLoopBackOff" {
				g.crash = true
			}
			for _, t := range []*corev1.ContainerStateTerminated{cs.LastTerminationState.Terminated, cs.State.Terminated} {
				if t == nil {
					continue
				}
				if t.FinishedAt.Time.After(g.lastAt) {
					g.lastAt = t.FinishedAt.Time
					g.last = fmt.Sprintf("%s (%s, exit code %d)", cs.Name, t.Reason, t.ExitCode)
				}
				if t.Reason == "OOMKilled" && now.Sub(t.FinishedAt.Time) < oomWindow {
					g.ooms++
					oomedHere = true
					if t.FinishedAt.Time.After(g.oomAt) {
						g.oomAt = t.FinishedAt.Time
					}
					for _, c := range p.Spec.Containers {
						if c.Name == cs.Name {
							if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
								g.oomLimit = q.String()
							}
						}
					}
				}
			}
		}
		if oomedHere {
			g.oomPods++
		}
	}
	// forget pods that are gone
	r.c.mu.Lock()
	for k := range r.c.restarts {
		if !seen[k] {
			delete(r.c.restarts, k)
		}
	}
	r.c.mu.Unlock()

	var out []watch.Observation
	for _, g := range groups {
		if g.crash || (g.known && g.delta >= 3) {
			s := watch.SevWarn
			title := fmt.Sprintf("restarted %d times in the last hour", g.delta)
			if g.crash {
				s = watch.SevCrit
				title = "in a restart loop (CrashLoopBackOff)"
				if g.known && g.delta > 0 {
					title += fmt.Sprintf(", %d restarts in the last hour", g.delta)
				}
			} else if g.delta >= 10 {
				s = watch.SevCrit
			}
			ev := []string{fmt.Sprintf("%d restarts in total", g.total)}
			if g.last != "" {
				ev = append(ev, "last stop: "+g.last+", "+ago(now.Sub(g.lastAt))+" ago")
			}
			sig := watch.Signal{Kind: "k8s.restarting", NodeID: g.r.ID(), Severity: sev(g.r.NS, s), Title: title,
				Threshold: "3 or more restarts in an hour, or CrashLoopBackOff", Evidence: ev}
			// a pod that has crashed this many times over days is a known broken
			// thing, not a new fire; it is listed with the standing problems
			if g.crash && g.total >= 500 && now.Sub(g.oldest) > watch.ChronicAfter {
				sig.Chronic = true
				sig.Evidence = append(sig.Evidence, "it has been like this for "+ago(now.Sub(g.oldest)))
			}
			out = append(out, watch.Observation{Signal: sig})
		}
		if g.ooms > 0 {
			s := watch.SevWarn
			if g.ooms >= 3 {
				s = watch.SevCrit
			}
			ev := []string{}
			if g.oomLimit != "" {
				ev = append(ev, "memory limit "+g.oomLimit)
			}
			ev = append(ev, fmt.Sprintf("latest %s ago", ago(now.Sub(g.oomAt))))
			out = append(out, watch.Observation{Signal: watch.Signal{
				Kind: "k8s.oom-killed", NodeID: g.r.ID(), Severity: sev(g.r.NS, s),
				Title:     fmt.Sprintf("%d container(s) killed for running out of memory in the last %s", g.ooms, ago(oomWindow)),
				Threshold: "any OOM kill in the last 6 hours", Evidence: ev,
			}})
		}
	}
	return out, nil
}

// ---- nodes -----------------------------------------------------------------------------

type nodes struct{ c *Cluster }

func (*nodes) Name() string  { return "nodes" }
func (*nodes) Metered() bool { return false }

func (n *nodes) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	list, err := n.c.nodes(ctx)
	if err != nil {
		return nil, err
	}
	var out []watch.Observation
	cp, cpReady := 0, 0
	for _, nd := range list {
		_, isCP := nd.Labels["node-role.kubernetes.io/control-plane"]
		if isCP {
			cp++
		}
		ready := true
		var readyMsg string
		var since time.Time
		var pressure []string
		for _, c := range nd.Status.Conditions {
			switch c.Type {
			case corev1.NodeReady:
				if c.Status != corev1.ConditionTrue {
					ready, readyMsg, since = false, short(c.Message, 140), c.LastTransitionTime.Time
				}
			case corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure, corev1.NodeNetworkUnavailable:
				if c.Status == corev1.ConditionTrue {
					pressure = append(pressure, string(c.Type))
				}
			}
		}
		if isCP && ready {
			cpReady++
		}
		id := "node/" + nd.Name
		if !ready {
			out = append(out, watch.Observation{Signal: watch.Signal{
				Kind: "k8s.node-not-ready", NodeID: id, Severity: watch.SevCrit, Since: since,
				Title: "node is not ready", Threshold: "Ready condition is not True",
				Evidence: []string{readyMsg},
			}})
		}
		if len(pressure) > 0 {
			out = append(out, watch.Observation{Signal: watch.Signal{
				Kind: "k8s.node-pressure", NodeID: id, Severity: watch.SevWarn,
				Title: "node reports " + strings.Join(pressure, ", "), Threshold: "a pressure condition is True",
			}})
		}
		if nd.Spec.Unschedulable {
			var at time.Time
			for _, t := range nd.Spec.Taints {
				if t.Key == "node.kubernetes.io/unschedulable" && t.TimeAdded != nil {
					at = t.TimeAdded.Time
				}
			}
			out = append(out, watch.Observation{Signal: watch.Signal{
				Kind: "k8s.node-cordoned", NodeID: id, Severity: watch.SevWarn, Since: at,
				Title: "node is cordoned (no new pods are scheduled on it)", Threshold: "spec.unschedulable is true",
			}})
		}
	}
	if cp > 1 {
		quorum := cp/2 + 1
		if cpReady < quorum {
			out = append(out, watch.Observation{Signal: watch.Signal{
				Kind: "k8s.quorum-lost", NodeID: "", Severity: watch.SevCrit,
				Title:     fmt.Sprintf("control plane has lost quorum: %d of %d members ready, %d needed", cpReady, cp, quorum),
				Threshold: "ready control-plane nodes below a majority",
			}})
		} else if cpReady == quorum && cpReady < cp {
			out = append(out, watch.Observation{Signal: watch.Signal{
				Kind: "k8s.quorum-at-risk", NodeID: "", Severity: watch.SevWarn,
				Title:     fmt.Sprintf("control plane is one failure from losing quorum: %d of %d members ready", cpReady, cp),
				Threshold: "ready control-plane nodes equal a bare majority",
			}})
		}
	}
	return out, nil
}

// ---- services with nothing behind them ------------------------------------------------------

type services struct{ c *Cluster }

func (*services) Name() string  { return "services" }
func (*services) Metered() bool { return false }

func selects(sel map[string]string, labels map[string]string) bool {
	if len(sel) == 0 {
		return false
	}
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func (s *services) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	now := s.c.now()
	svcs, err := s.c.services(ctx)
	if err != nil {
		return nil, err
	}
	slices, err := s.c.slices(ctx)
	if err != nil {
		return nil, err
	}
	pods, err := s.c.pods(ctx)
	if err != nil {
		return nil, err
	}
	ings, err := s.c.ingresses(ctx)
	if err != nil {
		return nil, err
	}
	ready := map[string]int{}
	for _, sl := range slices {
		name := sl.Labels["kubernetes.io/service-name"]
		for _, e := range sl.Endpoints {
			if e.Conditions.Ready == nil || *e.Conditions.Ready {
				ready[sl.Namespace+"/"+name]++
			}
		}
	}
	exposed := map[string]bool{}
	for _, ing := range ings {
		if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
			exposed[ing.Namespace+"/"+ing.Spec.DefaultBackend.Service.Name] = true
		}
		for _, r := range ing.Spec.Rules {
			if r.HTTP == nil {
				continue
			}
			for _, p := range r.HTTP.Paths {
				if p.Backend.Service != nil {
					exposed[ing.Namespace+"/"+p.Backend.Service.Name] = true
				}
			}
		}
	}
	var out []watch.Observation
	for _, sv := range svcs {
		if sv.Spec.Type == corev1.ServiceTypeExternalName || len(sv.Spec.Selector) == 0 {
			continue
		}
		key := sv.Namespace + "/" + sv.Name
		if ready[key] > 0 {
			continue
		}
		var matched []corev1.Pod
		for _, p := range pods {
			if p.Namespace == sv.Namespace && selects(sv.Spec.Selector, p.Labels) && p.Status.Phase != corev1.PodSucceeded {
				matched = append(matched, p)
			}
		}
		public := exposed[key] || sv.Spec.Type == corev1.ServiceTypeLoadBalancer
		if len(matched) == 0 && !public {
			continue // nothing selected and nothing public: scaled to zero on purpose, most likely
		}
		sevr := watch.SevWarn
		if public {
			sevr = watch.SevCrit
		}
		title := fmt.Sprintf("no ready endpoints (%d pod(s) selected)", len(matched))
		if len(matched) == 0 {
			title = "no pods behind a service that is exposed to traffic"
		}
		// how long nothing has been ready: the age of the oldest pod behind it,
		// so a service in front of a workload that has been broken for months
		// is as old as the workload and joins it among the standing problems
		var since time.Time
		for _, p := range matched {
			if since.IsZero() || p.CreationTimestamp.Time.Before(since) {
				since = p.CreationTimestamp.Time
			}
		}
		ev := podReasons(matched, now)
		if public {
			ev = append(ev, "the service is reachable from outside the cluster")
		}
		out = append(out, watch.Observation{Signal: watch.Signal{
			Kind: "k8s.service-no-endpoints", NodeID: sv.Namespace + "/Service/" + sv.Name, Severity: sev(sv.Namespace, sevr),
			Since: since, Title: title, Threshold: "a service with a selector has no ready endpoint", Evidence: ev,
		}})
	}
	return out, nil
}

// ---- failed jobs ----------------------------------------------------------------------------

type jobsC struct{ c *Cluster }

func (*jobsC) Name() string         { return "jobs" }
func (*jobsC) Metered() bool        { return false }
func (*jobsC) Every() time.Duration { return time.Minute }

const jobWindow = 24 * time.Hour

func (j *jobsC) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	now := j.c.now()
	jobs, err := j.c.jobs(ctx)
	if err != nil {
		return nil, err
	}
	type agg struct {
		r       ref
		n       int
		reasons map[string]int
		latest  time.Time
	}
	groups := map[string]*agg{}
	for i := range jobs {
		jb := &jobs[i]
		for _, c := range jb.Status.Conditions {
			if c.Type == "Failed" && c.Status == corev1.ConditionTrue && now.Sub(c.LastTransitionTime.Time) < jobWindow {
				r := ref{jb.Namespace, "Jobs", "one-off jobs"}
				if ctl := metav1.GetControllerOf(jb); ctl != nil && ctl.Kind == "CronJob" {
					r = ref{jb.Namespace, "CronJob", ctl.Name}
				}
				g := groups[r.ID()]
				if g == nil {
					g = &agg{r: r, reasons: map[string]int{}}
					groups[r.ID()] = g
				}
				g.n++
				g.reasons[c.Reason]++
				if c.LastTransitionTime.Time.After(g.latest) {
					g.latest = c.LastTransitionTime.Time
				}
			}
		}
	}
	var out []watch.Observation
	for _, g := range groups {
		var reasons []string
		for r, n := range g.reasons {
			reasons = append(reasons, fmt.Sprintf("%d × %s", n, r))
		}
		sort.Strings(reasons)
		out = append(out, watch.Observation{Signal: watch.Signal{
			Kind: "k8s.jobs-failed", NodeID: g.r.ID(), Severity: sev(g.r.NS, watch.SevWarn),
			Title:     fmt.Sprintf("%d job(s) failed in the last 24 h", g.n),
			Threshold: "a Job reached the Failed condition", Evidence: append(reasons, "latest "+ago(now.Sub(g.latest))+" ago"),
		}})
	}
	return out, nil
}

// ---- storage and "cannot create" events -----------------------------------------------------

type storage struct{ c *Cluster }

func (*storage) Name() string         { return "storage" }
func (*storage) Metered() bool        { return false }
func (*storage) Every() time.Duration { return time.Minute }

var eventTitles = map[string]string{
	"FailedMount":        "a volume cannot be mounted",
	"FailedAttachVolume": "a volume cannot be attached",
	"ProvisioningFailed": "a volume cannot be provisioned",
	"FailedCreate":       "pods cannot be created",
}

func eventTime(e corev1.Event) time.Time {
	switch {
	case !e.LastTimestamp.IsZero():
		return e.LastTimestamp.Time
	case !e.EventTime.IsZero():
		return e.EventTime.Time
	}
	return e.CreationTimestamp.Time
}

func (s *storage) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	now := s.c.now()
	pvcs, err := s.c.pvcs(ctx)
	if err != nil {
		return nil, err
	}
	var out []watch.Observation
	for _, p := range pvcs {
		if p.Status.Phase == corev1.ClaimPending && now.Sub(p.CreationTimestamp.Time) > 5*time.Minute {
			out = append(out, watch.Observation{Signal: watch.Signal{
				Kind: "k8s.pvc-pending", NodeID: p.Namespace + "/PersistentVolumeClaim/" + p.Name, Severity: sev(p.Namespace, watch.SevWarn),
				Since: p.CreationTimestamp.Time, Title: "volume claim is still Pending", Threshold: "Pending for more than 5 minutes",
			}})
		}
	}
	events, err := s.c.warningEvents(ctx)
	if err != nil {
		return nil, err
	}
	pods, err := s.c.pods(ctx)
	if err != nil {
		return nil, err
	}
	own, err := s.c.owners(ctx)
	if err != nil {
		return nil, err
	}
	podByName := map[string]*corev1.Pod{}
	for i := range pods {
		podByName[pods[i].Namespace+"/"+pods[i].Name] = &pods[i]
	}
	type k struct{ id, reason string }
	type agg struct {
		ns, msg string
		n       int
		at      time.Time
	}
	groups := map[k]*agg{}
	for _, e := range events {
		if _, ok := eventTitles[e.Reason]; !ok || now.Sub(eventTime(e)) > 15*time.Minute {
			continue
		}
		id := e.InvolvedObject.Namespace + "/" + e.InvolvedObject.Kind + "/" + e.InvolvedObject.Name
		if e.InvolvedObject.Kind == "Pod" {
			if p, ok := podByName[e.InvolvedObject.Namespace+"/"+e.InvolvedObject.Name]; ok {
				id = own.ofPod(p).ID()
			}
		}
		key := k{id, e.Reason}
		g := groups[key]
		if g == nil {
			g = &agg{ns: e.InvolvedObject.Namespace, msg: short(e.Message, 180)}
			groups[key] = g
		}
		g.n++
		if t := eventTime(e); t.After(g.at) {
			g.at = t
		}
	}
	for key, g := range groups {
		out = append(out, watch.Observation{Signal: watch.Signal{
			Key: "storage|" + key.reason + "|" + key.id, Kind: "k8s." + strings.ToLower(key.reason), NodeID: key.id,
			Severity: sev(g.ns, watch.SevWarn), Title: eventTitles[key.reason],
			Threshold: key.reason + " events in the last 15 minutes", Evidence: []string{g.msg, "latest " + ago(now.Sub(g.at)) + " ago"},
		}})
	}
	return out, nil
}

// ---- autoscalers ----------------------------------------------------------------------------

type hpaC struct{ c *Cluster }

func (*hpaC) Name() string         { return "hpa" }
func (*hpaC) Metered() bool        { return false }
func (*hpaC) Every() time.Duration { return time.Minute }

func (h *hpaC) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	now := h.c.now()
	list, err := h.c.hpas(ctx)
	if err != nil {
		return nil, err
	}
	var out []watch.Observation
	for _, a := range list {
		target := a.Namespace + "/" + a.Spec.ScaleTargetRef.Kind + "/" + a.Spec.ScaleTargetRef.Name
		for _, c := range a.Status.Conditions {
			if (c.Type == "ScalingActive" || c.Type == "AbleToScale") && c.Status == corev1.ConditionFalse &&
				c.Reason != "ScalingDisabled" {
				out = append(out, watch.Observation{Signal: watch.Signal{
					Key: "hpa|" + a.Namespace + "/" + a.Name + "|" + string(c.Type), Kind: "k8s.hpa-cannot-scale", NodeID: target,
					Severity: sev(a.Namespace, watch.SevWarn), Since: c.LastTransitionTime.Time,
					Title:     "the autoscaler cannot scale this workload",
					Threshold: string(c.Type) + " is False", Evidence: []string{c.Reason + ": " + short(c.Message, 160)},
				}})
			}
		}
		if a.Status.CurrentReplicas >= a.Spec.MaxReplicas && a.Status.DesiredReplicas >= a.Spec.MaxReplicas && a.Spec.MaxReplicas > 0 {
			sig := watch.Signal{
				Key: "hpa|" + a.Namespace + "/" + a.Name + "|max", Kind: "k8s.hpa-at-max", NodeID: target,
				Severity: sev(a.Namespace, watch.SevWarn), Title: fmt.Sprintf("the autoscaler is at its maximum of %d replicas", a.Spec.MaxReplicas),
				Threshold: "current and desired replicas equal maxReplicas",
			}
			if a.Status.LastScaleTime != nil && now.Sub(a.Status.LastScaleTime.Time) > watch.ChronicAfter {
				sig.Chronic = true
			}
			out = append(out, watch.Observation{Signal: sig})
		}
	}
	return out, nil
}
