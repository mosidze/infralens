package k8swatch

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"infralens/internal/watch"
)

// Cluster is one connection plus short-lived caches, so seven collectors that
// all want the pod list cause one request, not seven.
type Cluster struct {
	Client kubernetes.Interface
	Now    func() time.Time

	mu       sync.Mutex
	cache    map[string]cached
	restarts map[string][]restartPoint
}

type cached struct {
	at   time.Time
	data any
}

type restartPoint struct {
	t time.Time
	n int32
}

const cacheTTL = 10 * time.Second

func (c *Cluster) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func fetch[T any](c *Cluster, name string, f func() ([]T, error)) ([]T, error) {
	c.mu.Lock()
	if v, ok := c.cache[name]; ok && c.now().Sub(v.at) < cacheTTL {
		c.mu.Unlock()
		return v.data.([]T), nil
	}
	c.mu.Unlock()
	data, err := f()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[string]cached{}
	}
	c.cache[name] = cached{c.now(), data}
	c.mu.Unlock()
	return data, nil
}

// all pages through a list call.
func all[T any, L any](ctx context.Context, list func(context.Context, metav1.ListOptions) (L, error), items func(L) []T, next func(L) string) ([]T, error) {
	var out []T
	opts := metav1.ListOptions{Limit: 500}
	for {
		l, err := list(ctx, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, items(l)...)
		if next(l) == "" {
			return out, nil
		}
		opts.Continue = next(l)
	}
}

func (c *Cluster) pods(ctx context.Context) ([]corev1.Pod, error) {
	return fetch(c, "pods", func() ([]corev1.Pod, error) {
		return all(ctx, c.Client.CoreV1().Pods("").List, func(l *corev1.PodList) []corev1.Pod { return l.Items }, func(l *corev1.PodList) string { return l.Continue })
	})
}
func (c *Cluster) replicaSets(ctx context.Context) ([]appsv1.ReplicaSet, error) {
	return fetch(c, "replicasets", func() ([]appsv1.ReplicaSet, error) {
		return all(ctx, c.Client.AppsV1().ReplicaSets("").List, func(l *appsv1.ReplicaSetList) []appsv1.ReplicaSet { return l.Items }, func(l *appsv1.ReplicaSetList) string { return l.Continue })
	})
}
func (c *Cluster) deployments(ctx context.Context) ([]appsv1.Deployment, error) {
	return fetch(c, "deployments", func() ([]appsv1.Deployment, error) {
		return all(ctx, c.Client.AppsV1().Deployments("").List, func(l *appsv1.DeploymentList) []appsv1.Deployment { return l.Items }, func(l *appsv1.DeploymentList) string { return l.Continue })
	})
}
func (c *Cluster) statefulSets(ctx context.Context) ([]appsv1.StatefulSet, error) {
	return fetch(c, "statefulsets", func() ([]appsv1.StatefulSet, error) {
		return all(ctx, c.Client.AppsV1().StatefulSets("").List, func(l *appsv1.StatefulSetList) []appsv1.StatefulSet { return l.Items }, func(l *appsv1.StatefulSetList) string { return l.Continue })
	})
}
func (c *Cluster) daemonSets(ctx context.Context) ([]appsv1.DaemonSet, error) {
	return fetch(c, "daemonsets", func() ([]appsv1.DaemonSet, error) {
		return all(ctx, c.Client.AppsV1().DaemonSets("").List, func(l *appsv1.DaemonSetList) []appsv1.DaemonSet { return l.Items }, func(l *appsv1.DaemonSetList) string { return l.Continue })
	})
}
func (c *Cluster) nodes(ctx context.Context) ([]corev1.Node, error) {
	return fetch(c, "nodes", func() ([]corev1.Node, error) {
		return all(ctx, c.Client.CoreV1().Nodes().List, func(l *corev1.NodeList) []corev1.Node { return l.Items }, func(l *corev1.NodeList) string { return l.Continue })
	})
}
func (c *Cluster) services(ctx context.Context) ([]corev1.Service, error) {
	return fetch(c, "services", func() ([]corev1.Service, error) {
		return all(ctx, c.Client.CoreV1().Services("").List, func(l *corev1.ServiceList) []corev1.Service { return l.Items }, func(l *corev1.ServiceList) string { return l.Continue })
	})
}
func (c *Cluster) slices(ctx context.Context) ([]discoveryv1.EndpointSlice, error) {
	return fetch(c, "endpointslices", func() ([]discoveryv1.EndpointSlice, error) {
		return all(ctx, c.Client.DiscoveryV1().EndpointSlices("").List, func(l *discoveryv1.EndpointSliceList) []discoveryv1.EndpointSlice { return l.Items }, func(l *discoveryv1.EndpointSliceList) string { return l.Continue })
	})
}
func (c *Cluster) ingresses(ctx context.Context) ([]networkingv1.Ingress, error) {
	return fetch(c, "ingresses", func() ([]networkingv1.Ingress, error) {
		return all(ctx, c.Client.NetworkingV1().Ingresses("").List, func(l *networkingv1.IngressList) []networkingv1.Ingress { return l.Items }, func(l *networkingv1.IngressList) string { return l.Continue })
	})
}
func (c *Cluster) jobs(ctx context.Context) ([]batchv1.Job, error) {
	return fetch(c, "jobs", func() ([]batchv1.Job, error) {
		return all(ctx, c.Client.BatchV1().Jobs("").List, func(l *batchv1.JobList) []batchv1.Job { return l.Items }, func(l *batchv1.JobList) string { return l.Continue })
	})
}
func (c *Cluster) cronJobs(ctx context.Context) ([]batchv1.CronJob, error) {
	return fetch(c, "cronjobs", func() ([]batchv1.CronJob, error) {
		return all(ctx, c.Client.BatchV1().CronJobs("").List, func(l *batchv1.CronJobList) []batchv1.CronJob { return l.Items }, func(l *batchv1.CronJobList) string { return l.Continue })
	})
}
func (c *Cluster) hpas(ctx context.Context) ([]autoscalingv2.HorizontalPodAutoscaler, error) {
	return fetch(c, "hpas", func() ([]autoscalingv2.HorizontalPodAutoscaler, error) {
		return all(ctx, c.Client.AutoscalingV2().HorizontalPodAutoscalers("").List, func(l *autoscalingv2.HorizontalPodAutoscalerList) []autoscalingv2.HorizontalPodAutoscaler {
			return l.Items
		}, func(l *autoscalingv2.HorizontalPodAutoscalerList) string { return l.Continue })
	})
}
func (c *Cluster) pvcs(ctx context.Context) ([]corev1.PersistentVolumeClaim, error) {
	return fetch(c, "pvcs", func() ([]corev1.PersistentVolumeClaim, error) {
		return all(ctx, c.Client.CoreV1().PersistentVolumeClaims("").List, func(l *corev1.PersistentVolumeClaimList) []corev1.PersistentVolumeClaim { return l.Items }, func(l *corev1.PersistentVolumeClaimList) string { return l.Continue })
	})
}
func (c *Cluster) warningEvents(ctx context.Context) ([]corev1.Event, error) {
	return fetch(c, "events", func() ([]corev1.Event, error) {
		return all(ctx, func(ctx context.Context, o metav1.ListOptions) (*corev1.EventList, error) {
			o.FieldSelector = "type=Warning"
			return c.Client.CoreV1().Events("").List(ctx, o)
		}, func(l *corev1.EventList) []corev1.Event { return l.Items }, func(l *corev1.EventList) string { return l.Continue })
	})
}

// ---- who owns what ------------------------------------------------------------------

// ref names the workload a pod belongs to. Judging at this level is what turns
// five hundred pods into a few dozen things.
type ref struct {
	NS, Kind, Name string
}

func (r ref) ID() string { return r.NS + "/" + r.Kind + "/" + r.Name }

// owner follows controller references: Pod -> ReplicaSet -> Deployment, a
// Job's pod -> its CronJob or the namespace's "Jobs" bucket. One-off Jobs are
// bucketed because every run has a new random name and would otherwise be
// hundreds of "workloads" that exist for minutes.
type owners struct {
	rs   map[string]ref // ns/name of ReplicaSet -> its Deployment
	jobs map[string]ref // ns/name of Job -> its CronJob
}

func (c *Cluster) owners(ctx context.Context) (*owners, error) {
	rss, err := c.replicaSets(ctx)
	if err != nil {
		return nil, err
	}
	jobs, err := c.jobs(ctx)
	if err != nil {
		return nil, err
	}
	o := &owners{rs: map[string]ref{}, jobs: map[string]ref{}}
	for _, r := range rss {
		if ctl := metav1.GetControllerOf(&r); ctl != nil && ctl.Kind == "Deployment" {
			o.rs[r.Namespace+"/"+r.Name] = ref{r.Namespace, "Deployment", ctl.Name}
		}
	}
	for _, j := range jobs {
		if ctl := metav1.GetControllerOf(&j); ctl != nil && ctl.Kind == "CronJob" {
			o.jobs[j.Namespace+"/"+j.Name] = ref{j.Namespace, "CronJob", ctl.Name}
		}
	}
	return o, nil
}

func (o *owners) ofPod(p *corev1.Pod) ref {
	ctl := metav1.GetControllerOf(p)
	if ctl == nil {
		return ref{p.Namespace, "Pod", p.Name}
	}
	switch ctl.Kind {
	case "ReplicaSet":
		if d, ok := o.rs[p.Namespace+"/"+ctl.Name]; ok {
			return d
		}
		return ref{p.Namespace, "ReplicaSet", ctl.Name}
	case "Job":
		if c, ok := o.jobs[p.Namespace+"/"+ctl.Name]; ok {
			return c
		}
		return ref{p.Namespace, "Jobs", "one-off jobs"}
	}
	return ref{p.Namespace, ctl.Kind, ctl.Name}
}

// ---- namespace classes ------------------------------------------------------------------

var nonProdSuffixes = []string{"-dev", "-staging", "-stage", "-test", "-sandbox", "-qa", "-preview"}

func isSystem(ns string) bool {
	switch ns {
	case "kube-system", "ingress-nginx", "cert-manager", "calico-system", "tigera-operator", "metallb-system", "kube-public":
		return true
	}
	return strings.HasPrefix(ns, "kube-")
}

func isNonProd(ns string) bool {
	for _, s := range nonProdSuffixes {
		if strings.HasSuffix(ns, s) {
			return true
		}
	}
	return false
}

// sev bends a base severity by where the problem is: the cluster's own
// plumbing is always critical, and a staging namespace never wakes anybody.
func sev(ns string, base watch.Severity) watch.Severity {
	switch {
	case isSystem(ns):
		return watch.SevCrit
	case isNonProd(ns) && base == watch.SevCrit:
		return watch.SevWarn
	}
	return base
}

func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "moments"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

func topLines(count map[string]int, n int) []string {
	type kv struct {
		k string
		n int
	}
	var l []kv
	for k, v := range count {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].n != l[j].n {
			return l[i].n > l[j].n
		}
		return l[i].k < l[j].k
	})
	var out []string
	for i, x := range l {
		if i == n {
			break
		}
		out = append(out, fmt.Sprintf("%d pod(s): %s", x.n, x.k))
	}
	return out
}

func short(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}
