package k8swatch

import (
	"context"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"

	"infralens/internal/engine"
	"infralens/internal/watch"
)

func ownerLabel(labels map[string]string) string {
	for _, k := range []string{"app.kubernetes.io/part-of", "team", "owner"} {
		if v := labels[k]; v != "" {
			return v
		}
	}
	return ""
}

// BuildGraph describes the cluster the way a scan describes an AWS account:
// what exists and what is connected to what. The monitor uses it to group
// problems into incidents and to say what is connected to a sick workload.
func BuildGraph(ctx context.Context, c *Cluster) (engine.ScanResult, error) {
	var res engine.ScanResult
	add := func(r ref, typ, owner string) {
		res.Nodes = append(res.Nodes, engine.ResourceNode{ID: r.ID(), Name: r.Name, Type: typ, Region: r.NS, Owner: owner})
	}
	deps, err := c.deployments(ctx)
	if err != nil {
		return res, err
	}
	for _, d := range deps {
		add(ref{d.Namespace, "Deployment", d.Name}, "k8s_deployment", ownerLabel(d.Labels))
	}
	sts, err := c.statefulSets(ctx)
	if err != nil {
		return res, err
	}
	for _, s := range sts {
		add(ref{s.Namespace, "StatefulSet", s.Name}, "k8s_statefulset", ownerLabel(s.Labels))
	}
	dss, err := c.daemonSets(ctx)
	if err != nil {
		return res, err
	}
	for _, d := range dss {
		add(ref{d.Namespace, "DaemonSet", d.Name}, "k8s_daemonset", ownerLabel(d.Labels))
	}
	crons, err := c.cronJobs(ctx)
	if err != nil {
		return res, err
	}
	for _, j := range crons {
		add(ref{j.Namespace, "CronJob", j.Name}, "k8s_cronjob", ownerLabel(j.Labels))
	}
	jobs, err := c.jobs(ctx)
	if err != nil {
		return res, err
	}
	jobNS := map[string]bool{}
	for _, j := range jobs {
		jobNS[j.Namespace] = true
	}
	for ns := range jobNS {
		add(ref{ns, "Jobs", "one-off jobs"}, "k8s_jobs", "")
	}
	nodes, err := c.nodes(ctx)
	if err != nil {
		return res, err
	}
	for _, n := range nodes {
		res.Nodes = append(res.Nodes, engine.ResourceNode{ID: "node/" + n.Name, Name: n.Name, Type: "k8s_node", Region: "cluster"})
	}
	svcs, err := c.services(ctx)
	if err != nil {
		return res, err
	}
	pods, err := c.pods(ctx)
	if err != nil {
		return res, err
	}
	own, err := c.owners(ctx)
	if err != nil {
		return res, err
	}
	for _, s := range svcs {
		r := ref{s.Namespace, "Service", s.Name}
		add(r, "k8s_service", ownerLabel(s.Labels))
		seen := map[string]bool{}
		for i := range pods {
			p := &pods[i]
			if p.Namespace != s.Namespace || !selects(s.Spec.Selector, p.Labels) || p.Status.Phase == corev1.PodSucceeded {
				continue
			}
			o := own.ofPod(p)
			if o.Kind == "Jobs" || seen[o.ID()] {
				continue
			}
			seen[o.ID()] = true
			res.Edges = append(res.Edges, engine.Edge{Source: r.ID(), Target: o.ID(), Label: "selects"})
		}
	}
	ings, err := c.ingresses(ctx)
	if err != nil {
		return res, err
	}
	for _, ing := range ings {
		ir := ref{ing.Namespace, "Ingress", ing.Name}
		add(ir, "k8s_ingress", ownerLabel(ing.Labels))
		backends := map[string]bool{}
		if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
			backends[ing.Spec.DefaultBackend.Service.Name] = true
		}
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP != nil {
				for _, p := range rule.HTTP.Paths {
					if p.Backend.Service != nil {
						backends[p.Backend.Service.Name] = true
					}
				}
			}
		}
		var names []string
		for n := range backends {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			res.Edges = append(res.Edges, engine.Edge{Source: ir.ID(), Target: ing.Namespace + "/Service/" + n, Label: "routes to"})
		}
	}
	hpas, err := c.hpas(ctx)
	if err != nil {
		return res, err
	}
	for _, a := range hpas {
		res.Edges = append(res.Edges, engine.Edge{
			Source: a.Namespace + "/HorizontalPodAutoscaler/" + a.Name,
			Target: a.Namespace + "/" + a.Spec.ScaleTargetRef.Kind + "/" + a.Spec.ScaleTargetRef.Name, Label: "scales"})
		add(ref{a.Namespace, "HorizontalPodAutoscaler", a.Name}, "k8s_hpa", "")
	}
	return res, nil
}

// KeepGraphFresh rebuilds the graph every few minutes: workloads come and go.
func KeepGraphFresh(ctx context.Context, c *Cluster, g *watch.Graph, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if res, err := BuildGraph(ctx, c); err == nil {
				g.Reset(res)
			}
		}
	}
}
