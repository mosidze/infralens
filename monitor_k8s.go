package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"infralens/internal/app"
	"infralens/internal/engine"
	"infralens/internal/k8swatch"
	"infralens/internal/watch"
)

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

func k8sContexts(kubeconfig string) ([]string, error) {
	return k8swatch.Contexts(expandHome(kubeconfig))
}

// startK8sMonitor watches one cluster context, read-only. The cluster is its
// own map: nothing has to be scanned first.
func startK8sMonitor(ctx context.Context, base string, spec app.MonitorSpec) (app.LiveSource, error) {
	conn, err := k8swatch.Connect(expandHome(spec.Kubeconfig), spec.Name)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to context %q: %w", spec.Name, err)
	}
	cl := &k8swatch.Cluster{Client: conn.Client}
	probe, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := k8swatch.BuildGraph(probe, cl)
	if err != nil {
		return nil, fmt.Errorf("cannot read the cluster %q: %w", spec.Name, err)
	}
	g := watch.NewGraph(res)
	tr := watch.NewTracker(3, 2)
	tr.SetNeed("nodes", 2)
	notesPath := filepath.Join(base, "context.json")
	r := &watch.Runner{
		Collectors: k8swatch.Collectors(cl),
		Tracker:    tr,
		Graph:      g,
		Interval:   30 * time.Second,
		Notes: func() engine.Context {
			c, _ := engine.LoadContext(notesPath)
			return c
		},
		Account: conn.Server,
		Profile: spec.Name,
		Kind:    "k8s",
		Stats:   conn.Counter.Counts,
	}
	go k8swatch.KeepGraphFresh(ctx, cl, g, 5*time.Minute)
	go r.Run(ctx)
	return r, nil
}
