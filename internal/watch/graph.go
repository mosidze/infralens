package watch

import (
	"sort"
	"strings"
	"sync"

	"infralens/internal/engine"
)

// Graph is the part of a scan the live screen needs: what a resource is, who
// owns it, what it costs and what it is connected to.
type Graph struct {
	mu     sync.RWMutex
	nodes  map[string]engine.ResourceNode
	byName map[string]string
	adj    map[string][]string
}

func NewGraph(res engine.ScanResult) *Graph {
	g := &Graph{}
	g.Reset(res)
	return g
}

// Reset replaces what the graph knows. A Kubernetes monitor does this every
// few minutes because workloads come and go; an AWS monitor never does.
func (g *Graph) Reset(res engine.ScanResult) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes, g.byName, g.adj = map[string]engine.ResourceNode{}, map[string]string{}, map[string][]string{}
	for _, n := range res.Nodes {
		g.nodes[n.ID] = n
		if n.Name != "" {
			if _, dup := g.byName[n.Name]; !dup {
				g.byName[n.Name] = n.ID
			}
		}
	}
	for _, e := range res.Edges {
		if _, ok := g.nodes[e.Source]; !ok {
			continue
		}
		if _, ok := g.nodes[e.Target]; !ok {
			continue
		}
		g.adj[e.Source] = append(g.adj[e.Source], e.Target)
		g.adj[e.Target] = append(g.adj[e.Target], e.Source)
	}
}

func (g *Graph) Node(id string) (engine.ResourceNode, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// Resolve finds a node by id, ARN or name. Collectors know a resource by
// whatever the API calls it.
func (g *Graph) Resolve(ref string) (string, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if _, ok := g.nodes[ref]; ok {
		return ref, true
	}
	if id, ok := g.byName[ref]; ok {
		return id, true
	}
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		if id, ok := g.byName[ref[i+1:]]; ok {
			return id, true
		}
	}
	return "", false
}

// Regions lists the regions the scan found something in, so the monitor only
// asks about places that have something to look at. With node types given it
// narrows to regions that hold at least one of them: there is no point asking
// every region whether its ECS services are running when only one has any.
func (g *Graph) Regions(nodeTypes ...string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	want := map[string]bool{}
	for _, t := range nodeTypes {
		want[t] = true
	}
	set := map[string]bool{}
	for _, n := range g.nodes {
		if n.Region == "" || n.Region == "global" {
			continue
		}
		if len(want) > 0 && !want[n.Type] {
			continue
		}
		set[n.Region] = true
	}
	var out []string
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func (g *Graph) neighbors(id string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return append([]string(nil), g.adj[id]...)
}

func kindOf(t string) string {
	t = strings.TrimPrefix(strings.TrimPrefix(t, "aws_"), "k8s_")
	return strings.ReplaceAll(t, "_", " ")
}

// connected summarises the neighbours of a node by kind, never by name, and
// says nothing about direction: the scan records that two things are
// connected, not which one needs the other.
func (g *Graph) connected(id string) (int, []string) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	count := map[string]int{}
	seen := map[string]bool{}
	for _, nb := range g.adj[id] {
		if seen[nb] {
			continue
		}
		seen[nb] = true
		count[kindOf(g.nodes[nb].Type)]++
	}
	var kinds []string
	for k, v := range count {
		kinds = append(kinds, k+" ×"+itoa(v))
	}
	sort.Strings(kinds)
	return len(seen), kinds
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
