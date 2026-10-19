package watch

import (
	"sort"
	"strings"

	"infralens/internal/engine"
)

// Graph is the part of a scan the live screen needs: what a resource is, who
// owns it, what it costs and what it is connected to.
type Graph struct {
	nodes  map[string]engine.ResourceNode
	byName map[string]string
	adj    map[string][]string
}

func NewGraph(res engine.ScanResult) *Graph {
	g := &Graph{nodes: map[string]engine.ResourceNode{}, byName: map[string]string{}, adj: map[string][]string{}}
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
	return g
}

func (g *Graph) Node(id string) (engine.ResourceNode, bool) {
	n, ok := g.nodes[id]
	return n, ok
}

// Resolve finds a node by id, ARN or name. Collectors know a resource by
// whatever the API calls it.
func (g *Graph) Resolve(ref string) (string, bool) {
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

func (g *Graph) neighbors(id string) []string { return g.adj[id] }

func kindOf(t string) string { return strings.ReplaceAll(strings.TrimPrefix(t, "aws_"), "_", " ") }

// connected summarises the neighbours of a node by kind, never by name, and
// says nothing about direction: the scan records that two things are
// connected, not which one needs the other.
func (g *Graph) connected(id string) (int, []string) {
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
