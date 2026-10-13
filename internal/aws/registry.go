package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Scanner is one self-describing inventory/waste check. Adding a service
// means adding a file that calls register in init(); nothing else changes.
type Scanner struct {
	// Name is the user-facing id used by --services / --skip.
	Name string
	Desc string
	// Types maps every node type the scanner emits to the Cost Explorer
	// service it bills under. It drives the coverage report.
	Types map[string]string
	// Informational scanners emit commitments/facts, not resource nodes, and
	// therefore need no Types.
	Informational bool
	// Regional runs once per region. Exactly one of Regional and Global is set.
	Regional func(ctx context.Context, cfg aws.Config, c *collector)
	// Global runs once per account (e.g. S3 bucket listing).
	Global func(ctx context.Context, dc *DiscoveryClient, c *collector)
}

var registry []Scanner

func register(s Scanner) {
	if s.Name == "" || (s.Regional == nil) == (s.Global == nil) || (len(s.Types) == 0 && !s.Informational) {
		panic(fmt.Sprintf("invalid scanner %+v", s.Name))
	}
	for _, r := range registry {
		if r.Name == s.Name {
			panic("duplicate scanner " + s.Name)
		}
	}
	registry = append(registry, s)
	sort.Slice(registry, func(i, j int) bool { return registry[i].Name < registry[j].Name })
}

// Scanners returns every registered scanner, sorted by name.
func Scanners() []Scanner { return append([]Scanner(nil), registry...) }

// SelectScanners applies --services (only) and --skip. Unknown names are an
// error: silently ignoring a typo would report a scan that never ran.
func SelectScanners(only, skip []string) ([]Scanner, error) {
	known := map[string]bool{}
	for _, s := range registry {
		known[s.Name] = true
	}
	for _, n := range append(append([]string{}, only...), skip...) {
		if !known[n] {
			names := make([]string, 0, len(registry))
			for _, s := range registry {
				names = append(names, s.Name)
			}
			return nil, fmt.Errorf("unknown service %q (available: %s)", n, strings.Join(names, ", "))
		}
	}
	has := func(list []string, n string) bool {
		for _, x := range list {
			if x == n {
				return true
			}
		}
		return false
	}
	var out []Scanner
	for _, s := range registry {
		if len(only) > 0 && !has(only, s.Name) {
			continue
		}
		if has(skip, s.Name) {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no scanners selected")
	}
	return out, nil
}

// CostServiceMap is node type -> Cost Explorer service for the given scanners.
func CostServiceMap(ss []Scanner) map[string]string {
	m := map[string]string{}
	for _, s := range ss {
		for t, svc := range s.Types {
			m[t] = svc
		}
	}
	return m
}
