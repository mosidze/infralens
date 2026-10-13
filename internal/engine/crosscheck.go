package engine

import (
	"fmt"
	"strings"
)

// CrossCheck compares what an AWS-native service claims with what this tool
// knows about the same resources, and records the difference. It never
// removes a finding: it adds evidence and, where the claim is contradicted
// by facts the tool holds, lowers the severity and says why.
func CrossCheck(res *ScanResult) {
	byID := map[string]ResourceNode{}
	for _, n := range res.Nodes {
		byID[n.ID] = n
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.Source != "trusted-advisor" || !strings.Contains(strings.ToLower(f.Title), "idle db instances") {
			continue
		}
		var readers, known int
		for _, id := range f.Resources {
			n, ok := byID[id]
			if !ok || n.Type != "aws_rds_instance" {
				continue
			}
			known++
			if n.Attrs["role"] == "reader" {
				readers++
			}
		}
		if known == 0 {
			continue
		}
		msg := fmt.Sprintf("InfraLens cross-check: %d of the %d flagged instances are Aurora readers (failover standbys, idle by design)", readers, known)
		if !containsStr(f.Evidence, msg) {
			f.Evidence = append(f.Evidence, msg)
		}
		if readers == known && f.Severity.Rank() < SevLow.Rank() {
			f.Severity = SevLow
			f.Evidence = append(f.Evidence, "severity lowered: the claim is contradicted by cluster membership; verify the writer instead")
		}
	}
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
