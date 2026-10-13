// Package importer reads the output of other audit tools into findings, so a
// report can show what they found next to what this tool found, with the
// source named. Nothing here re-implements their checks.
package importer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"infralens/internal/engine"
)

const maxProwlerBytes = 256 << 20

// prowlerRecord covers Prowler 4/5 (OCSF) and the older Prowler 3 layout.
type prowlerRecord struct {
	// OCSF
	StatusCode  string `json:"status_code"`
	Severity    string `json:"severity"`
	FindingInfo struct {
		UID   string `json:"uid"`
		Title string `json:"title"`
		Desc  string `json:"desc"`
	} `json:"finding_info"`
	Resources []struct {
		UID    string `json:"uid"`
		Name   string `json:"name"`
		Region string `json:"region"`
		Type   string `json:"type"`
	} `json:"resources"`
	Cloud struct {
		Region  string `json:"region"`
		Account struct {
			UID string `json:"uid"`
		} `json:"account"`
	} `json:"cloud"`
	Remediation struct {
		Desc string `json:"desc"`
	} `json:"remediation"`
	Metadata struct {
		EventCode string `json:"event_code"`
	} `json:"metadata"`

	// Prowler 3
	Status        string `json:"Status"`
	SeverityV3    string `json:"Severity"`
	CheckID       string `json:"CheckID"`
	CheckTitle    string `json:"CheckTitle"`
	ResourceID    string `json:"ResourceId"`
	RegionV3      string `json:"Region"`
	RemediationV3 struct {
		Recommendation struct {
			Text string `json:"Text"`
		} `json:"Recommendation"`
	} `json:"Remediation"`
}

func (r prowlerRecord) normalized() (check, title, status, sev, resource, region, rec string) {
	check = firstNonEmpty(r.Metadata.EventCode, r.CheckID, r.FindingInfo.UID)
	title = firstNonEmpty(r.FindingInfo.Title, r.CheckTitle)
	status = strings.ToUpper(firstNonEmpty(r.StatusCode, r.Status))
	sev = strings.ToLower(firstNonEmpty(r.Severity, r.SeverityV3))
	region = firstNonEmpty(r.Cloud.Region, r.RegionV3)
	rec = firstNonEmpty(r.Remediation.Desc, r.RemediationV3.Recommendation.Text)
	if len(r.Resources) > 0 {
		resource = firstNonEmpty(r.Resources[0].UID, r.Resources[0].Name)
		region = firstNonEmpty(r.Resources[0].Region, region)
	}
	resource = firstNonEmpty(resource, r.ResourceID)
	return
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func prowlerSeverity(s string) engine.Severity {
	switch s {
	case "critical":
		return engine.SevCritical
	case "high":
		return engine.SevHigh
	case "medium":
		return engine.SevMedium
	case "low":
		return engine.SevLow
	}
	return engine.SevInfo
}

// ParseProwler reads a Prowler JSON output (an array, or one record per line)
// and returns failed checks grouped by check id.
func ParseProwler(r io.Reader) ([]engine.Finding, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxProwlerBytes))
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("empty file")
	}
	var recs []prowlerRecord
	switch data[0] {
	case '[':
		if err := json.Unmarshal(data, &recs); err != nil {
			return nil, fmt.Errorf("not a Prowler JSON array: %w", err)
		}
	case '{':
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var rec prowlerRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				return nil, fmt.Errorf("not Prowler JSON lines: %w", err)
			}
			recs = append(recs, rec)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("not JSON")
	}

	type group struct {
		f engine.Finding
		n int
	}
	groups := map[string]*group{}
	var order []string
	for _, rec := range recs {
		check, title, status, sev, resource, region, remediation := rec.normalized()
		if status != "FAIL" || check == "" {
			continue
		}
		g := groups[check]
		if g == nil {
			g = &group{f: engine.Finding{
				Pillar: engine.PillarSecurity, Source: "prowler", Rule: "prowler." + check, Severity: prowlerSeverity(sev),
				Title: firstNonEmpty(title, check), Reference: check, Confidence: engine.ConfHigh, Region: region,
				Recommendation: truncate(remediation, 400),
			}}
			groups[check] = g
			order = append(order, check)
		}
		g.n++
		if resource != "" && len(g.f.Resources) < 40 {
			g.f.Resources = append(g.f.Resources, resource)
		}
	}
	var out []engine.Finding
	for _, k := range order {
		g := groups[k]
		g.f.Affected = g.n
		if len(g.f.Resources) > 0 {
			g.f.ResourceID = g.f.Resources[0]
		} else {
			g.f.ResourceID = "check:" + k
		}
		g.f.Evidence = []string{fmt.Sprintf("Prowler: %d failing resource(s) for check %s", g.n, k)}
		g.f.ID = engine.FindingID(g.f.Source, g.f.Rule, "")
		out = append(out, g.f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() < out[j].Severity.Rank()
		}
		return out[i].Affected > out[j].Affected
	})
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
