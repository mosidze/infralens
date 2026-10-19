package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"time"
)

// Context is what the owner knows and the tool cannot: planned migrations,
// intentionally idle resources. It changes how findings are presented and
// counted, never what is detected.
type Context struct {
	Notes []ContextNote `json:"notes"`
}

// ContextNote acknowledges findings that match. All given match fields must match.
type ContextNote struct {
	Match struct {
		ID      string `json:"id,omitempty"`      // exact resource/commitment id
		Name    string `json:"name,omitempty"`    // glob, e.g. "acme-feed-*"
		Type    string `json:"type,omitempty"`    // node type, e.g. aws_kinesis_stream
		Service string `json:"service,omitempty"` // Cost Explorer service, for commitments
		Region  string `json:"region,omitempty"`
		Rule    string `json:"rule,omitempty"`    // finding rule id, e.g. cost.idle.kinesis-stream
		Finding string `json:"finding,omitempty"` // finding id
	} `json:"match"`
	Note  string `json:"note"`
	Until string `json:"until,omitempty"` // YYYY-MM-DD; after this date the note no longer applies
}

// LoadContext reads a context file. Unknown keys are an error so a typo does
// not silently leave a finding un-acknowledged.
func LoadContext(path string) (Context, error) {
	var c Context
	if path == "" {
		return c, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	for i, n := range c.Notes {
		m := n.Match
		if m.ID == "" && m.Name == "" && m.Type == "" && m.Service == "" && m.Region == "" && m.Rule == "" && m.Finding == "" {
			return c, fmt.Errorf("%s: note %d has an empty match, it would apply to everything", path, i+1)
		}
		if n.Note == "" {
			return c, fmt.Errorf("%s: note %d has no text; say why the finding is expected", path, i+1)
		}
		if n.Until != "" {
			if _, err := time.Parse("2006-01-02", n.Until); err != nil {
				return c, fmt.Errorf("%s: note %d: until must be YYYY-MM-DD", path, i+1)
			}
		}
	}
	return c, nil
}

func (n ContextNote) live(now time.Time) bool {
	if n.Until == "" {
		return true
	}
	d, err := time.Parse("2006-01-02", n.Until)
	return err == nil && !now.After(d.Add(24*time.Hour))
}

func (n ContextNote) matches(id, name, typ, service, region string) bool {
	m := n.Match
	if m.ID != "" && m.ID != id {
		return false
	}
	if m.Type != "" && m.Type != typ {
		return false
	}
	if m.Service != "" && m.Service != service {
		return false
	}
	if m.Region != "" && m.Region != region {
		return false
	}
	if m.Name != "" {
		if ok, _ := path.Match(strings.ToLower(m.Name), strings.ToLower(name)); !ok {
			return false
		}
	}
	return true
}

// Apply attaches matching notes to resources and commitments and returns
// warnings for notes that matched nothing or have lapsed, so a stale note
// does not hide a finding without anyone noticing.
func (c Context) Apply(res *ScanResult, now time.Time) []string {
	var warn []string
	hits := make([]int, len(c.Notes))
	for i := range res.Nodes {
		n := &res.Nodes[i]
		for j, note := range c.Notes {
			if !note.live(now) || !note.matches(n.ID, n.Name, n.Type, res.TypeServices[n.Type], n.Region) {
				continue
			}
			n.Ack = &Ack{Note: note.Note, Until: note.Until}
			hits[j]++
			break
		}
	}
	for i := range res.Commitments {
		cm := &res.Commitments[i]
		for j, note := range c.Notes {
			if note.Match.Type != "" || !note.live(now) || !note.matches(cm.ID, cm.ID, "", cm.Service, cm.Region) {
				continue
			}
			cm.Ack = &Ack{Note: note.Note, Until: note.Until}
			hits[j]++
			break
		}
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		for j, note := range c.Notes {
			m := note.Match
			if !note.live(now) || (m.Rule == "" && m.Finding == "") {
				continue
			}
			if (m.Rule != "" && m.Rule != f.Rule) || (m.Finding != "" && m.Finding != f.ID) {
				continue
			}
			if m.Region != "" && m.Region != f.Region {
				continue
			}
			f.Ack = &Ack{Note: note.Note, Until: note.Until}
			hits[j]++
			break
		}
	}
	for j, note := range c.Notes {
		switch {
		case !note.live(now):
			warn = append(warn, fmt.Sprintf("context note %d (%q) expired on %s; the finding it covered is shown again", j+1, note.Note, note.Until))
		case hits[j] == 0:
			warn = append(warn, fmt.Sprintf("context note %d (%q) matched nothing in this scan", j+1, note.Note))
		}
	}
	return warn
}

// SuppressesLive reports whether an owner note silences a live problem. Only
// notes that name a rule beginning with "live." count: a note written to
// explain an audit finding ("idle by design") must not hide a real outage.
func (c Context) SuppressesLive(id, name, typ, region, rule string, now time.Time) (string, bool) {
	for _, n := range c.Notes {
		m := n.Match
		if !strings.HasPrefix(m.Rule, "live.") || m.Rule != "live."+rule || !n.live(now) {
			continue
		}
		if n.matches(id, name, typ, "", region) {
			return n.Note, true
		}
	}
	return "", false
}
