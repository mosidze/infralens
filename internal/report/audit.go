package report

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	awsDiscovery "infralens/internal/aws"
	"infralens/internal/engine"
	"infralens/internal/llm"
)

//go:embed audit.html
var auditTemplate string

// AIReading is optional model-written prose shown in the document, clearly
// marked as such. Its numbers and finding ids were validated against the scan.
type AIReading struct {
	Model      string
	Narrative  llm.Narrative
	DroppedAny int
}

// AuditOptions describe who the document is for and from whom.
type AuditOptions struct {
	Client     string
	Consultant string
	// Anonymize replaces names, IDs and the account number with stable aliases
	// so the document can be shared outside the engagement.
	Anonymize bool
	// LogoDataURI is an optional embedded logo (see LogoFromBytes).
	LogoDataURI string
	Version     string
	Now         time.Time
	AI          *AIReading
}

// LogoFromBytes validates a logo and returns it as a data URI. Only PNG, JPEG
// and SVG up to 256 KiB are accepted; the document must stay self-contained
// and must not smuggle other content in.
func LogoFromBytes(b []byte) (string, error) {
	if len(b) == 0 || len(b) > 256<<10 {
		return "", fmt.Errorf("logo must be 1 byte to 256 KiB, got %d bytes", len(b))
	}
	mime := http.DetectContentType(b)
	if strings.HasPrefix(strings.TrimSpace(string(b[:min(len(b), 512)])), "<") && strings.Contains(string(b), "<svg") {
		mime = "image/svg+xml"
		if strings.Contains(strings.ToLower(string(b)), "<script") {
			return "", fmt.Errorf("svg logo must not contain scripts")
		}
	}
	switch mime {
	case "image/png", "image/jpeg", "image/svg+xml":
	default:
		return "", fmt.Errorf("logo must be PNG, JPEG or SVG, got %s", mime)
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(b), nil
}

// ---- anonymisation -----------------------------------------------------------

type anonymizer struct {
	on     bool
	alias  map[string]string
	counts map[string]int
	known  []string // real strings to scrub from free text, longest first
}

func newAnonymizer(on bool, res engine.ScanResult) *anonymizer {
	a := &anonymizer{on: on, alias: map[string]string{}, counts: map[string]int{}}
	if !on {
		return a
	}
	for _, n := range res.Nodes {
		a.name(n.ID, n.Type)
		if n.Name != "" && n.Name != n.ID {
			a.alias[n.Name] = a.alias[n.ID]
			a.known = append(a.known, n.Name)
		}
		a.known = append(a.known, n.ID)
		if n.VPCID != "" {
			a.name(n.VPCID, "vpc")
			a.known = append(a.known, n.VPCID)
		}
	}
	for _, c := range res.Commitments {
		if c.ID != "" {
			a.name(c.ID, c.Kind)
			a.known = append(a.known, c.ID)
		}
	}
	for _, n := range res.Nodes {
		if n.IaC != nil {
			for _, s := range []string{n.IaC.Origin, n.IaC.Address, n.IaC.Module} {
				if len(s) > 3 {
					a.name(s, "iac")
					a.known = append(a.known, s)
				}
			}
		}
		if len(n.Owner) > 3 {
			a.name(n.Owner, "owner")
			a.known = append(a.known, n.Owner)
		}
	}
	if res.Account != "" {
		a.alias[res.Account] = "ACCOUNT"
		a.known = append(a.known, res.Account)
	}
	sort.Slice(a.known, func(i, j int) bool { return len(a.known[i]) > len(a.known[j]) })
	return a
}

func (a *anonymizer) name(real, kind string) string {
	if real == "" {
		return ""
	}
	if v, ok := a.alias[real]; ok {
		return v
	}
	k := strings.ReplaceAll(strings.TrimPrefix(kind, "aws_"), "_", "-")
	a.counts[k]++
	v := fmt.Sprintf("%s-%03d", k, a.counts[k])
	a.alias[real] = v
	return v
}

var (
	reAccountID = regexp.MustCompile(`\b\d{12}\b`)
	reLongHex   = regexp.MustCompile(`\b[0-9a-f]{12,}\b`)
)

// scrub removes known real identifiers from free text, and then anything that
// has the shape of an account number or an opaque AWS identifier, so a name
// the scan did not know about still does not get through in an ARN or a note.
func (a *anonymizer) scrub(s string) string {
	if !a.on {
		return s
	}
	for _, k := range a.known {
		if k != "" && strings.Contains(s, k) {
			s = strings.ReplaceAll(s, k, a.alias[k])
		}
	}
	s = reAccountID.ReplaceAllString(s, "ACCOUNT")
	return reLongHex.ReplaceAllString(s, "[id]")
}

func (a *anonymizer) label(n engine.ResourceNode) string {
	if !a.on {
		if n.Name != "" {
			return n.Name
		}
		return n.ID
	}
	return a.alias[n.ID]
}

// ---- view model --------------------------------------------------------------

type findingView struct {
	Name, Type, Region, Reason, Confidence, Cost string
	CostValue                                    float64
	Evidence                                     []string
	Note                                         string // owner acknowledgement
}

// verifyView lists, once per resource type, what its check cannot see.
type verifyView struct {
	Type  string
	Items []string
}

type commitView struct {
	Service, Detail, State, Ends string
	Facts, Suggestions           []string
	Note                         string
}

type serviceView struct {
	Name    string
	Billed  string
	Scanned bool
}

type countView struct {
	Label string
	N     int
}

type auditView struct {
	Client, Consultant, Version, Generated string
	Logo                                   template.URL
	Account, Scope                         string
	Headline                               []string
	Resources, Regions                     int
	EstCost, WasteCost, Coverage           string
	WasteCount, ShadowCount, AckedCount    int
	DecisionCount                          int
	High, Medium, Low                      []findingView
	VerifyByType                           []verifyView
	WasteCountsByConf                      [3]int
	Shadow                                 []findingView
	ShadowMore                             int
	Acked                                  []findingView
	Decisions                              []commitView
	OtherCommitments                       []commitView
	Services                               []serviceView
	BilledTotal, ScannedPct, ExplainedPct  string
	NotChecked                             []string
	Warnings                               []string
	Skipped                                []string
	Checks                                 []string
	IdleDays                               int
	Types                                  []countView
	Anonymized                             bool

	HasLedger  bool
	AI         *aiView
	Pillars    []pillarSection
	Priorities []priorityRow
	Ledger     *ledgerView
	IaC        *iacView
	Ownerless  string
}

// pillarFinding is a finding as the document shows it.
type pillarFinding struct {
	Title, Severity, Source, Cost, Recommendation string
	Confidence, Effort, Reference, Note           string
	Affected                                      int
	Resources                                     []string
	MoreResources                                 int
	Evidence                                      []string
}

type pillarSection struct {
	Key, Name, Intro string
	Open, Acked      int
	Critical, High   int
	Cost             string
	Findings         []pillarFinding
}

type aiView struct {
	Model      string
	Headline   string
	Paragraphs []string
	Actions    []aiAction
	Removed    int
}

type aiAction struct{ Title, Why, Severity string }

type priorityRow struct {
	N                                             int
	Title, Pillar, Severity, Source, Cost, Effort string
}

type ledgerSvc struct{ Name, Billed, Tied, Rest string }
type ledgerLineV struct{ Service, Usage, Cost, Why string }

type ledgerView struct {
	Month, Billed, Tied, Pct string
	Services                 []ledgerSvc
	Lines                    []ledgerLineV
}

type iacView struct {
	HasSources bool
	Lines      []string
	Notes      []string
}

func confRank(c engine.Confidence) int {
	switch c {
	case engine.ConfHigh:
		return 0
	case engine.ConfMedium:
		return 1
	}
	return 2
}

func buildAudit(res engine.ScanResult, o AuditOptions) auditView {
	an := newAnonymizer(o.Anonymize, res)
	v := auditView{
		Client: o.Client, Consultant: o.Consultant, Version: o.Version,
		Generated: o.Now.Format("2006-01-02"), Logo: template.URL(o.LogoDataURI), Anonymized: o.Anonymize,
		Resources: res.TotalLive, Regions: len(res.Regions),
		EstCost: engine.Money(res.EstimatedTCO), WasteCost: engine.Money(res.TotalWaste),
		WasteCount: res.WasteCount, ShadowCount: res.ShadowCount, AckedCount: res.AckedCount,
		Checks: res.Checks, IdleDays: res.IdleWindowDays,
	}
	if v.Client == "" {
		v.Client = "Client"
	}
	acct := res.Account
	if o.Anonymize {
		acct = "ACCOUNT"
	}
	if acct == "" {
		acct = res.Profile
	}
	v.Account = acct
	v.Scope = fmt.Sprintf("account %s, %d region(s), %d resources", acct, len(res.Regions), res.TotalLive)

	// findings
	mk := func(n engine.ResourceNode) findingView {
		f := findingView{
			Name: an.label(n), Type: typeName(n.Type), Region: n.Region,
			Reason: an.scrub(n.WasteReason), Confidence: string(n.Confidence),
			Cost: engine.Money(n.MonthlyCost), CostValue: n.MonthlyCost,
		}
		for _, e := range n.Evidence {
			if strings.HasPrefix(e, "tag ") || strings.HasPrefix(e, "no tags") || strings.HasPrefix(e, "no IaC") {
				continue // management classification, not the basis of the verdict
			}
			f.Evidence = append(f.Evidence, an.scrub(e))
		}
		if n.Ack != nil {
			f.Note = an.scrub(n.Ack.Note)
			if n.Ack.Until != "" {
				f.Note += " (until " + n.Ack.Until + ")"
			}
		}
		return f
	}
	var waste, acked, shadow []engine.ResourceNode
	for _, n := range res.Nodes {
		switch {
		case n.Status == engine.StatusOrphanWaste && n.Ack != nil:
			acked = append(acked, n)
		case n.Status == engine.StatusOrphanWaste:
			waste = append(waste, n)
		case n.Status == engine.StatusShadowIT:
			shadow = append(shadow, n)
		}
	}
	byCost := func(s []engine.ResourceNode) {
		sort.SliceStable(s, func(i, j int) bool { return s[i].MonthlyCost > s[j].MonthlyCost })
	}
	byCost(waste)
	byCost(acked)
	byCost(shadow)
	for _, n := range waste {
		f := mk(n)
		r := confRank(n.Confidence)
		v.WasteCountsByConf[r]++
		switch r {
		case 0:
			v.High = append(v.High, f)
		case 1:
			v.Medium = append(v.Medium, f)
		default:
			v.Low = append(v.Low, f)
		}
	}
	for _, n := range acked {
		v.Acked = append(v.Acked, mk(n))
	}
	// blind spots once per type present among the findings, not per finding
	seenType := map[string]bool{}
	for _, n := range append(append([]engine.ResourceNode{}, waste...), acked...) {
		if seenType[n.Type] {
			continue
		}
		seenType[n.Type] = true
		if c := awsDiscovery.Caveats(n.Type); len(c) > 0 {
			v.VerifyByType = append(v.VerifyByType, verifyView{Type: typeName(n.Type), Items: c})
		}
	}
	sort.Slice(v.VerifyByType, func(i, j int) bool { return v.VerifyByType[i].Type < v.VerifyByType[j].Type })
	const shadowShown = 40
	for i, n := range shadow {
		if i == shadowShown {
			v.ShadowMore = len(shadow) - shadowShown
			break
		}
		f := mk(n)
		f.Evidence = nil
		v.Shadow = append(v.Shadow, f)
	}

	// commitments
	cv := func(c engine.Commitment) commitView {
		x := commitView{Service: c.Service, Detail: an.scrub(c.Detail), State: c.State}
		if c.End != nil {
			x.Ends = c.End.Format("2006-01-02")
		}
		for _, f := range c.Facts {
			x.Facts = append(x.Facts, an.scrub(f))
		}
		if c.Ack != nil {
			x.Note = an.scrub(c.Ack.Note)
			if c.Ack.Until != "" {
				x.Note += " (until " + c.Ack.Until + ")"
			}
		} else {
			x.Suggestions = c.Suggestions
		}
		return x
	}
	for _, c := range res.Commitments {
		x := cv(c)
		if len(x.Suggestions) > 0 {
			v.Decisions = append(v.Decisions, x)
			v.DecisionCount++
		} else {
			v.OtherCommitments = append(v.OtherCommitments, x)
		}
	}

	// cost picture
	var billed, scanned float64
	for _, s := range res.ServiceCosts {
		billed += s.PreviousMonthCost
		if s.Scanned {
			scanned += s.PreviousMonthCost
		}
	}
	if billed > 0 {
		cv := engine.CoverageOf(res)
		v.BilledTotal = engine.Money(billed)
		v.Coverage = fmt.Sprintf("%.0f%%", scanned/billed*100)
		v.ScannedPct = v.Coverage
		v.ExplainedPct = fmt.Sprintf("%.0f%%", cv.ExplainedPct())
	}
	for i, s := range res.ServiceCosts {
		if i == 12 {
			break
		}
		v.Services = append(v.Services, serviceView{
			Name: s.Service, Billed: engine.Money(s.PreviousMonthCost), Scanned: s.Scanned,
		})
	}
	for _, s := range res.ServiceCosts {
		if !s.Scanned && s.PreviousMonthCost >= 100 {
			v.NotChecked = append(v.NotChecked,
				fmt.Sprintf("%s: %s billed last month, no check for this service yet", s.Service, engine.Money(s.PreviousMonthCost)))
		}
	}
	for _, w := range res.Warnings {
		v.Warnings = append(v.Warnings, an.scrub(w))
	}
	v.Skipped = res.Skipped

	// inventory by type
	counts := map[string]int{}
	for _, n := range res.Nodes {
		counts[typeName(n.Type)]++
	}
	for k, n := range counts {
		v.Types = append(v.Types, countView{k, n})
	}
	sort.Slice(v.Types, func(i, j int) bool {
		if v.Types[i].N != v.Types[j].N {
			return v.Types[i].N > v.Types[j].N
		}
		return v.Types[i].Label < v.Types[j].Label
	})

	v.HasLedger = res.Ledger != nil
	buildPillars(&v, res, an)
	if o.AI != nil {
		titles := map[string]engine.Finding{}
		for _, f := range res.Findings {
			titles[f.ID] = f
		}
		av := &aiView{Model: o.AI.Model, Headline: an.scrub(o.AI.Narrative.Headline), Removed: o.AI.DroppedAny}
		for _, p := range o.AI.Narrative.Paragraphs {
			av.Paragraphs = append(av.Paragraphs, an.scrub(p))
		}
		for _, a := range o.AI.Narrative.Actions {
			if f, ok := titles[a.FindingID]; ok {
				av.Actions = append(av.Actions, aiAction{Title: an.scrub(f.Title), Why: an.scrub(a.Why), Severity: string(f.Severity)})
			}
		}
		v.AI = av
	}
	v.Headline = headline(res, v)
	return v
}

var sourceLabel = map[string]string{
	"own": "InfraLens", "trusted-advisor": "Trusted Advisor", "cost-hub": "Cost Optimization Hub",
	"security-hub": "Security Hub", "compute-optimizer": "Compute Optimizer", "prowler": "Prowler",
}

var pillarMeta = []struct {
	Key, Name, Intro string
	Pillars          []engine.Pillar
}{
	{"security", "Security", "What the account exposes and what is missing to detect or contain a problem. Findings come from AWS Security Hub and Trusted Advisor when they are enabled, from this tool's own checks (IAM, security groups, CloudTrail, GuardDuty and configuration read from resources) and from Prowler when its output was supplied. This is a review of configuration, not a penetration test, and it is not complete.", []engine.Pillar{engine.PillarSecurity}},
	{"cost", "Cost", "Where the money goes and what looks avoidable. Amounts come from last full month's bill and are split between resources by measured usage; what could not be tied to a resource is listed as such. A candidate is evidence of non-use, not a promised saving.", []engine.Pillar{engine.PillarCost}},
	{"reliability", "Reliability and performance", "What would take a service down with one failure, and what is running on unsupported software. Read from resource configuration.", []engine.Pillar{engine.PillarReliability, engine.PillarPerformance}},
	{"iac", "Infrastructure as code and ownership", "How much of the account is actually under code (state files and stacks, not tags) and whether anyone is named as responsible for what runs.", []engine.Pillar{engine.PillarIaC, engine.PillarOps}},
}

func effortRank(e string) int {
	switch e {
	case "low":
		return 0
	case "medium":
		return 1
	case "high":
		return 2
	}
	return 3
}

func buildPillars(v *auditView, res engine.ScanResult, an *anonymizer) {
	card := func(f engine.Finding) pillarFinding {
		c := pillarFinding{
			Title: an.scrub(f.Title), Severity: string(f.Severity), Source: sourceLabel[f.Source],
			Recommendation: an.scrub(f.Recommendation), Confidence: string(f.Confidence), Effort: f.Effort,
			Reference: an.scrub(f.Reference), Affected: f.Affected,
		}
		if c.Source == "" {
			c.Source = f.Source
		}
		if f.MonthlyCost > 0 {
			c.Cost = engine.Money(f.MonthlyCost)
		}
		if f.Ack != nil {
			c.Note = an.scrub(f.Ack.Note)
		}
		res := f.Resources
		if len(res) == 0 && f.ResourceID != "" && !strings.HasPrefix(f.ResourceID, "account:") && !strings.HasPrefix(f.ResourceID, "check:") && !strings.HasPrefix(f.ResourceID, "usage:") {
			res = []string{f.ResourceID}
		}
		for i, r := range res {
			if i == 8 {
				break
			}
			if an.on {
				r = an.name(r, "resource")
			}
			c.Resources = append(c.Resources, r)
		}
		if len(res) > 8 || f.Affected > len(c.Resources) {
			c.MoreResources = max(len(res), f.Affected) - len(c.Resources)
		}
		for i, e := range f.Evidence {
			if i == 4 {
				break
			}
			c.Evidence = append(c.Evidence, an.scrub(e))
		}
		return c
	}

	byPillar := map[engine.Pillar][]engine.Finding{}
	for _, f := range res.Findings {
		byPillar[f.Pillar] = append(byPillar[f.Pillar], f)
	}
	for _, m := range pillarMeta {
		sec := pillarSection{Key: m.Key, Name: m.Name, Intro: m.Intro}
		var all []engine.Finding
		for _, p := range m.Pillars {
			all = append(all, byPillar[p]...)
		}
		sort.SliceStable(all, func(i, j int) bool {
			if all[i].Severity.Rank() != all[j].Severity.Rank() {
				return all[i].Severity.Rank() < all[j].Severity.Rank()
			}
			return all[i].MonthlyCost > all[j].MonthlyCost
		})
		var cost float64
		for _, f := range all {
			if f.Ack != nil {
				sec.Acked++
			} else {
				sec.Open++
				switch f.Severity {
				case engine.SevCritical:
					sec.Critical++
				case engine.SevHigh:
					sec.High++
				}
				cost += f.MonthlyCost
			}
			sec.Findings = append(sec.Findings, card(f))
		}
		if cost > 0 && m.Key == "cost" {
			sec.Cost = engine.Money(cost)
		}
		v.Pillars = append(v.Pillars, sec)
	}

	// what to do first: severity, then money at stake, then the cheapest to do
	var open []engine.Finding
	for _, f := range res.Findings {
		if f.Ack == nil && f.Severity != engine.SevInfo {
			open = append(open, f)
		}
	}
	sort.SliceStable(open, func(i, j int) bool {
		a, b := open[i], open[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if a.MonthlyCost != b.MonthlyCost {
			return a.MonthlyCost > b.MonthlyCost
		}
		return effortRank(a.Effort) < effortRank(b.Effort)
	})
	for i, f := range open {
		if i == 10 {
			break
		}
		r := priorityRow{N: i + 1, Title: an.scrub(f.Title), Pillar: string(f.Pillar), Severity: string(f.Severity),
			Source: sourceLabel[f.Source], Effort: f.Effort}
		if f.MonthlyCost > 0 {
			r.Cost = engine.Money(f.MonthlyCost)
		}
		v.Priorities = append(v.Priorities, r)
	}

	if l := res.Ledger; l != nil && l.Billed > 0 {
		lv := &ledgerView{
			Month: l.Month, Billed: engine.Money(l.Billed), Tied: engine.Money(l.Allocated),
			Pct: fmt.Sprintf("%.0f%%", l.Allocated/l.Billed*100),
		}
		for i, s := range l.Services {
			if i == 14 {
				break
			}
			lv.Services = append(lv.Services, ledgerSvc{Name: s.Service, Billed: engine.Money(s.Billed), Tied: engine.Money(s.Allocated),
				Rest: engine.Money(s.Billed - s.Allocated)})
		}
		var lines []ledgerLineV
		for _, s := range l.Services {
			for _, u := range s.Unallocated {
				lines = append(lines, ledgerLineV{Service: s.Service, Usage: u.Usage, Cost: engine.Money(u.Cost), Why: u.Reason})
			}
		}
		sort.SliceStable(lines, func(i, j int) bool { return lines[i].Cost > lines[j].Cost })
		if len(lines) > 10 {
			lines = lines[:10]
		}
		lv.Lines = lines
		v.Ledger = lv
	}

	if i := res.IaC; i != nil {
		iv := &iacView{HasSources: len(i.Sources) > 0, Notes: i.Notes}
		if !iv.HasSources {
			iv.Lines = []string{"No Terraform state or CloudFormation stack was read. Infrastructure-as-code coverage rests on tags alone, which are claims, not proof."}
		} else {
			iv.Lines = append(iv.Lines,
				fmt.Sprintf("Read: %s.", strings.Join(i.Sources, "; ")),
				fmt.Sprintf("Of %d inventoried resources that state and stacks can describe, %d are confirmed in code, %d carry an IaC tag that no state confirms, and %d have neither.",
					i.Considered, i.Matched, i.TagOnly, i.Unmanaged))
			if i.DriftChecked > 0 {
				iv.Lines = append(iv.Lines, fmt.Sprintf("Drift was compared for %d resources of %d types; %d differ from their state.", i.DriftChecked, len(i.DriftTypes), i.DriftFound))
			}
		}
		for k, n := range iv.Lines {
			iv.Lines[k] = an.scrub(n)
		}
		iv.Notes = nil
		for _, n := range i.Notes {
			iv.Notes = append(iv.Notes, an.scrub(n))
		}
		v.IaC = iv
	}

	owned, total := 0, 0
	for _, n := range res.Nodes {
		if n.Type == "aws_cloudwatch_log_group_rollup" || n.Type == "aws_ecs_cluster" {
			continue
		}
		total++
		if n.Owner != "" {
			owned++
		}
	}
	if total > 0 {
		v.Ownerless = fmt.Sprintf("%d of %d resources (%.0f%%) have a named owner, team or project", owned, total, float64(owned)/float64(total)*100)
	}
}

func typeName(t string) string {
	return strings.ReplaceAll(strings.TrimPrefix(t, "aws_"), "_", " ")
}

// headline writes the executive summary in plain sentences. It states what
// was found and, in the same breath, what the number is not.
func headline(res engine.ScanResult, v auditView) []string {
	var out []string
	if res.Ledger != nil {
		out = append(out, fmt.Sprintf(
			"We inspected %d resources across %d region(s) of %s with read-only API calls. Their cost is %s per month: last month's bill split between resources by measured usage where it could be tied to one, and catalogue estimates for the rest.",
			v.Resources, v.Regions, v.Account, v.EstCost))
	} else {
		out = append(out, fmt.Sprintf(
			"We inspected %d resources across %d region(s) of %s with read-only API calls. Their estimated cost at list price is %s per month.",
			v.Resources, v.Regions, v.Account, v.EstCost))
	}
	if v.WasteCount > 0 {
		out = append(out, fmt.Sprintf(
			"%d resource(s) show no sign of use over the last %d days. At list price they cost an estimated %s per month: %d with high, %d with medium and %d with low confidence. "+
				"These are candidates: each needs its owner's confirmation before anything is removed.",
			v.WasteCount, max(v.IdleDays, 14), v.WasteCost, v.WasteCountsByConf[0], v.WasteCountsByConf[1], v.WasteCountsByConf[2]))
	} else {
		out = append(out, "No resource met the criteria for a waste candidate in the checks that ran.")
	}
	if v.AckedCount > 0 {
		out = append(out, fmt.Sprintf("%d further candidate(s) were acknowledged by the owner as expected and are not counted.", v.AckedCount))
	}
	if v.ShadowCount > 0 {
		out = append(out, fmt.Sprintf("%d resource(s) carry no infrastructure-as-code marker (tags). This is a heuristic: it shows what to look at, not how something was created.", v.ShadowCount))
	}
	if v.DecisionCount > 0 {
		out = append(out, fmt.Sprintf("%d decision(s) about commitments depend on plans the scan cannot know; they are listed with the facts behind them, not as recommendations.", v.DecisionCount))
	}
	if v.Coverage != "" {
		out = append(out, fmt.Sprintf(
			"Checks exist for %s of last month's billed usage (%s), and their estimates account for %s of it. The difference is usage- or request-priced and only partly modelled; the rest is listed under \"What was not checked\".",
			v.Coverage, v.BilledTotal, v.ExplainedPct))
	}
	return out
}

// RenderAudit produces the client document: one self-contained, print-ready
// HTML page with no scripts. html/template escapes every value, which matters
// because names and tags come from the audited account.
func RenderAudit(res engine.ScanResult, o AuditOptions) (string, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	t, err := template.New("audit").Parse(auditTemplate)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, buildAudit(res, o)); err != nil {
		return "", err
	}
	return b.String(), nil
}

// ---- CSV ---------------------------------------------------------------------

// csvSafe neutralises spreadsheet formula injection: names and tags come from
// the audited account and a cell starting with = + - @ would be executed by Excel.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// FindingsCSV lists every waste candidate, acknowledged item and no-IaC resource.
func FindingsCSV(res engine.ScanResult, o AuditOptions) ([]byte, error) {
	an := newAnonymizer(o.Anonymize, res)
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"kind", "name", "type", "region", "monthly_cost_usd", "cost_source", "confidence", "reason", "evidence", "acknowledged", "note"})
	rows := []engine.ResourceNode{}
	for _, n := range res.Nodes {
		if n.Status == engine.StatusOrphanWaste || n.Status == engine.StatusShadowIT {
			rows = append(rows, n)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Status != rows[j].Status {
			return rows[i].Status == engine.StatusOrphanWaste
		}
		return rows[i].MonthlyCost > rows[j].MonthlyCost
	})
	for _, n := range rows {
		kind, note, acked := "waste_candidate", "", "no"
		if n.Status == engine.StatusShadowIT {
			kind = "no_iac_marker"
		}
		if n.Ack != nil {
			acked, note = "yes", an.scrub(n.Ack.Note)
		}
		var ev []string
		for _, e := range n.Evidence {
			ev = append(ev, an.scrub(e))
		}
		_ = w.Write([]string{
			kind, csvSafe(an.label(n)), n.Type, n.Region,
			strconv.FormatFloat(n.MonthlyCost, 'f', 2, 64), n.CostSource, string(n.Confidence),
			csvSafe(an.scrub(n.WasteReason)), csvSafe(strings.Join(ev, " | ")), acked, csvSafe(note),
		})
	}
	w.Flush()
	return b.Bytes(), w.Error()
}
