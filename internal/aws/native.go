package aws

import (
	"context"
	"fmt"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/computeoptimizer"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/costoptimizationhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	shTypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/support"
)

// Findings that AWS's own services already produce are consumed, not
// re-derived: Trusted Advisor, Cost Optimization Hub, Security Hub. Each
// adapter degrades to a note when its service is not available or not
// enabled; enabling anything is the owner's decision, never the tool's.

// ---- Trusted Advisor ---------------------------------------------------------

type taAPI interface {
	DescribeTrustedAdvisorChecks(ctx context.Context, in *support.DescribeTrustedAdvisorChecksInput, opts ...func(*support.Options)) (*support.DescribeTrustedAdvisorChecksOutput, error)
	DescribeTrustedAdvisorCheckSummaries(ctx context.Context, in *support.DescribeTrustedAdvisorCheckSummariesInput, opts ...func(*support.Options)) (*support.DescribeTrustedAdvisorCheckSummariesOutput, error)
	DescribeTrustedAdvisorCheckResult(ctx context.Context, in *support.DescribeTrustedAdvisorCheckResultInput, opts ...func(*support.Options)) (*support.DescribeTrustedAdvisorCheckResultOutput, error)
}

func scanTrustedAdvisor(ctx context.Context, dc *DiscoveryClient, c *collector) {
	cfg, err := dc.loadConfig(ctx, "us-east-1") // the Support API lives in us-east-1
	if err != nil {
		c.warn("trusted-advisor:config", err)
		return
	}
	trustedAdvisorWith(ctx, support.NewFromConfig(cfg), c)
}

const (
	taSummaryBatch   = 20
	taMaxResources   = 40  // flagged resources kept per check
	taMaxChecksFetch = 150 // detail fetches per scan; summaries decide what is worth it
)

func taPillar(category string) engine.Pillar {
	switch category {
	case "security":
		return engine.PillarSecurity
	case "cost_optimizing":
		return engine.PillarCost
	case "fault_tolerance":
		return engine.PillarReliability
	case "performance":
		return engine.PillarPerformance
	}
	return engine.PillarOps
}

var (
	reTag     = regexp.MustCompile(`<[^>]*>`)
	reSpaces  = regexp.MustCompile(`\s+`)
	reMoney   = regexp.MustCompile(`[-+]?\$?\s*([0-9][0-9,]*\.?[0-9]*)`)
	reRecoAct = regexp.MustCompile(`(?is)Recommended Action\s*(?:</b>)?\s*(?:<br\s*/?>)*(.*?)(?:<br\s*/?>\s*<br|<b>Additional|$)`)
)

// plainText strips markup from a Trusted Advisor description.
func plainText(s string) string {
	s = strings.ReplaceAll(s, "<br>", " ")
	s = strings.ReplaceAll(s, "<br/>", " ")
	s = reTag.ReplaceAllString(s, " ")
	return strings.TrimSpace(reSpaces.ReplaceAllString(html.UnescapeString(s), " "))
}

// taRecommendation extracts the "Recommended Action" section when present.
func taRecommendation(desc string) string {
	if m := reRecoAct.FindStringSubmatch(desc); m != nil {
		if t := plainText(m[1]); t != "" {
			return truncateText(t, 400)
		}
	}
	return ""
}

func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func trustedAdvisorWith(ctx context.Context, api taAPI, c *collector) {
	checks, err := api.DescribeTrustedAdvisorChecks(ctx, &support.DescribeTrustedAdvisorChecksInput{Language: aws.String("en")})
	if err != nil {
		if strings.Contains(err.Error(), "SubscriptionRequired") || strings.Contains(err.Error(), "AWS Premium Support") {
			c.skip("trusted-advisor", "needs a Business or Enterprise Support plan")
			return
		}
		c.warn("trusted-advisor:checks", err)
		return
	}
	byID := map[string]struct {
		name, category, desc string
		meta                 []string
	}{}
	var ids []string
	for _, ch := range checks.Checks {
		id := aws.ToString(ch.Id)
		byID[id] = struct {
			name, category, desc string
			meta                 []string
		}{aws.ToString(ch.Name), aws.ToString(ch.Category), aws.ToString(ch.Description), derefAll(ch.Metadata)}
		ids = append(ids, id)
	}

	type flagged struct {
		id, status string
		count      int64
		savings    float64
	}
	var bad []flagged
	for i := 0; i < len(ids); i += taSummaryBatch {
		out, err := api.DescribeTrustedAdvisorCheckSummaries(ctx, &support.DescribeTrustedAdvisorCheckSummariesInput{
			CheckIds: ptrs(ids[i:min(i+taSummaryBatch, len(ids))]),
		})
		if err != nil {
			c.warn("trusted-advisor:summaries", err)
			return
		}
		for _, s := range out.Summaries {
			st := aws.ToString(s.Status)
			if st != "error" && st != "warning" {
				continue
			}
			f := flagged{id: aws.ToString(s.CheckId), status: st}
			if s.ResourcesSummary != nil {
				f.count = s.ResourcesSummary.ResourcesFlagged
			}
			if s.CategorySpecificSummary != nil && s.CategorySpecificSummary.CostOptimizing != nil {
				f.savings = s.CategorySpecificSummary.CostOptimizing.EstimatedMonthlySavings
			}
			bad = append(bad, f)
		}
	}
	// errors first, then by savings and flagged count
	sort.SliceStable(bad, func(i, j int) bool {
		if (bad[i].status == "error") != (bad[j].status == "error") {
			return bad[i].status == "error"
		}
		if bad[i].savings != bad[j].savings {
			return bad[i].savings > bad[j].savings
		}
		return bad[i].count > bad[j].count
	})
	if len(bad) > taMaxChecksFetch {
		c.skip("trusted-advisor", fmt.Sprintf("%d further flagged checks not read (limit %d per scan)", len(bad)-taMaxChecksFetch, taMaxChecksFetch))
		bad = bad[:taMaxChecksFetch]
	}

	for _, b := range bad {
		ch := byID[b.id]
		f := engine.Finding{
			Pillar: taPillar(ch.category), Source: "trusted-advisor", Rule: "ta." + b.id,
			Title: ch.name, Reference: "Trusted Advisor check " + b.id,
			Severity: engine.SevMedium, Confidence: engine.ConfHigh, Affected: int(b.count),
			MonthlyCost:    b.savings,
			Recommendation: taRecommendation(ch.desc),
		}
		if b.status == "error" {
			f.Severity = engine.SevHigh
		}
		f.Evidence = append(f.Evidence, fmt.Sprintf("Trusted Advisor status: %s, %d resource(s) flagged", b.status, b.count))

		res, err := api.DescribeTrustedAdvisorCheckResult(ctx, &support.DescribeTrustedAdvisorCheckResultInput{
			CheckId: aws.String(b.id), Language: aws.String("en"),
		})
		if err != nil {
			c.warn("trusted-advisor:result", err)
		} else if res.Result != nil {
			saveIdx := -1
			for i, m := range ch.meta {
				if strings.Contains(strings.ToLower(m), "estimated monthly savings") {
					saveIdx = i
				}
			}
			var sum float64
			for _, r := range res.Result.FlaggedResources {
				if r.IsSuppressed {
					continue
				}
				id := aws.ToString(r.ResourceId)
				if len(f.Resources) < taMaxResources {
					f.Resources = append(f.Resources, id)
				}
				if f.Region == "" {
					f.Region = aws.ToString(r.Region)
				}
				if saveIdx >= 0 && saveIdx < len(r.Metadata) {
					if m := reMoney.FindStringSubmatch(aws.ToString(r.Metadata[saveIdx])); m != nil {
						v, _ := strconv.ParseFloat(strings.ReplaceAll(m[1], ",", ""), 64)
						sum += v
					}
				}
			}
			if f.MonthlyCost == 0 {
				f.MonthlyCost = sum
			}
			if len(f.Resources) > 0 {
				f.ResourceID = f.Resources[0]
			}
		}
		if f.ResourceID == "" {
			f.ResourceID = "check:" + b.id
		}
		f.ID = engine.FindingID(f.Source, f.Rule, "")
		c.finding(f)
	}
}

// ---- Cost Optimization Hub ---------------------------------------------------

type cohAPI interface {
	costoptimizationhub.ListRecommendationsAPIClient
}

func scanCostHub(ctx context.Context, dc *DiscoveryClient, c *collector) {
	cfg, err := dc.loadConfig(ctx, "us-east-1")
	if err != nil {
		c.warn("cost-hub:config", err)
		return
	}
	costHubWith(ctx, costoptimizationhub.NewFromConfig(cfg), c)
}

func costHubWith(ctx context.Context, api cohAPI, c *collector) {
	p := costoptimizationhub.NewListRecommendationsPaginator(api, &costoptimizationhub.ListRecommendationsInput{})
	n := 0
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			m := err.Error()
			if strings.Contains(m, "not enrolled") || strings.Contains(m, "AccessDenied") || strings.Contains(m, "OptInRequired") {
				c.skip("cost-hub", "Cost Optimization Hub is not enabled for this account")
				return
			}
			c.warn("cost-hub:recommendations", err)
			return
		}
		for _, r := range page.Items {
			if n >= 200 {
				return
			}
			n++
			save := aws.ToFloat64(r.EstimatedMonthlySavings)
			action := aws.ToString(r.ActionType)
			f := engine.Finding{
				Pillar: engine.PillarCost, Source: "cost-hub", Rule: "cost-hub." + strings.ToLower(action),
				Severity: costSeverityHub(save), Confidence: engine.ConfMedium, MonthlyCost: save,
				ResourceID: aws.ToString(r.ResourceId), ResourceType: aws.ToString(r.CurrentResourceType), Region: aws.ToString(r.Region),
				Effort: hubEffort(aws.ToString(r.ImplementationEffort)), Affected: 1,
				Reference: "Cost Optimization Hub " + aws.ToString(r.RecommendationId),
			}
			f.Title = fmt.Sprintf("%s: %s", hubAction(action), aws.ToString(r.CurrentResourceType))
			f.Evidence = []string{
				fmt.Sprintf("AWS estimates $%.2f/month (%.0f%%) from the last %d days of usage",
					save, aws.ToFloat64(r.EstimatedSavingsPercentage), aws.ToInt32(r.RecommendationLookbackPeriodInDays)),
			}
			if r.RollbackPossible != nil {
				f.Evidence = append(f.Evidence, "rollback possible: "+strconv.FormatBool(*r.RollbackPossible))
			}
			if r.RestartNeeded != nil && *r.RestartNeeded {
				f.Evidence = append(f.Evidence, "needs a restart")
			}
			f.Recommendation = hubAdvice(action)
			f.ID = engine.FindingID(f.Source, f.Rule+aws.ToString(r.RecommendationId), f.ResourceID)
			c.finding(f)
		}
	}
}

func costSeverityHub(m float64) engine.Severity {
	switch {
	case m >= 500:
		return engine.SevHigh
	case m >= 100:
		return engine.SevMedium
	}
	return engine.SevLow
}

func hubEffort(e string) string {
	switch strings.ToLower(e) {
	case "verylow", "low":
		return "low"
	case "medium":
		return "medium"
	}
	return "high"
}

func hubAction(a string) string {
	switch a {
	case "PurchaseSavingsPlans":
		return "Savings Plan purchase suggested"
	case "PurchaseReservedInstances":
		return "Reservation purchase suggested"
	case "Rightsize":
		return "Rightsize"
	case "Stop":
		return "Stop"
	case "Delete":
		return "Delete"
	case "Upgrade":
		return "Upgrade"
	case "MigrateToGraviton":
		return "Migrate to Graviton"
	case "ScaleIn":
		return "Scale in"
	}
	return a
}

// hubAdvice words purchase suggestions as conditional: the service computes
// them from past usage and does not know of migrations or shutdowns.
func hubAdvice(a string) string {
	switch a {
	case "PurchaseSavingsPlans", "PurchaseReservedInstances":
		return "AWS suggests this from the last weeks of usage. It is worth acting on only if the workload is expected to stay on AWS for the commitment term; if a migration, resize or shutdown is planned, ignore it."
	case "Delete", "Stop":
		return "Confirm with the owner that the resource is not needed before removing it."
	}
	return "Review the recommendation with the owner and the workload's history before changing it."
}

// ---- Security Hub ------------------------------------------------------------

type shAPI interface {
	securityhub.GetFindingsAPIClient
}

func scanSecurityHub(ctx context.Context, cfg aws.Config, c *collector) {
	securityHubWith(ctx, securityhub.NewFromConfig(cfg), c)
}

func shFilters() *shTypes.AwsSecurityFindingFilters {
	eq := func(v string) shTypes.StringFilter {
		return shTypes.StringFilter{Value: aws.String(v), Comparison: shTypes.StringFilterComparisonEquals}
	}
	return &shTypes.AwsSecurityFindingFilters{
		RecordState:    []shTypes.StringFilter{eq("ACTIVE")},
		SeverityLabel:  []shTypes.StringFilter{eq("CRITICAL"), eq("HIGH")},
		WorkflowStatus: []shTypes.StringFilter{eq("NEW"), eq("NOTIFIED")},
	}
}

const shMaxPages = 5

func securityHubWith(ctx context.Context, api shAPI, c *collector) {
	in := &securityhub.GetFindingsInput{Filters: shFilters(), MaxResults: aws.Int32(100)}
	p := securityhub.NewGetFindingsPaginator(api, in)
	type group struct {
		f engine.Finding
	}
	groups := map[string]*engine.Finding{}
	var order []string
	pages, truncated := 0, false
	for p.HasMorePages() {
		if pages == shMaxPages {
			truncated = true
			break
		}
		pages++
		page, err := p.NextPage(ctx)
		if err != nil {
			m := err.Error()
			if strings.Contains(m, "not subscribed") || strings.Contains(m, "InvalidAccess") || strings.Contains(m, "is not enabled") {
				return // Security Hub is not enabled in this region: nothing to read
			}
			c.warn("securityhub:findings", err)
			return
		}
		for _, x := range page.Findings {
			rule := aws.ToString(x.GeneratorId)
			if rule == "" {
				rule = aws.ToString(x.Title)
			}
			g := groups[rule]
			if g == nil {
				sev := engine.SevHigh
				if x.Severity != nil && x.Severity.Label == shTypes.SeverityLabelCritical {
					sev = engine.SevCritical
				}
				g = &engine.Finding{
					Pillar: engine.PillarSecurity, Source: "security-hub", Rule: "sh." + rule, Severity: sev,
					Title: aws.ToString(x.Title), Confidence: engine.ConfHigh, Region: c.region,
					Reference: rule,
				}
				if x.Remediation != nil && x.Remediation.Recommendation != nil {
					g.Recommendation = truncateText(aws.ToString(x.Remediation.Recommendation.Text), 400)
				}
				groups[rule] = g
				order = append(order, rule)
			}
			g.Affected++
			if len(x.Resources) > 0 {
				id := aws.ToString(x.Resources[0].Id)
				if len(g.Resources) < taMaxResources {
					g.Resources = append(g.Resources, id)
				}
				if g.ResourceID == "" {
					g.ResourceID, g.ResourceType = id, aws.ToString(x.Resources[0].Type)
				}
			}
		}
	}
	for _, rule := range order {
		g := groups[rule]
		g.Evidence = []string{fmt.Sprintf("Security Hub: %d active finding(s) for this control in %s", g.Affected, c.region)}
		if truncated {
			g.Evidence = append(g.Evidence, fmt.Sprintf("read the first %d pages only; the real count may be higher", shMaxPages))
		}
		g.ID = engine.FindingID(g.Source, g.Rule, c.region)
		c.finding(*g)
	}
}

// ---- hygiene: cheap facts about the account's own tooling --------------------

type hygieneAPI struct {
	optimizer interface {
		GetEnrollmentStatus(ctx context.Context, in *computeoptimizer.GetEnrollmentStatusInput, opts ...func(*computeoptimizer.Options)) (*computeoptimizer.GetEnrollmentStatusOutput, error)
	}
	ce interface {
		GetAnomalyMonitors(ctx context.Context, in *costexplorer.GetAnomalyMonitorsInput, opts ...func(*costexplorer.Options)) (*costexplorer.GetAnomalyMonitorsOutput, error)
	}
}

func scanHygiene(ctx context.Context, dc *DiscoveryClient, c *collector) {
	cfg, err := dc.loadConfig(ctx, "us-east-1")
	if err != nil {
		c.warn("hygiene:config", err)
		return
	}
	hygieneWith(ctx, hygieneAPI{optimizer: computeoptimizer.NewFromConfig(cfg), ce: costexplorer.NewFromConfig(cfg)}, c)
}

func hygieneWith(ctx context.Context, api hygieneAPI, c *collector) {
	if out, err := api.optimizer.GetEnrollmentStatus(ctx, &computeoptimizer.GetEnrollmentStatusInput{}); err != nil {
		c.warn("compute-optimizer:enrollment", err)
	} else if string(out.Status) != "Active" {
		f := engine.Finding{
			Pillar: engine.PillarCost, Source: "own", Rule: "ops.compute-optimizer-off", Severity: engine.SevLow,
			Title: "AWS Compute Optimizer is not enabled", ResourceID: "account:compute-optimizer",
			Evidence:       []string{"enrollment status: " + string(out.Status)},
			Recommendation: "Compute Optimizer is free and feeds rightsizing recommendations into Cost Optimization Hub. Enabling it is an account owner's decision; this tool never changes the account.",
			Confidence:     engine.ConfHigh, Effort: "low", Affected: 1,
		}
		f.ID = engine.FindingID(f.Source, f.Rule, f.ResourceID)
		c.finding(f)
	}
	if out, err := api.ce.GetAnomalyMonitors(ctx, &costexplorer.GetAnomalyMonitorsInput{}); err != nil {
		c.warn("cost-anomaly:monitors", err)
	} else if len(out.AnomalyMonitors) == 0 {
		f := engine.Finding{
			Pillar: engine.PillarCost, Source: "own", Rule: "ops.no-cost-anomaly-monitor", Severity: engine.SevLow,
			Title: "No AWS Cost Anomaly Detection monitor", ResourceID: "account:cost-anomaly",
			Evidence:       []string{"no anomaly monitors are configured"},
			Recommendation: "A monitor is free and alerts on unexpected spend. Worth having once someone is assigned to receive the alerts.",
			Confidence:     engine.ConfHigh, Effort: "low", Affected: 1,
		}
		f.ID = engine.FindingID(f.Source, f.Rule, f.ResourceID)
		c.finding(f)
	}
}

func init() {
	register(Scanner{Name: "trustedadvisor", Desc: "Trusted Advisor findings (needs Business/Enterprise Support), grouped by check",
		Informational: true, Global: scanTrustedAdvisor})
	register(Scanner{Name: "costhub", Desc: "Cost Optimization Hub recommendations (rightsizing, idle, purchase options)",
		Informational: true, Global: scanCostHub})
	register(Scanner{Name: "securityhub", Desc: "Security Hub HIGH/CRITICAL active findings, grouped by control (per region)",
		Informational: true, Regional: scanSecurityHub})
	register(Scanner{Name: "hygiene", Desc: "Account tooling: Compute Optimizer enrollment, cost anomaly monitors",
		Informational: true, Global: scanHygiene})
}

func derefAll(in []*string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, aws.ToString(p))
	}
	return out
}

func ptrs(in []string) []*string {
	out := make([]*string, len(in))
	for i := range in {
		out[i] = aws.String(in[i])
	}
	return out
}
