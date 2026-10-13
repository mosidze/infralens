package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/computeoptimizer"
	coTypes "github.com/aws/aws-sdk-go-v2/service/computeoptimizer/types"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	ceTypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	"github.com/aws/aws-sdk-go-v2/service/costoptimizationhub"
	cohTypes "github.com/aws/aws-sdk-go-v2/service/costoptimizationhub/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	shTypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/support"
	supTypes "github.com/aws/aws-sdk-go-v2/service/support/types"
)

// ---- Trusted Advisor ---------------------------------------------------------

type fakeTA struct {
	checks    []supTypes.TrustedAdvisorCheckDescription
	summaries map[string]supTypes.TrustedAdvisorCheckSummary
	results   map[string]*supTypes.TrustedAdvisorCheckResult
	err       error
	fetched   []string
}

func (f *fakeTA) DescribeTrustedAdvisorChecks(context.Context, *support.DescribeTrustedAdvisorChecksInput, ...func(*support.Options)) (*support.DescribeTrustedAdvisorChecksOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &support.DescribeTrustedAdvisorChecksOutput{Checks: f.checks}, nil
}
func (f *fakeTA) DescribeTrustedAdvisorCheckSummaries(_ context.Context, in *support.DescribeTrustedAdvisorCheckSummariesInput, _ ...func(*support.Options)) (*support.DescribeTrustedAdvisorCheckSummariesOutput, error) {
	out := &support.DescribeTrustedAdvisorCheckSummariesOutput{}
	for _, id := range in.CheckIds {
		if s, ok := f.summaries[aws.ToString(id)]; ok {
			out.Summaries = append(out.Summaries, s)
		}
	}
	return out, nil
}
func (f *fakeTA) DescribeTrustedAdvisorCheckResult(_ context.Context, in *support.DescribeTrustedAdvisorCheckResultInput, _ ...func(*support.Options)) (*support.DescribeTrustedAdvisorCheckResultOutput, error) {
	f.fetched = append(f.fetched, aws.ToString(in.CheckId))
	return &support.DescribeTrustedAdvisorCheckResultOutput{Result: f.results[aws.ToString(in.CheckId)]}, nil
}

func s(v string) *string { return &v }

func TestTrustedAdvisorGroupsByCheckAndSkipsHealthyOnes(t *testing.T) {
	api := &fakeTA{
		checks: []supTypes.TrustedAdvisorCheckDescription{
			{Id: s("c-s3"), Name: s("S3 Bucket Permissions"), Category: s("security"),
				Description: s("Checks buckets.<br><b>Recommended Action</b><br>Restrict public access to the bucket.<br><br><b>Additional Resources</b>")},
			{Id: s("c-ec2"), Name: s("Low Utilization EC2"), Category: s("cost_optimizing"),
				Metadata: []*string{s("Region"), s("Instance ID"), s("Estimated Monthly Savings")}},
			{Id: s("c-ok"), Name: s("Healthy check"), Category: s("security")},
			{Id: s("c-na"), Name: s("Not available"), Category: s("performance")},
		},
		summaries: map[string]supTypes.TrustedAdvisorCheckSummary{
			"c-s3":  {CheckId: s("c-s3"), Status: s("error"), ResourcesSummary: &supTypes.TrustedAdvisorResourcesSummary{ResourcesFlagged: 2}},
			"c-ec2": {CheckId: s("c-ec2"), Status: s("warning"), ResourcesSummary: &supTypes.TrustedAdvisorResourcesSummary{ResourcesFlagged: 2}},
			"c-ok":  {CheckId: s("c-ok"), Status: s("ok")},
			"c-na":  {CheckId: s("c-na"), Status: s("not_available")},
		},
		results: map[string]*supTypes.TrustedAdvisorCheckResult{
			"c-s3": {FlaggedResources: []supTypes.TrustedAdvisorResourceDetail{
				{ResourceId: s("bucket-a"), Region: s("eu-north-1")}, {ResourceId: s("bucket-b"), Region: s("eu-north-1")},
				{ResourceId: s("suppressed"), IsSuppressed: true},
			}},
			"c-ec2": {FlaggedResources: []supTypes.TrustedAdvisorResourceDetail{
				{ResourceId: s("i-1"), Region: s("eu-north-1"), Metadata: []*string{s("eu-north-1"), s("i-1"), s("$41.50")}},
				{ResourceId: s("i-2"), Region: s("eu-north-1"), Metadata: []*string{s("eu-north-1"), s("i-2"), s("$8.25")}},
			}},
		},
	}
	c := newTestCollector()
	trustedAdvisorWith(context.Background(), api, c)

	if len(c.findings) != 2 {
		t.Fatalf("one finding per flagged check, none for ok/not_available: %+v", c.findings)
	}
	if len(api.fetched) != 2 {
		t.Fatalf("details are fetched only for flagged checks, got %v", api.fetched)
	}
	by := map[string]engine.Finding{}
	for _, f := range c.findings {
		by[f.Rule] = f
	}
	sec := by["ta.c-s3"]
	if sec.Pillar != engine.PillarSecurity || sec.Severity != engine.SevHigh || sec.Source != "trusted-advisor" {
		t.Fatalf("security: %+v", sec)
	}
	if len(sec.Resources) != 2 || strings.Contains(strings.Join(sec.Resources, ","), "suppressed") {
		t.Fatalf("suppressed resources must be left out: %v", sec.Resources)
	}
	if sec.Recommendation != "Restrict public access to the bucket." {
		t.Fatalf("recommended action should be extracted as plain text: %q", sec.Recommendation)
	}
	cost := by["ta.c-ec2"]
	if cost.Pillar != engine.PillarCost || cost.Severity != engine.SevMedium || cost.MonthlyCost != 49.75 {
		t.Fatalf("savings come from the per-resource column: %+v", cost)
	}
	if sec.ID == "" || sec.ID == cost.ID {
		t.Fatal("ids must exist and differ")
	}
}

func TestTrustedAdvisorWithoutSupportPlanIsANoteNotAFailure(t *testing.T) {
	api := &fakeTA{err: errors.New("SubscriptionRequiredException: AWS Premium Support Subscription is required")}
	c := newTestCollector()
	trustedAdvisorWith(context.Background(), api, c)
	if len(c.warnings) != 0 || len(c.skipped) != 1 || !strings.Contains(c.skipped[0], "Support plan") {
		t.Fatalf("warnings=%v skipped=%v", c.warnings, c.skipped)
	}
}

func TestPlainText(t *testing.T) {
	got := plainText(`Checks <a href="x">things</a>.<br><br>See &amp; act`)
	if got != "Checks things . See & act" && got != "Checks things. See & act" {
		t.Fatalf("%q", got)
	}
	if strings.Contains(plainText("<script>alert(1)</script>x"), "<") {
		t.Fatal("markup must not survive")
	}
}

// ---- Cost Optimization Hub ---------------------------------------------------

type fakeCOH struct {
	items []cohTypes.Recommendation
	err   error
}

func (f fakeCOH) ListRecommendations(context.Context, *costoptimizationhub.ListRecommendationsInput, ...func(*costoptimizationhub.Options)) (*costoptimizationhub.ListRecommendationsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &costoptimizationhub.ListRecommendationsOutput{Items: f.items}, nil
}

func TestCostHubFindingsAreConditionalAndCarryEffort(t *testing.T) {
	yes, no := true, false
	api := fakeCOH{items: []cohTypes.Recommendation{
		{RecommendationId: s("r1"), ActionType: s("PurchaseReservedInstances"), CurrentResourceType: s("RdsReservedInstances"),
			EstimatedMonthlySavings: aws.Float64(237.84), EstimatedSavingsPercentage: aws.Float64(31), ImplementationEffort: s("VeryLow"),
			RollbackPossible: &no, ResourceId: s("res-1"), Region: s("eu-north-1"), RecommendationLookbackPeriodInDays: aws.Int32(30)},
		{RecommendationId: s("r2"), ActionType: s("Delete"), CurrentResourceType: s("EbsVolume"),
			EstimatedMonthlySavings: aws.Float64(620), ImplementationEffort: s("Medium"), RollbackPossible: &yes, ResourceId: s("vol-1")},
	}}
	c := newTestCollector()
	costHubWith(context.Background(), api, c)
	if len(c.findings) != 2 {
		t.Fatalf("%+v", c.findings)
	}
	var purchase, del engine.Finding
	for _, f := range c.findings {
		if strings.Contains(f.Rule, "purchase") {
			purchase = f
		} else {
			del = f
		}
	}
	if purchase.Effort != "low" || purchase.MonthlyCost != 237.84 || purchase.Pillar != engine.PillarCost {
		t.Fatalf("%+v", purchase)
	}
	adv := strings.ToLower(purchase.Recommendation)
	if !strings.Contains(adv, "only if the workload is expected to stay") || !strings.Contains(adv, "migration") {
		t.Fatalf("a purchase suggestion must name the plan it depends on: %q", purchase.Recommendation)
	}
	if del.Severity != engine.SevHigh {
		t.Fatalf("$620 is high: %+v", del)
	}
	if !strings.Contains(strings.Join(purchase.Evidence, " "), "rollback possible: false") {
		t.Fatalf("rollback is part of the evidence: %v", purchase.Evidence)
	}
}

func TestCostHubNotEnabled(t *testing.T) {
	c := newTestCollector()
	costHubWith(context.Background(), fakeCOH{err: errors.New("AccessDeniedException: Account is not enrolled")}, c)
	if len(c.warnings) != 0 || len(c.skipped) != 1 {
		t.Fatalf("warnings=%v skipped=%v", c.warnings, c.skipped)
	}
}

// ---- Security Hub ------------------------------------------------------------

type fakeSH struct {
	pages [][]shTypes.AwsSecurityFinding
	err   error
}

func (f *fakeSH) GetFindings(_ context.Context, in *securityhub.GetFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	i := 0
	if in.NextToken != nil {
		i = int((*in.NextToken)[0] - '0')
	}
	out := &securityhub.GetFindingsOutput{Findings: f.pages[i]}
	if i+1 < len(f.pages) {
		out.NextToken = aws.String(string(rune('0' + i + 1)))
	}
	return out, nil
}

func shFinding(gen, title, res string, sev shTypes.SeverityLabel) shTypes.AwsSecurityFinding {
	return shTypes.AwsSecurityFinding{
		GeneratorId: aws.String(gen), Title: aws.String(title), Severity: &shTypes.Severity{Label: sev},
		Resources:   []shTypes.Resource{{Id: aws.String(res), Type: aws.String("AwsS3Bucket")}},
		Remediation: &shTypes.Remediation{Recommendation: &shTypes.Recommendation{Text: aws.String("Block public access.")}},
	}
}

func TestSecurityHubGroupsByControl(t *testing.T) {
	api := &fakeSH{pages: [][]shTypes.AwsSecurityFinding{{
		shFinding("S3.8", "S3 buckets should block public access", "b1", shTypes.SeverityLabelHigh),
		shFinding("S3.8", "S3 buckets should block public access", "b2", shTypes.SeverityLabelHigh),
		shFinding("S3.8", "S3 buckets should block public access", "b3", shTypes.SeverityLabelHigh),
		shFinding("IAM.4", "Root user should not have access keys", "root", shTypes.SeverityLabelCritical),
	}}}
	c := newTestCollector()
	securityHubWith(context.Background(), api, c)
	if len(c.findings) != 2 {
		t.Fatalf("grouped by control: %+v", c.findings)
	}
	by := map[string]engine.Finding{}
	for _, f := range c.findings {
		by[f.Reference] = f
	}
	if by["S3.8"].Affected != 3 || len(by["S3.8"].Resources) != 3 || by["S3.8"].Severity != engine.SevHigh {
		t.Fatalf("%+v", by["S3.8"])
	}
	if by["IAM.4"].Severity != engine.SevCritical || by["IAM.4"].Pillar != engine.PillarSecurity {
		t.Fatalf("%+v", by["IAM.4"])
	}
	if by["S3.8"].ID == by["IAM.4"].ID {
		t.Fatal("distinct controls need distinct ids")
	}
}

func TestSecurityHubDisabledRegionIsSilent(t *testing.T) {
	c := newTestCollector()
	securityHubWith(context.Background(), &fakeSH{err: errors.New("InvalidAccessException: Account is not subscribed to AWS Security Hub")}, c)
	if len(c.warnings) != 0 || len(c.findings) != 0 {
		t.Fatalf("warnings=%v findings=%v", c.warnings, c.findings)
	}
}

func TestSecurityHubStatesWhenItStoppedReading(t *testing.T) {
	var pages [][]shTypes.AwsSecurityFinding
	for i := 0; i < shMaxPages+2; i++ {
		pages = append(pages, []shTypes.AwsSecurityFinding{shFinding("X.1", "t", "r", shTypes.SeverityLabelHigh)})
	}
	c := newTestCollector()
	securityHubWith(context.Background(), &fakeSH{pages: pages}, c)
	if len(c.findings) != 1 || !strings.Contains(strings.Join(c.findings[0].Evidence, " "), "may be higher") {
		t.Fatalf("a truncated read must say so: %+v", c.findings)
	}
}

// ---- hygiene -----------------------------------------------------------------

type fakeOptimizer struct{ status coTypes.Status }

func (f fakeOptimizer) GetEnrollmentStatus(context.Context, *computeoptimizer.GetEnrollmentStatusInput, ...func(*computeoptimizer.Options)) (*computeoptimizer.GetEnrollmentStatusOutput, error) {
	return &computeoptimizer.GetEnrollmentStatusOutput{Status: f.status}, nil
}

type fakeMonitors struct{ n int }

func (f fakeMonitors) GetAnomalyMonitors(context.Context, *costexplorer.GetAnomalyMonitorsInput, ...func(*costexplorer.Options)) (*costexplorer.GetAnomalyMonitorsOutput, error) {
	return &costexplorer.GetAnomalyMonitorsOutput{AnomalyMonitors: make([]ceTypes.AnomalyMonitor, f.n)}, nil
}

func TestHygieneReportsOnlyWhatIsMissing(t *testing.T) {
	c := newTestCollector()
	hygieneWith(context.Background(), hygieneAPI{optimizer: fakeOptimizer{coTypes.StatusInactive}, ce: fakeMonitors{0}}, c)
	if len(c.findings) != 2 {
		t.Fatalf("%+v", c.findings)
	}
	for _, f := range c.findings {
		if !strings.Contains(strings.ToLower(f.Recommendation), "owner") && !strings.Contains(strings.ToLower(f.Recommendation), "free") {
			t.Errorf("must stay a recommendation: %q", f.Recommendation)
		}
	}
	c2 := newTestCollector()
	hygieneWith(context.Background(), hygieneAPI{optimizer: fakeOptimizer{coTypes.StatusActive}, ce: fakeMonitors{2}}, c2)
	if len(c2.findings) != 0 {
		t.Fatalf("nothing is missing: %+v", c2.findings)
	}
}
