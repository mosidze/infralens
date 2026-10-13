package report

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"infralens/internal/engine"
)

func sampleScan() engine.ScanResult {
	end := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	res := engine.ScanResult{
		Account: "111122223333", Profile: "client-prod", Regions: []string{"eu-north-1"},
		Checks: []string{"rds", "elb"}, IdleWindowDays: 14,
		Nodes: []engine.ResourceNode{
			{ID: "arn:aws:elasticloadbalancing:eu-north-1:111122223333:loadbalancer/app/payments-prod/abc",
				Name: "payments-prod", Type: "aws_lb", Region: "eu-north-1", Status: engine.StatusOrphanWaste,
				MonthlyCost: 16.43, Confidence: engine.ConfHigh, WasteReason: "Load balancer without targets",
				Evidence: []string{"tag terraform present", "no target groups for 14d; owner payments-prod team"}},
			{ID: "vol-0123456789abcdef0", Name: "=HYPERLINK(\"http://evil\")", Type: "aws_ebs_volume", Region: "eu-north-1",
				Status: engine.StatusOrphanWaste, MonthlyCost: 8, Confidence: engine.ConfLow, WasteReason: "Unattached EBS volume"},
			{ID: "i-secret", Name: "</td><script>alert(1)</script>", Type: "aws_instance", Region: "eu-north-1",
				Status: engine.StatusShadowIT, MonthlyCost: 30},
			{ID: "k-acked", Name: "billing-stream", Type: "aws_kinesis_stream", Region: "eu-north-1",
				Status: engine.StatusOrphanWaste, MonthlyCost: 29.2, Confidence: engine.ConfLow,
				Ack: &engine.Ack{Note: "low traffic by design"}},
		},
		Commitments: []engine.Commitment{
			{Kind: "reservation", Service: "Amazon Relational Database Service", ID: "postgres1-2025-2026",
				Detail: "postgres1-2025-2026: 2 × db.t4g.large", State: "active", End: &end,
				Facts:       []string{"ends 2026-10-16 (3 days left)"},
				Suggestions: []string{"Decide before it ends. The scan cannot know your plans."}},
			{Kind: "coverage", Service: "Amazon OpenSearch Service", Detail: "last month 85% covered",
				Facts: []string{"coverage fell from 85% to 45% this month"}, Suggestions: []string{"If migration is planned, no action is needed."},
				Ack: &engine.Ack{Note: "moving to on-prem Elastic"}},
		},
		ServiceCosts: []engine.ServiceCost{
			{Service: "Amazon Relational Database Service", CostHistory: engine.CostHistory{PreviousMonthCost: 1273}, Scanned: true},
			{Service: "AWS Lambda", CostHistory: engine.CostHistory{PreviousMonthCost: 747}},
		},
		Warnings: []string{"eu-north-1/opensearch: AccessDenied for payments-prod"},
	}
	engine.Finalize(&res, map[string]string{"aws_lb": "Amazon Elastic Load Balancing"})
	return res
}

func TestAuditEscapesHostileContent(t *testing.T) {
	html, err := RenderAudit(sampleScan(), AuditOptions{Client: "<b>ACME</b>", Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<script>alert(1)", "<b>ACME</b>"} {
		if strings.Contains(html, bad) {
			t.Errorf("unescaped %q in document", bad)
		}
	}
	if strings.Contains(html, "<script") {
		t.Error("the audit document must contain no script at all")
	}
	if !strings.Contains(html, "&lt;b&gt;ACME&lt;/b&gt;") {
		t.Error("client name should be shown, escaped")
	}
}

func TestAuditContentAndFraming(t *testing.T) {
	html, err := RenderAudit(sampleScan(), AuditOptions{Client: "ACME", Consultant: "Jane Doe", Version: "1.0", Now: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"payments-prod", "$16.43", "High confidence", "what each check cannot see",
		"prepared by Jane Doe", "candidates: each needs its owner",
		"Decide before it ends", "If your plans allow",
		"low traffic by design",      // acknowledged finding shown with the owner's note
		"moving to on-prem Elastic",  // acknowledged commitment shown, suggestion hidden
		"AWS Lambda: $747.00 billed", // not-checked list
		"Check could not run",        // warnings surface
		"no data left it",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("document lacks %q", want)
		}
	}
	// an acknowledged commitment must not keep prompting
	if strings.Contains(html, "If migration is planned, no action is needed.") {
		t.Error("acknowledged suggestion must be hidden")
	}
	// the document must not claim certainty
	for _, banned := range []string{"you are wasting", "you are losing", "overpaying", "guaranteed"} {
		if strings.Contains(strings.ToLower(html), banned) {
			t.Errorf("assertive wording %q", banned)
		}
	}
}

func TestAuditAnonymizationLeaksNothing(t *testing.T) {
	res := sampleScan()
	opts := AuditOptions{Client: "ACME", Anonymize: true, Now: time.Now()}
	html, err := RenderAudit(res, opts)
	if err != nil {
		t.Fatal(err)
	}
	csv, err := FindingsCSV(res, opts)
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{"html": html, "csv": string(csv)} {
		for _, secret := range []string{"payments-prod", "111122223333", "vol-0123456789abcdef0", "i-secret", "billing-stream", "postgres1-2025-2026", "client-prod"} {
			if strings.Contains(doc, secret) {
				t.Errorf("%s leaks %q", name, secret)
			}
		}
	}
	// evidence text that quoted a real name is scrubbed, not dropped
	if !strings.Contains(html, "no target groups for 14d") {
		t.Error("evidence text must survive anonymisation")
	}
	if !strings.Contains(html, "ACCOUNT") {
		t.Error("account should be shown as an alias")
	}
}

func TestCSVNeutralisesFormulas(t *testing.T) {
	b, err := FindingsCSV(sampleScan(), AuditOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, ",=HYPERLINK") || strings.Contains(s, "\n=HYPERLINK") {
		t.Fatalf("a cell starting with = would run in a spreadsheet:\n%s", s)
	}
	if !strings.Contains(s, "'=HYPERLINK") {
		t.Fatalf("formula should be defused with a leading quote:\n%s", s)
	}
	if !strings.HasPrefix(s, "kind,name,type,region,monthly_cost_usd") {
		t.Fatalf("header: %q", strings.SplitN(s, "\n", 2)[0])
	}
	// acknowledged rows are marked, and ordered after nothing is lost
	if !strings.Contains(s, "billing-stream") || !strings.Contains(s, ",yes,low traffic by design") {
		t.Fatalf("acknowledged row missing:\n%s", s)
	}
}

func TestLogoValidation(t *testing.T) {
	png, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
	uri, err := LogoFromBytes(png)
	if err != nil || !strings.HasPrefix(uri, "data:image/png;base64,") {
		t.Fatalf("png: %v %q", err, uri)
	}
	if _, err := LogoFromBytes([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)); err == nil {
		t.Fatal("svg with script must be refused")
	}
	if _, err := LogoFromBytes([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>`)); err != nil {
		t.Fatalf("plain svg: %v", err)
	}
	if _, err := LogoFromBytes([]byte("MZ\x90\x00 not an image")); err == nil {
		t.Fatal("arbitrary bytes must be refused")
	}
	if _, err := LogoFromBytes(make([]byte, 300<<10)); err == nil {
		t.Fatal("oversize logo must be refused")
	}
	// it must survive escaping and appear as an image
	html, err := RenderAudit(sampleScan(), AuditOptions{LogoDataURI: uri, Now: time.Now()})
	if err != nil || !strings.Contains(html, `<img src="data:image/png;base64,`) {
		t.Fatalf("logo not embedded: %v", err)
	}
}

// Names the scan did not know about must not get through either: an ARN in a
// note, an opaque recommendation id, an account number.
func TestAnonymizerScrubsShapesNotJustKnownNames(t *testing.T) {
	a := newAnonymizer(true, engine.ScanResult{})
	got := a.scrub("arn:aws:iam::123456789012:user/alice and recommendation 7385e8238fd5cdfc")
	if strings.Contains(got, "123456789012") || strings.Contains(got, "7385e8238fd5cdfc") {
		t.Fatalf("%q", got)
	}
	if !strings.Contains(got, "ACCOUNT") {
		t.Fatalf("account numbers become ACCOUNT: %q", got)
	}
	// a short hex-looking word is not an identifier
	if got := a.scrub("deadbeef cafe"); got != "deadbeef cafe" {
		t.Fatalf("%q", got)
	}
	off := newAnonymizer(false, engine.ScanResult{})
	if off.scrub("123456789012") != "123456789012" {
		t.Fatal("without --anonymize nothing is changed")
	}
}

func TestPillarSectionsCarrySourcesAndNeverLeakResourceNames(t *testing.T) {
	res := sampleScan()
	res.Findings = append(res.Findings,
		engine.Finding{ID: "x1", Pillar: engine.PillarSecurity, Source: "security-hub", Rule: "sh.s3", Severity: engine.SevHigh,
			Title: "S3 buckets should block public access", Affected: 2, Resources: []string{"customer-secret-bucket", "other-bucket"},
			Recommendation: "Enable Block Public Access."},
		engine.Finding{ID: "x2", Pillar: engine.PillarSecurity, Source: "own", Rule: "sec.iam-user-no-mfa", Severity: engine.SevHigh,
			Title: "2 IAM users can sign in without MFA", Affected: 2, Resources: []string{"alice.smith", "bob.jones"}},
	)
	engine.Finalize(&res, nil)
	html, err := RenderAudit(res, AuditOptions{Client: "ACME", Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Security Hub", "S3 buckets should block public access", "What to do first", "alice.smith", "Where the findings are"} {
		if !strings.Contains(html, want) {
			t.Errorf("document lacks %q", want)
		}
	}
	anon, err := RenderAudit(res, AuditOptions{Client: "ACME", Anonymize: true, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"alice.smith", "bob.jones", "customer-secret-bucket", "other-bucket"} {
		if strings.Contains(anon, secret) {
			t.Errorf("anonymised document leaks %q", secret)
		}
	}
	if !strings.Contains(anon, "S3 buckets should block public access") {
		t.Error("titles and recommendations must survive anonymisation")
	}
}

func TestAnonymisedDocumentScrubsIaCNotes(t *testing.T) {
	res := sampleScan()
	res.IaC = &engine.IaCSummary{Notes: []string{"bucket acme-prod-tfstate-111122223333 looks like Terraform state"}}
	res.Nodes = append(res.Nodes, engine.ResourceNode{ID: "acme-prod-tfstate-111122223333", Name: "acme-prod-tfstate-111122223333", Type: "aws_s3_bucket", Region: "eu-west-1"})
	anon, err := RenderAudit(res, AuditOptions{Client: "ACME", Anonymize: true, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(anon, "acme-prod-tfstate") || strings.Contains(anon, "111122223333") {
		t.Fatal("IaC note leaks a bucket name or account number into the anonymised document")
	}
}
