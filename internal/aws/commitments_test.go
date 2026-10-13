package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	ceTypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	osTypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/savingsplans"
)

var now = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func ptr(t time.Time) *time.Time { return &t }

func TestClassifyReservation(t *testing.T) {
	d := func(days int) *time.Time { return ptr(now.AddDate(0, 0, days)) }
	cases := []struct {
		name     string
		cm       engine.Commitment
		keep     bool
		wantSugg bool
	}{
		{"active, far from end", engine.Commitment{State: "active", End: d(200)}, true, false},
		{"active, ending soon asks for a decision", engine.Commitment{State: "active", End: d(20)}, true, true},
		{"lapsed recently is shown as a fact only", engine.Commitment{State: "retired", End: d(-30)}, true, false},
		{"lapsed long ago is history", engine.Commitment{State: "retired", End: d(-400)}, false, false},
		{"unknown end, active", engine.Commitment{State: "active"}, true, false},
		{"unknown end, retired", engine.Commitment{State: "retired"}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keep, facts, sugg := classifyReservation(c.cm, now)
			if keep != c.keep || (len(sugg) > 0) != c.wantSugg {
				t.Fatalf("keep=%v sugg=%v facts=%v", keep, sugg, facts)
			}
			if keep && c.cm.End != nil && len(facts) == 0 {
				t.Fatal("a kept reservation needs a fact line")
			}
		})
	}
}

// The product rule: no wording may assert a loss. Suggestions are conditional.
func TestCoverageNotesAreConditionalNeverAssertive(t *testing.T) {
	_, sugg := coverageNotes(svcOpenSearch,
		coverage{pct: 40, onDemand: 4000, reserved: 2700, running: 6700},
		coverage{pct: 20, onDemand: 1000, reserved: 250, running: 1250}, 0)
	if len(sugg) != 1 {
		t.Fatalf("one suggestion expected, got %v", sugg)
	}
	s := strings.ToLower(sugg[0])
	for _, banned := range []string{"waste", "wasted", "loss", "losing", "overpay", "you should", "must"} {
		if strings.Contains(s, banned) {
			t.Errorf("assertive wording %q in %q", banned, sugg[0])
		}
	}
	if !strings.Contains(s, "if ") || !strings.Contains(s, "migration") || !strings.Contains(s, "cannot know") {
		t.Errorf("suggestion must name the plan it depends on: %q", sugg[0])
	}
}

func TestCoverageNotesQuietWhenThereIsNothingToSay(t *testing.T) {
	// well covered
	if _, s := coverageNotes(svcRDS, coverage{pct: 95, onDemand: 300, running: 6000}, coverage{pct: 95, running: 1000}, 0); len(s) != 0 {
		t.Fatalf("well-covered service: %v", s)
	}
	// uncovered last month but recovered this month (reservation bought on the 30th)
	facts, s := coverageNotes(svcRDS, coverage{pct: 38, onDemand: 4492, running: 7200}, coverage{pct: 96, onDemand: 40, running: 1000}, 0)
	if len(s) != 0 {
		t.Fatalf("recovered coverage must not produce a suggestion: %v", s)
	}
	if !strings.Contains(strings.Join(facts, " "), "recovered") {
		t.Fatalf("recovery should be stated as a fact: %v", facts)
	}
	// negligible on-demand usage
	if _, s := coverageNotes(svcEC2, coverage{pct: 0, onDemand: 50, running: 50}, coverage{}, 0); len(s) != 0 {
		t.Fatalf("tiny usage must stay quiet: %v", s)
	}
	// month just started: not enough data to claim anything about this month
	if _, s := coverageNotes(svcOpenSearch, coverage{pct: 30, onDemand: 5000, running: 7000}, coverage{running: 10}, 0); len(s) != 1 {
		t.Fatalf("with no month-to-date data the last month decides: %v", s)
	}
}

func TestUnusedReservedHoursAreReportedNeutrally(t *testing.T) {
	facts, sugg := coverageNotes(svcRDS, coverage{pct: 100, running: 2000}, coverage{}, 360)
	if !strings.Contains(strings.Join(facts, " "), "360 reserved hours went unused") {
		t.Fatalf("facts = %v", facts)
	}
	if len(sugg) != 1 || !strings.Contains(sugg[0], "If instances were resized") {
		t.Fatalf("suggestion must state the benign explanation first: %v", sugg)
	}
}

// ---- scanners with fakes ------------------------------------------------------

type fakeCE struct {
	cov    map[string]map[string]*ceTypes.CoverageHours // service -> start date -> hours
	unused map[string]string
	err    map[string]error
	// accounts is how many linked accounts the caller can see in Cost Explorer
	accounts int
}

func (f fakeCE) GetReservationCoverage(_ context.Context, in *costexplorer.GetReservationCoverageInput, _ ...func(*costexplorer.Options)) (*costexplorer.GetReservationCoverageOutput, error) {
	svc := in.Filter.Dimensions.Values[0]
	if err := f.err[svc]; err != nil {
		return nil, err
	}
	h := f.cov[svc][aws.ToString(in.TimePeriod.Start)]
	if h == nil {
		h = &ceTypes.CoverageHours{}
	}
	return &costexplorer.GetReservationCoverageOutput{Total: &ceTypes.Coverage{CoverageHours: h}}, nil
}
func (f fakeCE) GetReservationUtilization(_ context.Context, in *costexplorer.GetReservationUtilizationInput, _ ...func(*costexplorer.Options)) (*costexplorer.GetReservationUtilizationOutput, error) {
	u := f.unused[in.Filter.Dimensions.Values[0]]
	return &costexplorer.GetReservationUtilizationOutput{Total: &ceTypes.ReservationAggregates{UnusedHours: aws.String(u)}}, nil
}

func (f fakeCE) GetDimensionValues(context.Context, *costexplorer.GetDimensionValuesInput, ...func(*costexplorer.Options)) (*costexplorer.GetDimensionValuesOutput, error) {
	out := &costexplorer.GetDimensionValuesOutput{}
	for i := 0; i < f.accounts; i++ {
		out.DimensionValues = append(out.DimensionValues, ceTypes.DimensionValuesWithAttributes{Value: aws.String("acct")})
	}
	return out, nil
}

type fakeSP struct{}

func (fakeSP) DescribeSavingsPlans(context.Context, *savingsplans.DescribeSavingsPlansInput, ...func(*savingsplans.Options)) (*savingsplans.DescribeSavingsPlansOutput, error) {
	return &savingsplans.DescribeSavingsPlansOutput{}, nil
}

func hours(pct, od, res, run string) *ceTypes.CoverageHours {
	return &ceTypes.CoverageHours{CoverageHoursPercentage: aws.String(pct), OnDemandHours: aws.String(od),
		ReservedHours: aws.String(res), TotalRunningHours: aws.String(run)}
}

func TestScanCoverage(t *testing.T) {
	ce := fakeCE{
		cov: map[string]map[string]*ceTypes.CoverageHours{
			svcOpenSearch: {"2026-09-01": hours("85", "1193", "6727", "7920"), "2026-10-01": hours("90", "20", "200", "220")},
			svcRDS:        {"2026-09-01": hours("37.6", "4492", "2708", "7200"), "2026-10-01": hours("30", "700", "300", "1000")},
			// EC2: no usage of a reservable kind at all
		},
		unused: map[string]string{svcRDS: "0"},
		err:    map[string]error{"Amazon Redshift": errors.New("AccessDenied")},
	}
	c := newTestCollector()
	scanCoverageWith(context.Background(), ce, fakeSP{}, c, now)

	by := map[string]engine.Commitment{}
	for _, cm := range c.commits {
		by[cm.Service] = cm
	}
	if _, ok := by[svcEC2]; ok {
		t.Fatal("a service with no running hours must not appear")
	}
	if len(by[svcOpenSearch].Suggestions) != 0 {
		t.Fatalf("85%% covered needs no suggestion: %v", by[svcOpenSearch].Suggestions)
	}
	rdsC := by[svcRDS]
	if len(rdsC.Suggestions) != 1 || rdsC.CoveragePct < 37 || rdsC.OnDemandHours != 4492 {
		t.Fatalf("rds: %+v", rdsC)
	}
	if len(c.warnings) != 1 || !strings.Contains(c.warnings[0], "Redshift") {
		t.Fatalf("a failing service must be a warning, not silence: %v", c.warnings)
	}
}

type fakeRDSRI struct{ out []rdsTypes.ReservedDBInstance }

func (f fakeRDSRI) DescribeReservedDBInstances(context.Context, *rds.DescribeReservedDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeReservedDBInstancesOutput, error) {
	return &rds.DescribeReservedDBInstancesOutput{ReservedDBInstances: f.out}, nil
}

type fakeOSRI struct{ out []osTypes.ReservedInstance }

func (f fakeOSRI) DescribeReservedInstances(context.Context, *opensearch.DescribeReservedInstancesInput, ...func(*opensearch.Options)) (*opensearch.DescribeReservedInstancesOutput, error) {
	return &opensearch.DescribeReservedInstancesOutput{ReservedInstances: f.out}, nil
}

type fakeEC2RI struct{}

func (fakeEC2RI) DescribeReservedInstances(context.Context, *ec2.DescribeReservedInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeReservedInstancesOutput, error) {
	return &ec2.DescribeReservedInstancesOutput{}, nil
}

func TestScanReservations(t *testing.T) {
	year := int32(365 * 24 * 3600)
	api := reservationsAPI{
		rds: fakeRDSRI{[]rdsTypes.ReservedDBInstance{
			{ReservedDBInstanceId: aws.String("active-far"), DBInstanceClass: aws.String("db.r6g.large"), DBInstanceCount: aws.Int32(2),
				State: aws.String("active"), StartTime: ptr(now.AddDate(0, -1, 0)), Duration: aws.Int32(year)},
			{ReservedDBInstanceId: aws.String("lapsed-old"), DBInstanceClass: aws.String("db.t4g.medium"), DBInstanceCount: aws.Int32(4),
				State: aws.String("retired"), StartTime: ptr(now.AddDate(-3, 0, 0)), Duration: aws.Int32(year)},
		}},
		os: fakeOSRI{[]osTypes.ReservedInstance{
			{ReservedInstanceId: aws.String("os-ending"), InstanceType: osTypes.OpenSearchPartitionInstanceType("r6g.large.search"),
				InstanceCount: 3, State: aws.String("active"), StartTime: ptr(now.AddDate(0, 0, -340)), Duration: int32(year)},
			{ReservedInstanceId: aws.String("os-just-lapsed"), InstanceType: osTypes.OpenSearchPartitionInstanceType("c6g.xlarge.search"),
				InstanceCount: 3, State: aws.String("retired"), StartTime: ptr(now.AddDate(-1, 0, -16)), Duration: int32(year)},
		}},
		ec2: fakeEC2RI{},
	}
	c := newTestCollector()
	scanReservationsWith(context.Background(), api, c, now)

	got := map[string]engine.Commitment{}
	for _, cm := range c.commits {
		got[cm.ID] = cm
	}
	if _, ok := got["lapsed-old"]; ok {
		t.Fatal("a reservation that lapsed years ago is history")
	}
	if cm := got["active-far"]; len(cm.Suggestions) != 0 || cm.Region != "eu-north-1" {
		t.Fatalf("active-far: %+v", cm)
	}
	if cm := got["os-ending"]; len(cm.Suggestions) != 1 {
		t.Fatalf("a reservation ending inside 60 days asks for a decision: %+v", cm)
	}
	lapsed := got["os-just-lapsed"]
	if len(lapsed.Suggestions) != 0 || !strings.Contains(strings.Join(lapsed.Facts, " "), "ended") {
		t.Fatalf("a recent lapse is a fact, not a verdict: %+v", lapsed)
	}
}

// Regression from a live run: coverage was 85% last month and 45% this month
// after reservations ended. With only a last-month rule nothing was said.
func TestCoverageDropThisMonthIsSurfaced(t *testing.T) {
	facts, sugg := coverageNotes(svcOpenSearch,
		coverage{pct: 85, onDemand: 1193, reserved: 6727, running: 7920},
		coverage{pct: 45, onDemand: 1662, reserved: 1350, running: 3012}, 0)
	if len(sugg) != 1 {
		t.Fatalf("a drop from 85%% to 45%% must prompt once: %v", sugg)
	}
	if !strings.Contains(strings.Join(facts, " "), "fell from 85% to 45%") {
		t.Fatalf("the drop should be stated as a fact: %v", facts)
	}
	if !strings.Contains(sugg[0], "If a migration") {
		t.Fatalf("must name the plan it depends on: %q", sugg[0])
	}
	// but a small residue of on-demand hours is noise
	if _, s := coverageNotes(svcOpenSearch, coverage{pct: 90, onDemand: 700, running: 7000}, coverage{pct: 60, onDemand: 60, running: 150}, 0); len(s) != 0 {
		t.Fatalf("a few on-demand hours must stay quiet: %v", s)
	}
}

func TestPayerScopeIsLabelled(t *testing.T) {
	ce := fakeCE{
		cov:      map[string]map[string]*ceTypes.CoverageHours{svcRDS: {"2026-09-01": hours("48", "6004", "5509", "11513")}},
		accounts: 9,
	}
	c := newTestCollector()
	scanCoverageWith(context.Background(), ce, fakeSP{}, c, now)
	if len(c.commits) != 1 {
		t.Fatalf("commits: %+v", c.commits)
	}
	cm := c.commits[0]
	if !strings.Contains(cm.Detail, "organization-wide: 9 linked accounts") {
		t.Fatalf("scope missing from detail: %q", cm.Detail)
	}
	ce.accounts = 1
	c2 := newTestCollector()
	scanCoverageWith(context.Background(), ce, fakeSP{}, c2, now)
	if strings.Contains(c2.commits[0].Detail, "organization-wide") {
		t.Fatal("a single-account view must not be labelled organization-wide")
	}
}
