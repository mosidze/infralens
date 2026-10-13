package aws

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	ceTypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/savingsplans"
)

// Commitments are reported as facts plus suggestions that depend on plans
// the tool cannot know (a migration, a resize, a shutdown). Nothing here is
// ever called waste or loss: whether a lapsed or uncovered commitment is a
// problem is the owner's decision, and `--context` is how they tell the tool.

const (
	svcRDS        = "Amazon Relational Database Service"
	svcOpenSearch = "Amazon OpenSearch Service"
	svcEC2        = "Amazon Elastic Compute Cloud - Compute"

	// recentlyEnded: lapsed reservations older than this are history, not news.
	recentlyEnded = 120 * 24 * time.Hour
	// expiringSoon: an active reservation ending inside this window gets a decision prompt.
	expiringSoon = 60 * 24 * time.Hour
	// minOnDemandHours: below this a service's on-demand usage is too small to suggest anything
	// (about 0.3 instance-months).
	minOnDemandHours = 200.0
	// minMTDHours: month-to-date coverage is only trusted with at least 3 days of data.
	minMTDHours = 72.0
	// minMTDOnDemandHours: on-demand hours this month before a coverage drop is worth a prompt.
	minMTDOnDemandHours = 100.0
)

// ---- reservations (regional) ------------------------------------------------

type reservationsAPI struct {
	rds rds.DescribeReservedDBInstancesAPIClient
	os  interface {
		DescribeReservedInstances(ctx context.Context, in *opensearch.DescribeReservedInstancesInput, opts ...func(*opensearch.Options)) (*opensearch.DescribeReservedInstancesOutput, error)
	}
	ec2 interface {
		DescribeReservedInstances(ctx context.Context, in *ec2.DescribeReservedInstancesInput, opts ...func(*ec2.Options)) (*ec2.DescribeReservedInstancesOutput, error)
	}
}

func scanReservations(ctx context.Context, cfg aws.Config, c *collector) {
	scanReservationsWith(ctx, reservationsAPI{
		rds: rds.NewFromConfig(cfg), os: opensearch.NewFromConfig(cfg), ec2: ec2.NewFromConfig(cfg),
	}, c, time.Now())
}

func scanReservationsWith(ctx context.Context, api reservationsAPI, c *collector, now time.Time) {
	add := func(cm engine.Commitment) {
		cm.Region = c.region
		if keep, facts, sugg := classifyReservation(cm, now); keep {
			cm.Facts, cm.Suggestions = facts, sugg
			c.commit(cm)
		}
	}

	if out, err := api.rds.DescribeReservedDBInstances(ctx, &rds.DescribeReservedDBInstancesInput{}); err != nil {
		c.warn("rds:reserved-instances", err)
	} else {
		for _, r := range out.ReservedDBInstances {
			start := r.StartTime
			var end *time.Time
			if start != nil && r.Duration != nil {
				e := start.Add(time.Duration(*r.Duration) * time.Second)
				end = &e
			}
			add(engine.Commitment{
				Kind: "reservation", Service: svcRDS, ID: aws.ToString(r.ReservedDBInstanceId),
				Detail: fmt.Sprintf("%s: %d × %s, %s", aws.ToString(r.ReservedDBInstanceId), aws.ToInt32(r.DBInstanceCount), aws.ToString(r.DBInstanceClass), aws.ToString(r.OfferingType)),
				State:  aws.ToString(r.State), Start: start, End: end,
			})
		}
	}

	if out, err := api.os.DescribeReservedInstances(ctx, &opensearch.DescribeReservedInstancesInput{}); err != nil {
		c.warn("opensearch:reserved-instances", err)
	} else {
		for _, r := range out.ReservedInstances {
			start := r.StartTime
			var end *time.Time
			if start != nil {
				e := start.Add(time.Duration(r.Duration) * time.Second)
				end = &e
			}
			add(engine.Commitment{
				Kind: "reservation", Service: svcOpenSearch, ID: aws.ToString(r.ReservedInstanceId),
				Detail: fmt.Sprintf("%s: %d × %s, %s", shortID(aws.ToString(r.ReservedInstanceId)), r.InstanceCount, string(r.InstanceType), string(r.PaymentOption)),
				State:  aws.ToString(r.State), Start: start, End: end,
			})
		}
	}

	if out, err := api.ec2.DescribeReservedInstances(ctx, &ec2.DescribeReservedInstancesInput{}); err != nil {
		c.warn("ec2:reserved-instances", err)
	} else {
		for _, r := range out.ReservedInstances {
			add(engine.Commitment{
				Kind: "reservation", Service: svcEC2, ID: aws.ToString(r.ReservedInstancesId),
				Detail: fmt.Sprintf("%s: %d × %s, %s", shortID(aws.ToString(r.ReservedInstancesId)), aws.ToInt32(r.InstanceCount), string(r.InstanceType), string(r.OfferingType)),
				State:  string(r.State), Start: r.Start, End: r.End,
			})
		}
	}
}

// classifyReservation decides whether a reservation is worth showing and what
// to say about it. Pure, so it is tested without AWS.
func classifyReservation(cm engine.Commitment, now time.Time) (keep bool, facts, suggestions []string) {
	active := cm.State == "active" || cm.State == "payment-pending"
	if cm.End == nil {
		return active, nil, nil
	}
	left := cm.End.Sub(now)
	switch {
	case active && left > expiringSoon:
		return true, []string{fmt.Sprintf("active until %s (%d days left)", cm.End.Format("2006-01-02"), int(left.Hours()/24))}, nil
	case active:
		days := int(left.Hours() / 24)
		if days < 0 {
			days = 0
		}
		return true,
			[]string{fmt.Sprintf("ends %s (%d days left)", cm.End.Format("2006-01-02"), days)},
			[]string{"Decide before it ends: renew, resize or let it lapse. The right answer depends on whether this workload stays on AWS for another term, which the scan cannot know."}
	case now.Sub(*cm.End) <= recentlyEnded:
		return true,
			[]string{fmt.Sprintf("ended %s (%d days ago)", cm.End.Format("2006-01-02"), int(now.Sub(*cm.End).Hours()/24))},
			nil // whether a lapse matters is decided by coverage below, not by the fact that it lapsed
	}
	return false, nil, nil
}

// ---- coverage and savings plans (account-wide) -------------------------------

type ceAPI interface {
	GetReservationCoverage(ctx context.Context, in *costexplorer.GetReservationCoverageInput, opts ...func(*costexplorer.Options)) (*costexplorer.GetReservationCoverageOutput, error)
	GetReservationUtilization(ctx context.Context, in *costexplorer.GetReservationUtilizationInput, opts ...func(*costexplorer.Options)) (*costexplorer.GetReservationUtilizationOutput, error)
	GetDimensionValues(ctx context.Context, in *costexplorer.GetDimensionValuesInput, opts ...func(*costexplorer.Options)) (*costexplorer.GetDimensionValuesOutput, error)
}

type spAPI interface {
	DescribeSavingsPlans(ctx context.Context, in *savingsplans.DescribeSavingsPlansInput, opts ...func(*savingsplans.Options)) (*savingsplans.DescribeSavingsPlansOutput, error)
}

var coverageServices = []string{
	svcEC2, svcRDS, svcOpenSearch, "Amazon ElastiCache", "Amazon Redshift", "Amazon MemoryDB",
}

func scanCoverage(ctx context.Context, dc *DiscoveryClient, c *collector) {
	cfg, err := dc.loadConfig(ctx, "us-east-1")
	if err != nil {
		c.warn("coverage:config", err)
		return
	}
	scanCoverageWith(ctx, costexplorer.NewFromConfig(cfg), savingsplans.NewFromConfig(cfg), c, time.Now().UTC())
}

type window struct{ start, end time.Time }

func scanCoverageWith(ctx context.Context, ce ceAPI, sp spAPI, c *collector, now time.Time) {
	thisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	last := window{thisMonth.AddDate(0, -1, 0), thisMonth}
	mtd := window{thisMonth, now.Add(24 * time.Hour).Truncate(24 * time.Hour)}

	// A payer account sees consolidated usage of every linked account, a member
	// sees its own. Say which, or the same service reads differently in two scans.
	scope := ""
	if n := linkedAccounts(ctx, ce, last); n > 1 {
		scope = fmt.Sprintf("organization-wide: %d linked accounts", n)
	}

	for _, svc := range coverageServices {
		lastCov, err := coverageHours(ctx, ce, svc, last)
		if err != nil {
			c.warn("coverage:"+svc, err)
			continue
		}
		if lastCov.running == 0 {
			continue // no usage of a reservable resource: nothing to say
		}
		mtdCov, _ := coverageHours(ctx, ce, svc, mtd)
		util, uerr := unusedReserved(ctx, ce, svc, last)

		cm := engine.Commitment{
			Kind: "coverage", Service: svc,
			Detail:        fmt.Sprintf("last month %.0f%% covered, this month %.0f%%", lastCov.pct, mtdCov.pct),
			CoveragePct:   lastCov.pct,
			OnDemandHours: lastCov.onDemand, ReservedHours: lastCov.reserved,
		}
		if uerr == nil {
			cm.UnusedHours = util
		}
		cm.Facts, cm.Suggestions = coverageNotes(svc, lastCov, mtdCov, util)
		if scope != "" {
			cm.Detail += " (" + scope + ")"
			cm.Facts = append([]string{"scope: " + scope + " (consolidated billing); a member account shows only its own usage"}, cm.Facts...)
		}
		c.commit(cm)
	}

	// Savings Plans live in the payer account; from a member account the list is usually empty.
	if out, err := sp.DescribeSavingsPlans(ctx, &savingsplans.DescribeSavingsPlansInput{}); err != nil {
		c.warn("savingsplans:describe", err)
	} else {
		for _, p := range out.SavingsPlans {
			start, _ := time.Parse(time.RFC3339, aws.ToString(p.Start))
			end, _ := time.Parse(time.RFC3339, aws.ToString(p.End))
			cm := engine.Commitment{
				Kind: "savings_plan", Service: "Savings Plans", ID: aws.ToString(p.SavingsPlanId),
				Detail: fmt.Sprintf("%s, $%s/h, %s", string(p.SavingsPlanType), aws.ToString(p.Commitment), string(p.PaymentOption)),
				State:  string(p.State),
			}
			if !start.IsZero() {
				cm.Start = &start
			}
			if !end.IsZero() {
				cm.End = &end
			}
			if keep, f, s := classifyReservation(cm, now); keep {
				cm.Facts, cm.Suggestions = f, s
				c.commit(cm)
			}
		}
	}
}

type coverage struct{ pct, onDemand, reserved, running float64 }

func coverageHours(ctx context.Context, ce ceAPI, svc string, w window) (coverage, error) {
	if !w.end.After(w.start) {
		return coverage{}, nil
	}
	out, err := ce.GetReservationCoverage(ctx, &costexplorer.GetReservationCoverageInput{
		TimePeriod: &ceTypes.DateInterval{
			Start: aws.String(w.start.Format("2006-01-02")), End: aws.String(w.end.Format("2006-01-02")),
		},
		Filter: &ceTypes.Expression{Dimensions: &ceTypes.DimensionValues{
			Key: ceTypes.DimensionService, Values: []string{svc},
		}},
	})
	if err != nil {
		return coverage{}, err
	}
	var cv coverage
	if out.Total != nil && out.Total.CoverageHours != nil {
		h := out.Total.CoverageHours
		cv.pct = num(h.CoverageHoursPercentage)
		cv.onDemand = num(h.OnDemandHours)
		cv.reserved = num(h.ReservedHours)
		cv.running = num(h.TotalRunningHours)
	}
	return cv, nil
}

func unusedReserved(ctx context.Context, ce ceAPI, svc string, w window) (float64, error) {
	out, err := ce.GetReservationUtilization(ctx, &costexplorer.GetReservationUtilizationInput{
		TimePeriod: &ceTypes.DateInterval{
			Start: aws.String(w.start.Format("2006-01-02")), End: aws.String(w.end.Format("2006-01-02")),
		},
		Filter: &ceTypes.Expression{Dimensions: &ceTypes.DimensionValues{
			Key: ceTypes.DimensionService, Values: []string{svc},
		}},
	})
	if err != nil {
		return 0, err
	}
	if out.Total == nil {
		return 0, nil
	}
	return num(out.Total.UnusedHours), nil
}

func num(p *string) float64 {
	if p == nil {
		return 0
	}
	f, err := strconv.ParseFloat(*p, 64)
	if err != nil {
		return 0
	}
	return f
}

// coverageNotes turns coverage numbers into facts and conditional suggestions.
// Pure and tested. Suggestions always name the plan they depend on.
func coverageNotes(svc string, last, mtd coverage, unusedHours float64) (facts, suggestions []string) {
	facts = append(facts, fmt.Sprintf("last full month: %.0f of %.0f running hours were on-demand (%.0f%% covered)",
		last.onDemand, last.running, last.pct))
	if mtd.running >= minMTDHours {
		facts = append(facts, fmt.Sprintf("this month so far: %.0f%% covered (%.0f on-demand hours)", mtd.pct, mtd.onDemand))
	}
	if unusedHours >= 1 {
		facts = append(facts, fmt.Sprintf("%.0f reserved hours went unused last month (reserved capacity with no matching running instance)", unusedHours))
		suggestions = append(suggestions,
			"Reserved capacity is unmatched by usage. If instances were resized, stopped or moved off AWS this is expected; if not, check what the reservation was bought for.")
	}

	mtdKnown := mtd.running >= minMTDHours
	stillUncovered := !mtdKnown || mtd.pct < 80
	switch {
	case mtdKnown && mtd.pct < 80 && mtd.onDemand >= minMTDOnDemandHours && last.pct >= 80:
		// Coverage was fine last month and fell this month: the usual sign of a
		// reservation that ended and was not renewed.
		facts = append(facts, fmt.Sprintf("coverage fell from %.0f%% to %.0f%% this month", last.pct, mtd.pct))
		suggestions = append(suggestions, fmt.Sprintf(
			"%.0f on-demand hours so far this month. If this workload is expected to keep running for the next 12 months, renewing or replacing the ended reservation would price it lower than on-demand. "+
				"If a migration, resize or shutdown is planned, no action is needed. The scan cannot know your plans.", mtd.onDemand))
	case last.pct < 80 && last.onDemand >= minOnDemandHours && stillUncovered:
		suggestions = append(suggestions, fmt.Sprintf(
			"%.0f on-demand hours last month. If this workload is expected to run for the next 12 months, a reservation or Savings Plan would price it lower than on-demand. "+
				"If a migration, resize or shutdown is planned, no action is needed. The scan cannot know your plans.", last.onDemand))
	}
	if mtdKnown && last.pct < 80 && mtd.pct >= 80 {
		facts = append(facts, "coverage has recovered this month (a reservation was probably bought or renewed)")
	}
	return facts, suggestions
}

func sortCommitments(cs []engine.Commitment) {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].Service != cs[j].Service {
			return cs[i].Service < cs[j].Service
		}
		if cs[i].Kind != cs[j].Kind {
			return cs[i].Kind < cs[j].Kind
		}
		return cs[i].ID < cs[j].ID
	})
}

func init() {
	register(Scanner{
		Name: "reservations", Desc: "Reserved instances (RDS, OpenSearch, EC2): state, term end, decisions due",
		Informational: true, Regional: scanReservations,
	})
	register(Scanner{
		Name: "coverage", Desc: "Reservation coverage and unused hours per service, Savings Plans",
		Informational: true, Global: scanCoverage,
	})
}

// linkedAccounts counts the accounts that have usage in the window; more than
// one means the caller sees consolidated data.
func linkedAccounts(ctx context.Context, ce ceAPI, w window) int {
	out, err := ce.GetDimensionValues(ctx, &costexplorer.GetDimensionValuesInput{
		TimePeriod: &ceTypes.DateInterval{
			Start: aws.String(w.start.Format("2006-01-02")), End: aws.String(w.end.Format("2006-01-02")),
		},
		Dimension: ceTypes.DimensionLinkedAccount,
	})
	if err != nil {
		return 0
	}
	return len(out.DimensionValues)
}

// shortID keeps a UUID readable.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
