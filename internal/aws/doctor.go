package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	ceTypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"time"
)

// DoctorResult is the outcome of one access probe.
type DoctorResult struct {
	Name     string
	Scope    string
	OK       bool
	Problems []string
}

// Doctor checks, before an engagement starts, which parts of a scan will
// work with the credentials at hand. Each check is run on its own against one
// region and reported separately, so "what will be missing" is known up front
// instead of discovered as warnings in a finished report.
func (dc *DiscoveryClient) Doctor(ctx context.Context, region string) []DoctorResult {
	var out []DoctorResult
	add := func(name, scope string, problems []string) {
		out = append(out, DoctorResult{Name: name, Scope: scope, OK: len(problems) == 0, Problems: problems})
	}

	if acct, err := dc.AccountID(ctx); err != nil {
		add("identity", "account", []string{oneLineErr(err)})
		return out // nothing else can work
	} else {
		add("identity", "account "+acct, nil)
	}

	cfg, err := dc.loadConfig(ctx, region)
	if err != nil {
		add("config", region, []string{oneLineErr(err)})
		return out
	}
	if _, err := ec2.NewFromConfig(cfg).DescribeRegions(ctx, &ec2.DescribeRegionsInput{}); err != nil {
		add("regions", "ec2:DescribeRegions", []string{oneLineErr(err)})
	} else {
		add("regions", "ec2:DescribeRegions", nil)
	}
	ceCfg, _ := dc.loadConfig(ctx, "us-east-1")
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -1, 0)
	end := start.AddDate(0, 1, 0)
	_, ceErr := costexplorer.NewFromConfig(ceCfg).GetCostAndUsage(ctx, &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &ceTypes.DateInterval{Start: aws.String(start.Format("2006-01-02")), End: aws.String(end.Format("2006-01-02"))},
		Granularity: ceTypes.GranularityMonthly, Metrics: []string{"UnblendedCost"},
	})
	if ceErr != nil {
		add("cost-explorer", "ce:GetCostAndUsage", []string{oneLineErr(ceErr)})
	} else {
		add("cost-explorer", "ce:GetCostAndUsage", nil)
	}

	for _, sc := range dc.Scanners {
		c := newCollector(region, dc.Th)
		scope := "region " + region
		switch {
		case sc.Regional != nil:
			sc.Regional(ctx, cfg, c)
		case sc.Global != nil:
			scope = "account"
			sc.Global(ctx, dc, c)
		}
		add(sc.Name, scope, c.warnings)
	}
	sort.SliceStable(out, func(i, j int) bool { return !out[i].OK && out[j].OK })
	return out
}

func oneLineErr(err error) string {
	return firstLine(strings.Join(strings.Fields(err.Error()), " "), 220)
}

// DoctorSummary turns the results into a short verdict for an engagement.
func DoctorSummary(rs []DoctorResult) (ok, failed int, lines []string) {
	for _, r := range rs {
		if r.OK {
			ok++
			continue
		}
		failed++
		lines = append(lines, fmt.Sprintf("%s (%s): %s", r.Name, r.Scope, strings.Join(r.Problems, "; ")))
	}
	return
}
