package aws

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	ceTypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

// CostSummary is the Cost Explorer view of the last two months.
type CostSummary struct {
	Services  []engine.ServiceCost
	PrevTotal float64
	CurrTotal float64
}

// GetServiceCosts returns previous and current month cost per AWS service.
// Cost Explorer is a global API served from us-east-1.
func (dc *DiscoveryClient) GetServiceCosts(ctx context.Context) (CostSummary, error) {
	cfg, err := dc.loadConfig(ctx, "us-east-1")
	if err != nil {
		return CostSummary{}, err
	}
	now := time.Now().UTC()
	startCurr := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	startPrev := startCurr.AddDate(0, -1, 0)
	endCurr := startCurr.AddDate(0, 1, 0) // End is exclusive

	out, err := costexplorer.NewFromConfig(cfg).GetCostAndUsage(ctx, &costexplorer.GetCostAndUsageInput{
		TimePeriod: &ceTypes.DateInterval{
			Start: aws.String(startPrev.Format("2006-01-02")),
			End:   aws.String(endCurr.Format("2006-01-02")),
		},
		Granularity: ceTypes.GranularityMonthly,
		Metrics:     []string{"UnblendedCost"},
		// Usage only: tax, support and reservation upfront fees are not
		// something a resource scan can explain or optimise.
		Filter: &ceTypes.Expression{Dimensions: &ceTypes.DimensionValues{
			Key: ceTypes.DimensionRecordType, Values: []string{"Usage"},
		}},
		GroupBy: []ceTypes.GroupDefinition{{Type: ceTypes.GroupDefinitionTypeDimension, Key: aws.String("SERVICE")}},
	})
	if err != nil {
		return CostSummary{}, err
	}

	prevName, currName := startPrev.Format("Jan"), startCurr.Format("Jan")
	byService := map[string]*engine.ServiceCost{}
	var sum CostSummary
	for _, r := range out.ResultsByTime {
		isCurr := strings.HasPrefix(aws.ToString(r.TimePeriod.Start), startCurr.Format("2006-01"))
		for _, g := range r.Groups {
			svc := "Other"
			if len(g.Keys) > 0 {
				svc = g.Keys[0]
			}
			var val float64
			if m, ok := g.Metrics["UnblendedCost"]; ok && m.Amount != nil {
				val = parseFloat(*m.Amount)
			}
			sc := byService[svc]
			if sc == nil {
				sc = &engine.ServiceCost{Service: svc}
				sc.PreviousMonthName, sc.CurrentMonthName = prevName, currName
				byService[svc] = sc
			}
			if isCurr {
				sc.CurrentMonthCost += val
				sum.CurrTotal += val
			} else {
				sc.PreviousMonthCost += val
				sum.PrevTotal += val
			}
		}
	}
	for _, sc := range byService {
		if sc.PreviousMonthCost > 0 {
			sc.TrendPct = (sc.CurrentMonthCost - sc.PreviousMonthCost) / sc.PreviousMonthCost * 100
		}
		sum.Services = append(sum.Services, *sc)
	}
	sort.Slice(sum.Services, func(i, j int) bool {
		return sum.Services[i].CurrentMonthCost+sum.Services[i].PreviousMonthCost >
			sum.Services[j].CurrentMonthCost+sum.Services[j].PreviousMonthCost
	})
	return sum, nil
}

func parseFloat(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0 // Cost Explorer returns plain decimals; anything else counts as zero
	}
	return f
}

// usageAPI is the part of Cost Explorer the usage reader needs.
type usageAPI interface {
	GetCostAndUsage(ctx context.Context, in *costexplorer.GetCostAndUsageInput, opts ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error)
}

// GetUsageLines reads the last full month's usage as dollars per service and
// usage type. These are real billed amounts; the cost ledger attributes them
// to resources. It costs a few Cost Explorer requests (about $0.01 each).
func (dc *DiscoveryClient) GetUsageLines(ctx context.Context) ([]engine.UsageLine, string, error) {
	cfg, err := dc.loadConfig(ctx, "us-east-1")
	if err != nil {
		return nil, "", err
	}
	return usageLinesWith(ctx, costexplorer.NewFromConfig(cfg), time.Now().UTC())
}

func usageLinesWith(ctx context.Context, api usageAPI, now time.Time) ([]engine.UsageLine, string, error) {
	thisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	start := thisMonth.AddDate(0, -1, 0)
	in := &costexplorer.GetCostAndUsageInput{
		TimePeriod: &ceTypes.DateInterval{
			Start: aws.String(start.Format("2006-01-02")), End: aws.String(thisMonth.Format("2006-01-02")),
		},
		Granularity: ceTypes.GranularityMonthly,
		Metrics:     []string{"UnblendedCost", "UsageQuantity"},
		Filter: &ceTypes.Expression{Dimensions: &ceTypes.DimensionValues{
			Key: ceTypes.DimensionRecordType, Values: []string{"Usage"},
		}},
		GroupBy: []ceTypes.GroupDefinition{
			{Type: ceTypes.GroupDefinitionTypeDimension, Key: aws.String("SERVICE")},
			{Type: ceTypes.GroupDefinitionTypeDimension, Key: aws.String("USAGE_TYPE")},
		},
	}
	var lines []engine.UsageLine
	for {
		out, err := api.GetCostAndUsage(ctx, in)
		if err != nil {
			return nil, "", err
		}
		for _, r := range out.ResultsByTime {
			for _, g := range r.Groups {
				if len(g.Keys) < 2 {
					continue
				}
				l := engine.UsageLine{Service: g.Keys[0], UsageType: g.Keys[1]}
				if m, ok := g.Metrics["UnblendedCost"]; ok {
					l.Cost = parseFloat(aws.ToString(m.Amount))
				}
				if m, ok := g.Metrics["UsageQuantity"]; ok {
					l.Quantity = parseFloat(aws.ToString(m.Amount))
				}
				lines = append(lines, l)
			}
		}
		if out.NextPageToken == nil || *out.NextPageToken == "" {
			break
		}
		in.NextPageToken = out.NextPageToken
	}
	return lines, start.Format("2006-01"), nil
}
