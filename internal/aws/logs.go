package aws

import (
	"context"
	"fmt"
	"time"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

const gb = 1 << 30

type logGroup struct {
	name       string
	arn        string
	storedGB   float64
	retention  int32
	ingestedGB float64 // over the idle window, scaled to 30 days
	points     int
}

func scanLogGroups(ctx context.Context, cfg aws.Config, c *collector) {
	cli := cloudwatchlogs.NewFromConfig(cfg)
	cw := cloudwatch.NewFromConfig(cfg)

	var groups []*logGroup
	p := cloudwatchlogs.NewDescribeLogGroupsPaginator(cli, &cloudwatchlogs.DescribeLogGroupsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("logs:groups", err)
			return
		}
		for _, g := range page.LogGroups {
			groups = append(groups, &logGroup{
				name: aws.ToString(g.LogGroupName), arn: trimLogARN(aws.ToString(g.Arn)),
				storedGB: float64(aws.ToInt64(g.StoredBytes)) / gb, retention: aws.ToInt32(g.RetentionInDays),
			})
		}
	}
	if len(groups) == 0 {
		return
	}
	if err := fillIngestion(ctx, cw, groups, c.th.IdleWindowDays); err != nil {
		c.warn("cloudwatch:logs", err)
	}

	var small float64
	var smallCount int
	for _, g := range groups {
		cost := engine.LogGroupMonthlyCost(g.ingestedGB, g.storedGB)
		if cost < c.th.LogMinCost {
			small += cost
			smallCount++
			continue
		}
		n := engine.ResourceNode{
			ID: g.arn, Name: g.name, Type: "aws_cloudwatch_log_group", Group: "LOGS",
			Status: engine.StatusUnknown, Confidence: engine.ConfLow,
			MonthlyCost: cost, CostSource: engine.CostEstimated,
			Attrs: map[string]string{
				"stored_gb":       fmt.Sprintf("%.1f", g.storedGB),
				"ingested_gb_30d": fmt.Sprintf("%.1f", g.ingestedGB),
				"retention_days":  retentionLabel(g.retention),
			},
			Evidence: []string{"tags not fetched for log groups, ownership not classified"},
		}
		if g.retention == 0 && g.storedGB >= c.th.LogMinStoredGB {
			n.Evidence = append(n.Evidence, fmt.Sprintf("never expires: %.0f GB stored indefinitely", g.storedGB))
		}
		if g.points > 0 && g.ingestedGB == 0 && g.retention == 0 && g.storedGB >= c.th.LogMinStoredGB {
			markWaste(&n, "Log group without ingestion and without retention", engine.ConfMedium,
				fmt.Sprintf("no new data for %d days, %.0f GB kept forever", c.th.IdleWindowDays, g.storedGB))
		}
		c.add(n)
	}
	if smallCount > 0 {
		c.add(engine.ResourceNode{
			ID: "loggroups-small-" + c.region, Name: fmt.Sprintf("%d small log groups", smallCount),
			Type: "aws_cloudwatch_log_group_rollup", Group: "LOGS", Status: engine.StatusUnknown,
			MonthlyCost: small, CostSource: engine.CostEstimated,
			Evidence: []string{fmt.Sprintf("each under $%.0f/month, rolled up", c.th.LogMinCost)},
		})
	}
}

// fillIngestion reads IncomingBytes for all groups with GetMetricData,
// 500 queries per call.
func fillIngestion(ctx context.Context, cw *cloudwatch.Client, groups []*logGroup, days int) error {
	end := time.Now().UTC().Truncate(time.Hour)
	start := end.AddDate(0, 0, -days)
	scale := 30.0 / float64(days)

	for i := 0; i < len(groups); i += 500 {
		batch := groups[i:min(i+500, len(groups))]
		queries := make([]cwTypes.MetricDataQuery, len(batch))
		for j, g := range batch {
			queries[j] = cwTypes.MetricDataQuery{
				Id: aws.String(fmt.Sprintf("q%d", j)),
				MetricStat: &cwTypes.MetricStat{
					Metric: &cwTypes.Metric{
						Namespace: aws.String("AWS/Logs"), MetricName: aws.String("IncomingBytes"),
						Dimensions: []cwTypes.Dimension{{Name: aws.String("LogGroupName"), Value: aws.String(g.name)}},
					},
					Period: aws.Int32(86400), Stat: aws.String("Sum"),
				},
				ReturnData: aws.Bool(true),
			}
		}
		p := cloudwatch.NewGetMetricDataPaginator(cw, &cloudwatch.GetMetricDataInput{
			StartTime: aws.Time(start), EndTime: aws.Time(end), MetricDataQueries: queries,
		})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return err
			}
			for _, r := range page.MetricDataResults {
				var j int
				if _, err := fmt.Sscanf(aws.ToString(r.Id), "q%d", &j); err != nil || j >= len(batch) {
					continue
				}
				var sum float64
				for _, v := range r.Values {
					sum += v
				}
				batch[j].ingestedGB += sum / gb * scale
				batch[j].points += len(r.Values)
			}
		}
	}
	return nil
}

func retentionLabel(d int32) string {
	if d == 0 {
		return "never"
	}
	return fmt.Sprint(d)
}

// trimLogARN drops the trailing ":*" CloudWatch adds to log group ARNs.
func trimLogARN(arn string) string {
	if n := len(arn); n > 2 && arn[n-2:] == ":*" {
		return arn[:n-2]
	}
	return arn
}

func init() {
	register(Scanner{
		Name: "logs", Desc: "CloudWatch log groups: ingestion, retention",
		Types:    map[string]string{"aws_cloudwatch_log_group": "AmazonCloudWatch", "aws_cloudwatch_log_group_rollup": "AmazonCloudWatch"},
		Regional: scanLogGroups,
	})
}
