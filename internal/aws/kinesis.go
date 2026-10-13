package aws

import (
	"context"
	"fmt"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kTypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
)

// kinesisAPI is what the stream scanner needs from the SDK.
type kinesisAPI interface {
	kinesis.ListStreamsAPIClient
	DescribeStreamSummary(ctx context.Context, in *kinesis.DescribeStreamSummaryInput, opts ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error)
	ListTagsForStream(ctx context.Context, in *kinesis.ListTagsForStreamInput, opts ...func(*kinesis.Options)) (*kinesis.ListTagsForStreamOutput, error)
}

func scanKinesis(ctx context.Context, cfg aws.Config, c *collector) {
	scanKinesisWith(ctx, kinesis.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), c)
}

func scanKinesisWith(ctx context.Context, cli kinesisAPI, cw metricsAPI, c *collector) {

	p := kinesis.NewListStreamsPaginator(cli, &kinesis.ListStreamsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("kinesis:streams", err)
			return
		}
		for _, name := range page.StreamNames {
			sum, err := cli.DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{StreamName: aws.String(name)})
			if err != nil {
				c.warn("kinesis:describe", err)
				continue
			}
			d := sum.StreamDescriptionSummary
			var tags map[string]string
			if tl, err := cli.ListTagsForStream(ctx, &kinesis.ListTagsForStreamInput{StreamName: aws.String(name)}); err == nil {
				tags = tagMap(tl.Tags, func(t kTypes.Tag) (string, string) { return aws.ToString(t.Key), aws.ToString(t.Value) })
			}
			onDemand := d.StreamModeDetails != nil && d.StreamModeDetails.StreamMode == kTypes.StreamModeOnDemand
			shards := int(aws.ToInt32(d.OpenShardCount))
			mode := "PROVISIONED"
			if onDemand {
				mode = "ON_DEMAND"
			}
			n := engine.ResourceNode{
				ID: aws.ToString(d.StreamARN), Name: name, Type: "aws_kinesis_stream", Group: parseGroup(name),
				MonthlyCost: engine.KinesisMonthlyCost(onDemand, shards), CostSource: engine.CostEstimated, Tags: tags,
				Attrs:   map[string]string{"mode": mode, "shards": fmt.Sprint(shards), "retention_h": fmt.Sprint(aws.ToInt32(d.RetentionPeriodHours))},
				Drivers: map[string]float64{},
			}
			if onDemand {
				n.Drivers["hours_od"] = engine.HoursPerMonth
			} else {
				n.Drivers["shard_hours"] = float64(shards) * engine.HoursPerMonth
			}
			applyManagement(&n)
			n.Evidence = append(n.Evidence, "standing cost only; per-PUT/data charges not included")

			bytesIn, points, err := metricTotal(ctx, cw, metricQuery{
				"AWS/Kinesis", "IncomingBytes", map[string]string{"StreamName": name}, cwTypes.StatisticSum, c.th.IdleWindowDays,
			})
			switch {
			case err != nil:
				c.warn("cloudwatch:kinesis", err)
				n.Evidence = append(n.Evidence, "CloudWatch unavailable: usage not checked")
			case bytesIn == 0:
				conf := engine.ConfHigh
				if points == 0 {
					conf = engine.ConfMedium
				}
				markWaste(&n, "Kinesis stream without incoming data", conf,
					fmt.Sprintf("IncomingBytes = 0 for %d days (%d datapoints)", c.th.IdleWindowDays, points))
			case onDemand && bytesIn < c.th.KinesisNearIdleBytes:
				markWaste(&n, "On-demand Kinesis stream with negligible traffic", engine.ConfLow,
					fmt.Sprintf("%.2f MiB in %dd while the stream bills a fixed $%.2f/month", bytesIn/(1<<20), c.th.IdleWindowDays, n.MonthlyCost))
			default:
				n.Evidence = append(n.Evidence, fmt.Sprintf("%.1f MiB in over %dd", bytesIn/(1<<20), c.th.IdleWindowDays))
				if onDemand {
					n.Drivers["in_gb"] = bytesIn / (1 << 30) * 30 / float64(c.th.IdleWindowDays)
				}
			}
			c.add(n)
		}
	}
}

func init() {
	register(Scanner{
		Name: "kinesis", Desc: "Kinesis streams without or with negligible traffic",
		Types:    map[string]string{"aws_kinesis_stream": "Amazon Kinesis"},
		Regional: scanKinesis,
	})
}
