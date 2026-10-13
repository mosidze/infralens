package aws

import (
	"context"
	"fmt"
	"strings"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

// ---- SQS ----------------------------------------------------------------------

type sqsAPI interface {
	sqs.ListQueuesAPIClient
	ListQueueTags(ctx context.Context, in *sqs.ListQueueTagsInput, opts ...func(*sqs.Options)) (*sqs.ListQueueTagsOutput, error)
}

func scanSQS(ctx context.Context, cfg aws.Config, c *collector) {
	scanSQSWith(ctx, sqs.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), c)
}

func scanSQSWith(ctx context.Context, api sqsAPI, cw metricDataAPI, c *collector) {
	p := sqs.NewListQueuesPaginator(api, &sqs.ListQueuesInput{})
	var urls []string
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("sqs:queues", err)
			return
		}
		urls = append(urls, page.QueueUrls...)
	}
	if len(urls) == 0 {
		return
	}
	var qs []mq
	for _, u := range urls {
		name := lastToken(u)
		d := map[string]string{"QueueName": name}
		qs = append(qs,
			mq{"s/" + name, "AWS/SQS", "NumberOfMessagesSent", d, "Sum"},
			mq{"r/" + name, "AWS/SQS", "NumberOfMessagesReceived", d, "Sum"})
	}
	m, merr := batchMetrics(ctx, cw, qs, c.th.IdleWindowDays)
	if merr != nil {
		c.warn("cloudwatch:sqs", merr)
	}
	for _, u := range urls {
		name := lastToken(u)
		var tags map[string]string
		if t, err := api.ListQueueTags(ctx, &sqs.ListQueueTagsInput{QueueUrl: aws.String(u)}); err == nil {
			tags = t.Tags
		}
		n := engine.ResourceNode{
			ID: u, Name: name, Type: "aws_sqs_queue", Group: parseGroup(name), Tags: tags, CostSource: engine.CostEstimated,
			Attrs:   map[string]string{"fifo": fmt.Sprint(strings.HasSuffix(name, ".fifo"))},
			Drivers: map[string]float64{},
		}
		applyManagement(&n)
		if merr == nil {
			sent, recv := m["s/"+name].Value, m["r/"+name].Value
			n.MonthlyCost = engine.SQSMonthlyCost(sent, recv, c.th.IdleWindowDays)
			n.Attrs["sent_30d"] = fmt.Sprintf("%.0f", sent*30/float64(c.th.IdleWindowDays))
			n.Drivers["requests"] = (sent + 2*recv) * 30 / float64(c.th.IdleWindowDays)
			if sent == 0 && recv == 0 {
				n.Evidence = append(n.Evidence, fmt.Sprintf("no messages sent or received in %dd (an idle queue costs nothing)", c.th.IdleWindowDays))
			}
		} else {
			n.CostSource = engine.CostNotAvailable
		}
		n.Evidence = append(n.Evidence, "request charges only: about one send, receive and delete per message")
		c.add(n)
	}
}

// ---- Firehose -----------------------------------------------------------------

type firehoseAPI interface {
	ListDeliveryStreams(ctx context.Context, in *firehose.ListDeliveryStreamsInput, opts ...func(*firehose.Options)) (*firehose.ListDeliveryStreamsOutput, error)
	DescribeDeliveryStream(ctx context.Context, in *firehose.DescribeDeliveryStreamInput, opts ...func(*firehose.Options)) (*firehose.DescribeDeliveryStreamOutput, error)
}

func scanFirehose(ctx context.Context, cfg aws.Config, c *collector) {
	scanFirehoseWith(ctx, firehose.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), c)
}

func scanFirehoseWith(ctx context.Context, api firehoseAPI, cw metricDataAPI, c *collector) {
	var names []string
	var start *string
	for {
		out, err := api.ListDeliveryStreams(ctx, &firehose.ListDeliveryStreamsInput{ExclusiveStartDeliveryStreamName: start})
		if err != nil {
			c.warn("firehose:streams", err)
			return
		}
		names = append(names, out.DeliveryStreamNames...)
		if !aws.ToBool(out.HasMoreDeliveryStreams) || len(out.DeliveryStreamNames) == 0 {
			break
		}
		start = aws.String(out.DeliveryStreamNames[len(out.DeliveryStreamNames)-1])
	}
	if len(names) == 0 {
		return
	}
	var qs []mq
	for _, nm := range names {
		qs = append(qs, mq{nm, "AWS/Firehose", "IncomingBytes", map[string]string{"DeliveryStreamName": nm}, "Sum"})
	}
	m, merr := batchMetrics(ctx, cw, qs, c.th.IdleWindowDays)
	if merr != nil {
		c.warn("cloudwatch:firehose", merr)
	}
	for _, nm := range names {
		d, err := api.DescribeDeliveryStream(ctx, &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: aws.String(nm)})
		if err != nil {
			c.warn("firehose:describe", err)
			continue
		}
		desc := d.DeliveryStreamDescription
		n := engine.ResourceNode{
			ID: aws.ToString(desc.DeliveryStreamARN), Name: nm, Type: "aws_firehose_stream", Group: parseGroup(nm),
			CostSource: engine.CostEstimated,
			Attrs:      map[string]string{"type": string(desc.DeliveryStreamType), "status": string(desc.DeliveryStreamStatus)},
			Drivers:    map[string]float64{},
		}
		applyManagement(&n)
		n.Evidence = append(n.Evidence, "tags not read for Firehose; ownership not classified")
		if merr == nil {
			a := m[nm]
			n.MonthlyCost = engine.FirehoseMonthlyCost(a.Value, c.th.IdleWindowDays)
			n.Drivers["in_gb"] = a.Value / (1 << 30) * 30 / float64(c.th.IdleWindowDays)
			if a.Value == 0 {
				n.Evidence = append(n.Evidence, fmt.Sprintf("no incoming data in %dd (an idle stream costs nothing)", c.th.IdleWindowDays))
			}
		} else {
			n.CostSource = engine.CostNotAvailable
		}
		n.Evidence = append(n.Evidence, "ingestion charges only; format conversion and destination costs are not included")
		c.add(n)
	}
}

// ---- CloudFront ---------------------------------------------------------------

type cloudfrontAPI interface {
	cloudfront.ListDistributionsAPIClient
}

func scanCloudFront(ctx context.Context, cfg aws.Config, c *collector) {
	scanCloudFrontWith(ctx, cloudfront.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), c)
}

func scanCloudFrontWith(ctx context.Context, api cloudfrontAPI, cw metricDataAPI, c *collector) {
	p := cloudfront.NewListDistributionsPaginator(api, &cloudfront.ListDistributionsInput{})
	type dist struct {
		id, domain, arn string
		enabled         bool
		aliases         []string
	}
	var ds []dist
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("cloudfront:distributions", err)
			return
		}
		if page.DistributionList == nil {
			continue
		}
		for _, d := range page.DistributionList.Items {
			x := dist{id: aws.ToString(d.Id), domain: aws.ToString(d.DomainName), arn: aws.ToString(d.ARN), enabled: aws.ToBool(d.Enabled)}
			if d.Aliases != nil {
				x.aliases = d.Aliases.Items
			}
			ds = append(ds, x)
		}
	}
	if len(ds) == 0 {
		return
	}
	var qs []mq
	for _, d := range ds {
		qs = append(qs, mq{d.id, "AWS/CloudFront", "Requests", map[string]string{"DistributionId": d.id, "Region": "Global"}, "Sum"})
	}
	m, merr := batchMetrics(ctx, cw, qs, c.th.IdleWindowDays)
	if merr != nil {
		c.warn("cloudwatch:cloudfront", merr)
	}
	for _, d := range ds {
		name := d.domain
		if len(d.aliases) > 0 {
			name = d.aliases[0]
		}
		n := engine.ResourceNode{
			ID: d.arn, Name: name, Type: "aws_cloudfront_distribution", Group: "EDGE", CostSource: engine.CostEstimated,
			Attrs: map[string]string{"enabled": fmt.Sprint(d.enabled), "distribution": d.id, "aliases": fmt.Sprint(len(d.aliases))},
		}
		n.Region = "global"
		applyManagement(&n)
		n.Evidence = append(n.Evidence, "tags not read for CloudFront; ownership not classified")
		if merr == nil {
			a := m[d.id]
			n.MonthlyCost = engine.CloudFrontMonthlyCost(a.Value, c.th.IdleWindowDays)
			if a.Value == 0 && d.enabled {
				n.Evidence = append(n.Evidence, fmt.Sprintf("no requests in %dd for an enabled distribution", c.th.IdleWindowDays))
			}
		} else {
			n.CostSource = engine.CostNotAvailable
		}
		n.Evidence = append(n.Evidence, "request charges only; data transfer out is usually the larger part and is not modelled")
		c.add(n)
	}
}

func init() {
	register(Scanner{
		Name: "sqs", Desc: "SQS queues: request cost from message counts",
		Types: map[string]string{"aws_sqs_queue": "Amazon Simple Queue Service"}, Regional: scanSQS,
	})
	register(Scanner{
		Name: "firehose", Desc: "Firehose delivery streams: ingestion cost",
		Types: map[string]string{"aws_firehose_stream": "Amazon Kinesis Firehose"}, Regional: scanFirehose,
	})
	register(Scanner{
		Name: "cloudfront", Desc: "CloudFront distributions: request cost (account-wide, metrics from us-east-1)",
		Types: map[string]string{"aws_cloudfront_distribution": "Amazon CloudFront"},
		Global: func(ctx context.Context, dc *DiscoveryClient, c *collector) {
			cfg, err := dc.loadConfig(ctx, "us-east-1")
			if err != nil {
				c.warn("cloudfront:config", err)
				return
			}
			scanCloudFront(ctx, cfg, c)
		},
	})
}
