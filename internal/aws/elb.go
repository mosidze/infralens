package aws

import (
	"context"
	"fmt"
	"strings"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbTypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// elbAPI is what the load balancer scanner needs from the SDK.
type elbAPI interface {
	elasticloadbalancingv2.DescribeLoadBalancersAPIClient
	elasticloadbalancingv2.DescribeTargetGroupsAPIClient
	elasticloadbalancingv2.DescribeListenersAPIClient
	DescribeTags(ctx context.Context, in *elasticloadbalancingv2.DescribeTagsInput, opts ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTagsOutput, error)
	DescribeTargetHealth(ctx context.Context, in *elasticloadbalancingv2.DescribeTargetHealthInput, opts ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error)
}

func scanLoadBalancers(ctx context.Context, cfg aws.Config, c *collector) {
	scanLoadBalancersWith(ctx, elasticloadbalancingv2.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), c)
}

func scanLoadBalancersWith(ctx context.Context, cli elbAPI, cw metricsAPI, c *collector) {

	var lbs []elbTypes.LoadBalancer
	lp := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(cli, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	for lp.HasMorePages() {
		page, err := lp.NextPage(ctx)
		if err != nil {
			c.warn("elbv2:load-balancers", err)
			return
		}
		lbs = append(lbs, page.LoadBalancers...)
	}
	if len(lbs) == 0 {
		return
	}

	// target groups per LB, and registered target counts per group
	tgsByLB := map[string][]string{}
	tp := elasticloadbalancingv2.NewDescribeTargetGroupsPaginator(cli, &elasticloadbalancingv2.DescribeTargetGroupsInput{})
	for tp.HasMorePages() {
		page, err := tp.NextPage(ctx)
		if err != nil {
			c.warn("elbv2:target-groups", err)
			return
		}
		for _, tg := range page.TargetGroups {
			arn := aws.ToString(tg.TargetGroupArn)
			for _, lb := range tg.LoadBalancerArns {
				tgsByLB[lb] = append(tgsByLB[lb], arn)
				c.setTGLB(arn, lb)
			}
		}
	}

	tagsByARN := map[string]map[string]string{}
	for i := 0; i < len(lbs); i += 20 {
		end := min(i+20, len(lbs))
		var arns []string
		for _, lb := range lbs[i:end] {
			arns = append(arns, aws.ToString(lb.LoadBalancerArn))
		}
		out, err := cli.DescribeTags(ctx, &elasticloadbalancingv2.DescribeTagsInput{ResourceArns: arns})
		if err != nil {
			c.warn("elbv2:tags", err)
			continue
		}
		for _, d := range out.TagDescriptions {
			tagsByARN[aws.ToString(d.ResourceArn)] = tagMap(d.Tags, func(t elbTypes.Tag) (string, string) {
				return aws.ToString(t.Key), aws.ToString(t.Value)
			})
		}
	}

	for _, lb := range lbs {
		arn := aws.ToString(lb.LoadBalancerArn)
		name := aws.ToString(lb.LoadBalancerName)
		tags := tagsByARN[arn]

		registered, healthErr := 0, error(nil)
		for _, tg := range tgsByLB[arn] {
			h, err := cli.DescribeTargetHealth(ctx, &elasticloadbalancingv2.DescribeTargetHealthInput{TargetGroupArn: aws.String(tg)})
			if err != nil {
				healthErr = err
				break
			}
			registered += len(h.TargetHealthDescriptions)
		}

		staticOnly := false
		if len(tgsByLB[arn]) == 0 {
			var err error
			if staticOnly, err = listenersStaticOnly(ctx, cli, arn); err != nil {
				c.warn("elbv2:listeners", err)
			}
		}

		hourly := engine.ALBHour
		if lb.Type == elbTypes.LoadBalancerTypeEnumNetwork {
			hourly = engine.NLBHour
		}
		n := engine.ResourceNode{
			ID: arn, Name: name, Type: "aws_lb", Group: parseGroup(name), VPCID: aws.ToString(lb.VpcId),
			MonthlyCost: engine.MonthlyFromHourly(hourly), CostSource: engine.CostEstimated,
			Tags:    tags,
			Attrs:   map[string]string{"lb_type": string(lb.Type), "scheme": string(lb.Scheme), "dns_name": aws.ToString(lb.DNSName)},
			Drivers: map[string]float64{"hours": engine.HoursPerMonth},
		}
		applyManagement(&n)
		if healthErr != nil {
			c.warn("elbv2:target-health", healthErr)
		} else if v := lbVerdict(len(tgsByLB[arn]), registered, staticOnly); v.Waste {
			// Zero requests over the window confirms a dead balancer.
			if reqs, pts, err := metricTotal(ctx, cw, metricQuery{
				"AWS/" + lbNamespace(lb.Type), "RequestCount",
				map[string]string{"LoadBalancer": lbDimension(arn)}, cwTypes.StatisticSum, c.th.IdleWindowDays,
			}); err == nil && reqs == 0 && pts == 0 {
				v.Evidence += fmt.Sprintf("; no requests in %dd", c.th.IdleWindowDays)
				v.Confidence = engine.ConfHigh
			} else if err == nil && reqs > 0 {
				v.Evidence += fmt.Sprintf("; but %.0f requests in %dd (still answering)", reqs, c.th.IdleWindowDays)
				v.Confidence = engine.ConfLow
			}
			markWaste(&n, "Load balancer without targets", v.Confidence, v.Evidence)
		} else {
			n.Evidence = append(n.Evidence, v.Evidence)
		}
		c.add(n)
	}
}

// listenersStaticOnly reports whether the load balancer has listeners and
// all of them answer with a fixed response or a redirect.
func listenersStaticOnly(ctx context.Context, cli elasticloadbalancingv2.DescribeListenersAPIClient, lbARN string) (bool, error) {
	p := elasticloadbalancingv2.NewDescribeListenersPaginator(cli, &elasticloadbalancingv2.DescribeListenersInput{LoadBalancerArn: aws.String(lbARN)})
	count := 0
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return false, err
		}
		for _, l := range page.Listeners {
			count++
			for _, a := range l.DefaultActions {
				if a.Type != elbTypes.ActionTypeEnumFixedResponse && a.Type != elbTypes.ActionTypeEnumRedirect {
					return false, nil
				}
			}
		}
	}
	return count > 0, nil
}

func lbNamespace(t elbTypes.LoadBalancerTypeEnum) string {
	if t == elbTypes.LoadBalancerTypeEnumNetwork {
		return "NetworkELB"
	}
	return "ApplicationELB"
}

// lbDimension turns an ARN into the CloudWatch dimension value
// ("app/name/id" or "net/name/id").
func lbDimension(arn string) string {
	if i := strings.Index(arn, "loadbalancer/"); i >= 0 {
		return arn[i+len("loadbalancer/"):]
	}
	return arn
}

func init() {
	register(Scanner{
		Name: "elb", Desc: "ALB/NLB without targets or requests",
		Types:    map[string]string{"aws_lb": "Amazon Elastic Load Balancing"},
		Regional: scanLoadBalancers,
	})
}
