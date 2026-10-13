package aws

import (
	"context"
	"fmt"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// ---- Lambda -------------------------------------------------------------------

type lambdaAPI interface {
	lambda.ListFunctionsAPIClient
	ListTags(ctx context.Context, in *lambda.ListTagsInput, opts ...func(*lambda.Options)) (*lambda.ListTagsOutput, error)
}

func scanLambda(ctx context.Context, cfg aws.Config, c *collector) {
	scanLambdaWith(ctx, lambda.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), c)
}

func scanLambdaWith(ctx context.Context, api lambdaAPI, cw metricDataAPI, c *collector) {
	var fns []lambdaTypes.FunctionConfiguration
	p := lambda.NewListFunctionsPaginator(api, &lambda.ListFunctionsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("lambda:functions", err)
			return
		}
		fns = append(fns, page.Functions...)
	}
	if len(fns) == 0 {
		return
	}

	days := c.th.IdleWindowDays
	var qs []mq
	for _, f := range fns {
		name := aws.ToString(f.FunctionName)
		d := map[string]string{"FunctionName": name}
		qs = append(qs,
			mq{"inv/" + name, "AWS/Lambda", "Invocations", d, "Sum"},
			mq{"dur/" + name, "AWS/Lambda", "Duration", d, "Sum"})
	}
	m, merr := batchMetrics(ctx, cw, qs, days)
	if merr != nil {
		c.warn("cloudwatch:lambda", merr)
	}

	for _, f := range fns {
		name := aws.ToString(f.FunctionName)
		arn := aws.ToString(f.FunctionArn)
		var tags map[string]string
		if t, err := api.ListTags(ctx, &lambda.ListTagsInput{Resource: aws.String(arn)}); err == nil {
			tags = t.Tags
		}
		mem := float64(aws.ToInt32(f.MemorySize))
		arm := len(f.Architectures) > 0 && f.Architectures[0] == lambdaTypes.ArchitectureArm64
		n := engine.ResourceNode{
			ID: arn, Name: name, Type: "aws_lambda_function", Group: parseGroup(name), Tags: tags,
			CostSource: engine.CostEstimated,
			Attrs:      map[string]string{"runtime": string(f.Runtime), "memory_mb": fmt.Sprint(int(mem))},
		}
		if f.VpcConfig != nil {
			n.VPCID = aws.ToString(f.VpcConfig.VpcId)
			if len(f.VpcConfig.SubnetIds) > 0 {
				n.SubnetID = f.VpcConfig.SubnetIds[0]
			}
		}
		applyManagement(&n)
		if merr == nil {
			inv, dur := m["inv/"+name], m["dur/"+name]
			n.MonthlyCost = engine.LambdaMonthlyCost(inv.Value, dur.Value, mem, arm, days)
			scale := 30 / float64(days)
			gbs := dur.Value / 1000 * (mem / 1024) * scale
			n.Drivers = map[string]float64{"invocations": inv.Value * scale}
			if arm {
				n.Drivers["gb_s_arm"] = gbs
			} else {
				n.Drivers["gb_s"] = gbs
			}
			n.Attrs["invocations_30d"] = fmt.Sprintf("%.0f", inv.Value*30/float64(days))
			if inv.Value == 0 {
				n.Evidence = append(n.Evidence, fmt.Sprintf("no invocations in %d days (a function costs nothing while idle)", days))
			}
		} else {
			n.CostSource = engine.CostNotAvailable
			n.Evidence = append(n.Evidence, "CloudWatch unavailable: invocations not read")
		}
		n.Evidence = append(n.Evidence, "cost from invocations and duration in the window; provisioned concurrency and data transfer are not included")
		c.add(n)
	}
}

// ---- VPC endpoints ------------------------------------------------------------

func scanVPCEndpoints(ctx context.Context, cfg aws.Config, c *collector) {
	scanVPCEndpointsWith(ctx, ec2.NewFromConfig(cfg), c)
}

func scanVPCEndpointsWith(ctx context.Context, api ec2.DescribeVpcEndpointsAPIClient, c *collector) {
	p := ec2.NewDescribeVpcEndpointsPaginator(api, &ec2.DescribeVpcEndpointsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("ec2:vpc-endpoints", err)
			return
		}
		for _, e := range page.VpcEndpoints {
			id := aws.ToString(e.VpcEndpointId)
			tags := tagMap(e.Tags, func(t ec2Types.Tag) (string, string) { return aws.ToString(t.Key), aws.ToString(t.Value) })
			typ := string(e.VpcEndpointType)
			n := engine.ResourceNode{
				ID: id, Name: nameOr(tags, id), Type: "aws_vpc_endpoint", Group: "NETWORK",
				VPCID: aws.ToString(e.VpcId), Tags: tags, CostSource: engine.CostEstimated,
				MonthlyCost: engine.VPCEndpointMonthlyCost(typ, len(e.SubnetIds)),
				Attrs: map[string]string{
					"endpoint_type": typ, "service": aws.ToString(e.ServiceName),
					"azs": fmt.Sprint(len(e.SubnetIds)), "state": string(e.State),
				},
			}
			if len(e.SubnetIds) > 0 {
				n.SubnetID = e.SubnetIds[0]
			}
			applyManagement(&n)
			n.Evidence = append(n.Evidence, "standing cost only; data processed is not included, and usage is not checked for endpoints")
			c.add(n)
		}
	}
}

func init() {
	register(Scanner{
		Name: "lambda", Desc: "Lambda functions: cost from invocations and duration, idle functions",
		Types:    map[string]string{"aws_lambda_function": "AWS Lambda"},
		Regional: scanLambda,
	})
	register(Scanner{
		Name: "vpcendpoints", Desc: "VPC endpoints: interface endpoints bill per AZ-hour",
		Types:    map[string]string{"aws_vpc_endpoint": "Amazon Virtual Private Cloud"},
		Regional: scanVPCEndpoints,
	})
}
