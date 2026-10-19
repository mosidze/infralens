// Package awswatch holds the live monitor's AWS collectors. Each one asks AWS
// a cheap, read-only question ("is anything in ALARM?", "are all tasks
// running?") and reports only what is wrong. The calls go through the same
// read-only guard as a scan.
package awswatch

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/health"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	awsd "infralens/internal/aws"
)

type cwAPI interface {
	DescribeAlarms(context.Context, *cloudwatch.DescribeAlarmsInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

type ecsAPI interface {
	ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error)
	DescribeServices(context.Context, *ecs.DescribeServicesInput, ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
}

type elbAPI interface {
	DescribeTargetGroups(context.Context, *elasticloadbalancingv2.DescribeTargetGroupsInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error)
	DescribeTargetHealth(context.Context, *elasticloadbalancingv2.DescribeTargetHealthInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error)
}

type rdsAPI interface {
	DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
}

type sqsAPI interface {
	ListQueues(context.Context, *sqs.ListQueuesInput, ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
	GetQueueAttributes(context.Context, *sqs.GetQueueAttributesInput, ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

type healthAPI interface {
	DescribeEvents(context.Context, *health.DescribeEventsInput, ...func(*health.Options)) (*health.DescribeEventsOutput, error)
	DescribeAffectedEntities(context.Context, *health.DescribeAffectedEntitiesInput, ...func(*health.Options)) (*health.DescribeAffectedEntitiesOutput, error)
}

// Clients hands out API clients per region. The real one builds them from the
// guarded SDK config; tests supply fakes.
type Clients interface {
	CloudWatch(ctx context.Context, region string) (cwAPI, error)
	ECS(ctx context.Context, region string) (ecsAPI, error)
	ELB(ctx context.Context, region string) (elbAPI, error)
	RDS(ctx context.Context, region string) (rdsAPI, error)
	SQS(ctx context.Context, region string) (sqsAPI, error)
	Health(ctx context.Context) (healthAPI, error)
}

type sdkClients struct {
	dc  *awsd.DiscoveryClient
	mu  sync.Mutex
	cfg map[string]aws.Config
}

// NewClients builds the real client factory for a discovery client.
func NewClients(dc *awsd.DiscoveryClient) Clients {
	return &sdkClients{dc: dc, cfg: map[string]aws.Config{}}
}

func (s *sdkClients) config(ctx context.Context, region string) (aws.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.cfg[region]; ok {
		return c, nil
	}
	c, err := s.dc.Config(ctx, region)
	if err != nil {
		return c, err
	}
	s.cfg[region] = c
	return c, nil
}

func (s *sdkClients) CloudWatch(ctx context.Context, r string) (cwAPI, error) {
	c, err := s.config(ctx, r)
	return cloudwatch.NewFromConfig(c), err
}
func (s *sdkClients) ECS(ctx context.Context, r string) (ecsAPI, error) {
	c, err := s.config(ctx, r)
	return ecs.NewFromConfig(c), err
}
func (s *sdkClients) ELB(ctx context.Context, r string) (elbAPI, error) {
	c, err := s.config(ctx, r)
	return elasticloadbalancingv2.NewFromConfig(c), err
}
func (s *sdkClients) RDS(ctx context.Context, r string) (rdsAPI, error) {
	c, err := s.config(ctx, r)
	return rds.NewFromConfig(c), err
}
func (s *sdkClients) SQS(ctx context.Context, r string) (sqsAPI, error) {
	c, err := s.config(ctx, r)
	return sqs.NewFromConfig(c), err
}

// Health is a global service whose API lives in us-east-1.
func (s *sdkClients) Health(ctx context.Context) (healthAPI, error) {
	c, err := s.config(ctx, "us-east-1")
	return health.NewFromConfig(c), err
}
