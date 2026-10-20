package awswatch

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbTypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/health"
	healthTypes "github.com/aws/aws-sdk-go-v2/service/health/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"

	"infralens/internal/engine"
	"infralens/internal/watch"
)

var now = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// ---- fakes ---------------------------------------------------------------------------

type fake struct {
	alarms      []cwTypes.MetricAlarm
	composite   []cwTypes.CompositeAlarm
	clusters    []string
	services    map[string][]ecsTypes.Service // cluster -> services
	stopped     []ecsTypes.Task
	tgs         []elbTypes.TargetGroup
	targets     map[string][]elbTypes.TargetHealthDescription
	dbs         []rdsTypes.DBInstance
	dbClusters  []rdsTypes.DBCluster
	queues      []string
	depth       map[string]string
	events      []healthTypes.Event
	entities    []healthTypes.AffectedEntity
	healthErr   error
	failRegion  string
	attrsCalled []string
}

func (f *fake) check(region string) error {
	if region == f.failRegion {
		return errors.New("ExpiredToken: the security token included in the request is expired")
	}
	return nil
}

func (f *fake) CloudWatch(_ context.Context, r string) (cwAPI, error) { return f, f.check(r) }
func (f *fake) ECS(_ context.Context, r string) (ecsAPI, error)       { return f, f.check(r) }
func (f *fake) ELB(_ context.Context, r string) (elbAPI, error)       { return f, f.check(r) }
func (f *fake) RDS(_ context.Context, r string) (rdsAPI, error)       { return f, f.check(r) }
func (f *fake) SQS(_ context.Context, r string) (sqsAPI, error)       { return f, f.check(r) }
func (f *fake) Health(context.Context) (healthAPI, error)             { return f, nil }

func (f *fake) DescribeAlarms(_ context.Context, in *cloudwatch.DescribeAlarmsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	if in.StateValue != cwTypes.StateValueAlarm {
		panic("only alarms in ALARM may be requested")
	}
	return &cloudwatch.DescribeAlarmsOutput{MetricAlarms: f.alarms, CompositeAlarms: f.composite}, nil
}

func (f *fake) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: f.clusters}, nil
}
func (f *fake) ListServices(_ context.Context, in *ecs.ListServicesInput, _ ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	var arns []string
	for _, s := range f.services[aws.ToString(in.Cluster)] {
		arns = append(arns, aws.ToString(s.ServiceArn))
	}
	return &ecs.ListServicesOutput{ServiceArns: arns}, nil
}
func (f *fake) DescribeServices(_ context.Context, in *ecs.DescribeServicesInput, _ ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	if len(in.Services) > 10 {
		panic("DescribeServices accepts at most 10 services")
	}
	var out []ecsTypes.Service
	for _, s := range f.services[aws.ToString(in.Cluster)] {
		for _, a := range in.Services {
			if a == aws.ToString(s.ServiceArn) {
				out = append(out, s)
			}
		}
	}
	return &ecs.DescribeServicesOutput{Services: out}, nil
}
func (f *fake) ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	var a []string
	for range f.stopped {
		a = append(a, "t")
	}
	return &ecs.ListTasksOutput{TaskArns: a}, nil
}
func (f *fake) DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{Tasks: f.stopped}, nil
}

func (f *fake) DescribeTargetGroups(context.Context, *elasticloadbalancingv2.DescribeTargetGroupsInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error) {
	return &elasticloadbalancingv2.DescribeTargetGroupsOutput{TargetGroups: f.tgs}, nil
}
func (f *fake) DescribeTargetHealth(_ context.Context, in *elasticloadbalancingv2.DescribeTargetHealthInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error) {
	return &elasticloadbalancingv2.DescribeTargetHealthOutput{TargetHealthDescriptions: f.targets[aws.ToString(in.TargetGroupArn)]}, nil
}

func (f *fake) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: f.dbs}, nil
}
func (f *fake) DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	return &rds.DescribeDBClustersOutput{DBClusters: f.dbClusters}, nil
}

func (f *fake) ListQueues(context.Context, *sqs.ListQueuesInput, ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	return &sqs.ListQueuesOutput{QueueUrls: f.queues}, nil
}
func (f *fake) GetQueueAttributes(_ context.Context, in *sqs.GetQueueAttributesInput, _ ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	u := aws.ToString(in.QueueUrl)
	f.attrsCalled = append(f.attrsCalled, u)
	return &sqs.GetQueueAttributesOutput{Attributes: map[string]string{"ApproximateNumberOfMessages": f.depth[u]}}, nil
}

func (f *fake) DescribeEvents(context.Context, *health.DescribeEventsInput, ...func(*health.Options)) (*health.DescribeEventsOutput, error) {
	return &health.DescribeEventsOutput{Events: f.events}, f.healthErr
}
func (f *fake) DescribeAffectedEntities(context.Context, *health.DescribeAffectedEntitiesInput, ...func(*health.Options)) (*health.DescribeAffectedEntitiesOutput, error) {
	return &health.DescribeAffectedEntitiesOutput{Entities: f.entities}, nil
}

func src(f *fake, regions ...string) Source {
	if len(regions) == 0 {
		regions = []string{"eu-west-1"}
	}
	return Source{Clients: f, Regions: func(...string) []string { return regions }}
}

func env(nodes ...engine.ResourceNode) *watch.Env {
	return &watch.Env{Graph: watch.NewGraph(engine.ScanResult{Nodes: nodes}), Now: now}
}

func byKind(obs []watch.Observation) map[string]watch.Observation {
	m := map[string]watch.Observation{}
	for _, o := range obs {
		m[o.Kind+"|"+o.Title] = o
	}
	return m
}

// ---- tests ----------------------------------------------------------------------------

func TestAlarmsAreCriticalOnlyWhenSomeoneWiredThemToBeTold(t *testing.T) {
	f := &fake{
		alarms: []cwTypes.MetricAlarm{
			{AlarmName: aws.String("checkout-5xx"), Namespace: aws.String("AWS/ApplicationELB"), MetricName: aws.String("HTTPCode_Target_5XX_Count"),
				Dimensions:     []cwTypes.Dimension{{Name: aws.String("LoadBalancer"), Value: aws.String("app/storefront/50dc6c495c0c9188")}},
				ActionsEnabled: aws.Bool(true), AlarmActions: []string{"arn:aws:sns:eu-west-1:1:oncall"},
				Threshold: aws.Float64(50), ComparisonOperator: cwTypes.ComparisonOperatorGreaterThanThreshold, Period: aws.Int32(60), EvaluationPeriods: aws.Int32(5),
				Statistic: cwTypes.StatisticSum, StateReason: aws.String("Threshold Crossed: 5 datapoints were greater than 50"), StateUpdatedTimestamp: aws.Time(now.Add(-9 * time.Minute))},
			{AlarmName: aws.String("quiet-cpu"), Dimensions: []cwTypes.Dimension{{Name: aws.String("ServiceName"), Value: aws.String("catalog-svc-01")}},
				ActionsEnabled: aws.Bool(true), StateReason: aws.String("cpu high"), StateUpdatedTimestamp: aws.Time(now)},
		},
		composite: []cwTypes.CompositeAlarm{{AlarmName: aws.String("api-degraded"), ActionsEnabled: aws.Bool(true), AlarmActions: []string{"x"}, StateReason: aws.String("children in ALARM")}},
	}
	obs, err := (&alarms{src(f)}).Collect(context.Background(), env())
	if err != nil || len(obs) != 3 {
		t.Fatalf("obs %d err %v", len(obs), err)
	}
	m := byKind(obs)
	if o := m["alarm.firing|checkout-5xx"]; o.Severity != watch.SevCrit || o.NodeID != "storefront" || !o.Immediate || !strings.Contains(o.Threshold, "> 50") {
		t.Fatalf("paging alarm: %+v", o)
	}
	if o := m["alarm.firing|quiet-cpu"]; o.Severity != watch.SevWarn || o.NodeID != "catalog-svc-01" {
		t.Fatalf("alarm nobody is told about: %+v", o)
	}
	if o := m["alarm.firing|api-degraded"]; o.Severity != watch.SevCrit {
		t.Fatalf("composite: %+v", o)
	}
}

func TestEcsReportsOnlyServicesThatAreShortOrFailed(t *testing.T) {
	arn := func(n string) *string { return aws.String("arn:aws:ecs:eu-west-1:1:service/c/" + n) }
	svc := func(n string, desired, running int32, status string, rollout ecsTypes.DeploymentRolloutState) ecsTypes.Service {
		return ecsTypes.Service{ServiceArn: arn(n), ServiceName: aws.String(n), DesiredCount: desired, RunningCount: running, Status: aws.String(status),
			Deployments: []ecsTypes.Deployment{{RolloutState: rollout}}}
	}
	f := &fake{
		clusters: []string{"c"},
		services: map[string][]ecsTypes.Service{"c": {
			svc("ok", 3, 3, "ACTIVE", ecsTypes.DeploymentRolloutStateCompleted),
			svc("short", 3, 1, "ACTIVE", ecsTypes.DeploymentRolloutStateInProgress),
			svc("down", 2, 0, "ACTIVE", ecsTypes.DeploymentRolloutStateCompleted),
			svc("off", 0, 0, "ACTIVE", ecsTypes.DeploymentRolloutStateCompleted),
			svc("rolledback", 2, 2, "ACTIVE", ecsTypes.DeploymentRolloutStateFailed),
			svc("gone", 2, 0, "INACTIVE", ecsTypes.DeploymentRolloutStateCompleted),
		}},
		stopped: []ecsTypes.Task{
			{StoppedReason: aws.String("Essential container in task exited"), Containers: []ecsTypes.Container{{ExitCode: aws.Int32(137)}}},
			{StoppedReason: aws.String("Essential container in task exited"), Containers: []ecsTypes.Container{{ExitCode: aws.Int32(137)}}},
		},
	}
	obs, err := (&ecsC{s: src(f)}).Collect(context.Background(), env())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]watch.Observation{}
	for _, o := range obs {
		got[o.NodeID[strings.LastIndex(o.NodeID, "/")+1:]] = o
	}
	if len(got) != 3 {
		t.Fatalf("only short, down and rolledback are problems, got %v", len(got))
	}
	if got["down"].Severity != watch.SevCrit || got["short"].Severity != watch.SevWarn || got["rolledback"].Severity != watch.SevWarn {
		t.Fatalf("severities: %+v", got)
	}
	if !strings.Contains(strings.Join(got["short"].Evidence, " "), "2 task(s) stopped: Essential container in task exited (exit code 137)") {
		t.Fatalf("stop reasons must explain it: %v", got["short"].Evidence)
	}
	if got["short"].Immediate {
		t.Fatal("a rolling deployment must wait out the tracker, not show at once")
	}
}

func TestEcsAsksForServicesTenAtATime(t *testing.T) {
	var list []ecsTypes.Service
	for i := 0; i < 23; i++ {
		list = append(list, ecsTypes.Service{ServiceArn: aws.String("arn:s" + string(rune('a'+i))), Status: aws.String("ACTIVE"), DesiredCount: 1, RunningCount: 1})
	}
	f := &fake{clusters: []string{"c"}, services: map[string][]ecsTypes.Service{"c": list}}
	if _, err := (&ecsC{s: src(f)}).Collect(context.Background(), env()); err != nil { // the fake panics above 10
		t.Fatal(err)
	}
}

func TestLoadBalancerOnlyAttachedGroupsAndOnlyUnhealthyTargetsCount(t *testing.T) {
	d := func(id string, st elbTypes.TargetHealthStateEnum) elbTypes.TargetHealthDescription {
		return elbTypes.TargetHealthDescription{Target: &elbTypes.TargetDescription{Id: aws.String(id)},
			TargetHealth: &elbTypes.TargetHealth{State: st, Reason: elbTypes.TargetHealthReasonEnumFailedHealthChecks, Description: aws.String("Health checks failed")}}
	}
	f := &fake{
		tgs: []elbTypes.TargetGroup{
			{TargetGroupArn: aws.String("tg-partial"), TargetGroupName: aws.String("web"), LoadBalancerArns: []string{"lb-1"}},
			{TargetGroupArn: aws.String("tg-all"), TargetGroupName: aws.String("api"), LoadBalancerArns: []string{"lb-2"}},
			{TargetGroupArn: aws.String("tg-orphan"), TargetGroupName: aws.String("old")},
			{TargetGroupArn: aws.String("tg-fine"), TargetGroupName: aws.String("fine"), LoadBalancerArns: []string{"lb-3"}},
		},
		targets: map[string][]elbTypes.TargetHealthDescription{
			"tg-partial": {d("i-1", elbTypes.TargetHealthStateEnumHealthy), d("i-2", elbTypes.TargetHealthStateEnumUnhealthy), d("i-3", elbTypes.TargetHealthStateEnumDraining)},
			"tg-all":     {d("i-4", elbTypes.TargetHealthStateEnumUnhealthy), d("i-5", elbTypes.TargetHealthStateEnumUnhealthy)},
			"tg-orphan":  {d("i-6", elbTypes.TargetHealthStateEnumUnhealthy)},
			"tg-fine":    {d("i-7", elbTypes.TargetHealthStateEnumHealthy), d("i-8", elbTypes.TargetHealthStateEnumInitial)},
		},
	}
	obs, err := (&elbC{src(f)}).Collect(context.Background(), env())
	if err != nil || len(obs) != 2 {
		t.Fatalf("obs %d err %v", len(obs), err)
	}
	for _, o := range obs {
		switch o.NodeID {
		case "lb-1":
			if o.Severity != watch.SevWarn || o.Title != "1 of 2 targets are unhealthy" {
				t.Fatalf("partial: %+v", o)
			}
		case "lb-2":
			if o.Severity != watch.SevCrit {
				t.Fatalf("all unhealthy must be critical: %+v", o)
			}
		default:
			t.Fatalf("unexpected %s", o.NodeID)
		}
	}
}

func TestRdsBrokenStatesOnlyNotBusyOnes(t *testing.T) {
	f := &fake{
		dbs: []rdsTypes.DBInstance{
			{DBInstanceIdentifier: aws.String("a"), DBInstanceStatus: aws.String("available")},
			{DBInstanceIdentifier: aws.String("b"), DBInstanceStatus: aws.String("storage-full")},
			{DBInstanceIdentifier: aws.String("c"), DBInstanceStatus: aws.String("backing-up")},
			{DBInstanceIdentifier: aws.String("d"), DBInstanceStatus: aws.String("modifying")},
			{DBInstanceIdentifier: aws.String("e"), DBInstanceStatus: aws.String("stopped")},
		},
		dbClusters: []rdsTypes.DBCluster{{DBClusterIdentifier: aws.String("orders"), Status: aws.String("failed")}, {DBClusterIdentifier: aws.String("ok"), Status: aws.String("available")}},
	}
	obs, err := (&rdsC{src(f)}).Collect(context.Background(), env())
	if err != nil || len(obs) != 2 {
		t.Fatalf("obs %d err %v", len(obs), err)
	}
	ids := obs[0].NodeID + obs[1].NodeID
	if !strings.Contains(ids, "b") || !strings.Contains(ids, "orders") {
		t.Fatalf("ids %s", ids)
	}
}

func TestDeadLetterQueuesAreJudgedByGrowthNotByNotBeingEmpty(t *testing.T) {
	u := func(n string) string { return "https://sqs.eu-west-1.amazonaws.com/1/" + n }
	f := &fake{
		queues: []string{u("orders"), u("orders-dlq"), u("payments-deadletter"), u("empty-DLQ")},
		depth:  map[string]string{u("orders-dlq"): "3", u("payments-deadletter"): "1000", u("empty-DLQ"): "0"},
	}
	c := &sqsC{s: src(f)}
	t0 := now
	poll := func(at time.Time) map[string]watch.Observation {
		obs, err := c.Collect(context.Background(), &watch.Env{Graph: watch.NewGraph(engine.ScanResult{}), Now: at})
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]watch.Observation{}
		for _, o := range obs {
			m[o.NodeID[strings.LastIndex(o.NodeID, "/")+1:]] = o
		}
		return m
	}

	first := poll(t0)
	if len(first) != 2 {
		t.Fatalf("only non-empty dead-letter queues: %d", len(first))
	}
	for name, o := range first {
		if !o.Chronic {
			t.Fatalf("%s: the first reading cannot tell growth from a standing backlog, so it must not alarm", name)
		}
	}
	for _, c := range f.attrsCalled {
		if strings.HasSuffix(c, "/orders") {
			t.Fatal("a regular queue must not even be asked about")
		}
	}
	second := poll(t0.Add(2 * time.Minute))
	if !second["payments-deadletter"].Chronic {
		t.Fatal("a queue whose depth did not change is a standing backlog")
	}

	f.depth[u("payments-deadletter")] = "1250"
	f.depth[u("orders-dlq")] = "4"
	third := poll(t0.Add(4 * time.Minute))
	if o := third["payments-deadletter"]; o.Chronic || o.Severity != watch.SevCrit || !strings.Contains(o.Title, "+250") {
		t.Fatalf("a queue that gained 250 messages is sick now: %+v", o)
	}
	if o := third["orders-dlq"]; o.Chronic || o.Severity != watch.SevWarn {
		t.Fatalf("a small increase is a warning: %+v", o)
	}
}

type apiErr struct{ code string }

func (e apiErr) Error() string                 { return e.code }
func (e apiErr) ErrorCode() string             { return e.code }
func (e apiErr) ErrorMessage() string          { return e.code }
func (e apiErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestHealthNeedsSupportAndSaysSoInsteadOfLookingBroken(t *testing.T) {
	f := &fake{healthErr: apiErr{"SubscriptionRequiredException"}}
	_, err := (&healthC{src(f)}).Collect(context.Background(), env())
	if !errors.Is(err, watch.ErrNotAvailable) {
		t.Fatalf("want ErrNotAvailable, got %v", err)
	}
}

func TestHealthIssueIsCriticalOnlyWhenItTouchesSomethingYouRun(t *testing.T) {
	f := &fake{
		events: []healthTypes.Event{
			{Arn: aws.String("ev-1"), EventTypeCode: aws.String("AWS_RDS_OPERATIONAL_ISSUE"), Service: aws.String("RDS"), Region: aws.String("eu-west-1"), StartTime: aws.Time(now.Add(-time.Hour))},
		},
		entities: []healthTypes.AffectedEntity{{EntityValue: aws.String("orders-2")}},
	}
	obs, err := (&healthC{src(f)}).Collect(context.Background(), env(engine.ResourceNode{ID: "orders-2", Name: "orders-2", Type: "aws_rds_instance"}))
	if err != nil || len(obs) != 1 {
		t.Fatalf("obs %d err %v", len(obs), err)
	}
	if o := obs[0]; o.Severity != watch.SevCrit || o.NodeID != "orders-2" || !o.Immediate || o.Title != "aws rds operational issue" {
		t.Fatalf("%+v", o)
	}
	f.entities = []healthTypes.AffectedEntity{{EntityValue: aws.String("something-we-do-not-run")}}
	obs, _ = (&healthC{src(f)}).Collect(context.Background(), env())
	if obs[0].Severity != watch.SevWarn || obs[0].NodeID != "" {
		t.Fatalf("an AWS issue that does not touch you is context, not a fire: %+v", obs[0])
	}
}

func TestAFailingRegionFailsTheCollectorSoSilenceIsNeverReadAsHealthy(t *testing.T) {
	f := &fake{failRegion: "eu-north-1"}
	_, err := (&alarms{src(f, "eu-west-1", "eu-north-1")}).Collect(context.Background(), env())
	if err == nil || !strings.Contains(err.Error(), "eu-north-1") || !strings.Contains(err.Error(), "ExpiredToken") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunnerWithTheRealCollectorsRaisesSlowOnesLateAndFastOnesAtOnce(t *testing.T) {
	f := &fake{
		alarms:   []cwTypes.MetricAlarm{{AlarmName: aws.String("a"), ActionsEnabled: aws.Bool(true), AlarmActions: []string{"x"}, StateReason: aws.String("r"), StateUpdatedTimestamp: aws.Time(now)}},
		clusters: []string{"c"},
		services: map[string][]ecsTypes.Service{"c": {{ServiceArn: aws.String("arn:svc"), ServiceName: aws.String("svc"), Status: aws.String("ACTIVE"), DesiredCount: 2, RunningCount: 1}}},
	}
	clock := now
	r := &watch.Runner{
		Collectors: Collectors(src(f)),
		Tracker:    watch.NewTracker(2, 2),
		Graph:      watch.NewGraph(engine.ScanResult{}),
		Now:        func() time.Time { return clock },
	}
	r.PollOnce(context.Background())
	snap := r.Snapshot()
	if snap.Crit+snap.Warn != 1 {
		t.Fatalf("after one poll only the alarm should show: %+v", snap.Incidents)
	}
	clock = clock.Add(61 * time.Second)
	r.PollOnce(context.Background())
	if s := r.Snapshot(); s.Crit+s.Warn != 2 {
		t.Fatalf("after two polls the ecs problem shows too: %+v", s.Incidents)
	}
}

func TestAutoScalingAlarmsAreNotIllnessEvenWhenTheyAreInAlarm(t *testing.T) {
	scale := "arn:aws:autoscaling:eu-west-1:1:scalingPolicy:abc:resource/ecs/service/c/s:policyName/p"
	f := &fake{alarms: []cwTypes.MetricAlarm{
		{AlarmName: aws.String("TargetTracking-service/c/s-AlarmLow-1"), AlarmActions: []string{scale}, ActionsEnabled: aws.Bool(true)},
		{AlarmName: aws.String("q_sqs-scale-in"), AlarmActions: []string{scale}, ActionsEnabled: aws.Bool(true)},
		{AlarmName: aws.String("custom-name-but-scaling-only"), AlarmActions: []string{scale, scale}, ActionsEnabled: aws.Bool(true)},
		{AlarmName: aws.String("pages-and-scales"), AlarmActions: []string{scale, "arn:aws:sns:eu-west-1:1:oncall"}, ActionsEnabled: aws.Bool(true)},
		{AlarmName: aws.String("real-alarm"), AlarmActions: []string{"arn:aws:sns:eu-west-1:1:oncall"}, ActionsEnabled: aws.Bool(true)},
	}}
	obs, err := (&alarms{src(f)}).Collect(context.Background(), env())
	if err != nil || len(obs) != 2 {
		t.Fatalf("only the two alarms that tell a person should remain, got %d (%v)", len(obs), err)
	}
	m := byKind(obs)
	if _, ok := m["alarm.firing|pages-and-scales"]; !ok {
		t.Fatal("an alarm that also notifies a person is not capacity control")
	}
	if _, ok := m["alarm.firing|real-alarm"]; !ok {
		t.Fatal("real alarm lost")
	}
}

func TestHealthIssuesInRegionsYouDoNotUseAreIgnored(t *testing.T) {
	f := &fake{events: []healthTypes.Event{
		{Arn: aws.String("e1"), EventTypeCode: aws.String("AWS_X_ISSUE"), Service: aws.String("X"), Region: aws.String("me-central-1")},
		{Arn: aws.String("e2"), EventTypeCode: aws.String("AWS_Y_ISSUE"), Service: aws.String("Y"), Region: aws.String("eu-west-1")},
		{Arn: aws.String("e3"), EventTypeCode: aws.String("AWS_Z_ISSUE"), Service: aws.String("Z"), Region: aws.String("global")},
	}}
	obs, err := (&healthC{src(f, "eu-west-1")}).Collect(context.Background(), env())
	if err != nil || len(obs) != 2 {
		t.Fatalf("obs %d err %v", len(obs), err)
	}
}

func TestScalingAlarmsAreRecognisedByNameEvenWithoutAPolicy(t *testing.T) {
	f := &fake{alarms: []cwTypes.MetricAlarm{
		{AlarmName: aws.String("bad-eddy_sqs-scale-in")}, {AlarmName: aws.String("x-ScaleOut-high")}, {AlarmName: aws.String("db-cpu-high")},
	}}
	obs, _ := (&alarms{src(f)}).Collect(context.Background(), env())
	if len(obs) != 1 || obs[0].Title != "db-cpu-high" {
		t.Fatalf("%+v", obs)
	}
}

func TestOnlyRegionsHoldingTheKindOfResourceAreAsked(t *testing.T) {
	g := watch.NewGraph(engine.ScanResult{Nodes: []engine.ResourceNode{
		{ID: "svc", Type: "aws_ecs_service", Region: "eu-west-1"},
		{ID: "lb", Type: "aws_lb", Region: "eu-north-1"},
		{ID: "x", Type: "aws_s3_bucket", Region: "us-east-2"},
	}})
	if got := g.Regions("aws_ecs_service"); len(got) != 1 || got[0] != "eu-west-1" {
		t.Fatalf("ecs regions %v", got)
	}
	if got := g.Regions(); len(got) != 3 {
		t.Fatalf("all regions %v", got)
	}
}
