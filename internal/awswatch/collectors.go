package awswatch

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go"

	"infralens/internal/watch"
)

// Source is what every collector needs: API clients and the regions worth
// asking about (those where the last scan found resources).
type Source struct {
	Clients Clients
	Regions func() []string
}

// Collectors returns the free-state collectors in the order the screen lists
// them. None of them costs anything per call.
func Collectors(s Source) []watch.Collector {
	return []watch.Collector{&alarms{s}, &ecsC{s}, &elbC{s}, &rdsC{s}, &sqsC{s}, &healthC{s}}
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// perRegion runs fn in each region and joins the results. A region that
// fails fails the collector: a half-answer must not read as "all clear".
func perRegion(ctx context.Context, s Source, fn func(region string) ([]watch.Observation, error)) ([]watch.Observation, error) {
	var out []watch.Observation
	for _, r := range s.Regions() {
		got, err := fn(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r, err)
		}
		out = append(out, got...)
	}
	return out, nil
}

// ---- CloudWatch alarms ---------------------------------------------------------

type alarms struct{ s Source }

func (*alarms) Name() string  { return "alarms" }
func (*alarms) Metered() bool { return false }

// dimensionRef picks the dimension that names the resource an alarm watches.
var dimensionOrder = []string{"ServiceName", "DBInstanceIdentifier", "DBClusterIdentifier", "LoadBalancer", "FunctionName",
	"QueueName", "StreamName", "DomainName", "NatGatewayId", "TableName", "InstanceId", "DeliveryStreamName", "DistributionId"}

func dimensionRef(dims []cwTypes.Dimension) string {
	byName := map[string]string{}
	for _, d := range dims {
		byName[aws.ToString(d.Name)] = aws.ToString(d.Value)
	}
	for _, n := range dimensionOrder {
		if v := byName[n]; v != "" {
			if n == "LoadBalancer" { // app/name/id
				if i := strings.Index(v, "/"); i >= 0 {
					v = v[i+1:]
					if j := strings.Index(v, "/"); j >= 0 {
						v = v[:j]
					}
				}
			}
			return v
		}
	}
	return ""
}

func (a *alarms) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	return perRegion(ctx, a.s, func(region string) ([]watch.Observation, error) {
		cw, err := a.s.Clients.CloudWatch(ctx, region)
		if err != nil {
			return nil, err
		}
		var out []watch.Observation
		p := cloudwatch.NewDescribeAlarmsPaginator(cw, &cloudwatch.DescribeAlarmsInput{
			StateValue: cwTypes.StateValueAlarm,
			AlarmTypes: []cwTypes.AlarmType{cwTypes.AlarmTypeMetricAlarm, cwTypes.AlarmTypeCompositeAlarm},
		})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, m := range page.MetricAlarms {
				sev := watch.SevWarn
				if aws.ToBool(m.ActionsEnabled) && len(m.AlarmActions) > 0 {
					sev = watch.SevCrit // someone wired this alarm to be told about it
				}
				thr := ""
				if m.Threshold != nil {
					thr = fmt.Sprintf("%s %s %s %v (%d × %d s)", aws.ToString(m.MetricName), statistic(m), cmp(m.ComparisonOperator), *m.Threshold, aws.ToInt32(m.EvaluationPeriods), aws.ToInt32(m.Period))
				}
				out = append(out, watch.Observation{Immediate: true, Signal: watch.Signal{
					Key: "alarms|" + region + "|" + aws.ToString(m.AlarmName), Kind: "alarm.firing",
					NodeID: dimensionRef(m.Dimensions), Severity: sev, Since: aws.ToTime(m.StateUpdatedTimestamp),
					Title: aws.ToString(m.AlarmName), Threshold: thr,
					Evidence: []string{oneLine(aws.ToString(m.StateReason), 240), "alarm in " + region},
				}})
			}
			for _, c := range page.CompositeAlarms {
				sev := watch.SevWarn
				if aws.ToBool(c.ActionsEnabled) && len(c.AlarmActions) > 0 {
					sev = watch.SevCrit
				}
				out = append(out, watch.Observation{Immediate: true, Signal: watch.Signal{
					Key: "alarms|" + region + "|" + aws.ToString(c.AlarmName), Kind: "alarm.firing",
					Severity: sev, Since: aws.ToTime(c.StateUpdatedTimestamp), Title: aws.ToString(c.AlarmName),
					Evidence: []string{oneLine(aws.ToString(c.StateReason), 240), "composite alarm in " + region},
				}})
			}
		}
		return out, nil
	})
}

func statistic(m cwTypes.MetricAlarm) string {
	if m.ExtendedStatistic != nil {
		return aws.ToString(m.ExtendedStatistic)
	}
	return string(m.Statistic)
}

func cmp(op cwTypes.ComparisonOperator) string {
	switch op {
	case cwTypes.ComparisonOperatorGreaterThanThreshold:
		return ">"
	case cwTypes.ComparisonOperatorGreaterThanOrEqualToThreshold:
		return ">="
	case cwTypes.ComparisonOperatorLessThanThreshold:
		return "<"
	case cwTypes.ComparisonOperatorLessThanOrEqualToThreshold:
		return "<="
	}
	return string(op)
}

// ---- ECS ------------------------------------------------------------------------

type ecsC struct{ s Source }

func (*ecsC) Name() string  { return "ecs" }
func (*ecsC) Metered() bool { return false }

func (e *ecsC) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	return perRegion(ctx, e.s, func(region string) ([]watch.Observation, error) {
		api, err := e.s.Clients.ECS(ctx, region)
		if err != nil {
			return nil, err
		}
		var out []watch.Observation
		cp := ecs.NewListClustersPaginator(api, &ecs.ListClustersInput{})
		for cp.HasMorePages() {
			cpage, err := cp.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, cluster := range cpage.ClusterArns {
				var arns []string
				sp := ecs.NewListServicesPaginator(api, &ecs.ListServicesInput{Cluster: aws.String(cluster)})
				for sp.HasMorePages() {
					sp2, err := sp.NextPage(ctx)
					if err != nil {
						return nil, err
					}
					arns = append(arns, sp2.ServiceArns...)
				}
				for i := 0; i < len(arns); i += 10 {
					end := i + 10
					if end > len(arns) {
						end = len(arns)
					}
					d, err := api.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: aws.String(cluster), Services: arns[i:end]})
					if err != nil {
						return nil, err
					}
					for _, svc := range d.Services {
						if o, ok := e.problem(ctx, api, cluster, svc, env.Now); ok {
							out = append(out, o)
						}
					}
				}
			}
		}
		return out, nil
	})
}

func (e *ecsC) problem(ctx context.Context, api ecsAPI, cluster string, svc ecsTypes.Service, now time.Time) (watch.Observation, bool) {
	if aws.ToString(svc.Status) != "ACTIVE" {
		return watch.Observation{}, false
	}
	desired, running := svc.DesiredCount, svc.RunningCount
	failedRollout := false
	for _, d := range svc.Deployments {
		if d.RolloutState == ecsTypes.DeploymentRolloutStateFailed {
			failedRollout = true
		}
	}
	short := desired > 0 && running < desired
	if !short && !failedRollout {
		return watch.Observation{}, false
	}
	sev := watch.SevWarn
	title := fmt.Sprintf("%d of %d tasks %s running", running, desired, map[bool]string{true: "is", false: "are"}[running == 1])
	if desired > 0 && running == 0 {
		sev = watch.SevCrit
		title = fmt.Sprintf("no tasks running (%d wanted)", desired)
	}
	var ev []string
	if failedRollout {
		ev = append(ev, "the latest deployment failed")
		if !short {
			title = "the latest deployment failed"
		}
	}
	for _, r := range stoppedReasons(ctx, api, cluster, aws.ToString(svc.ServiceName)) {
		ev = append(ev, r)
	}
	for _, event := range svc.Events {
		if len(ev) >= 5 {
			break
		}
		if now.Sub(aws.ToTime(event.CreatedAt)) < 20*time.Minute && looksBad(aws.ToString(event.Message)) {
			ev = append(ev, oneLine(aws.ToString(event.Message), 200))
		}
	}
	return watch.Observation{Signal: watch.Signal{
		Kind: "ecs.under-replicated", NodeID: aws.ToString(svc.ServiceArn), Severity: sev, Title: title,
		Threshold: "running count below desired", Evidence: ev,
	}}, true
}

func looksBad(m string) bool {
	m = strings.ToLower(m)
	for _, w := range []string{"unable", "fail", "unhealthy", "stopped", "insufficient", "cannot"} {
		if strings.Contains(m, w) {
			return true
		}
	}
	return false
}

// stoppedReasons asks why recent tasks stopped. It is only called for a
// service that is already in trouble, so the extra calls are rare.
func stoppedReasons(ctx context.Context, api ecsAPI, cluster, service string) []string {
	lt, err := api.ListTasks(ctx, &ecs.ListTasksInput{Cluster: aws.String(cluster), ServiceName: aws.String(service),
		DesiredStatus: ecsTypes.DesiredStatusStopped, MaxResults: aws.Int32(10)})
	if err != nil || len(lt.TaskArns) == 0 {
		return nil
	}
	dt, err := api.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(cluster), Tasks: lt.TaskArns})
	if err != nil {
		return nil
	}
	count := map[string]int{}
	for _, t := range dt.Tasks {
		r := oneLine(aws.ToString(t.StoppedReason), 140)
		for _, c := range t.Containers {
			if c.ExitCode != nil && *c.ExitCode != 0 {
				r += fmt.Sprintf(" (exit code %d)", *c.ExitCode)
				break
			}
		}
		if r != "" {
			count[r]++
		}
	}
	type kv struct {
		k string
		n int
	}
	var list []kv
	for k, n := range count {
		list = append(list, kv{k, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].k < list[j].k
	})
	var out []string
	for i, x := range list {
		if i == 3 {
			break
		}
		out = append(out, fmt.Sprintf("%d task(s) stopped: %s", x.n, x.k))
	}
	return out
}

// ---- load balancers ---------------------------------------------------------------

type elbC struct{ s Source }

func (*elbC) Name() string         { return "elb" }
func (*elbC) Metered() bool        { return false }
func (*elbC) Every() time.Duration { return time.Minute }

func (e *elbC) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	return perRegion(ctx, e.s, func(region string) ([]watch.Observation, error) {
		api, err := e.s.Clients.ELB(ctx, region)
		if err != nil {
			return nil, err
		}
		var out []watch.Observation
		p := elasticloadbalancingv2.NewDescribeTargetGroupsPaginator(api, &elasticloadbalancingv2.DescribeTargetGroupsInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, tg := range page.TargetGroups {
				if len(tg.LoadBalancerArns) == 0 {
					continue // not attached to a balancer: nothing depends on it
				}
				h, err := api.DescribeTargetHealth(ctx, &elasticloadbalancingv2.DescribeTargetHealthInput{TargetGroupArn: tg.TargetGroupArn})
				if err != nil {
					return nil, err
				}
				healthy, unhealthy := 0, 0
				var why []string
				for _, d := range h.TargetHealthDescriptions {
					if d.TargetHealth == nil {
						continue
					}
					switch d.TargetHealth.State {
					case elbTypes.TargetHealthStateEnumHealthy:
						healthy++
					case elbTypes.TargetHealthStateEnumUnhealthy:
						unhealthy++
						if len(why) < 3 {
							id := ""
							if d.Target != nil {
								id = aws.ToString(d.Target.Id)
							}
							why = append(why, strings.TrimSpace(fmt.Sprintf("%s %s", d.TargetHealth.Reason, oneLine(aws.ToString(d.TargetHealth.Description), 100)))+" ("+id+")")
						}
					}
				}
				if unhealthy == 0 {
					continue
				}
				sev := watch.SevWarn
				if healthy == 0 {
					sev = watch.SevCrit
				}
				out = append(out, watch.Observation{Signal: watch.Signal{
					Key: "elb|" + aws.ToString(tg.TargetGroupArn), Kind: "elb.unhealthy-targets", NodeID: tg.LoadBalancerArns[0],
					Severity: sev, Title: fmt.Sprintf("%d of %d targets are unhealthy", unhealthy, healthy+unhealthy),
					Threshold: "any unhealthy target in " + aws.ToString(tg.TargetGroupName), Evidence: why,
				}})
			}
		}
		return out, nil
	})
}

// ---- RDS --------------------------------------------------------------------------

type rdsC struct{ s Source }

func (*rdsC) Name() string  { return "rds" }
func (*rdsC) Metered() bool { return false }

// badRDSStatus lists states that mean "broken", not "busy". Transient states
// (modifying, backing-up, rebooting) are left out on purpose.
var badRDSStatus = map[string]bool{
	"failed": true, "storage-full": true, "incompatible-credentials": true, "incompatible-network": true,
	"incompatible-option-group": true, "incompatible-parameters": true, "incompatible-restore": true,
	"inaccessible-encryption-credentials": true, "inaccessible-encryption-credentials-recoverable": true,
	"restore-error": true, "insufficient-capacity": true, "kms-key-error": true,
}

func (r *rdsC) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	return perRegion(ctx, r.s, func(region string) ([]watch.Observation, error) {
		api, err := r.s.Clients.RDS(ctx, region)
		if err != nil {
			return nil, err
		}
		var out []watch.Observation
		ip := rds.NewDescribeDBInstancesPaginator(api, &rds.DescribeDBInstancesInput{})
		for ip.HasMorePages() {
			page, err := ip.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, d := range page.DBInstances {
				if st := aws.ToString(d.DBInstanceStatus); badRDSStatus[st] {
					out = append(out, rdsObs(aws.ToString(d.DBInstanceIdentifier), "instance", st))
				}
			}
		}
		cp := rds.NewDescribeDBClustersPaginator(api, &rds.DescribeDBClustersInput{})
		for cp.HasMorePages() {
			page, err := cp.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, c := range page.DBClusters {
				if st := aws.ToString(c.Status); badRDSStatus[st] {
					out = append(out, rdsObs(aws.ToString(c.DBClusterIdentifier), "cluster", st))
				}
			}
		}
		return out, nil
	})
}

func rdsObs(id, kind, status string) watch.Observation {
	return watch.Observation{Signal: watch.Signal{
		Kind: "rds.bad-status", NodeID: id, Severity: watch.SevCrit,
		Title:     "database " + kind + " is in state " + status,
		Threshold: "state is one of the broken states",
		Evidence:  []string{"status " + status},
	}}
}

// ---- dead-letter queues --------------------------------------------------------------

type sqsC struct{ s Source }

func (*sqsC) Name() string         { return "sqs" }
func (*sqsC) Metered() bool        { return false }
func (*sqsC) Every() time.Duration { return 2 * time.Minute }

func isDLQ(url string) bool {
	n := strings.ToLower(url[strings.LastIndex(url, "/")+1:])
	return strings.Contains(n, "dlq") || strings.Contains(n, "dead")
}

func (q *sqsC) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	return perRegion(ctx, q.s, func(region string) ([]watch.Observation, error) {
		api, err := q.s.Clients.SQS(ctx, region)
		if err != nil {
			return nil, err
		}
		var out []watch.Observation
		p := sqs.NewListQueuesPaginator(api, &sqs.ListQueuesInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, u := range page.QueueUrls {
				if !isDLQ(u) {
					continue
				}
				a, err := api.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: aws.String(u),
					AttributeNames: []sqsTypes.QueueAttributeName{sqsTypes.QueueAttributeNameApproximateNumberOfMessages}})
				if err != nil {
					return nil, err
				}
				var n int
				fmt.Sscanf(a.Attributes[string(sqsTypes.QueueAttributeNameApproximateNumberOfMessages)], "%d", &n)
				if n == 0 {
					continue
				}
				sev := watch.SevWarn
				if n >= 100 {
					sev = watch.SevCrit
				}
				out = append(out, watch.Observation{Signal: watch.Signal{
					Kind: "sqs.dlq-not-empty", NodeID: u, Severity: sev,
					Title:     fmt.Sprintf("%d message(s) waiting in a dead-letter queue", n),
					Threshold: "a dead-letter queue is not empty",
					Evidence:  []string{"messages that failed processing and were set aside"},
				}})
			}
		}
		return out, nil
	})
}

// ---- AWS Health -----------------------------------------------------------------------

type healthC struct{ s Source }

func (*healthC) Name() string         { return "health" }
func (*healthC) Metered() bool        { return false }
func (*healthC) Every() time.Duration { return 2 * time.Minute }

func (h *healthC) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	api, err := h.s.Clients.Health(ctx)
	if err != nil {
		return nil, err
	}
	ev, err := api.DescribeEvents(ctx, &health.DescribeEventsInput{Filter: &healthTypes.EventFilter{
		EventStatusCodes:    []healthTypes.EventStatusCode{healthTypes.EventStatusCodeOpen},
		EventTypeCategories: []healthTypes.EventTypeCategory{healthTypes.EventTypeCategoryIssue},
	}})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && ae.ErrorCode() == "SubscriptionRequiredException" {
			return nil, fmt.Errorf("%w: AWS Health needs a Business or Enterprise support plan", watch.ErrNotAvailable)
		}
		return nil, err
	}
	var out []watch.Observation
	for _, e := range ev.Events {
		node := ""
		sev := watch.SevWarn
		if e.Arn != nil {
			if ents, err := api.DescribeAffectedEntities(ctx, &health.DescribeAffectedEntitiesInput{
				Filter: &healthTypes.EntityFilter{EventArns: []string{aws.ToString(e.Arn)}}}); err == nil {
				for _, x := range ents.Entities {
					if id, ok := env.Graph.Resolve(aws.ToString(x.EntityValue)); ok {
						node, sev = id, watch.SevCrit
						break
					}
				}
			}
		}
		out = append(out, watch.Observation{Immediate: true, Signal: watch.Signal{
			Key: "health|" + aws.ToString(e.Arn), Kind: "health.open-issue", NodeID: node, Severity: sev,
			Since:    aws.ToTime(e.StartTime),
			Title:    strings.ToLower(strings.ReplaceAll(aws.ToString(e.EventTypeCode), "_", " ")),
			Evidence: []string{"AWS reports an open issue with " + aws.ToString(e.Service) + " in " + aws.ToString(e.Region)},
		}})
	}
	return out, nil
}
