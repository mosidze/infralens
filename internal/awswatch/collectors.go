package awswatch

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
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
	// Regions returns the regions worth asking about, optionally only those
	// holding resources of the given node types.
	Regions func(nodeTypes ...string) []string
}

// Collectors returns the free-state collectors in the order the screen lists
// them. None of them costs anything per call.
func Collectors(s Source) []watch.Collector {
	return []watch.Collector{&alarms{s}, &ecsC{s: s}, &elbC{s}, &rdsC{s}, &sqsC{s: s}, &healthC{s}}
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// perRegion runs fn in every region, a few at a time. A region that fails
// fails the collector: a half-answer must not read as "all clear".
func perRegion(ctx context.Context, s Source, nodeTypes []string, fn func(region string) ([]watch.Observation, error)) ([]watch.Observation, error) {
	regions := s.Regions(nodeTypes...)
	results := make([][]watch.Observation, len(regions))
	errs := make([]error, len(regions))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, r := range regions {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, r string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i], errs[i] = fn(r)
		}(i, r)
	}
	wg.Wait()
	var out []watch.Observation
	for i, r := range regions {
		if errs[i] != nil {
			return nil, fmt.Errorf("%s: %w", r, errs[i])
		}
		out = append(out, results[i]...)
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

// capacityControl reports whether an alarm only exists to drive Auto Scaling.
// Target-tracking and step-scaling alarms sit in ALARM whenever a service is
// under- or over-used; that is the scaler doing its job, not something being
// ill, and on a busy account they outnumber real alarms a hundred to one.
func capacityControl(name string, actions []string) bool {
	if strings.HasPrefix(name, "TargetTracking-") {
		return true
	}
	// alarms that exist to trigger scaling are named for it, whether or not a
	// scaling policy is attached to them
	low := strings.ToLower(name)
	for _, w := range []string{"scale-in", "scale-out", "scalein", "scaleout", "scale_in", "scale_out", "alarmlow", "alarmhigh"} {
		if strings.Contains(low, w) {
			return true
		}
	}
	if len(actions) == 0 {
		return false
	}
	for _, a := range actions {
		if !strings.Contains(a, ":autoscaling:") && !strings.Contains(a, "scalingPolicy") {
			return false
		}
	}
	return true
}

func (a *alarms) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	return perRegion(ctx, a.s, nil, func(region string) ([]watch.Observation, error) {
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
				if capacityControl(aws.ToString(m.AlarmName), m.AlarmActions) {
					continue
				}
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
				if capacityControl(aws.ToString(c.AlarmName), c.AlarmActions) {
					continue
				}
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

// ecsC lists each cluster's services only now and then (they change rarely)
// and asks about their state every minute, which keeps the call count low.
type ecsC struct {
	s     Source
	mu    sync.Mutex
	cache map[string]svcList
}

type svcList struct {
	arns []string
	at   time.Time
}

const svcListTTL = 10 * time.Minute

func (e *ecsC) services(ctx context.Context, api ecsAPI, cluster string, now time.Time) ([]string, error) {
	e.mu.Lock()
	if c, ok := e.cache[cluster]; ok && now.Sub(c.at) < svcListTTL {
		e.mu.Unlock()
		return c.arns, nil
	}
	e.mu.Unlock()
	var arns []string
	sp := ecs.NewListServicesPaginator(api, &ecs.ListServicesInput{Cluster: aws.String(cluster)})
	for sp.HasMorePages() {
		page, err := sp.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		arns = append(arns, page.ServiceArns...)
	}
	e.mu.Lock()
	if e.cache == nil {
		e.cache = map[string]svcList{}
	}
	e.cache[cluster] = svcList{arns, now}
	e.mu.Unlock()
	return arns, nil
}

func (*ecsC) Name() string         { return "ecs" }
func (*ecsC) Metered() bool        { return false }
func (*ecsC) Every() time.Duration { return time.Minute }

func (e *ecsC) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	return perRegion(ctx, e.s, []string{"aws_ecs_service", "aws_ecs_cluster"}, func(region string) ([]watch.Observation, error) {
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
				arns, err := e.services(ctx, api, cluster, env.Now)
				if err != nil {
					return nil, err
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
	var since time.Time // when a failed deployment last moved: the earliest honest start we know
	for _, d := range svc.Deployments {
		if d.RolloutState == ecsTypes.DeploymentRolloutStateFailed {
			failedRollout = true
			if t := aws.ToTime(d.UpdatedAt); t.After(since) {
				since = t
			}
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
		Kind: "ecs.under-replicated", NodeID: aws.ToString(svc.ServiceArn), Severity: sev, Title: title, Since: since,
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
	return perRegion(ctx, e.s, []string{"aws_lb"}, func(region string) ([]watch.Observation, error) {
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

func (*rdsC) Name() string         { return "rds" }
func (*rdsC) Metered() bool        { return false }
func (*rdsC) Every() time.Duration { return time.Minute }

// badRDSStatus lists states that mean "broken", not "busy". Transient states
// (modifying, backing-up, rebooting) are left out on purpose.
var badRDSStatus = map[string]bool{
	"failed": true, "storage-full": true, "incompatible-credentials": true, "incompatible-network": true,
	"incompatible-option-group": true, "incompatible-parameters": true, "incompatible-restore": true,
	"inaccessible-encryption-credentials": true, "inaccessible-encryption-credentials-recoverable": true,
	"restore-error": true, "insufficient-capacity": true, "kms-key-error": true,
}

func (r *rdsC) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	return perRegion(ctx, r.s, []string{"aws_rds_instance"}, func(region string) ([]watch.Observation, error) {
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

// sqsC watches dead-letter queues for *growth*. A queue that has held the same
// messages for months is a backlog somebody has left alone, not something that
// is sick now; one that is filling is. It remembers depths between polls, so
// it needs a couple of polls before it can tell the two apart.
type sqsC struct {
	s    Source
	mu   sync.Mutex
	hist map[string][]depthPoint
}

type depthPoint struct {
	t time.Time
	n int
}

const dlqWindow = 45 * time.Minute

func (*sqsC) Name() string         { return "sqs" }
func (*sqsC) Metered() bool        { return false }
func (*sqsC) Every() time.Duration { return 5 * time.Minute }

func isDLQ(url string) bool {
	n := strings.ToLower(url[strings.LastIndex(url, "/")+1:])
	return strings.Contains(n, "dlq") || strings.Contains(n, "dead")
}

// observe records a depth and returns how much the queue has grown over the
// window and whether there was an earlier reading to compare with.
func (q *sqsC) observe(url string, n int, now time.Time) (grew int, known bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.hist == nil {
		q.hist = map[string][]depthPoint{}
	}
	var keep []depthPoint
	for _, p := range q.hist[url] {
		if now.Sub(p.t) <= dlqWindow {
			keep = append(keep, p)
		}
	}
	if len(keep) > 0 {
		base := keep[0].n
		for _, p := range keep {
			if p.n < base {
				base = p.n
			}
		}
		grew, known = n-base, true
	}
	q.hist[url] = append(keep, depthPoint{now, n})
	return grew, known
}

func (q *sqsC) Collect(ctx context.Context, env *watch.Env) ([]watch.Observation, error) {
	return perRegion(ctx, q.s, []string{"aws_sqs_queue"}, func(region string) ([]watch.Observation, error) {
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
				grew, known := q.observe(u, n, env.Now)
				if n == 0 {
					continue
				}
				sig := watch.Signal{Kind: "sqs.dlq-growing", NodeID: u, Severity: watch.SevWarn,
					Threshold: "a dead-letter queue is filling"}
				switch {
				case known && grew > 0:
					if grew >= 100 {
						sig.Severity = watch.SevCrit
					}
					sig.Title = fmt.Sprintf("dead-letter queue is filling: %d message(s), +%d recently", n, grew)
					sig.Evidence = []string{"messages that failed processing keep arriving"}
				default:
					sig.Chronic = true
					sig.Kind = "sqs.dlq-standing"
					sig.Title = fmt.Sprintf("%d message(s) standing in a dead-letter queue", n)
					sig.Evidence = []string{"the depth is not growing (or has only just been observed)"}
				}
				out = append(out, watch.Observation{Signal: sig})
			}
		}
		return out, nil
	})
}

// ---- AWS Health -----------------------------------------------------------------------

type healthC struct{ s Source }

func (*healthC) Name() string         { return "health" }
func (*healthC) Metered() bool        { return false }
func (*healthC) Every() time.Duration { return 5 * time.Minute }

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
	watched := map[string]bool{"": true, "global": true}
	for _, r := range h.s.Regions() {
		watched[r] = true
	}
	var out []watch.Observation
	for _, e := range ev.Events {
		// An outage in a region where nothing of yours runs is not your problem.
		if !watched[aws.ToString(e.Region)] {
			continue
		}
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
