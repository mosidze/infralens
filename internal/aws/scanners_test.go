package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbTypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kTypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// ---- fakes -----------------------------------------------------------------

// fakeCW answers GetMetricStatistics from canned daily values keyed by
// "namespace/metric/<first dimension value>". A missing key yields no datapoints.
type fakeCW struct {
	data map[string][]float64
	err  error
}

func (f fakeCW) GetMetricStatistics(_ context.Context, in *cloudwatch.GetMetricStatisticsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	key := aws.ToString(in.Namespace) + "/" + aws.ToString(in.MetricName)
	if len(in.Dimensions) > 0 {
		key += "/" + aws.ToString(in.Dimensions[0].Value)
	}
	out := &cloudwatch.GetMetricStatisticsOutput{}
	for _, v := range f.data[key] {
		v := v
		out.Datapoints = append(out.Datapoints, cwTypes.Datapoint{Sum: &v, Maximum: &v, Average: &v})
	}
	return out, nil
}

func days(n int, v float64) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func newTestCollector() *collector { return newCollector("eu-north-1", DefaultThresholds()) }

func nodeByID(t *testing.T, c *collector, id string) engine.ResourceNode {
	t.Helper()
	for _, n := range c.nodes {
		if n.ID == id {
			return n
		}
	}
	t.Fatalf("node %q not produced; have %d nodes", id, len(c.nodes))
	return engine.ResourceNode{}
}

func hasEvidence(n engine.ResourceNode, sub string) bool {
	for _, e := range n.Evidence {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

func daysAgo(n int) *time.Time { t := time.Now().Add(-time.Duration(n) * 24 * time.Hour); return &t }

// ---- RDS -------------------------------------------------------------------

type fakeRDS struct {
	instances  []rdsTypes.DBInstance
	clusters   []rdsTypes.DBCluster
	clusterErr error
}

func (f fakeRDS) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: f.instances}, nil
}
func (f fakeRDS) DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	if f.clusterErr != nil {
		return nil, f.clusterErr
	}
	return &rds.DescribeDBClustersOutput{DBClusters: f.clusters}, nil
}

func dbInst(id string, age int, status string) rdsTypes.DBInstance {
	return rdsTypes.DBInstance{
		DBInstanceIdentifier: aws.String(id), DBInstanceClass: aws.String("db.r6g.large"),
		DBInstanceStatus: aws.String(status), AllocatedStorage: aws.Int32(100),
		StorageType: aws.String("aurora"), Engine: aws.String("aurora-postgresql"),
		InstanceCreateTime: daysAgo(age),
	}
}

func TestRDSVerdictsFromAPIResponses(t *testing.T) {
	api := fakeRDS{
		instances: []rdsTypes.DBInstance{
			dbInst("pg-writer", 400, "available"),  // idle writer of a 2-member cluster
			dbInst("pg-reader", 400, "available"),  // idle reader of the same cluster
			dbInst("solo-idle", 400, "available"),  // standalone, idle
			dbInst("solo-busy", 400, "available"),  // standalone, has connections
			dbInst("solo-young", 3, "available"),   // idle but 3 days old
			dbInst("solo-stopped", 400, "stopped"), // not available: not judged
		},
		clusters: []rdsTypes.DBCluster{{
			DBClusterIdentifier: aws.String("pg"),
			DBClusterMembers: []rdsTypes.DBClusterMember{
				{DBInstanceIdentifier: aws.String("pg-writer"), IsClusterWriter: aws.Bool(true)},
				{DBInstanceIdentifier: aws.String("pg-reader"), IsClusterWriter: aws.Bool(false)},
			},
		}},
	}
	cw := fakeCW{data: map[string][]float64{
		"AWS/RDS/DatabaseConnections/pg-writer":    days(14, 0),
		"AWS/RDS/DatabaseConnections/pg-reader":    days(14, 0),
		"AWS/RDS/DatabaseConnections/solo-idle":    days(14, 0),
		"AWS/RDS/DatabaseConnections/solo-busy":    days(14, 7),
		"AWS/RDS/DatabaseConnections/solo-young":   days(3, 0),
		"AWS/RDS/DatabaseConnections/solo-stopped": days(14, 0),
	}}
	c := newTestCollector()
	scanRDSWith(context.Background(), api, cw, c)

	cases := []struct {
		id       string
		status   engine.ResourceStatus
		conf     engine.Confidence
		evidence string
	}{
		{"pg-writer", engine.StatusOrphanWaste, engine.ConfHigh, "0 connections"},
		// Regression: Aurora readers are failover standbys, idle by design.
		{"pg-reader", engine.StatusManaged, "", "standby"},
		{"solo-idle", engine.StatusOrphanWaste, engine.ConfHigh, "0 connections"},
		{"solo-busy", engine.StatusManaged, "", "max 7 connections"},
		{"solo-young", engine.StatusOrphanWaste, engine.ConfLow, "0 connections"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			n := nodeByID(t, c, tc.id)
			// "managed" here means: not flagged as waste. Tags are empty, so
			// the management classifier yields shadow_it for non-waste.
			isWaste := n.Status == engine.StatusOrphanWaste
			if isWaste != (tc.status == engine.StatusOrphanWaste) {
				t.Fatalf("waste=%v, want %v (%+v)", isWaste, tc.status == engine.StatusOrphanWaste, n.Evidence)
			}
			if isWaste && n.Confidence != tc.conf {
				t.Fatalf("confidence = %s, want %s", n.Confidence, tc.conf)
			}
			if !hasEvidence(n, tc.evidence) {
				t.Fatalf("evidence %v lacks %q", n.Evidence, tc.evidence)
			}
		})
	}
	if n := nodeByID(t, c, "solo-stopped"); n.Status == engine.StatusOrphanWaste {
		t.Fatal("a stopped database must not be judged by connections")
	}
}

func TestRDSWithoutClusterRolesJudgesNothing(t *testing.T) {
	// If cluster membership is unknown an idle standby could be called waste,
	// so no idle verdict may be issued at all.
	api := fakeRDS{
		instances:  []rdsTypes.DBInstance{dbInst("pg-reader", 400, "available")},
		clusterErr: errors.New("AccessDenied: rds:DescribeDBClusters"),
	}
	cw := fakeCW{data: map[string][]float64{"AWS/RDS/DatabaseConnections/pg-reader": days(14, 0)}}
	c := newTestCollector()
	scanRDSWith(context.Background(), api, cw, c)
	if nodeByID(t, c, "pg-reader").Status == engine.StatusOrphanWaste {
		t.Fatal("must not flag waste without cluster roles")
	}
	if len(c.warnings) == 0 {
		t.Fatal("the missing permission must surface as a warning")
	}
}

// ---- EBS, EIP, NAT ----------------------------------------------------------

type fakeEBS struct {
	volumes   []ec2Types.Volume
	snapshots []ec2Types.Snapshot
	images    []ec2Types.Image
	imagesErr error
}

func (f fakeEBS) DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return &ec2.DescribeVolumesOutput{Volumes: f.volumes}, nil
}
func (f fakeEBS) DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	return &ec2.DescribeSnapshotsOutput{Snapshots: f.snapshots}, nil
}
func (f fakeEBS) DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	if f.imagesErr != nil {
		return nil, f.imagesErr
	}
	return &ec2.DescribeImagesOutput{Images: f.images}, nil
}

func TestEBSVolumesAndSnapshots(t *testing.T) {
	api := fakeEBS{
		volumes: []ec2Types.Volume{
			{VolumeId: aws.String("vol-free"), Size: aws.Int32(100), VolumeType: ec2Types.VolumeTypeGp3, State: ec2Types.VolumeStateAvailable, CreateTime: daysAgo(30)},
			{VolumeId: aws.String("vol-used"), Size: aws.Int32(100), VolumeType: ec2Types.VolumeTypeGp3, State: ec2Types.VolumeStateInUse,
				Attachments: []ec2Types.VolumeAttachment{{InstanceId: aws.String("i-1")}}},
		},
		snapshots: []ec2Types.Snapshot{
			{SnapshotId: aws.String("snap-orphan"), VolumeId: aws.String("vol-gone"), StartTime: daysAgo(400), VolumeSize: aws.Int32(50)},
			{SnapshotId: aws.String("snap-has-volume"), VolumeId: aws.String("vol-used"), StartTime: daysAgo(400), VolumeSize: aws.Int32(50)},
			{SnapshotId: aws.String("snap-ami"), VolumeId: aws.String("vol-gone2"), StartTime: daysAgo(400), VolumeSize: aws.Int32(50)},
			{SnapshotId: aws.String("snap-young"), VolumeId: aws.String("vol-gone3"), StartTime: daysAgo(5), VolumeSize: aws.Int32(50)},
		},
		images: []ec2Types.Image{{BlockDeviceMappings: []ec2Types.BlockDeviceMapping{
			{Ebs: &ec2Types.EbsBlockDevice{SnapshotId: aws.String("snap-ami")}},
		}}},
	}
	c := newTestCollector()
	scanVolumesWith(context.Background(), api, c)

	free := nodeByID(t, c, "vol-free")
	if free.Status != engine.StatusOrphanWaste || free.Confidence != engine.ConfHigh {
		t.Fatalf("unattached volume: %+v", free)
	}
	if got := free.MonthlyCost; got < 7.9 || got > 8.1 {
		t.Fatalf("gp3 100 GB should cost about $8, got %v", got)
	}
	if nodeByID(t, c, "vol-used").Status == engine.StatusOrphanWaste {
		t.Fatal("an attached volume is not waste")
	}
	if nodeByID(t, c, "snap-orphan").Status != engine.StatusOrphanWaste {
		t.Fatal("old snapshot of a deleted volume, not used by an AMI, must be flagged")
	}
	if nodeByID(t, c, "snap-orphan").Confidence != engine.ConfLow {
		t.Fatal("snapshot cost is an upper bound, confidence must stay low")
	}
	for _, id := range []string{"snap-has-volume", "snap-ami", "snap-young"} {
		for _, n := range c.nodes {
			if n.ID == id {
				t.Fatalf("%s must not be reported as orphan", id)
			}
		}
	}
	// the attached volume links to its instance
	found := false
	for _, e := range c.edges {
		if e.Source == "i-1" && e.Target == "vol-used" {
			found = true
		}
	}
	if !found {
		t.Fatal("volume attachment edge missing")
	}
}

func TestSnapshotCheckSkippedWhenAMIsUnreadable(t *testing.T) {
	// Without the AMI list a snapshot backing an AMI could look orphaned.
	api := fakeEBS{
		snapshots: []ec2Types.Snapshot{{SnapshotId: aws.String("snap-x"), VolumeId: aws.String("vol-gone"), StartTime: daysAgo(400)}},
		imagesErr: errors.New("UnauthorizedOperation"),
	}
	c := newTestCollector()
	scanVolumesWith(context.Background(), api, c)
	for _, n := range c.nodes {
		if n.Type == "aws_ebs_snapshot" {
			t.Fatal("no snapshot may be judged without the AMI list")
		}
	}
	if len(c.warnings) == 0 {
		t.Fatal("skipped check must be reported")
	}
}

type fakeAddr struct{ addrs []ec2Types.Address }

func (f fakeAddr) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return &ec2.DescribeAddressesOutput{Addresses: f.addrs}, nil
}

func TestElasticIPs(t *testing.T) {
	c := newTestCollector()
	scanAddressesWith(context.Background(), fakeAddr{[]ec2Types.Address{
		{AllocationId: aws.String("eipalloc-used"), PublicIp: aws.String("1.1.1.1"), AssociationId: aws.String("eipassoc-1")},
		{AllocationId: aws.String("eipalloc-free"), PublicIp: aws.String("2.2.2.2")},
	}}, c)
	if len(c.nodes) != 1 || c.nodes[0].ID != "eipalloc-free" || c.nodes[0].Status != engine.StatusOrphanWaste {
		t.Fatalf("only the unassociated address is waste: %+v", c.nodes)
	}
}

type fakeNAT struct{ gws []ec2Types.NatGateway }

func (f fakeNAT) DescribeNatGateways(context.Context, *ec2.DescribeNatGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	return &ec2.DescribeNatGatewaysOutput{NatGateways: f.gws}, nil
}

func TestNATGateways(t *testing.T) {
	gw := func(id string, age int) ec2Types.NatGateway {
		return ec2Types.NatGateway{NatGatewayId: aws.String(id), State: ec2Types.NatGatewayStateAvailable,
			VpcId: aws.String("vpc-1"), CreateTime: daysAgo(age)}
	}
	cw := fakeCW{data: map[string][]float64{
		"AWS/NATGateway/BytesOutToDestination/nat-busy":   days(14, 50<<20),
		"AWS/NATGateway/BytesInFromSource/nat-busy":       days(14, 40<<20),
		"AWS/NATGateway/BytesInFromDestination/nat-busy":  days(14, 40<<20),
		"AWS/NATGateway/BytesOutToDestination/nat-silent": days(14, 0),
		"AWS/NATGateway/BytesOutToDestination/nat-new":    days(2, 0),
	}}
	c := newTestCollector()
	scanNATWith(context.Background(), fakeNAT{[]ec2Types.NatGateway{gw("nat-busy", 200), gw("nat-silent", 200), gw("nat-new", 2)}}, cw, c)

	busy := nodeByID(t, c, "nat-busy")
	if busy.Status == engine.StatusOrphanWaste {
		t.Fatal("a gateway with traffic is not waste")
	}
	if busy.MonthlyCost <= engine.MonthlyFromHourly(engine.NATGatewayHour) {
		t.Fatalf("data processing must raise the cost above the hourly floor, got %v", busy.MonthlyCost)
	}
	if s := nodeByID(t, c, "nat-silent"); s.Status != engine.StatusOrphanWaste || s.Confidence != engine.ConfHigh {
		t.Fatalf("silent old gateway: %+v", s)
	}
	if n := nodeByID(t, c, "nat-new"); n.Status != engine.StatusOrphanWaste || n.Confidence != engine.ConfLow {
		t.Fatalf("a 2-day-old gateway cannot be judged with confidence: %+v", n)
	}
}

func TestNATWithoutMetricsIsNotJudged(t *testing.T) {
	gw := ec2Types.NatGateway{NatGatewayId: aws.String("nat-1"), State: ec2Types.NatGatewayStateAvailable, CreateTime: daysAgo(300)}
	c := newTestCollector()
	scanNATWith(context.Background(), fakeNAT{[]ec2Types.NatGateway{gw}}, fakeCW{err: errors.New("AccessDenied")}, c)
	if nodeByID(t, c, "nat-1").Status == engine.StatusOrphanWaste {
		t.Fatal("CloudWatch failure must not turn into a waste verdict")
	}
	if len(c.warnings) == 0 {
		t.Fatal("CloudWatch failure must surface")
	}
}

// ---- ELB -------------------------------------------------------------------

type fakeELB struct {
	lbs       []elbTypes.LoadBalancer
	tgs       []elbTypes.TargetGroup
	listeners map[string][]elbTypes.Listener
	targets   map[string]int
}

func (f fakeELB) DescribeLoadBalancers(context.Context, *elasticloadbalancingv2.DescribeLoadBalancersInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	return &elasticloadbalancingv2.DescribeLoadBalancersOutput{LoadBalancers: f.lbs}, nil
}
func (f fakeELB) DescribeTargetGroups(context.Context, *elasticloadbalancingv2.DescribeTargetGroupsInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error) {
	return &elasticloadbalancingv2.DescribeTargetGroupsOutput{TargetGroups: f.tgs}, nil
}
func (f fakeELB) DescribeListeners(_ context.Context, in *elasticloadbalancingv2.DescribeListenersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
	return &elasticloadbalancingv2.DescribeListenersOutput{Listeners: f.listeners[aws.ToString(in.LoadBalancerArn)]}, nil
}
func (f fakeELB) DescribeTags(context.Context, *elasticloadbalancingv2.DescribeTagsInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTagsOutput, error) {
	return &elasticloadbalancingv2.DescribeTagsOutput{}, nil
}
func (f fakeELB) DescribeTargetHealth(_ context.Context, in *elasticloadbalancingv2.DescribeTargetHealthInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error) {
	out := &elasticloadbalancingv2.DescribeTargetHealthOutput{}
	for i := 0; i < f.targets[aws.ToString(in.TargetGroupArn)]; i++ {
		out.TargetHealthDescriptions = append(out.TargetHealthDescriptions, elbTypes.TargetHealthDescription{})
	}
	return out, nil
}

func TestLoadBalancerVerdicts(t *testing.T) {
	lbARN := func(name string) string {
		return fmt.Sprintf("arn:aws:elasticloadbalancing:eu-north-1:1:loadbalancer/app/%s/abc", name)
	}
	mk := func(name string) elbTypes.LoadBalancer {
		return elbTypes.LoadBalancer{LoadBalancerArn: aws.String(lbARN(name)), LoadBalancerName: aws.String(name), Type: elbTypes.LoadBalancerTypeEnumApplication}
	}
	static := []elbTypes.Listener{{DefaultActions: []elbTypes.Action{{Type: elbTypes.ActionTypeEnumFixedResponse}}}}
	api := fakeELB{
		lbs: []elbTypes.LoadBalancer{mk("dead"), mk("redirector"), mk("empty-tg"), mk("live")},
		tgs: []elbTypes.TargetGroup{
			{TargetGroupArn: aws.String("tg-empty"), LoadBalancerArns: []string{lbARN("empty-tg")}},
			{TargetGroupArn: aws.String("tg-live"), LoadBalancerArns: []string{lbARN("live")}},
		},
		listeners: map[string][]elbTypes.Listener{lbARN("dead"): static, lbARN("redirector"): static},
		targets:   map[string]int{"tg-empty": 0, "tg-live": 3},
	}
	cw := fakeCW{data: map[string][]float64{
		// "dead" has no RequestCount datapoints at all
		"AWS/ApplicationELB/RequestCount/app/redirector/abc": days(14, 400),
		"AWS/ApplicationELB/RequestCount/app/empty-tg/abc":   days(14, 0),
		"AWS/ApplicationELB/RequestCount/app/live/abc":       days(14, 9000),
	}}
	c := newTestCollector()
	scanLoadBalancersWith(context.Background(), api, cw, c)

	if n := nodeByID(t, c, lbARN("dead")); n.Status != engine.StatusOrphanWaste || n.Confidence != engine.ConfHigh {
		t.Fatalf("no targets, no requests: %+v", n)
	}
	// Regression: a redirector with no target groups but real traffic is alive.
	if n := nodeByID(t, c, lbARN("redirector")); n.Status == engine.StatusOrphanWaste && n.Confidence != engine.ConfLow {
		t.Fatalf("a balancer still answering requests must not be a confident candidate: %+v", n)
	}
	if n := nodeByID(t, c, lbARN("empty-tg")); n.Status != engine.StatusOrphanWaste {
		t.Fatalf("target group without targets: %+v", n)
	}
	if n := nodeByID(t, c, lbARN("live")); n.Status == engine.StatusOrphanWaste {
		t.Fatalf("balancer with targets and traffic: %+v", n)
	}
}

// ---- Kinesis ---------------------------------------------------------------

type fakeKinesis struct {
	names    []string
	onDemand map[string]bool
}

func (f fakeKinesis) ListStreams(context.Context, *kinesis.ListStreamsInput, ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error) {
	return &kinesis.ListStreamsOutput{StreamNames: f.names}, nil
}
func (f fakeKinesis) DescribeStreamSummary(_ context.Context, in *kinesis.DescribeStreamSummaryInput, _ ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error) {
	name := aws.ToString(in.StreamName)
	mode := kTypes.StreamModeProvisioned
	if f.onDemand[name] {
		mode = kTypes.StreamModeOnDemand
	}
	return &kinesis.DescribeStreamSummaryOutput{StreamDescriptionSummary: &kTypes.StreamDescriptionSummary{
		StreamARN: aws.String("arn:aws:kinesis:eu-north-1:1:stream/" + name), StreamName: aws.String(name),
		OpenShardCount: aws.Int32(2), StreamModeDetails: &kTypes.StreamModeDetails{StreamMode: mode},
		RetentionPeriodHours: aws.Int32(24),
	}}, nil
}
func (f fakeKinesis) ListTagsForStream(context.Context, *kinesis.ListTagsForStreamInput, ...func(*kinesis.Options)) (*kinesis.ListTagsForStreamOutput, error) {
	return &kinesis.ListTagsForStreamOutput{}, nil
}

func TestKinesisVerdicts(t *testing.T) {
	api := fakeKinesis{
		names:    []string{"silent", "trickle-od", "trickle-prov", "busy-od", "nodata"},
		onDemand: map[string]bool{"silent": true, "trickle-od": true, "busy-od": true, "nodata": true},
	}
	cw := fakeCW{data: map[string][]float64{
		"AWS/Kinesis/IncomingBytes/silent":       days(14, 0),
		"AWS/Kinesis/IncomingBytes/trickle-od":   days(14, 100<<10), // ~1.4 MiB over the window
		"AWS/Kinesis/IncomingBytes/trickle-prov": days(14, 100<<10),
		"AWS/Kinesis/IncomingBytes/busy-od":      days(14, 500<<20),
		// "nodata": no datapoints
	}}
	c := newTestCollector()
	scanKinesisWith(context.Background(), api, cw, c)

	arn := func(n string) string { return "arn:aws:kinesis:eu-north-1:1:stream/" + n }
	if n := nodeByID(t, c, arn("silent")); n.Status != engine.StatusOrphanWaste || n.Confidence != engine.ConfHigh {
		t.Fatalf("zero bytes: %+v", n)
	}
	if n := nodeByID(t, c, arn("nodata")); n.Status != engine.StatusOrphanWaste || n.Confidence != engine.ConfMedium {
		t.Fatalf("no datapoints at all is medium confidence: %+v", n)
	}
	if n := nodeByID(t, c, arn("trickle-od")); n.Status != engine.StatusOrphanWaste || n.Confidence != engine.ConfLow {
		t.Fatalf("on-demand near-idle is a weak candidate: %+v", n)
	}
	// near-idle applies to on-demand only: a provisioned stream at the same
	// traffic is not flagged by this rule.
	if nodeByID(t, c, arn("trickle-prov")).Status == engine.StatusOrphanWaste {
		t.Fatal("provisioned stream with some traffic must not be flagged")
	}
	if nodeByID(t, c, arn("busy-od")).Status == engine.StatusOrphanWaste {
		t.Fatal("busy stream flagged")
	}
}
