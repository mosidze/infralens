package aws

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfnT "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	ceTypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	ecTypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/memorydb"
	mdbTypes "github.com/aws/aws-sdk-go-v2/service/memorydb/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	rsTypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// fakeMD answers GetMetricData from canned daily values keyed by "Metric/FirstDimensionValue".
type fakeMD struct {
	vals map[string][]float64
	err  error
}

func (f fakeMD) GetMetricData(_ context.Context, in *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := &cloudwatch.GetMetricDataOutput{}
	for _, q := range in.MetricDataQueries {
		m := q.MetricStat.Metric
		key := aws.ToString(m.MetricName)
		if len(m.Dimensions) > 0 {
			key += "/" + aws.ToString(m.Dimensions[0].Value)
		}
		out.MetricDataResults = append(out.MetricDataResults, cwTypes.MetricDataResult{Id: q.Id, Values: f.vals[key]})
	}
	return out, nil
}

// ---- batch reader ------------------------------------------------------------

func TestBatchMetricsSumsAndMaxes(t *testing.T) {
	api := fakeMD{vals: map[string][]float64{"Invocations/a": {1, 2, 3}, "CurrConnections/b": {0, 5, 2}}}
	m, err := batchMetrics(context.Background(), api, []mq{
		{"inv", "AWS/Lambda", "Invocations", map[string]string{"FunctionName": "a"}, "Sum"},
		{"conn", "AWS/ElastiCache", "CurrConnections", map[string]string{"CacheClusterId": "b"}, "Maximum"},
		{"none", "AWS/Lambda", "Invocations", map[string]string{"FunctionName": "zzz"}, "Sum"},
	}, 14)
	if err != nil {
		t.Fatal(err)
	}
	if m["inv"].Value != 6 || m["inv"].Points != 3 || m["conn"].Value != 5 || m["none"].Points != 0 {
		t.Fatalf("%+v", m)
	}
	// more than 500 queries are split across calls
	var qs []mq
	for i := 0; i < 1201; i++ {
		qs = append(qs, mq{Key: string(rune('a'+i%26)) + string(rune(i)), Namespace: "x", Metric: "M", Dims: map[string]string{"D": "v"}, Stat: "Sum"})
	}
	if _, err := batchMetrics(context.Background(), fakeMD{}, qs, 14); err != nil {
		t.Fatal(err)
	}
}

// ---- Lambda ------------------------------------------------------------------

type fakeLambdaFns struct {
	fns []lambdaTypes.FunctionConfiguration
}

func (f fakeLambdaFns) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{Functions: f.fns}, nil
}
func (f fakeLambdaFns) ListTags(context.Context, *lambda.ListTagsInput, ...func(*lambda.Options)) (*lambda.ListTagsOutput, error) {
	return &lambda.ListTagsOutput{Tags: map[string]string{"terraform": "true"}}, nil
}

func TestLambdaCostFromUsage(t *testing.T) {
	api := fakeLambdaFns{[]lambdaTypes.FunctionConfiguration{
		{FunctionName: aws.String("busy"), FunctionArn: aws.String("arn:busy"), MemorySize: aws.Int32(1024)},
		{FunctionName: aws.String("idle"), FunctionArn: aws.String("arn:idle"), MemorySize: aws.Int32(128)},
	}}
	md := fakeMD{vals: map[string][]float64{
		"Invocations/busy": days(14, 100000),     // 1.4M in 14d
		"Duration/busy":    days(14, 100000*200), // 200 ms each
	}}
	c := newTestCollector()
	scanLambdaWith(context.Background(), api, md, c)
	busy := nodeByID(t, c, "arn:busy")
	// 1.4M inv * 0.2 ms... gb-s = 1.4M*0.2s*1GB = 280000 -> *1.66667e-5 = 4.667 ; req 1.4M*0.2/1M = 0.28 ; both scaled by 30/14
	want := (280000*engine.LambdaGBSecond + 1.4*engine.LambdaPerMillionReq) * 30 / 14
	if math.Abs(busy.MonthlyCost-want) > 0.05 {
		t.Fatalf("lambda cost = %v, want about %v", busy.MonthlyCost, want)
	}
	idle := nodeByID(t, c, "arn:idle")
	if idle.Status == engine.StatusOrphanWaste || idle.MonthlyCost != 0 {
		t.Fatalf("an idle function costs nothing and is not waste: %+v", idle)
	}
	if !hasEvidence(idle, "no invocations") {
		t.Fatalf("idle function should say so: %v", idle.Evidence)
	}
}

func TestLambdaMetricFailureIsNotZeroCost(t *testing.T) {
	api := fakeLambdaFns{[]lambdaTypes.FunctionConfiguration{{FunctionName: aws.String("f"), FunctionArn: aws.String("arn:f"), MemorySize: aws.Int32(256)}}}
	c := newTestCollector()
	scanLambdaWith(context.Background(), api, fakeMD{err: errors.New("AccessDenied")}, c)
	n := nodeByID(t, c, "arn:f")
	if n.CostSource != engine.CostNotAvailable {
		t.Fatalf("an unreadable metric must read as 'not available', not $0: %+v", n)
	}
	if len(c.warnings) == 0 {
		t.Fatal("must warn")
	}
}

// ---- Redshift ----------------------------------------------------------------

type fakeRedshift struct{ cs []rsTypes.Cluster }

func (f fakeRedshift) DescribeClusters(context.Context, *redshift.DescribeClustersInput, ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
	return &redshift.DescribeClustersOutput{Clusters: f.cs}, nil
}

func TestRedshiftIdleVerdict(t *testing.T) {
	cl := func(id string, ageDays int) rsTypes.Cluster {
		return rsTypes.Cluster{ClusterIdentifier: aws.String(id), NodeType: aws.String("ra3.xlplus"), NumberOfNodes: aws.Int32(2),
			ClusterStatus: aws.String("available"), ClusterCreateTime: daysAgo(ageDays)}
	}
	api := fakeRedshift{[]rsTypes.Cluster{cl("idle", 300), cl("busy", 300), cl("young", 2)}}
	md := fakeMD{vals: map[string][]float64{
		"DatabaseConnections/idle":  days(14, 0),
		"DatabaseConnections/busy":  days(14, 4),
		"DatabaseConnections/young": days(2, 0),
	}}
	c := newTestCollector()
	scanRedshiftWith(context.Background(), api, md, c)
	if n := nodeByID(t, c, "idle"); n.Status != engine.StatusOrphanWaste || n.Confidence != engine.ConfHigh {
		t.Fatalf("idle: %+v", n)
	}
	if nodeByID(t, c, "busy").Status == engine.StatusOrphanWaste {
		t.Fatal("busy cluster flagged")
	}
	if n := nodeByID(t, c, "young"); n.Status != engine.StatusOrphanWaste || n.Confidence != engine.ConfLow {
		t.Fatalf("a young cluster cannot be judged with confidence: %+v", n)
	}
	if got := nodeByID(t, c, "idle").MonthlyCost; math.Abs(got-1.086*730*2) > 0.5 {
		t.Fatalf("2 x ra3.xlplus = %v", got)
	}
}

// ---- ElastiCache -------------------------------------------------------------

type fakeEC struct{ cs []ecTypes.CacheCluster }

func (f fakeEC) DescribeCacheClusters(context.Context, *elasticache.DescribeCacheClustersInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error) {
	return &elasticache.DescribeCacheClustersOutput{CacheClusters: f.cs}, nil
}

func TestElastiCacheJudgesOnlyStandaloneClusters(t *testing.T) {
	mk := func(id, rg string) ecTypes.CacheCluster {
		c := ecTypes.CacheCluster{CacheClusterId: aws.String(id), CacheNodeType: aws.String("cache.r6g.large"), NumCacheNodes: aws.Int32(1),
			Engine: aws.String("redis"), CacheClusterStatus: aws.String("available"), CacheClusterCreateTime: daysAgo(400)}
		if rg != "" {
			c.ReplicationGroupId = aws.String(rg)
		}
		return c
	}
	api := fakeEC{[]ecTypes.CacheCluster{mk("solo-idle", ""), mk("solo-busy", ""), mk("repl-member-001", "repl")}}
	md := fakeMD{vals: map[string][]float64{
		"CurrConnections/solo-idle":       days(14, 1),
		"CurrConnections/solo-busy":       days(14, 40),
		"CurrConnections/repl-member-001": days(14, 1),
	}}
	c := newTestCollector()
	scanElastiCacheWith(context.Background(), api, md, c)
	if nodeByID(t, c, "solo-idle").Status != engine.StatusOrphanWaste {
		t.Fatal("a standalone cluster with only the monitoring connection is idle")
	}
	if nodeByID(t, c, "solo-busy").Status == engine.StatusOrphanWaste {
		t.Fatal("busy cluster flagged")
	}
	// Regression guard: replication links look like connections, so members of
	// a replication group must never be judged by connection counts.
	if n := nodeByID(t, c, "repl-member-001"); n.Status == engine.StatusOrphanWaste || !hasEvidence(n, "idle not judged") {
		t.Fatalf("replication group member: %+v", n)
	}
}

// ---- MemoryDB ----------------------------------------------------------------

type fakeMDB struct{ cs []mdbTypes.Cluster }

func (f fakeMDB) DescribeClusters(context.Context, *memorydb.DescribeClustersInput, ...func(*memorydb.Options)) (*memorydb.DescribeClustersOutput, error) {
	return &memorydb.DescribeClustersOutput{Clusters: f.cs}, nil
}
func (f fakeMDB) ListTags(context.Context, *memorydb.ListTagsInput, ...func(*memorydb.Options)) (*memorydb.ListTagsOutput, error) {
	return &memorydb.ListTagsOutput{}, nil
}

func TestMemoryDB(t *testing.T) {
	mk := func(name string) mdbTypes.Cluster {
		return mdbTypes.Cluster{Name: aws.String(name), ARN: aws.String("arn:" + name), NodeType: aws.String("db.r6g.large"),
			Status: aws.String("available"), NumberOfShards: aws.Int32(1),
			Shards: []mdbTypes.Shard{{Nodes: []mdbTypes.Node{{}, {}}}}}
	}
	md := fakeMD{vals: map[string][]float64{"CurrConnections/idle": days(14, 0), "CurrConnections/busy": days(14, 12)}}
	c := newTestCollector()
	scanMemoryDBWith(context.Background(), fakeMDB{[]mdbTypes.Cluster{mk("idle"), mk("busy"), mk("nometric")}}, md, c)
	if n := nodeByID(t, c, "arn:idle"); n.Status != engine.StatusOrphanWaste || n.Confidence != engine.ConfMedium {
		t.Fatalf("durable store: idle is medium at best: %+v", n)
	}
	if nodeByID(t, c, "arn:busy").Status == engine.StatusOrphanWaste || nodeByID(t, c, "arn:nometric").Status == engine.StatusOrphanWaste {
		t.Fatal("busy or unmeasured cluster flagged")
	}
	if got := nodeByID(t, c, "arn:busy").MonthlyCost; math.Abs(got-0.29*730*2) > 0.5 {
		t.Fatalf("2 nodes: %v", got)
	}
}

// ---- DynamoDB ----------------------------------------------------------------

type fakeDDB struct {
	tables map[string]*ddbTypes.TableDescription
}

func (f fakeDDB) ListTables(context.Context, *dynamodb.ListTablesInput, ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	out := &dynamodb.ListTablesOutput{}
	for n := range f.tables {
		out.TableNames = append(out.TableNames, n)
	}
	return out, nil
}
func (f fakeDDB) DescribeTable(_ context.Context, in *dynamodb.DescribeTableInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	return &dynamodb.DescribeTableOutput{Table: f.tables[aws.ToString(in.TableName)]}, nil
}
func (f fakeDDB) ListTagsOfResource(context.Context, *dynamodb.ListTagsOfResourceInput, ...func(*dynamodb.Options)) (*dynamodb.ListTagsOfResourceOutput, error) {
	return &dynamodb.ListTagsOfResourceOutput{}, nil
}

func TestDynamoDBVerdicts(t *testing.T) {
	prov := func(name string, rcu, wcu int64) *ddbTypes.TableDescription {
		return &ddbTypes.TableDescription{TableName: aws.String(name), TableArn: aws.String("arn:" + name), CreationDateTime: daysAgo(500),
			ProvisionedThroughput: &ddbTypes.ProvisionedThroughputDescription{ReadCapacityUnits: aws.Int64(rcu), WriteCapacityUnits: aws.Int64(wcu)}}
	}
	od := &ddbTypes.TableDescription{TableName: aws.String("ondemand-idle"), TableArn: aws.String("arn:ondemand-idle"), CreationDateTime: daysAgo(500),
		BillingModeSummary: &ddbTypes.BillingModeSummary{BillingMode: ddbTypes.BillingModePayPerRequest}}
	api := fakeDDB{map[string]*ddbTypes.TableDescription{
		"prov-idle": prov("prov-idle", 100, 50), "prov-busy": prov("prov-busy", 100, 50), "ondemand-idle": od,
	}}
	md := fakeMD{vals: map[string][]float64{"ConsumedReadCapacityUnits/prov-busy": days(14, 5000)}}
	c := newTestCollector()
	scanDynamoDBWith(context.Background(), api, md, c)

	idle := nodeByID(t, c, "arn:prov-idle")
	if idle.Status != engine.StatusOrphanWaste {
		t.Fatalf("a provisioned table that consumes nothing is a candidate: %+v", idle)
	}
	want := 100*engine.DynamoRCUHour*730 + 50*engine.DynamoWCUHour*730
	if math.Abs(idle.MonthlyCost-want) > 0.01 {
		t.Fatalf("provisioned cost = %v, want %v", idle.MonthlyCost, want)
	}
	if nodeByID(t, c, "arn:prov-busy").Status == engine.StatusOrphanWaste {
		t.Fatal("busy table flagged")
	}
	if n := nodeByID(t, c, "arn:ondemand-idle"); n.Status == engine.StatusOrphanWaste || n.MonthlyCost != 0 {
		t.Fatalf("an idle on-demand table costs nothing: %+v", n)
	}
}

func TestPricingHelpers(t *testing.T) {
	if got := engine.VPCEndpointMonthlyCost("Interface", 3); math.Abs(got-0.01*730*3) > 1e-9 {
		t.Fatalf("interface endpoint: %v", got)
	}
	if engine.VPCEndpointMonthlyCost("Gateway", 3) != 0 {
		t.Fatal("gateway endpoints are free")
	}
	if got := engine.DynamoDBMonthlyCost(false, 0, 0, 10<<30); got != 0 {
		t.Fatalf("10 GB is inside the free tier: %v", got)
	}
	if got := engine.DynamoDBMonthlyCost(false, 0, 0, 125<<30); math.Abs(got-100*0.25) > 1e-6 {
		t.Fatalf("125 GB: %v", got)
	}
	if _, known := engine.RedshiftMonthlyCost("ra3.unknown", 2); known {
		t.Fatal("unknown node type must say so")
	}
	_ = time.Now
}

// Regression from a live run: DescribeClusters returns no nodes unless
// ShowShardDetails is set, and the cluster was priced at $0 without a word.
func TestMemoryDBAsksForShardDetailsAndNeverPricesAtZero(t *testing.T) {
	var sawFlag bool
	api := recordingMDB{fakeMDB: fakeMDB{[]mdbTypes.Cluster{{
		Name: aws.String("c"), ARN: aws.String("arn:c"), NodeType: aws.String("db.r6g.xlarge"), Status: aws.String("available"),
		NumberOfShards: aws.Int32(1), // Shards omitted: what the API returns without the flag
	}}}, flag: &sawFlag}
	c := newTestCollector()
	scanMemoryDBWith(context.Background(), api, fakeMD{}, c)
	if !sawFlag {
		t.Fatal("DescribeClusters must be called with ShowShardDetails")
	}
	n := nodeByID(t, c, "arn:c")
	if n.CostSource != engine.CostNotAvailable || n.MonthlyCost != 0 || !hasEvidence(n, "node count not returned") {
		t.Fatalf("unknown node count must read as 'not available', not as a $0 estimate: %+v", n)
	}
}

type recordingMDB struct {
	fakeMDB
	flag *bool
}

func (r recordingMDB) DescribeClusters(ctx context.Context, in *memorydb.DescribeClustersInput, o ...func(*memorydb.Options)) (*memorydb.DescribeClustersOutput, error) {
	if aws.ToBool(in.ShowShardDetails) {
		*r.flag = true
	}
	return r.fakeMDB.DescribeClusters(ctx, in, o...)
}

func TestServiceNotOfferedInRegionIsNotAWarning(t *testing.T) {
	c := newTestCollector()
	c.warn("memorydb:clusters", errors.New(`Post "https://memory-db.ap-northeast-3.amazonaws.com/": dial tcp: lookup memory-db.ap-northeast-3.amazonaws.com: no such host`))
	c.warn("rds:instances", errors.New("AccessDenied"))
	if len(c.warnings) != 1 || len(c.skipped) != 1 {
		t.Fatalf("warnings=%v skipped=%v", c.warnings, c.skipped)
	}
}

// ---- cost allocation inputs ---------------------------------------------------

func TestFargateDriversSplitByPricingClass(t *testing.T) {
	// 10 tasks of 0.5 vCPU / 1 GiB: FARGATE base 1, the rest on SPOT
	split := map[string]float64{"FARGATE": 1, "FARGATE_SPOT": 9}
	d := fargateDrivers(512, 1024, 0, false, split)
	if math.Abs(d["vcpu_h_od"]-0.5*730*1) > 1e-6 || math.Abs(d["vcpu_h_spot"]-0.5*730*9) > 1e-6 {
		t.Fatalf("vcpu hours: %v", d)
	}
	if math.Abs(d["gb_h_spot"]-1*730*9) > 1e-6 {
		t.Fatalf("gb hours: %v", d)
	}
	if _, ok := d["eph_gb_h"]; ok {
		t.Fatal("20 GiB or less of ephemeral storage is free and must not be a driver")
	}
	if e := fargateDrivers(1024, 2048, 220, false, split)["eph_gb_h"]; math.Abs(e-200*730*10) > 1e-6 {
		t.Fatalf("ephemeral storage above 20 GiB: %v", e)
	}
	arm := fargateDrivers(1024, 2048, 0, true, map[string]float64{"FARGATE": 2})
	if arm["vcpu_h_od_arm"] == 0 || arm["vcpu_h_od"] != 0 {
		t.Fatalf("arm tasks bill under their own usage types: %v", arm)
	}
}

type fakeUsageCE struct {
	pages []*costexplorer.GetCostAndUsageOutput
}

func (f *fakeUsageCE) GetCostAndUsage(_ context.Context, in *costexplorer.GetCostAndUsageInput, _ ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error) {
	i := 0
	if in.NextPageToken != nil {
		i = 1
	}
	return f.pages[i], nil
}

func TestUsageLinesFollowPagination(t *testing.T) {
	g := func(svc, ut, cost string) ceTypes.Group {
		return ceTypes.Group{Keys: []string{svc, ut}, Metrics: map[string]ceTypes.MetricValue{
			"UnblendedCost": {Amount: aws.String(cost)}, "UsageQuantity": {Amount: aws.String("7")}}}
	}
	api := &fakeUsageCE{pages: []*costexplorer.GetCostAndUsageOutput{
		{NextPageToken: aws.String("t"), ResultsByTime: []ceTypes.ResultByTime{{Groups: []ceTypes.Group{g("EC2 - Other", "EUN1-NatGateway-Bytes", "995.38")}}}},
		{ResultsByTime: []ceTypes.ResultByTime{{Groups: []ceTypes.Group{g("AWS Lambda", "EUN1-Request", "5.72"), {Keys: []string{"broken"}}}}}},
	}}
	lines, month, err := usageLinesWith(context.Background(), api, time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC))
	if err != nil || len(lines) != 2 || month != "2026-09" {
		t.Fatalf("lines=%v month=%q err=%v", lines, month, err)
	}
	if lines[0].Cost != 995.38 || lines[0].Service != "EC2 - Other" || lines[1].UsageType != "EUN1-Request" {
		t.Fatalf("%+v", lines)
	}
}

// ---- IaC sources ---------------------------------------------------------------

type fakeCFN struct {
	stacks    []cfnT.StackSummary
	resources map[string][]cfnT.StackResourceSummary
}

func (f fakeCFN) ListStacks(context.Context, *cloudformation.ListStacksInput, ...func(*cloudformation.Options)) (*cloudformation.ListStacksOutput, error) {
	return &cloudformation.ListStacksOutput{StackSummaries: f.stacks}, nil
}
func (f fakeCFN) ListStackResources(_ context.Context, in *cloudformation.ListStackResourcesInput, _ ...func(*cloudformation.Options)) (*cloudformation.ListStackResourcesOutput, error) {
	return &cloudformation.ListStackResourcesOutput{StackResourceSummaries: f.resources[aws.ToString(in.StackName)]}, nil
}

func TestCloudFormationRefs(t *testing.T) {
	api := fakeCFN{
		stacks: []cfnT.StackSummary{{
			StackName: aws.String("net-vpc"), StackId: aws.String("arn:stack/net-vpc/1"),
			DriftInformation: &cfnT.StackDriftInformationSummary{StackDriftStatus: cfnT.StackDriftStatusDrifted},
		}},
		resources: map[string][]cfnT.StackResourceSummary{"arn:stack/net-vpc/1": {
			{LogicalResourceId: aws.String("Nat"), ResourceType: aws.String("AWS::EC2::NatGateway"), PhysicalResourceId: aws.String("nat-0abc"), ResourceStatus: cfnT.ResourceStatusCreateComplete},
			{LogicalResourceId: aws.String("Role"), ResourceType: aws.String("AWS::IAM::Role"), PhysicalResourceId: aws.String("role"), ResourceStatus: cfnT.ResourceStatusCreateComplete},
			{LogicalResourceId: aws.String("Old"), ResourceType: aws.String("AWS::EC2::Volume"), PhysicalResourceId: aws.String("vol-1"), ResourceStatus: cfnT.ResourceStatusDeleteComplete},
		}},
	}
	c := newTestCollector()
	cloudFormationWith(context.Background(), api, c)
	if c.stacks != 1 || len(c.iacrefs) != 1 {
		t.Fatalf("stacks=%d refs=%+v", c.stacks, c.iacrefs)
	}
	r := c.iacrefs[0]
	if r.ID != "nat-0abc" || r.Origin != "net-vpc" || r.Drift != "DRIFTED" || r.Region != "eu-north-1" || r.Source != "cloudformation" {
		t.Fatalf("%+v", r)
	}
}

type fakeStateS3 struct {
	objs map[string]string
}

func (f fakeStateS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	out := &s3.ListObjectsV2Output{}
	for k, v := range f.objs {
		if strings.HasPrefix(k, aws.ToString(in.Prefix)) {
			out.Contents = append(out.Contents, s3Types.Object{Key: aws.String(k), Size: aws.Int64(int64(len(v)))})
		}
	}
	return out, nil
}
func (f fakeStateS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(f.objs[aws.ToString(in.Key)]))}, nil
}

func TestLoadS3StateReadsOnlyStateFilesAndSurvivesABrokenOne(t *testing.T) {
	good := `{"version":4,"resources":[{"mode":"managed","type":"aws_instance","name":"a","instances":[{"attributes":{"id":"i-1","user_data":"TOPSECRET"}}]}]}`
	api := fakeStateS3{objs: map[string]string{
		"core/terraform.tfstate":      good,
		"core/terraform.tfstate.json": good, // wrong suffix: not read
		"core/README.md":              "hello",
		"bad/terraform.tfstate":       "not json at all",
		"empty/terraform.tfstate":     "",
	}}
	var out TerraformResult
	loadS3State(context.Background(), api, "bucket", "", &out)
	if out.Files != 1 || len(out.Refs) != 1 || out.Refs[0].ID != "i-1" || out.Refs[0].Origin != "core/terraform.tfstate" {
		t.Fatalf("files=%d refs=%+v notes=%v", out.Files, out.Refs, out.Notes)
	}
	if len(out.Notes) != 1 || !strings.Contains(out.Notes[0], "bad/terraform.tfstate") {
		t.Fatalf("a broken state must be reported, not fatal: %v", out.Notes)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "TOPSECRET") {
		t.Fatal("state content leaked into the result")
	}
}

func TestLoadLocalState(t *testing.T) {
	dir := t.TempDir()
	good := `{"version":4,"resources":[{"mode":"managed","type":"aws_ebs_volume","name":"v","instances":[{"attributes":{"id":"vol-9","size":50}}]}]}`
	_ = os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "a", "b", "terraform.tfstate"), []byte(good), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "a", "notes.txt"), []byte("x"), 0o600)
	var out TerraformResult
	loadLocalState(dir, &out)
	if out.Files != 1 || len(out.Refs) != 1 || out.Refs[0].Attrs["size"] != "50" {
		t.Fatalf("%+v", out)
	}
	var missing TerraformResult
	loadLocalState(filepath.Join(dir, "nope"), &missing)
	if len(missing.Notes) != 1 {
		t.Fatal("a missing path must be a note")
	}
}
