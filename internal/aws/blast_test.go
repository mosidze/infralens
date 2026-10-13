package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cfTypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kTypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53Types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

type fakeR53 struct {
	zones   []r53Types.HostedZone
	records map[string][]r53Types.ResourceRecordSet
	err     error
}

func (f fakeR53) ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &route53.ListHostedZonesOutput{HostedZones: f.zones}, nil
}
func (f fakeR53) ListResourceRecordSets(_ context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: f.records[aws.ToString(in.HostedZoneId)]}, nil
}

type fakeCF struct{ items []cfTypes.DistributionSummary }

func (f fakeCF) ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	return &cloudfront.ListDistributionsOutput{DistributionList: &cfTypes.DistributionList{Items: f.items}}, nil
}

type fakeRT struct{ tables []ec2Types.RouteTable }

func (f fakeRT) DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	return &ec2.DescribeRouteTablesOutput{RouteTables: f.tables}, nil
}

type fakeSnaps struct{ snaps []ec2Types.Snapshot }

func (f fakeSnaps) DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	return &ec2.DescribeSnapshotsOutput{Snapshots: f.snaps}, nil
}

type fakeLambda struct {
	maps []lambdaTypes.EventSourceMappingConfiguration
}

func (f fakeLambda) ListEventSourceMappings(context.Context, *lambda.ListEventSourceMappingsInput, ...func(*lambda.Options)) (*lambda.ListEventSourceMappingsOutput, error) {
	return &lambda.ListEventSourceMappingsOutput{EventSourceMappings: f.maps}, nil
}

type fakeConsumers struct{ names []string }

func (f fakeConsumers) ListStreamConsumers(context.Context, *kinesis.ListStreamConsumersInput, ...func(*kinesis.Options)) (*kinesis.ListStreamConsumersOutput, error) {
	out := &kinesis.ListStreamConsumersOutput{}
	for _, n := range f.names {
		out.Consumers = append(out.Consumers, kTypes.Consumer{ConsumerName: aws.String(n)})
	}
	return out, nil
}

func testAPIs() blastAPIs {
	return blastAPIs{
		route53: fakeR53{
			zones: []r53Types.HostedZone{{Id: aws.String("Z1"), Name: aws.String("example.com.")}},
			records: map[string][]r53Types.ResourceRecordSet{"Z1": {
				{Name: aws.String("app.example.com."), Type: r53Types.RRTypeA,
					AliasTarget: &r53Types.AliasTarget{DNSName: aws.String("dualstack.Dead-ALB-123.eu-north-1.elb.amazonaws.com.")}},
				{Name: aws.String("db.example.com."), Type: r53Types.RRTypeCname,
					ResourceRecords: []r53Types.ResourceRecord{{Value: aws.String("pg.cluster-abc.eu-north-1.rds.amazonaws.com")}}},
			}},
		},
		cloudfront: fakeCF{[]cfTypes.DistributionSummary{{Id: aws.String("E123"),
			Origins: &cfTypes.Origins{Items: []cfTypes.Origin{{DomainName: aws.String("used-alb-9.eu-north-1.elb.amazonaws.com")}}}}}},
		routeTable: func(string) (ec2.DescribeRouteTablesAPIClient, error) {
			return fakeRT{[]ec2Types.RouteTable{{
				RouteTableId: aws.String("rtb-1"),
				Routes:       []ec2Types.Route{{NatGatewayId: aws.String("nat-busy"), DestinationCidrBlock: aws.String("0.0.0.0/0")}},
				Associations: []ec2Types.RouteTableAssociation{{SubnetId: aws.String("subnet-a")}, {SubnetId: aws.String("subnet-b")}},
			}}}, nil
		},
		snapshots: func(string) (ec2.DescribeSnapshotsAPIClient, error) {
			return fakeSnaps{[]ec2Types.Snapshot{{SnapshotId: aws.String("snap-1"), StartTime: daysAgo(10)}}}, nil
		},
		lambda: func(string) (lambda.ListEventSourceMappingsAPIClient, error) {
			return fakeLambda{[]lambdaTypes.EventSourceMappingConfiguration{{
				FunctionArn: aws.String("arn:aws:lambda:eu-north-1:1:function:ingest"), State: aws.String("Enabled")}}}, nil
		},
		kinesis: func(string) (kinesis.ListStreamConsumersAPIClient, error) { return fakeConsumers{}, nil },
	}
}

func wasteNode(id, typ string, conf engine.Confidence, attrs map[string]string) engine.ResourceNode {
	return engine.ResourceNode{ID: id, Name: id, Type: typ, Region: "eu-north-1", Status: engine.StatusOrphanWaste,
		Confidence: conf, Attrs: attrs, MonthlyCost: 16}
}

func TestBlastRadiusLowersConfidenceOnlyWhenSomethingDepends(t *testing.T) {
	nodes := []engine.ResourceNode{
		wasteNode("lb-with-dns", "aws_lb", engine.ConfHigh, map[string]string{"dns_name": "Dead-ALB-123.eu-north-1.elb.amazonaws.com"}),
		wasteNode("lb-with-cf", "aws_lb", engine.ConfHigh, map[string]string{"dns_name": "used-alb-9.eu-north-1.elb.amazonaws.com"}),
		wasteNode("lb-alone", "aws_lb", engine.ConfHigh, map[string]string{"dns_name": "nobody.eu-north-1.elb.amazonaws.com"}),
		wasteNode("nat-busy", "aws_nat_gateway", engine.ConfHigh, nil),
		wasteNode("nat-free", "aws_nat_gateway", engine.ConfHigh, nil),
		wasteNode("vol-1", "aws_ebs_volume", engine.ConfHigh, nil),
		wasteNode("arn:aws:kinesis:eu-north-1:1:stream/s", "aws_kinesis_stream", engine.ConfHigh, nil),
		{ID: "managed-one", Type: "aws_lb", Status: engine.StatusManaged},
	}
	warns := enrichBlastWith(context.Background(), testAPIs(), nodes)
	if len(warns) != 0 {
		t.Fatalf("warnings: %v", warns)
	}
	by := map[string]engine.ResourceNode{}
	for _, n := range nodes {
		by[n.ID] = n
	}

	if n := by["lb-with-dns"]; n.Confidence != engine.ConfMedium || len(n.Blast.Dependents) != 1 || n.Blast.Dependents[0].Name != "app.example.com" {
		t.Fatalf("a DNS alias (dualstack prefix, trailing dot, mixed case) must be matched: %+v", n)
	}
	if n := by["lb-with-cf"]; n.Confidence != engine.ConfMedium || n.Blast.Dependents[0].Kind != "cloudfront" {
		t.Fatalf("a CloudFront origin must be matched: %+v", n)
	}
	if n := by["lb-alone"]; n.Confidence != engine.ConfHigh || len(n.Blast.Dependents) != 0 || len(n.Blast.Checked) != 2 {
		t.Fatalf("no dependents found must leave confidence alone and say what was checked: %+v", n)
	}
	if n := by["nat-busy"]; n.Confidence != engine.ConfMedium || !strings.Contains(n.Blast.Dependents[0].Detail, "2 associated subnet") {
		t.Fatalf("route through the gateway: %+v", n)
	}
	if n := by["vol-1"]; n.Confidence != engine.ConfHigh || !strings.Contains(strings.Join(n.Evidence, " "), "backup: 1 snapshot") {
		t.Fatalf("a backup is information for rollback, not a dependency: %+v", n)
	}
	k := by["arn:aws:kinesis:eu-north-1:1:stream/s"]
	if k.Confidence != engine.ConfMedium || k.Blast.Dependents[0].Name != "ingest" {
		t.Fatalf("a Lambda consumer lowers confidence: %+v", k)
	}
	if by["managed-one"].Blast != nil {
		t.Fatal("only waste candidates are looked up")
	}
}

func TestBlastRadiusCheckedListMakesAbsenceMeaningful(t *testing.T) {
	api := testAPIs()
	api.route53 = fakeR53{err: errors.New("AccessDenied: route53:ListHostedZones")}
	n := []engine.ResourceNode{wasteNode("lb-alone", "aws_lb", engine.ConfHigh, map[string]string{"dns_name": "nobody.elb.amazonaws.com"})}
	warns := enrichBlastWith(context.Background(), api, n)
	if len(warns) != 1 || !strings.Contains(warns[0], "route53") {
		t.Fatalf("the failure must surface: %v", warns)
	}
	b := n[0].Blast
	if len(b.Unchecked) != 1 || b.Unchecked[0] != "Route53 records" {
		t.Fatalf("unchecked: %+v", b)
	}
	if !strings.Contains(strings.Join(n[0].Evidence, " "), "dependency check incomplete") {
		t.Fatalf("incomplete lookup must be visible in the evidence: %v", n[0].Evidence)
	}
}

func TestRDSBlastRadiusUsesClusterEndpoints(t *testing.T) {
	nodes := []engine.ResourceNode{
		wasteNode("pg-1", "aws_rds_instance", engine.ConfHigh, map[string]string{
			"cluster": "pg", "cluster_endpoint": "pg.cluster-abc.eu-north-1.rds.amazonaws.com"}),
		{ID: "pg-2", Name: "pg-2", Type: "aws_rds_instance", Status: engine.StatusManaged, Attrs: map[string]string{"cluster": "pg"}},
	}
	enrichBlastWith(context.Background(), testAPIs(), nodes)
	b := nodes[0].Blast
	kinds := map[string]bool{}
	for _, d := range b.Dependents {
		kinds[d.Kind] = true
	}
	if !kinds["dns"] || !kinds["cluster-member"] {
		t.Fatalf("expected the CNAME and the sibling instance: %+v", b.Dependents)
	}
}

func TestLowerNeverRaises(t *testing.T) {
	for in, want := range map[engine.Confidence]engine.Confidence{
		engine.ConfHigh: engine.ConfMedium, engine.ConfMedium: engine.ConfLow, engine.ConfLow: engine.ConfLow,
	} {
		if got := lower(in); got != want {
			t.Errorf("lower(%s) = %s, want %s", in, got, want)
		}
	}
}
