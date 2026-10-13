package engine

import (
	"strings"
	"testing"
)

func iacNode(id, name, typ, region string, st ResourceStatus, managedBy string, attrs map[string]string) ResourceNode {
	return ResourceNode{ID: id, Name: name, Type: typ, Region: region, Status: st, ManagedBy: managedBy, Attrs: attrs, MonthlyCost: 10}
}

func findRule(res ScanResult, rule string) *Finding {
	for i := range res.Findings {
		if res.Findings[i].Rule == rule {
			return &res.Findings[i]
		}
	}
	return nil
}

func TestJoinIaCVerifiesMatchesAndFindsGaps(t *testing.T) {
	res := ScanResult{Regions: []string{"eu-north-1"}, Nodes: []ResourceNode{
		iacNode("i-1", "web", "aws_instance", "eu-north-1", StatusShadowIT, "", map[string]string{"instance_type": "t3.large"}),
		iacNode("arn:aws:lambda:eu-north-1:1:function:ingest", "ingest", "aws_lambda_function", "eu-north-1", StatusManaged, "Terraform", map[string]string{"memory_mb": "512", "runtime": "python3.12"}),
		iacNode("tagged-but-absent", "ghost", "aws_rds_instance", "eu-north-1", StatusManaged, "Terraform", nil),
		iacNode("hand-made", "hand", "aws_ebs_volume", "eu-north-1", StatusShadowIT, "", nil),
	}}
	refs := []IaCRef{
		{Source: "terraform", Origin: "services/web/terraform.tfstate", Address: "aws_instance.web", Type: "aws_instance", ID: "i-1",
			Attrs: map[string]string{"instance_type": "t3.small"}}, // drift: state says small, live is large
		{Source: "terraform", Origin: "services/ingest/terraform.tfstate", Address: "module.ingest.aws_lambda_function.fn", Module: "module.ingest",
			Type: "aws_lambda_function", ID: "ingest", Attrs: map[string]string{"memory_size": "512", "runtime": "python3.12"}},
		{Source: "terraform", Origin: "old/terraform.tfstate", Address: "aws_ebs_volume.gone", Type: "aws_ebs_volume",
			ID: "vol-deleted", ARN: "arn:aws:ec2:eu-north-1:1:volume/vol-deleted"},
		{Source: "terraform", Origin: "elsewhere.tfstate", Address: "aws_ebs_volume.other", Type: "aws_ebs_volume",
			ID: "vol-other-region", ARN: "arn:aws:ec2:us-west-2:1:volume/vol-other-region"},
		{Source: "terraform", Origin: "x", Type: "aws_iam_role", ID: "role"}, // type not inventoried: ignored
	}
	JoinIaC(&res, refs, []string{"terraform: s3://states"}, 4, 0, nil)

	web := res.Nodes[0]
	if web.Status != StatusManaged || web.ManagedBy != "Terraform" || web.IaC == nil || web.IaC.Address != "aws_instance.web" {
		t.Fatalf("a resource found in state is verified as managed, whatever its tags said: %+v", web)
	}
	if len(web.IaC.Drift) != 1 || web.IaC.Drift[0].State != "t3.small" || web.IaC.Drift[0].Live != "t3.large" {
		t.Fatalf("drift: %+v", web.IaC)
	}
	ingest := res.Nodes[1]
	if ingest.IaC == nil || len(ingest.IaC.Drift) != 0 || !ingest.IaC.DriftChecked {
		t.Fatalf("matched by function name with no drift: %+v", ingest.IaC)
	}
	if ingest.Owner != "ingest" || ingest.OwnerSource != "terraform module" {
		t.Fatalf("owner from the module: %q %q", ingest.Owner, ingest.OwnerSource)
	}
	if res.Nodes[2].IaC != nil || !strings.Contains(strings.Join(res.Nodes[2].Evidence, " "), "not found in the 4 state file") {
		t.Fatalf("tag claim not confirmed: %+v", res.Nodes[2])
	}
	if res.Nodes[3].Status != StatusShadowIT {
		t.Fatal("unmatched and untagged stays unmanaged")
	}

	s := res.IaC
	if s.Matched != 2 || s.TagOnly != 1 || s.Unmanaged != 1 || s.DriftFound != 1 || s.DriftChecked != 2 || s.Considered != 4 {
		t.Fatalf("summary: %+v", s)
	}
	if f := findRule(res, "iac.tag-not-in-state"); f == nil || f.Affected != 1 {
		t.Fatalf("tag-not-in-state: %+v", f)
	}
	orph := findRule(res, "iac.state-without-resource")
	if orph == nil || orph.Affected != 1 || orph.Resources[0] != "vol-deleted" {
		t.Fatalf("only the entry in a scanned region counts as an orphan: %+v", orph)
	}
	if f := findRule(res, "iac.drift.instance"); f == nil || !strings.Contains(strings.Join(f.Evidence, " "), "state=t3.small live=t3.large") {
		t.Fatalf("drift finding: %+v", f)
	}
}

func TestJoinIaCDoesNotCrossTypes(t *testing.T) {
	// a queue and a function can share a name; a state entry for one must not claim the other
	res := ScanResult{Regions: []string{"r"}, Nodes: []ResourceNode{
		iacNode("arn:aws:lambda:r:1:function:events", "events", "aws_lambda_function", "r", StatusShadowIT, "", nil),
	}}
	JoinIaC(&res, []IaCRef{{Source: "terraform", Origin: "o", Type: "aws_sqs_queue", ID: "events"}}, []string{"t"}, 1, 0, nil)
	if res.Nodes[0].IaC != nil || res.Nodes[0].Status != StatusShadowIT {
		t.Fatalf("type mismatch must not match: %+v", res.Nodes[0])
	}
}

func TestJoinIaCWithoutSourcesChangesNothing(t *testing.T) {
	res := ScanResult{Nodes: []ResourceNode{iacNode("i-1", "web", "aws_instance", "r", StatusManaged, "Terraform", nil)}}
	JoinIaC(&res, nil, nil, 0, 0, nil)
	if res.Nodes[0].IaC != nil || len(res.Findings) != 0 || len(res.Nodes[0].Evidence) != 0 {
		t.Fatalf("with nothing read, nothing may be claimed: %+v", res)
	}
}

func TestJoinIaCFlagsResourcesManagedTwice(t *testing.T) {
	res := ScanResult{Regions: []string{"r"}, Nodes: []ResourceNode{iacNode("i-1", "web", "aws_instance", "r", StatusManaged, "", nil)}}
	JoinIaC(&res, []IaCRef{
		{Source: "terraform", Origin: "a/terraform.tfstate", Type: "aws_instance", ID: "i-1", Address: "aws_instance.a"},
		{Source: "terraform", Origin: "b/terraform.tfstate", Type: "aws_instance", ID: "i-1", Address: "aws_instance.b"},
	}, []string{"t"}, 2, 0, nil)
	f := findRule(res, "iac.managed-twice")
	if f == nil || f.Severity != SevHigh || f.Affected != 1 {
		t.Fatalf("%+v", f)
	}
	// two instances of the same file are not a duplicate
	res2 := ScanResult{Regions: []string{"r"}, Nodes: []ResourceNode{iacNode("i-1", "web", "aws_instance", "r", StatusManaged, "", nil)}}
	JoinIaC(&res2, []IaCRef{
		{Source: "terraform", Origin: "a", Type: "aws_instance", ID: "i-1"},
		{Source: "terraform", Origin: "a", Type: "aws_instance", ID: "i-1", ARN: "arn:aws:ec2:r:1:instance/i-1"},
	}, []string{"t"}, 1, 0, nil)
	if findRule(res2, "iac.managed-twice") != nil {
		t.Fatal("one file is not two managers")
	}
}

func TestJoinIaCCloudFormationStackDrift(t *testing.T) {
	res := ScanResult{Regions: []string{"r"}, Nodes: []ResourceNode{iacNode("vol-1", "v", "aws_ebs_volume", "r", StatusShadowIT, "", nil)}}
	JoinIaC(&res, []IaCRef{
		{Source: "cloudformation", Origin: "net-vpc", Address: "DataVolume", Type: "AWS::EC2::Volume", ID: "vol-1", Region: "r", Drift: "DRIFTED"},
	}, []string{"cloudformation: 1 stack(s)"}, 0, 1, nil)
	n := res.Nodes[0]
	if n.Status != StatusManaged || n.ManagedBy != "CloudFormation" || n.Owner != "net-vpc" || n.OwnerSource != "cloudformation stack" {
		t.Fatalf("%+v", n)
	}
	if f := findRule(res, "iac.cloudformation-drift"); f == nil || f.Resources[0] != "net-vpc" {
		t.Fatalf("%+v", f)
	}
}

func TestDriftNeverComparesWhatTheStateDoesNotSay(t *testing.T) {
	res := ScanResult{Regions: []string{"r"}, Nodes: []ResourceNode{
		iacNode("vol-1", "v", "aws_ebs_volume", "r", StatusManaged, "", map[string]string{"size_gb": "100", "volume_type": "gp3"}),
	}}
	// state holds the size only: type must not be compared against nothing
	JoinIaC(&res, []IaCRef{{Source: "terraform", Origin: "o", Type: "aws_ebs_volume", ID: "vol-1", Attrs: map[string]string{"size": "100.0"}}},
		[]string{"t"}, 1, 0, nil)
	if res.Nodes[0].IaC == nil || len(res.Nodes[0].IaC.Drift) != 0 {
		t.Fatalf("100.0 and 100 are the same size: %+v", res.Nodes[0].IaC)
	}
}

// Regressions from the first live run against real state files.
func TestDriftIgnoresNamingAliasesAndOnDemandStreams(t *testing.T) {
	res := ScanResult{Regions: []string{"r"}, Nodes: []ResourceNode{
		iacNode("arn:aws:es:r:1:domain/s", "s", "aws_opensearch_domain", "r", StatusManaged, "", map[string]string{"instance_type": "r6g.large.search", "instances": "3"}),
		iacNode("arn:aws:kinesis:r:1:stream/k-od", "k-od", "aws_kinesis_stream", "r", StatusManaged, "", map[string]string{"mode": "ON_DEMAND", "shards": "8"}),
		iacNode("arn:aws:kinesis:r:1:stream/k-pr", "k-pr", "aws_kinesis_stream", "r", StatusManaged, "", map[string]string{"mode": "PROVISIONED", "shards": "8"}),
	}}
	JoinIaC(&res, []IaCRef{
		{Source: "terraform", Origin: "o", Type: "aws_opensearch_domain", ID: "arn:aws:es:r:1:domain/s",
			Attrs: map[string]string{"cluster_config.instance_type": "r6g.large.elasticsearch", "cluster_config.instance_count": "3"}},
		{Source: "terraform", Origin: "o", Type: "aws_kinesis_stream", ID: "k-od", ARN: "arn:aws:kinesis:r:1:stream/k-od", Attrs: map[string]string{"shard_count": "0"}},
		{Source: "terraform", Origin: "o", Type: "aws_kinesis_stream", ID: "k-pr", ARN: "arn:aws:kinesis:r:1:stream/k-pr", Attrs: map[string]string{"shard_count": "4"}},
	}, []string{"t"}, 1, 0, nil)
	if d := res.Nodes[0].IaC.Drift; len(d) != 0 {
		t.Fatalf(".elasticsearch and .search are the same instance type: %+v", d)
	}
	if d := res.Nodes[1].IaC.Drift; len(d) != 0 || res.Nodes[1].IaC.DriftChecked {
		t.Fatalf("shard count is meaningless for an on-demand stream: %+v", res.Nodes[1].IaC)
	}
	if d := res.Nodes[2].IaC.Drift; len(d) != 1 || d[0].State != "4" || d[0].Live != "8" {
		t.Fatalf("a provisioned stream with a different shard count is drift: %+v", d)
	}
}

func TestStateOrphansIgnoreTypesWithAnIncompleteInventory(t *testing.T) {
	res := ScanResult{Regions: []string{"eu-north-1"}}
	JoinIaC(&res, []IaCRef{
		// small log groups are rolled up in the inventory, so their absence says nothing
		{Source: "terraform", Origin: "o", Type: "aws_cloudwatch_log_group", ID: "/aws/lambda/x", ARN: "arn:aws:logs:eu-north-1:1:log-group:/aws/lambda/x"},
		{Source: "terraform", Origin: "o", Type: "aws_ebs_volume", ID: "vol-gone", ARN: "arn:aws:ec2:eu-north-1:1:volume/vol-gone"},
	}, []string{"t"}, 1, 0, nil)
	f := findRule(res, "iac.state-without-resource")
	if f == nil || f.Affected != 1 || f.Resources[0] != "vol-gone" {
		t.Fatalf("%+v", f)
	}
}

func TestDuplicateFindingSaysWhereTheCopiesAre(t *testing.T) {
	res := ScanResult{Regions: []string{"r"}, Nodes: []ResourceNode{iacNode("mysql2-1", "mysql2-1", "aws_rds_instance", "r", StatusManaged, "", nil)}}
	JoinIaC(&res, []IaCRef{
		{Source: "terraform", Origin: "datastores/rds/terraform.tfstate", Type: "aws_rds_cluster_instance", ID: "mysql2-1"},
		{Source: "terraform", Origin: "datastores/rds/mysql2/terraform.tfstate", Type: "aws_rds_cluster_instance", ID: "mysql2-1"},
	}, []string{"t"}, 2, 0, nil)
	f := findRule(res, "iac.managed-twice")
	if f == nil || !strings.Contains(strings.Join(f.Evidence, " "), "datastores/rds/mysql2/terraform.tfstate and") {
		t.Fatalf("%+v", f)
	}
}

func TestTagClaimsAreOnlyJudgedAgainstTheRightKindOfSource(t *testing.T) {
	// only CloudFormation was read: a Terraform tag cannot be confirmed or denied
	res := ScanResult{Regions: []string{"r"}, Nodes: []ResourceNode{iacNode("i-1", "web", "aws_instance", "r", StatusManaged, "Terraform", nil)}}
	JoinIaC(&res, nil, []string{"cloudformation: 2 stack(s)"}, 0, 2, nil)
	if res.IaC.TagOnly != 0 || findRule(res, "iac.tag-not-in-state") != nil {
		t.Fatalf("a Terraform claim must not be judged by stacks: %+v", res.IaC)
	}
}

// Regression: joining a waste candidate with its state used to overwrite the
// confidence of the waste verdict with the certainty of "found in code",
// turning every weak candidate into a high-confidence one.
func TestJoinIaCKeepsTheConfidenceOfAWasteVerdict(t *testing.T) {
	waste := iacNode("k-1", "idle-stream", "aws_kinesis_stream", "r", StatusOrphanWaste, "Terraform", nil)
	waste.Confidence = ConfLow
	managed := iacNode("k-2", "live-stream", "aws_kinesis_stream", "r", StatusManaged, "Terraform", nil)
	managed.Confidence = ConfMedium
	res := ScanResult{Regions: []string{"r"}, Nodes: []ResourceNode{waste, managed}}
	JoinIaC(&res, []IaCRef{
		{Source: "terraform", Origin: "o", Type: "aws_kinesis_stream", ID: "k-1"},
		{Source: "terraform", Origin: "o", Type: "aws_kinesis_stream", ID: "k-2"},
	}, []string{"t"}, 1, 0, nil)
	if res.Nodes[0].Confidence != ConfLow {
		t.Fatalf("a weak waste verdict must stay weak after the join, got %s", res.Nodes[0].Confidence)
	}
	if res.Nodes[1].Confidence != ConfHigh {
		t.Fatalf("a resource confirmed in code gains confidence about how it is managed: %s", res.Nodes[1].Confidence)
	}
}
