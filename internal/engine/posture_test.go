package engine

import (
	"strings"
	"testing"
)

func pn(id, typ string, attrs map[string]string) ResourceNode {
	return ResourceNode{ID: id, Name: id, Type: typ, Region: "r", Status: StatusManaged, Attrs: attrs, MonthlyCost: 10}
}

func ruleSet(res ScanResult) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range res.Findings {
		m[f.Rule] = f
	}
	return m
}

func TestPostureRulesReadOnlyWhatTheResourceStates(t *testing.T) {
	res := ScanResult{Nodes: []ResourceNode{
		pn("db-open", "aws_rds_instance", map[string]string{"public": "true", "encrypted": "false", "backup_days": "0", "multi_az": "false", "deletion_protection": "false", "status": "available"}),
		pn("db-ok", "aws_rds_instance", map[string]string{"public": "false", "encrypted": "true", "backup_days": "14", "multi_az": "true", "deletion_protection": "true", "status": "available"}),
		pn("db-unknown", "aws_rds_instance", map[string]string{}), // attributes not collected: no verdict
		pn("vol-clear", "aws_ebs_volume", map[string]string{"encrypted": "false"}),
		pn("os-public", "aws_opensearch_domain", map[string]string{"in_vpc": "false", "encrypted_at_rest": "false", "enforce_https": "true"}),
		pn("fn-old", "aws_lambda_function", map[string]string{"runtime": "python3.8"}),
		pn("fn-new", "aws_lambda_function", map[string]string{"runtime": "python3.12"}),
		pn("b-open", "aws_s3_bucket", map[string]string{"public_access_block": "false", "policy_public": "true"}),
		pn("b-ok", "aws_s3_bucket", map[string]string{"public_access_block": "true", "policy_public": "false"}),
	}}
	Finalize(&res, nil)
	r := ruleSet(res)

	for _, rule := range []string{
		"sec.rds-publicly-accessible", "sec.rds-unencrypted", "rel.rds-no-backups", "rel.rds-single-az",
		"rel.rds-no-deletion-protection", "sec.ebs-unencrypted", "sec.opensearch-public",
		"sec.opensearch-no-encryption-at-rest", "rel.lambda-deprecated-runtime",
		"sec.s3-public-access-block-off", "sec.s3-bucket-public",
	} {
		f, ok := r[rule]
		if !ok || f.Affected != 1 || f.Source != "own" || f.Recommendation == "" {
			t.Errorf("%s: %+v", rule, f)
		}
	}
	if f := r["sec.rds-publicly-accessible"]; f.Resources[0] != "db-open" || f.Severity != SevHigh {
		t.Fatalf("%+v", f)
	}
	if _, ok := r["sec.opensearch-https-not-enforced"]; ok {
		t.Fatal("HTTPS is enforced on the only domain: no finding")
	}
	// a resource whose attributes were not collected is never judged
	for _, f := range res.Findings {
		for _, id := range f.Resources {
			if id == "db-unknown" {
				t.Fatalf("db-unknown has no attributes and must not be flagged: %s", f.Rule)
			}
		}
	}
}

func TestSingleAZIsNotReportedForAClusterWithSeveralInstances(t *testing.T) {
	res := ScanResult{Nodes: []ResourceNode{
		pn("pg-1", "aws_rds_instance", map[string]string{"multi_az": "false", "cluster": "pg", "status": "available"}),
		pn("pg-2", "aws_rds_instance", map[string]string{"multi_az": "false", "cluster": "pg", "status": "available"}),
		pn("solo", "aws_rds_instance", map[string]string{"multi_az": "false", "cluster": "solo", "status": "available"}),
		pn("stopped", "aws_rds_instance", map[string]string{"multi_az": "false", "status": "stopped"}),
	}}
	Finalize(&res, nil)
	f, ok := ruleSet(res)["rel.rds-single-az"]
	if !ok || f.Affected != 1 || f.Resources[0] != "solo" {
		t.Fatalf("only the one-instance cluster lacks a standby: %+v", f)
	}
}

func TestPostureFindingsAreWordedAsFactsPlusOptions(t *testing.T) {
	res := ScanResult{Nodes: []ResourceNode{pn("db", "aws_rds_instance", map[string]string{"multi_az": "false", "status": "available"})}}
	Finalize(&res, nil)
	f := ruleSet(res)["rel.rds-single-az"]
	if !strings.HasSuffix(f.Title, "(1)") {
		t.Fatalf("the count belongs at the end of the title: %q", f.Title)
	}
	if !strings.Contains(f.Recommendation, "decide per database") {
		t.Fatalf("a cost-bearing change must be presented as a decision: %q", f.Recommendation)
	}
}
