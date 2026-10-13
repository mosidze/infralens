package aws

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryIsConsistent(t *testing.T) {
	seen := map[string]bool{}
	types := map[string]string{}
	for _, s := range Scanners() {
		if seen[s.Name] {
			t.Errorf("duplicate scanner %s", s.Name)
		}
		seen[s.Name] = true
		if (s.Regional == nil) == (s.Global == nil) {
			t.Errorf("%s: exactly one of Regional/Global must be set", s.Name)
		}
		if (len(s.Types) == 0 && !s.Informational) || s.Desc == "" {
			t.Errorf("%s: needs Types and Desc", s.Name)
		}
		for ty, svc := range s.Types {
			if prev, ok := types[ty]; ok {
				t.Errorf("node type %s claimed by %s and %s", ty, prev, s.Name)
			}
			types[ty] = s.Name
			if svc == "" {
				t.Errorf("%s: %s has no Cost Explorer service", s.Name, ty)
			}
		}
	}
	for _, want := range []string{"ec2", "ebs", "eip", "nat", "elb", "ecs", "rds", "opensearch", "kinesis", "logs", "s3", "reservations", "coverage", "lambda", "vpcendpoints", "redshift", "memorydb", "elasticache", "dynamodb", "sqs", "firehose", "cloudfront"} {
		if !seen[want] {
			t.Errorf("scanner %q not registered", want)
		}
	}
}

func TestSelectScanners(t *testing.T) {
	got, err := SelectScanners([]string{"rds", "s3"}, nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("only: %v %v", got, err)
	}
	all := len(Scanners())
	got, err = SelectScanners(nil, []string{"logs"})
	if err != nil || len(got) != all-1 {
		t.Fatalf("skip: %d %v", len(got), err)
	}
	if _, err := SelectScanners([]string{"rdss"}, nil); err == nil || !strings.Contains(err.Error(), "available:") {
		t.Fatalf("typo must be an error listing choices, got %v", err)
	}
	if _, err := SelectScanners([]string{"rds"}, []string{"rds"}); err == nil {
		t.Fatal("selecting nothing must be an error")
	}
	m := CostServiceMap(Scanners())
	if m["aws_ecs_service"] != "Amazon Elastic Container Service" {
		t.Fatalf("coverage map: %v", m)
	}
}

func TestLoadThresholds(t *testing.T) {
	th, err := LoadThresholds("")
	if err != nil || th != DefaultThresholds() {
		t.Fatal("empty path must give defaults")
	}
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "c.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	th, err = LoadThresholds(write(`{"idle_window_days": 30, "log_min_cost": 5}`))
	if err != nil || th.IdleWindowDays != 30 || th.LogMinCost != 5 || th.SnapshotMinAgeDays != 90 {
		t.Fatalf("partial override must keep other defaults: %+v %v", th, err)
	}
	if _, err := LoadThresholds(write(`{"idle_windw_days": 30}`)); err == nil {
		t.Fatal("unknown key must be rejected")
	}
	if _, err := LoadThresholds(write(`{"idle_window_days": 0}`)); err == nil {
		t.Fatal("out-of-range window must be rejected")
	}
}
