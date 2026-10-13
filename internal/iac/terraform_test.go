package iac

import (
	"encoding/json"
	"strings"
	"testing"
)

const sampleState = `{
  "version": 4,
  "terraform_version": "1.6.0",
  "serial": 12,
  "outputs": {"db_password": {"value": "OUTPUT-SECRET-123", "sensitive": true}},
  "resources": [
    {"mode":"managed","type":"aws_instance","name":"web","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
     "instances":[{"index_key":0,"attributes":{"id":"i-0abc","arn":"arn:aws:ec2:eu-north-1:1:instance/i-0abc",
        "instance_type":"t3.small","user_data":"#!/bin/bash\nexport TOKEN=USERDATA-SECRET-456","tags":{"Team":"web"}}}]},
    {"mode":"managed","type":"aws_db_instance","name":"main","module":"module.orders.module.db",
     "instances":[{"attributes":{"id":"orders-1","arn":"arn:aws:rds:eu-north-1:1:db:orders-1","instance_class":"db.r6g.large",
        "multi_az":true,"password":"DB-PASSWORD-789","username":"admin"}}]},
    {"mode":"managed","type":"aws_opensearch_domain","name":"s","instances":[{"attributes":{"id":"arn:aws:es:eu-north-1:1:domain/s",
        "engine_version":"OpenSearch_2.19","cluster_config":[{"instance_type":"r6g.large.search","instance_count":3}],
        "advanced_security_options":[{"master_user_options":[{"master_user_password":"OS-SECRET-000"}]}]}}]},
    {"mode":"data","type":"aws_caller_identity","name":"me","instances":[{"attributes":{"id":"123"}}]},
    {"mode":"managed","type":"aws_iam_role","name":"r","instances":[{"attributes":{"id":"role-x","arn":"arn:aws:iam::1:role/x"}}]},
    {"mode":"managed","type":"aws_ebs_volume","name":"d","instances":[
        {"index_key":"a","attributes":{"id":"vol-1","size":100,"type":"gp3","region":"eu-north-1"}},
        {"index_key":"b","attributes":{"id":"vol-2","size":200,"type":"gp3"}}]}
  ]
}`

func TestParseStateKeepsIdentifiersAndAllowListedAttributes(t *testing.T) {
	refs, err := ParseState(strings.NewReader(sampleState), "services/orders/terraform.tfstate")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]int{}
	for _, r := range refs {
		by[r.Type]++
	}
	// data sources and types the tool does not inventory (iam role) are not returned
	if by["aws_instance"] != 1 || by["aws_db_instance"] != 1 || by["aws_ebs_volume"] != 2 || by["aws_opensearch_domain"] != 1 || len(refs) != 5 {
		t.Fatalf("%v", by)
	}
	var db, os, vol1 = refs[1], refs[2], refs[3]
	if db.Module != "module.orders.module.db" || db.Address != "module.orders.module.db.aws_db_instance.main" {
		t.Fatalf("address: %+v", db)
	}
	if db.Attrs["instance_class"] != "db.r6g.large" || db.Attrs["multi_az"] != "true" {
		t.Fatalf("attrs: %+v", db.Attrs)
	}
	if os.Attrs["cluster_config.instance_type"] != "r6g.large.search" || os.Attrs["cluster_config.instance_count"] != "3" {
		t.Fatalf("nested attrs: %+v", os.Attrs)
	}
	if vol1.Address != `aws_ebs_volume.d["a"]` || vol1.Attrs["size"] != "100" || vol1.Region != "eu-north-1" {
		t.Fatalf("indexed: %+v", vol1)
	}
}

// The reason this package exists: a state file is full of secrets, and none
// of them may survive into anything that is stored, printed or sent.
func TestNoSecretSurvivesParsing(t *testing.T) {
	refs, err := ParseState(strings.NewReader(sampleState), "x.tfstate")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(refs)
	for _, secret := range []string{"OUTPUT-SECRET-123", "USERDATA-SECRET-456", "DB-PASSWORD-789", "OS-SECRET-000", "admin", "TOKEN"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("secret %q leaked into the parsed output:\n%s", secret, b)
		}
	}
	// tags are not kept either: they are read from the live resource
	if strings.Contains(string(b), `"Team"`) {
		t.Fatal("tags from state must not be kept")
	}
}

func TestParseStateRejectsWhatItCannotRead(t *testing.T) {
	for name, in := range map[string]string{
		"not json":   `hello`,
		"array":      `[1,2]`,
		"old format": `{"version":3,"modules":[]}`,
		"truncated":  `{"version":4,"resources":[{"mode":"managed","type":"aws_instance"`,
		"no version": `{"resources":[]}`,
	} {
		if _, err := ParseState(strings.NewReader(in), "bad"); err == nil {
			t.Errorf("%s must be an error", name)
		}
	}
	// an empty but valid state is fine
	refs, err := ParseState(strings.NewReader(`{"version":4,"resources":[]}`), "empty")
	if err != nil || len(refs) != 0 {
		t.Fatalf("%v %v", refs, err)
	}
}
