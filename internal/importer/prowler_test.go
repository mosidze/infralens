package importer

import (
	"strings"
	"testing"

	"infralens/internal/engine"
)

const ocsfArray = `[
 {"status_code":"FAIL","severity":"high","finding_info":{"uid":"u1","title":"S3 bucket allows public read"},
  "resources":[{"uid":"arn:aws:s3:::a","region":"eu-west-1"}],"cloud":{"region":"eu-west-1"},
  "remediation":{"desc":"Block public access."},"metadata":{"event_code":"s3_bucket_public_access"}},
 {"status_code":"FAIL","severity":"high","finding_info":{"uid":"u2","title":"S3 bucket allows public read"},
  "resources":[{"uid":"arn:aws:s3:::b"}],"metadata":{"event_code":"s3_bucket_public_access"}},
 {"status_code":"PASS","severity":"high","finding_info":{"title":"fine"},"metadata":{"event_code":"iam_root_mfa"}},
 {"status_code":"FAIL","severity":"critical","finding_info":{"title":"Root has access keys"},"metadata":{"event_code":"iam_no_root_access_key"}}
]`

func TestParseProwlerOCSFGroupsFailuresByCheck(t *testing.T) {
	fs, err := ParseProwler(strings.NewReader(ocsfArray))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("passing checks are not findings, failures group by check: %+v", fs)
	}
	if fs[0].Severity != engine.SevCritical || fs[0].Reference != "iam_no_root_access_key" {
		t.Fatalf("critical first: %+v", fs[0])
	}
	s3 := fs[1]
	if s3.Affected != 2 || len(s3.Resources) != 2 || s3.Source != "prowler" || s3.Pillar != engine.PillarSecurity || s3.Recommendation != "Block public access." {
		t.Fatalf("%+v", s3)
	}
	if s3.ID == "" || s3.ID == fs[0].ID {
		t.Fatal("ids")
	}
}

func TestParseProwlerV3JSONLines(t *testing.T) {
	in := `{"Status":"FAIL","Severity":"medium","CheckID":"ec2_ebs_volume_encryption","CheckTitle":"EBS volumes should be encrypted","ResourceId":"vol-1","Region":"eu-north-1","Remediation":{"Recommendation":{"Text":"Enable encryption"}}}
{"Status":"FAIL","Severity":"medium","CheckID":"ec2_ebs_volume_encryption","CheckTitle":"EBS volumes should be encrypted","ResourceId":"vol-2","Region":"eu-north-1"}
{"Status":"INFO","CheckID":"x"}
`
	fs, err := ParseProwler(strings.NewReader(in))
	if err != nil || len(fs) != 1 || fs[0].Affected != 2 || fs[0].Region != "eu-north-1" || fs[0].Severity != engine.SevMedium {
		t.Fatalf("%v %+v", err, fs)
	}
}

func TestParseProwlerRejectsNonsense(t *testing.T) {
	for name, in := range map[string]string{"empty": "", "text": "hello", "broken": `[{"a":`, "html": "<html>"} {
		if _, err := ParseProwler(strings.NewReader(in)); err == nil {
			t.Errorf("%s must be an error", name)
		}
	}
	if fs, err := ParseProwler(strings.NewReader(`[]`)); err != nil || len(fs) != 0 {
		t.Fatalf("an empty report is valid: %v %v", fs, err)
	}
}
