package aws

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	ctTypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2T "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamT "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func byRule(c *collector) map[string]engine.Finding {
	m := map[string]engine.Finding{}
	for _, f := range c.findings {
		m[f.Rule] = f
	}
	return m
}

// ---- IAM ----------------------------------------------------------------------

type fakeIAM struct {
	summary    map[string]int32
	policyErr  error
	policyLen  int32
	users      []string
	consoleFor map[string]bool
	mfaFor     map[string]bool
	keys       map[string][]iamT.AccessKeyMetadata
	lastUsed   map[string]*time.Time
}

func (f fakeIAM) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return &iam.GetAccountSummaryOutput{SummaryMap: f.summary}, nil
}
func (f fakeIAM) GetAccountPasswordPolicy(context.Context, *iam.GetAccountPasswordPolicyInput, ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	return &iam.GetAccountPasswordPolicyOutput{PasswordPolicy: &iamT.PasswordPolicy{MinimumPasswordLength: aws.Int32(f.policyLen)}}, nil
}
func (f fakeIAM) ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	out := &iam.ListUsersOutput{}
	for _, u := range f.users {
		out.Users = append(out.Users, iamT.User{UserName: aws.String(u)})
	}
	return out, nil
}
func (f fakeIAM) GetLoginProfile(_ context.Context, in *iam.GetLoginProfileInput, _ ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	if f.consoleFor[aws.ToString(in.UserName)] {
		return &iam.GetLoginProfileOutput{}, nil
	}
	return nil, errors.New("NoSuchEntity")
}
func (f fakeIAM) ListMFADevices(_ context.Context, in *iam.ListMFADevicesInput, _ ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	out := &iam.ListMFADevicesOutput{}
	if f.mfaFor[aws.ToString(in.UserName)] {
		out.MFADevices = []iamT.MFADevice{{}}
	}
	return out, nil
}
func (f fakeIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: f.keys[aws.ToString(in.UserName)]}, nil
}
func (f fakeIAM) GetAccessKeyLastUsed(_ context.Context, in *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	return &iam.GetAccessKeyLastUsedOutput{AccessKeyLastUsed: &iamT.AccessKeyLastUsed{LastUsedDate: f.lastUsed[aws.ToString(in.AccessKeyId)]}}, nil
}

func TestIAMChecks(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	old, recent := now.AddDate(0, 0, -200), now.AddDate(0, 0, -5)
	api := fakeIAM{
		summary:    map[string]int32{"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1},
		policyErr:  errors.New("NoSuchEntity: The Password Policy cannot be found"),
		users:      []string{"alice", "bob", "robot", "ghost"},
		consoleFor: map[string]bool{"alice": true, "bob": true},
		mfaFor:     map[string]bool{"alice": true},
		keys: map[string][]iamT.AccessKeyMetadata{
			"robot": {{AccessKeyId: aws.String("AKIAOLD"), Status: iamT.StatusTypeActive, CreateDate: &old}},
			"bob":   {{AccessKeyId: aws.String("AKIANEW"), Status: iamT.StatusTypeActive, CreateDate: &recent}, {AccessKeyId: aws.String("AKIAOFF"), Status: iamT.StatusTypeInactive, CreateDate: &old}},
		},
		lastUsed: map[string]*time.Time{"AKIAOLD": &old, "AKIANEW": &recent},
	}
	c := newTestCollector()
	iamWith(context.Background(), api, c, now)
	r := byRule(c)

	if r["sec.root-mfa-off"].Severity != engine.SevCritical || r["sec.root-access-keys"].Severity != engine.SevCritical {
		t.Fatalf("root findings: %+v", r)
	}
	if _, ok := r["sec.no-password-policy"]; !ok {
		t.Fatal("missing password policy")
	}
	noMFA := r["sec.iam-user-no-mfa"]
	if noMFA.Affected != 1 || noMFA.Resources[0] != "bob" {
		t.Fatalf("only bob can sign in without MFA (alice has it, robot and ghost have no console): %+v", noMFA)
	}
	if k := r["sec.iam-key-not-rotated"]; k.Affected != 1 || !strings.Contains(k.Resources[0], "AKIAOLD") {
		t.Fatalf("old active key: %+v", k)
	}
	if k := r["sec.iam-key-unused"]; k.Affected != 1 || !strings.Contains(k.Resources[0], "AKIAOLD") {
		t.Fatalf("unused: %+v", k)
	}
	for _, f := range c.findings {
		for _, res := range f.Resources {
			if strings.Contains(res, "AKIAOFF") {
				t.Fatalf("an inactive key is not a finding: %s", f.Rule)
			}
		}
	}
}

func TestIAMCleanAccountProducesNothing(t *testing.T) {
	api := fakeIAM{summary: map[string]int32{"AccountMFAEnabled": 1}, policyLen: 16}
	c := newTestCollector()
	iamWith(context.Background(), api, c, time.Now())
	if len(c.findings) != 0 || len(c.warnings) != 0 {
		t.Fatalf("%+v %v", c.findings, c.warnings)
	}
}

// ---- security groups ------------------------------------------------------------

type fakeSG struct {
	groups []ec2T.SecurityGroup
	enis   []ec2T.NetworkInterface
}

func (f fakeSG) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.groups}, nil
}
func (f fakeSG) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: f.enis}, nil
}

func world(proto string, from, to int32) ec2T.IpPermission {
	return ec2T.IpPermission{IpProtocol: aws.String(proto), FromPort: aws.Int32(from), ToPort: aws.Int32(to),
		IpRanges: []ec2T.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}}
}

func TestSecurityGroupExposure(t *testing.T) {
	sg := func(id string, perms ...ec2T.IpPermission) ec2T.SecurityGroup {
		return ec2T.SecurityGroup{GroupId: aws.String(id), GroupName: aws.String(id + "-name"), IpPermissions: perms}
	}
	api := fakeSG{
		groups: []ec2T.SecurityGroup{
			sg("sg-all", world("-1", 0, 0)),
			sg("sg-ssh", world("tcp", 22, 22)),
			sg("sg-web", world("tcp", 443, 443), world("tcp", 80, 80)), // public web: not a finding
			sg("sg-unused", world("tcp", 3389, 3389)),
			sg("sg-range", world("tcp", 0, 65535)),
			sg("sg-private", ec2T.IpPermission{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(22), ToPort: aws.Int32(22),
				IpRanges: []ec2T.IpRange{{CidrIp: aws.String("10.0.0.0/8")}}}),
		},
		enis: []ec2T.NetworkInterface{
			{Groups: []ec2T.GroupIdentifier{{GroupId: aws.String("sg-all")}}},
			{Groups: []ec2T.GroupIdentifier{{GroupId: aws.String("sg-ssh")}, {GroupId: aws.String("sg-web")}, {GroupId: aws.String("sg-range")}}},
			{Groups: []ec2T.GroupIdentifier{{GroupId: aws.String("sg-private")}}},
		},
	}
	c := newTestCollector()
	sgExposureWith(context.Background(), api, c)
	r := byRule(c)

	if a := r["sec.sg-open-all"]; a.Severity != engine.SevCritical || a.Affected != 1 || !strings.Contains(a.Resources[0], "sg-all") {
		t.Fatalf("all traffic: %+v", a)
	}
	s := r["sec.sg-open-sensitive"]
	if s.Affected != 2 {
		t.Fatalf("ssh and the wide range, both attached: %+v", s)
	}
	sort.Strings(s.Resources)
	if !strings.Contains(strings.Join(s.Resources, " "), "22/SSH") || !strings.Contains(strings.Join(s.Resources, " "), "sg-range") {
		t.Fatalf("%+v", s.Resources)
	}
	u := r["sec.sg-open-unattached"]
	if u.Severity != engine.SevLow || u.Affected != 1 || !strings.Contains(u.Resources[0], "sg-unused") {
		t.Fatalf("an unattached open group is low, not critical: %+v", u)
	}
	for _, f := range c.findings {
		for _, res := range f.Resources {
			if strings.Contains(res, "sg-web") || strings.Contains(res, "sg-private") {
				t.Fatalf("public web ports and private sources are not findings: %s %s", f.Rule, res)
			}
		}
	}
}

// ---- CloudTrail, GuardDuty --------------------------------------------------------

type fakeTrail struct {
	trails  []ctTypes.Trail
	logging bool
}

func (f fakeTrail) DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return &cloudtrail.DescribeTrailsOutput{TrailList: f.trails}, nil
}
func (f fakeTrail) GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(f.logging)}, nil
}

func TestCloudTrailCoverage(t *testing.T) {
	multi := ctTypes.Trail{TrailARN: aws.String("arn:t"), IsMultiRegionTrail: aws.Bool(true), HomeRegion: aws.String("eu-west-1"), LogFileValidationEnabled: aws.Bool(true)}

	c := newTestCollector()
	cloudTrailWith(context.Background(), fakeTrail{trails: []ctTypes.Trail{multi}, logging: true}, c)
	if len(c.findings) != 0 {
		t.Fatalf("a logging multi-region trail covers every region: %+v", c.findings)
	}
	c = newTestCollector()
	cloudTrailWith(context.Background(), fakeTrail{}, c)
	if f := byRule(c)["sec.no-cloudtrail"]; f.Severity != engine.SevHigh {
		t.Fatalf("%+v", c.findings)
	}
	c = newTestCollector()
	cloudTrailWith(context.Background(), fakeTrail{trails: []ctTypes.Trail{multi}, logging: false}, c)
	if _, ok := byRule(c)["sec.cloudtrail-not-logging"]; !ok {
		t.Fatalf("%+v", c.findings)
	}
	// a single-region trail in another region does not cover this one
	other := ctTypes.Trail{TrailARN: aws.String("arn:o"), IsMultiRegionTrail: aws.Bool(false), HomeRegion: aws.String("us-west-2")}
	c = newTestCollector()
	cloudTrailWith(context.Background(), fakeTrail{trails: []ctTypes.Trail{other}, logging: true}, c)
	if _, ok := byRule(c)["sec.no-cloudtrail"]; !ok {
		t.Fatal("a trail homed elsewhere does not cover this region")
	}
}

type fakeGD struct {
	ids    []string
	status string
}

func (f fakeGD) ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return &guardduty.ListDetectorsOutput{DetectorIds: f.ids}, nil
}
func (f fakeGD) GetDetector(context.Context, *guardduty.GetDetectorInput, ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
	return &guardduty.GetDetectorOutput{Status: "ENABLED"}, nil
}

func TestGuardDuty(t *testing.T) {
	c := newTestCollector()
	guardDutyWith(context.Background(), fakeGD{}, c)
	if len(c.findings) != 1 || c.findings[0].Rule != "sec.guardduty-disabled" {
		t.Fatalf("%+v", c.findings)
	}
	c = newTestCollector()
	guardDutyWith(context.Background(), fakeGD{ids: []string{"d1"}}, c)
	if len(c.findings) != 0 {
		t.Fatalf("%+v", c.findings)
	}
}

func TestRegionalFindingsAreGroupedIntoOne(t *testing.T) {
	res := engine.ScanResult{}
	for _, region := range []string{"eu-north-1", "eu-west-1", "us-east-1"} {
		c := newCollector(region, DefaultThresholds())
		guardDutyWith(context.Background(), fakeGD{}, c)
		res.Findings = append(res.Findings, c.findings...)
	}
	engine.Finalize(&res, nil)
	var gd []engine.Finding
	for _, f := range res.Findings {
		if f.Rule == "sec.guardduty-disabled" {
			gd = append(gd, f)
		}
	}
	if len(gd) != 1 || gd[0].Affected != 3 || len(gd[0].Resources) != 3 {
		t.Fatalf("three regions must read as one finding listing three regions: %+v", gd)
	}
}
