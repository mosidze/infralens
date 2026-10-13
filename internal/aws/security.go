package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// A thin layer of own security checks, kept to the few that matter most and
// that need only Describe/List/Get calls. They are a floor for accounts that
// have no Security Hub or Trusted Advisor, not a replacement for a security
// product: the document says what was and was not looked at.

const (
	iamUserCap   = 300
	staleKeyDays = 90
)

func secFinding(rule string, sev engine.Severity, title, rec string, evidence []string, resources []string, group string) engine.Finding {
	f := engine.Finding{
		Pillar: engine.PillarSecurity, Source: "own", Rule: rule, Severity: sev, Title: title,
		Recommendation: rec, Evidence: evidence, Confidence: engine.ConfHigh, Effort: "low",
		Affected: len(resources), Resources: resources, GroupKey: group,
	}
	if len(resources) > 0 {
		f.ResourceID = resources[0]
	} else {
		f.ResourceID = "account:" + rule
		f.Affected = 1
	}
	f.ID = engine.FindingID(f.Source, f.Rule, group+f.ResourceID)
	return f
}

// ---- IAM ----------------------------------------------------------------------

type iamAPI interface {
	GetAccountSummary(ctx context.Context, in *iam.GetAccountSummaryInput, opts ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	GetAccountPasswordPolicy(ctx context.Context, in *iam.GetAccountPasswordPolicyInput, opts ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	iam.ListUsersAPIClient
	ListMFADevices(ctx context.Context, in *iam.ListMFADevicesInput, opts ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, opts ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetAccessKeyLastUsed(ctx context.Context, in *iam.GetAccessKeyLastUsedInput, opts ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
	GetLoginProfile(ctx context.Context, in *iam.GetLoginProfileInput, opts ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error)
}

func scanIAM(ctx context.Context, dc *DiscoveryClient, c *collector) {
	cfg, err := dc.loadConfig(ctx, "us-east-1")
	if err != nil {
		c.warn("iam:config", err)
		return
	}
	iamWith(ctx, iam.NewFromConfig(cfg), c, time.Now())
}

func iamWith(ctx context.Context, api iamAPI, c *collector, now time.Time) {
	if sum, err := api.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{}); err != nil {
		c.warn("iam:account-summary", err)
	} else {
		if sum.SummaryMap["AccountMFAEnabled"] == 0 {
			c.finding(secFinding("sec.root-mfa-off", engine.SevCritical, "The root user has no MFA device",
				"Attach a hardware or virtual MFA device to the root user and keep the credentials out of daily use.",
				[]string{"IAM account summary: AccountMFAEnabled = 0"}, nil, ""))
		}
		if sum.SummaryMap["AccountAccessKeysPresent"] > 0 {
			c.finding(secFinding("sec.root-access-keys", engine.SevCritical, "The root user has access keys",
				"Delete root access keys and use roles or IAM users. Root keys cannot be restricted by policy.",
				[]string{fmt.Sprintf("IAM account summary: AccountAccessKeysPresent = %d", sum.SummaryMap["AccountAccessKeysPresent"])}, nil, ""))
		}
	}

	if pp, err := api.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{}); err != nil {
		if isNoSuchEntity(err) {
			c.finding(secFinding("sec.no-password-policy", engine.SevMedium, "The account has no IAM password policy",
				"Set a password policy (length, rotation, reuse) if any IAM user signs in with a password, or move people to SSO.",
				[]string{"GetAccountPasswordPolicy returned NoSuchEntity"}, nil, ""))
		} else {
			c.warn("iam:password-policy", err)
		}
	} else if pp.PasswordPolicy != nil && aws.ToInt32(pp.PasswordPolicy.MinimumPasswordLength) < 14 {
		c.finding(secFinding("sec.weak-password-policy", engine.SevLow, "The IAM password policy allows short passwords",
			"Raise the minimum length to at least 14 characters.",
			[]string{fmt.Sprintf("MinimumPasswordLength = %d", aws.ToInt32(pp.PasswordPolicy.MinimumPasswordLength))}, nil, ""))
	}

	var users []iamTypes.User
	p := iam.NewListUsersPaginator(api, &iam.ListUsersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("iam:users", err)
			return
		}
		users = append(users, page.Users...)
	}
	if len(users) > iamUserCap {
		c.skip("iam", fmt.Sprintf("%d users; the first %d were checked", len(users), iamUserCap))
		users = users[:iamUserCap]
	}

	var noMFA, oldKeys, unusedKeys []string
	for _, u := range users {
		name := aws.ToString(u.UserName)
		// MFA matters for users who can sign in to the console
		if _, err := api.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: u.UserName}); err == nil {
			if m, err := api.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: u.UserName}); err == nil && len(m.MFADevices) == 0 {
				noMFA = append(noMFA, name)
			}
		}
		keys, err := api.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: u.UserName})
		if err != nil {
			continue
		}
		for _, k := range keys.AccessKeyMetadata {
			if k.Status != iamTypes.StatusTypeActive {
				continue
			}
			label := name + "/" + aws.ToString(k.AccessKeyId)
			if k.CreateDate != nil && now.Sub(*k.CreateDate) > staleKeyDays*24*time.Hour {
				oldKeys = append(oldKeys, label)
			}
			lu, err := api.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: k.AccessKeyId})
			if err != nil || lu.AccessKeyLastUsed == nil {
				continue
			}
			last := lu.AccessKeyLastUsed.LastUsedDate
			if last == nil || now.Sub(*last) > staleKeyDays*24*time.Hour {
				unusedKeys = append(unusedKeys, label)
			}
		}
	}
	sort.Strings(noMFA)
	sort.Strings(oldKeys)
	sort.Strings(unusedKeys)
	if len(noMFA) > 0 {
		c.finding(secFinding("sec.iam-user-no-mfa", engine.SevHigh, fmt.Sprintf("%d IAM users can sign in to the console without MFA", len(noMFA)),
			"Require MFA for console users, or move them to SSO where it is enforced centrally.",
			[]string{fmt.Sprintf("checked %d users", len(users))}, noMFA, "iam"))
	}
	if len(oldKeys) > 0 {
		c.finding(secFinding("sec.iam-key-not-rotated", engine.SevMedium, fmt.Sprintf("%d active access keys are older than %d days", len(oldKeys), staleKeyDays),
			"Rotate the keys, or replace long-lived keys with roles. Check what uses each key before deleting it.",
			[]string{"age is taken from the key's creation date"}, oldKeys, "iam"))
	}
	if len(unusedKeys) > 0 {
		c.finding(secFinding("sec.iam-key-unused", engine.SevMedium, fmt.Sprintf("%d active access keys have not been used for %d days", len(unusedKeys), staleKeyDays),
			"Deactivate the key first, wait a cycle, then delete it. A key nobody uses is risk without value.",
			[]string{"never used, or last used more than the threshold ago"}, unusedKeys, "iam"))
	}
}

// isNoSuchEntity recognises IAM's "that does not exist" both as the typed
// SDK error and by its code, so the check does not depend on the wrapper.
func isNoSuchEntity(err error) bool {
	var nse *iamTypes.NoSuchEntityException
	return errors.As(err, &nse) || apiCode(err, "NoSuchEntity") || strings.Contains(err.Error(), "NoSuchEntity")
}

// ---- security groups open to the world ---------------------------------------

var sensitivePorts = map[int32]string{
	22: "SSH", 23: "Telnet", 135: "RPC", 445: "SMB", 1433: "SQL Server", 1521: "Oracle", 2375: "Docker",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5984: "CouchDB", 6379: "Redis", 9200: "OpenSearch",
	9300: "OpenSearch", 11211: "Memcached", 27017: "MongoDB",
}

type sgAPI interface {
	ec2.DescribeSecurityGroupsAPIClient
	ec2.DescribeNetworkInterfacesAPIClient
}

func scanSGExposure(ctx context.Context, cfg aws.Config, c *collector) {
	sgExposureWith(ctx, ec2.NewFromConfig(cfg), c)
}

// openPorts returns what an ingress rule exposes to the whole internet.
func openPorts(p ec2Types.IpPermission) (all bool, ports []string) {
	world := false
	for _, r := range p.IpRanges {
		if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
			world = true
		}
	}
	for _, r := range p.Ipv6Ranges {
		if aws.ToString(r.CidrIpv6) == "::/0" {
			world = true
		}
	}
	if !world {
		return false, nil
	}
	if aws.ToString(p.IpProtocol) == "-1" {
		return true, nil
	}
	from, to := aws.ToInt32(p.FromPort), aws.ToInt32(p.ToPort)
	if to < from {
		to = from
	}
	if to-from > 2000 { // a wide range: every sensitive port inside it is exposed
		for port, name := range sensitivePorts {
			if port >= from && port <= to {
				ports = append(ports, fmt.Sprintf("%d/%s", port, name))
			}
		}
		sort.Strings(ports)
		if len(ports) == 0 {
			ports = []string{fmt.Sprintf("%d-%d", from, to)}
		}
		return false, ports
	}
	for port := from; port <= to; port++ {
		if name, ok := sensitivePorts[port]; ok {
			ports = append(ports, fmt.Sprintf("%d/%s", port, name))
		}
	}
	return false, ports
}

func sgExposureWith(ctx context.Context, api sgAPI, c *collector) {
	inUse := map[string]int{}
	np := ec2.NewDescribeNetworkInterfacesPaginator(api, &ec2.DescribeNetworkInterfacesInput{})
	for np.HasMorePages() {
		page, err := np.NextPage(ctx)
		if err != nil {
			c.warn("ec2:network-interfaces", err)
			return
		}
		for _, ni := range page.NetworkInterfaces {
			for _, g := range ni.Groups {
				inUse[aws.ToString(g.GroupId)]++
			}
		}
	}
	p := ec2.NewDescribeSecurityGroupsPaginator(api, &ec2.DescribeSecurityGroupsInput{})
	var openAll, openSensitive, unusedOpen []string
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("ec2:security-groups", err)
			return
		}
		for _, g := range page.SecurityGroups {
			id := aws.ToString(g.GroupId)
			var all bool
			var ports []string
			for _, perm := range g.IpPermissions {
				a, ps := openPorts(perm)
				all = all || a
				ports = append(ports, ps...)
			}
			if !all && len(ports) == 0 {
				continue
			}
			label := fmt.Sprintf("%s (%s, %s)", id, aws.ToString(g.GroupName), c.region)
			switch {
			case inUse[id] == 0:
				unusedOpen = append(unusedOpen, label)
			case all:
				openAll = append(openAll, label)
			default:
				openSensitive = append(openSensitive, label+" "+strings.Join(uniq(ports), ","))
			}
		}
	}
	if len(openAll) > 0 {
		c.finding(secFinding("sec.sg-open-all", engine.SevCritical, "Security groups in use allow all traffic from the internet",
			"Restrict the source to the networks that need it. A group open on every port exposes whatever listens on the attached instances.",
			[]string{"ingress from 0.0.0.0/0 or ::/0 on all protocols, attached to at least one network interface"}, openAll, "sg-open-all"))
	}
	if len(openSensitive) > 0 {
		c.finding(secFinding("sec.sg-open-sensitive", engine.SevHigh, "Security groups in use expose administrative or database ports to the internet",
			"Close these ports to the internet; reach them through a bastion, SSM or a VPN.",
			[]string{"ingress from 0.0.0.0/0 or ::/0 on SSH, RDP or a database port, attached to at least one network interface"}, openSensitive, "sg-open-sensitive"))
	}
	if len(unusedOpen) > 0 {
		c.finding(secFinding("sec.sg-open-unattached", engine.SevLow, "Security groups open to the internet are attached to nothing",
			"Delete them so that nobody attaches one by accident.",
			[]string{"open ingress, but no network interface uses the group"}, unusedOpen, "sg-open-unattached"))
	}
}

func uniq(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// ---- CloudTrail and GuardDuty ------------------------------------------------

type trailAPI interface {
	DescribeTrails(ctx context.Context, in *cloudtrail.DescribeTrailsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, in *cloudtrail.GetTrailStatusInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

func scanCloudTrail(ctx context.Context, cfg aws.Config, c *collector) {
	cloudTrailWith(ctx, cloudtrail.NewFromConfig(cfg), c)
}

func cloudTrailWith(ctx context.Context, api trailAPI, c *collector) {
	out, err := api.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		c.warn("cloudtrail:trails", err)
		return
	}
	covered, logging, validated := false, false, true
	for _, t := range out.TrailList {
		if aws.ToBool(t.IsMultiRegionTrail) || aws.ToString(t.HomeRegion) == c.region {
			covered = true
		} else {
			continue
		}
		if st, err := api.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN}); err == nil && aws.ToBool(st.IsLogging) {
			logging = true
		}
		if !aws.ToBool(t.LogFileValidationEnabled) {
			validated = false
		}
	}
	switch {
	case !covered:
		c.finding(secFinding("sec.no-cloudtrail", engine.SevHigh, "No CloudTrail trail covers these regions",
			"Create a multi-region trail so that API activity is recorded; without it there is nothing to investigate with.",
			[]string{"no multi-region trail and no trail homed in the region"}, []string{c.region}, "no-cloudtrail"))
	case !logging:
		c.finding(secFinding("sec.cloudtrail-not-logging", engine.SevHigh, "A CloudTrail trail exists but is not logging",
			"Start logging on the trail.", []string{"GetTrailStatus: IsLogging = false"}, []string{c.region}, "cloudtrail-not-logging"))
	case !validated:
		c.finding(secFinding("sec.cloudtrail-no-validation", engine.SevLow, "CloudTrail log file validation is off",
			"Enable log file validation so tampering with delivered logs can be detected.",
			[]string{"LogFileValidationEnabled = false on a covering trail"}, []string{c.region}, "cloudtrail-no-validation"))
	}
}

type guardDutyAPI interface {
	guardduty.ListDetectorsAPIClient
	GetDetector(ctx context.Context, in *guardduty.GetDetectorInput, opts ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error)
}

func scanGuardDuty(ctx context.Context, cfg aws.Config, c *collector) {
	guardDutyWith(ctx, guardduty.NewFromConfig(cfg), c)
}

func guardDutyWith(ctx context.Context, api guardDutyAPI, c *collector) {
	out, err := api.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		c.warn("guardduty:detectors", err)
		return
	}
	on := false
	for _, id := range out.DetectorIds {
		if d, err := api.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: aws.String(id)}); err == nil && string(d.Status) == "ENABLED" {
			on = true
		}
	}
	if !on {
		c.finding(secFinding("sec.guardduty-disabled", engine.SevMedium, "GuardDuty threat detection is not enabled",
			"Enable GuardDuty in the regions in use (it is billed by volume and has a free trial). Whether to cover unused regions is a decision for the owner.",
			[]string{"no enabled detector"}, []string{c.region}, "guardduty-disabled"))
	}
}

func init() {
	register(Scanner{Name: "iam", Desc: "IAM: root MFA and keys, password policy, console users without MFA, stale access keys",
		Informational: true, Global: scanIAM})
	register(Scanner{Name: "sgexposure", Desc: "Security groups open to the internet, split by attachment and port",
		Informational: true, Regional: scanSGExposure})
	register(Scanner{Name: "cloudtrail", Desc: "CloudTrail coverage and logging state per region",
		Informational: true, Regional: scanCloudTrail})
	register(Scanner{Name: "guardduty", Desc: "GuardDuty enabled per region",
		Informational: true, Regional: scanGuardDuty})
}
