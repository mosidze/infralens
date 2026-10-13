package engine

import (
	"fmt"
	"sort"
	"strings"
)

// Posture findings are read from attributes the scanners already collected:
// no further API calls, and no opinion about anything the account did not
// state. Each rule groups resources, so a document lists one line per
// problem and the affected resources under it.

type postureRule struct {
	Rule, Pillar, Title, Recommendation, Reference string
	Severity                                       Severity
	Effort                                         string
	NodeTypes                                      []string
	Hit                                            func(n ResourceNode, ctx postureCtx) (bool, string)
}

type postureCtx struct {
	clusterMembers map[string]int
}

var deprecatedRuntimes = map[string]string{
	// runtimes AWS Lambda no longer allows to create or update; the list is
	// conservative and meant to be extended, not trusted as complete
	"python2.7": "2021-07", "python3.6": "2022-07", "python3.7": "2023-12", "python3.8": "2024-10",
	"nodejs": "2016", "nodejs4.3": "2020", "nodejs6.10": "2019", "nodejs8.10": "2020", "nodejs10.x": "2021-07",
	"nodejs12.x": "2023-03", "nodejs14.x": "2023-12", "nodejs16.x": "2024-06",
	"dotnetcore1.0": "2019", "dotnetcore2.0": "2019", "dotnetcore2.1": "2022-01", "dotnetcore3.1": "2023-04",
	"dotnet5.0": "2022-05", "dotnet6": "2024-12", "java8": "2024-01", "go1.x": "2024-01",
	"ruby2.5": "2021-07", "ruby2.7": "2023-12", "provided": "2024-01",
}

func truthy(s string) bool { return strings.EqualFold(s, "true") }
func falsey(s string) bool { return strings.EqualFold(s, "false") }

var postureRules = []postureRule{
	{Rule: "sec.rds-publicly-accessible", Pillar: "security", Severity: SevHigh, Effort: "medium",
		Title:          "RDS instances are reachable from the internet",
		Recommendation: "Turn off public accessibility unless it is required, and restrict the security group. Check what connects to it first.",
		Reference:      "CIS AWS Foundations: RDS instances should not be publicly accessible",
		NodeTypes:      []string{"aws_rds_instance"},
		Hit: func(n ResourceNode, _ postureCtx) (bool, string) {
			return truthy(n.Attrs["public"]), "PubliclyAccessible = true"
		}},
	{Rule: "sec.rds-unencrypted", Pillar: "security", Severity: SevMedium, Effort: "high",
		Title:          "RDS storage is not encrypted",
		Recommendation: "Encryption cannot be switched on in place: it needs a snapshot copy and restore. Plan it with the owner.",
		NodeTypes:      []string{"aws_rds_instance"},
		Hit: func(n ResourceNode, _ postureCtx) (bool, string) {
			return falsey(n.Attrs["encrypted"]), "StorageEncrypted = false"
		}},
	{Rule: "rel.rds-no-backups", Pillar: "reliability", Severity: SevHigh, Effort: "low",
		Title:          "RDS instances have automated backups switched off",
		Recommendation: "Set a backup retention period (at least 7 days) unless the data is reproducible.",
		NodeTypes:      []string{"aws_rds_instance"},
		Hit: func(n ResourceNode, _ postureCtx) (bool, string) {
			v, ok := n.Attrs["backup_days"]
			return ok && v == "0", "backup retention period is 0"
		}},
	{Rule: "rel.rds-single-az", Pillar: "reliability", Severity: SevMedium, Effort: "medium",
		Title:          "RDS instances have no standby in another availability zone",
		Recommendation: "A single instance goes down with its zone. Multi-AZ or a replica in another zone removes that; the cost doubles for the instance, so decide per database.",
		Reference:      "Well-Architected: Reliability",
		NodeTypes:      []string{"aws_rds_instance"},
		Hit: func(n ResourceNode, ctx postureCtx) (bool, string) {
			if !falsey(n.Attrs["multi_az"]) || n.Attrs["status"] == "stopped" {
				return false, ""
			}
			if c := n.Attrs["cluster"]; c != "" && ctx.clusterMembers[c] > 1 {
				return false, "" // an Aurora cluster with more than one instance spreads over zones
			}
			return true, "Multi-AZ = false and no other instance in the cluster"
		}},
	{Rule: "rel.rds-no-deletion-protection", Pillar: "reliability", Severity: SevLow, Effort: "low",
		Title:          "RDS instances can be deleted without a second step",
		Recommendation: "Deletion protection costs nothing and stops an accidental delete from a console or a bad apply.",
		NodeTypes:      []string{"aws_rds_instance"},
		Hit: func(n ResourceNode, _ postureCtx) (bool, string) {
			return falsey(n.Attrs["deletion_protection"]), "DeletionProtection = false"
		}},
	{Rule: "sec.ebs-unencrypted", Pillar: "security", Severity: SevMedium, Effort: "medium",
		Title:          "EBS volumes are not encrypted",
		Recommendation: "Enable EBS encryption by default for the region so new volumes are covered; existing volumes need a snapshot copy.",
		NodeTypes:      []string{"aws_ebs_volume"},
		Hit: func(n ResourceNode, _ postureCtx) (bool, string) {
			return falsey(n.Attrs["encrypted"]), "Encrypted = false"
		}},
	{Rule: "sec.opensearch-public", Pillar: "security", Severity: SevHigh, Effort: "high",
		Title:          "OpenSearch domains have a public endpoint",
		Recommendation: "Move the domain into a VPC, or confirm that the access policy is strictly limited. A public endpoint is only as safe as its policy.",
		NodeTypes:      []string{"aws_opensearch_domain"},
		Hit: func(n ResourceNode, _ postureCtx) (bool, string) {
			return falsey(n.Attrs["in_vpc"]), "not in a VPC (public endpoint)"
		}},
	{Rule: "sec.opensearch-no-encryption-at-rest", Pillar: "security", Severity: SevMedium, Effort: "high",
		Title:          "OpenSearch domains do not encrypt data at rest",
		Recommendation: "Encryption at rest can be enabled on newer engine versions; older domains need a new domain and a reindex.",
		NodeTypes:      []string{"aws_opensearch_domain"},
		Hit: func(n ResourceNode, _ postureCtx) (bool, string) {
			return falsey(n.Attrs["encrypted_at_rest"]), "encryption at rest is off"
		}},
	{Rule: "sec.opensearch-no-node-to-node-encryption", Pillar: "security", Severity: SevLow, Effort: "high",
		Title:          "OpenSearch domains do not encrypt traffic between nodes",
		Recommendation: "Enable node-to-node encryption when the domain is next rebuilt or upgraded.",
		NodeTypes:      []string{"aws_opensearch_domain"},
		Hit: func(n ResourceNode, _ postureCtx) (bool, string) {
			return falsey(n.Attrs["node_to_node_encryption"]), "node-to-node encryption is off"
		}},
	{Rule: "sec.opensearch-https-not-enforced", Pillar: "security", Severity: SevMedium, Effort: "low",
		Title:          "OpenSearch domains accept plain HTTP",
		Recommendation: "Set EnforceHTTPS on the domain endpoint options.",
		NodeTypes:      []string{"aws_opensearch_domain"},
		Hit: func(n ResourceNode, _ postureCtx) (bool, string) {
			return falsey(n.Attrs["enforce_https"]), "EnforceHTTPS = false"
		}},
	{Rule: "rel.lambda-deprecated-runtime", Pillar: "reliability", Severity: SevMedium, Effort: "medium",
		Title:          "Lambda functions run on deprecated runtimes",
		Recommendation: "AWS stops patching and eventually blocks updates on deprecated runtimes. Move each function to a supported runtime; test first, behaviour can change between major versions.",
		Reference:      "AWS Lambda runtime deprecation policy",
		NodeTypes:      []string{"aws_lambda_function"},
		Hit: func(n ResourceNode, _ postureCtx) (bool, string) {
			rt := n.Attrs["runtime"]
			if since, ok := deprecatedRuntimes[rt]; ok {
				return true, fmt.Sprintf("runtime %s (deprecated since about %s)", rt, since)
			}
			return false, ""
		}},
	{Rule: "sec.s3-public-access-block-off", Pillar: "security", Severity: SevMedium, Effort: "low",
		Title:          "S3 buckets do not block public access",
		Recommendation: "Enable all four Block Public Access settings on every bucket that is not meant to be public, ideally account-wide.",
		NodeTypes:      []string{"aws_s3_bucket"},
		Hit: func(n ResourceNode, _ postureCtx) (bool, string) {
			return falsey(n.Attrs["public_access_block"]), "Block Public Access is not fully enabled"
		}},
	{Rule: "sec.s3-bucket-public", Pillar: "security", Severity: SevHigh, Effort: "medium",
		Title:          "S3 buckets are public through their policy",
		Recommendation: "Confirm the bucket is meant to serve the public (a website, a CDN origin). If not, remove the grant.",
		NodeTypes:      []string{"aws_s3_bucket"},
		Hit: func(n ResourceNode, _ postureCtx) (bool, string) {
			return truthy(n.Attrs["policy_public"]), "the bucket policy makes it public"
		}},
}

// postureFindings applies the rules and returns one grouped finding per rule.
func postureFindings(res *ScanResult) []Finding {
	ctx := postureCtx{clusterMembers: map[string]int{}}
	for _, n := range res.Nodes {
		if n.Type == "aws_rds_instance" && n.Attrs["cluster"] != "" {
			ctx.clusterMembers[n.Attrs["cluster"]]++
		}
	}
	var out []Finding
	for _, r := range postureRules {
		types := map[string]bool{}
		for _, t := range r.NodeTypes {
			types[t] = true
		}
		var hits []ResourceNode
		var why []string
		var cost float64
		for _, n := range res.Nodes {
			if !types[n.Type] {
				continue
			}
			if ok, w := r.Hit(n, ctx); ok {
				hits = append(hits, n)
				if len(why) == 0 {
					why = append(why, w)
				}
				cost += n.MonthlyCost
			}
		}
		if len(hits) == 0 {
			continue
		}
		sort.SliceStable(hits, func(i, j int) bool { return hits[i].MonthlyCost > hits[j].MonthlyCost })
		f := Finding{
			Pillar: Pillar(r.Pillar), Source: "own", Rule: r.Rule, Severity: r.Severity, Derived: true,
			Title:    fmt.Sprintf("%s (%d)", r.Title, len(hits)),
			Affected: len(hits), ResourceType: hits[0].Type, ResourceID: hits[0].ID, ResourceName: hits[0].Name, Region: hits[0].Region,
			Confidence: ConfHigh, Effort: r.Effort, Reference: r.Reference, Recommendation: r.Recommendation,
			Evidence:    append([]string{why[0] + " (read from the resource's configuration)"}, exampleNames(hits, 5)...),
			MonthlyCost: cost,
		}
		for i, h := range hits {
			if i == 40 {
				break
			}
			f.Resources = append(f.Resources, h.ID)
		}
		f.ID = FindingID(f.Source, f.Rule, "")
		out = append(out, f)
	}
	return out
}

func exampleNames(ns []ResourceNode, n int) []string {
	var names []string
	for i, x := range ns {
		if i == n {
			names = append(names, fmt.Sprintf("... and %d more", len(ns)-n))
			break
		}
		names = append(names, x.Name)
	}
	return []string{"e.g. " + strings.Join(names, ", ")}
}
