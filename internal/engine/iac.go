package engine

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// IaCRef is one resource that an infrastructure-as-code source claims to
// manage: an instance in a Terraform state file or a resource of a
// CloudFormation stack. Only identifiers and a short list of attributes are
// kept; state files hold secrets and nothing else from them is retained.
type IaCRef struct {
	Source  string            `json:"source"` // terraform | cloudformation
	Origin  string            `json:"origin"` // state file key/path or stack name
	Address string            `json:"address,omitempty"`
	Module  string            `json:"module,omitempty"`
	Type    string            `json:"type"` // terraform type or CloudFormation type
	ID      string            `json:"id"`
	ARN     string            `json:"arn,omitempty"`
	Region  string            `json:"region,omitempty"`
	Attrs   map[string]string `json:"attrs,omitempty"`
	Drift   string            `json:"drift,omitempty"` // CloudFormation stack drift status
}

// DriftItem is one attribute whose live value differs from the state.
type DriftItem struct {
	Attr  string `json:"attr"`
	State string `json:"state"`
	Live  string `json:"live"`
}

// IaCInfo is attached to a resource found in a state file or stack.
type IaCInfo struct {
	Source  string      `json:"source"`
	Origin  string      `json:"origin"`
	Address string      `json:"address,omitempty"`
	Module  string      `json:"module,omitempty"`
	Drift   []DriftItem `json:"drift,omitempty"`
	// DriftChecked is true when this resource's type has a drift comparison.
	DriftChecked bool `json:"drift_checked,omitempty"`
}

// IaCSummary says what was read and how much of the account it covers.
type IaCSummary struct {
	Sources      []string `json:"sources"`
	StateFiles   int      `json:"state_files"`
	Stacks       int      `json:"stacks"`
	Instances    int      `json:"instances"` // resources claimed by state/stacks, of types this tool inventories
	Matched      int      `json:"matched"`
	TagOnly      int      `json:"tag_only"`  // tagged as IaC, not found in what was read
	Unmanaged    int      `json:"unmanaged"` // no tag and not found
	NotInAWS     int      `json:"not_in_aws"`
	DriftChecked int      `json:"drift_checked"`
	DriftTypes   []string `json:"drift_types,omitempty"`
	DriftFound   int      `json:"drift_found"`
	Duplicates   int      `json:"duplicates"`
	Considered   int      `json:"considered"` // inventoried resources of types that state or stacks can describe
	// SupportedTypes are the node types that state and stacks are matched
	// against, so a viewer can tell "not found" from "cannot be compared".
	SupportedTypes []string `json:"supported_types,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

// iacTypes maps Terraform and CloudFormation resource types to the node type
// this tool uses. Only listed types take part: a join on an unknown type
// would be a guess.
var iacTypes = map[string]string{
	"aws_instance": "aws_instance", "AWS::EC2::Instance": "aws_instance",
	"aws_ebs_volume": "aws_ebs_volume", "AWS::EC2::Volume": "aws_ebs_volume",
	"aws_eip": "aws_eip", "AWS::EC2::EIP": "aws_eip",
	"aws_nat_gateway": "aws_nat_gateway", "AWS::EC2::NatGateway": "aws_nat_gateway",
	"aws_lb": "aws_lb", "aws_alb": "aws_lb", "AWS::ElasticLoadBalancingV2::LoadBalancer": "aws_lb",
	"aws_ecs_service": "aws_ecs_service", "AWS::ECS::Service": "aws_ecs_service",
	"aws_ecs_cluster": "aws_ecs_cluster", "AWS::ECS::Cluster": "aws_ecs_cluster",
	"aws_db_instance": "aws_rds_instance", "aws_rds_cluster_instance": "aws_rds_instance", "AWS::RDS::DBInstance": "aws_rds_instance",
	"aws_opensearch_domain": "aws_opensearch_domain", "aws_elasticsearch_domain": "aws_opensearch_domain",
	"AWS::OpenSearchService::Domain": "aws_opensearch_domain", "AWS::Elasticsearch::Domain": "aws_opensearch_domain",
	"aws_kinesis_stream": "aws_kinesis_stream", "AWS::Kinesis::Stream": "aws_kinesis_stream",
	"aws_cloudwatch_log_group": "aws_cloudwatch_log_group", "AWS::Logs::LogGroup": "aws_cloudwatch_log_group",
	"aws_s3_bucket": "aws_s3_bucket", "AWS::S3::Bucket": "aws_s3_bucket",
	"aws_lambda_function": "aws_lambda_function", "AWS::Lambda::Function": "aws_lambda_function",
	"aws_vpc_endpoint": "aws_vpc_endpoint", "AWS::EC2::VPCEndpoint": "aws_vpc_endpoint",
	"aws_redshift_cluster": "aws_redshift_cluster", "AWS::Redshift::Cluster": "aws_redshift_cluster",
	"aws_memorydb_cluster": "aws_memorydb_cluster", "AWS::MemoryDB::Cluster": "aws_memorydb_cluster",
	"aws_elasticache_cluster": "aws_elasticache_cluster", "AWS::ElastiCache::CacheCluster": "aws_elasticache_cluster",
	"aws_dynamodb_table": "aws_dynamodb_table", "AWS::DynamoDB::Table": "aws_dynamodb_table",
	"aws_sqs_queue": "aws_sqs_queue", "AWS::SQS::Queue": "aws_sqs_queue",
	"aws_kinesis_firehose_delivery_stream": "aws_firehose_stream", "AWS::KinesisFirehose::DeliveryStream": "aws_firehose_stream",
	"aws_cloudfront_distribution": "aws_cloudfront_distribution", "AWS::CloudFront::Distribution": "aws_cloudfront_distribution",
	"aws_ebs_snapshot": "aws_ebs_snapshot",
}

// IaCNodeType returns the node type for an IaC resource type, if known.
func IaCNodeType(t string) (string, bool) { v, ok := iacTypes[t]; return v, ok }

// IaCTypeCovered reports whether a node type can be matched at all.
func iacTypeCovered(nodeType string) bool {
	for _, v := range iacTypes {
		if v == nodeType {
			return true
		}
	}
	return false
}

// driftRule compares one state attribute with one live attribute.
// When is a live attribute that must have this value for the comparison to
// mean anything (a shard count says nothing about an on-demand stream).
type driftRule struct {
	NodeType, StateKey, LiveKey string
	WhenKey, WhenValue          string
}

var driftRules = []driftRule{
	{NodeType: "aws_instance", StateKey: "instance_type", LiveKey: "instance_type"},
	{NodeType: "aws_ebs_volume", StateKey: "size", LiveKey: "size_gb"},
	{NodeType: "aws_ebs_volume", StateKey: "type", LiveKey: "volume_type"},
	{NodeType: "aws_rds_instance", StateKey: "instance_class", LiveKey: "class"},
	{NodeType: "aws_rds_instance", StateKey: "multi_az", LiveKey: "multi_az"},
	{NodeType: "aws_lambda_function", StateKey: "memory_size", LiveKey: "memory_mb"},
	{NodeType: "aws_lambda_function", StateKey: "runtime", LiveKey: "runtime"},
	{NodeType: "aws_kinesis_stream", StateKey: "shard_count", LiveKey: "shards", WhenKey: "mode", WhenValue: "PROVISIONED"},
	{NodeType: "aws_opensearch_domain", StateKey: "engine_version", LiveKey: "engine_version"},
	{NodeType: "aws_opensearch_domain", StateKey: "cluster_config.instance_type", LiveKey: "instance_type"},
	{NodeType: "aws_opensearch_domain", StateKey: "cluster_config.instance_count", LiveKey: "instances"},
	{NodeType: "aws_elasticache_cluster", StateKey: "node_type", LiveKey: "node_type"},
	{NodeType: "aws_elasticache_cluster", StateKey: "num_cache_nodes", LiveKey: "nodes"},
	{NodeType: "aws_dynamodb_table", StateKey: "read_capacity", LiveKey: "rcu"},
	{NodeType: "aws_dynamodb_table", StateKey: "write_capacity", LiveKey: "wcu"},
}

// DriftAttributes lists the state attributes the tool keeps, per Terraform
// type family. Everything else in a state file is dropped on read.
func DriftAttributes() map[string]bool {
	m := map[string]bool{}
	for _, r := range driftRules {
		m[r.StateKey] = true
	}
	return m
}

// normalizeValue removes naming differences that are not differences: the
// OpenSearch Service kept the ".elasticsearch" suffix in older Terraform
// state while the API reports ".search".
func normalizeValue(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimSuffix(v, ".elasticsearch")
	return strings.TrimSuffix(v, ".search")
}

func sameValue(a, b string) bool {
	a, b = normalizeValue(a), normalizeValue(b)
	if a == b {
		return true
	}
	fa, ea := strconv.ParseFloat(a, 64)
	fb, eb := strconv.ParseFloat(b, 64)
	return ea == nil && eb == nil && fa == fb
}

// nodeKeys are the identifiers under which a state or stack may know a node.
func nodeKeys(n ResourceNode) []string {
	var ks []string
	add := func(s string) {
		if len(s) >= 3 {
			ks = append(ks, s)
		}
	}
	add(n.ID)
	add(n.Name)
	if i := strings.LastIndexAny(n.ID, "/:"); i >= 0 {
		add(n.ID[i+1:])
	}
	if strings.HasPrefix(n.ID, "arn:aws:s3:::") {
		add(strings.TrimPrefix(n.ID, "arn:aws:s3:::"))
	}
	return ks
}

// JoinIaC attaches state/stack information to resources and records what the
// comparison found. It is meant to run once per scan, with the sources that
// were actually read named in sources.
func JoinIaC(res *ScanResult, refs []IaCRef, sources []string, stateFiles, stacks int, notes []string) {
	sum := &IaCSummary{Sources: sources, StateFiles: stateFiles, Stacks: stacks, Notes: notes, SupportedTypes: supportedNodeTypes()}
	res.IaC = sum
	if len(sources) == 0 {
		return
	}

	// index references by every key they are known by
	type hit struct{ i int }
	idx := map[string][]int{}
	typed := make([]IaCRef, 0, len(refs))
	for _, r := range refs {
		nt, ok := IaCNodeType(r.Type)
		if !ok {
			continue
		}
		r.Type = nt
		typed = append(typed, r)
		for _, k := range []string{r.ID, r.ARN} {
			if len(k) >= 3 {
				idx[k] = append(idx[k], len(typed)-1)
			}
		}
	}
	sum.Instances = len(typed)

	regions := map[string]bool{}
	for _, r := range res.Regions {
		regions[r] = true
	}

	matchedRef := make([]bool, len(typed))
	byOrigin := map[string]map[string]bool{} // node id -> origins
	typeStats := map[string]int{}
	driftTypes := map[string]bool{}
	var tagOnly, unmanaged []ResourceNode
	driftByType := map[string][]ResourceNode{}

	for i := range res.Nodes {
		n := &res.Nodes[i]
		if !iacTypeCovered(n.Type) {
			continue
		}
		sum.Considered++
		var found []int
		seen := map[int]bool{}
		for _, k := range nodeKeys(*n) {
			for _, ri := range idx[k] {
				if typed[ri].Type == n.Type && !seen[ri] {
					seen[ri] = true
					found = append(found, ri)
				}
			}
		}
		if len(found) == 0 {
			// A tag can only be judged against the kind of source that was read:
			// a Terraform claim needs state files, a CloudFormation claim needs stacks.
			judged := (n.ManagedBy == "Terraform" && stateFiles > 0) || (n.ManagedBy == "CloudFormation" && stacks > 0)
			if n.ManagedBy != "" && !judged {
				continue
			}
			if n.ManagedBy != "" {
				sum.TagOnly++
				tagOnly = append(tagOnly, *n)
				n.Evidence = append(n.Evidence, fmt.Sprintf("tagged as managed by %s, but not found in the %d state file(s) and %d stack(s) that were read", n.ManagedBy, stateFiles, stacks))
			} else {
				sum.Unmanaged++
				unmanaged = append(unmanaged, *n)
			}
			continue
		}
		sum.Matched++
		for _, ri := range found {
			matchedRef[ri] = true
		}
		r := typed[found[0]]
		info := &IaCInfo{Source: r.Source, Origin: r.Origin, Address: r.Address, Module: r.Module}
		n.IaC = info // before any copy of the node is taken below
		for _, ri := range found {
			if byOrigin[n.ID] == nil {
				byOrigin[n.ID] = map[string]bool{}
			}
			byOrigin[n.ID][typed[ri].Origin] = true
		}
		// verified by state or stack: this is stronger than a tag
		tool := map[string]string{"terraform": "Terraform", "cloudformation": "CloudFormation"}[r.Source]
		if n.Status == StatusShadowIT {
			n.Status = StatusManaged
		}
		if tool != "" {
			n.ManagedBy = tool
		}
		// Confidence belongs to the verdict the resource already has. A waste
		// candidate keeps its own; only a resource whose verdict was "how it is
		// managed" gains the certainty of being found in code.
		if n.Status != StatusOrphanWaste {
			n.Confidence = ConfHigh
		}
		n.Evidence = append(n.Evidence, fmt.Sprintf("found in %s %s as %s", r.Source, r.Origin, r.Address))
		if n.Owner == "" {
			switch {
			case r.Module != "":
				n.Owner, n.OwnerSource = firstModule(r.Module), "terraform module"
			case r.Source == "terraform" && r.Origin != "":
				n.Owner, n.OwnerSource = path.Base(path.Dir(r.Origin)), "terraform state path"
			case r.Source == "cloudformation":
				n.Owner, n.OwnerSource = r.Origin, "cloudformation stack"
			}
		}
		if r.Source == "terraform" {
			for _, rule := range driftRules {
				if rule.NodeType != n.Type {
					continue
				}
				sv, ok := r.Attrs[rule.StateKey]
				if !ok || sv == "" {
					continue // the state does not say: nothing to compare
				}
				lv, ok := n.Attrs[rule.LiveKey]
				if !ok {
					continue
				}
				if rule.WhenKey != "" && n.Attrs[rule.WhenKey] != rule.WhenValue {
					continue
				}
				info.DriftChecked = true
				if !sameValue(sv, lv) {
					info.Drift = append(info.Drift, DriftItem{Attr: rule.StateKey, State: sv, Live: lv})
				}
			}
			if info.DriftChecked {
				sum.DriftChecked++
				typeStats[n.Type]++
				driftTypes[n.Type] = true
			}
			if len(info.Drift) > 0 {
				sum.DriftFound++
				driftByType[n.Type] = append(driftByType[n.Type], *n)
			}
		}
	}

	for t := range driftTypes {
		sum.DriftTypes = append(sum.DriftTypes, t)
	}
	sort.Strings(sum.DriftTypes)

	var fs []Finding
	add := func(f Finding) {
		if f.ID == "" {
			f.ID = FindingID(f.Source, f.Rule, f.ResourceType+"|"+f.Title)
		}
		fs = append(fs, f)
	}
	names := func(ns []ResourceNode, n int) ([]string, []string) {
		var ids, label []string
		for i, x := range ns {
			if i == n {
				break
			}
			ids = append(ids, x.ID)
			label = append(label, x.Name)
		}
		return ids, label
	}

	if len(tagOnly) > 0 {
		ids, label := names(tagOnly, 40)
		add(Finding{
			Pillar: PillarIaC, Source: "own", Rule: "iac.tag-not-in-state", Severity: SevMedium,
			Title:    fmt.Sprintf("%d resources are tagged as managed by IaC but are in none of the state files or stacks that were read", len(tagOnly)),
			Affected: len(tagOnly), Resources: ids, ResourceID: ids[0], ResourceName: label[0], Confidence: ConfMedium, Effort: "medium",
			Evidence: []string{
				fmt.Sprintf("read %d state file(s) and %d stack(s); the resource may live in a state that was not provided", stateFiles, stacks),
				"examples: " + strings.Join(firstStrings(label, 5), ", "),
			},
			Recommendation: "Locate the state that holds each resource, or remove the tag. A tag that the state does not confirm gives false comfort.",
		})
	}
	if sum.Duplicates = countDuplicates(byOrigin); sum.Duplicates > 0 {
		var ids []string
		for id, o := range byOrigin {
			if len(o) > 1 {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		add(Finding{
			Pillar: PillarIaC, Source: "own", Rule: "iac.managed-twice", Severity: SevHigh,
			Title:    fmt.Sprintf("%d resources appear in more than one state file or stack", sum.Duplicates),
			Affected: sum.Duplicates, Resources: firstStrings(ids, 40), ResourceID: ids[0], Confidence: ConfHigh, Effort: "high",
			Evidence:       append([]string{"two sources managing one resource will fight over it on the next apply"}, duplicateExamples(byOrigin, ids, 4)...),
			Recommendation: "Decide which state owns each resource and remove it from the other (terraform state rm), preferably with the owner at hand.",
		})
	}
	if orphans := stateOrphans(typed, matchedRef, res, regions); len(orphans) > 0 {
		sum.NotInAWS = len(orphans)
		var ids []string
		for _, r := range orphans {
			ids = append(ids, r.ID)
		}
		add(Finding{
			Pillar: PillarIaC, Source: "own", Rule: "iac.state-without-resource", Severity: SevLow,
			Title:    fmt.Sprintf("%d state entries point at resources that were not found in the account", len(orphans)),
			Affected: len(orphans), Resources: firstStrings(ids, 40), ResourceID: ids[0], Confidence: ConfMedium, Effort: "low",
			Evidence: []string{
				"only types this tool inventories, in regions that were scanned, are compared",
				"the resource may have been deleted outside Terraform, or live in an account or region not scanned",
			},
			Recommendation: "Run a plan in the owning workspace; a resource that really is gone should be removed from the state or recreated deliberately.",
		})
	}
	for _, t := range sum.DriftTypes {
		ns := driftByType[t]
		if len(ns) == 0 {
			continue
		}
		ids, label := names(ns, 40)
		var ex []string
		for _, n := range ns[:min(3, len(ns))] {
			for _, d := range n.IaC.Drift {
				ex = append(ex, fmt.Sprintf("%s: %s state=%s live=%s", n.Name, d.Attr, d.State, d.Live))
			}
		}
		add(Finding{
			Pillar: PillarIaC, Source: "own", Rule: "iac.drift." + strings.TrimPrefix(t, "aws_"), Severity: SevMedium,
			Title:    fmt.Sprintf("%d %s differ from their Terraform state", len(ns), strings.ReplaceAll(strings.TrimPrefix(t, "aws_"), "_", " ")),
			Affected: len(ns), Resources: ids, ResourceID: ids[0], ResourceName: label[0], ResourceType: t, Confidence: ConfMedium, Effort: "medium",
			Evidence:       append([]string{"compared attributes: " + driftKeys(t)}, ex...),
			Recommendation: "Either the change was made by hand and should be brought back into code, or the state is stale. Check who changed it before the next apply overwrites it.",
		})
	}
	// stack-level drift
	seenStack := map[string]bool{}
	var drifted []string
	for _, r := range refs {
		if r.Source == "cloudformation" && r.Drift == "DRIFTED" && !seenStack[r.Origin] {
			seenStack[r.Origin] = true
			drifted = append(drifted, r.Origin)
		}
	}
	if len(drifted) > 0 {
		sort.Strings(drifted)
		add(Finding{
			Pillar: PillarIaC, Source: "own", Rule: "iac.cloudformation-drift", Severity: SevMedium,
			Title:    fmt.Sprintf("%d CloudFormation stack(s) report drift", len(drifted)),
			Affected: len(drifted), Resources: drifted, ResourceID: drifted[0], Confidence: ConfHigh, Effort: "medium",
			Evidence:       []string{"status reported by CloudFormation (the last drift detection that was run)"},
			Recommendation: "Review the drift detail in CloudFormation before the next stack update replaces the live settings.",
		})
	}
	_ = unmanaged
	res.Findings = append(res.Findings, fs...)
}

func firstModule(m string) string {
	// module.checkout.module.db -> checkout
	parts := strings.Split(m, ".")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "module" {
			return parts[i+1]
		}
	}
	return m
}

func firstStrings(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func countDuplicates(byOrigin map[string]map[string]bool) int {
	n := 0
	for _, o := range byOrigin {
		if len(o) > 1 {
			n++
		}
	}
	return n
}

func driftKeys(nodeType string) string {
	var ks []string
	for _, r := range driftRules {
		if r.NodeType == nodeType {
			ks = append(ks, r.StateKey)
		}
	}
	return strings.Join(ks, ", ")
}

// stateOrphans are claims by a state or stack, of a type this tool
// inventories, for which no live resource exists in a scanned region.
func stateOrphans(refs []IaCRef, matched []bool, res *ScanResult, regions map[string]bool) []IaCRef {
	var out []IaCRef
	for i, r := range refs {
		if matched[i] {
			continue
		}
		// only types this tool enumerates completely can be called missing:
		// small log groups are rolled up and snapshots are listed only when
		// orphaned, so their absence from the inventory means nothing
		if nt := r.Type; nt == "aws_cloudwatch_log_group" || nt == "aws_ebs_snapshot" {
			continue
		}
		// a reference without a region cannot be placed: leave it out
		reg := r.Region
		if reg == "" && strings.HasPrefix(r.ARN, "arn:") {
			if p := strings.Split(r.ARN, ":"); len(p) > 3 {
				reg = p[3]
			}
		}
		if reg == "" || !regions[reg] {
			continue
		}
		if r.Source == "cloudformation" && r.ID == "" {
			continue
		}
		out = append(out, r)
	}
	return out
}

func duplicateExamples(byOrigin map[string]map[string]bool, ids []string, n int) []string {
	var out []string
	for _, id := range firstStrings(ids, n) {
		var o []string
		for k := range byOrigin[id] {
			o = append(o, k)
		}
		sort.Strings(o)
		out = append(out, fmt.Sprintf("%s: %s", lastSegmentOf(id), strings.Join(o, " and ")))
	}
	return out
}

func lastSegmentOf(id string) string {
	if i := strings.LastIndexAny(id, "/:"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

func supportedNodeTypes() []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range iacTypes {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
