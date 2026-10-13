// Package cleanup turns waste candidates into reviewable shell scripts. It
// only generates text: nothing here calls AWS or runs a command. The scripts
// are built so that running one does nothing destructive by default.
package cleanup

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	awsDiscovery "infralens/internal/aws"
	"infralens/internal/engine"
)

// File is one generated file.
type File struct {
	Name    string
	Content string
}

// Options select what is generated.
type Options struct {
	// MinConfidence: "high", "medium" (default) or "low".
	MinConfidence engine.Confidence
	Now           time.Time
}

func rank(c engine.Confidence) int {
	switch c {
	case engine.ConfHigh:
		return 0
	case engine.ConfMedium:
		return 1
	}
	return 2
}

// shq quotes s for POSIX sh as a single-quoted word. Resource names and IDs
// come from the audited account and are never trusted.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

var control = regexp.MustCompile(`[\x00-\x1f\x7f]+`)

// comment makes s safe to put after '# ': no newline can end the comment line
// and start a command.
func comment(s string) string { return control.ReplaceAllString(s, " ") }

var fileSafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func fileName(i int, n engine.ResourceNode) string {
	base := n.Name
	if base == "" || base == n.ID {
		base = n.ID
	}
	base = fileSafe.ReplaceAllString(base, "_")
	if len(base) > 48 {
		base = base[:48]
	}
	t := strings.TrimPrefix(n.Type, "aws_")
	return fmt.Sprintf("%02d-%s-%s.sh", i, fileSafe.ReplaceAllString(t, "_"), strings.Trim(base, "._-"))
}

// Generate builds the pack: one script per candidate, an index and a README.
// Acknowledged candidates are skipped: the owner has said they are expected.
func Generate(res engine.ScanResult, o Options) []File {
	if o.MinConfidence == "" {
		o.MinConfidence = engine.ConfMedium
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	var picked []engine.ResourceNode
	skippedLow, skippedAck := 0, 0
	for _, n := range res.Nodes {
		if n.Status != engine.StatusOrphanWaste {
			continue
		}
		if n.Ack != nil {
			skippedAck++
			continue
		}
		if rank(n.Confidence) > rank(o.MinConfidence) {
			skippedLow++
			continue
		}
		picked = append(picked, n)
	}
	sort.SliceStable(picked, func(i, j int) bool {
		if rank(picked[i].Confidence) != rank(picked[j].Confidence) {
			return rank(picked[i].Confidence) < rank(picked[j].Confidence)
		}
		return picked[i].MonthlyCost > picked[j].MonthlyCost
	})

	var files []File
	var idx strings.Builder
	idx.WriteString("script,resource,type,region,est_usd_month,confidence,dependents\n")
	for i, n := range picked {
		name := fileName(i+1, n)
		files = append(files, File{name, script(res, n, o)})
		deps := 0
		if n.Blast != nil {
			for _, d := range n.Blast.Dependents {
				if d.Kind != "backup" {
					deps++
				}
			}
		}
		fmt.Fprintf(&idx, "%s,%s,%s,%s,%.2f,%s,%d\n", name, csvCell(n.Name), n.Type, n.Region, n.MonthlyCost, n.Confidence, deps)
	}
	files = append(files, File{"index.csv", idx.String()})
	files = append(files, File{"README.md", readme(res, picked, skippedLow, skippedAck, o)})
	return files
}

func csvCell(s string) string {
	s = control.ReplaceAllString(s, " ")
	if s != "" && strings.ContainsAny(s[:1], "=+-@") {
		s = "'" + s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func readme(res engine.ScanResult, picked []engine.ResourceNode, skippedLow, skippedAck int, o Options) string {
	var b strings.Builder
	b.WriteString("# Cleanup pack\n\n")
	fmt.Fprintf(&b, "Generated %s from a scan of account %s. **Nothing in this directory has been run.**\n\n",
		o.Now.Format("2006-01-02"), comment(res.Account))
	b.WriteString("Each script handles one candidate and is safe to run as it is: by default it prints what it *would* do.\n\n")
	b.WriteString("## How a script works\n\n")
	b.WriteString("1. Read it. Confirm with the owner that the resource is not needed (the header lists the evidence, the dependents found and what the check cannot see).\n")
	b.WriteString("2. `AWS_PROFILE=<profile> bash NN-....sh` : **dry run**, prints the commands, changes nothing. It checks that you are in the right account first.\n")
	b.WriteString("3. `DRY_RUN=0 AWS_PROFILE=<profile> bash NN-....sh` : **quarantine**: takes a backup and tags the resource (and, where it is reversible, stops it). Wait a billing cycle and watch for complaints.\n")
	b.WriteString("4. `DRY_RUN=0 STAGE=delete CONFIRM=<resource id> AWS_PROFILE=<profile> bash NN-....sh` : **removal**. Needs the exact resource id as confirmation.\n\n")
	b.WriteString("Each script ends with a rollback function that says how to get the resource back, and where it cannot be restored it says so.\n\n")
	fmt.Fprintf(&b, "## Included: %d candidate(s), confidence %s or better\n\n", len(picked), o.MinConfidence)
	var total float64
	for _, n := range picked {
		total += n.MonthlyCost
	}
	fmt.Fprintf(&b, "Estimated list-price cost of the included resources: $%.2f/month. This is not a promise of savings.\n\n", total)
	if skippedLow > 0 {
		fmt.Fprintf(&b, "- %d lower-confidence candidate(s) not included (use `--min-confidence low`).\n", skippedLow)
	}
	if skippedAck > 0 {
		fmt.Fprintf(&b, "- %d candidate(s) acknowledged by the owner as expected were skipped.\n", skippedAck)
	}
	return b.String()
}

// script renders one candidate.
func script(res engine.ScanResult, n engine.ResourceNode, o Options) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("#!/usr/bin/env bash")
	w("# InfraLens cleanup script. REVIEW BEFORE RUNNING. Generated by a tool, not an instruction to delete.")
	w("#")
	w("# resource   : %s (%s)", comment(n.Name), comment(n.ID))
	w("# type       : %s    region: %s", comment(n.Type), comment(n.Region))
	w("# finding    : %s", comment(n.WasteReason))
	w("# confidence : %s    est. cost: $%.2f/month (list price)", n.Confidence, n.MonthlyCost)
	for _, e := range n.Evidence {
		if strings.HasPrefix(e, "tag ") || strings.HasPrefix(e, "no tags") || strings.HasPrefix(e, "no IaC") {
			continue
		}
		w("# evidence   : %s", comment(e))
	}
	if n.Blast != nil {
		if len(n.Blast.Checked) > 0 {
			w("# looked at  : %s", comment(strings.Join(n.Blast.Checked, ", ")))
		}
		for _, d := range n.Blast.Dependents {
			w("# DEPENDENT  : %s %s (%s)", comment(d.Kind), comment(d.Name), comment(d.Detail))
		}
		if len(n.Blast.Unchecked) > 0 {
			w("# NOT LOOKED AT (no permission): %s", comment(strings.Join(n.Blast.Unchecked, ", ")))
		}
	}
	for _, c := range awsDiscovery.Caveats(n.Type) {
		w("# cannot see : %s", comment(c))
	}
	w("")
	w("set -euo pipefail")
	w("export AWS_PAGER=''")
	w("")
	w(`[ -n "${AWS_PROFILE:-}" ] || { echo "set AWS_PROFILE to the profile for this account" >&2; exit 2; }`)
	w("ACCOUNT=%s", shq(res.Account))
	w("REGION=%s", shq(n.Region))
	w("RESOURCE=%s", shq(n.ID))
	w("TODAY=$(date -u +%%F)")
	w(`DRY_RUN="${DRY_RUN:-1}"      # 1 = print only (default)`)
	w(`STAGE="${STAGE:-quarantine}" # quarantine | delete`)
	w(`CONFIRM="${CONFIRM:-}"       # must equal the resource id for STAGE=delete`)
	w("")
	w(`run() { echo "+ $*" >&2; if [ "$DRY_RUN" = "0" ]; then "$@"; fi; }`)
	w(`save() { f="$1"; shift; echo "+ $* > $f" >&2; if [ "$DRY_RUN" = "0" ]; then "$@" > "$f"; fi; }`)
	w(`destructive() {`)
	w(`  if [ "$STAGE" != "delete" ]; then echo "- (stage is $STAGE, not delete) skipped: $*" >&2; return 0; fi`)
	w(`  if [ "$DRY_RUN" != "0" ]; then echo "+ (dry run) $*" >&2; return 0; fi`)
	w(`  if [ "$CONFIRM" != "$RESOURCE" ]; then echo "refusing: set CONFIRM to the exact resource id" >&2; exit 3; fi`)
	w(`  echo "+ $*" >&2; "$@"`)
	w(`}`)
	w("")
	w("# 0. right account?")
	w(`[ "$(aws sts get-caller-identity --query Account --output text)" = "$ACCOUNT" ] || { echo "wrong account" >&2; exit 2; }`)
	w("")
	body(&b, n)
	return b.String()
}

func body(b *strings.Builder, n engine.ResourceNode) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format+"\n", a...) }
	tagKV := "Key=infralens:quarantine,Value=$TODAY"

	switch n.Type {
	case "aws_ebs_volume":
		az := shq(n.Attrs["az"])
		if n.Attrs["az"] == "" {
			az = "'<availability-zone>'"
		}
		vt := n.Attrs["volume_type"]
		if vt == "" {
			vt = "gp3"
		}
		w("# 1. still unattached?")
		w(`[ "$(aws ec2 describe-volumes --region "$REGION" --volume-ids "$RESOURCE" --query 'Volumes[0].State' --output text)" = "available" ] || { echo "volume is attached now; stop" >&2; exit 4; }`)
		w("")
		w("# 2. backup: the way back")
		w(`SNAP=$(run aws ec2 create-snapshot --region "$REGION" --volume-id "$RESOURCE" --description "infralens pre-delete $TODAY" --query SnapshotId --output text || true)`)
		w(`[ -z "${SNAP:-}" ] || run aws ec2 wait snapshot-completed --region "$REGION" --snapshot-ids "$SNAP"`)
		w("")
		w("# 3. quarantine mark")
		w(`run aws ec2 create-tags --region "$REGION" --resources "$RESOURCE" --tags %s`, tagKV)
		w("")
		w("# 4. removal (STAGE=delete, DRY_RUN=0, CONFIRM=<id>)")
		w(`destructive aws ec2 delete-volume --region "$REGION" --volume-id "$RESOURCE"`)
		w("")
		w("rollback() {")
		w("  # recreate the volume from the snapshot taken above (or the newest snapshot of this volume)")
		w(`  echo "aws ec2 create-volume --region \"$REGION\" --availability-zone %s --volume-type %s --snapshot-id <snapshot-id>"`, az, shq(vt))
		w("}")

	case "aws_eip":
		w("# 1. still unassociated?")
		w(`[ "$(aws ec2 describe-addresses --region "$REGION" --allocation-ids "$RESOURCE" --query 'Addresses[0].AssociationId' --output text)" = "None" ] || { echo "address is associated now; stop" >&2; exit 4; }`)
		w("")
		w("# 2. quarantine mark (there is no backup of an address)")
		w(`run aws ec2 create-tags --region "$REGION" --resources "$RESOURCE" --tags %s`, tagKV)
		w("")
		w("# 3. removal. The public IP cannot be re-acquired once released; check that nobody whitelisted it.")
		w(`destructive aws ec2 release-address --region "$REGION" --allocation-id "$RESOURCE"`)
		w("")
		w("rollback() {")
		w(`  echo "A released Elastic IP cannot be recovered. A new address can be allocated, but it will be a different IP."`)
		w("}")

	case "aws_nat_gateway":
		w("# 1. any route still going through it?")
		w(`ROUTES=$(aws ec2 describe-route-tables --region "$REGION" --filters "Name=route.nat-gateway-id,Values=$RESOURCE" --query 'RouteTables[].RouteTableId' --output text)`)
		w(`[ -z "$ROUTES" ] || { echo "route tables still use this gateway: $ROUTES" >&2; exit 4; }`)
		w("")
		w("# 2. backup: keep its definition")
		w(`save "nat-$RESOURCE.json" aws ec2 describe-nat-gateways --region "$REGION" --nat-gateway-ids "$RESOURCE" || true`)
		w("")
		w("# 3. quarantine mark")
		w(`run aws ec2 create-tags --region "$REGION" --resources "$RESOURCE" --tags %s`, tagKV)
		w("")
		w("# 4. removal")
		w(`destructive aws ec2 delete-nat-gateway --region "$REGION" --nat-gateway-id "$RESOURCE"`)
		w("")
		w("rollback() {")
		w(`  echo "recreate with: aws ec2 create-nat-gateway --region \"$REGION\" --subnet-id <subnet from nat-$RESOURCE.json> --allocation-id <new EIP>; then restore the routes."`)
		w("}")

	case "aws_lb":
		w("# 1. backup: balancer, listeners, rules, target groups, tags")
		w(`run mkdir -p "backup-lb"`)
		w(`save "backup-lb/lb.json" aws elbv2 describe-load-balancers --region "$REGION" --load-balancer-arns "$RESOURCE" || true`)
		w(`save "backup-lb/listeners.json" aws elbv2 describe-listeners --region "$REGION" --load-balancer-arn "$RESOURCE" || true`)
		w(`save "backup-lb/target-groups.json" aws elbv2 describe-target-groups --region "$REGION" --load-balancer-arn "$RESOURCE" || true`)
		w(`save "backup-lb/tags.json" aws elbv2 describe-tags --region "$REGION" --resource-arns "$RESOURCE" || true`)
		w("")
		w("# 2. quarantine mark")
		w(`run aws elbv2 add-tags --region "$REGION" --resource-arns "$RESOURCE" --tags "Key=infralens:quarantine,Value=$TODAY"`)
		w("")
		w("# 3. before removal check DNS and CloudFront yourself if the header lists no 'looked at' for them")
		w(`destructive aws elbv2 delete-load-balancer --region "$REGION" --load-balancer-arn "$RESOURCE"`)
		w("")
		w("rollback() {")
		w(`  echo "recreate from backup-lb/*.json (balancer, listeners, rules); DNS records may need to be re-pointed."`)
		w("}")

	case "aws_rds_instance":
		cluster := n.Attrs["cluster"]
		w("# 1. still idle? (look at DatabaseConnections yourself before the stage that stops it)")
		if cluster != "" {
			w("# This instance belongs to cluster %s. Stopping/deleting acts on the cluster, not on one instance.", comment(cluster))
			cq := shq(cluster)
			w("CLUSTER=%s", cq)
			w("# 2. backup")
			w(`run aws rds create-db-cluster-snapshot --region "$REGION" --db-cluster-identifier "$CLUSTER" --db-cluster-snapshot-identifier "infralens-$CLUSTER-$TODAY"`)
			w("# 3. quarantine mark and a reversible stop (a stopped cluster restarts by itself after 7 days)")
			w(`run aws rds add-tags-to-resource --region "$REGION" --resource-name "$(aws rds describe-db-clusters --region "$REGION" --db-cluster-identifier "$CLUSTER" --query 'DBClusters[0].DBClusterArn' --output text)" --tags %s`, "Key=infralens:quarantine,Value=$TODAY")
			w(`run aws rds stop-db-cluster --region "$REGION" --db-cluster-identifier "$CLUSTER"`)
			w("# 4. removal of the whole cluster (all instances in it)")
			w(`destructive aws rds delete-db-cluster --region "$REGION" --db-cluster-identifier "$CLUSTER" --final-db-snapshot-identifier "infralens-final-$CLUSTER-$TODAY"`)
		} else {
			w("# 2. backup")
			w(`run aws rds create-db-snapshot --region "$REGION" --db-instance-identifier "$RESOURCE" --db-snapshot-identifier "infralens-$RESOURCE-$TODAY"`)
			w("# 3. reversible stop (restarts by itself after 7 days)")
			w(`run aws rds stop-db-instance --region "$REGION" --db-instance-identifier "$RESOURCE"`)
			w("# 4. removal")
			w(`destructive aws rds delete-db-instance --region "$REGION" --db-instance-identifier "$RESOURCE" --final-db-snapshot-identifier "infralens-final-$RESOURCE-$TODAY"`)
		}
		w("")
		w("rollback() {")
		w(`  echo "start again: aws rds start-db-%s ...; after deletion restore from the infralens-* snapshot taken above."`, map[bool]string{true: "cluster", false: "instance"}[cluster != ""])
		w("}")

	case "aws_kinesis_stream":
		w("# 1. backup: keep the stream definition (the data itself is not recoverable)")
		w(`save "stream.json" aws kinesis describe-stream-summary --region "$REGION" --stream-name %s || true`, shq(lastPart(n.ID)))
		w("")
		w("# 2. quarantine mark")
		w(`run aws kinesis add-tags-to-stream --region "$REGION" --stream-name %s --tags "infralens:quarantine=$TODAY"`, shq(lastPart(n.ID)))
		w("")
		w("# 3. removal. Data in the stream is lost; check consumers and producers first.")
		w(`destructive aws kinesis delete-stream --region "$REGION" --stream-name %s`, shq(lastPart(n.ID)))
		w("")
		w("rollback() {")
		w(`  echo "recreate the stream with the mode and shard count from stream.json; its data cannot be restored."`)
		w("}")

	case "aws_ebs_snapshot":
		w("# 1. quarantine mark")
		w(`run aws ec2 create-tags --region "$REGION" --resources "$RESOURCE" --tags %s`, tagKV)
		w("")
		w("# 2. removal. A snapshot cannot be restored once deleted.")
		w(`destructive aws ec2 delete-snapshot --region "$REGION" --snapshot-id "$RESOURCE"`)
		w("")
		w("rollback() {")
		w(`  echo "a deleted snapshot cannot be recovered"`)
		w("}")

	case "aws_cloudwatch_log_group":
		name := shq(n.Name)
		w("# Logs are not deleted by this script. The reversible, cheaper step is a retention policy.")
		w(`run aws logs put-retention-policy --region "$REGION" --log-group-name %s --retention-in-days 90`, name)
		w("")
		w("rollback() {")
		w(`  echo "aws logs delete-retention-policy --region \"$REGION\" --log-group-name %s   # back to never expire"`, name)
		w("}")

	default:
		w("# No automated removal is generated for %s: it needs a manual procedure.", comment(n.Type))
		w(`echo "no automated procedure for %s; review the header and handle manually" >&2`, comment(n.Type))
		w("")
		w("rollback() { :; }")
	}
}

func lastPart(arn string) string {
	if i := strings.LastIndexAny(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}
