// Package demo builds a synthetic scan of a made-up company. It exists so the
// product can be shown, screenshotted and tested without any real account:
// every name, number and identifier here is invented.
package demo

import (
	"fmt"
	"time"

	awsDiscovery "infralens/internal/aws"
	"infralens/internal/engine"
)

const Account = "123456789012"

// Scan returns a complete, finalised synthetic scan taken at `at`.
func Scan(at time.Time) engine.ScanResult {
	r := engine.ScanResult{
		Timestamp: at, Profile: "northwind-prod", Account: Account,
		Regions:        []string{"eu-west-1", "eu-central-1"},
		Checks:         []string{"coverage", "dynamodb", "ebs", "ec2", "ecs", "eip", "elb", "kinesis", "lambda", "logs", "nat", "opensearch", "rds", "reservations", "s3"},
		IdleWindowDays: 14,
	}
	tf := map[string]string{"terraform": "true", "Environment": "prod"}
	add := func(n engine.ResourceNode) { r.Nodes = append(r.Nodes, n) }
	edge := func(a, b, l string) { r.Edges = append(r.Edges, engine.Edge{Source: a, Target: b, Label: l}) }
	arn := func(svc, region, rest string) string {
		return fmt.Sprintf("arn:aws:%s:%s:%s:%s", svc, region, Account, rest)
	}

	// network and edge
	vpc := "vpc-0a1b2c3d4e5f60718"
	lb := arn("elasticloadbalancing", "eu-west-1", "loadbalancer/app/storefront/50dc6c495c0c9188")
	add(engine.ResourceNode{ID: lb, Name: "storefront", Type: "aws_lb", Group: "STOREFRONT", Region: "eu-west-1", VPCID: vpc,
		Status: engine.StatusManaged, ManagedBy: "Terraform", Confidence: engine.ConfHigh, MonthlyCost: 16.43, CostSource: engine.CostEstimated, Tags: tf})
	for i, nm := range []string{"internal-api", "legacy-redirect", "campaign-2022"} {
		w := engine.ResourceNode{ID: arn("elasticloadbalancing", "eu-west-1", "loadbalancer/app/"+nm+"/aa00bb11cc22dd3"+fmt.Sprint(i)),
			Name: nm, Type: "aws_lb", Group: "EDGE", Region: "eu-west-1", VPCID: vpc, Status: engine.StatusOrphanWaste, ManagedBy: "Terraform",
			Confidence: engine.ConfHigh, MonthlyCost: 16.43, CostSource: engine.CostEstimated, Tags: tf,
			WasteReason: "Load balancer without targets",
			Evidence:    []string{"no target groups; listeners only return fixed responses or redirects (placeholder/redirector?); no requests in 14d"},
			Blast:       &engine.BlastRadius{Checked: []string{"Route53 records", "CloudFront origins"}}}
		if nm == "legacy-redirect" {
			w.Confidence = engine.ConfMedium
			w.Evidence = append(w.Evidence, "1 dependent(s) found: dns old.northwind.example")
			w.Blast.Dependents = []engine.Dependent{{Kind: "dns", Name: "old.northwind.example", Detail: "alias A in zone northwind.example"}}
		}
		add(w)
	}
	for i, az := range []string{"a", "b"} {
		add(engine.ResourceNode{ID: fmt.Sprintf("nat-0%d9f8e7d6c5b4a3921", i), Name: "nat-" + az, Type: "aws_nat_gateway", Group: "NETWORK",
			Region: "eu-west-1", VPCID: vpc, Status: engine.StatusManaged, ManagedBy: "Terraform", Confidence: engine.ConfHigh,
			MonthlyCost: 32.85 + 190*float64(i+1), CostSource: engine.CostEstimated, Tags: tf,
			Evidence: []string{fmt.Sprintf("data processing: %d GB/month at $0.045/GB", 4200+i*900), "45000 MiB sent in 14d"}})
	}

	// compute
	for _, c := range []struct {
		name     string
		svcs     int
		cpu, mem int
	}{
		{"checkout", 14, 1024, 2048}, {"catalog", 22, 512, 1024}, {"search", 9, 2048, 8192}, {"batch", 11, 4096, 16384},
	} {
		cl := arn("ecs", "eu-west-1", "cluster/"+c.name)
		add(engine.ResourceNode{ID: cl, Name: c.name, Type: "aws_ecs_cluster", Group: "COMPUTE", Region: "eu-west-1",
			Status: engine.StatusManaged, ManagedBy: "Terraform", Confidence: engine.ConfHigh, CostSource: engine.CostNotAvailable, Tags: tf})
		for i := 0; i < c.svcs; i++ {
			id := arn("ecs", "eu-west-1", fmt.Sprintf("service/%s/%s-svc-%02d", c.name, c.name, i))
			cost := engine.FargateMonthlyCost(c.cpu, c.mem, float64(1+i%3))
			add(engine.ResourceNode{ID: id, Name: fmt.Sprintf("%s-svc-%02d", c.name, i), Type: "aws_ecs_service", Group: "COMPUTE",
				Region: "eu-west-1", VPCID: vpc, Status: engine.StatusManaged, ManagedBy: "Terraform", Confidence: engine.ConfHigh,
				MonthlyCost: cost, CostSource: engine.CostEstimated, Tags: tf,
				Attrs: map[string]string{"cluster": c.name, "launch_type": "FARGATE"}})
			edge(cl, id, "contains")
			if c.name == "checkout" {
				edge(lb, id, "routes to")
			}
		}
	}
	add(engine.ResourceNode{ID: "i-0123456789abcdef0", Name: "jump-host", Type: "aws_instance", Group: "COMPUTE", Region: "eu-west-1", VPCID: vpc,
		Status: engine.StatusShadowIT, Confidence: engine.ConfMedium, MonthlyCost: 30.4, CostSource: engine.CostEstimated,
		Evidence: []string{"no tags at all"}, Attrs: map[string]string{"instance_type": "t3.large", "state": "running"}})
	for _, f := range []struct {
		n   string
		mem int
		inv float64
	}{{"order-events", 512, 9e6}, {"image-resize", 1769, 3e6}, {"nightly-export", 1024, 30}} {
		add(engine.ResourceNode{ID: arn("lambda", "eu-west-1", "function:"+f.n), Name: f.n, Type: "aws_lambda_function", Group: "COMPUTE",
			Region: "eu-west-1", Status: engine.StatusManaged, ManagedBy: "Terraform", Confidence: engine.ConfHigh,
			MonthlyCost: engine.LambdaMonthlyCost(f.inv/2.14, f.inv/2.14*180, float64(f.mem), true, 14), CostSource: engine.CostEstimated, Tags: tf})
	}

	// data
	for _, d := range []struct {
		id, class string
		waste     bool
	}{{"orders-1", "db.r6g.large", false}, {"orders-2", "db.r6g.large", false}, {"reporting-1", "db.t4g.large", true}} {
		n := engine.ResourceNode{ID: d.id, Name: d.id, Type: "aws_rds_instance", Group: "DATABASE", Region: "eu-west-1", VPCID: vpc,
			Status: engine.StatusManaged, ManagedBy: "Terraform", Confidence: engine.ConfHigh, CostSource: engine.CostEstimated, Tags: tf,
			Attrs: map[string]string{"class": d.class, "engine": "aurora-postgresql", "cluster": d.id[:len(d.id)-2]}}
		n.MonthlyCost, _ = engine.EstimateRDSCost(d.class, 100, false, "aurora")
		if d.waste {
			n.Status, n.WasteReason = engine.StatusOrphanWaste, "Database without connections"
			n.Evidence = []string{"0 connections in 14d"}
			n.Blast = &engine.BlastRadius{Checked: []string{"Route53 records", "cluster membership"}}
		}
		add(n)
	}
	add(engine.ResourceNode{ID: arn("es", "eu-west-1", "domain/catalog-search"), Name: "catalog-search", Type: "aws_opensearch_domain", Group: "SEARCH",
		Region: "eu-west-1", Status: engine.StatusManaged, ManagedBy: "Terraform", Confidence: engine.ConfHigh,
		MonthlyCost: 1240, CostSource: engine.CostEstimated, Tags: tf})
	for _, s := range []string{"clicks-raw", "orders-raw", "returns-raw", "wishlist-raw", "promo-sync-raw"} {
		n := engine.ResourceNode{ID: arn("kinesis", "eu-west-1", "stream/"+s), Name: s, Type: "aws_kinesis_stream", Group: "STREAMING",
			Region: "eu-west-1", Status: engine.StatusManaged, ManagedBy: "Terraform", Confidence: engine.ConfHigh,
			MonthlyCost: 29.2, CostSource: engine.CostEstimated, Tags: tf}
		if s == "promo-sync-raw" {
			n.Status, n.Confidence, n.WasteReason = engine.StatusOrphanWaste, engine.ConfLow, "On-demand Kinesis stream with negligible traffic"
			n.Evidence = []string{"0.12 MiB in 14d while the stream bills a fixed $29.20/month"}
			n.Blast = &engine.BlastRadius{Checked: []string{"Lambda event source mappings", "enhanced fan-out consumers"}}
		}
		add(n)
	}
	add(engine.ResourceNode{ID: arn("dynamodb", "eu-west-1", "table/sessions-legacy"), Name: "sessions-legacy", Type: "aws_dynamodb_table", Group: "DATA",
		Region: "eu-west-1", Status: engine.StatusOrphanWaste, ManagedBy: "Terraform", Confidence: engine.ConfHigh,
		MonthlyCost: engine.DynamoDBMonthlyCost(true, 400, 200, 3<<30), CostSource: engine.CostEstimated, Tags: tf,
		WasteReason: "Provisioned DynamoDB table without consumption",
		Evidence:    []string{"no read or write capacity consumed in 14d while 400 RCU / 200 WCU are provisioned"}})

	// storage
	for i, g := range []struct {
		size int
		used bool
	}{{500, false}, {200, false}, {100, true}} {
		id := fmt.Sprintf("vol-0%d1a2b3c4d5e6f708", i)
		n := engine.ResourceNode{ID: id, Name: fmt.Sprintf("data-%d", i), Type: "aws_ebs_volume", Group: "STORAGE", Region: "eu-west-1",
			Status: engine.StatusManaged, ManagedBy: "Terraform", Confidence: engine.ConfHigh,
			MonthlyCost: engine.EBSMonthlyCost("gp3", int32(g.size)), CostSource: engine.CostEstimated, Tags: tf,
			Attrs: map[string]string{"size_gb": fmt.Sprint(g.size), "volume_type": "gp3", "az": "eu-west-1a"}}
		if !g.used {
			n.Status, n.WasteReason = engine.StatusOrphanWaste, "Unattached EBS volume"
			n.Evidence = []string{fmt.Sprintf("state=available (not attached to any instance), %d GB gp3, created 210d ago", g.size), "backup: 2 snapshot(s), newest 2026-09-02"}
			n.Blast = &engine.BlastRadius{Checked: []string{"snapshots of this volume"},
				Dependents: []engine.Dependent{{Kind: "backup", Name: "snapshots exist", Detail: "2 snapshot(s), newest 2026-09-02"}}}
		}
		add(n)
	}
	add(engine.ResourceNode{ID: "eipalloc-0f1e2d3c4b5a69788", Name: "203.0.113.17", Type: "aws_eip", Group: "NETWORK", Region: "eu-west-1",
		Status: engine.StatusOrphanWaste, Confidence: engine.ConfHigh, MonthlyCost: 3.65, CostSource: engine.CostEstimated,
		WasteReason: "Elastic IP not associated", Evidence: []string{"no association (no instance or network interface), billed as idle public IPv4"}})
	for i := 0; i < 24; i++ {
		add(engine.ResourceNode{ID: "arn:aws:s3:::northwind-prod-assets-" + fmt.Sprintf("%02d", i), Name: "northwind-prod-assets-" + fmt.Sprintf("%02d", i),
			Type: "aws_s3_bucket", Group: "STORAGE", Region: "eu-west-1", Status: engine.StatusManaged, ManagedBy: "Terraform",
			Confidence: engine.ConfHigh, MonthlyCost: float64(5 + i*7), CostSource: engine.CostEstimated, Tags: tf})
	}

	// commitments (invented)
	end := at.AddDate(0, 0, 4)
	start := end.AddDate(-1, 0, 0)
	r.Commitments = []engine.Commitment{
		{Kind: "reservation", Service: "Amazon Relational Database Service", ID: "orders-2025-2026", Region: "eu-west-1",
			Detail: "orders-2025-2026: 2 × db.r6g.large, All Upfront", State: "active", Start: &start, End: &end,
			Facts:       []string{"ends " + end.Format("2006-01-02") + " (4 days left)"},
			Suggestions: []string{"Decide before it ends: renew, resize or let it lapse. The right answer depends on whether this workload stays on AWS for another term, which the scan cannot know."}},
		{Kind: "coverage", Service: "Amazon ElastiCache", Detail: "last month 0% covered, this month 0%", CoveragePct: 0, OnDemandHours: 2160,
			Facts:       []string{"last full month: 2160 of 2160 running hours were on-demand (0% covered)", "this month so far: 0% covered (800 on-demand hours)"},
			Suggestions: []string{"2160 on-demand hours last month. If this workload is expected to run for the next 12 months, a reservation or Savings Plan would price it lower than on-demand. If a migration, resize or shutdown is planned, no action is needed. The scan cannot know your plans."}},
		{Kind: "savings_plan", Service: "Savings Plans", ID: "sp-demo", Detail: "Compute, $2.50/h, All Upfront", State: "active",
			Facts: []string{"active until " + at.AddDate(1, 6, 0).Format("2006-01-02")}},
	}
	e := at.AddDate(1, 6, 0)
	r.Commitments[2].End = &e

	// billing (invented)
	for _, s := range []struct {
		n         string
		prev, cur float64
	}{
		{"Amazon Elastic Container Service", 2400, 2500}, {"Amazon OpenSearch Service", 1250, 1260}, {"Amazon Relational Database Service", 900, 880},
		{"EC2 - Other", 650, 700}, {"Amazon Simple Storage Service", 420, 430}, {"AWS Lambda", 260, 270}, {"Amazon CloudFront", 310, 320},
		{"Amazon Virtual Private Cloud", 190, 190}, {"Amazon Kinesis", 150, 150},
	} {
		r.ServiceCosts = append(r.ServiceCosts, engine.ServiceCost{Service: s.n,
			CostHistory: engine.CostHistory{PreviousMonthCost: s.prev, CurrentMonthCost: s.cur}})
		r.TotalPrevCost += s.prev
		r.TotalCurrCost += s.cur
	}
	enrich(&r, at)
	costMap := awsDiscovery.CostServiceMap(awsDiscovery.Scanners())
	engine.Finalize(&r, costMap)
	return r
}

// enrich adds what a fuller engagement would have: measured drivers, a bill
// to allocate, Terraform state with a little drift, owners and findings from
// other tools. It is all invented, and it exists so the product's three
// layers (cost, security, infrastructure as code) show up in the example.
func enrich(r *engine.ScanResult, at time.Time) {
	clusters := map[string][2]float64{"checkout": {1024, 2048}, "catalog": {512, 1024}, "search": {2048, 8192}, "batch": {4096, 16384}}
	teams := map[string]string{"checkout": "checkout", "catalog": "catalog", "search": "search", "batch": "data-platform"}
	var sumV, sumG, sumVol, sumS3, sumLamGBs, sumInv, natGB, lbCount, rdsLarge, rdsT4g float64
	nat := 0
	for i := range r.Nodes {
		n := &r.Nodes[i]
		if n.Attrs == nil {
			n.Attrs = map[string]string{}
		}
		d := map[string]float64{}
		switch n.Type {
		case "aws_nat_gateway":
			gb := 4200 + float64(nat)*900
			nat++
			d["hours"], d["gb"] = 730, gb
			natGB += gb
		case "aws_lb":
			d["hours"] = 730
			lbCount++
		case "aws_ecs_service":
			cl := n.Attrs["cluster"]
			var idx int
			fmt.Sscanf(n.Name[len(cl)+len("-svc-"):], "%d", &idx)
			tasks := float64(1 + idx%3)
			d["vcpu_h_od"] = clusters[cl][0] / 1024 * 730 * tasks
			d["gb_h_od"] = clusters[cl][1] / 1024 * 730 * tasks
			sumV += d["vcpu_h_od"]
			sumG += d["gb_h_od"]
			n.Tags = withTags(n.Tags, "Team", teams[cl])
		case "aws_rds_instance":
			d["hours"] = 730
			n.Tags = withTags(n.Tags, "Owner", "data-platform")
			if n.Attrs["class"] == "db.r6g.large" {
				rdsLarge++
			} else {
				rdsT4g++
			}
		case "aws_ebs_volume":
			var gb float64
			fmt.Sscanf(n.Attrs["size_gb"], "%f", &gb)
			d["gb"] = gb
			sumVol += gb
		case "aws_opensearch_domain":
			n.Attrs["instance_type"], n.Attrs["instances"], n.Attrs["engine_version"], n.Attrs["volume_type"] = "r6g.large.search", "3", "OpenSearch_2.11", "gp3"
			d["hours"], d["ebs_gb"] = 3*730, 1500
			n.Tags = withTags(n.Tags, "Team", "search")
		case "aws_kinesis_stream":
			d["hours_od"] = 730
		case "aws_lambda_function":
			inv := map[string]float64{"order-events": 9e6, "image-resize": 3e6, "nightly-export": 30}[n.Name]
			mem := map[string]float64{"order-events": 512, "image-resize": 1769, "nightly-export": 1024}[n.Name]
			d["invocations"], d["gb_s"] = inv, inv*0.18*mem/1024
			sumInv += inv
			sumLamGBs += d["gb_s"]
			n.Attrs["memory_mb"], n.Attrs["runtime"] = fmt.Sprint(mem), "python3.12"
			n.Tags = withTags(n.Tags, "Team", "growth")
		case "aws_s3_bucket":
			gb := n.MonthlyCost / 0.023
			d["gb_std"] = gb
			sumS3 += gb
		}
		if len(d) > 0 {
			n.Drivers = d
		}
	}
	lines := []engine.UsageLine{
		{Service: "Amazon Elastic Container Service", UsageType: "EU-Fargate-vCPU-Hours:perCPU", Cost: sumV * 0.04048, Quantity: sumV},
		{Service: "Amazon Elastic Container Service", UsageType: "EU-Fargate-GB-Hours", Cost: sumG * 0.004445, Quantity: sumG},
		{Service: "Amazon Relational Database Service", UsageType: "EU-InstanceUsage:db.r6g.large", Cost: rdsLarge * 730 * 0.29, Quantity: rdsLarge * 730},
		{Service: "Amazon Relational Database Service", UsageType: "EU-InstanceUsage:db.t4g.large", Cost: rdsT4g * 730 * 0.15, Quantity: rdsT4g * 730},
		{Service: "Amazon Relational Database Service", UsageType: "EU-InstanceUsage:db.r5.xlarge", Cost: 360, Quantity: 730},
		{Service: "Amazon OpenSearch Service", UsageType: "EU-ESInstance:r6g.large", Cost: 3 * 730 * 0.167, Quantity: 3 * 730},
		{Service: "Amazon OpenSearch Service", UsageType: "EU-ES:GP3-Storage", Cost: 1500 * 0.1, Quantity: 1500},
		{Service: "EC2 - Other", UsageType: "EU-NatGateway-Hours", Cost: 2 * 730 * 0.048, Quantity: 2 * 730},
		{Service: "EC2 - Other", UsageType: "EU-NatGateway-Bytes", Cost: natGB * 0.048, Quantity: natGB},
		{Service: "EC2 - Other", UsageType: "EU-EBS:VolumeUsage.gp3", Cost: sumVol * 0.08, Quantity: sumVol},
		{Service: "EC2 - Other", UsageType: "EU-DataTransfer-Out-Bytes", Cost: 310, Quantity: 3400},
		{Service: "Amazon Elastic Load Balancing", UsageType: "EU-LoadBalancerUsage", Cost: lbCount * 730 * 0.0225, Quantity: lbCount * 730},
		{Service: "Amazon Simple Storage Service", UsageType: "EU-TimedStorage-ByteHrs", Cost: sumS3 * 0.023, Quantity: sumS3},
		{Service: "Amazon Kinesis", UsageType: "EU-OnDemand-StreamHour", Cost: 5 * 730 * 0.04, Quantity: 5 * 730},
		{Service: "AWS Lambda", UsageType: "EU-Lambda-GB-Second", Cost: sumLamGBs * 0.0000166667, Quantity: sumLamGBs},
		{Service: "AWS Lambda", UsageType: "EU-Request", Cost: sumInv * 0.0000002, Quantity: sumInv},
		{Service: "AWS Support (Business)", UsageType: "Dollar", Cost: 390, Quantity: 1},
	}

	// Terraform state: most resources are in it, three are only tagged, one
	// entry points at something that no longer exists, two attributes drifted.
	tagOnly := map[string]bool{"campaign-2022": true, "northwind-prod-assets-17": true, "northwind-prod-assets-18": true, "northwind-prod-assets-19": true}
	tfType := map[string]string{"aws_rds_instance": "aws_db_instance"}
	var refs []engine.IaCRef
	for _, n := range r.Nodes {
		if n.ManagedBy != "Terraform" || tagOnly[n.Name] {
			continue
		}
		t := n.Type
		if v, ok := tfType[t]; ok {
			t = v
		}
		ref := engine.IaCRef{Source: "terraform", Origin: "prod/terraform.tfstate", Address: t + "." + sanitize(n.Name), Module: "module.platform",
			Type: t, ID: n.ID, Region: n.Region, Attrs: map[string]string{}}
		if len(n.ID) > 4 && n.ID[:4] == "arn:" {
			ref.ARN = n.ID
		}
		switch n.Type {
		case "aws_lambda_function":
			ref.Attrs["memory_size"], ref.Attrs["runtime"] = n.Attrs["memory_mb"], n.Attrs["runtime"]
			if n.Name == "image-resize" {
				ref.Attrs["memory_size"] = "1024" // changed in the console since the last apply
			}
		case "aws_rds_instance":
			ref.Attrs["instance_class"] = n.Attrs["class"]
			if n.Name == "orders-2" {
				ref.Attrs["instance_class"] = "db.r6g.xlarge"
			}
		case "aws_ebs_volume":
			ref.Attrs["size"], ref.Attrs["type"] = n.Attrs["size_gb"], n.Attrs["volume_type"]
		}
		refs = append(refs, ref)
	}
	refs = append(refs, engine.IaCRef{Source: "terraform", Origin: "prod/terraform.tfstate", Address: "aws_instance.bastion_old", Module: "module.platform",
		Type: "aws_instance", ID: "i-0a1b2c3d4e5f60789", Region: "eu-west-1"})
	engine.JoinIaC(r, refs, []string{"terraform: s3://northwind-tfstate/prod/terraform.tfstate (example)"}, 1, 0, nil)

	engine.Allocate(r, lines)
	r.Ledger.Month = at.AddDate(0, -1, 0).Format("2006-01")
	r.Findings = append(r.Findings, engine.LedgerFindings(r)...)

	// the bill the report quotes is the ledger's, so the two must agree
	r.ServiceCosts, r.TotalPrevCost, r.TotalCurrCost = nil, 0, 0
	for _, ls := range r.Ledger.Services {
		prev := ls.Billed * 0.96
		r.ServiceCosts = append(r.ServiceCosts, engine.ServiceCost{Service: ls.Service,
			CostHistory: engine.CostHistory{PreviousMonthCost: prev, CurrentMonthCost: ls.Billed}})
		r.TotalPrevCost += prev
		r.TotalCurrCost += ls.Billed
	}

	f := func(src, rule string, pil engine.Pillar, sev engine.Severity, title, rec string, affected int, res ...string) engine.Finding {
		id := ""
		if len(res) > 0 {
			id = res[0]
		}
		return engine.Finding{ID: engine.FindingID(src, rule, id+title), Pillar: pil, Source: src, Rule: rule, Severity: sev, Title: title,
			Recommendation: rec, Affected: affected, Resources: res, Confidence: engine.ConfHigh}
	}
	r.Findings = append(r.Findings,
		f("security-hub", "s3.2", engine.PillarSecurity, engine.SevCritical, "S3 buckets should block public access",
			"Enable S3 Block Public Access on the account and on these buckets unless a bucket is a deliberate public website.", 2, "northwind-prod-assets-03", "northwind-prod-assets-11"),
		f("security-hub", "cloudtrail.1", engine.PillarSecurity, engine.SevHigh, "CloudTrail should be enabled and configured with at least one multi-Region trail",
			"Create a multi-Region trail that delivers to a bucket in a separate logging account.", 1),
		f("security-hub", "rds.7", engine.PillarReliability, engine.SevMedium, "RDS clusters should have deletion protection enabled",
			"Turn on deletion protection for production clusters; it is a flag, not a restart.", 2, "orders", "reporting"),
		f("trusted-advisor", "ta.iam-mfa-root", engine.PillarSecurity, engine.SevHigh, "MFA on the root account",
			"Enable a hardware or virtual MFA device on the root user.", 1),
		f("own", "sec.sg-open-ssh", engine.PillarSecurity, engine.SevHigh, "A security group allows SSH from anywhere",
			"Restrict port 22 to a bastion or use SSM Session Manager; check what the group is attached to first.", 1, "sg-0a1b2c3d4e5f60718"),
		f("own", "rel.single-nat", engine.PillarReliability, engine.SevLow, "One NAT gateway per VPC",
			"If an Availability Zone fails, private subnets lose egress. One NAT per AZ costs more; whether that is worth it depends on the workload.", 1, "nat-009f8e7d6c5b4a3921"),
		f("cost-hub", "coh.rightsize-ecs", engine.PillarCost, engine.SevMedium, "Right-size ECS services in the batch cluster",
			"Recommendations from Cost Optimization Hub: lower the task memory of a few services whose usage stays under half of the reservation.", 4, "batch-svc-01", "batch-svc-04"),
	)
	for i := range r.Findings {
		if r.Findings[i].Source == "cost-hub" {
			r.Findings[i].MonthlyCost = 180
		}
	}
}

func withTags(in map[string]string, k, v string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for a, b := range in {
		out[a] = b
	}
	out[k] = v
	return out
}

func sanitize(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c == '-' || c == '.' {
			b[i] = '_'
		}
	}
	return string(b)
}
