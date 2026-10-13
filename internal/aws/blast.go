package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/route53"
)

// Blast radius answers "what would removing this touch?" for waste
// candidates only. A verdict that nothing uses a resource is much weaker when
// a DNS record, a CloudFront origin or a route table still points at it, so
// the lookups run after detection and may lower the confidence.

type blastAPIs struct {
	route53 interface {
		route53.ListHostedZonesAPIClient
		route53.ListResourceRecordSetsAPIClient
	}
	cloudfront cloudfront.ListDistributionsAPIClient
	routeTable func(region string) (ec2.DescribeRouteTablesAPIClient, error)
	snapshots  func(region string) (ec2.DescribeSnapshotsAPIClient, error)
	lambda     func(region string) (lambda.ListEventSourceMappingsAPIClient, error)
	kinesis    func(region string) (kinesis.ListStreamConsumersAPIClient, error)
}

// EnrichBlast fills Blast on waste candidates and returns warnings. It never
// changes a verdict upwards: dependents can only lower confidence.
func (dc *DiscoveryClient) EnrichBlast(ctx context.Context, nodes []engine.ResourceNode) []string {
	cache := map[string]aws.Config{}
	cfgFor := func(region string) (aws.Config, error) {
		if c, ok := cache[region]; ok {
			return c, nil
		}
		c, err := dc.loadConfig(ctx, region)
		if err == nil {
			cache[region] = c
		}
		return c, err
	}
	global, err := cfgFor("us-east-1")
	if err != nil {
		return []string{"blast-radius: " + oneLineErr(err)}
	}
	return enrichBlastWith(ctx, blastAPIs{
		route53:    route53.NewFromConfig(global),
		cloudfront: cloudfront.NewFromConfig(global),
		routeTable: func(r string) (ec2.DescribeRouteTablesAPIClient, error) {
			c, err := cfgFor(r)
			return ec2.NewFromConfig(c), err
		},
		snapshots: func(r string) (ec2.DescribeSnapshotsAPIClient, error) {
			c, err := cfgFor(r)
			return ec2.NewFromConfig(c), err
		},
		lambda: func(r string) (lambda.ListEventSourceMappingsAPIClient, error) {
			c, err := cfgFor(r)
			return lambda.NewFromConfig(c), err
		},
		kinesis: func(r string) (kinesis.ListStreamConsumersAPIClient, error) {
			c, err := cfgFor(r)
			return kinesis.NewFromConfig(c), err
		},
	}, nodes)
}

func enrichBlastWith(ctx context.Context, api blastAPIs, nodes []engine.ResourceNode) []string {
	var warns []string
	warn := func(what string, err error) { warns = append(warns, "blast-radius/"+what+": "+oneLineErr(err)) }

	var dns map[string][]dnsRecord
	var dnsErr error
	dnsOnce := func() (map[string][]dnsRecord, error) {
		if dns == nil && dnsErr == nil {
			dns, dnsErr = buildDNSIndex(ctx, api.route53)
			if dnsErr != nil {
				warn("route53", dnsErr)
			}
		}
		return dns, dnsErr
	}
	var cfOrigins map[string][]string
	var cfErr error
	cfOnce := func() (map[string][]string, error) {
		if cfOrigins == nil && cfErr == nil {
			cfOrigins, cfErr = buildOriginIndex(ctx, api.cloudfront)
			if cfErr != nil {
				warn("cloudfront", cfErr)
			}
		}
		return cfOrigins, cfErr
	}

	// cluster membership, for "other members of this cluster"
	members := map[string][]string{}
	for _, n := range nodes {
		if c := n.Attrs["cluster"]; c != "" && n.Type == "aws_rds_instance" {
			members[c] = append(members[c], n.Name)
		}
	}

	for i := range nodes {
		n := &nodes[i]
		if n.Status != engine.StatusOrphanWaste {
			continue
		}
		b := &engine.BlastRadius{}
		check := func(name string) { b.Checked = append(b.Checked, name) }
		miss := func(name string) { b.Unchecked = append(b.Unchecked, name) }

		switch n.Type {
		case "aws_lb":
			if name := n.Attrs["dns_name"]; name != "" {
				if idx, err := dnsOnce(); err != nil {
					miss("Route53 records")
				} else {
					check("Route53 records")
					for _, r := range idx[normDNS(name)] {
						b.Dependents = append(b.Dependents, engine.Dependent{Kind: "dns", Name: r.name, Detail: r.kind + " in zone " + r.zone})
					}
				}
				if idx, err := cfOnce(); err != nil {
					miss("CloudFront origins")
				} else {
					check("CloudFront origins")
					for _, d := range idx[normDNS(name)] {
						b.Dependents = append(b.Dependents, engine.Dependent{Kind: "cloudfront", Name: d, Detail: "distribution uses this balancer as an origin"})
					}
				}
			} else {
				miss("Route53 records (balancer DNS name unknown)")
			}

		case "aws_rds_instance":
			targets := []string{n.Attrs["endpoint"], n.Attrs["cluster_endpoint"], n.Attrs["reader_endpoint"]}
			if idx, err := dnsOnce(); err != nil {
				miss("Route53 records")
			} else {
				check("Route53 records")
				seen := map[string]bool{}
				for _, t := range targets {
					if t == "" {
						continue
					}
					for _, r := range idx[normDNS(t)] {
						if k := r.name + r.zone; !seen[k] {
							seen[k] = true
							b.Dependents = append(b.Dependents, engine.Dependent{Kind: "dns", Name: r.name, Detail: r.kind + " in zone " + r.zone + " -> " + t})
						}
					}
				}
			}
			if c := n.Attrs["cluster"]; c != "" {
				check("cluster membership")
				var others []string
				for _, m := range members[c] {
					if m != n.Name {
						others = append(others, m)
					}
				}
				sort.Strings(others)
				if len(others) > 0 {
					b.Dependents = append(b.Dependents, engine.Dependent{Kind: "cluster-member", Name: strings.Join(others, ", "),
						Detail: "other instance(s) of cluster " + c + "; removing an instance leaves the cluster as is, removing the cluster removes them too"})
				}
			}

		case "aws_nat_gateway":
			rt, err := api.routeTable(n.Region)
			if err != nil {
				miss("route tables")
				break
			}
			tables, err := routeTablesVia(ctx, rt, n.ID)
			if err != nil {
				warn("route-tables", err)
				miss("route tables")
				break
			}
			check("route tables")
			for _, t := range tables {
				b.Dependents = append(b.Dependents, engine.Dependent{Kind: "route", Name: t.id, Detail: t.detail})
			}

		case "aws_ebs_volume":
			sn, err := api.snapshots(n.Region)
			if err != nil {
				miss("snapshots of this volume")
				break
			}
			out, err := sn.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
				OwnerIds: []string{"self"},
				Filters:  []ec2Types.Filter{{Name: aws.String("volume-id"), Values: []string{n.ID}}},
			})
			if err != nil {
				warn("snapshots", err)
				miss("snapshots of this volume")
				break
			}
			check("snapshots of this volume")
			if len(out.Snapshots) > 0 {
				newest := out.Snapshots[0].StartTime
				for _, s := range out.Snapshots {
					if s.StartTime != nil && (newest == nil || s.StartTime.After(*newest)) {
						newest = s.StartTime
					}
				}
				d := fmt.Sprintf("%d snapshot(s)", len(out.Snapshots))
				if newest != nil {
					d += ", newest " + newest.Format("2006-01-02")
				}
				b.Dependents = append(b.Dependents, engine.Dependent{Kind: "backup", Name: "snapshots exist", Detail: d})
			}

		case "aws_kinesis_stream":
			lm, err := api.lambda(n.Region)
			if err != nil {
				miss("Lambda event source mappings")
			} else {
				p := lambda.NewListEventSourceMappingsPaginator(lm, &lambda.ListEventSourceMappingsInput{EventSourceArn: aws.String(n.ID)})
				var lerr error
				for p.HasMorePages() {
					page, err := p.NextPage(ctx)
					if err != nil {
						lerr = err
						break
					}
					for _, m := range page.EventSourceMappings {
						b.Dependents = append(b.Dependents, engine.Dependent{Kind: "consumer", Name: lastToken(aws.ToString(m.FunctionArn)),
							Detail: "Lambda event source mapping, state " + aws.ToString(m.State)})
					}
				}
				if lerr != nil {
					warn("lambda", lerr)
					miss("Lambda event source mappings")
				} else {
					check("Lambda event source mappings")
				}
			}
			kn, err := api.kinesis(n.Region)
			if err != nil {
				miss("enhanced fan-out consumers")
				break
			}
			cp := kinesis.NewListStreamConsumersPaginator(kn, &kinesis.ListStreamConsumersInput{StreamARN: aws.String(n.ID)})
			var kerr error
			for cp.HasMorePages() {
				page, err := cp.NextPage(ctx)
				if err != nil {
					kerr = err
					break
				}
				for _, c := range page.Consumers {
					b.Dependents = append(b.Dependents, engine.Dependent{Kind: "consumer", Name: aws.ToString(c.ConsumerName), Detail: "enhanced fan-out consumer"})
				}
			}
			if kerr != nil {
				warn("kinesis", kerr)
				miss("enhanced fan-out consumers")
			} else {
				check("enhanced fan-out consumers")
			}

		default:
			continue // no dependency lookup defined for this type
		}

		n.Blast = b
		applyBlast(n)
	}
	return warns
}

// applyBlast folds the lookup result into the verdict. A backup is good news
// for rollback and does not lower confidence; anything that depends on the
// resource does, and says so in the evidence.
func applyBlast(n *engine.ResourceNode) {
	if n.Blast == nil {
		return
	}
	var deps []string
	for _, d := range n.Blast.Dependents {
		if d.Kind == "backup" {
			n.Evidence = append(n.Evidence, "backup: "+d.Detail)
			continue
		}
		deps = append(deps, d.Kind+" "+d.Name)
	}
	if len(deps) > 0 {
		n.Evidence = append(n.Evidence, fmt.Sprintf("%d dependent(s) found: %s", len(deps), strings.Join(firstN(deps, 4), "; ")))
		n.Confidence = lower(n.Confidence)
	}
	if len(n.Blast.Unchecked) > 0 {
		n.Evidence = append(n.Evidence, "dependency check incomplete: could not look at "+strings.Join(n.Blast.Unchecked, ", "))
	}
}

func lower(c engine.Confidence) engine.Confidence {
	switch c {
	case engine.ConfHigh:
		return engine.ConfMedium
	case engine.ConfMedium:
		return engine.ConfLow
	}
	return engine.ConfLow
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string{}, s[:n]...), fmt.Sprintf("... %d more", len(s)-n))
}

// ---- DNS and CloudFront indexes ----------------------------------------------

type dnsRecord struct{ name, kind, zone string }

// normDNS lowercases, drops the trailing dot and the "dualstack." prefix that
// ALIAS targets carry.
func normDNS(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	return strings.TrimPrefix(s, "dualstack.")
}

func buildDNSIndex(ctx context.Context, api interface {
	route53.ListHostedZonesAPIClient
	route53.ListResourceRecordSetsAPIClient
}) (map[string][]dnsRecord, error) {
	idx := map[string][]dnsRecord{}
	zp := route53.NewListHostedZonesPaginator(api, &route53.ListHostedZonesInput{})
	for zp.HasMorePages() {
		zones, err := zp.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, z := range zones.HostedZones {
			rp := route53.NewListResourceRecordSetsPaginator(api, &route53.ListResourceRecordSetsInput{HostedZoneId: z.Id})
			for rp.HasMorePages() {
				page, err := rp.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, rs := range page.ResourceRecordSets {
					name := strings.TrimSuffix(aws.ToString(rs.Name), ".")
					zone := strings.TrimSuffix(aws.ToString(z.Name), ".")
					if rs.AliasTarget != nil {
						k := normDNS(aws.ToString(rs.AliasTarget.DNSName))
						idx[k] = append(idx[k], dnsRecord{name, "alias " + string(rs.Type), zone})
					}
					for _, rr := range rs.ResourceRecords {
						k := normDNS(aws.ToString(rr.Value))
						idx[k] = append(idx[k], dnsRecord{name, string(rs.Type), zone})
					}
				}
			}
		}
	}
	return idx, nil
}

func buildOriginIndex(ctx context.Context, api cloudfront.ListDistributionsAPIClient) (map[string][]string, error) {
	idx := map[string][]string{}
	p := cloudfront.NewListDistributionsPaginator(api, &cloudfront.ListDistributionsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if page.DistributionList == nil {
			continue
		}
		for _, d := range page.DistributionList.Items {
			if d.Origins == nil {
				continue
			}
			for _, o := range d.Origins.Items {
				k := normDNS(aws.ToString(o.DomainName))
				idx[k] = append(idx[k], aws.ToString(d.Id))
			}
		}
	}
	return idx, nil
}

// ---- route tables ------------------------------------------------------------

type routeRef struct{ id, detail string }

// routeTablesVia lists route tables that still send traffic through the NAT gateway.
func routeTablesVia(ctx context.Context, api ec2.DescribeRouteTablesAPIClient, natID string) ([]routeRef, error) {
	p := ec2.NewDescribeRouteTablesPaginator(api, &ec2.DescribeRouteTablesInput{
		Filters: []ec2Types.Filter{{Name: aws.String("route.nat-gateway-id"), Values: []string{natID}}},
	})
	var out []routeRef
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range page.RouteTables {
			for _, r := range t.Routes {
				if aws.ToString(r.NatGatewayId) == natID {
					subnets := 0
					for _, a := range t.Associations {
						if a.SubnetId != nil {
							subnets++
						}
					}
					out = append(out, routeRef{
						id: aws.ToString(t.RouteTableId),
						detail: fmt.Sprintf("route %s via this gateway; %d associated subnet(s)",
							aws.ToString(r.DestinationCidrBlock), subnets),
					})
				}
			}
		}
	}
	return out, nil
}

// lastToken returns the part after the last ':' or '/', e.g. a Lambda function name.
func lastToken(arn string) string {
	if i := strings.LastIndexAny(arn, ":/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}
