package aws

import (
	"context"
	"fmt"
	"strings"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	osTypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
)

func scanOpenSearch(ctx context.Context, cfg aws.Config, c *collector) {
	cli := opensearch.NewFromConfig(cfg)
	cw := cloudwatch.NewFromConfig(cfg)

	names, err := cli.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		c.warn("opensearch:domains", err)
		return
	}
	var all []string
	for _, d := range names.DomainNames {
		all = append(all, aws.ToString(d.DomainName))
	}
	for i := 0; i < len(all); i += 5 {
		desc, err := cli.DescribeDomains(ctx, &opensearch.DescribeDomainsInput{DomainNames: all[i:min(i+5, len(all))]})
		if err != nil {
			c.warn("opensearch:describe", err)
			continue
		}
		for _, d := range desc.DomainStatusList {
			scanDomain(ctx, cli, cw, c, d)
		}
	}
}

func scanDomain(ctx context.Context, cli *opensearch.Client, cw *cloudwatch.Client, c *collector, d osTypes.DomainStatus) {
	name := aws.ToString(d.DomainName)
	arn := aws.ToString(d.ARN)
	cc := d.ClusterConfig
	if cc == nil {
		return
	}

	var tags map[string]string
	if tl, err := cli.ListTags(ctx, &opensearch.ListTagsInput{ARN: aws.String(arn)}); err != nil {
		c.warn("opensearch:tags", err)
	} else {
		tags = tagMap(tl.TagList, func(t osTypes.Tag) (string, string) { return aws.ToString(t.Key), aws.ToString(t.Value) })
	}

	ebsGB := 0
	if d.EBSOptions != nil {
		ebsGB = int(aws.ToInt32(d.EBSOptions.VolumeSize))
	}
	count := int(aws.ToInt32(cc.InstanceCount))
	masters := 0
	if aws.ToBool(cc.DedicatedMasterEnabled) {
		masters = int(aws.ToInt32(cc.DedicatedMasterCount))
	}
	cost, known := engine.OpenSearchMonthlyCost(string(cc.InstanceType), count, string(cc.DedicatedMasterType), masters, ebsGB, count)

	n := engine.ResourceNode{
		ID: arn, Name: name, Type: "aws_opensearch_domain", Group: "SEARCH",
		MonthlyCost: cost, CostSource: engine.CostEstimated, Tags: tags,
		Attrs: map[string]string{
			"instance_type": string(cc.InstanceType), "instances": fmt.Sprint(count),
			"engine_version": aws.ToString(d.EngineVersion), "ebs_gb_per_node": fmt.Sprint(ebsGB),
			"multi_az": fmt.Sprint(aws.ToBool(cc.ZoneAwarenessEnabled)),
		},
		Drivers: map[string]float64{
			"hours":  float64(count) * engine.HoursPerMonth,
			"ebs_gb": float64(ebsGB) * float64(count),
		},
	}
	if d.EBSOptions != nil {
		n.Attrs["volume_type"] = string(d.EBSOptions.VolumeType)
	}
	n.Attrs["in_vpc"] = fmt.Sprint(d.VPCOptions != nil && aws.ToString(d.VPCOptions.VPCId) != "")
	if d.EncryptionAtRestOptions != nil {
		n.Attrs["encrypted_at_rest"] = fmt.Sprint(aws.ToBool(d.EncryptionAtRestOptions.Enabled))
	}
	if d.NodeToNodeEncryptionOptions != nil {
		n.Attrs["node_to_node_encryption"] = fmt.Sprint(aws.ToBool(d.NodeToNodeEncryptionOptions.Enabled))
	}
	if d.DomainEndpointOptions != nil {
		n.Attrs["enforce_https"] = fmt.Sprint(aws.ToBool(d.DomainEndpointOptions.EnforceHTTPS))
	}
	if d.VPCOptions != nil {
		n.VPCID = aws.ToString(d.VPCOptions.VPCId)
	}
	applyManagement(&n)
	n.Evidence = append(n.Evidence, "on-demand list price; reserved instances are not visible to the API and not applied")
	if !known {
		n.Evidence = append(n.Evidence, "price for "+string(cc.InstanceType)+" unknown, flat estimate used")
	}
	if aws.ToBool(d.Processing) {
		n.Evidence = append(n.Evidence, "domain is being modified")
	}

	// Account ID is the third-from-last ARN field's neighbour: arn:aws:es:region:ACCOUNT:domain/name
	parts := strings.Split(arn, ":")
	if len(parts) > 4 {
		dims := map[string]string{"DomainName": name, "ClientId": parts[4]}
		search, sp, serr := metricTotal(ctx, cw, metricQuery{"AWS/ES", "SearchRate", dims, cwTypes.StatisticMaximum, c.th.IdleWindowDays})
		index, ip, ierr := metricTotal(ctx, cw, metricQuery{"AWS/ES", "IndexingRate", dims, cwTypes.StatisticMaximum, c.th.IdleWindowDays})
		switch {
		case serr != nil || ierr != nil:
			c.warn("cloudwatch:opensearch", firstErr(serr, ierr))
			n.Evidence = append(n.Evidence, "CloudWatch unavailable: usage not checked")
		case sp == 0 && ip == 0:
			n.Evidence = append(n.Evidence, "no search/indexing datapoints, usage unknown")
		case search == 0 && index == 0:
			markWaste(&n, "OpenSearch domain without search or indexing", engine.ConfMedium,
				fmt.Sprintf("SearchRate and IndexingRate are 0 for %d days", c.th.IdleWindowDays))
		default:
			n.Evidence = append(n.Evidence, fmt.Sprintf("active: peak search %.0f/min, indexing %.0f/min in %dd", search, index, c.th.IdleWindowDays))
		}
	}
	c.add(n)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func init() {
	register(Scanner{
		Name: "opensearch", Desc: "OpenSearch domains, usage via CloudWatch",
		Types:    map[string]string{"aws_opensearch_domain": "Amazon OpenSearch Service"},
		Regional: scanOpenSearch,
	})
}
