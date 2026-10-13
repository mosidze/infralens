package aws

import (
	"context"
	"fmt"
	"time"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func ec2Tags(tags []ec2Types.Tag) map[string]string {
	return tagMap(tags, func(t ec2Types.Tag) (string, string) { return aws.ToString(t.Key), aws.ToString(t.Value) })
}

func scanEC2(ctx context.Context, cfg aws.Config, c *collector) {
	p := ec2.NewDescribeInstancesPaginator(ec2.NewFromConfig(cfg), &ec2.DescribeInstancesInput{
		Filters: []ec2Types.Filter{{
			Name:   aws.String("instance-state-name"),
			Values: []string{"pending", "running", "stopping", "stopped"},
		}},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("ec2:instances", err)
			return
		}
		for _, r := range page.Reservations {
			for _, i := range r.Instances {
				id := aws.ToString(i.InstanceId)
				tags := ec2Tags(i.Tags)
				n := engine.ResourceNode{
					ID: id, Name: nameOr(tags, id), Type: "aws_instance",
					Group: "COMPUTE", VPCID: aws.ToString(i.VpcId), SubnetID: aws.ToString(i.SubnetId),
					Tags:  tags,
					Attrs: map[string]string{"instance_type": string(i.InstanceType), "state": string(i.State.Name)},
				}
				applyManagement(&n)
				if i.State.Name == ec2Types.InstanceStateNameStopped {
					n.CostSource = engine.CostEstimated
					n.Evidence = append(n.Evidence, "instance is stopped: compute is not billed, attached volumes are")
				} else {
					cost, known := engine.EC2MonthlyCost(string(i.InstanceType))
					n.MonthlyCost, n.CostSource = cost, engine.CostEstimated
					if !known {
						n.Evidence = append(n.Evidence, "price for "+string(i.InstanceType)+" unknown, flat estimate used")
					}
				}
				c.add(n)
			}
		}
	}
}

// ebsAPI is what the volume and snapshot scanner needs from the SDK.
type ebsAPI interface {
	ec2.DescribeVolumesAPIClient
	ec2.DescribeSnapshotsAPIClient
	DescribeImages(ctx context.Context, in *ec2.DescribeImagesInput, opts ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
}

func scanVolumes(ctx context.Context, cfg aws.Config, c *collector) {
	scanVolumesWith(ctx, ec2.NewFromConfig(cfg), c)
}

func scanVolumesWith(ctx context.Context, cli ebsAPI, c *collector) {
	volumeIDs := map[string]bool{}

	p := ec2.NewDescribeVolumesPaginator(cli, &ec2.DescribeVolumesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("ec2:volumes", err)
			return
		}
		for _, v := range page.Volumes {
			id := aws.ToString(v.VolumeId)
			volumeIDs[id] = true
			tags := ec2Tags(v.Tags)
			size := aws.ToInt32(v.Size)
			n := engine.ResourceNode{
				ID: id, Name: nameOr(tags, id), Type: "aws_ebs_volume", Group: "STORAGE",
				MonthlyCost: engine.EBSMonthlyCost(string(v.VolumeType), size), CostSource: engine.CostEstimated,
				Tags:    tags,
				Attrs:   map[string]string{"size_gb": fmt.Sprint(size), "volume_type": string(v.VolumeType), "state": string(v.State), "az": aws.ToString(v.AvailabilityZone), "encrypted": fmt.Sprint(aws.ToBool(v.Encrypted))},
				Drivers: map[string]float64{"gb": float64(size)},
			}
			applyManagement(&n)
			if v.State == ec2Types.VolumeStateAvailable {
				age := "unknown age"
				if v.CreateTime != nil {
					age = fmt.Sprintf("created %dd ago", int(time.Since(*v.CreateTime).Hours()/24))
				}
				markWaste(&n, "Unattached EBS volume", engine.ConfHigh,
					fmt.Sprintf("state=available (not attached to any instance), %d GB %s, %s", size, v.VolumeType, age))
			}
			c.add(n)
			for _, a := range v.Attachments {
				c.link(aws.ToString(a.InstanceId), id, "attached")
			}
		}
	}
	scanSnapshots(ctx, cli, c, volumeIDs)
}

func scanSnapshots(ctx context.Context, cli ebsAPI, c *collector, volumeIDs map[string]bool) {
	usedByAMI := map[string]bool{}
	imgs, err := cli.DescribeImages(ctx, &ec2.DescribeImagesInput{Owners: []string{"self"}})
	if err != nil {
		// Without the AMI list we cannot tell leftovers from AMI backing.
		c.warn("ec2:images (snapshot check skipped)", err)
		return
	}
	for _, im := range imgs.Images {
		for _, bd := range im.BlockDeviceMappings {
			if bd.Ebs != nil && bd.Ebs.SnapshotId != nil {
				usedByAMI[*bd.Ebs.SnapshotId] = true
			}
		}
	}

	p := ec2.NewDescribeSnapshotsPaginator(cli, &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("ec2:snapshots", err)
			return
		}
		for _, s := range page.Snapshots {
			if s.StartTime == nil {
				continue
			}
			age := time.Since(*s.StartTime)
			id := aws.ToString(s.SnapshotId)
			if !snapshotOrphan(age, volumeIDs[aws.ToString(s.VolumeId)], usedByAMI[id], c.th) {
				continue
			}
			tags := ec2Tags(s.Tags)
			size := aws.ToInt32(s.VolumeSize)
			n := engine.ResourceNode{
				ID: id, Name: nameOr(tags, id), Type: "aws_ebs_snapshot", Group: "STORAGE",
				MonthlyCost: float64(size) * engine.SnapshotGBMonth, CostSource: engine.CostEstimated,
				Tags:  tags,
				Attrs: map[string]string{"size_gb": fmt.Sprint(size), "source_volume": aws.ToString(s.VolumeId)},
			}
			applyManagement(&n)
			markWaste(&n, "Orphan snapshot (upper-bound cost)", engine.ConfLow,
				fmt.Sprintf("%dd old, source volume %s no longer exists, not used by any AMI; cost is an upper bound (snapshots are incremental)",
					int(age.Hours()/24), aws.ToString(s.VolumeId)))
			c.add(n)
		}
	}
}

type addressesAPI interface {
	DescribeAddresses(ctx context.Context, in *ec2.DescribeAddressesInput, opts ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
}

func scanAddresses(ctx context.Context, cfg aws.Config, c *collector) {
	scanAddressesWith(ctx, ec2.NewFromConfig(cfg), c)
}

func scanAddressesWith(ctx context.Context, cli addressesAPI, c *collector) {
	out, err := cli.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		c.warn("ec2:addresses", err)
		return
	}
	for _, a := range out.Addresses {
		if a.AssociationId != nil {
			continue // in use; billed as public IPv4 together with its owner
		}
		id := aws.ToString(a.AllocationId)
		if id == "" {
			id = aws.ToString(a.PublicIp)
		}
		tags := ec2Tags(a.Tags)
		n := engine.ResourceNode{
			ID: id, Name: nameOr(tags, aws.ToString(a.PublicIp)), Type: "aws_eip", Group: "NETWORK",
			MonthlyCost: engine.MonthlyFromHourly(engine.PublicIPv4Hour), CostSource: engine.CostEstimated,
			Tags:  tags,
			Attrs: map[string]string{"public_ip": aws.ToString(a.PublicIp)},
		}
		applyManagement(&n)
		markWaste(&n, "Elastic IP not associated", engine.ConfHigh,
			"no association (no instance or network interface), billed as idle public IPv4")
		c.add(n)
	}
}

func scanNAT(ctx context.Context, cfg aws.Config, c *collector) {
	scanNATWith(ctx, ec2.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), c)
}

func scanNATWith(ctx context.Context, cli ec2.DescribeNatGatewaysAPIClient, cw metricsAPI, c *collector) {
	p := ec2.NewDescribeNatGatewaysPaginator(cli, &ec2.DescribeNatGatewaysInput{
		Filter: []ec2Types.Filter{{Name: aws.String("state"), Values: []string{"available"}}},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("ec2:nat", err)
			return
		}
		for _, g := range page.NatGateways {
			id := aws.ToString(g.NatGatewayId)
			tags := ec2Tags(g.Tags)
			n := engine.ResourceNode{
				ID: id, Name: nameOr(tags, id), Type: "aws_nat_gateway", Group: "NETWORK",
				VPCID: aws.ToString(g.VpcId), SubnetID: aws.ToString(g.SubnetId),
				MonthlyCost: engine.MonthlyFromHourly(engine.NATGatewayHour), CostSource: engine.CostEstimated,
				Tags:    tags,
				Drivers: map[string]float64{"hours": engine.HoursPerMonth},
			}
			applyManagement(&n)

			if proc, _, perr := natProcessedBytes(ctx, cw, id, c.th.IdleWindowDays); perr == nil && proc > 0 {
				gbMonth := proc / (1 << 30) * 30 / float64(c.th.IdleWindowDays)
				n.MonthlyCost += gbMonth * engine.NATDataGB
				n.Drivers["gb"] = gbMonth
				n.Evidence = append(n.Evidence, fmt.Sprintf("data processing: %.0f GB/month at $%.3f/GB", gbMonth, engine.NATDataGB))
			}

			bytesOut, points, err := metricTotal(ctx, cw, metricQuery{
				namespace: "AWS/NATGateway", metric: "BytesOutToDestination",
				dims: map[string]string{"NatGatewayId": id}, stat: cwTypes.StatisticSum, days: c.th.IdleWindowDays,
			})
			if err != nil {
				c.warn("cloudwatch:nat", err)
				n.Evidence = append(n.Evidence, "CloudWatch unavailable: traffic not checked")
			} else {
				age := time.Duration(1<<62 - 1)
				if g.CreateTime != nil {
					age = time.Since(*g.CreateTime)
				}
				v := natVerdict(bytesOut, points, age, c.th)
				if v.Waste {
					markWaste(&n, "NAT gateway without traffic", v.Confidence, v.Evidence)
				} else {
					n.Evidence = append(n.Evidence, v.Evidence)
				}
			}
			c.add(n)
		}
	}
}

// natProcessedBytes sums the bytes the gateway processed in both directions
// over the window, which is what data processing is billed on.
func natProcessedBytes(ctx context.Context, cw metricsAPI, id string, days int) (float64, int, error) {
	var total float64
	var pts int
	for _, m := range []string{"BytesInFromSource", "BytesInFromDestination"} {
		v, p, err := metricTotal(ctx, cw, metricQuery{
			namespace: "AWS/NATGateway", metric: m,
			dims: map[string]string{"NatGatewayId": id}, stat: cwTypes.StatisticSum, days: days,
		})
		if err != nil {
			return 0, 0, err
		}
		total += v
		pts += p
	}
	return total, pts, nil
}

func init() {
	register(Scanner{
		Name: "ec2", Desc: "EC2 instances (cost by type, stopped state)",
		Types:    map[string]string{"aws_instance": "Amazon Elastic Compute Cloud - Compute"},
		Regional: scanEC2,
	})
	register(Scanner{
		Name: "ebs", Desc: "EBS volumes (unattached) and orphan snapshots",
		Types:    map[string]string{"aws_ebs_volume": "EC2 - Other", "aws_ebs_snapshot": "EC2 - Other"},
		Regional: scanVolumes,
	})
	register(Scanner{
		Name: "eip", Desc: "Elastic IPs not associated",
		Types:    map[string]string{"aws_eip": "EC2 - Other"},
		Regional: scanAddresses,
	})
	register(Scanner{
		Name: "nat", Desc: "NAT gateways (traffic via CloudWatch, data processing cost)",
		Types:    map[string]string{"aws_nat_gateway": "EC2 - Other"},
		Regional: scanNAT,
	})
}
