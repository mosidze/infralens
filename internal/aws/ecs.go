package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// taskSize is a task definition's CPU units and memory MiB.
type taskSize struct {
	cpu, mem int
	arm      bool
	ephGiB   int // configured ephemeral storage; Fargate bills what exceeds 20 GiB
}

func ecsTags(tags []ecsTypes.Tag) map[string]string {
	return tagMap(tags, func(t ecsTypes.Tag) (string, string) { return aws.ToString(t.Key), aws.ToString(t.Value) })
}

func isFargate(s ecsTypes.Service) bool {
	if s.LaunchType == ecsTypes.LaunchTypeFargate {
		return true
	}
	for _, cp := range s.CapacityProviderStrategy {
		if strings.Contains(aws.ToString(cp.CapacityProvider), "FARGATE") {
			return true
		}
	}
	return false
}

func scanECS(ctx context.Context, cfg aws.Config, c *collector) {
	cli := ecs.NewFromConfig(cfg)

	var clusterARNs []string
	p := ecs.NewListClustersPaginator(cli, &ecs.ListClustersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("ecs:clusters", err)
			return
		}
		clusterARNs = append(clusterARNs, page.ClusterArns...)
	}
	if len(clusterARNs) == 0 {
		return
	}

	// task definition CPU/memory, cached across services
	tdCache := map[string]taskSize{}
	taskSizeOf := func(arn string) (taskSize, bool) {
		if ts, ok := tdCache[arn]; ok {
			return ts, ts.cpu > 0
		}
		out, err := cli.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: aws.String(arn)})
		var ts taskSize
		if err == nil && out.TaskDefinition != nil {
			ts.cpu, _ = strconv.Atoi(aws.ToString(out.TaskDefinition.Cpu))
			ts.mem, _ = strconv.Atoi(aws.ToString(out.TaskDefinition.Memory))
			if rp := out.TaskDefinition.RuntimePlatform; rp != nil {
				ts.arm = rp.CpuArchitecture == ecsTypes.CPUArchitectureArm64
			}
			if es := out.TaskDefinition.EphemeralStorage; es != nil {
				ts.ephGiB = int(es.SizeInGiB)
			}
		}
		tdCache[arn] = ts
		return ts, ts.cpu > 0 && ts.mem > 0
	}

	for i := 0; i < len(clusterARNs); i += 100 {
		end := min(i+100, len(clusterARNs))
		desc, err := cli.DescribeClusters(ctx, &ecs.DescribeClustersInput{
			Clusters: clusterARNs[i:end],
			Include:  []ecsTypes.ClusterField{ecsTypes.ClusterFieldTags},
		})
		if err != nil {
			c.warn("ecs:describe-clusters", err)
			continue
		}
		for _, cl := range desc.Clusters {
			scanCluster(ctx, cli, c, cl, taskSizeOf)
		}
	}
}

func scanCluster(ctx context.Context, cli *ecs.Client, c *collector, cl ecsTypes.Cluster,
	taskSizeOf func(string) (taskSize, bool)) {

	clARN := aws.ToString(cl.ClusterArn)
	clName := aws.ToString(cl.ClusterName)
	cn := engine.ResourceNode{
		ID: clARN, Name: clName, Type: "aws_ecs_cluster", Group: parseGroup(clName),
		CostSource: engine.CostNotAvailable, Tags: ecsTags(cl.Tags),
		Attrs: map[string]string{"running_tasks": fmt.Sprint(cl.RunningTasksCount), "services": fmt.Sprint(cl.ActiveServicesCount)},
	}
	applyManagement(&cn)
	clusterMgmt := engine.ClassifyManagement(cn.Tags)
	c.add(cn)

	var svcARNs []string
	p := ecs.NewListServicesPaginator(cli, &ecs.ListServicesInput{Cluster: aws.String(clARN)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("ecs:services", err)
			return
		}
		svcARNs = append(svcARNs, page.ServiceArns...)
	}

	for i := 0; i < len(svcARNs); i += 10 {
		end := min(i+10, len(svcARNs))
		out, err := cli.DescribeServices(ctx, &ecs.DescribeServicesInput{
			Cluster:  aws.String(clARN),
			Services: svcARNs[i:end],
			Include:  []ecsTypes.ServiceField{ecsTypes.ServiceFieldTags},
		})
		if err != nil {
			c.warn("ecs:describe-services", err)
			continue
		}
		for _, s := range out.Services {
			id := aws.ToString(s.ServiceArn)
			name := aws.ToString(s.ServiceName)
			n := engine.ResourceNode{
				ID: id, Name: name, Type: "aws_ecs_service", Group: parseGroup(name),
				Tags: ecsTags(s.Tags),
				Attrs: map[string]string{
					"cluster": clName, "desired": fmt.Sprint(s.DesiredCount), "running": fmt.Sprint(s.RunningCount),
				},
			}
			applyManagement(&n)
			if n.Status == engine.StatusShadowIT && clusterMgmt.Status == engine.StatusManaged {
				n.Status, n.ManagedBy, n.Confidence = engine.StatusManaged, clusterMgmt.ManagedBy, engine.ConfMedium
				n.Evidence = append(n.Evidence, "inherits management from cluster: "+clusterMgmt.Evidence)
			}

			if s.NetworkConfiguration != nil && s.NetworkConfiguration.AwsvpcConfiguration != nil {
				for _, sn := range s.NetworkConfiguration.AwsvpcConfiguration.Subnets {
					if vpc := c.subnetVPC[sn]; vpc != "" {
						n.VPCID, n.SubnetID = vpc, sn
						break
					}
				}
			}

			switch {
			case isFargate(s):
				n.Attrs["launch_type"] = "FARGATE"
				if ts, ok := taskSizeOf(aws.ToString(s.TaskDefinition)); ok {
					tasks := s.RunningCount
					if tasks == 0 {
						tasks = s.DesiredCount
					}
					split := engine.SplitTasks(int(tasks), providerShares(s))
					blended := engine.FargateBlendedTasks(split)
					n.MonthlyCost = engine.FargateMonthlyCost(ts.cpu, ts.mem, blended)
					n.Drivers = fargateDrivers(ts.cpu, ts.mem, ts.ephGiB, ts.arm, split)
					n.CostSource = engine.CostEstimated
					n.Evidence = append(n.Evidence, fmt.Sprintf("Fargate %d CPU units / %d MiB x %d task(s)%s",
						ts.cpu, ts.mem, tasks, describeSplit(split)))
				} else {
					n.CostSource = engine.CostNotAvailable
					n.Evidence = append(n.Evidence, "task definition size unavailable, cost not estimated")
				}
			default:
				n.Attrs["launch_type"] = "EC2"
				n.CostSource = engine.CostNotAvailable
				n.Evidence = append(n.Evidence, "runs on cluster EC2 capacity, cost is in the instances")
			}
			if s.DesiredCount == 0 {
				n.Evidence = append(n.Evidence, "scaled to zero (no running tasks)")
			}

			c.add(n)
			c.link(clARN, id, "contains")
			for _, lb := range s.LoadBalancers {
				if tg := aws.ToString(lb.TargetGroupArn); tg != "" {
					c.addServiceTG(id, tg)
				}
			}
		}
	}
}

// providerShares reads the service's capacity provider strategy; with none,
// every task is plain on-demand Fargate.
func providerShares(s ecsTypes.Service) []engine.ProviderShare {
	var out []engine.ProviderShare
	for _, cp := range s.CapacityProviderStrategy {
		out = append(out, engine.ProviderShare{
			Name: aws.ToString(cp.CapacityProvider), Base: int(cp.Base), Weight: int(cp.Weight),
		})
	}
	if len(out) == 0 {
		out = []engine.ProviderShare{{Name: "FARGATE", Base: 0, Weight: 1}}
	}
	return out
}

func describeSplit(split map[string]float64) string {
	var spot, od float64
	for name, n := range split {
		if strings.Contains(strings.ToUpper(name), "SPOT") {
			spot += n
		} else {
			od += n
		}
	}
	if spot == 0 {
		return ""
	}
	return fmt.Sprintf(" (%.1f on-demand + %.1f spot at ~%.0f%% of price)", od, spot, engine.FargateSpotFactor*100)
}

func init() {
	register(Scanner{
		Name: "ecs", Desc: "ECS clusters/services, Fargate cost with Spot blend",
		Types:    map[string]string{"aws_ecs_cluster": "Amazon Elastic Container Service", "aws_ecs_service": "Amazon Elastic Container Service"},
		Regional: scanECS,
	})
}

// fargateDrivers are the monthly quantities Fargate bills by, split by
// pricing class (spot / on-demand, x86 / arm) the way the bill splits them.
// split gives the number of tasks per capacity provider.
func fargateDrivers(cpuUnits, memMiB, ephGiB int, arm bool, split map[string]float64) map[string]float64 {
	vcpu := float64(cpuUnits) / 1024
	gb := float64(memMiB) / 1024
	d := map[string]float64{}
	var total float64
	for name, tasks := range split {
		if tasks <= 0 {
			continue
		}
		total += tasks
		class := "od"
		if strings.Contains(strings.ToUpper(name), "SPOT") {
			class = "spot"
		}
		suffix := ""
		if arm {
			suffix = "_arm"
		}
		d["vcpu_h_"+class+suffix] += vcpu * engine.HoursPerMonth * tasks
		d["gb_h_"+class+suffix] += gb * engine.HoursPerMonth * tasks
	}
	if extra := ephGiB - 20; extra > 0 && total > 0 {
		d["eph_gb_h"] = float64(extra) * engine.HoursPerMonth * total
	}
	return d
}
