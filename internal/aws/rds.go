package aws

import (
	"context"
	"fmt"
	"time"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// clusterRole describes an instance's place in an Aurora cluster.
type clusterRole struct {
	cluster  string
	writer   bool
	members  int
	endpoint string
	reader   string
}

// isStandbyReader is true for a non-writer member of a multi-instance
// cluster. Such readers are failover targets: zero connections is by design
// and says nothing about waste.
func isStandbyReader(r clusterRole, inCluster bool) bool {
	return inCluster && !r.writer && r.members > 1
}

// rdsAPI is what the RDS scanner needs from the SDK.
type rdsAPI interface {
	rds.DescribeDBInstancesAPIClient
	rds.DescribeDBClustersAPIClient
}

func clusterRoles(ctx context.Context, cli rds.DescribeDBClustersAPIClient) (map[string]clusterRole, error) {
	roles := map[string]clusterRole{}
	p := rds.NewDescribeDBClustersPaginator(cli, &rds.DescribeDBClustersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return roles, err
		}
		for _, cl := range page.DBClusters {
			for _, m := range cl.DBClusterMembers {
				roles[aws.ToString(m.DBInstanceIdentifier)] = clusterRole{
					cluster:  aws.ToString(cl.DBClusterIdentifier),
					writer:   aws.ToBool(m.IsClusterWriter),
					members:  len(cl.DBClusterMembers),
					endpoint: aws.ToString(cl.Endpoint),
					reader:   aws.ToString(cl.ReaderEndpoint),
				}
			}
		}
	}
	return roles, nil
}

func scanRDS(ctx context.Context, cfg aws.Config, c *collector) {
	scanRDSWith(ctx, rds.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), c)
}

func scanRDSWith(ctx context.Context, cli rdsAPI, cw metricsAPI, c *collector) {
	roles, rolesErr := clusterRoles(ctx, cli)
	if rolesErr != nil {
		// Without roles an idle standby could be mistaken for waste, so the
		// idle check is skipped for every instance.
		c.warn("rds:clusters (idle check skipped)", rolesErr)
	}
	p := rds.NewDescribeDBInstancesPaginator(cli, &rds.DescribeDBInstancesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("rds:instances", err)
			return
		}
		for _, db := range page.DBInstances {
			id := aws.ToString(db.DBInstanceIdentifier)
			tags := tagMap(db.TagList, func(t rdsTypes.Tag) (string, string) {
				return aws.ToString(t.Key), aws.ToString(t.Value)
			})
			storage := aws.ToInt32(db.AllocatedStorage)
			multi := aws.ToBool(db.MultiAZ)
			cost, known := engine.EstimateRDSCost(aws.ToString(db.DBInstanceClass), storage, multi, aws.ToString(db.StorageType))

			n := engine.ResourceNode{
				ID: id, Name: id, Type: "aws_rds_instance", Group: "DATABASE",
				MonthlyCost: cost, CostSource: engine.CostEstimated, Tags: tags,
				Attrs: map[string]string{
					"class": aws.ToString(db.DBInstanceClass), "engine": aws.ToString(db.Engine),
					"status": aws.ToString(db.DBInstanceStatus), "storage_gb": fmt.Sprint(storage),
					"multi_az": fmt.Sprint(multi),
				},
			}
			if db.DBSubnetGroup != nil {
				n.VPCID = aws.ToString(db.DBSubnetGroup.VpcId)
			}
			applyManagement(&n)
			if !known {
				n.Evidence = append(n.Evidence, "price for "+aws.ToString(db.DBInstanceClass)+" unknown, flat estimate used")
			}

			role, inCluster := roles[id]
			n.Attrs["public"] = fmt.Sprint(aws.ToBool(db.PubliclyAccessible))
			n.Attrs["encrypted"] = fmt.Sprint(aws.ToBool(db.StorageEncrypted))
			n.Attrs["backup_days"] = fmt.Sprint(aws.ToInt32(db.BackupRetentionPeriod))
			n.Attrs["deletion_protection"] = fmt.Sprint(aws.ToBool(db.DeletionProtection))
			if aws.ToString(db.DBInstanceStatus) == "available" {
				n.Drivers = map[string]float64{"hours": engine.HoursPerMonth, "storage_gb": float64(storage)}
			}
			if db.Endpoint != nil {
				n.Attrs["endpoint"] = aws.ToString(db.Endpoint.Address)
			}
			if inCluster {
				n.Attrs["cluster_endpoint"] = role.endpoint
				n.Attrs["reader_endpoint"] = role.reader
				n.Attrs["cluster"] = role.cluster
				n.Attrs["role"] = map[bool]string{true: "writer", false: "reader"}[role.writer]
			}
			switch {
			case rolesErr != nil:
				n.Evidence = append(n.Evidence, "cluster roles unavailable: idle check skipped")
			case isStandbyReader(role, inCluster):
				n.Evidence = append(n.Evidence, fmt.Sprintf("reader/failover standby of cluster %s: idle by design, not judged", role.cluster))
			case aws.ToString(db.DBInstanceStatus) == "available":
				maxConns, points, err := metricTotal(ctx, cw, metricQuery{
					namespace: "AWS/RDS", metric: "DatabaseConnections",
					dims: map[string]string{"DBInstanceIdentifier": id}, stat: cwTypes.StatisticMaximum, days: c.th.IdleWindowDays,
				})
				if err != nil {
					c.warn("cloudwatch:rds", err)
					n.Evidence = append(n.Evidence, "CloudWatch unavailable: connections not checked")
				} else {
					age := time.Duration(1<<62 - 1)
					if db.InstanceCreateTime != nil {
						age = time.Since(*db.InstanceCreateTime)
					}
					v := rdsVerdict(maxConns, points, age, c.th)
					if v.Waste {
						markWaste(&n, "Database without connections", v.Confidence, v.Evidence)
					} else {
						n.Evidence = append(n.Evidence, v.Evidence)
					}
				}
			}
			c.add(n)
		}
	}
}

func init() {
	register(Scanner{
		Name: "rds", Desc: "RDS/Aurora instances, idle writers (readers are standbys)",
		Types:    map[string]string{"aws_rds_instance": "Amazon Relational Database Service"},
		Regional: scanRDS,
	})
}
