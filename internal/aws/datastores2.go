package aws

import (
	"context"
	"fmt"
	"time"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/memorydb"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
)

// youngerThanWindow says whether a resource is too new for an idle verdict.
func youngerThanWindow(created *time.Time, days int) bool {
	return created != nil && time.Since(*created) < time.Duration(days)*24*time.Hour
}

// idleConfidence grades an "unused in the window" verdict: no measurements at
// all is weaker than measurements that are all zero, and a young resource
// cannot be called idle with confidence.
func idleConfidence(points int, created *time.Time, days int) engine.Confidence {
	switch {
	case youngerThanWindow(created, days):
		return engine.ConfLow
	case points == 0:
		return engine.ConfMedium
	}
	return engine.ConfHigh
}

// ---- Redshift -----------------------------------------------------------------

func scanRedshift(ctx context.Context, cfg aws.Config, c *collector) {
	scanRedshiftWith(ctx, redshift.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), c)
}

func scanRedshiftWith(ctx context.Context, api redshift.DescribeClustersAPIClient, cw metricDataAPI, c *collector) {
	p := redshift.NewDescribeClustersPaginator(api, &redshift.DescribeClustersInput{})
	var ids []string
	nodes := map[string]engine.ResourceNode{}
	created := map[string]*time.Time{}
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("redshift:clusters", err)
			return
		}
		for _, cl := range page.Clusters {
			id := aws.ToString(cl.ClusterIdentifier)
			tags := map[string]string{}
			for _, t := range cl.Tags {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			cnt := int(aws.ToInt32(cl.NumberOfNodes))
			cost, known := engine.RedshiftMonthlyCost(aws.ToString(cl.NodeType), cnt)
			n := engine.ResourceNode{
				ID: id, Name: id, Type: "aws_redshift_cluster", Group: "DATABASE", VPCID: aws.ToString(cl.VpcId),
				Tags: tags, MonthlyCost: cost, CostSource: engine.CostEstimated,
				Attrs: map[string]string{"node_type": aws.ToString(cl.NodeType), "nodes": fmt.Sprint(cnt), "status": aws.ToString(cl.ClusterStatus)},
			}
			applyManagement(&n)
			if !known {
				n.CostSource = engine.CostNotAvailable
				n.Evidence = append(n.Evidence, "price for "+aws.ToString(cl.NodeType)+" unknown, cost not estimated")
			}
			nodes[id] = n
			created[id] = cl.ClusterCreateTime
			if aws.ToString(cl.ClusterStatus) == "available" {
				ids = append(ids, id)
			}
		}
	}
	var qs []mq
	for _, id := range ids {
		qs = append(qs, mq{id, "AWS/Redshift", "DatabaseConnections", map[string]string{"ClusterIdentifier": id}, "Maximum"})
	}
	m, err := batchMetrics(ctx, cw, qs, c.th.IdleWindowDays)
	if err != nil {
		c.warn("cloudwatch:redshift", err)
	}
	for id, n := range nodes {
		if _, judged := containsStr(ids, id); judged && err == nil {
			a := m[id]
			if a.Value == 0 && a.Points > 0 || (a.Points == 0 && !youngerThanWindow(created[id], c.th.IdleWindowDays)) {
				markWaste(&n, "Redshift cluster without connections", idleConfidence(a.Points, created[id], c.th.IdleWindowDays),
					fmt.Sprintf("0 connections in %dd (%d datapoints)", c.th.IdleWindowDays, a.Points))
			} else {
				n.Evidence = append(n.Evidence, fmt.Sprintf("max %.0f connections in %dd", a.Value, c.th.IdleWindowDays))
			}
		}
		c.add(n)
	}
}

func containsStr(s []string, v string) (int, bool) {
	for i, x := range s {
		if x == v {
			return i, true
		}
	}
	return -1, false
}

// ---- MemoryDB -----------------------------------------------------------------

type memoryDBAPI interface {
	memorydb.DescribeClustersAPIClient
	ListTags(ctx context.Context, in *memorydb.ListTagsInput, opts ...func(*memorydb.Options)) (*memorydb.ListTagsOutput, error)
}

func scanMemoryDB(ctx context.Context, cfg aws.Config, c *collector) {
	scanMemoryDBWith(ctx, memorydb.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), c)
}

func scanMemoryDBWith(ctx context.Context, api memoryDBAPI, cw metricDataAPI, c *collector) {
	// Without ShowShardDetails the response carries no nodes at all, and a
	// cluster would silently be priced at $0.
	p := memorydb.NewDescribeClustersPaginator(api, &memorydb.DescribeClustersInput{ShowShardDetails: aws.Bool(true)})
	type item struct {
		n      engine.ResourceNode
		judged bool
	}
	var items []item
	var qs []mq
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("memorydb:clusters", err)
			return
		}
		for _, cl := range page.Clusters {
			name := aws.ToString(cl.Name)
			nodeCount := 0
			for _, s := range cl.Shards {
				nodeCount += len(s.Nodes)
			}
			cost, known := engine.MemoryDBMonthlyCost(aws.ToString(cl.NodeType), nodeCount)
			if nodeCount == 0 {
				known = false // node count unknown is not "free"
			}
			var tags map[string]string
			if t, err := api.ListTags(ctx, &memorydb.ListTagsInput{ResourceArn: cl.ARN}); err == nil {
				tags = map[string]string{}
				for _, x := range t.TagList {
					tags[aws.ToString(x.Key)] = aws.ToString(x.Value)
				}
			}
			n := engine.ResourceNode{
				ID: aws.ToString(cl.ARN), Name: name, Type: "aws_memorydb_cluster", Group: "DATABASE", Tags: tags,
				MonthlyCost: cost, CostSource: engine.CostEstimated,
				Attrs: map[string]string{"node_type": aws.ToString(cl.NodeType), "nodes": fmt.Sprint(nodeCount),
					"shards": fmt.Sprint(aws.ToInt32(cl.NumberOfShards)), "status": aws.ToString(cl.Status)},
				Drivers: map[string]float64{"hours": float64(nodeCount) * engine.HoursPerMonth},
			}
			applyManagement(&n)
			switch {
			case nodeCount == 0:
				n.CostSource = engine.CostNotAvailable
				n.Evidence = append(n.Evidence, "node count not returned, cost not estimated")
			case !known:
				n.CostSource = engine.CostNotAvailable
				n.Evidence = append(n.Evidence, "price for "+aws.ToString(cl.NodeType)+" unknown, cost not estimated")
			default:
				n.Evidence = append(n.Evidence, "approximate list price; check against the bill")
			}
			judged := aws.ToString(cl.Status) == "available"
			items = append(items, item{n, judged})
			if judged {
				qs = append(qs, mq{name, "AWS/MemoryDB", "CurrConnections", map[string]string{"ClusterName": name}, "Maximum"})
			}
		}
	}
	m, err := batchMetrics(ctx, cw, qs, c.th.IdleWindowDays)
	if err != nil {
		c.warn("cloudwatch:memorydb", err)
	}
	for _, it := range items {
		n := it.n
		if it.judged && err == nil {
			a := m[n.Name]
			switch {
			case a.Points == 0:
				n.Evidence = append(n.Evidence, "no connection metric returned; usage unknown")
			case a.Value == 0:
				markWaste(&n, "MemoryDB cluster without connections", engine.ConfMedium,
					fmt.Sprintf("0 connections in %dd (%d datapoints); replication traffic is not a client", c.th.IdleWindowDays, a.Points))
			default:
				n.Evidence = append(n.Evidence, fmt.Sprintf("max %.0f connections in %dd", a.Value, c.th.IdleWindowDays))
			}
		}
		c.add(n)
	}
}

// ---- ElastiCache ---------------------------------------------------------------

func scanElastiCache(ctx context.Context, cfg aws.Config, c *collector) {
	scanElastiCacheWith(ctx, elasticache.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), c)
}

func scanElastiCacheWith(ctx context.Context, api elasticache.DescribeCacheClustersAPIClient, cw metricDataAPI, c *collector) {
	p := elasticache.NewDescribeCacheClustersPaginator(api, &elasticache.DescribeCacheClustersInput{})
	type item struct {
		n      engine.ResourceNode
		judged bool
		id     string
		born   *time.Time
	}
	var items []item
	var qs []mq
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("elasticache:clusters", err)
			return
		}
		for _, cl := range page.CacheClusters {
			id := aws.ToString(cl.CacheClusterId)
			cnt := int(aws.ToInt32(cl.NumCacheNodes))
			cost, known := engine.ElastiCacheMonthlyCost(aws.ToString(cl.CacheNodeType), cnt)
			n := engine.ResourceNode{
				ID: aws.ToString(cl.ARN), Name: id, Type: "aws_elasticache_cluster", Group: "DATABASE",
				MonthlyCost: cost, CostSource: engine.CostEstimated,
				Attrs: map[string]string{"node_type": aws.ToString(cl.CacheNodeType), "nodes": fmt.Sprint(cnt),
					"engine": aws.ToString(cl.Engine), "status": aws.ToString(cl.CacheClusterStatus)},
				Drivers: map[string]float64{"hours": float64(cnt) * engine.HoursPerMonth},
			}
			if n.ID == "" {
				n.ID = id
			}
			// tags are not read here: ElastiCache needs one call per ARN and the
			// type is classified from the replication group when there is one
			applyManagement(&n)
			n.Evidence = append(n.Evidence, "tags not read for ElastiCache; ownership not classified")
			if !known {
				n.CostSource = engine.CostNotAvailable
				n.Evidence = append(n.Evidence, "price for "+aws.ToString(cl.CacheNodeType)+" unknown, cost not estimated")
			}
			// Replicas and members of a replication group see replication
			// links as connections; judging them by connections is unsound.
			standalone := aws.ToString(cl.ReplicationGroupId) == ""
			if !standalone {
				n.Attrs["replication_group"] = aws.ToString(cl.ReplicationGroupId)
				n.Evidence = append(n.Evidence, "member of replication group "+aws.ToString(cl.ReplicationGroupId)+": idle not judged")
			}
			judged := standalone && aws.ToString(cl.CacheClusterStatus) == "available"
			items = append(items, item{n, judged, id, cl.CacheClusterCreateTime})
			if judged {
				qs = append(qs, mq{id, "AWS/ElastiCache", "CurrConnections", map[string]string{"CacheClusterId": id}, "Maximum"})
			}
		}
	}
	m, err := batchMetrics(ctx, cw, qs, c.th.IdleWindowDays)
	if err != nil {
		c.warn("cloudwatch:elasticache", err)
	}
	for _, it := range items {
		n := it.n
		if it.judged && err == nil {
			a := m[it.id]
			switch {
			case a.Points == 0:
				n.Evidence = append(n.Evidence, "no connection metric returned; usage unknown")
			case a.Value <= 1: // the monitoring connection of a standalone node
				markWaste(&n, "ElastiCache cluster without client connections", idleConfidence(a.Points, it.born, c.th.IdleWindowDays),
					fmt.Sprintf("max %.0f connection(s) in %dd", a.Value, c.th.IdleWindowDays))
			default:
				n.Evidence = append(n.Evidence, fmt.Sprintf("max %.0f connections in %dd", a.Value, c.th.IdleWindowDays))
			}
		}
		c.add(n)
	}
}

// ---- DynamoDB -----------------------------------------------------------------

type dynamoAPI interface {
	dynamodb.ListTablesAPIClient
	DescribeTable(ctx context.Context, in *dynamodb.DescribeTableInput, opts ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	ListTagsOfResource(ctx context.Context, in *dynamodb.ListTagsOfResourceInput, opts ...func(*dynamodb.Options)) (*dynamodb.ListTagsOfResourceOutput, error)
}

func scanDynamoDB(ctx context.Context, cfg aws.Config, c *collector) {
	scanDynamoDBWith(ctx, dynamodb.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), c)
}

func scanDynamoDBWith(ctx context.Context, api dynamoAPI, cw metricDataAPI, c *collector) {
	p := dynamodb.NewListTablesPaginator(api, &dynamodb.ListTablesInput{})
	var names []string
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("dynamodb:tables", err)
			return
		}
		names = append(names, page.TableNames...)
	}
	if len(names) == 0 {
		return
	}
	var qs []mq
	for _, t := range names {
		d := map[string]string{"TableName": t}
		qs = append(qs,
			mq{"r/" + t, "AWS/DynamoDB", "ConsumedReadCapacityUnits", d, "Sum"},
			mq{"w/" + t, "AWS/DynamoDB", "ConsumedWriteCapacityUnits", d, "Sum"})
	}
	m, merr := batchMetrics(ctx, cw, qs, c.th.IdleWindowDays)
	if merr != nil {
		c.warn("cloudwatch:dynamodb", merr)
	}
	for _, t := range names {
		d, err := api.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(t)})
		if err != nil {
			c.warn("dynamodb:describe", err)
			continue
		}
		td := d.Table
		if td == nil {
			continue
		}
		provisioned := td.BillingModeSummary == nil || string(td.BillingModeSummary.BillingMode) != "PAY_PER_REQUEST"
		var rcu, wcu int64
		if td.ProvisionedThroughput != nil {
			rcu, wcu = aws.ToInt64(td.ProvisionedThroughput.ReadCapacityUnits), aws.ToInt64(td.ProvisionedThroughput.WriteCapacityUnits)
		}
		if rcu == 0 && wcu == 0 {
			provisioned = false
		}
		var tags map[string]string
		if tl, err := api.ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{ResourceArn: td.TableArn}); err == nil {
			tags = map[string]string{}
			for _, x := range tl.Tags {
				tags[aws.ToString(x.Key)] = aws.ToString(x.Value)
			}
		}
		mode := "on-demand"
		if provisioned {
			mode = "provisioned"
		}
		n := engine.ResourceNode{
			ID: aws.ToString(td.TableArn), Name: t, Type: "aws_dynamodb_table", Group: parseGroup(t), Tags: tags,
			MonthlyCost: engine.DynamoDBMonthlyCost(provisioned, rcu, wcu, aws.ToInt64(td.TableSizeBytes)), CostSource: engine.CostEstimated,
			Attrs: map[string]string{"billing": mode, "rcu": fmt.Sprint(rcu), "wcu": fmt.Sprint(wcu),
				"size_gb": fmt.Sprintf("%.1f", float64(aws.ToInt64(td.TableSizeBytes))/(1<<30))},
			Drivers: map[string]float64{"gb": float64(aws.ToInt64(td.TableSizeBytes)) / (1 << 30)},
		}
		if provisioned {
			n.Drivers["rcu_h"] = float64(rcu) * engine.HoursPerMonth
			n.Drivers["wcu_h"] = float64(wcu) * engine.HoursPerMonth
		}
		applyManagement(&n)
		if !provisioned {
			n.Evidence = append(n.Evidence, "on-demand: request charges depend on traffic and are not included")
		}
		if merr == nil {
			scale := 30 / float64(c.th.IdleWindowDays)
			n.Drivers["r_units"] = m["r/"+t].Value * scale
			n.Drivers["w_units"] = m["w/"+t].Value * scale
			use := m["r/"+t].Value + m["w/"+t].Value
			pts := m["r/"+t].Points + m["w/"+t].Points
			switch {
			case use > 0:
				n.Evidence = append(n.Evidence, fmt.Sprintf("%.0f capacity units consumed in %dd", use, c.th.IdleWindowDays))
			case provisioned:
				// DynamoDB emits no datapoints when nothing is consumed, so
				// "none returned" is the expected shape of an idle table.
				markWaste(&n, "Provisioned DynamoDB table without consumption", idleConfidence(pts, td.CreationDateTime, c.th.IdleWindowDays),
					fmt.Sprintf("no read or write capacity consumed in %dd while %d RCU / %d WCU are provisioned", c.th.IdleWindowDays, rcu, wcu))
			default:
				n.Evidence = append(n.Evidence, fmt.Sprintf("no consumption in %dd (on-demand: only storage is billed)", c.th.IdleWindowDays))
			}
		}
		c.add(n)
	}
}

func init() {
	register(Scanner{
		Name: "redshift", Desc: "Redshift clusters: node cost, clusters without connections",
		Types: map[string]string{"aws_redshift_cluster": "Amazon Redshift"}, Regional: scanRedshift,
	})
	register(Scanner{
		Name: "memorydb", Desc: "MemoryDB clusters: node cost, clusters without connections",
		Types: map[string]string{"aws_memorydb_cluster": "Amazon MemoryDB"}, Regional: scanMemoryDB,
	})
	register(Scanner{
		Name: "elasticache", Desc: "ElastiCache clusters: node cost, standalone clusters without connections",
		Types: map[string]string{"aws_elasticache_cluster": "Amazon ElastiCache"}, Regional: scanElastiCache,
	})
	register(Scanner{
		Name: "dynamodb", Desc: "DynamoDB tables: provisioned capacity, storage, tables without consumption",
		Types: map[string]string{"aws_dynamodb_table": "Amazon DynamoDB"}, Regional: scanDynamoDB,
	})
}
