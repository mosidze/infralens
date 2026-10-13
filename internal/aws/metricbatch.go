package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// metricDataAPI is what the batch reader needs from CloudWatch.
type metricDataAPI interface {
	cloudwatch.GetMetricDataAPIClient
}

// mq is one metric to read; Key identifies the result.
type mq struct {
	Key       string
	Namespace string
	Metric    string
	Dims      map[string]string
	Stat      string // Sum | Maximum | Average
}

// metricAgg is a metric over the window: the sum or maximum of its daily
// values, and how many datapoints back it. Points == 0 means "CloudWatch had
// nothing", which for several services means "no activity" and for others
// "not measured"; callers must say which.
type metricAgg struct {
	Value  float64
	Points int
}

// batchMetrics reads many metrics with GetMetricData (500 per call). It is
// the only efficient way to cover hundreds of functions or queues.
func batchMetrics(ctx context.Context, api metricDataAPI, qs []mq, days int) (map[string]metricAgg, error) {
	out := make(map[string]metricAgg, len(qs))
	if len(qs) == 0 {
		return out, nil
	}
	if days < 1 {
		days = 14
	}
	end := time.Now().UTC().Truncate(time.Hour)
	start := end.AddDate(0, 0, -days)
	for i := 0; i < len(qs); i += 500 {
		batch := qs[i:min(i+500, len(qs))]
		queries := make([]cwTypes.MetricDataQuery, len(batch))
		for j, q := range batch {
			var dims []cwTypes.Dimension
			for k, v := range q.Dims {
				dims = append(dims, cwTypes.Dimension{Name: aws.String(k), Value: aws.String(v)})
			}
			queries[j] = cwTypes.MetricDataQuery{
				Id: aws.String(fmt.Sprintf("q%d", j)),
				MetricStat: &cwTypes.MetricStat{
					Metric: &cwTypes.Metric{Namespace: aws.String(q.Namespace), MetricName: aws.String(q.Metric), Dimensions: dims},
					Period: aws.Int32(86400), Stat: aws.String(q.Stat),
				},
				ReturnData: aws.Bool(true),
			}
		}
		p := cloudwatch.NewGetMetricDataPaginator(api, &cloudwatch.GetMetricDataInput{
			StartTime: aws.Time(start), EndTime: aws.Time(end), MetricDataQueries: queries,
		})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return out, err
			}
			for _, r := range page.MetricDataResults {
				var j int
				if _, err := fmt.Sscanf(aws.ToString(r.Id), "q%d", &j); err != nil || j >= len(batch) {
					continue
				}
				q := batch[j]
				a := out[q.Key]
				for _, v := range r.Values {
					switch q.Stat {
					case "Maximum":
						if v > a.Value {
							a.Value = v
						}
					default:
						a.Value += v
					}
					a.Points++
				}
				out[q.Key] = a
			}
		}
	}
	return out, nil
}
