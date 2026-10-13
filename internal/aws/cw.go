package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

type metricQuery struct {
	namespace, metric string
	dims              map[string]string
	stat              cwTypes.Statistic
	days              int
}

// metricTotal returns the aggregate of a daily metric over the idle window
// (sum for Sum, max for Maximum) and how many datapoints back it.
// metricsAPI is the part of the CloudWatch client the scanners use, so that
// tests can answer with canned datapoints.
type metricsAPI interface {
	GetMetricStatistics(ctx context.Context, in *cloudwatch.GetMetricStatisticsInput, opts ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error)
}

func metricTotal(ctx context.Context, cli metricsAPI, q metricQuery) (value float64, points int, err error) {
	var dims []cwTypes.Dimension
	for k, v := range q.dims {
		dims = append(dims, cwTypes.Dimension{Name: aws.String(k), Value: aws.String(v)})
	}
	if q.days < 1 {
		q.days = 14
	}
	end := time.Now().UTC()
	out, err := cli.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String(q.namespace),
		MetricName: aws.String(q.metric),
		Dimensions: dims,
		StartTime:  aws.Time(end.AddDate(0, 0, -q.days)),
		EndTime:    aws.Time(end),
		Period:     aws.Int32(86400),
		Statistics: []cwTypes.Statistic{q.stat},
	})
	if err != nil {
		return 0, 0, err
	}
	for _, dp := range out.Datapoints {
		switch q.stat {
		case cwTypes.StatisticSum:
			value += aws.ToFloat64(dp.Sum)
		case cwTypes.StatisticMaximum:
			if v := aws.ToFloat64(dp.Maximum); v > value {
				value = v
			}
		}
		points++
	}
	return value, points, nil
}
