package aws

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

const s3Workers = 8

// scanS3 inventories buckets account-wide. S3 is listed once, not per
// region; each bucket is then inspected in its own region.
func scanS3(ctx context.Context, dc *DiscoveryClient, c *collector) {
	cfg, err := dc.loadConfig(ctx, "us-east-1")
	if err != nil {
		c.warn("s3:config", err)
		return
	}
	cli := s3.NewFromConfig(cfg)

	var buckets []s3Types.Bucket
	p := s3.NewListBucketsPaginator(cli, &s3.ListBucketsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("s3:list-buckets", err)
			return
		}
		buckets = append(buckets, page.Buckets...)
	}

	var (
		cfgMu  sync.Mutex
		cfgs   = map[string]aws.Config{}
		cfgFor = func(region string) (aws.Config, error) {
			cfgMu.Lock()
			defer cfgMu.Unlock()
			if cf, ok := cfgs[region]; ok {
				return cf, nil
			}
			cf, err := dc.loadConfig(ctx, region)
			if err == nil {
				cfgs[region] = cf
			}
			return cf, err
		}
		failMu sync.Mutex
		failed = map[string]int{} // api -> number of buckets it failed for
		wg     sync.WaitGroup
		sem    = make(chan struct{}, s3Workers)
	)
	fail := func(api string) {
		failMu.Lock()
		failed[api]++
		failMu.Unlock()
	}

	for _, b := range buckets {
		wg.Add(1)
		sem <- struct{}{}
		go func(b s3Types.Bucket) {
			defer wg.Done()
			defer func() { <-sem }()
			region := aws.ToString(b.BucketRegion)
			if region == "" {
				var err error
				if region, err = bucketRegion(ctx, cli, aws.ToString(b.Name)); err != nil {
					fail("location")
					return
				}
			}
			bcfg, err := cfgFor(region)
			if err != nil {
				fail("config")
				return
			}
			c.add(inspectBucket(ctx, s3.NewFromConfig(bcfg), cloudwatch.NewFromConfig(bcfg), aws.ToString(b.Name), region, dc.Th, fail))
		}(b)
	}
	wg.Wait()

	for api, n := range failed {
		c.warn("s3:"+api, fmt.Errorf("failed for %d of %d buckets", n, len(buckets)))
	}
}

func inspectBucket(ctx context.Context, cli *s3.Client, cw *cloudwatch.Client, name, region string, th Thresholds, fail func(string)) engine.ResourceNode {
	n := engine.ResourceNode{
		ID: "arn:aws:s3:::" + name, Name: name, Type: "aws_s3_bucket", Group: parseGroup(name),
		Region: region, CostSource: engine.CostEstimated, Attrs: map[string]string{},
	}

	tagsRead := true
	if out, err := cli.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: aws.String(name)}); err == nil {
		n.Tags = tagMap(out.TagSet, func(t s3Types.Tag) (string, string) { return aws.ToString(t.Key), aws.ToString(t.Value) })
	} else if !apiCode(err, "NoSuchTagSet") {
		fail("tagging")
		tagsRead = false
	}
	if tagsRead {
		applyManagement(&n)
	} else {
		// An unreadable tag set says nothing about ownership.
		n.Status, n.Confidence = engine.StatusUnknown, engine.ConfLow
		n.Evidence = append(n.Evidence, "tags could not be read, ownership not classified")
	}

	versioning := false
	if out, err := cli.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(name)}); err == nil {
		versioning = out.Status == s3Types.BucketVersioningStatusEnabled
	} else {
		fail("versioning")
	}
	lifecycle := false
	if out, err := cli.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(name)}); err == nil {
		lifecycle = len(out.Rules) > 0
	} else if !apiCode(err, "NoSuchLifecycleConfiguration") {
		fail("lifecycle")
	}
	n.Attrs["versioning"] = fmt.Sprint(versioning)
	n.Attrs["lifecycle"] = fmt.Sprint(lifecycle)
	if pab, ok := publicAccessBlock(ctx, cli, name, fail); ok {
		n.Attrs["public_access_block"] = fmt.Sprint(pab)
	}
	if ps, err := cli.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: aws.String(name)}); err == nil && ps.PolicyStatus != nil {
		n.Attrs["policy_public"] = fmt.Sprint(aws.ToBool(ps.PolicyStatus.IsPublic))
	} else if err != nil && !apiCode(err, "NoSuchBucketPolicy") {
		fail("policystatus")
	}

	size, ok := bucketSizeBytes(ctx, cw, name)
	if !ok {
		n.Evidence = append(n.Evidence, "no size metric (new or empty bucket); cost not estimated")
		n.CostSource = engine.CostNotAvailable
		return n
	}
	gbSize := size / (1 << 30)
	n.MonthlyCost = engine.S3MonthlyCost(gbSize)
	n.Attrs["standard_gb"] = fmt.Sprintf("%.1f", gbSize)
	n.Drivers = map[string]float64{"gb_std": gbSize}
	n.Evidence = append(n.Evidence, "Standard storage class only; other classes and requests not included")
	if gbSize >= th.S3NoLifecycleGB && !lifecycle {
		n.Evidence = append(n.Evidence, fmt.Sprintf("%.0f GB with no lifecycle rules", gbSize))
		if versioning {
			n.Evidence = append(n.Evidence, "versioning enabled without lifecycle: old versions accumulate")
		}
	}
	return n
}

// bucketSizeBytes returns the latest daily StandardStorage size.
func bucketSizeBytes(ctx context.Context, cw *cloudwatch.Client, bucket string) (float64, bool) {
	end := time.Now().UTC()
	out, err := cw.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace: aws.String("AWS/S3"), MetricName: aws.String("BucketSizeBytes"),
		Dimensions: []cwTypes.Dimension{
			{Name: aws.String("BucketName"), Value: aws.String(bucket)},
			{Name: aws.String("StorageType"), Value: aws.String("StandardStorage")},
		},
		StartTime: aws.Time(end.AddDate(0, 0, -3)), EndTime: aws.Time(end),
		Period: aws.Int32(86400), Statistics: []cwTypes.Statistic{cwTypes.StatisticAverage},
	})
	if err != nil || len(out.Datapoints) == 0 {
		return 0, false
	}
	latest := out.Datapoints[0]
	for _, d := range out.Datapoints[1:] {
		if d.Timestamp != nil && latest.Timestamp != nil && d.Timestamp.After(*latest.Timestamp) {
			latest = d
		}
	}
	return aws.ToFloat64(latest.Average), true
}

func apiCode(err error, code string) bool {
	var ae smithy.APIError
	return errors.As(err, &ae) && ae.ErrorCode() == code
}

// bucketRegion resolves a bucket's region. GetBucketLocation answers from any
// region; an empty constraint means us-east-1 and "EU" is the legacy eu-west-1.
func bucketRegion(ctx context.Context, cli *s3.Client, bucket string) (string, error) {
	out, err := cli.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(bucket)})
	if err != nil {
		return "", err
	}
	switch loc := string(out.LocationConstraint); loc {
	case "":
		return "us-east-1", nil
	case "EU":
		return "eu-west-1", nil
	default:
		return loc, nil
	}
}

func init() {
	register(Scanner{
		Name: "s3", Desc: "S3 buckets: size, lifecycle, versioning, tags (account-wide)",
		Types:  map[string]string{"aws_s3_bucket": "Amazon Simple Storage Service"},
		Global: scanS3,
	})
}

// publicAccessBlock reports whether all four Block Public Access settings
// are on for the bucket. A bucket with no configuration has them off.
func publicAccessBlock(ctx context.Context, cli *s3.Client, name string, fail func(string)) (bool, bool) {
	out, err := cli.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(name)})
	if err != nil {
		if apiCode(err, "NoSuchPublicAccessBlockConfiguration") {
			return false, true
		}
		fail("publicaccessblock")
		return false, false
	}
	c := out.PublicAccessBlockConfiguration
	if c == nil {
		return false, true
	}
	return aws.ToBool(c.BlockPublicAcls) && aws.ToBool(c.IgnorePublicAcls) &&
		aws.ToBool(c.BlockPublicPolicy) && aws.ToBool(c.RestrictPublicBuckets), true
}
