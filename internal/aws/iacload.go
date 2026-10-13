package aws

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"infralens/internal/engine"
	"infralens/internal/iac"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfnTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ---- Terraform state ---------------------------------------------------------

const (
	maxStateFiles   = 600
	stateFileSuffix = ".tfstate"
)

// TerraformResult is what reading the state sources produced.
type TerraformResult struct {
	Refs    []engine.IaCRef
	Files   int
	Sources []string
	Notes   []string
}

type s3Reader interface {
	s3.ListObjectsV2APIClient
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// LoadTerraformState reads state from each spec: a file, a directory, or an
// s3://bucket[/prefix]. Reading is explicit; nothing is fetched unless the
// caller named it, because state is sensitive.
func (dc *DiscoveryClient) LoadTerraformState(ctx context.Context, specs []string) TerraformResult {
	var out TerraformResult
	for _, spec := range specs {
		out.Sources = append(out.Sources, "terraform: "+spec)
		switch {
		case strings.HasPrefix(spec, "s3://"):
			bucket, prefix, _ := strings.Cut(strings.TrimPrefix(spec, "s3://"), "/")
			region, err := dc.bucketRegionFor(ctx, bucket)
			if err != nil {
				out.Notes = append(out.Notes, fmt.Sprintf("%s: cannot find the bucket's region: %s", spec, oneLineErr(err)))
				continue
			}
			cfg, err := dc.loadConfig(ctx, region)
			if err != nil {
				out.Notes = append(out.Notes, fmt.Sprintf("%s: %s", spec, oneLineErr(err)))
				continue
			}
			loadS3State(ctx, s3.NewFromConfig(cfg), bucket, prefix, &out)
		default:
			loadLocalState(spec, &out)
		}
	}
	return out
}

func (dc *DiscoveryClient) bucketRegionFor(ctx context.Context, bucket string) (string, error) {
	cfg, err := dc.loadConfig(ctx, "us-east-1")
	if err != nil {
		return "", err
	}
	return bucketRegion(ctx, s3.NewFromConfig(cfg), bucket)
}

func loadS3State(ctx context.Context, api s3Reader, bucket, prefix string, out *TerraformResult) {
	p := s3.NewListObjectsV2Paginator(api, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(prefix)})
	var keys []string
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			out.Notes = append(out.Notes, fmt.Sprintf("s3://%s/%s: %s", bucket, prefix, oneLineErr(err)))
			return
		}
		for _, o := range page.Contents {
			k := aws.ToString(o.Key)
			if strings.HasSuffix(k, stateFileSuffix) && aws.ToInt64(o.Size) > 0 {
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	if len(keys) > maxStateFiles {
		out.Notes = append(out.Notes, fmt.Sprintf("s3://%s: %d state files found, the first %d were read", bucket, len(keys), maxStateFiles))
		keys = keys[:maxStateFiles]
	}
	for _, k := range keys {
		obj, err := api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(k)})
		if err != nil {
			out.Notes = append(out.Notes, fmt.Sprintf("s3://%s/%s: %s", bucket, k, oneLineErr(err)))
			continue
		}
		refs, perr := iac.ParseState(obj.Body, k)
		_, _ = io.Copy(io.Discard, io.LimitReader(obj.Body, 1<<20))
		obj.Body.Close()
		if perr != nil {
			out.Notes = append(out.Notes, oneLineErr(perr))
			continue
		}
		out.Files++
		out.Refs = append(out.Refs, refs...)
	}
}

func loadLocalState(spec string, out *TerraformResult) {
	st, err := os.Stat(spec)
	if err != nil {
		out.Notes = append(out.Notes, fmt.Sprintf("%s: %s", spec, err))
		return
	}
	var files []string
	if st.IsDir() {
		_ = filepath.WalkDir(spec, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, stateFileSuffix) && len(files) < maxStateFiles {
				files = append(files, p)
			}
			return nil
		})
	} else {
		files = []string{spec}
	}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			out.Notes = append(out.Notes, err.Error())
			continue
		}
		refs, perr := iac.ParseState(fh, f)
		fh.Close()
		if perr != nil {
			out.Notes = append(out.Notes, oneLineErr(perr))
			continue
		}
		out.Files++
		out.Refs = append(out.Refs, refs...)
	}
}

// ---- CloudFormation ----------------------------------------------------------

type cfnAPI interface {
	cloudformation.ListStacksAPIClient
	cloudformation.ListStackResourcesAPIClient
}

func scanCloudFormation(ctx context.Context, cfg aws.Config, c *collector) {
	cloudFormationWith(ctx, cloudformation.NewFromConfig(cfg), c)
}

func cloudFormationWith(ctx context.Context, api cfnAPI, c *collector) {
	live := []cfnTypes.StackStatus{
		cfnTypes.StackStatusCreateComplete, cfnTypes.StackStatusUpdateComplete,
		cfnTypes.StackStatusUpdateRollbackComplete, cfnTypes.StackStatusRollbackComplete,
		cfnTypes.StackStatusImportComplete, cfnTypes.StackStatusImportRollbackComplete,
		cfnTypes.StackStatusUpdateCompleteCleanupInProgress,
	}
	p := cloudformation.NewListStacksPaginator(api, &cloudformation.ListStacksInput{StackStatusFilter: live})
	type stack struct{ name, id, drift string }
	var stacks []stack
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("cloudformation:stacks", err)
			return
		}
		for _, s := range page.StackSummaries {
			d := ""
			if s.DriftInformation != nil {
				d = string(s.DriftInformation.StackDriftStatus)
			}
			stacks = append(stacks, stack{aws.ToString(s.StackName), aws.ToString(s.StackId), d})
		}
	}
	for _, s := range stacks {
		c.stacks++
		rp := cloudformation.NewListStackResourcesPaginator(api, &cloudformation.ListStackResourcesInput{StackName: aws.String(s.id)})
		for rp.HasMorePages() {
			page, err := rp.NextPage(ctx)
			if err != nil {
				c.warn("cloudformation:resources", err)
				break
			}
			for _, r := range page.StackResourceSummaries {
				if _, ok := engine.IaCNodeType(aws.ToString(r.ResourceType)); !ok {
					continue
				}
				if r.ResourceStatus == cfnTypes.ResourceStatusDeleteComplete {
					continue
				}
				id := aws.ToString(r.PhysicalResourceId)
				if id == "" {
					continue
				}
				c.iacRef(engine.IaCRef{
					Source: "cloudformation", Origin: s.name, Address: aws.ToString(r.LogicalResourceId),
					Type: aws.ToString(r.ResourceType), ID: id, Region: c.region, Drift: s.drift,
				})
			}
		}
	}
}

func init() {
	register(Scanner{
		Name: "cloudformation", Desc: "CloudFormation stacks: which resources they manage, and stack drift status",
		Informational: true, Regional: scanCloudFormation,
	})
}
