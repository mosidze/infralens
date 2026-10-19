package aws

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"

	"infralens/internal/engine"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/smithy-go/middleware"
)

type DiscoveryClient struct {
	Profile     string
	Concurrency int
	Scanners    []Scanner
	Th          Thresholds
	// Log receives every API call; it is also where the read-only guard
	// reports a blocked operation. Never nil after NewDiscoveryClient.
	Log *APILog

	cred credResolver
}

func NewDiscoveryClient(profile string, concurrency int) *DiscoveryClient {
	if concurrency < 1 {
		concurrency = 4
	}
	return &DiscoveryClient{Profile: profile, Concurrency: concurrency, Scanners: Scanners(), Th: DefaultThresholds(), Log: NewAPILog(nil, profile)}
}

func (dc *DiscoveryClient) loadConfig(ctx context.Context, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{}
	if dc.Log != nil {
		opts = append(opts, config.WithAPIOptions([]func(*middleware.Stack) error{dc.Log.apiOption()}))
	}
	if dc.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(dc.Profile))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	if p := dc.credentials(ctx); p != nil {
		opts = append(opts, config.WithCredentialsProvider(p))
	}
	return config.LoadDefaultConfig(ctx, opts...)
}

// Config returns an SDK configuration for a region with the read-only guard
// and the profile's credentials, for callers outside this package that make
// their own read calls (the live monitor).
func (dc *DiscoveryClient) Config(ctx context.Context, region string) (aws.Config, error) {
	return dc.loadConfig(ctx, region)
}

func (dc *DiscoveryClient) RunSSOLogin(ctx context.Context) error {
	args := []string{"sso", "login"}
	if dc.Profile != "" {
		args = append(args, "--profile", dc.Profile)
	}
	if out, err := exec.CommandContext(ctx, "aws", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("sso login failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// GetActiveRegions lists regions enabled for the account.
func (dc *DiscoveryClient) GetActiveRegions(ctx context.Context) ([]string, error) {
	cfg, err := dc.loadConfig(ctx, "us-east-1")
	if err != nil {
		return nil, err
	}
	out, err := ec2.NewFromConfig(cfg).DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(false)})
	if err != nil {
		return nil, err
	}
	regs := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		regs = append(regs, aws.ToString(r.RegionName))
	}
	sort.Strings(regs)
	return regs, nil
}

// collector gathers results from the per-service scanners of one region.
type collector struct {
	mu       sync.Mutex
	region   string
	th       Thresholds
	nodes    []engine.ResourceNode
	edges    []engine.Edge
	warnings []string
	commits  []engine.Commitment
	skipped  []string
	findings []engine.Finding
	iacrefs  []engine.IaCRef
	stacks   int
	// subnetVPC maps subnet ID to VPC ID; filled before the scanners run.
	subnetVPC map[string]string
	// tgToLB maps target group ARN to load balancer ARN.
	tgToLB map[string]string
	// svcToTG lists ECS service ID -> target group ARNs, resolved at the end.
	svcToTG map[string][]string
}

func newCollector(region string, th Thresholds) *collector {
	return &collector{
		region:    region,
		th:        th,
		subnetVPC: map[string]string{},
		tgToLB:    map[string]string{},
		svcToTG:   map[string][]string{},
	}
}

func (c *collector) add(n engine.ResourceNode) {
	if n.Region == "" {
		n.Region = c.region
	}
	c.mu.Lock()
	c.nodes = append(c.nodes, n)
	c.mu.Unlock()
}

func (c *collector) iacRef(r engine.IaCRef) {
	c.mu.Lock()
	c.iacrefs = append(c.iacrefs, r)
	c.mu.Unlock()
}

func (c *collector) finding(f engine.Finding) {
	c.mu.Lock()
	c.findings = append(c.findings, f)
	c.mu.Unlock()
}

func (c *collector) commit(cm engine.Commitment) {
	c.mu.Lock()
	c.commits = append(c.commits, cm)
	c.mu.Unlock()
}

func (c *collector) link(src, dst, label string) {
	c.mu.Lock()
	c.edges = append(c.edges, engine.Edge{Source: src, Target: dst, Label: label})
	c.mu.Unlock()
}

// notOffered reports an error that means the service has no endpoint in this
// region (its hostname does not resolve). That is a fact about the region, not
// a failure of the scan, so it is recorded apart from warnings.
func notOffered(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "no such host") || strings.Contains(m, "could not resolve host")
}

// skip records a check that did not apply (not subscribed, not enabled).
func (c *collector) skip(service, why string) {
	c.mu.Lock()
	c.skipped = append(c.skipped, fmt.Sprintf("%s: %s", service, why))
	c.mu.Unlock()
}

func (c *collector) warn(service string, err error) {
	if notOffered(err) {
		c.mu.Lock()
		c.skipped = append(c.skipped, fmt.Sprintf("%s: %s is not offered in this region", c.region, service))
		c.mu.Unlock()
		return
	}
	msg := strings.Join(strings.Fields(err.Error()), " ")
	if len(msg) > 220 {
		msg = msg[:220] + "..."
	}
	c.mu.Lock()
	c.warnings = append(c.warnings, fmt.Sprintf("%s/%s: %s", c.region, service, msg))
	c.mu.Unlock()
}

func (c *collector) setTGLB(tg, lb string) {
	c.mu.Lock()
	c.tgToLB[tg] = lb
	c.mu.Unlock()
}

func (c *collector) addServiceTG(svc, tg string) {
	c.mu.Lock()
	c.svcToTG[svc] = append(c.svcToTG[svc], tg)
	c.mu.Unlock()
}

// resolveLinks connects ECS services to the load balancers fronting them.
func (c *collector) resolveLinks() {
	for svc, tgs := range c.svcToTG {
		for _, tg := range tgs {
			if lb, ok := c.tgToLB[tg]; ok {
				c.edges = append(c.edges, engine.Edge{Source: lb, Target: svc, Label: "routes to"})
			}
		}
	}
}

// ScanResult is everything found in the account.
type ScanOutput struct {
	Nodes       []engine.ResourceNode
	Edges       []engine.Edge
	Warnings    []string
	Commitments []engine.Commitment
	// Skipped are checks that did not apply because the service does not
	// exist in the region. They are not failures.
	Skipped []string
	// Findings come from AWS-native services and own checks that are not
	// about a single resource node.
	Findings []engine.Finding
	// IaCRefs and Stacks come from CloudFormation; Terraform state is read
	// separately because it is sensitive and only read when asked for.
	IaCRefs []engine.IaCRef
	Stacks  int
}

// ScanAll scans regions in parallel, bounded by Concurrency.
func (dc *DiscoveryClient) ScanAll(ctx context.Context, regions []string) ScanOutput {
	var (
		out ScanOutput
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, dc.Concurrency)
	)
	global := newCollector("global", dc.Th)
	for _, sc := range dc.Scanners {
		if sc.Global == nil {
			continue
		}
		wg.Add(1)
		go func(sc Scanner) {
			defer wg.Done()
			sc.Global(ctx, dc, global)
		}(sc)
	}
	for _, region := range regions {
		wg.Add(1)
		sem <- struct{}{}
		go func(region string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := dc.ScanRegion(ctx, region)
			mu.Lock()
			out.Nodes = append(out.Nodes, r.Nodes...)
			out.Edges = append(out.Edges, r.Edges...)
			out.Warnings = append(out.Warnings, r.Warnings...)
			out.Commitments = append(out.Commitments, r.Commitments...)
			out.Skipped = append(out.Skipped, r.Skipped...)
			out.Findings = append(out.Findings, r.Findings...)
			out.IaCRefs = append(out.IaCRefs, r.IaCRefs...)
			out.Stacks += r.Stacks
			mu.Unlock()
		}(region)
	}
	wg.Wait()
	out.Nodes = append(out.Nodes, global.nodes...)
	out.Edges = append(out.Edges, global.edges...)
	out.Warnings = append(out.Warnings, global.warnings...)
	out.Commitments = append(out.Commitments, global.commits...)
	out.Skipped = append(out.Skipped, global.skipped...)
	out.Findings = append(out.Findings, global.findings...)
	sort.Strings(out.Skipped)
	sortCommitments(out.Commitments)
	sort.Strings(out.Warnings)
	return out
}

// ScanRegion runs every service scanner of one region.
func (dc *DiscoveryClient) ScanRegion(ctx context.Context, region string) ScanOutput {
	c := newCollector(region, dc.Th)
	cfg, err := dc.loadConfig(ctx, region)
	if err != nil {
		c.warn("config", err)
		return ScanOutput{Warnings: c.warnings}
	}

	// Subnets first: other scanners use them to place resources in a VPC.
	scanSubnets(ctx, cfg, c)

	var wg sync.WaitGroup
	for _, sc := range dc.Scanners {
		if sc.Regional == nil {
			continue
		}
		wg.Add(1)
		go func(sc Scanner) {
			defer wg.Done()
			sc.Regional(ctx, cfg, c)
		}(sc)
	}
	wg.Wait()
	c.resolveLinks()

	return ScanOutput{Nodes: c.nodes, Edges: c.edges, Warnings: c.warnings, Commitments: c.commits, Skipped: c.skipped, Findings: c.findings, IaCRefs: c.iacrefs, Stacks: c.stacks}
}

func scanSubnets(ctx context.Context, cfg aws.Config, c *collector) {
	p := ec2.NewDescribeSubnetsPaginator(ec2.NewFromConfig(cfg), &ec2.DescribeSubnetsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			c.warn("ec2:subnets", err)
			return
		}
		for _, s := range page.Subnets {
			c.subnetVPC[aws.ToString(s.SubnetId)] = aws.ToString(s.VpcId)
		}
	}
}

// applyManagement fills status/managed_by/evidence from the node's tags.
func applyManagement(n *engine.ResourceNode) {
	cl := engine.ClassifyManagement(n.Tags)
	n.Status = cl.Status
	n.ManagedBy = cl.ManagedBy
	n.Confidence = cl.Confidence
	n.Evidence = append(n.Evidence, cl.Evidence)
}

// markWaste flips a node to orphan_waste, keeping the earlier evidence.
func markWaste(n *engine.ResourceNode, reason string, conf engine.Confidence, evidence ...string) {
	n.Status = engine.StatusOrphanWaste
	n.WasteReason = reason
	n.Confidence = conf
	n.Evidence = append(n.Evidence, evidence...)
}

func tagMap[T any](tags []T, kv func(T) (string, string)) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		k, v := kv(t)
		m[k] = v
	}
	return m
}

func nameOr(tags map[string]string, fallback string) string {
	if v := tags["Name"]; v != "" {
		return v
	}
	return fallback
}

func parseGroup(name string) string {
	parts := strings.Split(name, "-")
	if len(parts) > 1 && len(parts[0]) >= 2 {
		return strings.ToUpper(parts[0])
	}
	return "SHARED"
}

func lastSegment(arn string) string {
	return arn[strings.LastIndex(arn, "/")+1:]
}
