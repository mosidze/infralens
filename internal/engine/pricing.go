package engine

import (
	"fmt"
	"strings"
)

// Prices are on-demand us-east-1/eu-west-1 list prices, USD, 730 h/month.
// They are estimates: the report labels them as such and prefers Cost
// Explorer figures where those exist.
const (
	HoursPerMonth = 730.0

	NATGatewayHour   = 0.045
	PublicIPv4Hour   = 0.005
	EBSgp3GBMonth    = 0.08
	EBSgp2GBMonth    = 0.10
	EBSio1GBMonth    = 0.125
	EBSstGBMonth     = 0.045
	EBScoldGBMonth   = 0.015
	EBSMagGBMonth    = 0.05
	SnapshotGBMonth  = 0.05
	ALBHour          = 0.0225
	NLBHour          = 0.0225
	FargateVCPUHour  = 0.04048
	FargateGBHour    = 0.004445
	rdsStorageGBgp   = 0.115
	rdsStorageGBio1  = 0.125
	defaultEC2Hourly = 0.05
)

var ec2Hourly = map[string]float64{
	"t3.nano": 0.0052, "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416, "t3.large": 0.0832, "t3.xlarge": 0.1664, "t3.2xlarge": 0.3328,
	"t4g.nano": 0.0042, "t4g.micro": 0.0084, "t4g.small": 0.0168, "t4g.medium": 0.0336, "t4g.large": 0.0672, "t4g.xlarge": 0.1344,
	"m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384, "m6i.large": 0.096, "m6i.xlarge": 0.192, "m6g.large": 0.077, "m6g.xlarge": 0.154,
	"c5.large": 0.085, "c5.xlarge": 0.17, "c6i.large": 0.085, "c6g.large": 0.068,
	"r5.large": 0.126, "r5.xlarge": 0.252, "r6i.large": 0.126, "r6g.large": 0.1008,
}

var rdsHourly = map[string]float64{
	"db.t4g.micro": 0.016, "db.t3.micro": 0.017, "db.t4g.small": 0.032, "db.t3.small": 0.034,
	"db.t4g.medium": 0.065, "db.t3.medium": 0.068, "db.t4g.large": 0.129, "db.t3.large": 0.136,
	"db.m5.large": 0.171, "db.m6g.large": 0.152, "db.r5.large": 0.24, "db.r6g.large": 0.26,
	"db.r5.xlarge": 0.48, "db.r6g.xlarge": 0.52,
}

// EC2MonthlyCost estimates a running instance. Unknown types fall back to a
// flat guess and return known=false so callers can lower confidence.
func EC2MonthlyCost(instanceType string) (cost float64, known bool) {
	if h, ok := ec2Hourly[strings.ToLower(instanceType)]; ok {
		return h * HoursPerMonth, true
	}
	return defaultEC2Hourly * HoursPerMonth, false
}

// EstimateRDSCost estimates an RDS instance plus its storage.
func EstimateRDSCost(instanceClass string, storageGB int32, multiAZ bool, storageType string) (cost float64, known bool) {
	h, ok := rdsHourly[strings.ToLower(instanceClass)]
	if !ok {
		h = 0.2
	}
	compute := h * HoursPerMonth
	per := rdsStorageGBgp
	if strings.HasPrefix(storageType, "io") {
		per = rdsStorageGBio1
	}
	storage := float64(storageGB) * per
	if multiAZ {
		compute *= 2
		storage *= 2
	}
	return compute + storage, ok
}

// EBSMonthlyCost estimates a volume by type and size.
func EBSMonthlyCost(volumeType string, sizeGB int32) float64 {
	var per float64
	switch volumeType {
	case "gp3":
		per = EBSgp3GBMonth
	case "gp2":
		per = EBSgp2GBMonth
	case "io1", "io2":
		per = EBSio1GBMonth
	case "st1":
		per = EBSstGBMonth
	case "sc1":
		per = EBScoldGBMonth
	case "standard":
		per = EBSMagGBMonth
	default:
		per = EBSgp2GBMonth
	}
	return per * float64(sizeGB)
}

// FargateMonthlyCost estimates always-on tasks. cpuUnits is ECS CPU units
// (1024 = 1 vCPU), memMiB is in MiB.
func FargateMonthlyCost(cpuUnits, memMiB int, tasks float64) float64 {
	vcpu := float64(cpuUnits) / 1024
	gb := float64(memMiB) / 1024
	return (vcpu*FargateVCPUHour + gb*FargateGBHour) * HoursPerMonth * tasks
}

func MonthlyFromHourly(h float64) float64 { return h * HoursPerMonth }

// Money formats a dollar amount with thousands separators: $11,200.53.
func Money(v float64) string {
	neg := v < 0
	if neg {
		v = -v
	}
	s := fmt.Sprintf("%.2f", v)
	whole, frac := s[:len(s)-3], s[len(s)-3:]
	var b strings.Builder
	for i, r := range whole {
		if i > 0 && (len(whole)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	out := "$" + b.String() + frac
	if neg {
		out = "-" + out
	}
	return out
}

// OpenSearch on-demand instance-hour prices (estimates; reservations are
// invisible to the API and not accounted for).
var openSearchHourly = map[string]float64{
	"t3.small.search": 0.036, "t3.medium.search": 0.073,
	"c6g.large.search": 0.126, "c6g.xlarge.search": 0.252, "c6g.2xlarge.search": 0.504,
	"m6g.large.search": 0.159, "m6g.xlarge.search": 0.318,
	"r6g.large.search": 0.186, "r6g.xlarge.search": 0.372,
	"r7g.large.search": 0.195, "r7g.xlarge.search": 0.39,
}

const (
	openSearchEBSGBMonth = 0.122
	kinesisShardHour     = 0.015
	kinesisOnDemandHour  = 0.04
	LogIngestGB          = 0.54 // derived from Cost Explorer: 446 GB -> $241
	LogStorageGBMonth    = 0.03
	S3StandardGBMonth    = 0.023
)

// OpenSearchMonthlyCost estimates data nodes, dedicated masters and EBS.
func OpenSearchMonthlyCost(instanceType string, count int, masterType string, masterCount int, ebsGB int, ebsNodes int) (cost float64, known bool) {
	known = true
	price := func(t string) float64 {
		if h, ok := openSearchHourly[t]; ok {
			return h
		}
		known = false
		return 0.2
	}
	cost = price(instanceType) * float64(count) * HoursPerMonth
	if masterCount > 0 && masterType != "" {
		cost += price(masterType) * float64(masterCount) * HoursPerMonth
	}
	cost += float64(ebsGB) * float64(ebsNodes) * openSearchEBSGBMonth
	return cost, known
}

// KinesisMonthlyCost estimates the standing cost of a stream, not per-PUT usage.
func KinesisMonthlyCost(onDemand bool, shards int) float64 {
	if onDemand {
		return kinesisOnDemandHour * HoursPerMonth
	}
	return kinesisShardHour * float64(shards) * HoursPerMonth
}

func LogGroupMonthlyCost(ingestedGBPerMonth, storedGB float64) float64 {
	return ingestedGBPerMonth*LogIngestGB + storedGB*LogStorageGBMonth
}

func S3MonthlyCost(standardGB float64) float64 { return standardGB * S3StandardGBMonth }

// FargateSpotFactor is the typical Spot price relative to on-demand Fargate.
const FargateSpotFactor = 0.30

// NATDataGB is the NAT gateway data processing price per GB.
const NATDataGB = 0.045

// ProviderShare is one entry of an ECS capacity provider strategy.
type ProviderShare struct {
	Name   string
	Base   int
	Weight int
}

// SplitTasks distributes tasks over providers the way ECS does: bases are
// filled first in order, the rest is split by weight.
func SplitTasks(tasks int, ps []ProviderShare) map[string]float64 {
	out := map[string]float64{}
	remaining := float64(tasks)
	for _, p := range ps {
		take := float64(p.Base)
		if take > remaining {
			take = remaining
		}
		if take > 0 {
			out[p.Name] += take
			remaining -= take
		}
	}
	var totalWeight float64
	for _, p := range ps {
		totalWeight += float64(p.Weight)
	}
	if remaining > 0 && totalWeight > 0 {
		for _, p := range ps {
			out[p.Name] += remaining * float64(p.Weight) / totalWeight
		}
	} else if remaining > 0 && len(ps) > 0 {
		out[ps[0].Name] += remaining
	}
	return out
}

// FargateBlendedTasks returns task-equivalents at on-demand price: Spot
// tasks count FargateSpotFactor each.
func FargateBlendedTasks(split map[string]float64) float64 {
	var eq float64
	for name, n := range split {
		if strings.Contains(strings.ToUpper(name), "SPOT") {
			eq += n * FargateSpotFactor
		} else {
			eq += n
		}
	}
	return eq
}

// ---- additional services (list-price estimates; reservations not applied) -----

var redshiftNodeHourly = map[string]float64{
	"dc2.large": 0.25, "dc2.8xlarge": 4.80, "ra3.xlplus": 1.086, "ra3.4xlarge": 3.26, "ra3.16xlarge": 13.04,
}

var memoryDBNodeHourly = map[string]float64{
	"db.t4g.small": 0.07, "db.t4g.medium": 0.14, "db.r6g.large": 0.29, "db.r6g.xlarge": 0.58, "db.r6g.2xlarge": 1.16,
	"db.r7g.large": 0.31, "db.r7g.xlarge": 0.62,
}

var elastiCacheNodeHourly = map[string]float64{
	"cache.t4g.micro": 0.016, "cache.t4g.small": 0.032, "cache.t4g.medium": 0.065, "cache.t3.micro": 0.017,
	"cache.t3.small": 0.034, "cache.t3.medium": 0.068, "cache.m6g.large": 0.149, "cache.m6g.xlarge": 0.298,
	"cache.r6g.large": 0.206, "cache.r6g.xlarge": 0.411, "cache.r7g.large": 0.219,
}

const (
	VPCEndpointAZHour    = 0.01
	DynamoRCUHour        = 0.00013
	DynamoWCUHour        = 0.00065
	DynamoStorageGBMonth = 0.25
	DynamoFreeStorageGB  = 25.0
	LambdaGBSecond       = 0.0000166667
	LambdaGBSecondArm    = 0.0000133334
	LambdaPerMillionReq  = 0.20
	SQSPerMillionReq     = 0.40
	FirehosePerGB        = 0.029
	CloudFrontPerMillion = 1.0 // HTTPS requests, indicative; transfer not modelled
)

// NodeHourlyCost looks up a node-hour price. known=false means the type is
// missing from the table and the caller should say the figure is a guess.
func NodeHourlyCost(table map[string]float64, nodeType string, nodes int) (monthly float64, known bool) {
	h, ok := table[strings.ToLower(nodeType)]
	if !ok {
		return 0, false
	}
	return h * HoursPerMonth * float64(nodes), true
}

func RedshiftMonthlyCost(nodeType string, nodes int) (float64, bool) {
	return NodeHourlyCost(redshiftNodeHourly, nodeType, nodes)
}
func MemoryDBMonthlyCost(nodeType string, nodes int) (float64, bool) {
	return NodeHourlyCost(memoryDBNodeHourly, nodeType, nodes)
}
func ElastiCacheMonthlyCost(nodeType string, nodes int) (float64, bool) {
	return NodeHourlyCost(elastiCacheNodeHourly, nodeType, nodes)
}

// VPCEndpointMonthlyCost: an interface endpoint bills per AZ-hour; gateway
// endpoints are free.
func VPCEndpointMonthlyCost(endpointType string, azs int) float64 {
	if !strings.EqualFold(endpointType, "Interface") && !strings.EqualFold(endpointType, "GatewayLoadBalancer") {
		return 0
	}
	return VPCEndpointAZHour * HoursPerMonth * float64(azs)
}

// DynamoDBMonthlyCost covers provisioned capacity and storage. On-demand
// request charges depend on traffic and are not included.
func DynamoDBMonthlyCost(provisioned bool, rcu, wcu int64, storageBytes int64) float64 {
	var c float64
	if provisioned {
		c += float64(rcu)*DynamoRCUHour*HoursPerMonth + float64(wcu)*DynamoWCUHour*HoursPerMonth
	}
	gb := float64(storageBytes) / (1 << 30)
	if gb > DynamoFreeStorageGB {
		c += (gb - DynamoFreeStorageGB) * DynamoStorageGBMonth
	}
	return c
}

// LambdaMonthlyCost scales window totals to a 30-day month.
func LambdaMonthlyCost(invocations, durationMs, memoryMB float64, arm bool, windowDays int) float64 {
	if windowDays < 1 {
		windowDays = 14
	}
	scale := 30.0 / float64(windowDays)
	rate := LambdaGBSecond
	if arm {
		rate = LambdaGBSecondArm
	}
	gbs := durationMs / 1000 * (memoryMB / 1024)
	return (gbs*rate + invocations/1e6*LambdaPerMillionReq) * scale
}

// SQSMonthlyCost estimates request charges: a message costs about one send,
// one receive and one delete.
func SQSMonthlyCost(sent, received float64, windowDays int) float64 {
	if windowDays < 1 {
		windowDays = 14
	}
	return (sent + 2*received) / 1e6 * SQSPerMillionReq * 30 / float64(windowDays)
}

func FirehoseMonthlyCost(ingestedBytes float64, windowDays int) float64 {
	if windowDays < 1 {
		windowDays = 14
	}
	return ingestedBytes / (1 << 30) * FirehosePerGB * 30 / float64(windowDays)
}

func CloudFrontMonthlyCost(requests float64, windowDays int) float64 {
	if windowDays < 1 {
		windowDays = 14
	}
	return requests / 1e6 * CloudFrontPerMillion * 30 / float64(windowDays)
}
