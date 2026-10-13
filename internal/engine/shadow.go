package engine

import "strings"

// Classification is the outcome of looking at a resource's tags.
type Classification struct {
	Status     ResourceStatus
	ManagedBy  string
	Confidence Confidence
	Evidence   string
}

var iacTagKeys = []struct {
	key, tool string
}{
	{"aws:cloudformation:stack-id", "CloudFormation"},
	{"aws:cloudformation:stack-name", "CloudFormation"},
	{"aws:eks:cluster-name", "EKS"},
	{"aws:autoscaling:groupName", "AutoScaling"},
	{"aws:elasticbeanstalk:environment-name", "ElasticBeanstalk"},
	{"terraform", "Terraform"},
	{"tf_module", "Terraform"},
	{"pulumi:project", "Pulumi"},
}

// ClassifyManagement decides from tags whether a resource is code-managed.
// Tags are the only signal available through the AWS API alone, so a
// resource without any IaC marker is reported as Shadow IT with medium
// confidence: it may be managed by a pipeline that does not tag.
func ClassifyManagement(tags map[string]string) Classification {
	lower := make(map[string]string, len(tags))
	for k, v := range tags {
		lower[strings.ToLower(k)] = v
	}

	for _, t := range iacTagKeys {
		if _, ok := lower[strings.ToLower(t.key)]; ok {
			return Classification{StatusManaged, t.tool, ConfHigh, "tag " + t.key + " present"}
		}
	}
	for _, k := range []string{"managedby", "managed-by", "managed_by", "created_by", "createdby", "provisioner"} {
		v, ok := lower[k]
		if !ok {
			continue
		}
		vl := strings.ToLower(v)
		for _, tool := range []string{"terraform", "terragrunt", "cloudformation", "cdk", "pulumi", "ansible", "crossplane"} {
			if strings.Contains(vl, tool) {
				return Classification{StatusManaged, v, ConfHigh, "tag " + k + "=" + v}
			}
		}
		return Classification{StatusManaged, v, ConfMedium, "tag " + k + "=" + v + " (not a known IaC tool)"}
	}
	if len(tags) == 0 {
		return Classification{StatusShadowIT, "", ConfMedium, "no tags at all"}
	}
	return Classification{StatusShadowIT, "", ConfMedium, "no IaC marker among tags"}
}
