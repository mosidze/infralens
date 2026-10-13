package aws

import "testing"

// Every node type a scanner can flag as waste must carry caveats, so that
// `explain` never presents a verdict without its blind spots.
func TestEveryFlaggableTypeHasCaveats(t *testing.T) {
	flaggable := []string{
		"aws_rds_instance", "aws_nat_gateway", "aws_lb", "aws_ebs_volume", "aws_ebs_snapshot",
		"aws_eip", "aws_kinesis_stream", "aws_opensearch_domain", "aws_cloudwatch_log_group",
		"aws_redshift_cluster", "aws_memorydb_cluster", "aws_elasticache_cluster", "aws_dynamodb_table",
	}
	for _, ty := range flaggable {
		if len(Caveats(ty)) == 0 {
			t.Errorf("%s has no caveats", ty)
		}
	}
	for _, s := range Scanners() {
		for ty := range s.Types {
			if ty == "aws_ecs_service" || ty == "aws_ecs_cluster" || ty == "aws_instance" || ty == "aws_cloudwatch_log_group_rollup" {
				continue // never flagged as waste
			}
			if len(Caveats(ty)) == 0 {
				t.Errorf("scanner %s emits %s without caveats", s.Name, ty)
			}
		}
	}
}
