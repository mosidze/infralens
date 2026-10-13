package aws

import (
	"encoding/json"
	"fmt"
	"os"
)

// Thresholds are the tunable rules behind waste verdicts. Defaults are
// conservative; a JSON file passed with --config overrides any subset.
type Thresholds struct {
	// IdleWindowDays is how far back CloudWatch is read to call a resource idle.
	IdleWindowDays int `json:"idle_window_days"`
	// NATIdleBytes: a NAT gateway that sent less than this over the window is idle.
	NATIdleBytes float64 `json:"nat_idle_bytes"`
	// SnapshotMinAgeDays: younger snapshots are never called orphaned.
	SnapshotMinAgeDays int `json:"snapshot_min_age_days"`
	// KinesisNearIdleBytes: an on-demand stream below this is paid for, not used.
	KinesisNearIdleBytes float64 `json:"kinesis_near_idle_bytes"`
	// LogMinCost: log groups cheaper than this per month are rolled up.
	LogMinCost float64 `json:"log_min_cost"`
	// LogMinStoredGB: a never-expiring idle log group below this is ignored.
	LogMinStoredGB float64 `json:"log_min_stored_gb"`
	// S3NoLifecycleGB: buckets at least this big without lifecycle rules are flagged in evidence.
	S3NoLifecycleGB float64 `json:"s3_no_lifecycle_gb"`
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		IdleWindowDays:       14,
		NATIdleBytes:         1 << 20,
		SnapshotMinAgeDays:   90,
		KinesisNearIdleBytes: 16 << 20,
		LogMinCost:           1.0,
		LogMinStoredGB:       1,
		S3NoLifecycleGB:      100,
	}
}

// LoadThresholds reads overrides from a JSON file on top of the defaults.
// Unknown keys are an error so that a typo does not silently do nothing.
func LoadThresholds(path string) (Thresholds, error) {
	th := DefaultThresholds()
	if path == "" {
		return th, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return th, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&th); err != nil {
		return th, fmt.Errorf("%s: %w", path, err)
	}
	if th.IdleWindowDays < 1 || th.IdleWindowDays > 60 {
		return th, fmt.Errorf("%s: idle_window_days must be 1..60 (CloudWatch daily datapoints)", path)
	}
	return th, nil
}
