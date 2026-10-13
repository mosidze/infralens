package aws

import (
	"fmt"
	"time"

	"infralens/internal/engine"
)

// idleVerdict is the outcome of a usage-based waste check.
type idleVerdict struct {
	Waste      bool
	Confidence engine.Confidence
	Evidence   string
}

// natVerdict decides whether a NAT gateway carried traffic. bytesOut is the
// summed BytesOutToDestination over the idle window, points the number of
// datapoints CloudWatch returned, age the gateway's age. A gateway younger
// than the window cannot be called idle with high confidence.
func natVerdict(bytesOut float64, points int, age time.Duration, th Thresholds) idleVerdict {
	window := time.Duration(th.IdleWindowDays) * 24 * time.Hour
	if bytesOut >= th.NATIdleBytes {
		return idleVerdict{false, engine.ConfHigh, fmt.Sprintf("%.1f MiB sent in %dd", bytesOut/(1<<20), th.IdleWindowDays)}
	}
	conf := engine.ConfHigh
	if age < window {
		conf = engine.ConfLow
	} else if points == 0 {
		conf = engine.ConfMedium
	}
	return idleVerdict{true, conf, fmt.Sprintf("%.0f bytes sent in %dd (%d datapoints), age %dd", bytesOut, th.IdleWindowDays, points, int(age.Hours()/24))}
}

// rdsVerdict flags a database with no connections in the window.
func rdsVerdict(maxConns float64, points int, age time.Duration, th Thresholds) idleVerdict {
	window := time.Duration(th.IdleWindowDays) * 24 * time.Hour
	if points == 0 {
		return idleVerdict{false, engine.ConfLow, "no CloudWatch datapoints, cannot judge"}
	}
	if maxConns > 0 {
		return idleVerdict{false, engine.ConfHigh, fmt.Sprintf("max %.0f connections in %dd", maxConns, th.IdleWindowDays)}
	}
	conf := engine.ConfHigh
	if age < window {
		conf = engine.ConfLow
	}
	return idleVerdict{true, conf, fmt.Sprintf("0 connections in %dd", th.IdleWindowDays)}
}

// lbVerdict flags a load balancer that has nothing behind it. staticOnly
// means every listener answers with a fixed response or a redirect: such an
// ALB is a deliberate placeholder/redirector, so it is only a weak candidate.
func lbVerdict(targetGroups, registeredTargets int, staticOnly bool) idleVerdict {
	switch {
	case targetGroups == 0 && staticOnly:
		return idleVerdict{true, engine.ConfLow, "no target groups; listeners only return fixed responses or redirects (placeholder/redirector?)"}
	case targetGroups == 0:
		return idleVerdict{true, engine.ConfMedium, "no target groups and no static-only listeners"}
	case registeredTargets == 0:
		return idleVerdict{true, engine.ConfHigh, fmt.Sprintf("%d target group(s), zero registered targets", targetGroups)}
	}
	return idleVerdict{false, engine.ConfHigh, fmt.Sprintf("%d registered targets", registeredTargets)}
}

// snapshotOrphan says a snapshot is leftover: old, its source volume is gone
// and no AMI uses it. Real cost is incremental, so confidence stays low.
func snapshotOrphan(age time.Duration, volumeExists, usedByAMI bool, th Thresholds) bool {
	return age > time.Duration(th.SnapshotMinAgeDays)*24*time.Hour && !volumeExists && !usedByAMI
}
