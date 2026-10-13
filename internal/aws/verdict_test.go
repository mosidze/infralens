package aws

import (
	"testing"
	"time"

	"infralens/internal/engine"
)

const day = 24 * time.Hour

func TestNATVerdict(t *testing.T) {
	cases := []struct {
		name   string
		bytes  float64
		points int
		age    time.Duration
		waste  bool
		conf   engine.Confidence
	}{
		{"busy", 500 << 20, 14, 100 * day, false, engine.ConfHigh},
		{"silent with datapoints", 0, 14, 100 * day, true, engine.ConfHigh},
		{"silent no datapoints", 0, 0, 100 * day, true, engine.ConfMedium},
		{"too young to judge", 0, 3, 2 * day, true, engine.ConfLow},
		{"health-check noise", 1000, 5, 100 * day, true, engine.ConfHigh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := natVerdict(c.bytes, c.points, c.age, DefaultThresholds())
			if v.Waste != c.waste || v.Confidence != c.conf {
				t.Fatalf("got %+v", v)
			}
		})
	}
}

func TestRDSVerdict(t *testing.T) {
	if v := rdsVerdict(0, 0, 100*day, DefaultThresholds()); v.Waste {
		t.Fatal("no datapoints must not be called waste")
	}
	if v := rdsVerdict(3, 14, 100*day, DefaultThresholds()); v.Waste {
		t.Fatal("connections seen must not be waste")
	}
	if v := rdsVerdict(0, 14, 100*day, DefaultThresholds()); !v.Waste || v.Confidence != engine.ConfHigh {
		t.Fatalf("idle old db: %+v", v)
	}
	if v := rdsVerdict(0, 2, 3*day, DefaultThresholds()); !v.Waste || v.Confidence != engine.ConfLow {
		t.Fatalf("idle young db must be low confidence: %+v", v)
	}
}

func TestLBVerdict(t *testing.T) {
	if v := lbVerdict(0, 0, false); !v.Waste || v.Confidence != engine.ConfMedium {
		t.Fatalf("no target groups: %+v", v)
	}
	if v := lbVerdict(0, 0, true); !v.Waste || v.Confidence != engine.ConfLow {
		t.Fatalf("static-only listeners must be a weak candidate: %+v", v)
	}
	if v := lbVerdict(2, 0, false); !v.Waste || v.Confidence != engine.ConfHigh {
		t.Fatalf("empty target groups: %+v", v)
	}
	if v := lbVerdict(2, 3, false); v.Waste {
		t.Fatalf("has targets: %+v", v)
	}
}

func TestSnapshotOrphan(t *testing.T) {
	if !snapshotOrphan(120*day, false, false, DefaultThresholds()) {
		t.Fatal("old, volume gone, no AMI must be orphan")
	}
	for _, c := range []struct {
		age       time.Duration
		vol, used bool
	}{{10 * day, false, false}, {120 * day, true, false}, {120 * day, false, true}} {
		if snapshotOrphan(c.age, c.vol, c.used, DefaultThresholds()) {
			t.Fatalf("must not be orphan: %+v", c)
		}
	}
}

func TestParseGroup(t *testing.T) {
	for in, want := range map[string]string{"acme-backend-echo": "ACME", "web": "SHARED", "a-b": "SHARED"} {
		if got := parseGroup(in); got != want {
			t.Errorf("parseGroup(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsStandbyReader(t *testing.T) {
	if !isStandbyReader(clusterRole{cluster: "c", members: 2}, true) {
		t.Fatal("non-writer in a 2-member cluster is a standby")
	}
	if isStandbyReader(clusterRole{cluster: "c", writer: true, members: 2}, true) {
		t.Fatal("writer is not a standby")
	}
	if isStandbyReader(clusterRole{}, false) {
		t.Fatal("standalone instance is not a standby")
	}
	if isStandbyReader(clusterRole{cluster: "c", members: 1}, true) {
		t.Fatal("single-member cluster has no standby")
	}
}
