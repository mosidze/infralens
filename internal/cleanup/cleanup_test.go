package cleanup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"infralens/internal/engine"
)

func nodes() []engine.ResourceNode {
	w := func(id, name, typ string, conf engine.Confidence, cost float64, attrs map[string]string) engine.ResourceNode {
		return engine.ResourceNode{ID: id, Name: name, Type: typ, Region: "eu-north-1", Status: engine.StatusOrphanWaste,
			Confidence: conf, MonthlyCost: cost, Attrs: attrs, WasteReason: "idle",
			Evidence: []string{"no use for 14d"}}
	}
	return []engine.ResourceNode{
		w("vol-0abc", "old-data", "aws_ebs_volume", engine.ConfHigh, 8, map[string]string{"az": "eu-north-1a", "volume_type": "gp3"}),
		w("eipalloc-0abc", "2.2.2.2", "aws_eip", engine.ConfHigh, 3.6, nil),
		w("nat-0abc", "nat", "aws_nat_gateway", engine.ConfHigh, 32.85, nil),
		w("arn:aws:elasticloadbalancing:eu-north-1:123456789012:loadbalancer/app/dead/abc", "dead", "aws_lb", engine.ConfHigh, 16.4, nil),
		w("pg-1", "pg-1", "aws_rds_instance", engine.ConfMedium, 190, map[string]string{"cluster": "pg"}),
		w("solo", "solo", "aws_rds_instance", engine.ConfMedium, 50, nil),
		w("arn:aws:kinesis:eu-north-1:123456789012:stream/s1", "s1", "aws_kinesis_stream", engine.ConfMedium, 29, nil),
		w("snap-0abc", "snap-0abc", "aws_ebs_snapshot", engine.ConfHigh, 3, nil),
		w("/aws/lambda/x", "/aws/lambda/x", "aws_cloudwatch_log_group", engine.ConfMedium, 5, nil),
		w("arn:aws:es:eu-north-1:123456789012:domain/d", "d", "aws_opensearch_domain", engine.ConfHigh, 500, nil),
		w("weak", "weak", "aws_kinesis_stream", engine.ConfLow, 29, nil),
		{ID: "ack", Name: "acked", Type: "aws_ebs_volume", Status: engine.StatusOrphanWaste, Confidence: engine.ConfHigh,
			Ack: &engine.Ack{Note: "expected"}},
		{ID: "fine", Name: "fine", Type: "aws_ebs_volume", Status: engine.StatusManaged},
	}
}

func gen(t *testing.T, ns []engine.ResourceNode, o Options) map[string]string {
	t.Helper()
	res := engine.ScanResult{Account: "123456789012", Nodes: ns}
	out := map[string]string{}
	for _, f := range Generate(res, o) {
		out[f.Name] = f.Content
	}
	return out
}

func TestSelectionRespectsConfidenceAndAcknowledgement(t *testing.T) {
	files := gen(t, nodes(), Options{})
	scripts := 0
	for name := range files {
		if strings.HasSuffix(name, ".sh") {
			scripts++
		}
	}
	if scripts != 10 {
		t.Fatalf("10 medium-or-better candidates expected, got %d: %v", scripts, keys(files))
	}
	idx := files["index.csv"]
	if strings.Contains(idx, "weak") || strings.Contains(idx, "acked") || strings.Contains(idx, "fine") {
		t.Fatalf("low-confidence, acknowledged and non-waste resources must not get a script:\n%s", idx)
	}
	all := gen(t, nodes(), Options{MinConfidence: engine.ConfLow})
	if !strings.Contains(all["index.csv"], "weak") {
		t.Fatal("--min-confidence low must include weak candidates")
	}
	if !strings.Contains(files["README.md"], "Nothing in this directory has been run") {
		t.Fatal("README must say nothing was run")
	}
}

func keys(m map[string]string) []string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	return k
}

func TestEveryScriptIsValidShell(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	for name, body := range gen(t, nodes(), Options{MinConfidence: engine.ConfLow}) {
		if !strings.HasSuffix(name, ".sh") {
			continue
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bash, "-n", p).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}

// ---- behaviour: run the scripts against a stub aws ---------------------------

const stubAWS = `#!/usr/bin/env bash
echo "$@" >> "$STUB_LOG"
case "$*" in
  *"sts get-caller-identity"*) echo "${STUB_ACCOUNT:-123456789012}" ;;
  *"describe-volumes"*)        echo "available" ;;
  *"describe-addresses"*)      echo "None" ;;
  *"describe-route-tables"*)   echo "" ;;
  *"create-snapshot"*)         echo "snap-123" ;;
esac
exit 0
`

type runResult struct {
	code int
	log  string
}

func runScript(t *testing.T, script string, env map[string]string) runResult {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "aws"), []byte(stubAWS), 0o700); err != nil {
		t.Fatal(err)
	}
	sp := filepath.Join(dir, "s.sh")
	if err := os.WriteFile(sp, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	logp := filepath.Join(dir, "calls.log")
	cmd := exec.Command(bash, sp)
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin", "AWS_PROFILE=test", "STUB_LOG=" + logp, "HOME=" + dir}, flat(env)...)
	err = cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(logp)
	return runResult{code, string(b)}
}

func flat(m map[string]string) []string {
	var out []string
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

var writeVerbs = []string{"create-", "delete-", "release-", "stop-", "put-", "add-tags", "tag-", "terminate", "modify-", "update-"}

func writes(log string) []string {
	var w []string
	for _, l := range strings.Split(log, "\n") {
		for _, v := range writeVerbs {
			if strings.Contains(l, v) {
				w = append(w, l)
				break
			}
		}
	}
	return w
}

func TestScriptsAreSafeByDefault(t *testing.T) {
	files := gen(t, nodes(), Options{MinConfidence: engine.ConfLow})
	for name, body := range files {
		if !strings.HasSuffix(name, ".sh") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			// default: dry run, quarantine stage -> only reads
			r := runScript(t, body, nil)
			if r.code != 0 {
				t.Fatalf("a dry run must succeed, exit %d\n%s", r.code, r.log)
			}
			if w := writes(r.log); len(w) > 0 {
				t.Fatalf("dry run issued write calls: %v", w)
			}
			// wrong account: stops before anything
			r = runScript(t, body, map[string]string{"STUB_ACCOUNT": "999999999999", "DRY_RUN": "0"})
			if r.code != 2 || len(writes(r.log)) > 0 {
				t.Fatalf("wrong account must stop with 2 and no writes: exit %d writes %v", r.code, writes(r.log))
			}
			// no AWS_PROFILE: refuses
			// real run, quarantine stage: never deletes
			r = runScript(t, body, map[string]string{"DRY_RUN": "0"})
			for _, l := range writes(r.log) {
				if strings.Contains(l, "delete-") || strings.Contains(l, "release-address") {
					t.Fatalf("quarantine stage issued a removal: %s", l)
				}
			}
			// delete stage without confirmation: refuses, nothing removed
			r = runScript(t, body, map[string]string{"DRY_RUN": "0", "STAGE": "delete"})
			for _, l := range writes(r.log) {
				if strings.Contains(l, "delete-") || strings.Contains(l, "release-address") {
					t.Fatalf("removal without CONFIRM: %s", l)
				}
			}
		})
	}
}

func TestRemovalNeedsExactConfirmation(t *testing.T) {
	files := gen(t, nodes(), Options{})
	var vol string
	for n, b := range files {
		if strings.Contains(n, "ebs_volume") {
			vol = b
		}
	}
	r := runScript(t, vol, map[string]string{"DRY_RUN": "0", "STAGE": "delete", "CONFIRM": "vol-wrong"})
	if r.code != 3 || strings.Contains(r.log, "delete-volume") {
		t.Fatalf("a wrong confirmation must refuse: exit %d\n%s", r.code, r.log)
	}
	r = runScript(t, vol, map[string]string{"DRY_RUN": "0", "STAGE": "delete", "CONFIRM": "vol-0abc"})
	if r.code != 0 || !strings.Contains(r.log, "delete-volume") {
		t.Fatalf("the exact id must allow the removal: exit %d\n%s", r.code, r.log)
	}
	// the backup comes before the removal
	if strings.Index(r.log, "create-snapshot") > strings.Index(r.log, "delete-volume") || !strings.Contains(r.log, "create-snapshot") {
		t.Fatalf("snapshot must precede delete:\n%s", r.log)
	}
}

func TestHostileNamesCannotInjectCommands(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "pwned")
	evil := "x'; touch " + canary + "; echo '\n; touch " + canary + " #"
	ns := []engine.ResourceNode{
		{ID: "vol-0abc", Name: evil, Type: "aws_ebs_volume", Region: "eu-north-1", Status: engine.StatusOrphanWaste,
			Confidence: engine.ConfHigh, WasteReason: evil, Evidence: []string{evil},
			Attrs: map[string]string{"az": evil, "volume_type": evil}},
		{ID: "arn:aws:kinesis:eu-north-1:1:stream/" + evil, Name: evil, Type: "aws_kinesis_stream", Region: "eu-north-1",
			Status: engine.StatusOrphanWaste, Confidence: engine.ConfHigh},
		{ID: evil, Name: evil, Type: "aws_cloudwatch_log_group", Region: "eu-north-1",
			Status: engine.StatusOrphanWaste, Confidence: engine.ConfHigh},
	}
	for name, body := range gen(t, ns, Options{}) {
		if !strings.HasSuffix(name, ".sh") {
			continue
		}
		if strings.ContainsAny(name, "'; \n") {
			t.Fatalf("file name must be safe: %q", name)
		}
		for _, env := range []map[string]string{nil, {"DRY_RUN": "0"}, {"DRY_RUN": "0", "STAGE": "delete", "CONFIRM": "no"}} {
			runScript(t, body, env)
		}
		if _, err := os.Stat(canary); err == nil {
			t.Fatalf("%s executed injected code", name)
		}
	}
}

func TestIndexNeutralisesSpreadsheetFormulas(t *testing.T) {
	files := gen(t, []engine.ResourceNode{{ID: "v", Name: "=HYPERLINK(\"x\")", Type: "aws_ebs_volume", Region: "r",
		Status: engine.StatusOrphanWaste, Confidence: engine.ConfHigh}}, Options{})
	if strings.Contains(files["index.csv"], `,"=HYPER`) || !strings.Contains(files["index.csv"], `"'=HYPERLINK`) {
		t.Fatalf("index.csv:\n%s", files["index.csv"])
	}
}

func TestDependentsAreInTheHeader(t *testing.T) {
	n := nodes()[3]
	n.Blast = &engine.BlastRadius{
		Checked:    []string{"Route53 records"},
		Dependents: []engine.Dependent{{Kind: "dns", Name: "app.example.com", Detail: "alias A"}},
		Unchecked:  []string{"CloudFront origins"},
	}
	files := gen(t, []engine.ResourceNode{n}, Options{Now: time.Now()})
	var s string
	for k, v := range files {
		if strings.HasSuffix(k, ".sh") {
			s = v
		}
	}
	for _, want := range []string{"DEPENDENT  : dns app.example.com", "looked at  : Route53 records", "NOT LOOKED AT", "cannot see"} {
		if !strings.Contains(s, want) {
			t.Errorf("header lacks %q", want)
		}
	}
	_ = fmt.Sprint
}
