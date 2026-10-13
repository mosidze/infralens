package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"infralens/internal/engine"
	"infralens/internal/settings"
)

func scan() engine.ScanResult {
	res := engine.ScanResult{
		Account: "123456789012", Profile: "client-prod", Regions: []string{"eu-north-1"},
		Nodes: []engine.ResourceNode{
			{ID: "arn:aws:rds:eu-north-1:123456789012:db:payments-ledger-1", Name: "payments-ledger-1", Type: "aws_rds_instance",
				Region: "eu-north-1", Status: engine.StatusOrphanWaste, MonthlyCost: 190.5, Confidence: engine.ConfHigh,
				WasteReason: "Database without connections", Evidence: []string{"0 connections in 14d on payments-ledger-1"}},
			{ID: "i-0abc", Name: "jump-host", Type: "aws_instance", Region: "eu-north-1", Status: engine.StatusShadowIT, MonthlyCost: 30},
		},
		Findings: []engine.Finding{{
			ID: "sec-1", Pillar: engine.PillarSecurity, Source: "security-hub", Rule: "sh.s3", Severity: engine.SevCritical,
			Title: "S3 bucket alice@example.com-backups should block public access", Affected: 2,
			Recommendation: "Enable Block Public Access on arn:aws:s3:::acme-backups.",
		}},
		EstimatedTCO: 4200, TotalWaste: 190.5,
	}
	engine.Finalize(&res, nil)
	return res
}

func TestFactsCarryNoNamesAndKeepIDs(t *testing.T) {
	f := BuildFacts(scan(), 0)
	b, _ := json.Marshal(f)
	for _, secret := range []string{"payments-ledger-1", "123456789012", "alice@example.com", "acme-backups", "jump-host", "client-prod", "i-0abc"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("facts must not carry %q:\n%s", secret, b)
		}
	}
	if len(f.Findings) < 2 || !f.HasID("sec-1") {
		t.Fatalf("findings and their ids must be kept: %+v", f.Findings)
	}
	// Finalize recomputes the total from the resources: 190.50 + 30.00
	if f.MonthlyCost != "$220.50" || f.WasteCost != "$190.50" {
		t.Fatalf("%+v", f)
	}
	// info-level and acknowledged findings are not worth the model's attention
	res := scan()
	res.Findings = append(res.Findings,
		engine.Finding{ID: "i-1", Severity: engine.SevInfo, Title: "noise"},
		engine.Finding{ID: "a-1", Severity: engine.SevHigh, Title: "known", Ack: &engine.Ack{Note: "expected"}})
	f = BuildFacts(res, 0)
	if f.HasID("i-1") || f.HasID("a-1") {
		t.Fatal("info and acknowledged findings must not be sent")
	}
}

func TestNarrativeValidationRemovesWhatIsNotInTheFacts(t *testing.T) {
	f := BuildFacts(scan(), 0)
	raw := "Here you go:\n```json\n" + `{
	  "headline": "The account costs $220.50 a month and has one critical exposure.",
	  "paragraphs": [
	    "Waste candidates cost $190.50 a month. The team could save $9,999 by deleting everything.",
	    "A bucket is exposed to the public (see the critical finding)."
	  ],
	  "actions": [
	    {"finding_id": "sec-1", "why": "Public exposure of data."},
	    {"finding_id": "made-up-id", "why": "Because I said so."}
	  ]
	}` + "\n```"
	n, ck, err := ParseNarrative(raw, f)
	if err != nil {
		t.Fatal(err)
	}
	all := n.Headline + " " + strings.Join(n.Paragraphs, " ")
	if strings.Contains(all, "9,999") || strings.Contains(all, "save") {
		t.Fatalf("an amount that is not in the facts must be removed with its sentence: %q", all)
	}
	if !strings.Contains(all, "$190.50") || !strings.Contains(n.Headline, "$220.50") {
		t.Fatalf("amounts that are in the facts survive: %q", all)
	}
	if len(n.Actions) != 1 || n.Actions[0].FindingID != "sec-1" {
		t.Fatalf("an action citing a finding that does not exist is dropped: %+v", n.Actions)
	}
	if ck.DroppedSentences != 1 || ck.DroppedIDs != 1 {
		t.Fatalf("what was removed must be reported: %+v", ck)
	}
}

func TestAnswerValidation(t *testing.T) {
	f := BuildFacts(scan(), 0)
	a, ck, err := ParseAnswer(`{"answer":"One critical security finding is open.","finding_ids":["sec-1","ghost"]}`, f)
	if err != nil || len(a.FindingIDs) != 1 || ck.DroppedIDs != 1 {
		t.Fatalf("%+v %+v %v", a, ck, err)
	}
	if _, _, err := ParseAnswer(`{"answer":"It will save $1,234,567.","finding_ids":[]}`, f); err == nil {
		t.Fatal("an answer that contains only an invented number must not survive")
	}
	if _, _, err := ParseAnswer("I cannot help with that.", f); err == nil {
		t.Fatal("prose without JSON is an error, not an answer")
	}
}

func TestMoneyShorthandIsChecked(t *testing.T) {
	f := BuildFacts(scan(), 0)
	n, _, err := ParseNarrative(`{"headline":"Cost is about $0.22k a month.","paragraphs":["Waste is $5k."],"actions":[]}`, f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(n.Headline, "$0.22k") {
		t.Fatalf("$0.22k is $220, within rounding of $220.50, and must stay: %q", n.Headline)
	}
	if len(n.Paragraphs) != 0 {
		t.Fatalf("$5k is not in the facts: %v", n.Paragraphs)
	}
}

func TestPromptNeverContainsNames(t *testing.T) {
	sys, usr := NarrativePrompt(BuildFacts(scan(), 0), "Russian")
	if !strings.Contains(sys, "Never invent") || !strings.Contains(usr, "Russian") {
		t.Fatal("rules and language must be in the prompt")
	}
	if strings.Contains(usr, "payments-ledger") || strings.Contains(sys, "payments-ledger") {
		t.Fatal("prompt leaks a resource name")
	}
}

// ---- providers against a local server ----------------------------------------------

func provider(t *testing.T, cfg settings.LLM, h http.HandlerFunc) Provider {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg.BaseURL = srv.URL
	if cfg.Model == "" {
		cfg.Model = "test-model" // an empty model triggers a listing request
	}
	st := settings.NewStore(t.TempDir())
	t.Setenv("TEST_LLM_KEY", "k-123")
	p, err := New(cfg, st, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProvidersSpeakTheirOwnProtocol(t *testing.T) {
	cases := []struct {
		name string
		cfg  settings.LLM
		h    http.HandlerFunc
		want string
	}{
		{"anthropic", settings.LLM{Provider: "anthropic", KeyRef: "env:TEST_LLM_KEY"}, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != "k-123" || r.Header.Get("anthropic-version") == "" {
				t.Errorf("anthropic request: %s %v", r.URL.Path, r.Header)
			}
			io.WriteString(w, `{"content":[{"type":"text","text":"hi from claude"}]}`)
		}, "hi from claude"},
		{"openai", settings.LLM{Provider: "openai", KeyRef: "env:TEST_LLM_KEY"}, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer k-123" {
				t.Errorf("openai request: %s %v", r.URL.Path, r.Header)
			}
			io.WriteString(w, `{"choices":[{"message":{"content":"hi from gpt"}}]}`)
		}, "hi from gpt"},
		{"gemini", settings.LLM{Provider: "gemini", KeyRef: "env:TEST_LLM_KEY"}, func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, ":generateContent") || r.Header.Get("x-goog-api-key") != "k-123" {
				t.Errorf("gemini request: %s %v", r.URL.Path, r.Header)
			}
			if r.URL.RawQuery != "" {
				t.Errorf("the key must not travel in the URL: %q", r.URL.RawQuery)
			}
			io.WriteString(w, `{"candidates":[{"content":{"parts":[{"text":"hi from gemini"}]}}]}`)
		}, "hi from gemini"},
		{"ollama", settings.LLM{Provider: "ollama"}, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/chat" {
				t.Errorf("ollama path %s", r.URL.Path)
			}
			io.WriteString(w, `{"message":{"content":"hi from llama"}}`)
		}, "hi from llama"},
		{"compatible", settings.LLM{Provider: "openai-compatible"}, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				t.Error("no key was configured, none may be sent")
			}
			io.WriteString(w, `{"choices":[{"message":{"content":"hi from vllm"}}]}`)
		}, "hi from vllm"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := provider(t, c.cfg, c.h)
			got, err := p.Complete(context.Background(), "sys", "user")
			if err != nil || got != c.want {
				t.Fatalf("%q %v", got, err)
			}
		})
	}
}

func TestProviderErrorsDoNotLeakTheKeyOrThePrompt(t *testing.T) {
	p := provider(t, settings.LLM{Provider: "anthropic", KeyRef: "env:TEST_LLM_KEY"}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"invalid x-api-key"}`)
	})
	_, err := p.Complete(context.Background(), "SYSTEM-PROMPT-SECRET", "USER-PROMPT-SECRET")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("%v", err)
	}
	for _, leak := range []string{"k-123", "SYSTEM-PROMPT-SECRET", "USER-PROMPT-SECRET"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error leaks %q: %v", leak, err)
		}
	}
}

func TestNewRefusesMissingKeysAndUnknownProviders(t *testing.T) {
	st := settings.NewStore(t.TempDir())
	for name, cfg := range map[string]settings.LLM{
		"no key":     {Provider: "anthropic"},
		"unset env":  {Provider: "openai", KeyRef: "env:SURELY_NOT_SET_XYZ"},
		"unknown":    {Provider: "skynet"},
		"none":       {},
		"compat url": {Provider: "openai-compatible"},
	} {
		if _, err := New(cfg, st, nil); err == nil {
			t.Errorf("%s must be an error", name)
		}
	}
	// a local model needs no key
	p, err := New(settings.LLM{Provider: "ollama"}, st, nil)
	if err != nil || !p.Local() {
		t.Fatalf("ollama on loopback is local: %v", err)
	}
	remote, _ := New(settings.LLM{Provider: "ollama", BaseURL: "http://gpu-box.corp:11434"}, st, nil)
	if remote.Local() {
		t.Fatal("a non-loopback address is not local")
	}
}

func TestSentenceSplittingKeepsNumbersWhole(t *testing.T) {
	got := splitSentences("It costs $4,200.00 a month. Version 2.1 is out! Is it? Yes")
	if len(got) != 4 || !strings.Contains(got[0], "$4,200.00") || !strings.Contains(got[1], "2.1") {
		t.Fatalf("%q", got)
	}
}

func TestNodeFactsAreScopedAndCarryNoNames(t *testing.T) {
	res := engine.ScanResult{
		Account: "111122223333",
		Nodes: []engine.ResourceNode{
			{ID: "vol-0a1b2c3d4e5f", Name: "payroll-data", Type: "aws_ebs_volume", Region: "eu-west-1", MonthlyCost: 40, CostBasis: "estimated",
				Status: engine.StatusOrphanWaste, WasteReason: "unattached payroll-data volume"},
			{ID: "i-other", Name: "other", Type: "aws_instance"},
		},
		Edges: []engine.Edge{{Source: "i-other", Target: "vol-0a1b2c3d4e5f"}},
		Findings: []engine.Finding{
			{ID: "f1", Pillar: engine.PillarCost, Severity: engine.SevMedium, Title: "Unattached volume payroll-data", ResourceID: "vol-0a1b2c3d4e5f", MonthlyCost: 40},
			{ID: "f2", Pillar: engine.PillarSecurity, Severity: engine.SevHigh, Title: "Something else", ResourceID: "i-other"},
		},
	}
	f, ok := BuildNodeFacts(res, "vol-0a1b2c3d4e5f")
	if !ok || f.Resource == nil {
		t.Fatal("node not found")
	}
	if !f.HasID("f1") || f.HasID("f2") {
		t.Fatal("findings must be limited to the selected resource")
	}
	b, _ := json.Marshal(f)
	for _, secret := range []string{"payroll-data", "vol-0a1b2c3d4e5f", "111122223333", "i-other"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("facts leak %q: %s", secret, b)
		}
	}
	if !strings.Contains(f.Resource.IaCCheck, "not checked") {
		t.Fatalf("absence of a state source must not read as 'created by hand': %q", f.Resource.IaCCheck)
	}
	if _, ok := BuildNodeFacts(res, "missing"); ok {
		t.Fatal("unknown node accepted")
	}
}
