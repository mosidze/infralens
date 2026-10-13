package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"infralens/internal/engine"
	"infralens/internal/history"
	"infralens/internal/settings"
)

func newTestServer(t *testing.T, hooks Hooks) (*Server, *httptest.Server, string) {
	t.Helper()
	base := t.TempDir()
	s, err := New(Config{Base: base, Store: settings.NewStore(base), Version: "test", Token: "tok", Hooks: hooks})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	s.SetAllowedHosts(strings.TrimPrefix(ts.URL, "http://"))
	return s, ts, base
}

func do(t *testing.T, ts *httptest.Server, method, path, body string, mod func(*http.Request)) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "tok"})
	if method != "GET" {
		req.Header.Set("X-Infralens", "1")
	}
	if mod != nil {
		mod(req)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestRequestsWithoutTokenOrWithForeignHostOrOriginAreRefused(t *testing.T) {
	_, ts, _ := newTestServer(t, Hooks{})

	// no cookie
	req, _ := http.NewRequest("GET", ts.URL+"/api/state", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("no cookie: %d", resp.StatusCode)
	}
	// wrong cookie
	if r := do(t, ts, "GET", "/api/state", "", func(r *http.Request) {
		r.Header.Del("Cookie")
		r.AddCookie(&http.Cookie{Name: cookieName, Value: "nope"})
	}); r.StatusCode != 401 {
		t.Fatalf("wrong cookie: %d", r.StatusCode)
	}
	// DNS-rebinding style: right cookie, foreign Host
	if r := do(t, ts, "GET", "/api/state", "", func(r *http.Request) { r.Host = "evil.example:80" }); r.StatusCode != 403 {
		t.Fatalf("foreign host: %d", r.StatusCode)
	}
	// cross-origin write
	if r := do(t, ts, "PUT", "/api/context", `{"notes":[]}`, func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }); r.StatusCode != 403 {
		t.Fatalf("foreign origin: %d", r.StatusCode)
	}
	// write without the custom header (a plain cross-site form post)
	if r := do(t, ts, "PUT", "/api/context", `{"notes":[]}`, func(r *http.Request) { r.Header.Del("X-Infralens") }); r.StatusCode != 403 {
		t.Fatalf("no header: %d", r.StatusCode)
	}
	// the happy path works
	if r := do(t, ts, "GET", "/api/state", "", nil); r.StatusCode != 200 {
		t.Fatalf("state: %d", r.StatusCode)
	}
}

func TestTokenInURLBecomesCookieAndWrongTokenIsRefused(t *testing.T) {
	_, ts, _ := newTestServer(t, Hooks{})
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, _ := c.Get(ts.URL + "/?t=tok")
	if r.StatusCode != 303 {
		t.Fatalf("status %d", r.StatusCode)
	}
	var got *http.Cookie
	for _, ck := range r.Cookies() {
		if ck.Name == cookieName {
			got = ck
		}
	}
	if got == nil || !got.HttpOnly || got.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie not set properly: %+v", got)
	}
	r, _ = c.Get(ts.URL + "/?t=wrong")
	if r.StatusCode != 403 {
		t.Fatalf("wrong token: %d", r.StatusCode)
	}
	if r.Header.Get("Set-Cookie") != "" {
		t.Fatal("cookie set for a wrong token")
	}
}

func TestListenRefusesNonLoopback(t *testing.T) {
	for _, a := range []string{"0.0.0.0:0", "192.168.1.5:8080", ":8080", "example.com:80"} {
		if ln, err := Listen(a); err == nil {
			ln.Close()
			t.Errorf("%s was accepted", a)
		}
	}
	ln, err := Listen("")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}

func TestContextValidationAndPersistence(t *testing.T) {
	_, ts, base := newTestServer(t, Hooks{})
	if r := do(t, ts, "PUT", "/api/context", `{"notes":[{"match":{},"note":"x"}]}`, nil); r.StatusCode != 400 {
		t.Fatalf("a note matching everything was accepted: %d", r.StatusCode)
	}
	if r := do(t, ts, "PUT", "/api/context", `{"notes":[{"match":{"name":"a*"},"note":""}]}`, nil); r.StatusCode != 400 {
		t.Fatalf("empty note accepted: %d", r.StatusCode)
	}
	if r := do(t, ts, "PUT", "/api/context", `{"notes":[{"match":{"name":"a*"},"note":"by design","bogus":1}]}`, nil); r.StatusCode != 400 {
		t.Fatalf("unknown field accepted: %d", r.StatusCode)
	}
	if r := do(t, ts, "PUT", "/api/context", `{"notes":[{"match":{"name":"a*"},"note":"by design"}]}`, nil); r.StatusCode != 200 {
		t.Fatalf("valid note refused: %d", r.StatusCode)
	}
	st, err := os.Stat(filepath.Join(base, "context.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("context file: %v %v", err, st)
	}
}

func TestSettingsNeverEchoTheKeyAndRejectPastedKeyAsEnvName(t *testing.T) {
	_, ts, base := newTestServer(t, Hooks{})
	r := do(t, ts, "PUT", "/api/settings", `{"provider":"openai","key_env":"sk-abcdef123456"}`, nil)
	if r.StatusCode != 400 {
		t.Fatalf("a key pasted into the env-name field was accepted: %d", r.StatusCode)
	}
	r = do(t, ts, "PUT", "/api/settings", `{"provider":"openai","key":"sk-TOPSECRET"}`, nil)
	if r.StatusCode != 200 {
		t.Fatalf("status %d", r.StatusCode)
	}
	var buf strings.Builder
	b := make([]byte, 4096)
	n, _ := r.Body.Read(b)
	buf.Write(b[:n])
	if strings.Contains(buf.String(), "TOPSECRET") {
		t.Fatal("key echoed in the response")
	}
	g := do(t, ts, "GET", "/api/state", "", nil)
	n, _ = g.Body.Read(b)
	if strings.Contains(string(b[:n]), "TOPSECRET") {
		t.Fatal("key present in state")
	}
	s, _ := os.ReadFile(filepath.Join(base, "settings.json"))
	if strings.Contains(string(s), "TOPSECRET") {
		t.Fatal("key written to settings.json")
	}
	sec, _ := os.ReadFile(filepath.Join(base, "secrets.json"))
	if !strings.Contains(string(sec), "TOPSECRET") {
		t.Fatal("key was not stored in secrets.json")
	}
}

func TestScanJobRunsOnceAndReportsProgress(t *testing.T) {
	release := make(chan struct{})
	var base string
	hooks := Hooks{Scan: func(ctx context.Context, r ScanRequest, c string, progress func(string)) (string, error) {
		progress("step one")
		<-release
		return history.Save(base, engine.ScanResult{Account: "111122223333", Timestamp: time.Now()}, 0)
	}}
	_, ts, b := newTestServer(t, hooks)
	base = b

	if r := do(t, ts, "POST", "/api/scan", `{"profile":"a;rm -rf /"}`, nil); r.StatusCode != 400 {
		t.Fatalf("odd profile accepted: %d", r.StatusCode)
	}
	if r := do(t, ts, "POST", "/api/scan", `{"profile":"prod"}`, nil); r.StatusCode != 202 {
		t.Fatalf("start: %d", r.StatusCode)
	}
	if r := do(t, ts, "POST", "/api/scan", `{"profile":"prod"}`, nil); r.StatusCode != 409 {
		t.Fatalf("second scan not refused: %d", r.StatusCode)
	}
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for {
		r := do(t, ts, "GET", "/api/state", "", nil)
		var st struct {
			Job   *job       `json:"job"`
			Scans []scanInfo `json:"scans"`
		}
		_ = json.NewDecoder(r.Body).Decode(&st)
		if st.Job != nil && st.Job.State == "done" {
			if len(st.Job.Lines) == 0 || st.Job.Scan == "" || len(st.Scans) != 1 {
				t.Fatalf("job: %+v scans: %d", st.Job, len(st.Scans))
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not finish: %+v", st.Job)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestScanAndOutputPathsCannotEscape(t *testing.T) {
	_, ts, base := newTestServer(t, Hooks{})
	_ = os.WriteFile(filepath.Join(base, "secrets.json"), []byte(`{"llm":"k"}`), 0o600)
	for _, p := range []string{
		"/scan/..%2F..%2Fsecrets/x.json/report",
		"/scan/%2E%2E/secrets.json/report",
		"/out/..%2F/audit.html",
		"/out/..%2Fsecrets.json/audit.html",
		"/out/x/secrets.json",
	} {
		if r := do(t, ts, "GET", p, "", nil); r.StatusCode == 200 {
			t.Errorf("%s served", p)
		}
	}
	r := do(t, ts, "POST", "/api/audit", `{"scan":"../secrets.json","client":"C"}`, nil)
	if r.StatusCode != 404 {
		t.Fatalf("audit of a traversal id: %d", r.StatusCode)
	}
}

func TestAuditWritesPackAndAnonymisedPackOmitsRawFiles(t *testing.T) {
	_, ts, base := newTestServer(t, Hooks{})
	p, err := history.Save(base, engine.ScanResult{Account: "111122223333", Profile: "p", Timestamp: time.Now(),
		Nodes: []engine.ResourceNode{{ID: "i-1", Name: "payroll-db", Type: "aws_instance", Region: "eu-west-1"}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	id := filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p)

	r := do(t, ts, "POST", "/api/audit", `{"scan":"`+id+`","client":"ACME"}`, nil)
	var out struct {
		Dir   string   `json:"dir"`
		Files []string `json:"files"`
	}
	_ = json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || len(out.Files) != 3 {
		t.Fatalf("plain pack: %d %+v", r.StatusCode, out)
	}
	if g := do(t, ts, "GET", "/out/"+out.Dir+"/audit.html", "", nil); g.StatusCode != 200 || !strings.Contains(g.Header.Get("Content-Security-Policy"), "connect-src 'none'") {
		t.Fatalf("audit.html: %d csp=%q", g.StatusCode, g.Header.Get("Content-Security-Policy"))
	}

	r = do(t, ts, "POST", "/api/audit", `{"scan":"`+id+`","client":"ACME","anonymize":true}`, nil)
	out.Files = nil
	_ = json.NewDecoder(r.Body).Decode(&out)
	for _, f := range out.Files {
		if f == "report.html" {
			t.Fatal("anonymised pack contains the raw report")
		}
		b, _ := os.ReadFile(filepath.Join(base, "audits", out.Dir, f))
		if strings.Contains(string(b), "payroll-db") || strings.Contains(string(b), "111122223333") {
			t.Fatalf("%s leaks an identifier", f)
		}
	}
	if strings.Contains(out.Dir, "111122223333") {
		t.Fatal("anonymised directory name carries the account number")
	}

	// AI needs consent
	r = do(t, ts, "POST", "/api/audit", `{"scan":"`+id+`","client":"ACME","ai":true}`, nil)
	if r.StatusCode != 400 {
		t.Fatalf("AI without consent: %d", r.StatusCode)
	}
}

func fakeOllama(t *testing.T, reply string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.Write([]byte(`{"models":[{"name":"m1"}]}`))
			return
		}
		b, _ := json.Marshal(map[string]any{"message": map[string]string{"content": reply}})
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAIReportIsSeparateValidatedAndListsModels(t *testing.T) {
	reply := `{"headline":"Waste is about $12,345 a month","paragraphs":["Review the flagged items."],"actions":[{"finding_id":"deadbeef0000","why":"invented"}]}`
	ol := fakeOllama(t, reply)
	_, ts, base := newTestServer(t, Hooks{})
	p, _ := history.Save(base, engine.ScanResult{Account: "111122223333", Timestamp: time.Now()}, 0)
	id := filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p)

	if r := do(t, ts, "PUT", "/api/settings", `{"provider":"ollama","base_url":"`+ol.URL+`","model":"m1"}`, nil); r.StatusCode != 200 {
		t.Fatalf("settings: %d", r.StatusCode)
	}
	r := do(t, ts, "GET", "/api/llm/models", "", nil)
	var m struct {
		Models []string `json:"models"`
	}
	_ = json.NewDecoder(r.Body).Decode(&m)
	if r.StatusCode != 200 || len(m.Models) != 1 || m.Models[0] != "m1" {
		t.Fatalf("models: %d %+v", r.StatusCode, m)
	}

	r = do(t, ts, "POST", "/api/ai/report", `{"scan":"`+id+`"}`, nil) // local model: no consent needed
	var out struct {
		File    string `json:"file"`
		Removed int    `json:"removed"`
	}
	_ = json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || out.File == "" || out.Removed == 0 {
		t.Fatalf("report: %d %+v", r.StatusCode, out)
	}
	g := do(t, ts, "GET", "/ai/"+out.File, "", nil)
	b := make([]byte, 1<<16)
	n, _ := g.Body.Read(b)
	doc := string(b[:n])
	if g.StatusCode != 200 || strings.Contains(doc, "12,345") || strings.Contains(doc, "deadbeef0000") {
		t.Fatalf("document kept an invented amount or id (%d)", g.StatusCode)
	}
	if !strings.Contains(doc, "Written by a language model") {
		t.Fatal("document is not marked as model-written")
	}
	if do(t, ts, "GET", "/ai/..%2Fsecrets.json", "", nil).StatusCode == 200 {
		t.Fatal("path escape")
	}
}

func TestRemoteModelNeedsConsentForAIReport(t *testing.T) {
	_, ts, base := newTestServer(t, Hooks{})
	p, _ := history.Save(base, engine.ScanResult{Account: "111122223333", Timestamp: time.Now()}, 0)
	id := filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p)
	do(t, ts, "PUT", "/api/settings", `{"provider":"openai-compatible","base_url":"http://example.invalid","key":"k"}`, nil)
	if r := do(t, ts, "POST", "/api/ai/report", `{"scan":"`+id+`"}`, nil); r.StatusCode != 400 {
		t.Fatalf("remote model without consent: %d", r.StatusCode)
	}
}

func TestAINodeNeedsConsentWhenRemoteAndValidatesAnswer(t *testing.T) {
	reply := `{"answer":"It is an EBS volume with an estimated price. It costs about $999 a month.","finding_ids":["nope"]}`
	ol := fakeOllama(t, reply)
	_, ts, base := newTestServer(t, Hooks{})
	p, _ := history.Save(base, engine.ScanResult{Account: "111122223333", Timestamp: time.Now(),
		Nodes: []engine.ResourceNode{{ID: "vol-1", Name: "data", Type: "aws_ebs_volume", MonthlyCost: 40}}}, 0)
	id := filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p)

	do(t, ts, "PUT", "/api/settings", `{"provider":"ollama","base_url":"`+ol.URL+`","model":"m1"}`, nil)
	r := do(t, ts, "POST", "/api/ai/node", `{"scan":"`+id+`","node":"vol-1"}`, nil)
	var out struct {
		Answer  string `json:"answer"`
		Removed int    `json:"removed"`
	}
	_ = json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || strings.Contains(out.Answer, "999") || out.Removed == 0 {
		t.Fatalf("local answer: %d %+v", r.StatusCode, out)
	}
	if r := do(t, ts, "POST", "/api/ai/node", `{"scan":"`+id+`","node":"missing"}`, nil); r.StatusCode != 404 {
		t.Fatalf("unknown node: %d", r.StatusCode)
	}

	do(t, ts, "PUT", "/api/settings", `{"provider":"openai-compatible","base_url":"http://example.invalid","key":"k"}`, nil)
	r = do(t, ts, "POST", "/api/ai/node", `{"scan":"`+id+`","node":"vol-1"}`, nil)
	if r.StatusCode != 409 {
		t.Fatalf("remote without consent: %d", r.StatusCode)
	}
}
