// Package app is the local web application: a small HTTP server that listens
// on the loopback interface only and drives scans, reports and settings from a
// browser. It holds AWS credentials' power indirectly (a scan runs with the
// user's profile), so every request must carry a one-time token, a loopback
// Host, and for writes a same-origin Origin plus a custom header.
package app

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"infralens/internal/engine"
	"infralens/internal/history"
	"infralens/internal/llm"
	"infralens/internal/report"
	"infralens/internal/settings"
)

//go:embed web/index.html
var indexHTML string

//go:embed web/app.js
var appJS string

//go:embed web/app.css
var appCSS string

// ScanRequest is what the browser may choose for a scan. Everything else
// (thresholds, output paths, API log) is fixed by the server.
type ScanRequest struct {
	Profile  string `json:"profile"`
	Regions  string `json:"regions"`
	Services string `json:"services"`
	TFState  string `json:"tfstate"`
	Prowler  string `json:"prowler"`
	SSOLogin bool   `json:"sso_login"`
}

// Hooks connect the server to the scanner, which lives in package main.
type Hooks struct {
	Profiles func() ([]string, error)
	// Scan runs one scan and returns the path of the saved history file.
	Scan func(ctx context.Context, r ScanRequest, contextFile string, progress func(string)) (string, error)
}

type Config struct {
	Base    string // ~/.infralens
	Store   *settings.Store
	Hooks   Hooks
	Version string
	Token   string // generated when empty
}

type Server struct {
	cfg  Config
	mu   sync.Mutex
	job  *job
	host map[string]bool // allowed Host header values, set by Listen
}

type job struct {
	ID      string    `json:"id"`
	Profile string    `json:"profile"`
	State   string    `json:"state"` // running | done | failed | cancelled
	Lines   []string  `json:"lines"`
	Error   string    `json:"error,omitempty"`
	Scan    string    `json:"scan,omitempty"` // scan id when done
	Started time.Time `json:"started"`
	cancel  context.CancelFunc
}

func New(cfg Config) (*Server, error) {
	if cfg.Token == "" {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		cfg.Token = hex.EncodeToString(b)
	}
	if cfg.Base == "" || cfg.Store == nil {
		return nil, errors.New("app: Base and Store are required")
	}
	return &Server{cfg: cfg, host: map[string]bool{}}, nil
}

func (s *Server) Token() string { return s.cfg.Token }

// Listen binds a loopback address. Anything that is not loopback is refused:
// the server has no user accounts and must never be reachable from a network.
func Listen(addr string) (net.Listener, error) {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(h)
	if h == "localhost" {
		ip = net.ParseIP("127.0.0.1")
		addr = strings.Replace(addr, "localhost", "127.0.0.1", 1)
	}
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("refusing to listen on %q: only loopback addresses are allowed", addr)
	}
	return net.Listen("tcp", addr)
}

// Serve runs until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s.host = map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true, "[::1]:" + port: true}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		sc, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = srv.Shutdown(sc)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// SetAllowedHosts is for tests that use httptest.
func (s *Server) SetAllowedHosts(h ...string) {
	s.host = map[string]bool{}
	for _, x := range h {
		s.host[x] = true
	}
}

const cookieName = "infralens"

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.page(indexHTML, "text/html; charset=utf-8"))
	mux.HandleFunc("GET /static/app.js", s.page(appJS, "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /static/app.css", s.page(appCSS, "text/css; charset=utf-8"))
	mux.HandleFunc("GET /api/state", s.getState)
	mux.HandleFunc("POST /api/scan", s.postScan)
	mux.HandleFunc("POST /api/job/cancel", s.cancelJob)
	mux.HandleFunc("GET /api/context", s.getContext)
	mux.HandleFunc("PUT /api/context", s.putContext)
	mux.HandleFunc("GET /api/settings", s.getSettings)
	mux.HandleFunc("PUT /api/settings", s.putSettings)
	mux.HandleFunc("POST /api/llm/test", s.llmTest)
	mux.HandleFunc("POST /api/ai/preview", s.aiPreview)
	mux.HandleFunc("POST /api/ai/report", s.aiReport)
	mux.HandleFunc("POST /api/ai/node", s.aiNode)
	mux.HandleFunc("GET /api/llm/models", s.llmModels)
	mux.HandleFunc("GET /ai/{file}", s.aiFile)
	mux.HandleFunc("POST /api/audit", s.postAudit)
	mux.HandleFunc("GET /scan/{account}/{file}/report", s.scanReport)
	mux.HandleFunc("GET /out/{dir}/{file}", s.outFile)
	return s.guard(mux)
}

// ---- request guard -----------------------------------------------------------

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if !s.host[r.Host] {
			http.Error(w, "unexpected Host", http.StatusForbidden)
			return
		}
		// First visit: the token in the URL becomes an HttpOnly cookie and is
		// removed from the address bar.
		if t := r.URL.Query().Get("t"); t != "" && r.Method == http.MethodGet && r.URL.Path == "/" {
			if subtle.ConstantTimeCompare([]byte(t), []byte(s.cfg.Token)) != 1 {
				http.Error(w, "bad token", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.cfg.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 30 * 24 * 3600})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.cfg.Token)) != 1 {
			http.Error(w, "open the address printed by `infralens serve`", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" {
				u, err := url.Parse(o)
				if err != nil || !s.host[u.Host] {
					http.Error(w, "cross-origin request refused", http.StatusForbidden)
					return
				}
			}
			if r.Header.Get("X-Infralens") != "1" {
				http.Error(w, "missing X-Infralens header", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		// The report is a self-contained document with inline script; it gets
		// its own policy and may not talk to the network at all.
		if strings.HasSuffix(r.URL.Path, "/report") || strings.HasPrefix(r.URL.Path, "/out/") || strings.HasPrefix(r.URL.Path, "/ai/") {
			h.Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'")
		} else {
			h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) page(body, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write([]byte(body))
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// ---- scans on disk -----------------------------------------------------------

var safeName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type scanInfo struct {
	ID        string    `json:"id"` // account/file
	Account   string    `json:"account"`
	Profile   string    `json:"profile"`
	Time      time.Time `json:"time"`
	Resources int       `json:"resources"`
	Findings  int       `json:"findings"`
	Waste     float64   `json:"waste"`
	Cost      float64   `json:"cost"`
}

func (s *Server) listScans() []scanInfo {
	root := filepath.Join(s.cfg.Base, "history")
	var out []scanInfo
	accts, _ := os.ReadDir(root)
	for _, a := range accts {
		if !a.IsDir() || !safeName.MatchString(a.Name()) {
			continue
		}
		files, _ := os.ReadDir(filepath.Join(root, a.Name()))
		names := []string{}
		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".json") && safeName.MatchString(f.Name()) {
				names = append(names, f.Name())
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		if len(names) > 12 {
			names = names[:12]
		}
		for _, n := range names {
			res, err := history.Read(filepath.Join(root, a.Name(), n))
			if err != nil {
				continue
			}
			out = append(out, scanInfo{
				ID: a.Name() + "/" + n, Account: res.Account, Profile: res.Profile, Time: res.Timestamp,
				Resources: len(res.Nodes), Findings: len(res.Findings), Waste: res.TotalWaste, Cost: res.TotalCurrCost,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

// loadScan resolves "account/file" under the history directory only.
func (s *Server) loadScan(id string) (engine.ScanResult, error) {
	acct, file, ok := strings.Cut(id, "/")
	if !ok || !safeName.MatchString(acct) || !safeName.MatchString(file) || !strings.HasSuffix(file, ".json") || strings.Contains(acct, "..") {
		return engine.ScanResult{}, errors.New("bad scan id")
	}
	res, err := history.Read(filepath.Join(s.cfg.Base, "history", acct, file))
	if err != nil {
		return res, errors.New("scan not found")
	}
	s.applyContext(&res)
	return res, nil
}

func (s *Server) contextPath() string { return filepath.Join(s.cfg.Base, "context.json") }

func (s *Server) loadContext() engine.Context {
	c, err := engine.LoadContext(s.contextPath())
	if err != nil {
		return engine.Context{}
	}
	return c
}

// applyContext puts the owner's notes onto a stored scan, starting from the
// raw findings so removed notes stop applying.
func (s *Server) applyContext(res *engine.ScanResult) {
	owner := s.loadContext()
	if len(owner.Notes) == 0 {
		return
	}
	for i := range res.Nodes {
		res.Nodes[i].Ack = nil
	}
	for i := range res.Commitments {
		res.Commitments[i].Ack = nil
	}
	owner.Apply(res, time.Now())
	engine.Finalize(res, res.TypeServices)
	res.Summary = report.LocalSummary(*res)
}

// ---- handlers ----------------------------------------------------------------

type llmView struct {
	settings.LLM
	KeyState string `json:"key_state"`
}

func (s *Server) llmView() llmView {
	st, _ := s.cfg.Store.Load()
	v := llmView{LLM: st.LLM}
	switch {
	case strings.HasPrefix(v.KeyRef, "secret:"):
		v.KeyState = "stored"
		if !s.cfg.Store.HasSecret(strings.TrimPrefix(v.KeyRef, "secret:")) {
			v.KeyState = "missing"
		}
	case strings.HasPrefix(v.KeyRef, "env:"):
		v.KeyState = "set"
		if os.Getenv(strings.TrimPrefix(v.KeyRef, "env:")) == "" {
			v.KeyState = "not set in the shell that started infralens"
		}
	case v.Provider == "":
		v.KeyState = "not configured"
	default:
		v.KeyState = "none"
	}
	return v
}

func (s *Server) getState(w http.ResponseWriter, r *http.Request) {
	var profiles []string
	if s.cfg.Hooks.Profiles != nil {
		profiles, _ = s.cfg.Hooks.Profiles()
	}
	s.mu.Lock()
	var j *job
	if s.job != nil {
		c := *s.job
		c.Lines = append([]string{}, s.job.Lines...)
		j = &c
	}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"version": s.cfg.Version, "profiles": profiles, "scans": s.listScans(), "job": j,
		"llm": s.llmView(), "notes": len(s.loadContext().Notes),
	})
}

var safeProfile = regexp.MustCompile(`^[A-Za-z0-9._@+=,/ -]{0,128}$`)

func (s *Server) postScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, "bad request")
		return
	}
	for _, v := range []string{req.Profile, req.Regions, req.Services} {
		if !safeProfile.MatchString(v) {
			fail(w, 400, "unexpected characters in a field")
			return
		}
	}
	if strings.Contains(req.Profile, ",") {
		fail(w, 400, "one profile at a time")
		return
	}
	if s.cfg.Hooks.Scan == nil {
		fail(w, 501, "scanning is not available")
		return
	}
	s.mu.Lock()
	if s.job != nil && s.job.State == "running" {
		s.mu.Unlock()
		fail(w, 409, "a scan is already running")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{ID: fmt.Sprint(time.Now().UnixNano()), Profile: req.Profile, State: "running", Started: time.Now(), cancel: cancel}
	s.job = j
	s.mu.Unlock()

	add := func(line string) {
		s.mu.Lock()
		j.Lines = append(j.Lines, line)
		if len(j.Lines) > 500 {
			j.Lines = j.Lines[len(j.Lines)-500:]
		}
		s.mu.Unlock()
	}
	go func() {
		ctxFile := ""
		if _, err := os.Stat(s.contextPath()); err == nil {
			ctxFile = s.contextPath()
		}
		path, err := s.cfg.Hooks.Scan(ctx, req, ctxFile, add)
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case ctx.Err() != nil:
			j.State = "cancelled"
		case err != nil:
			j.State, j.Error = "failed", err.Error()
		default:
			j.State = "done"
			if rel, e := filepath.Rel(filepath.Join(s.cfg.Base, "history"), path); e == nil {
				j.Scan = filepath.ToSlash(rel)
			}
		}
	}()
	writeJSON(w, 202, map[string]string{"id": j.ID})
}

func (s *Server) cancelJob(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.job != nil && s.job.State == "running" && s.job.cancel != nil {
		s.job.cancel()
	}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) getContext(w http.ResponseWriter, r *http.Request) {
	c := s.loadContext()
	if c.Notes == nil {
		c.Notes = []engine.ContextNote{}
	}
	writeJSON(w, 200, c)
}

func (s *Server) putContext(w http.ResponseWriter, r *http.Request) {
	var c engine.Context
	if err := readJSON(r, &c); err != nil {
		fail(w, 400, "not a valid notes document")
		return
	}
	for i, n := range c.Notes {
		m := n.Match
		if strings.TrimSpace(n.Note) == "" {
			fail(w, 400, fmt.Sprintf("note %d has no text", i+1))
			return
		}
		if m.ID == "" && m.Name == "" && m.Type == "" && m.Service == "" && m.Region == "" && m.Rule == "" && m.Finding == "" {
			fail(w, 400, fmt.Sprintf("note %d matches everything; give it at least one match field", i+1))
			return
		}
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.MkdirAll(s.cfg.Base, 0o700); err != nil {
		fail(w, 500, err.Error())
		return
	}
	tmp := s.contextPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		fail(w, 500, err.Error())
		return
	}
	if err := os.Rename(tmp, s.contextPath()); err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]int{"notes": len(c.Notes)})
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.llmView())
}

type settingsReq struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	BaseURL  string `json:"base_url"`
	KeyEnv   string `json:"key_env"`
	Key      string `json:"key"` // stored in secrets.json, never echoed back
	Profile  string `json:"profile"`
	Region   string `json:"region"`
	Language string `json:"language"`
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var q settingsReq
	if err := readJSON(r, &q); err != nil {
		fail(w, 400, "bad request")
		return
	}
	st, err := s.cfg.Store.Load()
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	l := st.LLM
	l.Provider, l.Model, l.BaseURL = strings.TrimSpace(q.Provider), strings.TrimSpace(q.Model), strings.TrimSpace(q.BaseURL)
	l.Profile, l.Region, l.Language = strings.TrimSpace(q.Profile), strings.TrimSpace(q.Region), strings.TrimSpace(q.Language)
	switch {
	case q.Key != "":
		if err := s.cfg.Store.SetSecret("llm", strings.TrimSpace(q.Key)); err != nil {
			fail(w, 500, err.Error())
			return
		}
		l.KeyRef = "secret:llm"
	case q.KeyEnv != "":
		if !envName.MatchString(q.KeyEnv) {
			fail(w, 400, "that is not an environment variable name; paste the key into the key field instead")
			return
		}
		l.KeyRef = "env:" + q.KeyEnv
	}
	st.LLM = l
	if err := s.cfg.Store.Save(st); err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, s.llmView())
}

func (s *Server) provider() (llm.Provider, settings.LLM, error) {
	st, err := s.cfg.Store.Load()
	if err != nil {
		return nil, st.LLM, err
	}
	p, err := llm.New(st.LLM, s.cfg.Store, nil)
	return p, st.LLM, err
}

func (s *Server) llmTest(w http.ResponseWriter, r *http.Request) {
	p, _, err := s.provider()
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	out, err := p.Complete(ctx, "Reply with the single word: ok", "ping")
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	if len(out) > 80 {
		out = out[:80]
	}
	writeJSON(w, 200, map[string]any{"model": p.Name(), "local": p.Local(), "answer": strings.TrimSpace(out)})
}

type scanRef struct {
	Scan string `json:"scan"`
}

func (s *Server) llmModels(w http.ResponseWriter, r *http.Request) {
	st, err := s.cfg.Store.Load()
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ids, err := llm.ListModels(ctx, st.LLM, s.cfg.Store, nil)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"models": ids, "suggested": llm.PickDefault(st.LLM.Provider, ids), "current": st.LLM.Model})
}

type aiReportReq struct {
	Scan     string `json:"scan"`
	Question string `json:"question"`
	Consent  bool   `json:"consent"`
}

// aiReport writes a stand-alone AI analysis of one scan. A remote model is
// only called after the caller says the preview was seen.
func (s *Server) aiReport(w http.ResponseWriter, r *http.Request) {
	var q aiReportReq
	if err := readJSON(r, &q); err != nil {
		fail(w, 400, "bad request")
		return
	}
	q.Question = strings.TrimSpace(q.Question)
	if len(q.Question) > 1000 {
		fail(w, 400, "the question is too long")
		return
	}
	res, err := s.loadScan(q.Scan)
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	p, l, err := s.provider()
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if !p.Local() && !q.Consent {
		fail(w, 400, "the model is remote; confirm after looking at what is sent")
		return
	}
	facts := llm.BuildFacts(res, 60)
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	rep := report.AIReport{Model: p.Name(), Question: q.Question, Account: res.Account, Taken: res.Timestamp}
	if q.Question != "" {
		a, ck, err := llm.Ask(ctx, p, facts, q.Question, l.Language)
		if err != nil {
			fail(w, 502, err.Error())
			return
		}
		rep.Answer, rep.Removed = &a, ck.DroppedSentences+ck.DroppedIDs
	} else {
		n, ck, err := llm.GenerateNarrative(ctx, p, facts, l.Language)
		if err != nil {
			fail(w, 502, err.Error())
			return
		}
		rep.Narrative, rep.Removed = &n, ck.DroppedSentences+ck.DroppedIDs
	}
	doc, err := report.RenderAIReport(res, rep)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	dir := filepath.Join(s.cfg.Base, "ai")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fail(w, 500, err.Error())
		return
	}
	name := dirUnsafe.ReplaceAllString(history.Key(res)+"-"+time.Now().UTC().Format("20060102T150405Z"), "_") + ".html"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(doc), 0o600); err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"file": name, "model": p.Name(), "removed": rep.Removed,
		"path": filepath.Join(dir, name), "narrative": rep.Narrative, "answer": rep.Answer})
}

type aiNodeReq struct {
	Scan     string `json:"scan"`
	Node     string `json:"node"`
	Question string `json:"question"`
	Consent  bool   `json:"consent"`
}

// aiNode answers a question about one resource from facts scoped to it. The
// reply says which findings it rests on, so the reader can check it.
func (s *Server) aiNode(w http.ResponseWriter, r *http.Request) {
	var q aiNodeReq
	if err := readJSON(r, &q); err != nil {
		fail(w, 400, "bad request")
		return
	}
	q.Question = strings.TrimSpace(q.Question)
	if q.Question == "" {
		q.Question = "Explain this resource: why it is shown this way, how its cost was obtained, what it is connected to, whether it is in code, and what should be confirmed with its owner before any action."
	}
	if len(q.Question) > 600 {
		fail(w, 400, "the question is too long")
		return
	}
	res, err := s.loadScan(q.Scan)
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	facts, ok := llm.BuildNodeFacts(res, q.Node)
	if !ok {
		fail(w, 404, "resource not found in this scan")
		return
	}
	p, l, err := s.provider()
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	sys, usr := llm.AskPrompt(facts, q.Question, l.Language)
	if !p.Local() && !q.Consent {
		writeJSON(w, 409, map[string]any{"needs_consent": true, "model": p.Name(), "bytes": len(sys) + len(usr), "payload": usr})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	a, ck, err := llm.Ask(ctx, p, facts, q.Question, l.Language)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	titles := map[string]string{}
	for _, f := range res.Findings {
		titles[f.ID] = f.Title
	}
	var refs []string
	for _, id := range a.FindingIDs {
		if t, ok := titles[id]; ok {
			refs = append(refs, t)
		}
	}
	writeJSON(w, 200, map[string]any{"answer": a.Answer, "findings": refs, "model": p.Name(),
		"removed": ck.DroppedSentences + ck.DroppedIDs, "based_on": len(facts.Findings)})
}

func (s *Server) aiFile(w http.ResponseWriter, r *http.Request) {
	f := r.PathValue("file")
	if !safeName.MatchString(f) || !strings.HasSuffix(f, ".html") || strings.Contains(f, "..") {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(filepath.Join(s.cfg.Base, "ai", f))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

// aiPreview shows exactly what would leave the machine, before it does.
func (s *Server) aiPreview(w http.ResponseWriter, r *http.Request) {
	var q scanRef
	if err := readJSON(r, &q); err != nil {
		fail(w, 400, "bad request")
		return
	}
	res, err := s.loadScan(q.Scan)
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	p, l, err := s.provider()
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	facts := llm.BuildFacts(res, 60)
	sys, usr := llm.NarrativePrompt(facts, l.Language)
	writeJSON(w, 200, map[string]any{"model": p.Name(), "local": p.Local(), "bytes": len(sys) + len(usr), "system": sys, "user": usr})
}

type auditReq struct {
	Scan       string `json:"scan"`
	Client     string `json:"client"`
	Consultant string `json:"consultant"`
	Anonymize  bool   `json:"anonymize"`
	AI         bool   `json:"ai"`
	AIConsent  bool   `json:"ai_consent"`
	LogoB64    string `json:"logo_b64"`
}

var dirUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func (s *Server) postAudit(w http.ResponseWriter, r *http.Request) {
	var q auditReq
	if err := readJSON(r, &q); err != nil {
		fail(w, 400, "bad request")
		return
	}
	q.Client = strings.TrimSpace(q.Client)
	if q.Client == "" {
		fail(w, 400, "client name is required (it is printed on the document)")
		return
	}
	res, err := s.loadScan(q.Scan)
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	opts := report.AuditOptions{Client: q.Client, Consultant: strings.TrimSpace(q.Consultant), Anonymize: q.Anonymize, Version: s.cfg.Version, Now: time.Now()}
	if q.LogoB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(q.LogoB64)
		if err != nil {
			fail(w, 400, "logo is not valid base64")
			return
		}
		if opts.LogoDataURI, err = report.LogoFromBytes(raw); err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	note := ""
	if q.AI {
		switch {
		case !q.AIConsent:
			fail(w, 400, "AI reading needs consent after seeing the preview")
			return
		default:
			p, l, err := s.provider()
			if err != nil {
				fail(w, 400, err.Error())
				return
			}
			facts := llm.BuildFacts(res, 60)
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
			n, ck, err := llm.GenerateNarrative(ctx, p, facts, l.Language)
			cancel()
			if err != nil {
				note = "AI reading skipped: " + err.Error()
			} else {
				opts.AI = &report.AIReading{Model: p.Name(), Narrative: n, DroppedAny: ck.DroppedSentences + ck.DroppedIDs}
			}
		}
	}
	doc, err := report.RenderAudit(res, opts)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	csvb, err := report.FindingsCSV(res, opts)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	name := dirUnsafe.ReplaceAllString(history.Key(res)+"-"+time.Now().UTC().Format("20060102T150405Z"), "_")
	if q.Anonymize {
		name = "anonymized-" + time.Now().UTC().Format("20060102T150405Z")
	}
	dir := filepath.Join(s.cfg.Base, "audits", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fail(w, 500, err.Error())
		return
	}
	files := map[string][]byte{"audit.html": []byte(doc), "findings.csv": csvb}
	if !q.Anonymize {
		if h, err := report.RenderHTML(res); err == nil {
			files["report.html"] = []byte(h)
		}
	}
	var names []string
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			fail(w, 500, err.Error())
			return
		}
		names = append(names, n)
	}
	sort.Strings(names)
	writeJSON(w, 200, map[string]any{"dir": name, "path": dir, "files": names, "note": note, "anonymized": q.Anonymize})
}

func (s *Server) scanReport(w http.ResponseWriter, r *http.Request) {
	res, err := s.loadScan(r.PathValue("account") + "/" + r.PathValue("file"))
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	html, err := report.RenderHTML(res)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

var outNames = map[string]string{
	"audit.html":   "text/html; charset=utf-8",
	"report.html":  "text/html; charset=utf-8",
	"findings.csv": "text/csv; charset=utf-8",
}

func (s *Server) outFile(w http.ResponseWriter, r *http.Request) {
	dir, file := r.PathValue("dir"), r.PathValue("file")
	ct, ok := outNames[file]
	if !ok || !safeName.MatchString(dir) || strings.Contains(dir, "..") {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(filepath.Join(s.cfg.Base, "audits", dir, file))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ct)
	if strings.HasSuffix(file, ".csv") {
		w.Header().Set("Content-Disposition", `attachment; filename="`+file+`"`)
	}
	_, _ = w.Write(b)
}
