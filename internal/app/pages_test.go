package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"infralens/internal/settings"
)

func TestPagesAreServedBehindTheGuardAndListedInState(t *testing.T) {
	base := t.TempDir()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "page:"+r.URL.Path) })
	s, err := New(Config{Base: base, Store: settings.NewStore(base), Token: "tok", Pages: []Page{{Name: "digest", Label: "Digest", Handler: h}}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	s.SetAllowedHosts(strings.TrimPrefix(ts.URL, "http://"))

	// no cookie: refused like any other path
	resp, _ := http.Get(ts.URL + "/x/digest/")
	if resp.StatusCode != 401 {
		t.Fatalf("no cookie: %d", resp.StatusCode)
	}
	r := do(t, ts, "GET", "/x/digest/latest", "", nil)
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || string(b) != "page:/latest" {
		t.Fatalf("page: %d %q", r.StatusCode, b)
	}
	if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'self'") || !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("page must be frameable by the app and same-origin only: %q", csp)
	}
	r = do(t, ts, "GET", "/api/state", "", nil)
	var st struct {
		Pages []pageView `json:"pages"`
	}
	json.NewDecoder(r.Body).Decode(&st)
	if len(st.Pages) != 1 || st.Pages[0].Name != "digest" || st.Pages[0].Label != "Digest" {
		t.Fatalf("state pages: %+v", st.Pages)
	}
}

func TestBadPagesAreRefused(t *testing.T) {
	base := t.TempDir()
	h := http.NotFoundHandler()
	for _, p := range [][]Page{
		{{Name: "../x", Label: "a", Handler: h}},
		{{Name: "a", Label: "", Handler: h}},
		{{Name: "a", Label: "a"}},
		{{Name: "a", Label: "a", Handler: h}, {Name: "a", Label: "b", Handler: h}},
	} {
		if _, err := New(Config{Base: base, Store: settings.NewStore(base), Pages: p}); err == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
}
