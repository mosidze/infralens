package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"infralens/internal/settings"
)

func TestGeminiModelsAreFetchedAndFilteredAndDefaultIsNotRetired(t *testing.T) {
	var gotKey string
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1beta/models") && r.Method == "GET":
			gotKey = r.Header.Get("x-goog-api-key")
			w.Write([]byte(`{"models":[
			 {"name":"models/gemini-2.0-flash","supportedGenerationMethods":["generateContent"]},
			 {"name":"models/gemini-3.8-flash","supportedGenerationMethods":["generateContent"]},
			 {"name":"models/gemini-3.8-flash-lite","supportedGenerationMethods":["generateContent"]},
			 {"name":"models/gemini-3.8-pro-preview","supportedGenerationMethods":["generateContent"]},
			 {"name":"models/text-embedding-9","supportedGenerationMethods":["embedContent"]}]}`))
		default:
			asked = r.URL.Path
			w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`))
		}
	}))
	defer srv.Close()
	t.Setenv("TEST_GEMINI_KEY", "k-123")
	st := settings.NewStore(t.TempDir())
	cfg := settings.LLM{Provider: "gemini", KeyRef: "env:TEST_GEMINI_KEY", BaseURL: srv.URL}

	ids, err := ListModels(context.Background(), cfg, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gotKey != "k-123" {
		t.Fatal("key not sent as header")
	}
	for _, id := range ids {
		if strings.Contains(id, "embedding") {
			t.Fatalf("model that cannot generate listed: %s", id)
		}
	}
	if got := PickDefault("gemini", ids); got != "gemini-3.8-flash" {
		t.Fatalf("default = %q, want the newest plain flash", got)
	}

	// with no model chosen, New asks the provider instead of using a stale name
	p, err := New(cfg, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(asked, "gemini-3.8-flash:generateContent") {
		t.Fatalf("called %q", asked)
	}
}

func TestOllamaAndOpenAIListsAndFallbackWhenListingFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			w.Write([]byte(`{"models":[{"name":"llama3.1:8b"},{"name":"qwen3:14b"}]}`))
		case "/v1/models":
			w.Write([]byte(`{"data":[{"id":"gpt-9-mini"},{"id":"text-embedding-3-small"},{"id":"whisper-1"},{"id":"gpt-9"}]}`))
		default:
			http.Error(w, "no", 500)
		}
	}))
	defer srv.Close()
	st := settings.NewStore(t.TempDir())
	ids, err := ListModels(context.Background(), settings.LLM{Provider: "ollama", BaseURL: srv.URL}, st, nil)
	if err != nil || len(ids) != 2 {
		t.Fatalf("ollama: %v %v", ids, err)
	}
	t.Setenv("K", "x")
	ids, err = ListModels(context.Background(), settings.LLM{Provider: "openai", BaseURL: srv.URL, KeyRef: "env:K"}, st, nil)
	if err != nil || strings.Join(ids, ",") != "gpt-9,gpt-9-mini" {
		t.Fatalf("openai: %v %v", ids, err)
	}
	// listing fails (500): New still works with the built-in fallback name
	t.Setenv("K2", "x")
	p, err := New(settings.LLM{Provider: "anthropic", KeyRef: "env:K2", BaseURL: srv.URL}, st, nil)
	if err != nil || !strings.HasPrefix(p.Name(), "anthropic:") {
		t.Fatalf("fallback: %v %v", p, err)
	}
	if _, err := ListModels(context.Background(), settings.LLM{Provider: "bedrock"}, st, nil); err == nil {
		t.Fatal("bedrock listing should explain itself")
	}
}

func TestPickDefaultSkipsNonChatModelsAndComparesVersionsNumerically(t *testing.T) {
	ids := []string{"gemini-2.5-flash", "gemini-3.5-flash", "gemini-3.10-flash", "gemini-3.8-flash", "gemini-3.8-flash-tts",
		"gemini-omni-1.1-flash", "antigravity-preview-09-2026", "gemini-3.8-flash-lite", "gemini-flash-latest", "gemini-3.1-pro-preview"}
	if got := PickDefault("gemini", ids); got != "gemini-3.10-flash" {
		t.Fatalf("got %q", got)
	}
	if got := PickDefault("anthropic", []string{"claude-haiku-4-5", "claude-sonnet-4-5", "claude-opus-4-5"}); got != "claude-sonnet-4-5" {
		t.Fatalf("anthropic: %q", got)
	}
}
