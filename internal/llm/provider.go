// Package llm talks to language models and keeps them in their place: a
// model writes prose around facts the tool computed. It never detects, never
// supplies numbers, and anything it says about a finding is checked against
// the findings that exist before it is shown.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"infralens/internal/settings"
)

// Provider completes a prompt.
type Provider interface {
	Name() string
	// Local reports that the data stays on this machine.
	Local() bool
	Complete(ctx context.Context, system, user string) (string, error)
}

var defaultModels = map[string]string{
	"gemini":    "gemini-flash-latest",
	"openai":    "gpt-4o-mini",
	"anthropic": "claude-sonnet-4-5",
	"ollama":    "llama3.1",
}

const maxResponseBytes = 4 << 20

// New builds a provider from settings. A key is resolved through the store
// only here, at the moment of use.
func New(cfg settings.LLM, store *settings.Store, httpc *http.Client) (Provider, error) {
	if httpc == nil {
		httpc = &http.Client{Timeout: 4 * time.Minute}
	}
	model := cfg.Model
	if model == "" && cfg.Provider != "bedrock" && cfg.Provider != "" {
		// No model chosen: ask the provider what it offers now rather than
		// rely on a name that may have been retired.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if ids, err := ListModels(ctx, cfg, store, httpc); err == nil {
			model = PickDefault(cfg.Provider, ids)
		}
		cancel()
	}
	if model == "" {
		model = defaultModels[cfg.Provider]
	}
	key := func() (string, error) {
		if cfg.KeyRef == "" {
			return "", fmt.Errorf("%s needs an API key: set key_ref to env:NAME or secret:NAME", cfg.Provider)
		}
		return store.Resolve(cfg.KeyRef)
	}
	switch cfg.Provider {
	case "gemini":
		k, err := key()
		if err != nil {
			return nil, err
		}
		return &gemini{key: k, model: model, c: httpc, base: orDefault(cfg.BaseURL, "https://generativelanguage.googleapis.com")}, nil
	case "openai", "openai-compatible":
		base := cfg.BaseURL
		if cfg.Provider == "openai-compatible" && base == "" {
			return nil, fmt.Errorf("openai-compatible needs base_url")
		}
		var k string
		if cfg.KeyRef != "" {
			var err error
			if k, err = store.Resolve(cfg.KeyRef); err != nil {
				return nil, err
			}
		} else if cfg.Provider == "openai" {
			return nil, fmt.Errorf("openai needs an API key: set key_ref to env:NAME or secret:NAME")
		}
		return &openAI{key: k, model: model, c: httpc, base: orDefault(base, "https://api.openai.com"),
			local: cfg.Provider == "openai-compatible" && isLoopback(base)}, nil
	case "anthropic":
		k, err := key()
		if err != nil {
			return nil, err
		}
		return &anthropic{key: k, model: model, c: httpc, base: orDefault(cfg.BaseURL, "https://api.anthropic.com")}, nil
	case "ollama":
		return &ollama{model: model, c: httpc, base: orDefault(cfg.BaseURL, "http://127.0.0.1:11434")}, nil
	case "bedrock":
		return newBedrock(cfg, model)
	case "":
		return nil, fmt.Errorf("no language model is configured")
	}
	return nil, fmt.Errorf("unknown provider %q", cfg.Provider)
}

func orDefault(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimRight(v, "/")
}

func isLoopback(u string) bool {
	return strings.Contains(u, "://127.0.0.1") || strings.Contains(u, "://localhost") || strings.Contains(u, "://[::1]")
}

// post sends JSON and returns the body. Errors carry the status and the start
// of the body, never the request (which holds the prompt and the key).
func post(ctx context.Context, c *http.Client, url string, headers map[string]string, body any) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", stripURL(err))
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		s := strings.Join(strings.Fields(string(out)), " ")
		if len(s) > 300 {
			s = s[:300] + "…"
		}
		return nil, fmt.Errorf("model API returned %d: %s", resp.StatusCode, s)
	}
	return out, nil
}

// stripURL removes the URL from a transport error: some providers accept the
// key as a query parameter and it must not appear in messages.
func stripURL(err error) error {
	m := err.Error()
	if i := strings.Index(m, "\": "); i >= 0 && strings.Contains(m[:i], "http") {
		return fmt.Errorf("%s", m[i+3:])
	}
	return err
}

// ---- Gemini ---------------------------------------------------------------------

type gemini struct {
	key, model, base string
	c                *http.Client
}

func (g *gemini) Name() string { return "gemini:" + g.model }
func (g *gemini) Local() bool  { return false }
func (g *gemini) Complete(ctx context.Context, system, user string) (string, error) {
	body := map[string]any{
		"systemInstruction": map[string]any{"parts": []map[string]string{{"text": system}}},
		"contents":          []map[string]any{{"role": "user", "parts": []map[string]string{{"text": user}}}},
		"generationConfig":  map[string]any{"temperature": 0.2},
	}
	out, err := post(ctx, g.c, g.base+"/v1beta/models/"+g.model+":generateContent", map[string]string{"x-goog-api-key": g.key}, body)
	if err != nil {
		return "", err
	}
	var r struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return "", err
	}
	if len(r.Candidates) == 0 || len(r.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("the model returned no answer")
	}
	var sb strings.Builder
	for _, p := range r.Candidates[0].Content.Parts {
		sb.WriteString(p.Text)
	}
	return sb.String(), nil
}

// ---- OpenAI and compatible ------------------------------------------------------

type openAI struct {
	key, model, base string
	c                *http.Client
	local            bool
}

func (o *openAI) Name() string { return "openai:" + o.model }
func (o *openAI) Local() bool  { return o.local }
func (o *openAI) Complete(ctx context.Context, system, user string) (string, error) {
	h := map[string]string{}
	if o.key != "" {
		h["Authorization"] = "Bearer " + o.key
	}
	body := map[string]any{
		"model": o.model, "temperature": 0.2,
		"messages": []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}},
	}
	out, err := post(ctx, o.c, o.base+"/v1/chat/completions", h, body)
	if err != nil {
		return "", err
	}
	var r struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(out, &r); err != nil || len(r.Choices) == 0 {
		return "", fmt.Errorf("the model returned no answer")
	}
	return r.Choices[0].Message.Content, nil
}

// ---- Anthropic ------------------------------------------------------------------

type anthropic struct {
	key, model, base string
	c                *http.Client
}

func (a *anthropic) Name() string { return "anthropic:" + a.model }
func (a *anthropic) Local() bool  { return false }
func (a *anthropic) Complete(ctx context.Context, system, user string) (string, error) {
	body := map[string]any{
		"model": a.model, "max_tokens": 4096, "temperature": 0.2, "system": system,
		"messages": []map[string]string{{"role": "user", "content": user}},
	}
	out, err := post(ctx, a.c, a.base+"/v1/messages",
		map[string]string{"x-api-key": a.key, "anthropic-version": "2023-06-01"}, body)
	if err != nil {
		return "", err
	}
	var r struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, c := range r.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("the model returned no answer")
	}
	return sb.String(), nil
}

// ---- Ollama ---------------------------------------------------------------------

type ollama struct {
	model, base string
	c           *http.Client
}

func (o *ollama) Name() string { return "ollama:" + o.model }
func (o *ollama) Local() bool  { return isLoopback(o.base) }
func (o *ollama) Complete(ctx context.Context, system, user string) (string, error) {
	body := map[string]any{
		"model": o.model, "stream": false, "options": map[string]any{"temperature": 0.2},
		"messages": []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}},
	}
	out, err := post(ctx, o.c, o.base+"/api/chat", nil, body)
	if err != nil {
		return "", err
	}
	var r struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(out, &r); err != nil || r.Message.Content == "" {
		return "", fmt.Errorf("the model returned no answer")
	}
	return r.Message.Content, nil
}
