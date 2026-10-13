package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"infralens/internal/settings"
)

// ListModels asks the provider which models it offers right now. Providers
// retire and add models often, so the list is fetched, not hard-coded. It only
// sends the key; no inventory data is involved.
func ListModels(ctx context.Context, cfg settings.LLM, store *settings.Store, httpc *http.Client) ([]string, error) {
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	key := ""
	if cfg.KeyRef != "" {
		k, err := store.Resolve(cfg.KeyRef)
		if err != nil {
			return nil, err
		}
		key = k
	}
	var ids []string
	switch cfg.Provider {
	case "gemini":
		if key == "" {
			return nil, fmt.Errorf("gemini needs an API key")
		}
		base := orDefault(cfg.BaseURL, "https://generativelanguage.googleapis.com")
		next := ""
		for page := 0; page < 5; page++ {
			u := base + "/v1beta/models?pageSize=200"
			if next != "" {
				u += "&pageToken=" + url.QueryEscape(next)
			}
			var r struct {
				Models []struct {
					Name    string   `json:"name"`
					Methods []string `json:"supportedGenerationMethods"`
				} `json:"models"`
				Next string `json:"nextPageToken"`
			}
			if err := getJSON(ctx, httpc, u, map[string]string{"x-goog-api-key": key}, &r); err != nil {
				return nil, err
			}
			for _, m := range r.Models {
				for _, meth := range m.Methods {
					if meth == "generateContent" {
						ids = append(ids, strings.TrimPrefix(m.Name, "models/"))
						break
					}
				}
			}
			if next = r.Next; next == "" {
				break
			}
		}
	case "openai", "openai-compatible":
		h := map[string]string{}
		if key != "" {
			h["Authorization"] = "Bearer " + key
		}
		base := orDefault(cfg.BaseURL, "https://api.openai.com")
		var r struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := getJSON(ctx, httpc, base+"/v1/models", h, &r); err != nil {
			return nil, err
		}
		for _, m := range r.Data {
			ids = append(ids, m.ID)
		}
		if cfg.Provider == "openai" {
			ids = filterOut(ids, "embed", "tts", "whisper", "dall-e", "moderation", "transcribe", "image", "audio", "realtime", "search", "davinci", "babbage", "instruct")
		}
	case "anthropic":
		if key == "" {
			return nil, fmt.Errorf("anthropic needs an API key")
		}
		base := orDefault(cfg.BaseURL, "https://api.anthropic.com")
		var r struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := getJSON(ctx, httpc, base+"/v1/models?limit=100", map[string]string{"x-api-key": key, "anthropic-version": "2023-06-01"}, &r); err != nil {
			return nil, err
		}
		for _, m := range r.Data {
			ids = append(ids, m.ID)
		}
	case "ollama":
		base := orDefault(cfg.BaseURL, "http://127.0.0.1:11434")
		var r struct {
			Models []struct {
				Name string `json:"name"`
			} `json:"models"`
		}
		if err := getJSON(ctx, httpc, base+"/api/tags", nil, &r); err != nil {
			return nil, err
		}
		for _, m := range r.Models {
			ids = append(ids, m.Name)
		}
	case "bedrock":
		return nil, fmt.Errorf("bedrock model ids depend on region and access; enter a model id or inference profile id")
	case "":
		return nil, fmt.Errorf("choose a provider first")
	default:
		return nil, fmt.Errorf("unknown provider %q", cfg.Provider)
	}
	sort.Strings(ids)
	return ids, nil
}

func filterOut(ids []string, words ...string) []string {
	var out []string
next:
	for _, id := range ids {
		l := strings.ToLower(id)
		for _, w := range words {
			if strings.Contains(l, w) {
				continue next
			}
		}
		out = append(out, id)
	}
	return out
}

// PickDefault chooses a sensible model from a fetched list: a general-purpose
// text model of the preferred family, newest version. Providers list many
// models that accept the same call but are not chat models (speech, image,
// agents), so those are screened out by name. It is a convenience; the
// user can always choose another.
func PickDefault(provider string, ids []string) string {
	prefer := map[string][]string{
		"gemini":    {"flash"},
		"openai":    {"mini", "gpt"},
		"anthropic": {"sonnet", "haiku"},
	}[provider]
	avoid := []string{"preview", "exp", "lite", "thinking", "image", "tts", "audio", "embed", "vision", "live",
		"robotics", "computer", "customtools", "learnlm", "gemma", "nano", "banana", "omni", "antigravity",
		"research", "lyria", "transcribe", "veo", "imagen", "-latest", "codex", "search", "pro-"}
	good := filterOut(ids, avoid...)
	if len(good) == 0 {
		good = ids
	}
	newest := func(c []string) string {
		best := c[0]
		for _, id := range c[1:] {
			if v, w := versionOf(id), versionOf(best); versionLess(w, v) || (!versionLess(v, w) && id > best) {
				best = id
			}
		}
		return best
	}
	for _, p := range prefer {
		var c []string
		for _, id := range good {
			if strings.Contains(strings.ToLower(id), p) {
				c = append(c, id)
			}
		}
		if len(c) > 0 {
			return newest(c)
		}
	}
	if len(good) > 0 {
		return newest(good)
	}
	return ""
}

var versionRe = regexp.MustCompile(`\d+(?:\.\d+)*`)

// versionOf returns the first dotted number in an id (gemini-3.8-flash -> [3 8]).
func versionOf(id string) []int {
	m := versionRe.FindString(id)
	var v []int
	for _, p := range strings.Split(m, ".") {
		n, _ := strconv.Atoi(p)
		v = append(v, n)
	}
	return v
}

func versionLess(a, b []int) bool {
	for i := 0; i < len(a) || i < len(b); i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func getJSON(ctx context.Context, c *http.Client, u string, headers map[string]string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", stripURL(err))
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		s := strings.Join(strings.Fields(string(b)), " ")
		if len(s) > 300 {
			s = s[:300] + "…"
		}
		return fmt.Errorf("model API returned %d: %s", resp.StatusCode, s)
	}
	return json.Unmarshal(b, v)
}
