package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const DefaultModel = "gemini-3.1-pro-preview"

type Client struct {
	APIKey string
	Model  string
	HTTP   *http.Client
}

func NewClient(model string) (*Client, error) {
	key := os.Getenv("GEMINI_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("GEMINI_API_KEY is not set")
	}
	if model == "" {
		model = DefaultModel
	}
	return &Client{APIKey: key, Model: model, HTTP: &http.Client{Timeout: 3 * time.Minute}}, nil
}

const promptHeader = `Ты ведущий Cloud Architect и эксперт по оптимизации AWS.
Ниже JSON с обезличенным инвентарём AWS-аккаунта: идентификаторы заменены алиасами, стоимость оценочная.
Поля status: managed (под IaC), shadow_it (нет маркеров IaC), orphan_waste (неиспользуемый ресурс).

Составь структурированное заключение:
1. Executive Summary: общий вердикт, соотношение managed и shadow_it.
2. Потери (monthly waste): список найденного мусора и сколько он стоит; учитывай confidence.
3. Архитектурные риски: неизолированные ресурсы, сервисы без маркеров IaC.
4. Action Plan: безопасные шаги зачистки (снепшот перед удалением, порядок, откат).

Не придумывай ресурсы, которых нет в данных. Пиши емко, инженерным языком.

`

// Prompt renders the full text sent to the model for a payload.
func Prompt(p MaskedPayload) (string, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	return promptHeader + string(b), nil
}

func (c *Client) Analyze(ctx context.Context, prompt string) (string, error) {
	endpoint := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", url.PathEscape(c.Model))
	body, err := json.Marshal(map[string]any{
		"contents": []map[string]any{{"parts": []map[string]any{{"text": prompt}}}},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini api error (%d): %s", resp.StatusCode, truncate(string(respBody), 300))
	}

	var res struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(respBody, &res); err != nil {
		return "", err
	}
	if len(res.Candidates) > 0 && len(res.Candidates[0].Content.Parts) > 0 {
		return res.Candidates[0].Content.Parts[0].Text, nil
	}
	return "", fmt.Errorf("gemini returned no candidates")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
