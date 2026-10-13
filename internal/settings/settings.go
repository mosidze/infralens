// Package settings keeps the user's configuration (which model to ask,
// where it lives) apart from the secrets that go with it. Settings can be
// shown, exported and backed up; secrets never leave their own file.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// LLM describes how to reach a language model. KeyRef names a secret; it
// never holds the secret itself.
type LLM struct {
	Provider string `json:"provider"` // gemini | openai | anthropic | ollama | openai-compatible | bedrock | ""
	Model    string `json:"model,omitempty"`
	BaseURL  string `json:"base_url,omitempty"`
	KeyRef   string `json:"key_ref,omitempty"` // env:NAME | secret:NAME
	Profile  string `json:"profile,omitempty"` // AWS profile for bedrock
	Region   string `json:"region,omitempty"`  // AWS region for bedrock
	Language string `json:"language,omitempty"`
}

type Settings struct {
	LLM            LLM    `json:"llm"`
	DefaultProfile string `json:"default_profile,omitempty"`
}

// Store reads and writes settings and secrets under one directory.
type Store struct {
	dir string
	mu  sync.Mutex
}

// DefaultDir is ~/.infralens.
func DefaultDir() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".infralens"), nil
}

func NewStore(dir string) *Store { return &Store{dir: dir} }

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

func (s *Store) ensure() error { return os.MkdirAll(s.dir, 0o700) }

func writePrivate(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) Load() (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var st Settings
	b, err := os.ReadFile(s.path("settings.json"))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("settings.json: %w", err)
	}
	return st, nil
}

func (s *Store) Save(st Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensure(); err != nil {
		return err
	}
	// A pasted key must never land in this file: only references are allowed.
	if r := st.LLM.KeyRef; r != "" && !strings.HasPrefix(r, "env:") && !strings.HasPrefix(r, "secret:") {
		return fmt.Errorf("key_ref must be a reference (env:NAME or secret:NAME), not the key itself")
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	return writePrivate(s.path("settings.json"), b)
}

// ---- secrets ------------------------------------------------------------------

func (s *Store) readSecrets() (map[string]string, error) {
	m := map[string]string{}
	b, err := os.ReadFile(s.path("secrets.json"))
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("secrets.json: %w", err)
	}
	return m, nil
}

// SetSecret stores a value under a name in a file readable only by the user.
func (s *Store) SetSecret(name, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" || strings.ContainsAny(name, " :/") {
		return fmt.Errorf("invalid secret name")
	}
	if err := s.ensure(); err != nil {
		return err
	}
	m, err := s.readSecrets()
	if err != nil {
		return err
	}
	if value == "" {
		delete(m, name)
	} else {
		m[name] = value
	}
	b, _ := json.Marshal(m)
	return writePrivate(s.path("secrets.json"), b)
}

// HasSecret says whether a named secret exists, without revealing it.
func (s *Store) HasSecret(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readSecrets()
	return err == nil && m[name] != ""
}

// Resolve turns a reference into the secret: env:NAME reads the environment,
// secret:NAME reads the private secrets file.
func (s *Store) Resolve(ref string) (string, error) {
	switch {
	case ref == "":
		return "", nil
	case strings.HasPrefix(ref, "env:"):
		name := strings.TrimPrefix(ref, "env:")
		v := os.Getenv(name)
		if v == "" {
			return "", fmt.Errorf("environment variable %s is not set", name)
		}
		return v, nil
	case strings.HasPrefix(ref, "secret:"):
		s.mu.Lock()
		defer s.mu.Unlock()
		m, err := s.readSecrets()
		if err != nil {
			return "", err
		}
		name := strings.TrimPrefix(ref, "secret:")
		if m[name] == "" {
			return "", fmt.Errorf("no secret named %q; set it in settings", name)
		}
		return m[name], nil
	}
	return "", fmt.Errorf("unknown key reference %q (use env:NAME or secret:NAME)", ref)
}
