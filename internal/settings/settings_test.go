package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSettingsAndSecretsAreSeparateAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s := NewStore(dir)
	st := Settings{LLM: LLM{Provider: "anthropic", Model: "m", KeyRef: "secret:anthropic"}}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret("anthropic", "sk-ant-VERY-SECRET"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil || got.LLM.Provider != "anthropic" || got.LLM.KeyRef != "secret:anthropic" {
		t.Fatalf("%+v %v", got, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
	if strings.Contains(string(b), "VERY-SECRET") {
		t.Fatal("the secret must never be in the settings file")
	}
	for _, f := range []string{"settings.json", "secrets.json"} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, fi, err)
		}
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode().Perm())
	}
	v, err := s.Resolve("secret:anthropic")
	if err != nil || v != "sk-ant-VERY-SECRET" {
		t.Fatalf("%q %v", v, err)
	}
	if !s.HasSecret("anthropic") || s.HasSecret("nope") {
		t.Fatal("HasSecret")
	}
	// removal
	_ = s.SetSecret("anthropic", "")
	if s.HasSecret("anthropic") {
		t.Fatal("empty value deletes the secret")
	}
}

func TestResolveReferences(t *testing.T) {
	s := NewStore(t.TempDir())
	t.Setenv("MY_LLM_KEY", "abc")
	if v, err := s.Resolve("env:MY_LLM_KEY"); err != nil || v != "abc" {
		t.Fatalf("%q %v", v, err)
	}
	if _, err := s.Resolve("env:NOT_SET_ANYWHERE"); err == nil {
		t.Fatal("unset variable must be an error")
	}
	if v, err := s.Resolve(""); err != nil || v != "" {
		t.Fatal("no reference means no key (local models)")
	}
	if _, err := s.Resolve("sk-pasted-the-key-here"); err == nil {
		t.Fatal("a raw key is not a reference")
	}
}

func TestSaveRefusesAPastedKey(t *testing.T) {
	s := NewStore(t.TempDir())
	for _, k := range []string{"sk-this is a key", "sk-proj-abcdefghijklmnop", "AIzaSyD-abcdef"} {
		if err := s.Save(Settings{LLM: LLM{Provider: "openai", KeyRef: k}}); err == nil {
			t.Fatalf("%q looks like a key and must be refused so it does not land in the settings file", k)
		}
	}
	if err := s.Save(Settings{LLM: LLM{Provider: "openai", KeyRef: "env:OPENAI_API_KEY"}}); err != nil {
		t.Fatal(err)
	}
}
