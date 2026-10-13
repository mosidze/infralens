package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxShortcutWritesEntryAndIconAndRemovesThem(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "share"))
	if err := os.MkdirAll(filepath.Join(home, "Desktop"), 0o755); err != nil {
		t.Fatal(err)
	}
	exe := `/opt/my tools/infra"lens`
	paths, err := linuxShortcut(home, exe, "", true, false)
	if err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(home, "share", "applications", "infralens.desktop")
	b, err := os.ReadFile(entry)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `Exec="/opt/my tools/infra\"lens" serve`) {
		t.Fatalf("Exec line is not quoted: %s", s)
	}
	if !strings.Contains(s, "Terminal=true") || !strings.Contains(s, "Icon="+filepath.Join(home, "share", "icons")) {
		t.Fatalf("entry: %s", s)
	}
	if _, err := os.Stat(filepath.Join(home, "Desktop", "InfraLens.desktop")); err != nil {
		t.Fatal("desktop copy missing")
	}
	if len(paths) != 3 {
		t.Fatalf("paths: %v", paths)
	}
	st, _ := os.Stat(entry)
	if st.Mode().Perm()&0o100 == 0 {
		t.Fatal("launcher must be executable")
	}
	if _, err := linuxShortcut(home, exe, "", true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(entry); !os.IsNotExist(err) {
		t.Fatal("entry not removed")
	}
}

func TestTokenIsStableAcrossRunsAndPrivate(t *testing.T) {
	dir := t.TempDir()
	a, err := loadOrCreateToken(dir)
	if err != nil || len(a) < 32 {
		t.Fatalf("token: %q %v", a, err)
	}
	b, _ := loadOrCreateToken(dir)
	if a != b {
		t.Fatal("token changed between runs; bookmarks would break")
	}
	st, _ := os.Stat(filepath.Join(dir, "serve.token"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
}
