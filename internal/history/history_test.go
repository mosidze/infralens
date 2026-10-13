package history

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"infralens/internal/engine"
)

func res(account, profile string, at time.Time, waste float64) engine.ScanResult {
	return engine.ScanResult{Timestamp: at, Account: account, Profile: profile, TotalWaste: waste,
		Diff: &engine.Diff{}}
}

func TestSaveLatestRoundTrip(t *testing.T) {
	base := t.TempDir()
	r := res("123456789012", "prod", time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC), 5)
	if _, _, err := Latest(base, r); !errors.Is(err, ErrNone) {
		t.Fatalf("empty history: %v", err)
	}
	p1, err := Save(base, r, 0)
	if err != nil {
		t.Fatal(err)
	}
	r2 := res("123456789012", "prod", r.Timestamp.Add(24*time.Hour), 9)
	if _, err := Save(base, r2, 0); err != nil {
		t.Fatal(err)
	}
	path, got, err := Latest(base, r)
	if err != nil || got.TotalWaste != 9 || path == p1 {
		t.Fatalf("latest = %v %v %v", path, got.TotalWaste, err)
	}
	if got.Diff != nil {
		t.Fatal("diff must not be persisted")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", st.Mode().Perm())
	}
	dst, _ := os.Stat(filepath.Dir(path))
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", dst.Mode().Perm())
	}
}

func TestAccountsAreSeparate(t *testing.T) {
	base := t.TempDir()
	at := time.Now()
	if _, err := Save(base, res("111111111111", "a", at, 1), 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Latest(base, res("222222222222", "b", at, 0)); !errors.Is(err, ErrNone) {
		t.Fatal("other account must not see the scan")
	}
}

func TestKeyCannotEscape(t *testing.T) {
	for _, profile := range []string{"../../etc", "..", "a/b", ""} {
		k := Key(engine.ScanResult{Profile: profile})
		if filepath.Base(k) != k || k == ".." || k == "." {
			t.Errorf("Key(%q) = %q", profile, k)
		}
	}
}

func TestPrune(t *testing.T) {
	base := t.TempDir()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if _, err := Save(base, res("1", "p", at.Add(time.Duration(i)*time.Hour), float64(i)), 3); err != nil {
			t.Fatal(err)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(base, "history", "1"))
	if len(ents) != 3 {
		t.Fatalf("kept %d, want 3", len(ents))
	}
	_, got, _ := Latest(base, res("1", "p", at, 0))
	if got.TotalWaste != 4 {
		t.Fatalf("newest must survive pruning, got %v", got.TotalWaste)
	}
}
