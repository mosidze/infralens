// Package history keeps previous scans on disk so a new scan can be
// compared with the last one. Scans contain account inventory, so the
// directory and files are private to the user.
package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"infralens/internal/engine"
)

var ErrNone = errors.New("no previous scan")

var unsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// DefaultBase is ~/.infralens.
func DefaultBase() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".infralens"), nil
}

// Key chooses the per-account directory name: the account ID when known,
// else the profile name, sanitised so it cannot escape the base directory.
func Key(res engine.ScanResult) string {
	k := res.Account
	if k == "" {
		k = "profile-" + res.Profile
	}
	k = unsafe.ReplaceAllString(k, "_")
	if k == "" || strings.Trim(k, ".") == "" {
		k = "unknown"
	}
	return k
}

func dirFor(base string, res engine.ScanResult) string {
	return filepath.Join(base, "history", Key(res))
}

// Latest returns the newest stored scan of the same account, or ErrNone.
func Latest(base string, res engine.ScanResult) (string, engine.ScanResult, error) {
	dir := dirFor(base, res)
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return "", engine.ScanResult{}, ErrNone
	}
	if err != nil {
		return "", engine.ScanResult{}, err
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", engine.ScanResult{}, ErrNone
	}
	sort.Strings(names) // names are UTC timestamps, so lexical order is time order
	path := filepath.Join(dir, names[len(names)-1])
	prev, err := Read(path)
	return path, prev, err
}

func Read(path string) (engine.ScanResult, error) {
	var r engine.ScanResult
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// Save stores the scan and keeps only the newest keep files (keep <= 0: all).
func Save(base string, res engine.ScanResult, keep int) (string, error) {
	dir := dirFor(base, res)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// The diff belongs to the comparison, not to the stored scan.
	res.Diff = nil
	b, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	name := res.Timestamp.UTC().Format("20060102T150405Z") + ".json"
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	if keep > 0 {
		prune(dir, keep)
	}
	return path, nil
}

func prune(dir string, keep int) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keep {
		_ = os.Remove(filepath.Join(dir, names[0]))
		names = names[1:]
	}
}

// Since is a helper for display: how long ago the baseline was taken.
func Since(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d d", int(d.Hours()/24))
}

// LatestForProfile returns the newest stored scan taken with a profile, across
// accounts, or ErrNone. The live monitor uses it to learn what to watch.
func LatestForProfile(base, profile string) (string, engine.ScanResult, error) {
	var bestPath string
	var best engine.ScanResult
	accts, _ := os.ReadDir(filepath.Join(base, "history"))
	for _, a := range accts {
		if !a.IsDir() {
			continue
		}
		dir := filepath.Join(base, "history", a.Name())
		files, _ := os.ReadDir(dir)
		var names []string
		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".json") {
				names = append(names, f.Name())
			}
		}
		sort.Strings(names)
		for i := len(names) - 1; i >= 0 && i >= len(names)-3; i-- { // the last few are enough to find a match
			p := filepath.Join(dir, names[i])
			r, err := Read(p)
			if err != nil || r.Profile != profile {
				continue
			}
			if bestPath == "" || r.Timestamp.After(best.Timestamp) {
				bestPath, best = p, r
			}
			break
		}
	}
	if bestPath == "" {
		return "", engine.ScanResult{}, ErrNone
	}
	return bestPath, best, nil
}
