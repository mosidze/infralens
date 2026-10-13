package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const iconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
<rect width="64" height="64" rx="14" fill="#2457d6"/>
<circle cx="28" cy="28" r="14" fill="none" stroke="#fff" stroke-width="5"/>
<path d="M39 39 L52 52" stroke="#fff" stroke-width="6" stroke-linecap="round"/>
</svg>
`

// runShortcut creates a launcher for `infralens serve`: a menu entry (and
// optionally a desktop icon) on Linux, a double-clickable .command on macOS.
// It only writes files in the user's own directories and never needs root.
func runShortcut(args []string) int {
	fs := flag.NewFlagSet("shortcut", flag.ContinueOnError)
	desktop := fs.Bool("desktop", false, "also put the launcher on the desktop")
	remove := fs.Bool("remove", false, "remove the launcher instead")
	addr := fs.String("addr", "", "address to serve on (default: the built-in fixed port)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot find this program:", err)
		return exitError
	}
	if strings.Contains(exe, "/go-build") || strings.HasPrefix(exe, os.TempDir()) {
		fmt.Fprintln(os.Stderr, "error: this looks like a temporary build; install the binary somewhere permanent first and run `shortcut` from there")
		return exitError
	}
	var paths []string
	switch runtime.GOOS {
	case "linux":
		paths, err = linuxShortcut(home, exe, *addr, *desktop, *remove)
	case "darwin":
		paths, err = macShortcut(home, exe, *addr, *remove)
	default:
		fmt.Fprintln(os.Stderr, "error: shortcuts are supported on Linux and macOS; on other systems run `infralens serve`")
		return exitError
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	verb := "created"
	if *remove {
		verb = "removed"
	}
	for _, p := range paths {
		fmt.Printf("[+] %s %s\n", verb, p)
	}
	return exitOK
}

// quoteExec quotes one argument for a freedesktop Exec line.
func quoteExec(s string) string {
	r := strings.NewReplacer(`\`, `\\\\`, `"`, `\"`, "`", "\\`", `$`, `\\$`)
	return `"` + r.Replace(s) + `"`
}

func desktopEntry(exe, addr, icon string) string {
	cmd := quoteExec(exe) + " serve"
	if addr != "" {
		cmd += " --addr " + quoteExec(addr)
	}
	return "[Desktop Entry]\nType=Application\nName=InfraLens\nComment=Read-only AWS audit: scan, map, reports\n" +
		"Exec=" + cmd + "\nIcon=" + icon + "\nTerminal=true\nCategories=Utility;\nStartupNotify=false\n"
}

func linuxShortcut(home, exe, addr string, desktop, remove bool) ([]string, error) {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		dataHome = filepath.Join(home, ".local", "share")
	}
	apps := filepath.Join(dataHome, "applications")
	icons := filepath.Join(dataHome, "icons", "hicolor", "scalable", "apps")
	entry := filepath.Join(apps, "infralens.desktop")
	icon := filepath.Join(icons, "infralens.svg")
	targets := []string{entry}
	if desktop {
		d := filepath.Join(home, "Desktop")
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			targets = append(targets, filepath.Join(d, "InfraLens.desktop"))
		}
	}
	if remove {
		var done []string
		for _, t := range append(targets, icon) {
			if err := os.Remove(t); err == nil {
				done = append(done, t)
			}
		}
		return done, nil
	}
	for _, d := range []string{apps, icons} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(icon, []byte(iconSVG), 0o644); err != nil {
		return nil, err
	}
	body := desktopEntry(exe, addr, icon)
	for _, t := range targets {
		if err := os.WriteFile(t, []byte(body), 0o755); err != nil {
			return nil, err
		}
	}
	return append(targets, icon), nil
}

func macShortcut(home, exe, addr string, remove bool) ([]string, error) {
	dir := filepath.Join(home, "Applications")
	path := filepath.Join(dir, "InfraLens.command")
	if remove {
		if err := os.Remove(path); err != nil {
			return nil, nil
		}
		return []string{path}, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	cmd := "exec " + q(exe) + " serve"
	if addr != "" {
		cmd += " --addr " + q(addr)
	}
	if err := os.WriteFile(path, []byte("#!/bin/bash\n"+cmd+"\n"), 0o755); err != nil {
		return nil, err
	}
	return []string{path}, nil
}
