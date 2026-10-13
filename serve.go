package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"strings"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"

	"infralens/internal/app"
	awsDiscovery "infralens/internal/aws"
	"infralens/internal/history"
	"infralens/internal/settings"
)

// runServe starts the local web application. It listens on loopback only and
// prints a one-time address; the browser exchanges the token for a cookie.
func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", defaultServeAddr, "loopback address to listen on (port 0 = pick a free one)")
	home := fs.String("home", "", "data directory (default ~/.infralens)")
	noOpen := fs.Bool("no-open", false, "do not try to open the browser")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	base := *home
	if base == "" {
		b, err := history.DefaultBase()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
		base = b
	}
	ln, err := app.Listen(*addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if strings.Contains(err.Error(), "address already in use") {
			fmt.Fprintf(os.Stderr, "InfraLens may already be running on %s (open that address in the browser), or choose another port with --addr 127.0.0.1:PORT\n", *addr)
		}
		return exitError
	}
	token, err := loadOrCreateToken(base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	srv, err := app.New(app.Config{
		Token: token,
		Base:  base, Store: settings.NewStore(base), Version: version,
		Hooks: app.Hooks{Profiles: awsDiscovery.ListProfiles, Scan: scanHook(base)},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	url := fmt.Sprintf("http://%s/?t=%s", ln.Addr(), srv.Token())
	fmt.Println("InfraLens is running. Open this address once; the browser then remembers it:")
	fmt.Println("  " + url)
	fmt.Printf("After that, http://%s/ is enough.\n", ln.Addr())
	fmt.Println("Press Ctrl+C to stop.")
	if !*noOpen {
		openBrowser(url)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := srv.Serve(ctx, ln); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	return exitOK
}

// defaultServeAddr is fixed so that a bookmark or a shortcut keeps working.
const defaultServeAddr = "127.0.0.1:8765"

// loadOrCreateToken keeps the access token between runs in a private file, so
// a bookmarked address and the browser's cookie stay valid. The file is as
// sensitive as the secrets next to it and has the same mode.
func loadOrCreateToken(base string) (string, error) {
	path := filepath.Join(base, "serve.token")
	if b, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(b)); len(t) >= 32 {
			return t, nil
		}
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	t := hex.EncodeToString(buf)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	return t, nil
}

func scanHook(base string) func(context.Context, app.ScanRequest, string, func(string)) (string, error) {
	return func(ctx context.Context, r app.ScanRequest, contextFile string, progress func(string)) (string, error) {
		f := newScanFlags()
		f.profile, f.regions, f.services = r.Profile, r.Regions, r.Services
		f.tfstate, f.prowler, f.ssoLogin = r.TFState, r.Prowler, r.SSOLogin
		f.contextPath = contextFile
		f.historyDir = base
		f.htmlOut, f.jsonOut = "", ""
		f.progress = progress
		_, _, err := scanProfile(ctx, f, r.Profile, false)
		if err != nil {
			return "", err
		}
		if f.savedAs == "" {
			return "", fmt.Errorf("the scan finished but was not saved")
		}
		return f.savedAs, nil
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return
	}
	_ = cmd.Start() // best effort; the address is printed anyway
}
