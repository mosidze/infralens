// Package k8swatch is the Kubernetes side of the Problem Monitor. It judges
// health per workload, not per pod: a Deployment with all its replicas ready
// is healthy however many of its pods have restarted over the months, and a
// pod is only shown as evidence for the workload it belongs to.
//
// Like the AWS side it is read-only by construction: the transport refuses
// anything but GET and HEAD, so list and watch work and nothing can be
// created, changed or deleted.
package k8swatch

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Counter records how many requests were sent and how many were refused.
type Counter struct{ calls, blocked atomic.Int64 }

func (c *Counter) Counts() (int, int) { return int(c.calls.Load()), int(c.blocked.Load()) }

type readOnly struct {
	next http.RoundTripper
	c    *Counter
}

func (r readOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		r.c.blocked.Add(1)
		return nil, fmt.Errorf("blocked: %s %s is not a read; this tool never changes a cluster", req.Method, req.URL.Path)
	}
	r.c.calls.Add(1)
	return r.next.RoundTrip(req)
}

func loading(kubeconfig string) *clientcmd.ClientConfigLoadingRules {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	return rules
}

// Contexts lists the contexts of a kubeconfig (the default chain when empty).
func Contexts(kubeconfig string) ([]string, error) {
	cfg, err := loading(kubeconfig).Load()
	if err != nil {
		return nil, err
	}
	var out []string
	for name := range cfg.Contexts {
		out = append(out, name)
	}
	sortStrings(out)
	return out, nil
}

// Connection is a read-only client plus what the screen may say about it.
type Connection struct {
	Client  kubernetes.Interface
	Context string
	Server  string // host only, never credentials
	Counter *Counter
}

// Connect builds a read-only client for one context.
func Connect(kubeconfig, context string) (*Connection, error) {
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading(kubeconfig), &clientcmd.ConfigOverrides{CurrentContext: context})
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, err
	}
	return ConnectConfig(cfg, context)
}

// ConnectConfig builds a read-only client from a REST config that the caller
// assembled itself, for a service that gets its token from a secret store
// rather than a kubeconfig file. name labels the connection on screen. The
// caller's config is not modified.
func ConnectConfig(in *rest.Config, name string) (*Connection, error) {
	if in == nil || in.Host == "" {
		return nil, errors.New("no API server address")
	}
	cfg := rest.CopyConfig(in)
	counter := &Counter{}
	cfg.QPS, cfg.Burst, cfg.Timeout = 20, 40, 30e9
	prev := cfg.WrapTransport
	cfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		if prev != nil {
			rt = prev(rt)
		}
		return readOnly{next: rt, c: counter}
	}
	cs, err := kubernetes.NewForConfig(rest.CopyConfig(cfg))
	if err != nil {
		return nil, err
	}
	return &Connection{Client: cs, Context: name, Server: host(cfg.Host), Counter: counter}, nil
}

func host(s string) string {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Host
	}
	return strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
}

var errNoContext = errors.New("no such context in the kubeconfig")

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
