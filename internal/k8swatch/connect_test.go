package k8swatch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func TestConnectConfigIsReadOnlyAndLeavesTheCallersConfigAlone(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"NamespaceList","apiVersion":"v1","items":[]}`))
	}))
	defer srv.Close()

	in := &rest.Config{Host: srv.URL, BearerToken: "t0ken"}
	conn, err := ConnectConfig(in, "vault")
	if err != nil {
		t.Fatal(err)
	}
	if in.WrapTransport != nil || in.QPS != 0 {
		t.Fatal("ConnectConfig modified the caller's config")
	}
	if conn.Context != "vault" || conn.Server == "" {
		t.Fatalf("labels: context=%q server=%q", conn.Context, conn.Server)
	}
	if _, err := conn.Client.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if auth != "Bearer t0ken" {
		t.Fatalf("token not sent: %q", auth)
	}
	if err := conn.Client.CoreV1().Namespaces().Delete(context.Background(), "x", metav1.DeleteOptions{}); err == nil {
		t.Fatal("a delete went through")
	}
	if calls, blocked := conn.Counter.Counts(); calls != 1 || blocked != 1 {
		t.Fatalf("counts: calls=%d blocked=%d", calls, blocked)
	}
}

func TestConnectConfigNeedsAnAddress(t *testing.T) {
	if _, err := ConnectConfig(&rest.Config{}, "x"); err == nil {
		t.Fatal("empty host accepted")
	}
	if _, err := ConnectConfig(nil, "x"); err == nil {
		t.Fatal("nil config accepted")
	}
}
