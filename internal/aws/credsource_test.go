package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func withRunner(t *testing.T, f func(ctx context.Context, args ...string) ([]byte, error)) {
	t.Helper()
	old := cliRunner
	cliRunner = f
	t.Cleanup(func() { cliRunner = old })
}

func TestExportCLICredentials(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	var got []string
	withRunner(t, func(_ context.Context, args ...string) ([]byte, error) {
		got = args
		return []byte(`{"Version":1,"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"s3cr3t","SessionToken":"tok","Expiration":"` + exp + `"}`), nil
	})
	c, err := exportCLICredentials(context.Background(), "prod")
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != "ASIAEXAMPLE" || c.SessionToken != "tok" || !c.CanExpire || c.Expires.IsZero() {
		t.Fatalf("%+v", c)
	}
	if strings.Join(got, " ") != "configure export-credentials --format process --profile prod" {
		t.Fatalf("args: %v", got)
	}
}

func TestExportCLICredentialsRejectsBadOutput(t *testing.T) {
	for name, out := range map[string]string{"empty": `{}`, "garbage": `not json`, "no secret": `{"AccessKeyId":"A"}`} {
		withRunner(t, func(context.Context, ...string) ([]byte, error) { return []byte(out), nil })
		if _, err := exportCLICredentials(context.Background(), "p"); err == nil {
			t.Errorf("%s must be an error", name)
		}
	}
	withRunner(t, func(context.Context, ...string) ([]byte, error) { return nil, errors.New("exit 255") })
	if _, err := exportCLICredentials(context.Background(), "p"); err == nil {
		t.Error("CLI failure must be an error")
	}
}

func TestIsSSOFailure(t *testing.T) {
	for _, m := range []string{
		"failed to refresh cached credentials, refresh cached SSO token failed",
		"operation error SSO OIDC: CreateToken ... InvalidGrantException",
		"the SSO session token has expired",
	} {
		if !isSSOFailure(errors.New(m)) {
			t.Errorf("must be treated as an SSO failure: %s", m)
		}
	}
	// a real permission problem must not trigger a credential fallback
	if isSSOFailure(errors.New("AccessDenied: not authorized to perform ec2:DescribeInstances")) || isSSOFailure(nil) {
		t.Error("only SSO failures fall back to the CLI")
	}
}
