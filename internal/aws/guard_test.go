package aws

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
)

func TestIsReadOperation(t *testing.T) {
	for _, op := range []string{"DescribeInstances", "ListClusters", "GetMetricData", "GetCostAndUsage", "GetCallerIdentity"} {
		if !IsReadOperation(op) {
			t.Errorf("%s must be allowed", op)
		}
	}
	for _, op := range []string{"DeleteVolume", "TerminateInstances", "PutRetentionPolicy", "CreateSnapshot", "ModifyDBInstance",
		"StopDBInstance", "ReleaseAddress", "TagResources", "UpdateDistribution", "", "describeInstances", "RunInstances"} {
		if IsReadOperation(op) {
			t.Errorf("%s must be refused", op)
		}
	}
}

// runGuard drives the guard the way the SDK stack does: the service metadata
// middleware sets service and operation on the context first.
func runGuard(l *APILog, op string, next middleware.InitializeHandler) error {
	return runGuardFor(l, "EC2", op, next)
}

func runGuardFor(l *APILog, service, op string, next middleware.InitializeHandler) error {
	reg := awsmiddleware.RegisterServiceMetadata{ServiceID: service, OperationName: op, Region: "eu-north-1"}
	_, _, err := reg.HandleInitialize(context.Background(), middleware.InitializeInput{},
		middleware.InitializeHandlerFunc(func(ctx context.Context, in middleware.InitializeInput) (middleware.InitializeOutput, middleware.Metadata, error) {
			return l.handle(ctx, in, next)
		}))
	return err
}

func TestGuardBlocksWritesBeforeTheyReachAWS(t *testing.T) {
	var buf bytes.Buffer
	l := NewAPILog(&buf, "prod")
	reached := false
	next := middleware.InitializeHandlerFunc(func(context.Context, middleware.InitializeInput) (middleware.InitializeOutput, middleware.Metadata, error) {
		reached = true
		return middleware.InitializeOutput{}, middleware.Metadata{}, nil
	})

	if err := runGuard(l, "DeleteVolume", next); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("a write must be blocked, got %v", err)
	}
	if reached {
		t.Fatal("a blocked operation must never reach the next handler")
	}
	if err := runGuard(l, "DescribeVolumes", next); err != nil || !reached {
		t.Fatalf("a read must pass: err=%v reached=%v", err, reached)
	}
	calls, blocked := l.Counts()
	if calls != 2 || blocked != 1 {
		t.Fatalf("counts = %d calls, %d blocked", calls, blocked)
	}
	log := buf.String()
	if !strings.Contains(log, `"operation":"DeleteVolume"`) || !strings.Contains(log, `"blocked":true`) {
		t.Fatalf("blocked call must be logged:\n%s", log)
	}
	if !strings.Contains(log, `"operation":"DescribeVolumes"`) || !strings.Contains(log, `"profile":"prod"`) {
		t.Fatalf("allowed call must be logged:\n%s", log)
	}
}

func TestGuardLogsFailuresWithoutSecrets(t *testing.T) {
	var buf bytes.Buffer
	l := NewAPILog(&buf, "")
	fail := middleware.InitializeHandlerFunc(func(context.Context, middleware.InitializeInput) (middleware.InitializeOutput, middleware.Metadata, error) {
		return middleware.InitializeOutput{}, middleware.Metadata{}, errors.New("AccessDenied: not authorised\nrequest id abc")
	})
	if err := runGuard(l, "DescribeInstances", fail); err == nil {
		t.Fatal("the underlying error must propagate")
	}
	if strings.Contains(buf.String(), "request id") {
		t.Fatalf("only the first line of an error is logged:\n%s", buf.String())
	}
}

func TestPolicyIsReadOnlyAndCoversEveryCheck(t *testing.T) {
	acts, err := Policy(Scanners(), true)
	if err != nil {
		t.Fatalf("every registered check needs IAM actions: %v", err)
	}
	for _, a := range acts {
		i := strings.IndexByte(a, ':')
		if i < 0 || !IsReadOperation(a[i+1:]) {
			t.Errorf("policy action %q is not read-only", a)
		}
	}
	// narrowing the checks narrows the policy
	few, err := Policy(mustSelect(t, "rds"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(few) >= len(acts) {
		t.Fatal("a single check must need fewer actions than all of them")
	}
	for _, a := range few {
		if strings.HasPrefix(a, "kinesis:") || strings.HasPrefix(a, "route53:") {
			t.Errorf("unrelated action %q in the rds-only policy", a)
		}
	}
	doc, err := PolicyDocument(acts)
	if err != nil || !strings.Contains(string(doc), `"Effect": "Allow"`) {
		t.Fatalf("policy document: %v", err)
	}
}

func mustSelect(t *testing.T, names ...string) []Scanner {
	t.Helper()
	s, err := SelectScanners(names, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Regression from a live run: the SDK refreshes an SSO token with
// "SSO OIDC CreateToken" and assumes roles with "STS AssumeRole". The guard
// first blocked them, which broke SSO and role profiles.
func TestGuardAllowsOnlyTheCredentialFlow(t *testing.T) {
	ok := middleware.InitializeHandlerFunc(func(context.Context, middleware.InitializeInput) (middleware.InitializeOutput, middleware.Metadata, error) {
		return middleware.InitializeOutput{}, middleware.Metadata{}, nil
	})
	l := NewAPILog(nil, "")
	for _, c := range []struct{ svc, op string }{
		{"SSO OIDC", "CreateToken"}, {"STS", "AssumeRole"}, {"STS", "AssumeRoleWithWebIdentity"}, {"STS", "GetCallerIdentity"}, {"SSO", "GetRoleCredentials"},
	} {
		if err := runGuardFor(l, c.svc, c.op, ok); err != nil {
			t.Errorf("%s %s must be allowed: %v", c.svc, c.op, err)
		}
	}
	for _, c := range []struct{ svc, op string }{
		{"EC2", "CreateToken"}, // the name alone is not enough: the service must match
		{"IAM", "CreateAccessKey"},
		{"STS", "AssumeRoot"},
		{"EC2", "DeleteVolume"},
		{"SSO OIDC", "RegisterClient"}, // not part of the refresh flow
	} {
		if err := runGuardFor(l, c.svc, c.op, ok); err == nil {
			t.Errorf("%s %s must stay blocked", c.svc, c.op)
		}
	}
}
