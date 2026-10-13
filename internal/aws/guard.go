package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
)

// The tool promises read-only access. That promise is enforced in code, not
// by convention: every SDK call passes through this guard, which refuses any
// operation whose name is not Describe*, List* or Get*. A bug or a future
// edit that tries to change something fails loudly instead of changing it.

var readPrefixes = []string{"Describe", "List", "Get"}

// IsReadOperation reports whether an AWS API operation name is read-only by
// the naming convention the guard enforces.
func IsReadOperation(op string) bool {
	for _, p := range readPrefixes {
		if strings.HasPrefix(op, p) {
			return true
		}
	}
	return false
}

// credentialFlow lists the calls the SDK itself makes to obtain or refresh a
// session. They create a token, they do not change anything in the audited
// account, and without them SSO and role-based profiles cannot work at all.
// The list is exact (service and operation); everything else must be a read.
var credentialFlow = map[string]map[string]bool{
	"SSO OIDC": {"CreateToken": true},
	"STS":      {"AssumeRole": true, "AssumeRoleWithWebIdentity": true, "GetSessionToken": true},
}

func isCredentialFlow(service, op string) bool { return credentialFlow[service][op] }

// APILog records every call that went through the guard, one JSON object per
// line, so a client can see exactly what the tool did in their account.
type APILog struct {
	mu      sync.Mutex
	w       io.Writer
	profile string
	n       int
	denied  int
}

func NewAPILog(w io.Writer, profile string) *APILog { return &APILog{w: w, profile: profile} }

// Counts returns how many calls were made and how many were blocked.
func (l *APILog) Counts() (calls, blocked int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n, l.denied
}

type logLine struct {
	Time      string `json:"time"`
	Profile   string `json:"profile,omitempty"`
	Service   string `json:"service"`
	Operation string `json:"operation"`
	Region    string `json:"region,omitempty"`
	Blocked   bool   `json:"blocked,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (l *APILog) record(ln logLine) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n++
	if ln.Blocked {
		l.denied++
	}
	if l.w == nil {
		return
	}
	ln.Time = time.Now().UTC().Format(time.RFC3339Nano)
	ln.Profile = l.profile
	b, err := json.Marshal(ln)
	if err != nil {
		return
	}
	_, _ = l.w.Write(append(b, '\n'))
}

// handle is the guard itself, separated from the middleware wiring so it can
// be tested without an AWS client.
func (l *APILog) handle(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
	svc, op, region := awsmiddleware.GetServiceID(ctx), awsmiddleware.GetOperationName(ctx), awsmiddleware.GetRegion(ctx)
	if !IsReadOperation(op) && !isCredentialFlow(svc, op) {
		l.record(logLine{Service: svc, Operation: op, Region: region, Blocked: true})
		return middleware.InitializeOutput{}, middleware.Metadata{},
			fmt.Errorf("blocked: %s %s is not a read-only operation; this tool never changes an account", svc, op)
	}
	out, md, err := next.HandleInitialize(ctx, in)
	ln := logLine{Service: svc, Operation: op, Region: region}
	if err != nil {
		ln.Error = firstLine(err.Error(), 160)
	}
	l.record(ln)
	return out, md, err
}

func (l *APILog) apiOption() func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("InfraLensReadOnlyGuard", l.handle), middleware.After)
	}
}

func firstLine(s string, n int) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > n {
		s = s[:n] + "..."
	}
	return s
}
